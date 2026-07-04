"""
Kubernetes API client wrapper.

This is the ONLY module in the gateway that communicates with the Kubernetes
API server.  It is called exclusively after:

  1. OPA has returned an explicit "allow" decision, AND
  2. Either the risk level is "low" or "medium", OR a human has explicitly
     approved the action via the /approve/{id} endpoint.

Design
──────
• We wrap the official ``kubernetes`` Python client (the same library used
  by kubectl under the hood).
• Configuration is loaded in priority order: in-cluster service-account token
  (when running as a pod) → ~/.kube/config / $KUBECONFIG (local dev).
• If neither config source is available, every call raises
  ``K8sUnavailableError``.  The gateway converts that to a clearly-labelled
  [SIMULATED] response so no reviewer mistakes unavailability for success.
• The dispatch table pattern (action × resource → SDK call) makes it easy to
  audit exactly what surface area the gateway exposes to agents.

Extending support
─────────────────
To add a new resource or verb, add a branch in ``_dispatch()``.  The tests
in ``tests/test_k8s_client.py`` document the expected behaviour.
"""

import logging
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config.config_exception import ConfigException

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class K8sUnavailableError(Exception):
    """
    Raised when no Kubernetes cluster configuration can be found.

    The gateway treats this differently from a normal API error: it returns
    a loud, clearly-labelled [SIMULATED] response rather than HTTP 502, so
    the demo degrades gracefully when no cluster is present.
    """


class K8sActionError(Exception):
    """Raised when the Kubernetes API returns an error for a valid request."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _load_config() -> None:
    """
    Load Kubernetes config.

    Tries in-cluster config first (so the same code works inside a pod),
    then falls back to the kubeconfig file.

    Raises:
        K8sUnavailableError: If neither source is available.
    """
    # In-cluster: pod has a service-account token mounted automatically.
    try:
        config.load_incluster_config()
        logger.debug("Loaded in-cluster Kubernetes config")
        return
    except ConfigException:
        pass

    # Kubeconfig file: respects $KUBECONFIG and ~/.kube/config.
    try:
        config.load_kube_config()
        logger.debug("Loaded kubeconfig file")
        return
    except ConfigException as exc:
        raise K8sUnavailableError(
            "No Kubernetes configuration found (tried in-cluster token and "
            "kubeconfig).  Run `bash demo/setup.sh` to provision a local kind "
            "cluster, or set $KUBECONFIG to point at your cluster config."
        ) from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def execute_action(
    action: str,
    resource: str,
    namespace: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    """
    Execute a single agent action against the Kubernetes API.

    Args:
        action:    Kubernetes verb (get, list, create, update, patch, delete, …).
        resource:  Lowercase resource kind (pods, deployments, secrets, …).
        namespace: Target namespace.
        params:    Arbitrary key-value pairs forwarded to the SDK call
                   (e.g. ``{"name": "my-pod"}`` for a get/delete).

    Returns:
        ``{"status": "success", "data": <api_response>}``

    Raises:
        K8sUnavailableError: No cluster config was found.
        K8sActionError:      The Kubernetes API returned an error.
        ValueError:          Unsupported action/resource combination.
    """
    _load_config()

    action_lower = action.lower().strip()
    resource_lower = resource.lower().strip()
    namespace_clean = namespace.strip() or "default"

    logger.info(
        "Executing k8s action: %s %s/%s  params=%s",
        action_lower,
        namespace_clean,
        resource_lower,
        params,
    )

    try:
        result = _dispatch(action_lower, resource_lower, namespace_clean, params)
    except ApiException as exc:
        raise K8sActionError(
            f"Kubernetes API returned HTTP {exc.status}: {exc.reason}",
            status_code=exc.status,
        ) from exc

    return {"status": "success", "data": result}


# ---------------------------------------------------------------------------
# Internal dispatch
# ---------------------------------------------------------------------------


def _dispatch(
    action: str,
    resource: str,
    namespace: str,
    params: dict[str, Any],
) -> Any:
    """
    Route (action, resource) to the appropriate Kubernetes SDK call.

    Returns raw Python objects (lists, dicts) — serialisation happens in
    the caller (FastAPI's JSON encoder).

    Raises:
        ValueError: For unsupported (action, resource) combinations.
    """
    v1 = client.CoreV1Api()
    apps = client.AppsV1Api()

    # ── Pods ──────────────────────────────────────────────────────────────
    if resource in ("pods", "pod"):
        if action == "list":
            resp = v1.list_namespaced_pod(namespace=namespace)
            return [
                {"name": p.metadata.name, "phase": p.status.phase} for p in resp.items
            ]
        if action == "get":
            name = _require_param(params, "name", action, resource)
            resp = v1.read_namespaced_pod(name=name, namespace=namespace)
            return {
                "name": resp.metadata.name,
                "namespace": resp.metadata.namespace,
                "phase": resp.status.phase,
                "node": resp.spec.node_name,
            }
        if action == "delete":
            name = _require_param(params, "name", action, resource)
            v1.delete_namespaced_pod(name=name, namespace=namespace)
            return {"deleted": name, "namespace": namespace}

    # ── Deployments ───────────────────────────────────────────────────────
    elif resource in ("deployments", "deployment"):
        if action == "list":
            resp = apps.list_namespaced_deployment(namespace=namespace)
            return [
                {
                    "name": d.metadata.name,
                    "replicas": d.spec.replicas,
                    "ready": d.status.ready_replicas or 0,
                }
                for d in resp.items
            ]
        if action == "get":
            name = _require_param(params, "name", action, resource)
            resp = apps.read_namespaced_deployment(name=name, namespace=namespace)
            return {
                "name": resp.metadata.name,
                "replicas": resp.spec.replicas,
                "ready": resp.status.ready_replicas or 0,
                "image": resp.spec.template.spec.containers[0].image,
            }
        if action == "create":
            body = _build_deployment(params)
            resp = apps.create_namespaced_deployment(namespace=namespace, body=body)
            return {
                "name": resp.metadata.name,
                "namespace": resp.metadata.namespace,
                "uid": resp.metadata.uid,
            }
        if action in ("update", "patch"):
            name = _require_param(params, "name", action, resource)
            body = _build_deployment(params)
            resp = apps.patch_namespaced_deployment(
                name=name, namespace=namespace, body=body
            )
            return {"name": resp.metadata.name, "patched": True}
        if action == "delete":
            name = _require_param(params, "name", action, resource)
            apps.delete_namespaced_deployment(name=name, namespace=namespace)
            return {"deleted": name, "namespace": namespace}

    # ── Secrets (list only — gateway is NOT a secret manager) ─────────────
    elif resource in ("secrets", "secret"):
        if action == "list":
            resp = v1.list_namespaced_secret(namespace=namespace)
            # Return only names — NEVER return secret data values.
            return [s.metadata.name for s in resp.items]

    # ── Namespaces ────────────────────────────────────────────────────────
    elif resource in ("namespaces", "namespace"):
        if action == "list":
            resp = v1.list_namespace()
            return [n.metadata.name for n in resp.items]

    # ── ConfigMaps ────────────────────────────────────────────────────────
    elif resource in ("configmaps", "configmap"):
        if action == "list":
            resp = v1.list_namespaced_config_map(namespace=namespace)
            return [cm.metadata.name for cm in resp.items]

    raise ValueError(
        f"Unsupported combination: action='{action}' resource='{resource}'. "
        "To add support, add a branch in app/k8s/client.py::_dispatch()."
    )


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------


def _require_param(params: dict[str, Any], key: str, action: str, resource: str) -> str:
    """
    Extract a required parameter from the params dict.

    Raises:
        ValueError: If the key is absent or empty.
    """
    value = params.get(key, "")
    if not value:
        raise ValueError(
            f"'{key}' is required in params for action='{action}' "
            f"on resource='{resource}'."
        )
    return str(value)


def _build_deployment(params: dict[str, Any]) -> client.V1Deployment:
    """
    Construct a V1Deployment from the params dict.

    Resource limits are always included so the resulting manifest passes the
    Gatekeeper K8sRequireLimits constraint.  Security context defaults are
    set to non-root / no-privilege-escalation — overridable via params.

    Expected params
    ───────────────
      name            Deployment name (default: "gateway-managed-app").
      image           Container image (default: "nginx:alpine").
      replicas        Integer replica count (default: 1).
      container_port  Exposed port (default: 80).
      cpu_request     CPU request  (default: "50m").
      cpu_limit       CPU limit    (default: "200m").
      memory_request  Memory request (default: "64Mi").
      memory_limit    Memory limit   (default: "128Mi").
    """
    name = params.get("name", "gateway-managed-app")
    image = params.get("image", "nginx:alpine")
    replicas = int(params.get("replicas", 1))
    port = int(params.get("container_port", 80))
    cpu_req = params.get("cpu_request", "50m")
    cpu_lim = params.get("cpu_limit", "200m")
    mem_req = params.get("memory_request", "64Mi")
    mem_lim = params.get("memory_limit", "128Mi")

    resources = client.V1ResourceRequirements(
        requests={"cpu": cpu_req, "memory": mem_req},
        limits={"cpu": cpu_lim, "memory": mem_lim},
    )

    return client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=client.V1ObjectMeta(
            name=name,
            labels={"managed-by": "ai-k8s-gateway"},
        ),
        spec=client.V1DeploymentSpec(
            replicas=replicas,
            selector=client.V1LabelSelector(match_labels={"app": name}),
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={"app": name, "managed-by": "ai-k8s-gateway"},
                ),
                spec=client.V1PodSpec(
                    # Pod-level security: run as non-root by default.
                    security_context=client.V1PodSecurityContext(
                        run_as_non_root=True,
                        run_as_user=65534,  # nobody
                    ),
                    containers=[
                        client.V1Container(
                            name=name,
                            image=image,
                            ports=[client.V1ContainerPort(container_port=port)],
                            resources=resources,
                            # Container-level security: no privilege escalation.
                            security_context=client.V1SecurityContext(
                                privileged=False,
                                allow_privilege_escalation=False,
                            ),
                        )
                    ],
                ),
            ),
        ),
    )
