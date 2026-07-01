"""
ai_agent_client.py — Python client for the AI Agent Kubernetes Security Gateway

This is the code an AI agent (LangChain tool, AutoGen agent, custom bot, etc.)
would import and use to safely interact with a Kubernetes cluster.

Instead of calling kubectl or the k8s API directly, the agent calls this client,
which routes every action through the gateway's 5-stage enforcement pipeline.

Usage
─────
    from ai_agent_client import GatewayClient, GatewayDeniedError

    client = GatewayClient(
        gateway_url="http://ai-gateway.ai-gateway.svc.cluster.local:8000",
        token=os.environ["AGENT_JWT"],
    )

    # List pods — low risk, always allowed for any role
    pods = client.list_pods(namespace="production")

    # Create a deployment — medium risk, allowed for deployer role
    result = client.create_deployment(
        namespace="production",
        name="my-service",
        image="gcr.io/myco/my-service:v1.2.3",
        replicas=3,
    )

    # Gateway blocks dangerous actions automatically
    try:
        client.create_deployment(
            namespace="production",
            name="evil",
            image="cryptominer:latest",   # ← gateway blocks this
            replicas=100,                 # ← and this
        )
    except GatewayDeniedError as e:
        print(f"Blocked: {e.reason}")
        # "image 'cryptominer:latest' is not from a trusted registry;
        #  replicas=100 exceeds the agent gateway limit of 10"

LangChain Tool integration
──────────────────────────
    from langchain.tools import StructuredTool
    from ai_agent_client import GatewayClient

    client = GatewayClient(...)

    k8s_tool = StructuredTool.from_function(
        func=client.create_deployment,
        name="create_k8s_deployment",
        description="Deploy a containerised application to Kubernetes.",
    )
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GatewayError(Exception):
    """Base class for gateway errors."""


class GatewayAuthError(GatewayError):
    """JWT missing, expired, or invalid — agent needs a new token."""


class GatewayDeniedError(GatewayError):
    """OPA policy denied the action."""
    def __init__(self, reason: str, risk_level: str, risk_score: int) -> None:
        super().__init__(reason)
        self.reason     = reason
        self.risk_level = risk_level
        self.risk_score = risk_score


class GatewayPendingError(GatewayError):
    """Action was queued for human approval (high-risk but OPA-allowed)."""
    def __init__(self, request_id: str) -> None:
        super().__init__(f"Action queued for human approval: {request_id}")
        self.request_id = request_id


class GatewayConnectionError(GatewayError):
    """Cannot reach the gateway."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

@dataclass
class GatewayClient:
    """
    HTTP client for the AI Agent Kubernetes Security Gateway.

    Wraps POST /agent-action into typed methods so AI agents never
    have to construct raw JSON payloads or handle HTTP status codes.

    Args:
        gateway_url:  Base URL of the gateway (no trailing slash).
        token:        Bearer JWT.  Obtain one from the gateway operator
                      or via the /token endpoint (if your deployment
                      exposes one).
        timeout:      Request timeout in seconds (default: 30).
        retry_on_503: If True, retry once after 1s on HTTP 503.
    """
    gateway_url:   str
    token:         str
    timeout:       float = 30.0
    retry_on_503:  bool  = True
    _client:       httpx.Client = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = httpx.Client(
            base_url=self.gateway_url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type":  "application/json",
                "User-Agent":    "ai-k8s-gateway-python-client/2.0",
            },
            timeout=self.timeout,
        )

    def __enter__(self) -> "GatewayClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # ── Core action dispatcher ────────────────────────────────────────────────

    def action(
        self,
        action: str,
        resource: str,
        namespace: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a raw action to the gateway.

        Raises:
            GatewayAuthError:       HTTP 401
            GatewayDeniedError:     HTTP 403
            GatewayPendingError:    HTTP 202  (queued for human approval)
            GatewayConnectionError: Network error
        """
        payload = {
            "action":    action,
            "resource":  resource,
            "namespace": namespace,
            "params":    params or {},
        }

        try:
            resp = self._client.post("/agent-action", json=payload)
        except httpx.RequestError as exc:
            raise GatewayConnectionError(
                f"Cannot reach gateway at {self.gateway_url}: {exc}"
            ) from exc

        if resp.status_code == 503 and self.retry_on_503:
            time.sleep(1)
            try:
                resp = self._client.post("/agent-action", json=payload)
            except httpx.RequestError as exc:
                raise GatewayConnectionError(str(exc)) from exc

        return self._handle_response(resp)

    def _handle_response(self, resp: httpx.Response) -> dict[str, Any]:
        if resp.status_code == 200:
            return resp.json()

        if resp.status_code == 202:
            body = resp.json()
            raise GatewayPendingError(body.get("request_id", "unknown"))

        if resp.status_code == 401:
            raise GatewayAuthError(
                "JWT rejected by gateway. Obtain a new token and retry."
            )

        if resp.status_code == 403:
            body = resp.json()
            detail = body.get("detail", {})
            raise GatewayDeniedError(
                reason     = detail.get("reason",     "Policy denied the action."),
                risk_level = detail.get("risk_level", "unknown"),
                risk_score = detail.get("risk_score", -1),
            )

        # Unexpected status — surface the raw response for debugging.
        raise GatewayError(
            f"Unexpected gateway response {resp.status_code}: {resp.text[:300]}"
        )

    # ── Typed convenience methods ─────────────────────────────────────────────

    def list_pods(self, namespace: str = "default") -> list[dict]:
        """List pods in a namespace. Always read-only (low risk)."""
        return self.action("list", "pods", namespace)

    def get_pod(self, name: str, namespace: str = "default") -> dict:
        """Get details for a specific pod."""
        return self.action("get", "pods", namespace, params={"name": name})

    def list_deployments(self, namespace: str = "default") -> list[dict]:
        """List deployments in a namespace."""
        return self.action("list", "deployments", namespace)

    def get_deployment(self, name: str, namespace: str = "default") -> dict:
        """Get details for a specific deployment."""
        return self.action("get", "deployments", namespace, params={"name": name})

    def create_deployment(
        self,
        name: str,
        image: str,
        namespace: str = "default",
        replicas: int = 1,
        container_port: int = 80,
        cpu_request: str = "50m",
        cpu_limit: str = "200m",
        memory_request: str = "64Mi",
        memory_limit: str = "128Mi",
    ) -> dict:
        """
        Create a Kubernetes deployment.

        Risk score: 1 (create) + extras based on image/replicas.
        Requires deployer role.
        Blocked if: image not trusted, replicas > 10, namespace is kube-system.

        Example:
            client.create_deployment(
                name="my-api",
                image="gcr.io/myco/my-api:v1.2.3",
                namespace="production",
                replicas=3,
            )
        """
        return self.action(
            "create", "deployments", namespace,
            params={
                "name":           name,
                "image":          image,
                "replicas":       replicas,
                "container_port": container_port,
                "cpu_request":    cpu_request,
                "cpu_limit":      cpu_limit,
                "memory_request": memory_request,
                "memory_limit":   memory_limit,
            },
        )

    def patch_deployment(
        self,
        name: str,
        namespace: str = "default",
        image: str | None = None,
        replicas: int | None = None,
    ) -> dict:
        """Update an existing deployment's image or replica count."""
        params: dict[str, Any] = {"name": name}
        if image    is not None: params["image"]    = image
        if replicas is not None: params["replicas"] = replicas
        return self.action("patch", "deployments", namespace, params=params)

    def list_secrets(self, namespace: str = "default") -> list[str]:
        """
        List secret *names* in a namespace.

        Note: The gateway NEVER returns secret values — only names.
        Risk: medium (secrets resource).  Requires deployer role.
        """
        return self.action("list", "secrets", namespace)

    def list_namespaces(self) -> list[str]:
        """List all cluster namespaces."""
        return self.action("list", "namespaces", "default")

    # ── Approval queue ────────────────────────────────────────────────────────

    def list_pending_approvals(self) -> list[dict]:
        """List actions waiting for human approval."""
        try:
            resp = self._client.get("/pending")
        except httpx.RequestError as exc:
            raise GatewayConnectionError(str(exc)) from exc
        return self._handle_response(resp)

    def approve(self, request_id: str, reason: str) -> dict:
        """Approve a queued high-risk action."""
        try:
            resp = self._client.post(
                f"/approve/{request_id}",
                json={"approved": True, "reason": reason},
            )
        except httpx.RequestError as exc:
            raise GatewayConnectionError(str(exc)) from exc
        return self._handle_response(resp)

    def reject(self, request_id: str, reason: str) -> dict:
        """Reject a queued high-risk action."""
        try:
            resp = self._client.post(
                f"/approve/{request_id}",
                json={"approved": False, "reason": reason},
            )
        except httpx.RequestError as exc:
            raise GatewayConnectionError(str(exc)) from exc
        return self._handle_response(resp)


# ---------------------------------------------------------------------------
# LangChain Tool wrappers (optional — requires langchain installed)
# ---------------------------------------------------------------------------

def make_langchain_tools(client: GatewayClient) -> list:
    """
    Create LangChain StructuredTool objects from the GatewayClient methods.

    Usage:
        from langchain.agents import AgentExecutor, create_openai_tools_agent
        from ai_agent_client import GatewayClient, make_langchain_tools

        client = GatewayClient(gateway_url=..., token=...)
        tools  = make_langchain_tools(client)
        agent  = create_openai_tools_agent(llm, tools, prompt)
        executor = AgentExecutor(agent=agent, tools=tools)
    """
    try:
        from langchain.tools import StructuredTool
    except ImportError:
        raise ImportError(
            "langchain is not installed. "
            "Run: pip install langchain to use make_langchain_tools()."
        )

    return [
        StructuredTool.from_function(
            func=client.list_pods,
            name="list_k8s_pods",
            description=(
                "List all pods in a Kubernetes namespace. "
                "Args: namespace (str, default='default'). "
                "Returns a list of pod info dicts."
            ),
        ),
        StructuredTool.from_function(
            func=client.list_deployments,
            name="list_k8s_deployments",
            description=(
                "List all deployments in a Kubernetes namespace. "
                "Args: namespace (str). Returns a list of deployment dicts."
            ),
        ),
        StructuredTool.from_function(
            func=client.create_deployment,
            name="create_k8s_deployment",
            description=(
                "Deploy a containerised application to Kubernetes. "
                "Args: name (str), image (str — must be from trusted registry), "
                "namespace (str), replicas (int, max 10), "
                "cpu_limit (str), memory_limit (str). "
                "Raises GatewayDeniedError if the image is untrusted, "
                "namespace is kube-system, or replicas > 10."
            ),
        ),
        StructuredTool.from_function(
            func=client.patch_deployment,
            name="patch_k8s_deployment",
            description=(
                "Update an existing deployment's image or replica count. "
                "Args: name (str), namespace (str), "
                "image (str | None), replicas (int | None)."
            ),
        ),
        StructuredTool.from_function(
            func=client.list_namespaces,
            name="list_k8s_namespaces",
            description="List all Kubernetes namespaces. No args required.",
        ),
    ]


# ---------------------------------------------------------------------------
# Quick interactive demo (run directly: python ai_agent_client.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:8000")
    TOKEN   = os.environ.get("AGENT_JWT")

    if not TOKEN:
        print("Mint a token first:")
        print("  set AGENT_JWT=$(python -m app.auth.mint_tokens --agent agent-deploy --bare)")
        raise SystemExit(1)

    print(f"\nConnecting to gateway at {GATEWAY}...\n")

    with GatewayClient(gateway_url=GATEWAY, token=TOKEN) as client:

        # ── Read operations (always allowed) ──────────────────────────────
        print("=== Listing namespaces ===")
        ns = client.list_namespaces()
        print(json.dumps(ns, indent=2))

        print("\n=== Listing pods in demo namespace ===")
        pods = client.list_pods("demo")
        print(json.dumps(pods, indent=2))

        # ── Write operation (allowed for deployer) ────────────────────────
        print("\n=== Creating deployment (trusted image) ===")
        try:
            result = client.create_deployment(
                name="demo-app", image="nginx:alpine",
                namespace="demo", replicas=2,
            )
            print(f"Created: {json.dumps(result, indent=2)}")
        except GatewayDeniedError as e:
            print(f"Denied ({e.risk_level}, score={e.risk_score}): {e.reason}")

        # ── Blocked: untrusted image ──────────────────────────────────────
        print("\n=== Attempting untrusted image (should be blocked) ===")
        try:
            client.create_deployment(
                name="evil", image="cryptominer:latest",
                namespace="demo", replicas=1,
            )
        except GatewayDeniedError as e:
            print(f"✅ Correctly blocked — {e.reason}")

        # ── Blocked: privileged via raw action ────────────────────────────
        print("\n=== Attempting privileged container (should be blocked) ===")
        try:
            client.action(
                "create", "deployments", "demo",
                params={"name": "evil-priv", "image": "nginx:alpine", "privileged": True},
            )
        except GatewayDeniedError as e:
            print(f"✅ Correctly blocked — {e.reason}")

        print("\nDone. Check audit.log for the full trail.")
