"""
AI Agent Kubernetes Security Gateway — FastAPI application.

Every agent action passes through a five-stage pipeline before (optionally)
reaching the Kubernetes API server.

Request lifecycle
─────────────────

  POST /agent-action
    │
    ├─ Stage 1 │ JWT authentication
    │           └─ 401 if token is invalid or expired
    │
    ├─ Stage 2 │ Risk scoring (rule-based, no ML)
    │           └─ Produces: low / medium / high + raw score + reasons
    │
    ├─ Stage 3 │ OPA policy evaluation  ← contacts OPA sidecar via REST
    │           └─ deny  → audit(deny) → 403, pipeline stops
    │
    ├─ Stage 4 │ Audit log  (written here for every non-deny path too)
    │
    └─ Stage 5 │ Kubernetes dispatch
                ├─ high risk  → approval queue → 202 (pending)
                └─ low/medium → execute on k8s → 200

Additional endpoints
────────────────────
  GET  /pending              List high-risk actions awaiting human approval
  POST /approve/{id}         Approve or deny a queued action
  GET  /health               Liveness probe
"""

import logging
import uuid
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.approval.queue import PendingRequest, approval_queue
from app.audit import logger as audit
from app.auth.jwt_handler import verify_token
from app.config import settings
from app.k8s.client import K8sActionError, K8sUnavailableError, execute_action
from app.risk.scorer import score as compute_risk

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
from app.audit.structured_logger import setup_structured_logging

setup_structured_logging(logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI Agent Kubernetes Security Gateway",
    description=(
        "Policy-enforcement gateway that sits between an AI agent and a "
        "Kubernetes cluster. Every request is authenticated (JWT), risk-scored, "
        "audited, and evaluated by OPA before reaching the cluster.  High-risk "
        "actions require explicit human approval."
    ),
    version="1.0.0",
    contact={
        "name": "Portfolio project",
        "url": "https://github.com/your-handle/ai-k8s-gateway",
    },
    license_info={"name": "MIT"},
)

security = HTTPBearer()

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AgentActionRequest(BaseModel):
    """Body accepted by POST /agent-action."""

    action: str  # Kubernetes verb: get, list, create, …
    resource: str  # Resource kind:   pods, deployments, …
    namespace: str = "default"
    params: dict[str, Any] = {}  # Extra args forwarded to the k8s SDK


class AgentActionResponse(BaseModel):
    """Body returned by POST /agent-action on non-403 outcomes."""

    request_id: str
    decision: str  # "allow" | "deny" | "pending-approval"
    risk_level: str
    risk_score: int
    message: str
    data: Optional[Any] = None


class ApproveRequest(BaseModel):
    """Body accepted by POST /approve/{id}."""

    approved: bool
    reason: Optional[str] = None  # optional human comment for the audit log


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _query_opa(
    *,
    identity: str,
    role: str,
    action: str,
    resource: str,
    namespace: str,
    risk_level: str,
    params: dict[str, Any],
) -> tuple[bool, str]:
    """
    Call the OPA sidecar's REST API for an allow/deny decision.

    The full ``params`` dict is forwarded as ``input.params`` so the Rego
    policy can inspect image names, securityContext fields, replica counts,
    etc. — not just the action/resource/namespace triple.

    On OPA unavailability, the gateway fails CLOSED (deny) — a malfunction in
    the policy engine is not a reason to let requests through unchecked.

    Returns:
        (allowed: bool, reason: str)
    """
    opa_input = {
        "input": {
            "identity": identity,
            "role": role,
            "action": action.lower(),
            "resource": resource.lower(),
            "namespace": namespace.lower(),
            "risk_level": risk_level,
            # v2: full params dict so OPA can inspect image, privileged, etc.
            "params": params,
        }
    }

    url = f"{settings.opa_url}/{settings.opa_policy_path}"
    logger.debug("Querying OPA at %s with input=%s", url, opa_input)

    try:
        async with httpx.AsyncClient(timeout=5.0) as http:
            resp = await http.post(url, json=opa_input)
            resp.raise_for_status()
            result: dict = resp.json().get("result", {})

            allowed = bool(result.get("allow", False))
            reason = str(result.get("reason", "OPA decision (no reason provided)"))
            logger.info("OPA decision: allow=%s  reason=%r", allowed, reason)
            return allowed, reason

    except httpx.RequestError as exc:
        logger.error("OPA unreachable (%s) — failing closed (deny)", exc)
        return False, "OPA sidecar unreachable — failing closed for safety"

    except httpx.HTTPStatusError as exc:
        logger.error("OPA HTTP error %d — failing closed", exc.response.status_code)
        return False, f"OPA returned HTTP {exc.response.status_code} — failing closed"


async def _execute_k8s(
    action: str, resource: str, namespace: str, params: dict[str, Any]
) -> dict[str, Any]:
    """
    Execute an approved action on the Kubernetes cluster.

    If the cluster is unreachable, returns a loud, visually-distinct
    [SIMULATED] response so nobody mistakes unavailability for real output.
    This is the fallback of last resort — the demo/setup.sh script should
    be run first to provision a real kind cluster.
    """
    try:
        return execute_action(action, resource, namespace, params)

    except K8sUnavailableError as exc:
        logger.warning(
            "⚠  Cluster unreachable — returning SIMULATED response.  "
            "Run `bash demo/setup.sh` to fix this.  Error: %s",
            exc,
        )
        return {
            "status": "[SIMULATED — cluster unreachable]",
            "WARNING": (
                "No Kubernetes cluster was found.  "
                "This response is NOT REAL.  "
                "Run `bash demo/setup.sh` to provision a local kind cluster."
            ),
            "would_have_executed": {
                "action": action,
                "resource": resource,
                "namespace": namespace,
                "params": params,
            },
        }

    except (K8sActionError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Kubernetes API error: {exc}",
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.post(
    "/agent-action",
    response_model=AgentActionResponse,
    status_code=200,
    summary="Submit an agent action for policy evaluation",
    tags=["Core"],
)
async def agent_action(
    body: AgentActionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> AgentActionResponse:
    """
    Main enforcement endpoint — the heart of the gateway.

    The five-stage pipeline runs synchronously per request:
    JWT → risk scoring → OPA evaluation → audit → k8s dispatch (or queue).
    """
    request_id = str(uuid.uuid4())

    # ── Stage 1: JWT authentication ───────────────────────────────────────
    token_payload = verify_token(credentials)
    identity = token_payload["sub"]
    role = token_payload["role"]

    logger.info(
        "[%s] agent=%s role=%s  action=%s resource=%s ns=%s",
        request_id,
        identity,
        role,
        body.action,
        body.resource,
        body.namespace,
    )

    # ── Stage 2: Risk scoring ─────────────────────────────────────────────
    # v2: pass body.params so the scorer can inspect image, privileged, etc.
    rs = compute_risk(body.action, body.resource, body.namespace, body.params)
    logger.info("[%s] risk=%s score=%d", request_id, rs.level, rs.score)

    # ── Stage 3: OPA policy evaluation ───────────────────────────────────
    # v2: params forwarded so OPA can evaluate image/securityContext rules.
    allowed, opa_reason = await _query_opa(
        identity=identity,
        role=role,
        action=body.action,
        resource=body.resource,
        namespace=body.namespace,
        risk_level=rs.level,
        params=body.params,
    )

    # ── Stage 4a: Audit — denied path ────────────────────────────────────
    if not allowed:
        audit.log(
            request_id=request_id,
            identity=identity,
            role=role,
            action=body.action,
            resource=body.resource,
            namespace=body.namespace,
            params=body.params,
            risk_level=rs.level,
            risk_score=rs.score,
            risk_reasons=list(rs.reasons),
            decision="deny",
            opa_reason=opa_reason,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "request_id": request_id,
                "decision": "deny",
                "reason": opa_reason,
                "risk_level": rs.level,
            },
        )

    # ── Stage 5a: High-risk → queue for human approval ───────────────────
    if rs.level == "high":
        pending = PendingRequest(
            request_id=request_id,
            identity=identity,
            role=role,
            action=body.action,
            resource=body.resource,
            namespace=body.namespace,
            params=body.params,
            risk_level=rs.level,
            risk_score=rs.score,
            risk_reasons=list(rs.reasons),
        )
        approval_queue.enqueue(pending)

        audit.log(
            request_id=request_id,
            identity=identity,
            role=role,
            action=body.action,
            resource=body.resource,
            namespace=body.namespace,
            params=body.params,
            risk_level=rs.level,
            risk_score=rs.score,
            risk_reasons=list(rs.reasons),
            decision="pending-approval",
            opa_reason=opa_reason,
        )

        logger.info("[%s] High-risk action queued for human approval", request_id)
        return AgentActionResponse(
            request_id=request_id,
            decision="pending-approval",
            risk_level=rs.level,
            risk_score=rs.score,
            message=(
                f"Action is high-risk and has been queued for human approval. "
                f"Use GET /pending to view it and "
                f"POST /approve/{request_id} to resolve."
            ),
        )

    # ── Stage 5b: Low/Medium risk → execute on Kubernetes ────────────────
    k8s_result = await _execute_k8s(
        body.action, body.resource, body.namespace, body.params
    )

    audit.log(
        request_id=request_id,
        identity=identity,
        role=role,
        action=body.action,
        resource=body.resource,
        namespace=body.namespace,
        params=body.params,
        risk_level=rs.level,
        risk_score=rs.score,
        risk_reasons=list(rs.reasons),
        decision="allow",
        opa_reason=opa_reason,
    )

    return AgentActionResponse(
        request_id=request_id,
        decision="allow",
        risk_level=rs.level,
        risk_score=rs.score,
        message="Action evaluated, approved, and executed on Kubernetes.",
        data=k8s_result,
    )


@app.get(
    "/pending",
    summary="List all actions awaiting human approval",
    tags=["Human Approval"],
)
async def list_pending(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """
    Return the current contents of the human-approval queue.

    Any authenticated agent identity may view the queue.
    In production, restrict this to operator roles only.
    """
    verify_token(credentials)
    items = approval_queue.list_pending()
    return {
        "count": len(items),
        "items": items,
    }


@app.post(
    "/approve/{request_id}",
    summary="Approve or deny a high-risk action",
    tags=["Human Approval"],
)
async def approve_action(
    request_id: str,
    body: ApproveRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """
    Resolve a pending high-risk action.

    - ``approved=true``  → remove from queue, execute on Kubernetes, audit.
    - ``approved=false`` → remove from queue, discard, audit.

    A second audit record is appended so the log shows both the original
    pending entry and the final human decision.
    """
    token_payload = verify_token(credentials)
    approver = token_payload["sub"]

    pending = approval_queue.resolve(request_id)
    if pending is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No pending request found with id={request_id!r}. "
                "It may have already been resolved or the ID is incorrect."
            ),
        )

    if body.approved:
        k8s_result = await _execute_k8s(
            pending.action, pending.resource, pending.namespace, pending.params
        )
        final_decision = "human-allow"
        message = f"Approved by {approver!r} and executed on Kubernetes."
    else:
        k8s_result = None
        final_decision = "human-deny"
        message = (
            f"Denied by {approver!r}. Reason: {body.reason or 'no reason provided'}"
        )

    # Second audit record — captures the human decision.
    audit.log(
        request_id=request_id,
        identity=pending.identity,
        role=pending.role,
        action=pending.action,
        resource=pending.resource,
        namespace=pending.namespace,
        params=pending.params,
        risk_level=pending.risk_level,
        risk_score=pending.risk_score,
        risk_reasons=pending.risk_reasons,
        decision=final_decision,
        opa_reason=(
            f"Human {'approved' if body.approved else 'denied'} by {approver!r}. "
            f"Reason: {body.reason or 'none'}"
        ),
    )

    logger.info("[%s] Human resolution: %s by %s", request_id, final_decision, approver)

    return {
        "request_id": request_id,
        "decision": final_decision,
        "approver": approver,
        "message": message,
        "data": k8s_result,
    }


@app.get("/health", summary="Gateway liveness probe", tags=["Ops"])
async def health() -> dict[str, str]:
    """Returns ``{"status": "ok"}`` when the gateway process is alive."""
    return {"status": "ok"}
