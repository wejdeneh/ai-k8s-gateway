"""
JWT authentication for the AI Agent Kubernetes Security Gateway.

Agents authenticate by presenting a Bearer JWT in the Authorization header.
Tokens are short-lived (15 minutes by default) and carry a `role` claim that
the OPA policy engine uses when making authorization decisions.

Supported roles
───────────────
  readonly  (agent-readonly) — may only GET / LIST / WATCH resources.
  deployer  (agent-deploy)   — may create/update/patch resources, but not
                               delete, and not mutate kube-system or secrets.

Design notes
────────────
• We use HS256 (symmetric) for simplicity in local dev.  A production system
  should use RS256 with a public/private key pair so the gateway only holds
  the private key and verifiers only need the public key.
• The `jti` (JWT ID) claim is included for future revocation support — e.g. a
  Redis blocklist keyed by jti.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from jose import JWTError, jwt

from app.config import settings

# ── Production Security Guardrail ──────────────────────────────────────────
# Fail fast if running in-cluster with the default developer secret.
if settings.k8s_in_cluster and settings.jwt_secret == "dev-secret-change-in-production":
    raise RuntimeError(
        "SECURITY COMPLIANCE FAILURE: The default JWT_SECRET value "
        "('dev-secret-change-in-production') cannot be used when "
        "K8S_IN_CLUSTER is enabled. Update the environment configuration."
    )

# ---------------------------------------------------------------------------
# Pre-defined agent identities.
# In a real system these would live in your identity provider (Okta, Cognito,
# etc.).  Here they are hardcoded for demo purposes.
# ---------------------------------------------------------------------------
AGENT_IDENTITIES: dict[str, dict[str, str]] = {
    "agent-readonly": {"role": "readonly", "sub": "agent-readonly"},
    "agent-deploy": {"role": "deployer", "sub": "agent-deploy"},
}


def create_token(agent_id: str) -> str:
    """
    Mint a short-lived JWT for a known agent identity.

    Args:
        agent_id: Key in AGENT_IDENTITIES (e.g. "agent-readonly").

    Returns:
        A signed JWT string.

    Raises:
        ValueError: If agent_id is not a recognised identity.
    """
    if agent_id not in AGENT_IDENTITIES:
        raise ValueError(
            f"Unknown agent identity: {agent_id!r}. "
            f"Valid options: {list(AGENT_IDENTITIES)}"
        )

    identity = AGENT_IDENTITIES[agent_id]
    now = datetime.now(timezone.utc)

    payload = {
        "sub": identity["sub"],  # subject — stable agent identifier
        "role": identity["role"],  # used by OPA for authz decisions
        "jti": str(uuid.uuid4()),  # unique token ID (for revocation)
        "iat": now,  # issued-at
        "exp": now + timedelta(minutes=settings.jwt_ttl_minutes),
    }

    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def verify_token(credentials: HTTPAuthorizationCredentials) -> dict:
    """
    Verify a Bearer JWT extracted from the Authorization header.

    Args:
        credentials: Parsed Authorization: Bearer <token> header from FastAPI's
                     HTTPBearer security scheme.

    Returns:
        The decoded payload dict, guaranteed to contain ``sub`` and ``role``.

    Raises:
        HTTPException(401): On any verification failure — invalid signature,
                            expired token, missing claims, etc.
    """
    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Include a valid Bearer JWT.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload: dict = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError:
        raise auth_error

    # Ensure the required claims are present.
    sub: Optional[str] = payload.get("sub")
    role: Optional[str] = payload.get("role")
    if sub is None or role is None:
        raise auth_error

    return payload
