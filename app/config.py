"""
Central configuration for the AI Agent Kubernetes Security Gateway.

All settings are read from environment variables, with sane defaults for
local development.  In production, set these via your secret manager or
container orchestrator — never hard-code them in source.

Usage:
    from app.config import settings
    print(settings.opa_url)
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── JWT ──────────────────────────────────────────────────────────────────
    # IMPORTANT: change jwt_secret to a cryptographically random string in
    # production (e.g. `openssl rand -hex 32`).
    jwt_secret: str = "dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 15

    # ── OPA sidecar ──────────────────────────────────────────────────────────
    # When running via docker-compose, OPA is reachable at http://opa:8181.
    # For local development without docker-compose, use http://localhost:8181.
    opa_url: str = "http://localhost:8181"
    # OPA REST API path for the agent.authz package.
    # Full URL: {opa_url}/v1/data/agent/authz
    opa_policy_path: str = "v1/data/agent/authz"

    # ── Audit log ─────────────────────────────────────────────────────────────
    audit_log_path: str = "audit.log"

    # ── Kubernetes ────────────────────────────────────────────────────────────
    # Set to True when the gateway itself runs inside a Kubernetes pod and
    # should load credentials from the pod's service-account token.
    k8s_in_cluster: bool = False

    # ── Content-aware policy ──────────────────────────────────────────────────
    # Image prefixes considered "trusted" for risk scoring and OPA evaluation.
    # Anything NOT matching one of these prefixes adds +1 to the risk score and
    # triggers an OPA deny_reason.  Override via env var as a comma-separated
    # string: TRUSTED_IMAGE_PREFIXES="gcr.io/myco/,quay.io/myco/"
    trusted_image_prefixes: list[str] = [
        "nginx:",  # Docker Hub official
        "python:",
        "alpine:",
        "busybox:",
        "gcr.io/",  # Google Container Registry
        "quay.io/",  # Red Hat Quay
        "registry.k8s.io/",  # Kubernetes official images
    ]

    # Maximum replica count an agent may request via the gateway.
    # Higher values add +1 to risk score and trigger an OPA deny_reason.
    max_replicas_threshold: int = 10

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


# Module-level singleton imported by all other modules.
settings = Settings()
