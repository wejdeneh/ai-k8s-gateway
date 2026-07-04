"""
Shared pytest fixtures for the AI Agent Kubernetes Security Gateway test suite.

Fixtures provided
─────────────────
  test_client        — FastAPI TestClient with OPA calls mocked to "allow"
  deny_client        — FastAPI TestClient with OPA calls mocked to "deny"
  readonly_token     — Valid JWT for agent-readonly (role=readonly)
  deploy_token       — Valid JWT for agent-deploy (role=deployer)
  expired_token      — A JWT that has already expired
  opa_allow_response — The JSON body OPA returns on allow
  opa_deny_response  — The JSON body OPA returns on deny
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from jose import jwt

# ---------------------------------------------------------------------------
# Ensure the test process uses a predictable secret and OPA URL.
# Set these BEFORE importing app modules so Settings picks them up.
# ---------------------------------------------------------------------------
os.environ.setdefault("JWT_SECRET",        "test-secret-not-for-production")
os.environ.setdefault("OPA_URL",           "http://mock-opa:8181")
os.environ.setdefault("AUDIT_LOG_PATH",    "/tmp/test-audit.log")
os.environ.setdefault("K8S_IN_CLUSTER",    "false")

from app.main import app                          # noqa: E402
from app.config import settings                   # noqa: E402
from app.auth.jwt_handler import AGENT_IDENTITIES # noqa: E402


# ---------------------------------------------------------------------------
# JWT fixtures
# ---------------------------------------------------------------------------

def _mint(agent_id: str, ttl_minutes: int = 15) -> str:
    identity = AGENT_IDENTITIES[agent_id]
    now = datetime.now(timezone.utc)
    payload = {
        "sub":  identity["sub"],
        "role": identity["role"],
        "iat":  now,
        "exp":  now + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


@pytest.fixture
def readonly_token() -> str:
    """Valid JWT for agent-readonly."""
    return _mint("agent-readonly")


@pytest.fixture
def deploy_token() -> str:
    """Valid JWT for agent-deploy."""
    return _mint("agent-deploy")


@pytest.fixture
def expired_token() -> str:
    """A JWT whose exp claim is already in the past."""
    return _mint("agent-readonly", ttl_minutes=-5)


# ---------------------------------------------------------------------------
# OPA response fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def opa_allow_response() -> dict:
    return {"result": {"allow": True, "reason": "Allowed by policy."}}


@pytest.fixture
def opa_deny_response() -> dict:
    return {"result": {"allow": False, "reason": "Denied: test denial."}}


# ---------------------------------------------------------------------------
# TestClient fixtures  (OPA mocked — no sidecar needed for unit tests)
# ---------------------------------------------------------------------------

def _make_client_generator(opa_response: dict):
    """
    Create a FastAPI TestClient generator with the OPA HTTP call and Kubernetes API execution patched.
    """
    import httpx

    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = opa_response
    mock_resp.raise_for_status = MagicMock()

    mock_http = AsyncMock()
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__  = AsyncMock(return_value=False)
    mock_http.post       = AsyncMock(return_value=mock_resp)

    mock_execute_action = MagicMock(return_value={"mocked": True})

    with (
        patch("app.main.httpx.AsyncClient", return_value=mock_http),
        patch("app.main.execute_action", mock_execute_action),
    ):
        yield TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def test_client(opa_allow_response: dict):
    """TestClient where OPA always returns allow=True."""
    yield from _make_client_generator(opa_allow_response)


@pytest.fixture
def deny_client(opa_deny_response: dict):
    """TestClient where OPA always returns allow=False."""
    yield from _make_client_generator(opa_deny_response)


# ---------------------------------------------------------------------------
# Helper: authorization header
# ---------------------------------------------------------------------------

def auth(token: str) -> dict[str, str]:
    """Return an Authorization header dict for use in test requests."""
    return {"Authorization": f"Bearer {token}"}
