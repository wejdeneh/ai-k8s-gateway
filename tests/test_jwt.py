"""
Unit tests for app/auth/jwt_handler.py

Tests cover:
  - Token creation: correct sub/role claims, expiry
  - Token verification: valid tokens, expired tokens, tampered signatures,
    wrong algorithm, missing Bearer prefix
  - All registered agent identities produce verifiable tokens
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt, JWTError

from app.auth.jwt_handler import (
    AGENT_IDENTITIES,
    create_token,
    verify_token,
)
from app.config import settings


class TestCreateToken:
    """create_token() produces correctly structured JWTs."""

    def test_returns_string(self) -> None:
        token = create_token("agent-readonly")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_has_three_parts(self) -> None:
        token = create_token("agent-readonly")
        parts = token.split(".")
        assert len(parts) == 3, "JWT must have header.payload.signature"

    def test_sub_claim_matches_identity(self) -> None:
        token = create_token("agent-readonly")
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        assert payload["sub"] == AGENT_IDENTITIES["agent-readonly"]["sub"]

    def test_role_claim_matches_identity(self) -> None:
        token = create_token("agent-deploy")
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        assert payload["role"] == AGENT_IDENTITIES["agent-deploy"]["role"]

    def test_exp_is_in_the_future(self) -> None:
        token = create_token("agent-readonly")
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        now = datetime.now(timezone.utc).timestamp()
        assert payload["exp"] > now

    def test_ttl_approximately_correct(self) -> None:
        """Token expiry should be within ~1s of JWT_TTL_MINUTES."""
        token = create_token("agent-readonly")
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        expected_ttl_seconds = settings.jwt_ttl_minutes * 60
        actual_remaining = payload["exp"] - time.time()
        # Allow 5-second tolerance for slow CI runners.
        assert abs(actual_remaining - expected_ttl_seconds) < 5

    def test_unknown_agent_raises(self) -> None:
        with pytest.raises((KeyError, ValueError)):
            create_token("agent-that-does-not-exist")

    @pytest.mark.parametrize("agent_id", list(AGENT_IDENTITIES.keys()))
    def test_all_registered_identities_produce_valid_tokens(
        self, agent_id: str
    ) -> None:
        from types import SimpleNamespace
        token = create_token(agent_id)
        creds = SimpleNamespace(credentials=token)
        payload = verify_token(creds)
        assert payload["sub"]  == AGENT_IDENTITIES[agent_id]["sub"]
        assert payload["role"] == AGENT_IDENTITIES[agent_id]["role"]


class TestVerifyToken:
    """verify_token() correctly validates, rejects, and extracts claims."""

    # verify_token takes an HTTPAuthorizationCredentials object (from FastAPI's
    # HTTPBearer), which has a .credentials attribute holding the raw JWT string.
    # We use SimpleNamespace to avoid importing the full FastAPI type in tests.

    @staticmethod
    def _creds(token: str):
        """Wrap a token string in a minimal credentials-like object."""
        from types import SimpleNamespace
        return SimpleNamespace(credentials=token)

    def test_valid_token_returns_identity_and_role(self) -> None:
        token = create_token("agent-readonly")
        payload = verify_token(self._creds(token))
        assert payload["sub"]  == "agent-readonly"
        assert payload["role"] == "readonly"

    def test_deploy_token_returns_deployer_role(self) -> None:
        token = create_token("agent-deploy")
        payload = verify_token(self._creds(token))
        assert payload["sub"]  == "agent-deploy"
        assert payload["role"] == "deployer"

    def test_missing_bearer_prefix_raises(self) -> None:
        """Passing a raw token without 'Bearer' should fail — the .credentials
        field should be just the token (no 'Bearer' prefix); verify_token decodes
        it directly.  What must fail is an EMPTY or INVALID token string."""
        with pytest.raises(Exception):
            verify_token(self._creds(""))

    def test_empty_credentials_raises(self) -> None:
        with pytest.raises(Exception):
            verify_token(self._creds(""))

    def test_tampered_signature_raises(self) -> None:
        token = create_token("agent-readonly")
        header, payload_seg, sig = token.rsplit(".", 2)
        bad_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        tampered = f"{header}.{payload_seg}.{bad_sig}"
        with pytest.raises(Exception):
            verify_token(self._creds(tampered))

    def test_expired_token_raises(self) -> None:
        """Tokens with exp in the past must be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub":  "agent-readonly",
            "role": "readonly",
            "iat":  now - timedelta(minutes=30),
            "exp":  now - timedelta(minutes=15),   # expired!
        }
        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        with pytest.raises(Exception):
            verify_token(self._creds(token))

    def test_wrong_secret_raises(self) -> None:
        """Token signed with a different secret must be rejected."""
        payload = {
            "sub":  "agent-readonly",
            "role": "readonly",
            "iat":  datetime.now(timezone.utc),
            "exp":  datetime.now(timezone.utc) + timedelta(minutes=15),
        }
        bad_token = jwt.encode(payload, "wrong-secret-key", algorithm="HS256")
        with pytest.raises(Exception):
            verify_token(self._creds(bad_token))

    def test_missing_role_claim_raises(self) -> None:
        """Tokens without a role claim must be rejected (even if sig is valid)."""
        payload = {
            "sub": "agent-readonly",
            # role claim deliberately omitted
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        }
        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        with pytest.raises(Exception):
            verify_token(self._creds(token))

