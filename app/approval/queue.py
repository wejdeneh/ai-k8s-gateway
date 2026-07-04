"""
In-memory human-approval queue for high-risk agent actions.

When the risk scorer returns "high" for an OPA-allowed action, the gateway
does NOT forward it to Kubernetes immediately.  Instead it enqueues the
request here and returns HTTP 202 with a ``request_id``.

A human operator then uses two API endpoints to manage the queue:

  GET  /pending              — list all items awaiting approval
  POST /approve/{request_id} — approve or deny a specific item

Approved items are forwarded to the Kubernetes client by the gateway.
Denied items are discarded and the audit record is updated.

Architecture note
─────────────────
This is an in-memory v1 implementation.  In production you would replace
the dict with a durable store (Redis, PostgreSQL) so that pending approvals
survive gateway restarts and can be shared across horizontally-scaled
gateway replicas.  The public interface (enqueue / list_pending / resolve)
is intentionally simple so that swapping the backend is a single-module
change.

Thread-safety
─────────────
FastAPI may call these methods from multiple threads concurrently.
A ``threading.Lock`` protects the internal dict; there is no async lock
because these operations are all O(1) and complete without blocking I/O.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Optional


class PendingRequest:
    """
    Snapshot of a high-risk agent action that is waiting for human review.

    All fields are captured at enqueue time so the queue entry is immutable
    and survives any subsequent mutation of the original request context.
    """

    def __init__(
        self,
        *,
        request_id: str,
        identity: str,
        role: str,
        action: str,
        resource: str,
        namespace: str,
        params: dict[str, Any],
        risk_level: str,
        risk_score: int,
        risk_reasons: list[str],
    ) -> None:
        self.request_id = request_id
        self.identity = identity
        self.role = role
        self.action = action
        self.resource = resource
        self.namespace = namespace
        self.params = params
        self.risk_level = risk_level
        self.risk_score = risk_score
        self.risk_reasons = risk_reasons
        self.queued_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON responses."""
        return {
            "request_id": self.request_id,
            "identity": self.identity,
            "role": self.role,
            "action": self.action,
            "resource": self.resource,
            "namespace": self.namespace,
            "params": self.params,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "risk_reasons": self.risk_reasons,
            "queued_at": self.queued_at,
        }


class ApprovalQueue:
    """Thread-safe in-memory queue for pending high-risk actions."""

    def __init__(self) -> None:
        # dict[request_id → PendingRequest]
        self._queue: dict[str, PendingRequest] = {}
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────

    def enqueue(self, request: PendingRequest) -> str:
        """
        Add a request to the pending queue.

        Args:
            request: The PendingRequest to store.

        Returns:
            The ``request_id`` string (for convenience in the caller).
        """
        with self._lock:
            self._queue[request.request_id] = request
        return request.request_id

    def list_pending(self) -> list[dict[str, Any]]:
        """
        Return a snapshot of all pending requests as a list of dicts.

        The snapshot is taken under the lock but the returned list is a copy,
        so callers may iterate it freely without holding the lock.
        """
        with self._lock:
            return [r.to_dict() for r in self._queue.values()]

    def resolve(self, request_id: str) -> Optional["PendingRequest"]:
        """
        Remove and return the request identified by ``request_id``.

        Returns:
            The ``PendingRequest`` if found, or ``None`` if the ID is unknown
            (already resolved, never existed, or mistyped).
        """
        with self._lock:
            return self._queue.pop(request_id, None)

    def peek(self, request_id: str) -> Optional["PendingRequest"]:
        """Return the request without removing it (useful for status checks)."""
        with self._lock:
            return self._queue.get(request_id)

    @property
    def size(self) -> int:
        """Current number of items in the queue."""
        with self._lock:
            return len(self._queue)


# ---------------------------------------------------------------------------
# Module-level singleton — the FastAPI app imports this directly.
# ---------------------------------------------------------------------------
approval_queue = ApprovalQueue()
