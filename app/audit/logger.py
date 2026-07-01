"""
Append-only structured audit logger.

Every request that reaches the gateway — regardless of outcome — is written
as a single JSON line to ``audit.log``.  This provides an immutable record
suitable for ingestion by any SIEM or log-aggregation system (Splunk, Elastic,
Loki, CloudWatch Logs Insights, etc.).

Log record schema
─────────────────
  timestamp     ISO-8601 UTC timestamp of when the record was written
  request_id    UUID — correlates this log entry with the HTTP response
  identity      JWT `sub` claim (the agent's stable identifier)
  role          JWT `role` claim
  action        Kubernetes verb from the request body
  resource      Kubernetes resource kind from the request body
  namespace     Target namespace
  params        Full params dict from the request (for complete audit trail)
  risk_level    "low" | "medium" | "high"
  risk_score    Raw additive integer score from the scorer
  risk_reasons  List of scoring rationale strings
  decision      "allow" | "deny" | "pending-approval" | "human-allow" |
                "human-deny"
  opa_reason    Human-readable explanation returned by OPA (or None)
  error         Error message if the gateway itself failed (or None)

Thread-safety
─────────────
FastAPI may execute route handlers in a thread pool when they call blocking
functions.  A threading.Lock protects the log-file append so concurrent
requests never interleave partial writes.
"""

import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import settings

# Module-level lock shared across all threads in this process.
_lock = threading.Lock()


def log(
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
    decision: str,                     # allow / deny / pending-approval / …
    opa_reason: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """
    Append one structured audit record to the log file.

    This function is intentionally synchronous and fail-safe: a log write
    failure prints a warning to stderr but never raises an exception that
    would abort the request pipeline.
    """
    record: dict[str, Any] = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "request_id":   request_id,
        "identity":     identity,
        "role":         role,
        "action":       action,
        "resource":     resource,
        "namespace":    namespace,
        "params":       params,
        "risk_level":   risk_level,
        "risk_score":   risk_score,
        "risk_reasons": risk_reasons,
        "decision":     decision,
        "opa_reason":   opa_reason,
        "error":        error,
    }

    # json.dumps with default=str handles any non-serialisable values (e.g.
    # datetime objects that might appear in params).
    line = json.dumps(record, default=str)

    try:
        with _lock:
            # Mode "a" creates the file if it doesn't exist, then appends.
            # The lock ensures each line is written atomically.
            with open(settings.audit_log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except OSError as exc:
        # Deliberately swallowed — logging must never block a request.
        import sys
        print(
            f"[AUDIT WARNING] Failed to write audit record for "
            f"request_id={request_id!r}: {exc}",
            file=sys.stderr,
        )
