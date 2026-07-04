"""
Rule-based risk scorer for AI agent actions.

Scoring model (v2 — content-aware)
────────────────────────────────────
The final score is the sum of four independent dimensions:

  1. Action weight     (verb destructiveness)
     get / list / watch                   →  0  (read-only, no state change)
     create / update / patch / apply      →  1  (mutating)
     delete / replace / exec              →  2  (destructive or highly privileged)

  2. Namespace weight  (target sensitivity)
     kube-system / kube-public / kube-node-lease  →  +2
     any other namespace                           →  +0

  3. Resource weight   (data sensitivity)
     secrets / roles / rolebindings / serviceaccounts  →  +1
     all other resources                               →  +0

  4. Payload inspection (NEW in v2 — params dict)
     privileged=true                          →  +3  (container escape risk)
     hostNetwork / hostPID / hostIPC = true   →  +2  (host access)
     hostPath volume mount present            →  +2  (read host filesystem)
     image not in trusted registry list       →  +1  (unknown code origin)
     replicas > threshold                     →  +1  (resource exhaustion risk)

Risk bands
──────────
  0–1   →  LOW     — execute after OPA allow
  2–3   →  MEDIUM  — execute after OPA allow
  4+    →  HIGH    — OPA-allowed actions still require human approval

Examples
────────
  list pods default              →  0              LOW
  create nginx:alpine in demo    →  1              LOW
  delete pod in default          →  2              MEDIUM
  create privileged container    →  1 + 3 = 4      HIGH  (+ OPA deny)
  create untrusted image         →  1 + 1 = 2      MEDIUM (+ OPA deny)
  delete secret in kube-system   →  2 + 2 + 1 = 5  HIGH  (+ OPA deny)
"""

from __future__ import annotations

from typing import Any

from app.config import settings

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

ACTION_WEIGHTS: dict[str, int] = {
    "get": 0,
    "list": 0,
    "watch": 0,
    "create": 1,
    "update": 1,
    "patch": 1,
    "apply": 1,
    "delete": 2,
    "replace": 2,
    "exec": 2,
}

HIGH_RISK_NAMESPACES: frozenset[str] = frozenset(
    {"kube-system", "kube-public", "kube-node-lease"}
)

SENSITIVE_RESOURCES: frozenset[str] = frozenset(
    {
        "secret",
        "secrets",
        "role",
        "roles",
        "rolebinding",
        "rolebindings",
        "clusterrole",
        "clusterroles",
        "clusterrolebinding",
        "clusterrolebindings",
        "serviceaccount",
        "serviceaccounts",
    }
)

# Security context fields that allow container-to-host escape.
PRIVILEGED_FIELDS: dict[str, int] = {
    "privileged": 3,  # full container escape — highest risk
    "hostNetwork": 2,  # shares host network stack
    "hostPID": 2,  # can see and signal all host processes
    "hostIPC": 2,  # shares host IPC namespace
    "hostPath": 2,  # mounts host filesystem paths
}

# Verbs that accept a workload payload worth inspecting.
WRITE_VERBS: frozenset[str] = frozenset(
    {"create", "update", "patch", "apply", "replace"}
)


# ---------------------------------------------------------------------------
# Output types (kept as plain classes for compatibility — no NamedTuple
# so we can use dataclass-style defaults)
# ---------------------------------------------------------------------------


class RiskLevel:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskScore:
    """Result of a risk scoring operation."""

    def __init__(self, level: str, score: int, reasons: list[str]) -> None:
        self.level = level
        self.score = score
        self.reasons = reasons

    def __repr__(self) -> str:
        return f"RiskScore(level={self.level!r}, score={self.score}, reasons={self.reasons})"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score(
    action: str,
    resource: str,
    namespace: str,
    params: dict[str, Any] | None = None,
) -> RiskScore:
    """
    Compute the risk score for a single agent action.

    Args:
        action:    Kubernetes verb (case-insensitive).
        resource:  Kubernetes resource kind (case-insensitive).
        namespace: Target namespace (case-insensitive).
        params:    Optional payload dict (e.g. image, replicas, securityContext
                   fields).  Inspected for dangerous configurations on write
                   actions.  Ignored for read-only actions.

    Returns:
        A ``RiskScore`` with the band, raw integer, and human-readable reasons
        suitable for audit records and OPA input.
    """
    reasons: list[str] = []
    total = 0

    action_lower = action.lower().strip()
    ns_lower = namespace.lower().strip()
    resource_lower = resource.lower().strip()

    # ── 1. Action weight ─────────────────────────────────────────────────
    action_pts = ACTION_WEIGHTS.get(action_lower, 1)  # unknown verbs = medium
    total += action_pts
    reasons.append(f"action '{action_lower}' -> +{action_pts}")

    # ── 2. Namespace weight ──────────────────────────────────────────────
    if ns_lower in HIGH_RISK_NAMESPACES:
        total += 2
        reasons.append(f"namespace '{ns_lower}' is a privileged system namespace -> +2")

    # ── 3. Resource sensitivity ──────────────────────────────────────────
    if resource_lower in SENSITIVE_RESOURCES:
        total += 1
        reasons.append(
            f"resource '{resource_lower}' stores credentials or RBAC grants -> +1"
        )

    # ── 4. Payload inspection (write actions only) ────────────────────────
    if params and action_lower in WRITE_VERBS:
        bucket = _ScoreBucket(0)
        _score_params(params, reasons, bucket)
        total += bucket.value

    # ── Classify ──────────────────────────────────────────────────────────
    if total <= 1:
        level = RiskLevel.LOW
    elif total <= 3:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH

    return RiskScore(level=level, score=total, reasons=reasons)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _ScoreBucket:
    """Mutable integer bucket so helpers can accumulate a sub-score."""

    def __init__(self, initial: int = 0) -> None:
        self.value = initial


def _score_params(
    params: dict[str, Any],
    reasons: list[str],
    bucket: _ScoreBucket,
) -> None:
    """
    Inspect a flat params dict for dangerous security configurations.

    Mutates ``reasons`` and ``bucket`` in place.
    """
    # ── Dangerous security context fields ────────────────────────────────
    for field, pts in PRIVILEGED_FIELDS.items():
        val = params.get(field)
        if val is True:
            bucket.value += pts
            reasons.append(f"params.{field}=true grants host-level access -> +{pts}")

    # ── Image trust check ─────────────────────────────────────────────────
    image: str = str(params.get("image", "")).strip()
    if image and not _is_trusted_image(image):
        bucket.value += 1
        reasons.append(
            f"image '{image}' is not from a trusted registry "
            f"(trusted prefixes: {settings.trusted_image_prefixes}) -> +1"
        )

    # ── Replica count ─────────────────────────────────────────────────────
    try:
        replicas = int(params.get("replicas", 1))
    except (ValueError, TypeError):
        replicas = 1

    if replicas > settings.max_replicas_threshold:
        bucket.value += 1
        reasons.append(
            f"replicas={replicas} exceeds gateway threshold of "
            f"{settings.max_replicas_threshold} -> +1"
        )


def _is_trusted_image(image: str) -> bool:
    """Return True if the image string starts with a trusted registry prefix."""
    return any(image.startswith(prefix) for prefix in settings.trusted_image_prefixes)
