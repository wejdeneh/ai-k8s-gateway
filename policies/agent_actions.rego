# =============================================================================
# AI Agent Kubernetes Security Gateway — OPA Authorization Policy (v2)
# =============================================================================
#
# Package : agent.authz
# Query   : POST /v1/data/agent/authz
#
# Input shape (v2 — now includes params for content-aware evaluation):
#   {
#     "input": {
#       "identity":   "agent-deploy",
#       "role":       "deployer",
#       "action":     "create",
#       "resource":   "deployments",
#       "namespace":  "demo",
#       "risk_level": "high",
#       "params": {
#         "name":       "my-app",
#         "image":      "malicious:latest",   ← now evaluated!
#         "privileged": true,                 ← now evaluated!
#         "replicas":   100                   ← now evaluated!
#       }
#     }
#   }
#
# Output:
#   { "result": { "allow": true/false, "reason": "...", "deny_reasons": [...] } }
#
# Policy layers
# ─────────────
#   Layer 1 (role + verb):    readonly/deployer RBAC rules
#   Layer 2 (namespace):      privileged namespaces block mutations
#   Layer 3 (resource type):  secrets/RBAC resources block mutations
#   Layer 4 (payload):        image trust, container privileges, replica limits
#
# Default is DENY — requests must match an allow rule to proceed.
# =============================================================================

package agent.authz

import future.keywords

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

read_only_actions := {"get", "list", "watch"}
write_actions     := {"create", "update", "patch", "apply"}
delete_actions    := {"delete", "replace", "exec"}

privileged_namespaces := {"kube-system", "kube-public", "kube-node-lease"}

sensitive_resources := {
    "secret", "secrets",
    "role", "roles",
    "rolebinding", "rolebindings",
    "clusterrole", "clusterroles",
    "clusterrolebinding", "clusterrolebindings",
    "serviceaccount", "serviceaccounts",
}

# Image registry prefixes considered trusted.
# Sync this with settings.trusted_image_prefixes in app/config.py.
trusted_image_prefixes := [
    "nginx:",
    "python:",
    "alpine:",
    "busybox:",
    "gcr.io/",
    "quay.io/",
    "registry.k8s.io/",
]

# Maximum replica count permitted via the gateway.
max_replicas := 10

# ---------------------------------------------------------------------------
# Default: deny everything not explicitly allowed
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Allow rules (Layer 1 + 2 + 3)
# ---------------------------------------------------------------------------

# Rule A — readonly: any read-only verb on any resource.
allow if {
    input.role in {"readonly"}
    input.action in read_only_actions
}

# Rule B — deployer: read-only verbs anywhere.
allow if {
    input.role in {"deployer"}
    input.action in read_only_actions
}

# Rule C — deployer: write verbs, outside privileged namespaces,
#           on non-sensitive resources, AND passing payload inspection.
allow if {
    input.role in {"deployer"}
    input.action in write_actions
    not input.namespace in privileged_namespaces
    not input.resource in sensitive_resources
    # Payload must also pass — no allow if the image or securityContext is bad.
    count(payload_violations) == 0
}

# ---------------------------------------------------------------------------
# Deny reasons — Layer 1/2/3 (role + namespace + resource)
# ---------------------------------------------------------------------------

deny_reasons contains msg if {
    input.action in delete_actions
    msg := sprintf(
        "action '%v' is never permitted via the AI agent gateway — deletes require manual kubectl access",
        [input.action],
    )
}

deny_reasons contains msg if {
    input.namespace in privileged_namespaces
    input.action in write_actions
    msg := sprintf(
        "mutations in namespace '%v' are forbidden — control-plane namespaces require manual intervention",
        [input.namespace],
    )
}

deny_reasons contains msg if {
    input.role == "readonly"
    not input.action in read_only_actions
    msg := sprintf(
        "role 'readonly' cannot perform '%v' — only get/list/watch are permitted",
        [input.action],
    )
}

deny_reasons contains msg if {
    input.role == "deployer"
    input.action in write_actions
    input.resource in sensitive_resources
    msg := sprintf(
        "mutations to '%v' are forbidden — secrets and RBAC resources require human review",
        [input.resource],
    )
}

deny_reasons contains msg if {
    not input.role in {"readonly", "deployer"}
    msg := sprintf(
        "unrecognised role '%v' — no allow rules matched",
        [input.role],
    )
}

# ---------------------------------------------------------------------------
# Deny reasons — Layer 4 (payload / content-aware)
# ---------------------------------------------------------------------------

# payload_violations is a helper set used both in the allow rule (to block
# writes with bad payloads) and contributed to deny_reasons below.

payload_violations contains msg if {
    input.action in write_actions
    input.params.privileged == true
    msg := "params.privileged=true grants full container escape — not permitted via the gateway"
}

payload_violations contains msg if {
    input.action in write_actions
    input.params.hostNetwork == true
    msg := "params.hostNetwork=true grants direct access to the host network stack — not permitted"
}

payload_violations contains msg if {
    input.action in write_actions
    input.params.hostPID == true
    msg := "params.hostPID=true allows visibility into all host processes — not permitted"
}

payload_violations contains msg if {
    input.action in write_actions
    input.params.hostIPC == true
    msg := "params.hostIPC=true shares the host IPC namespace — not permitted"
}

payload_violations contains msg if {
    input.action in write_actions
    image := input.params.image
    image != ""
    image != null
    not _is_trusted_image(image)
    msg := sprintf(
        "image '%v' is not from a trusted registry — only images matching %v are permitted",
        [image, trusted_image_prefixes],
    )
}

payload_violations contains msg if {
    input.action in write_actions
    replicas := input.params.replicas
    replicas > max_replicas
    msg := sprintf(
        "replicas=%v exceeds the agent gateway limit of %v — potential resource exhaustion",
        [replicas, max_replicas],
    )
}

# Propagate all payload violations into the top-level deny_reasons set.
deny_reasons contains msg if {
    some msg in payload_violations
}

# ---------------------------------------------------------------------------
# reason — single string for the gateway to log and return to callers
# ---------------------------------------------------------------------------

reason := "Allowed by policy." if { allow }

reason := concat("; ", deny_reasons) if {
    not allow
    count(deny_reasons) > 0
}

reason := "Denied: default deny — no allow rule matched." if {
    not allow
    count(deny_reasons) == 0
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# _is_trusted_image succeeds if the image starts with any trusted prefix.
_is_trusted_image(image) if { startswith(image, "nginx:")            }
_is_trusted_image(image) if { startswith(image, "python:")           }
_is_trusted_image(image) if { startswith(image, "alpine:")           }
_is_trusted_image(image) if { startswith(image, "busybox:")          }
_is_trusted_image(image) if { startswith(image, "gcr.io/")           }
_is_trusted_image(image) if { startswith(image, "quay.io/")          }
_is_trusted_image(image) if { startswith(image, "registry.k8s.io/")  }
