# =============================================================================
# OPA Authorization Policy Unit Tests — policies/agent_actions_test.rego
# =============================================================================
# Runs via OPA CLI:
#   opa test policies/ -v
# =============================================================================

package agent.authz_test

import future.keywords

import data.agent.authz

# ── Read-only role tests ─────────────────────────────────────────────────────

test_readonly_allows_read_actions if {
    authz.allow with input as {
        "identity": "agent-readonly",
        "role": "readonly",
        "action": "list",
        "resource": "pods",
        "namespace": "default",
        "risk_level": "low",
        "params": {}
    }
}

test_readonly_denies_write_actions if {
    not authz.allow with input as {
        "identity": "agent-readonly",
        "role": "readonly",
        "action": "create",
        "resource": "deployments",
        "namespace": "default",
        "risk_level": "low",
        "params": {"name": "app", "image": "nginx:alpine"}
    }
    
    # Assert correct deny reason is returned
    reasons := authz.deny_reasons with input as {
        "identity": "agent-readonly",
        "role": "readonly",
        "action": "create",
        "resource": "deployments",
        "namespace": "default",
        "risk_level": "low",
        "params": {"name": "app", "image": "nginx:alpine"}
    }
    reasons["role 'readonly' cannot perform 'create' — only get/list/watch are permitted"]
}

# ── Deployer role tests ──────────────────────────────────────────────────────

test_deployer_allows_write_actions if {
    authz.allow with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "create",
        "resource": "deployments",
        "namespace": "demo",
        "risk_level": "low",
        "params": {"name": "web", "image": "nginx:alpine", "replicas": 3}
    }
}

test_deployer_denies_delete_actions if {
    not authz.allow with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "delete",
        "resource": "deployments",
        "namespace": "demo",
        "risk_level": "medium",
        "params": {"name": "web"}
    }
}

test_deployer_denies_kube_system_mutations if {
    not authz.allow with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "create",
        "resource": "deployments",
        "namespace": "kube-system",
        "risk_level": "high",
        "params": {"name": "web", "image": "nginx:alpine"}
    }
}

test_deployer_denies_sensitive_resource_mutations if {
    not authz.allow with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "create",
        "resource": "secrets",
        "namespace": "demo",
        "risk_level": "medium",
        "params": {"name": "my-secret"}
    }
}

# ── Payload violation tests (Layer 4) ────────────────────────────────────────

test_deployer_denies_privileged_workload if {
    not authz.allow with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "create",
        "resource": "deployments",
        "namespace": "demo",
        "risk_level": "high",
        "params": {"name": "evil", "image": "nginx:alpine", "privileged": true}
    }
    
    authz.payload_violations["params.privileged=true grants full container escape — not permitted via the gateway"] with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "create",
        "resource": "deployments",
        "namespace": "demo",
        "risk_level": "high",
        "params": {"name": "evil", "image": "nginx:alpine", "privileged": true}
    }
}

test_deployer_denies_untrusted_registry if {
    not authz.allow with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "create",
        "resource": "deployments",
        "namespace": "demo",
        "risk_level": "medium",
        "params": {"name": "evil", "image": "malicious/cryptominer:latest"}
    }
}

test_deployer_denies_excessive_replicas if {
    not authz.allow with input as {
        "identity": "agent-deploy",
        "role": "deployer",
        "action": "create",
        "resource": "deployments",
        "namespace": "demo",
        "risk_level": "medium",
        "params": {"name": "web", "image": "nginx:alpine", "replicas": 50}
    }
}
