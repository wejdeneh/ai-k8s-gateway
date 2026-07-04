# ADR 0004: Explicit Dispatch Table vs. Generic Kubernetes API Proxy

## Status
Accepted

## Context
The gateway executes approved actions on the Kubernetes cluster. There are two primary architectural designs for the client component:
1. **Generic API Proxy**: Accept raw JSON payloads (manifests or kubectl commands) from the AI agent and forward them directly to the Kubernetes API server endpoint (acting as a dynamic proxy).
2. **Explicit Dispatch Table**: Map specific `(action, resource)` pairs to explicit, tightly configured Python SDK calls, rejecting any unregistered combinations.

## Decision
We choose the **Explicit Dispatch Table** pattern.

The Kubernetes client module (`app/k8s/client.py`) only exposes explicit methods (e.g. `list_pods`, `create_deployment`) inside a static routing router function (`_dispatch`). Any request containing resource kinds or actions not registered in this routing table is rejected at the code level.

## Justification
- **Reduction of Attack Surface**: AI agents are highly vulnerable to prompt injection or model hallucination. A generic reverse proxy allows an attacker to call arbitrary Kubernetes APIs (e.g., modifying RBAC rules, executing web shells, deleting namespaces) if they bypass OPA. The dispatch table limits the attack surface exclusively to the exact API operations needed by the agent.
- **Payload Integrity & Secure Defaults**: In `_build_deployment`, the gateway overrides or injects security configurations (resource limits, runAsNonRoot, allowPrivilegeEscalation: false) at the SDK level. This guarantees that all gateway-created resources comply with cluster security policies.
- **Fail-Safe Output Serialization**: The gateway translates Kubernetes API responses into clean, filtered dictionaries before returning them to the agent. This prevents sensitive data leakage (such as secret data values or cluster private IPs) that standard raw API responses might contain.

## Consequences

### Positive
- Strict, code-level limit on the gateway's capabilities.
- Prevents data leakage of cluster internals.
- Enforces secure container configurations by default.

### Negative
- High maintenance overhead: adding support for a new resource (e.g., `Ingress`, `Service`) requires modifying the dispatch table, updating the Kubernetes ClusterRole, and rebuilding the gateway.
