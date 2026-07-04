# ADR 0002: Localhost OPA Sidecar vs. Embedded Policy Libraries

## Status
Accepted

## Context
The policy-enforcement gateway must make complex access control and payload parameter authorization decisions. There are two primary architectural options for evaluating policies:
1. **Embedded Python Rules**: Implement the security rules directly inside the FastAPI codebase using custom Python logic or JSON schema checkers.
2. **Out-of-Process Open Policy Agent (OPA) Sidecar**: Deploy the official CNCF OPA server alongside the gateway and query it via REST API.

## Decision
We choose the **Out-of-Process Open Policy Agent (OPA) Sidecar** pattern.

Every deployment pod will run the gateway container and an OPA container side-by-side. The gateway communicates with the sidecar over `127.0.0.1:8181` to avoid network latency and keep policy evaluations fast (sub-millisecond overhead).

## Justification
- **Separation of Concerns**: Security policies are written in declarative Rego language (`policies/agent_actions.rego`), separating security rule logic from the FastAPI routing/application code.
- **Industry Standard**: OPA is the industry-standard policy engine, used by organizations like Netflix, Cloudflare, and Goldman Sachs. Decoupling policy makes it easier for security teams to audit and update rules independently from the application code.
- **Declarative Power**: Rego is designed for hierarchical data inspection (like nested Kubernetes manifests) and naturally supports complex rule structures, sets, and helper variables.
- **Fail-Closed Integration**: OPA is queried inside a fail-closed try-except block. If OPA is unavailable, we deny the request by default.

## Consequences

### Positive
- Policies are highly auditable, modular, and can be tested independently using OPA CLI tool chains (`opa test`).
- Gateway code remains focused on HTTP routing, JWT verification, and audit logging.

### Negative
- Deploying the gateway requires running two containers per pod, slightly increasing the resource footprint.
- A HTTP REST hop over localhost is introduced for every request (typically < 2ms latency).
