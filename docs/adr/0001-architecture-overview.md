# ADR 0001: Three-Layer Defense-in-Depth Architecture

## Status
Accepted

## Context
When designing a security barrier between an autonomous AI agent and a Kubernetes cluster, we must assume that any single layer of defense can fail or be bypassed. For example:
- A compromise of the gateway's credentials/JWT secret.
- A remote code execution (RCE) vulnerability in the gateway's runtime (Python/FastAPI).
- Direct access to the cluster by a compromised agent that bypasses the API gateway (e.g. stolen Kubeconfig, service account token, or exposed API server).
- Workloads that are safe when initially deployed but behave maliciously at runtime (e.g., dynamic execution of remote code, container escape exploits, web shell execution).

## Decision
We adopt a **Three-Layer Defense-in-Depth Architecture**:

1. **Layer 1: Policy-Enforcement Gateway (Gateway/OPA)**
   - First line of defense.
   - Blocks unauthorized API calls at the perimeter.
   - Evaluates RBAC rules and payload parameters (untrusted images, privileged flags) before executing commands.
   
2. **Layer 2: Admission Control (OPA Gatekeeper)**
   - Second line of defense.
   - Enforced by the Kubernetes API server itself.
   - Acts as a bypass-proof guardrail. Even if an attacker obtains direct `kubeconfig` access and calls the API server directly, Gatekeeper will intercept and block non-compliant manifests.
   
3. **Layer 3: Runtime Threat Detection (Falco)**
   - Third line of defense.
   - Monitors syscalls from the Linux kernel on the host.
   - Catches post-admission compromises (e.g., spawning shell processes inside trusted containers, executing cryptominers, accessing host filesystem paths).

## Consequences

### Positive
- **No Single Point of Failure (SPOF)**: The security posture does not rely on a single software component.
- **Bypass-Proof**: The Kubernetes control plane itself guarantees Layer 2 enforcement.
- **Real-Time Forensic Audit**: Layer 3 logs detect active attacks and compromised workloads in real-time.

### Negative
- **Operational Complexity**: Engineers must maintain and configure rules in three different syntaxes/components (Python risk scorer, Gateway Rego, Gatekeeper Rego, Falco YAML rules).
- **Performance Overhead**: Gatekeeper validation adds latency to pod mutation requests; Falco DaemonSet consumes CPU/memory on every node to parse system calls.
