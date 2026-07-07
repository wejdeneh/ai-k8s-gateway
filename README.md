# KubeShield -- AI Agent Kubernetes Security Gateway

> **Portfolio project** — a production-pattern, defence-in-depth security gateway
> that sits between an AI agent and a Kubernetes cluster, ensuring no action reaches
> the cluster without authentication, risk scoring, OPA policy evaluation, and
> (for high-risk actions) explicit human approval.

---

<!-- After recording a demo, embed it here:
![Demo recording](./demo/demo.gif)
-->

## Architecture — Defence in Depth

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AI Agent (client)                          │
│           demo/agent_client.py  ·  any HTTP client  ·  SDK          │
└───────────────────────────────────┬─────────────────────────────────┘
                                    │  POST /agent-action
                                    │  Authorization: Bearer <JWT>
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Layer 1 — FastAPI Enforcement Gateway                  │
│                                                                     │
│  ① JWT verification   → HS256, 15-min TTL                           │
│  ② Risk scorer        → action + namespace + resource + PAYLOAD     │
│                          (image trust, privileged flag, replicas)   │
│  ③ OPA policy         → role-based + content-aware deny rules       │
│  ④ Audit log          → append-only JSONL, every request            │
│  ⑤ Dispatch           → deny=403, high-risk=queue(202), allow→k8s  │
│                                                                     │
│  Blocked by Layer 1:                                                │
│    • Unauthenticated requests                                       │
│    • Wrong-role mutations (readonly tries to create)                │
│    • privileged=true containers                                     │
│    • Untrusted image registries                                     │
│    • > 10 replicas (DoS prevention)                                 │
│    • Writes to kube-system                                          │
│    • Mutations to secrets/RBAC resources                            │
│    • All delete/exec/replace verbs                                  │
└─────────────────────────────────────────────────────────────────────┘
     │                    │                         │
     ▼                    ▼                         ▼
 OPA sidecar      Approval queue             Kubernetes API
 (Rego policy)    GET /pending              (kind cluster)
                  POST /approve/{id}
                                                    │
                                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│       Layer 2 — OPA Gatekeeper (Kubernetes Admission Controller)    │
│                                                                     │
│  Enforces the SAME policies at the k8s API server level.            │
│  Activates even when the gateway is bypassed (stolen kubeconfig,    │
│  direct kubectl, misconfigured service account, etc.)               │
│                                                                     │
│  Constraints (k8s/gatekeeper/):                                     │
│    • K8sNoPrivilegedContainer  — blocks privileged/hostNetwork/PID  │
│    • K8sAllowedRepos           — blocks untrusted image registries  │
│    • K8sRequireLimits          — requires CPU + memory limits       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│       Layer 3 — Falco Runtime Security                               │
│                                                                     │
│  Watches kernel syscalls from running containers.  Fires CRITICAL   │
│  alerts even for workloads admitted by Layers 1 & 2 that exhibit   │
│  anomalous runtime behaviour.                                       │
│                                                                     │
│  Rules (k8s/falco/rules.yaml):                                      │
│    • CRITICAL  Shell spawned in container                           │
│    • CRITICAL  Cryptomining process detected (xmrig, stratum+tcp)  │
│    • HIGH      Sensitive host file read (/etc/shadow, admin.conf)  │
│    • MEDIUM    Outbound connection on non-standard port             │
│    • WARNING   Package manager executed (apt, pip, npm…)            │
│    • WARNING   Service-account token read by unexpected process     │
└─────────────────────────────────────────────────────────────────────┘
```

### Why three layers?

| Threat | Blocked by |
|---|---|
| Unauthenticated agent | Layer 1 — JWT auth |
| Wrong-role mutation (readonly→create) | Layer 1 — OPA role rules |
| Privileged container via gateway | Layer 1 — OPA payload rules |
| Untrusted image via gateway | Layer 1 — OPA payload rules |
| Same attacks via **direct kubectl** (gateway bypassed) | Layer 2 — Gatekeeper |
| Trusted image that was later compromised | Layer 3 — Falco |
| Cryptominer running inside an admitted container | Layer 3 — Falco |

---

## Component Map

| Component | File | Purpose |
|---|---|---|
| **FastAPI gateway** | `app/main.py` | 5-stage pipeline orchestration |
| **JWT auth** | `app/auth/jwt_handler.py` | Issue & verify short-lived Bearer tokens |
| **Risk scorer (v2)** | `app/risk/scorer.py` | Rule-based: action + namespace + resource + **payload** |
| **Audit logger** | `app/audit/logger.py` | Append-only JSONL; every request, every outcome |
| **OPA policy (v2)** | `policies/agent_actions.rego` | Rego: role-based + content-aware allow/deny |
| **Approval queue** | `app/approval/queue.py` | Thread-safe in-memory queue for high-risk actions |
| **K8s client** | `app/k8s/client.py` | Dispatch table → kubernetes-python SDK; resource limits enforced |
| **Gatekeeper templates** | `k8s/gatekeeper/templates/` | 3 ConstraintTemplates (Rego policies) |
| **Gatekeeper constraints** | `k8s/gatekeeper/constraints/` | 3 Constraints (activate the templates) |
| **Falco rules** | `k8s/falco/rules.yaml` | 6 runtime threat detection rules |
| **Demo script** | `demo/agent_client.py` | 4 scenarios in < 90 seconds |
| **Cluster setup** | `demo/setup.sh` | Auto-provision kind cluster (idempotent) |

---

## Risk Scoring (v2 — content-aware)

The scorer adds four independent weights:

| Dimension | Condition | Points |
|---|---|---|
| **Action** | `get` / `list` / `watch` | +0 |
| | `create` / `update` / `patch` / `apply` | +1 |
| | `delete` / `replace` / `exec` | +2 |
| **Namespace** | `kube-system` / `kube-public` / `kube-node-lease` | +2 |
| **Resource** | `secrets`, `roles`, `rolebindings`, `serviceaccounts`, … | +1 |
| **Payload** | `privileged=true` | +3 |
| | `hostNetwork` / `hostPID` / `hostIPC = true` | +2 each |
| | image not from trusted registry | +1 |
| | `replicas > 10` | +1 |

**Bands:** 0–1 → `low` · 2–3 → `medium` · 4+ → `high`

| Scenario | Score | Level |
|---|---|---|
| `list pods default` | 0 | **low** |
| `create nginx:alpine demo` | 1 | **low** |
| `delete pods default` | 2 | **medium** |
| `create cryptominer:latest demo` | 2 | **medium** (+ OPA deny) |
| `create privileged=true demo` | 4 | **high** (+ OPA deny) |
| `delete secrets kube-system` | 5 | **high** (+ OPA deny) |

---

## OPA Policy (v2 — 4 layers of rules)

`policies/agent_actions.rego` — default is **deny**.

| Layer | Rule | Roles |
|---|---|---|
| 1 | Read-only actions on any resource | `readonly` |
| 2 | Write actions outside `kube-system` on non-sensitive resources | `deployer` |
| 3 | **Never**: `delete` / `replace` / `exec` for anyone | all |
| 4 | **Never**: `privileged=true`, `hostNetwork=true`, untrusted images, >10 replicas | all |

---

## Setup

### Prerequisites

| Tool | Purpose |
|---|---|
| Python 3.11+ | Run the gateway locally |
| Docker + Docker Desktop | OPA sidecar + kind on macOS/Windows |
| `kind` | Local Kubernetes cluster |
| `kubectl` | Verify cluster state |
| `helm` | Install Falco (optional) |

### Quick start (3 commands)

```bash
git clone https://github.com/your-handle/ai-k8s-gateway.git
cd ai-k8s-gateway

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Provision cluster + start gateway + OPA
make setup          # kind cluster (once, ~45s)
make docker-up      # gateway + OPA via docker-compose
make demo           # run all 4 scenarios
```

### Deploy Gateway via Helm (Layer 1 — Production Pattern)

We package the gateway and the OPA sidecar inside a production-ready Helm chart. This automatically configures:
- **Multi-Container Pod**: FastAPI Gateway + OPA Sidecar communicating via localhost loopback (`127.0.0.1:8181`).
- **Secure Network Isolation**: Installs a strict `NetworkPolicy` restricting ingress to port 8000 and blocking all egress except to the Kubernetes API Server and loopback.
- **Autoscaling & High Availability**: Configures a `HorizontalPodAutoscaler` (HPA) scaling between 2 and 10 replicas.
- **Automated Secret Generation**: Enforces secure-by-default secret management by dynamically generating a cryptographically secure 32-character random `JWT_SECRET` at install time.
- **Cloud-Native Logging**: Standard container stdout/stderr logs are output in structured JSON format.

```bash
# Install the Helm Chart
helm install ai-k8s-gateway charts/ai-k8s-gateway --namespace ai-gateway --create-namespace

# Verify gateway & OPA containers are running side-by-side
kubectl get pods -n ai-gateway
```

### Add Gatekeeper (Layer 2) — optional

```bash
make gatekeeper     # installs OPA Gatekeeper + all 3 constraints (~2 min)

# Verify it's enforcing:
kubectl get constraints
kubectl run bad --image=malicious:latest -n demo
# Error: image 'malicious:latest' is not from an approved registry
```

### Add Falco (Layer 3) — optional

```bash
make falco          # installs Falco via Helm (~3 min)

# Watch for alerts:
kubectl logs -l app.kubernetes.io/name=falco -n falco --follow

# Trigger a "Shell spawned in container" CRITICAL alert:
kubectl exec -it -n demo <any-pod> -- /bin/sh
```

---

## Run the demo

```bash
make demo
# or: python demo/agent_client.py
```

**4 scenarios in < 90 seconds:**

| Scenario | Agent | Action | Expected |
|---|---|---|---|
| 1 — Low risk | `agent-readonly` | list pods | ✅ Allow |
| 2 — Medium risk | `agent-deploy` | create deployment | ✅ Allow (cross-check: kube-system → ❌) |
| 3 — High risk | `agent-deploy` | delete in kube-system | ❌ OPA hard-block |
| 4 — Malicious pod | `agent-deploy` | create privileged / untrusted / 50 replicas | ❌ All blocked |

---

## Manual API usage

```bash
# Mint tokens
TOKEN_RO=$(python -m app.auth.mint_tokens --agent agent-readonly --bare)
TOKEN_DEPLOY=$(python -m app.auth.mint_tokens --agent agent-deploy --bare)

# List pods (low risk — allow)
curl -sX POST http://localhost:8000/agent-action \
  -H "Authorization: Bearer $TOKEN_RO" \
  -H "Content-Type: application/json" \
  -d '{"action":"list","resource":"pods","namespace":"demo","params":{}}' | jq .

# Create deployment (medium risk — allow)
curl -sX POST http://localhost:8000/agent-action \
  -H "Authorization: Bearer $TOKEN_DEPLOY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "create", "resource": "deployments", "namespace": "demo",
    "params": {"name": "my-app", "image": "nginx:alpine", "replicas": 2}
  }' | jq .

# Privileged container (HIGH risk — deny)
curl -sX POST http://localhost:8000/agent-action \
  -H "Authorization: Bearer $TOKEN_DEPLOY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "create", "resource": "deployments", "namespace": "demo",
    "params": {"name": "evil", "image": "nginx:alpine", "privileged": true}
  }' | jq .

# Untrusted image (deny)
curl -sX POST http://localhost:8000/agent-action \
  -H "Authorization: Bearer $TOKEN_DEPLOY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "create", "resource": "deployments", "namespace": "demo",
    "params": {"name": "miner", "image": "cryptominer:latest"}
  }' | jq .

# Audit log
cat audit.log | python -m json.tool | head -80
```

---

## Audit log format

Every request appends one JSONL record to `audit.log`:

```json
{
  "timestamp":    "2024-01-15T10:23:45.123456+00:00",
  "request_id":   "a4f7c2d1-...",
  "identity":     "agent-deploy",
  "role":         "deployer",
  "action":       "create",
  "resource":     "deployments",
  "namespace":    "demo",
  "params":       {"name": "my-app", "image": "nginx:alpine", "replicas": 2},
  "risk_level":   "low",
  "risk_score":   1,
  "risk_reasons": ["action 'create' -> +1"],
  "decision":     "allow",
  "opa_reason":   "Allowed by policy.",
  "error":        null
}
```

---

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v

# Expected output:
# tests/test_scorer.py::TestActionWeights::test_action_score[get-0] PASSED
# tests/test_scorer.py::TestParamsInspection::test_privileged_true_adds_three PASSED
# tests/test_jwt.py::TestVerifyToken::test_expired_token_raises PASSED
# tests/test_gateway.py::TestAuthentication::test_missing_authorization_header_returns_401 PASSED
# ... 40+ tests PASSED
```

---

## Project structure

```
ai-k8s-gateway/
├── .github/
│   └── workflows/
│       └── ci.yml            # CI/CD: Ruff, Bandit, Pip-Audit, Kubeconform
├── app/
│   ├── main.py               # FastAPI: 5-stage pipeline
│   ├── config.py             # Pydantic settings (env vars)
│   ├── auth/
│   │   ├── jwt_handler.py    # create_token() and verify_token()
│   │   └── mint_tokens.py    # CLI token minter
│   ├── risk/
│   │   └── scorer.py         # v2 rule-based scorer (params-aware)
│   ├── audit/
│   │   ├── logger.py         # Thread-safe JSONL audit logger
│   │   └── structured_logger.py # Stdout JSON structured logger
│   ├── approval/
│   │   └── queue.py          # Human-approval queue
│   └── k8s/
│       └── client.py         # K8s dispatch table + secure defaults
├── policies/
│   ├── agent_actions.rego    # v2 OPA policy (deny by default)
│   └── agent_actions_test.rego # Rego policy unit tests
├── charts/
│   └── ai-k8s-gateway/       # Helm Chart (Deployments, NetworkPolicies, HPAs, RBAC)
├── k8s/
│   ├── gatekeeper/
│   │   ├── install.sh
│   │   ├── templates/        # 3 ConstraintTemplates
│   │   └── constraints/      # 3 Constraints
│   └── falco/
│       ├── install.sh
│       └── rules.yaml        # 6 runtime detection rules
├── tests/
│   ├── test_scorer.py        # 50+ scorer unit tests
│   ├── test_jwt.py           # JWT handler tests
│   └── test_gateway.py       # Gateway integration tests (OPA mocked)
├── demo/
│   ├── setup.sh              # Auto-provision kind cluster
│   └── agent_client.py       # 4-scenario end-to-end demo
├── Makefile                  # make setup / gatekeeper / falco / demo / test / lint / helm-lint
├── docker-compose.yml        # Gateway + OPA sidecar
├── Dockerfile
├── requirements.txt
├── requirements-dev.txt
├── .env.example
```

---

## Design decisions

### Why OPA fails closed
Network partition between gateway and OPA → deny, not allow. Availability of the policy engine is not a reason to let unvetted actions reach the cluster.

### Why three independent enforcement points for the same image allowlist?
If any one layer has a bug, the others still protect the cluster. Defence in depth is not redundancy for its own sake — it's the assumption that every layer *will* eventually be bypassed.

### Why the K8s client wraps a dispatch table?
Rather than forwarding arbitrary API calls, the table makes the exact attack surface explicit. Every `(action, resource)` pair is a deliberate, auditable decision. Adding a new resource requires a code change and a code review — by design.

### Why HS256 and not RS256?
HS256 (symmetric) keeps key management simple for a local demo. Production should use RS256: gateways sign with the private key; verifiers (including OPA, if you push token claims into policy inputs) only need the public key.

### Why is the approval queue in-memory?
For v1, durability (Redis/Postgres) adds infrastructure without demonstrating new security concepts. The `ApprovalQueue` class has a clean `enqueue / list_pending / resolve` interface — swapping the backend is a single-module change.

---

## Recording a demo (asciinema)

```bash
pip install asciinema       # or brew install asciinema
asciinema rec demo/demo.cast

# Inside the recording:
make setup && make docker-up && make demo

# Ctrl-D to stop

# Convert to GIF (requires agg: cargo install agg)
agg demo/demo.cast demo/demo.gif
# Then uncomment the GIF line at the top of this README
```

---

## License

MIT — see [LICENSE](LICENSE).
