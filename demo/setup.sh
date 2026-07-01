#!/usr/bin/env bash
# =============================================================================
# demo/setup.sh — Auto-provision a local kind cluster for the gateway demo.
# =============================================================================
#
# What this script does:
#   1. Verifies prerequisites (kind, kubectl, docker).
#   2. Creates a kind cluster named "agent-gw-demo" (idempotent — safe to
#      re-run if the cluster already exists).
#   3. Switches kubectl context to the new cluster.
#   4. Creates a "demo" namespace.
#   5. Deploys a sample nginx workload so the demo has real pods to list/get.
#
# Prerequisites (install once, then never think about it again):
#   kind     https://kind.sigs.k8s.io/docs/user/quick-start/#installation
#   kubectl  https://kubernetes.io/docs/tasks/tools/
#   docker   https://docs.docker.com/get-docker/
#
# Usage:
#   bash demo/setup.sh
#   # Takes 30-60 seconds on first run; idempotent on subsequent runs.
# =============================================================================

set -euo pipefail

CLUSTER_NAME="agent-gw-demo"
NAMESPACE="demo"

# ANSI colours for readability in terminal output.
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'  # reset

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AI Agent Kubernetes Security Gateway — Demo Cluster Setup  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# 1. Check prerequisites
# =============================================================================
info "Checking prerequisites…"

MISSING=()
for cmd in kind kubectl docker; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING+=("$cmd")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    error "The following tools are not installed: ${MISSING[*]}"
    echo ""
    echo "  kind     → https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    echo "  kubectl  → https://kubernetes.io/docs/tasks/tools/"
    echo "  docker   → https://docs.docker.com/get-docker/"
    echo ""
    exit 1
fi
success "kind, kubectl, docker — all found."

# =============================================================================
# 2. Verify Docker is running
# =============================================================================
if ! docker info &>/dev/null; then
    error "Docker daemon is not running.  Start Docker Desktop and re-run."
    exit 1
fi
success "Docker daemon is running."

# =============================================================================
# 3. Create kind cluster (idempotent)
# =============================================================================
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    success "kind cluster '${CLUSTER_NAME}' already exists — reusing it."
else
    info "Creating kind cluster '${CLUSTER_NAME}' (this takes ~30-60 seconds)…"
    kind create cluster --name "$CLUSTER_NAME" --wait 90s
    success "kind cluster '${CLUSTER_NAME}' created."
fi

# =============================================================================
# 4. Switch kubectl context
# =============================================================================
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
success "kubectl context → kind-${CLUSTER_NAME}"

# Verify connectivity.
if ! kubectl cluster-info &>/dev/null; then
    error "Cannot reach the API server.  Check that kind and Docker are working."
    exit 1
fi
success "Cluster API server is reachable."

# =============================================================================
# 5. Create demo namespace
# =============================================================================
if kubectl get namespace "$NAMESPACE" &>/dev/null; then
    success "Namespace '${NAMESPACE}' already exists."
else
    kubectl create namespace "$NAMESPACE"
    success "Namespace '${NAMESPACE}' created."
fi

# =============================================================================
# 6. Deploy sample nginx workload (so the demo has real pods to observe)
# =============================================================================
info "Deploying sample nginx workload in namespace '${NAMESPACE}'…"

kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sample-nginx
  namespace: ${NAMESPACE}
  labels:
    managed-by: ai-k8s-gateway-demo
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sample-nginx
  template:
    metadata:
      labels:
        app: sample-nginx
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
        resources:
          requests:
            cpu: "50m"
            memory: "32Mi"
          limits:
            cpu: "100m"
            memory: "64Mi"
EOF

success "sample-nginx deployment applied in namespace '${NAMESPACE}'."

# Wait for pods to be scheduled (not necessarily Running — we just need them
# to exist so the demo's list-pods call returns real results).
info "Waiting for pods to be scheduled (up to 30s)…"
kubectl wait --for=condition=Available --timeout=30s \
    deployment/sample-nginx -n "$NAMESPACE" 2>/dev/null || \
    warn "Pods are not yet Ready — the demo will still work; they just won't all show as Running."

# =============================================================================
# Done
# =============================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Cluster is ready!  Run the demo:                           ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   # Terminal 1 — start the gateway + OPA                    ║${NC}"
echo -e "${GREEN}║   docker-compose up                                          ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   # Terminal 2 — run the end-to-end demo                    ║${NC}"
echo -e "${GREEN}║   python demo/agent_client.py                               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
