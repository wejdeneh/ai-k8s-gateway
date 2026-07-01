#!/usr/bin/env bash
# =============================================================================
# k8s/gatekeeper/install.sh — Install OPA Gatekeeper and apply all constraints
# =============================================================================
#
# OPA Gatekeeper is the Kubernetes-native admission controller that enforces
# policies at the API server level — BEFORE any workload is stored in etcd.
# It acts as a last line of defence that works even if the AI agent gateway
# is bypassed (e.g., via a compromised kubeconfig or direct kubectl access).
#
# This script:
#   1. Installs OPA Gatekeeper via the official release manifest
#   2. Waits for Gatekeeper's webhook to become ready
#   3. Applies all ConstraintTemplates (define the policy shape)
#   4. Applies all Constraints (activate the policy on the cluster)
#
# Usage:
#   bash k8s/gatekeeper/install.sh
#   make gatekeeper
#
# Prerequisites: kubectl pointed at the kind cluster (run demo/setup.sh first)
# =============================================================================

set -euo pipefail

GATEKEEPER_VERSION="v3.16.3"
GATEKEEPER_URL="https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AI Agent Gateway — Installing OPA Gatekeeper              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# 1. Install Gatekeeper (idempotent — apply is safe to re-run)
# =============================================================================
info "Installing OPA Gatekeeper ${GATEKEEPER_VERSION}…"
kubectl apply -f "$GATEKEEPER_URL"
success "Gatekeeper manifests applied."

# =============================================================================
# 2. Wait for Gatekeeper controller to be ready
# =============================================================================
info "Waiting for Gatekeeper controller-manager (up to 120s)…"
kubectl rollout status deployment/gatekeeper-controller-manager \
    -n gatekeeper-system --timeout=120s
success "Gatekeeper controller-manager is ready."

info "Waiting for Gatekeeper audit deployment (up to 60s)…"
kubectl rollout status deployment/gatekeeper-audit \
    -n gatekeeper-system --timeout=60s
success "Gatekeeper audit deployment is ready."

# Brief pause — the webhook needs a moment to register before we apply
# ConstraintTemplates (which themselves go through admission).
sleep 5

# =============================================================================
# 3. Apply ConstraintTemplates
# =============================================================================
info "Applying ConstraintTemplates…"
kubectl apply -f "${SCRIPT_DIR}/templates/"
success "ConstraintTemplates applied."

# Wait for CRDs to be established before applying Constraints.
info "Waiting for Constraint CRDs to be established (up to 30s)…"
kubectl wait --for=condition=Established \
    crd/k8snoprivilegedcontainer.constraints.gatekeeper.sh \
    crd/k8sallowedrepos.constraints.gatekeeper.sh \
    crd/k8srequirelimits.constraints.gatekeeper.sh \
    --timeout=30s 2>/dev/null || \
    warn "Some CRDs not yet established — retrying after 10s…" && sleep 10

# =============================================================================
# 4. Apply Constraints
# =============================================================================
info "Applying Constraints…"
kubectl apply -f "${SCRIPT_DIR}/constraints/"
success "Constraints applied."

# =============================================================================
# Done
# =============================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Gatekeeper is active!  Verify with:                       ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   kubectl get constraints                                    ║${NC}"
echo -e "${GREEN}║   kubectl get constrainttemplates                            ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   Test (should be rejected):                                 ║${NC}"
echo -e "${GREEN}║   kubectl run bad --image=malicious:latest -n demo           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
