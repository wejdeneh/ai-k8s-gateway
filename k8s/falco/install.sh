#!/usr/bin/env bash
# =============================================================================
# k8s/falco/install.sh — Install Falco via Helm for runtime threat detection
# =============================================================================
#
# Falco is a CNCF runtime security tool that watches kernel syscalls and
# fires alerts on suspicious container behaviour.  It is the final layer
# in the AI Agent Gateway's defence-in-depth stack:
#
#   Gateway policy → Gatekeeper admission → Falco runtime detection
#
# This script installs Falco via Helm with:
#   - Our custom rules file (k8s/falco/rules.yaml)
#   - JSON output for easy SIEM ingestion
#   - eBPF driver (more stable than kernel module on kind)
#
# Usage:
#   bash k8s/falco/install.sh
#   make falco
#
# Prerequisites:
#   - helm (https://helm.sh/docs/intro/install/)
#   - kind cluster running (run demo/setup.sh first)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FALCO_NAMESPACE="falco"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AI Agent Gateway — Installing Falco Runtime Security       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# Check prerequisites
# =============================================================================
for cmd in helm kubectl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}[ERROR]${NC} '$cmd' not found. Install it and re-run."
        exit 1
    fi
done
success "helm and kubectl found."

# =============================================================================
# Add Falco Helm repo
# =============================================================================
info "Adding falcosecurity Helm repository…"
helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
helm repo update
success "Helm repo ready."

# =============================================================================
# Create namespace
# =============================================================================
kubectl get namespace "$FALCO_NAMESPACE" &>/dev/null || \
    kubectl create namespace "$FALCO_NAMESPACE"
success "Namespace '${FALCO_NAMESPACE}' ready."

# =============================================================================
# Install / upgrade Falco
# =============================================================================
info "Installing Falco (this may take 2-3 minutes on first run)…"

helm upgrade --install falco falcosecurity/falco \
    --namespace "$FALCO_NAMESPACE" \
    --set driver.kind=ebpf \
    --set falco.json_output=true \
    --set falco.json_include_output_property=true \
    --set falco.log_level=info \
    --set-file "falco.rules_file[0]=/etc/falco/falco_rules.yaml" \
    --set-file "customRules.ai-gateway-rules\\.yaml=${SCRIPT_DIR}/rules.yaml" \
    --wait \
    --timeout 180s

success "Falco installed successfully."

# =============================================================================
# Verify
# =============================================================================
info "Verifying Falco pods…"
kubectl get pods -n "$FALCO_NAMESPACE"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Falco is running!  Monitor alerts with:                   ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   kubectl logs -l app.kubernetes.io/name=falco \\            ║${NC}"
echo -e "${GREEN}║       -n falco --follow                                      ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   Trigger a test alert (spawn shell in running container):   ║${NC}"
echo -e "${GREEN}║   kubectl exec -it -n demo \\                                ║${NC}"
echo -e "${GREEN}║       $(kubectl get pod -n demo -o name | head -1) \\        ║${NC}"
echo -e "${GREEN}║       -- /bin/sh                                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
