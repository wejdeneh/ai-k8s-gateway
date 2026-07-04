# =============================================================================
# AI Agent Kubernetes Security Gateway — Makefile
# =============================================================================
#
# Convenience targets for setting up, running, and testing the gateway.
# All shell-script targets use bash explicitly; on Windows, run them via
# WSL, Git Bash, or the Windows Subsystem for Linux.
#
# Usage:
#   make help         — show all targets
#   make setup        — provision kind cluster
#   make dev          — start OPA + gateway locally (no Docker)
#   make docker-up    — start via docker-compose
#   make gatekeeper   — install OPA Gatekeeper + constraints
#   make falco        — install Falco runtime security
#   make demo         — run end-to-end demo script
# =============================================================================

# Detect OS for path handling
ifeq ($(OS),Windows_NT)
  PYTHON := .venv\Scripts\python
  PIP    := .venv\Scripts\pip
  ACTIVATE := .venv\Scripts\activate
else
  PYTHON := .venv/bin/python
  PIP    := .venv/bin/pip
  ACTIVATE := .venv/bin/activate
endif

GATEWAY_URL ?= http://localhost:8000
OPA_URL     ?= http://localhost:8181

.DEFAULT_GOAL := help

.PHONY: help install setup venv dev-opa dev-gateway dev docker-up docker-down \
        gatekeeper falco demo tokens audit test-imports lint clean

# ---------------------------------------------------------------------------

## help: show this help message
help:
	@echo ""
	@echo "  AI Agent Kubernetes Security Gateway"
	@echo "  ─────────────────────────────────────"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  make /' | sort
	@echo ""

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

## venv: create Python virtual environment and install dependencies
venv:
	python -m venv .venv
	$(PIP) install --upgrade pip -q
	$(PIP) install -r requirements.txt -q
	@echo "Virtual environment ready.  Activate with: source $(ACTIVATE)"

## setup: provision kind cluster with sample workload (idempotent)
setup:
	bash demo/setup.sh

## gatekeeper: install OPA Gatekeeper admission controller + all constraints
gatekeeper:
	bash k8s/gatekeeper/install.sh

## falco: install Falco runtime threat detection via Helm
falco:
	bash k8s/falco/install.sh

# ---------------------------------------------------------------------------
# Local development (no docker-compose)
# ---------------------------------------------------------------------------

## dev-opa: start OPA sidecar in Docker on port 8181
dev-opa:
	docker run --rm -p 8181:8181 \
	    -v "$(shell pwd)/policies:/policies:ro" \
	    openpolicyagent/opa:latest run --server \
	    --addr=0.0.0.0:8181 \
	    --log-level=info \
	    /policies

## dev-gateway: start FastAPI gateway with hot-reload on port 8000
dev-gateway:
	$(PYTHON) -m uvicorn app.main:app --port 8000 --reload --log-level info

## dev: start OPA + gateway together (two tmux panes) — Linux/macOS only
dev:
	@echo "Starting OPA on :8181 and gateway on :8000..."
	@tmux new-session -d -s dev -x 220 -y 50 || true
	@tmux split-window -h -t dev
	@tmux send-keys -t dev:0.0 "make dev-opa" Enter
	@tmux send-keys -t dev:0.1 "sleep 3 && make dev-gateway" Enter
	@tmux attach -t dev

# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------

## docker-up: start gateway + OPA via docker-compose (detached)
docker-up:
	docker-compose up -d

## docker-down: stop docker-compose services and remove containers
docker-down:
	docker-compose down

## docker-logs: tail logs from all docker-compose services
docker-logs:
	docker-compose logs -f

## docker-rebuild: rebuild gateway image and restart (after code changes)
docker-rebuild:
	docker-compose up -d --build gateway

# ---------------------------------------------------------------------------
# Demo and testing
# ---------------------------------------------------------------------------

## demo: run end-to-end demo script against the running gateway
demo:
	$(PYTHON) demo/agent_client.py --gateway $(GATEWAY_URL)

## tokens: mint and print test JWTs for all agent identities
tokens:
	$(PYTHON) -m app.auth.mint_tokens

## audit: pretty-print the last 20 audit log entries
audit:
	@$(PYTHON) -c "\
import json, sys; \
lines = open('audit.log').readlines()[-20:]; \
[print(json.dumps(json.loads(l), indent=2)) for l in lines]" 2>/dev/null \
	|| echo "No audit.log found.  Run make demo first."

## test-imports: verify all Python modules import without errors
test-imports:
	$(PYTHON) -c "\
from app.main import app; \
from app.risk.scorer import score; \
from app.auth.jwt_handler import create_token; \
rs = score('delete', 'secrets', 'kube-system', {}); \
assert rs.level == 'high', f'Expected high, got {rs.level}'; \
tok = create_token('agent-readonly'); \
assert tok; \
print('All checks passed. score=', rs.score, 'level=', rs.level)"

## lint: run ruff linter (install with: pip install ruff)
lint:
	$(PYTHON) -m ruff check app/ demo/ --select E,W,F,I

## test: run all python unit and integration tests
test:
	pytest tests/ -v

## helm-lint: run helm lint against the security gateway chart
helm-lint:
	helm lint charts/ai-k8s-gateway

## opa-test: run OPA unit tests in Docker
opa-test:
	docker run --rm -v "$(shell pwd)/policies:/policies" openpolicyagent/opa test /policies -v

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

## clean: remove generated runtime files (audit log, pycache)
clean:
	@rm -f audit.log 2>/dev/null || del /f audit.log 2>NUL || true
	@find . -name "__pycache__" -type d -not -path "./.venv/*" \
	    -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -not -path "./.venv/*" -delete 2>/dev/null || true
	@echo "Cleaned."

## clean-cluster: delete the kind cluster (WARNING: destroys all cluster data)
clean-cluster:
	@echo "Deleting kind cluster 'agent-gw-demo'..."
	kind delete cluster --name agent-gw-demo
	@echo "Cluster deleted."
