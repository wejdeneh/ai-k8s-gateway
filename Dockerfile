FROM python:3.11-slim

# Metadata for OCI image spec.
LABEL org.opencontainers.image.title="AI Agent Kubernetes Security Gateway"
LABEL org.opencontainers.image.description="Policy-enforcement gateway between AI agents and Kubernetes"

WORKDIR /app

# Install minimal system dependencies.
# libssl-dev: required by the cryptography backend in python-jose.
# curl: used in healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cache friendly).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.
COPY app/ ./app/

# Create the logs directory where the audit log will be written.
# In docker-compose this directory is bind-mounted from the host.
RUN mkdir -p /app/logs

# Non-root user for production hardening.
# (kind and docker-compose setups will still work; kubeconfig volume
#  is mounted at /root/.kube for simplicity in local dev.)
# Comment out the two lines below and the USER directive if you hit
# file-permission issues with kubeconfig mounting.
# RUN groupadd -r gateway && useradd -r -g gateway gateway
# USER gateway

EXPOSE 8000

# Healthcheck so docker-compose knows when the gateway is ready.
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-level", "info"]
