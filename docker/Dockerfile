FROM python:3.12-slim

LABEL maintainer="Be TakeOff Sagl" \
      description="FlexEdgeAdmin — Forcepoint SMC Administration & Migration"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    certbot \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies (layer cached)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY shared/ ./shared/
COPY webapp/  ./webapp/
COPY cli/     ./cli/
COPY scripts/ ./scripts/

# Optional: .version.json is stamped by pack-release.sh into FlexEdgeAdminProd
# and serves as the version source for Coolify/CI deploys that don't set
# FLEXEDGE_* build args. The ./* wildcard ignores it silently when missing.
COPY CHANGELOG.md ./CHANGELOG.md
COPY .version.jso[n] ./

# Create runtime directories
RUN mkdir -p /app/data/projects /config

# Ensure shared module is importable from everywhere
ENV PYTHONPATH=/app

# ── Runtime configuration ────────────────────────────────────────────────
# All secrets are injected via environment variables or volume mounts.
# Never bake API keys or secrets into the image.
ENV DATABASE_URL=sqlite:////config/flexedge.db
ENV ENCRYPTION_KEY_FILE=/config/encryption.key
ENV USERS_CONFIG=/config/users.json
ENV TENANTS_CONFIG=/config/tenants.json
ENV FLASK_SECRET_KEY=""
ENV AZURE_TENANT_ID=""
ENV AZURE_CLIENT_ID=""
ENV AZURE_CLIENT_SECRET=""
ENV FLASK_DEBUG=0
ENV PORT=5000
ENV APP_TITLE=FlexEdgeAdmin

# ── Build version (injected by build args from deploy.sh / Makefile) ─────
ARG FLEXEDGE_VERSION=dev
ARG FLEXEDGE_COMMIT=unknown
ARG FLEXEDGE_COMMIT_FULL=unknown
ARG FLEXEDGE_BUILD_DATE=unknown
ENV FLEXEDGE_VERSION=$FLEXEDGE_VERSION
ENV FLEXEDGE_COMMIT=$FLEXEDGE_COMMIT
ENV FLEXEDGE_COMMIT_FULL=$FLEXEDGE_COMMIT_FULL
ENV FLEXEDGE_BUILD_DATE=$FLEXEDGE_BUILD_DATE

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT}/login || exit 1

# Default: run the web app via gunicorn
# CLI tools available via: docker compose exec flexedge-web python -m cli.connect --tenant prod
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--timeout", "120", "--chdir", "/app/webapp", "app:app"]
