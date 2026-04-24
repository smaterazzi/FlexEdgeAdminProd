#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  FlexEdgeAdmin — Standalone Installer (no Docker)
#
#  Installs FlexEdgeAdmin natively on Ubuntu/Debian:
#    1. Python 3.12+ virtualenv at /opt/flexedge/venv
#    2. Application code at /opt/flexedge/
#    3. Config + DB + encryption key at /etc/flexedge/
#    4. systemd service running gunicorn on 127.0.0.1:8088
#    5. nginx reverse proxy (with optional Let's Encrypt TLS)
#
#  Requires: Ubuntu 22.04+ / Debian 12+, sudo privileges.
#  Run from the project root:
#    sudo ./scripts/install-standalone.sh
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${CYAN}==>${NC} $1"; }
ok()    { echo -e "${GREEN}    ✓${NC} $1"; }
warn()  { echo -e "${YELLOW}    ⚠${NC} $1"; }
fail()  { echo -e "${RED}    ✗${NC} $1"; }

# ── Defaults ─────────────────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/flexedge}"
CONFIG_DIR="${CONFIG_DIR:-/etc/flexedge}"
SERVICE_USER="${SERVICE_USER:-flexedge}"
DOMAIN="${DOMAIN:-}"
PORT="${PORT:-8088}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse flags
for arg in "$@"; do
    case $arg in
        --domain)  shift; DOMAIN="${1:-}" ;;
        --no-tls)  NO_TLS=true ;;
        --help|-h)
            echo "Usage: sudo ./scripts/install-standalone.sh [--domain DOMAIN] [--no-tls]"
            echo ""
            echo "  --domain DOMAIN   Configure nginx + Let's Encrypt for this domain"
            echo "  --no-tls          Skip TLS setup (HTTP only — dev/internal use)"
            exit 0
            ;;
    esac
done

# ── Require root ─────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (use sudo)."
    exit 1
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FlexEdgeAdmin — Standalone Installer${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Step 1: System dependencies ──────────────────────────────────────────
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx certbot python3-certbot-nginx curl
ok "System packages installed"

# ── Step 2: Create service user ──────────────────────────────────────────
log "Creating service user '${SERVICE_USER}'..."
if id "$SERVICE_USER" &>/dev/null; then
    ok "User already exists"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "User created"
fi

# ── Step 3: Install application ──────────────────────────────────────────
log "Installing application to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

# Copy project code (skip venv, data, production, config runtime files)
rsync -a --delete \
    --exclude='venv/' --exclude='.venv/' \
    --exclude='__pycache__/' --exclude='*.pyc' \
    --exclude='data/' --exclude='production/' \
    --exclude='conf-files/' --exclude='.git/' \
    --exclude='config/flexedge.db*' --exclude='config/encryption.key' \
    --exclude='config/tenants.json' --exclude='config/users.json' --exclude='config/.env' \
    "$PROJECT_ROOT/" "$INSTALL_DIR/"

ok "Application files copied"

# ── Step 4: Python virtualenv ────────────────────────────────────────────
log "Creating Python virtualenv..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
ok "Virtualenv ready"

# ── Step 5: Config directory ─────────────────────────────────────────────
log "Creating config directory ${CONFIG_DIR}..."
mkdir -p "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# Generate .env if it doesn't exist
if [ ! -f "$CONFIG_DIR/.env" ]; then
    FLASK_SECRET=$("$INSTALL_DIR/venv/bin/python" -c "import secrets; print(secrets.token_hex(32))")
    cat > "$CONFIG_DIR/.env" <<ENVEOF
# FlexEdgeAdmin — Standalone install config
FLASK_SECRET_KEY=${FLASK_SECRET}
FLASK_DEBUG=0
PORT=${PORT}

# Azure Entra ID — run scripts/azure-setup.sh or fill in manually
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=

# Paths (standalone layout)
DATABASE_URL=sqlite:///${CONFIG_DIR}/flexedge.db
ENCRYPTION_KEY_FILE=${CONFIG_DIR}/encryption.key
APP_TITLE=FlexEdgeAdmin
ENVEOF
    chmod 640 "$CONFIG_DIR/.env"
    warn "Created ${CONFIG_DIR}/.env — fill in AZURE_* values before starting"
else
    ok ".env already exists"
fi

chown -R "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR"
ok "Config directory ready"

# ── Step 6: systemd service ──────────────────────────────────────────────
log "Creating systemd service..."
cat > /etc/systemd/system/flexedge.service <<UNITEOF
[Unit]
Description=FlexEdgeAdmin — Forcepoint SMC Administration
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}/webapp
Environment=PYTHONPATH=${INSTALL_DIR}
EnvironmentFile=${CONFIG_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn \\
    --workers 2 \\
    --bind 127.0.0.1:${PORT} \\
    --timeout 120 \\
    --access-logfile - \\
    --error-logfile - \\
    app:app
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable flexedge.service &>/dev/null
ok "systemd service created (flexedge.service)"

# ── Step 7: nginx configuration ──────────────────────────────────────────
log "Configuring nginx..."
NGINX_CONF="/etc/nginx/sites-available/flexedge"
SERVER_NAME="${DOMAIN:-_}"

cat > "$NGINX_CONF" <<NGINXEOF
# FlexEdgeAdmin — standalone nginx config
server {
    listen 80;
    server_name ${SERVER_NAME};

    # Let's Encrypt ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Increase upload limit for FortiGate config files
    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # SMC API calls can be slow
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
NGINXEOF

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/flexedge
rm -f /etc/nginx/sites-enabled/default

nginx -t &>/dev/null && systemctl reload nginx
ok "nginx configured (HTTP, proxying to 127.0.0.1:${PORT})"

# ── Step 8: Start service ────────────────────────────────────────────────
log "Starting FlexEdgeAdmin..."
systemctl restart flexedge.service
sleep 2

if systemctl is-active --quiet flexedge.service; then
    ok "flexedge.service is running"
else
    fail "flexedge.service failed to start. Check logs:"
    echo "    journalctl -u flexedge.service -n 50"
    exit 1
fi

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Install dir:   ${INSTALL_DIR}"
echo "  Config dir:    ${CONFIG_DIR}"
echo "  Service user:  ${SERVICE_USER}"
echo "  Service:       flexedge.service"
echo "  Port:          127.0.0.1:${PORT} (gunicorn)"
echo ""
echo -e "${BOLD}  Next steps:${NC}"
echo ""
echo "    1. Configure Azure AD:"
echo "       ${INSTALL_DIR}/scripts/azure-setup.sh"
echo "       (then copy values to ${CONFIG_DIR}/.env)"
echo ""
echo "    2. Restart after editing .env:"
echo "       sudo systemctl restart flexedge.service"
echo ""
if [[ -n "$DOMAIN" ]] && [[ "${NO_TLS:-false}" != "true" ]]; then
    echo "    3. Obtain Let's Encrypt certificate for ${DOMAIN}:"
    echo "       sudo certbot --nginx -d ${DOMAIN}"
    echo ""
    echo "    4. Open https://${DOMAIN}"
else
    echo "    3. Access at: http://<server-ip>/"
    echo ""
    echo "    4. For TLS later: sudo certbot --nginx -d your-domain.com"
fi
echo ""
echo -e "${BOLD}  Useful commands:${NC}"
echo ""
echo "    sudo systemctl status flexedge      # check status"
echo "    sudo systemctl restart flexedge     # restart"
echo "    sudo journalctl -u flexedge -f      # follow logs"
echo "    sudo nano ${CONFIG_DIR}/.env        # edit config"
echo ""
