#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
#  FlexEdgeAdmin — Server Deployment Script
#
#  Automates setup on a fresh Ubuntu 22.04+ VPS:
#    1. Installs Docker + Docker Compose (if not present)
#    2. Creates config files from templates (if not present)
#    3. Generates a Flask secret key
#    4. Builds and starts the application
#
#  Usage:
#    chmod +x deploy.sh
#    ./deploy.sh              # Interactive setup
#    ./deploy.sh --no-tls     # Skip TLS/nginx (development)
#    ./deploy.sh --update     # Pull latest code and rebuild
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_color() { echo -e "${1}${2}${NC}"; }
print_step()  { echo ""; print_color "$BLUE" "==> $1"; }
print_ok()    { print_color "$GREEN" "    ✓ $1"; }
print_warn()  { print_color "$YELLOW" "    ⚠ $1"; }
print_err()   { print_color "$RED" "    ✗ $1"; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_BASE="-f $PROJECT_DIR/docker/docker-compose.yml"
COMPOSE_PROD="-f $PROJECT_DIR/docker/docker-compose.prod.yml"
USE_TLS=true
UPDATE_ONLY=false
UNINSTALL=false
PURGE=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --no-tls)    USE_TLS=false ;;
        --update)    UPDATE_ONLY=true ;;
        --uninstall) UNINSTALL=true ;;
        --purge)     PURGE=true ;;
        --help|-h)
            echo "Usage: ./deploy.sh [OPTIONS]"
            echo ""
            echo "Install / start:"
            echo "  (no flags)         Install Docker, configure, build, and start with TLS"
            echo "  --no-tls           Skip TLS/nginx setup (dev mode, port 5000 only)"
            echo "  --update           Pull latest code and rebuild containers"
            echo ""
            echo "Uninstall:"
            echo "  --uninstall        Stop and remove containers (preserves data + .env)"
            echo "  --uninstall --purge  DESTRUCTIVE: also delete DB, encryption key, .env,"
            echo "                       Docker images, certbot volumes — full clean slate"
            exit 0
            ;;
    esac
done

# ── Uninstall mode ───────────────────────────────────────────────────────
if [ "$UNINSTALL" = true ]; then
    cd "$PROJECT_DIR"

    print_step "Uninstalling FlexEdgeAdmin..."

    # Stop and remove containers (both dev and prod compose files)
    print_step "Stopping containers..."
    docker compose $COMPOSE_BASE $COMPOSE_PROD down 2>/dev/null || true
    docker compose $COMPOSE_BASE down 2>/dev/null || true
    print_ok "Containers stopped and removed"

    if [ "$PURGE" = true ]; then
        echo ""
        print_color "$RED" "    ⚠ PURGE MODE: This will permanently delete:"
        echo "      - config/flexedge.db          (all tenants, users, API keys)"
        echo "      - config/encryption.key       (recovery key — IRREVERSIBLE)"
        echo "      - .env                         (Azure AD credentials)"
        echo "      - data/projects/              (migration project data)"
        echo "      - Docker images for this project"
        echo "      - certbot TLS volumes (if present)"
        echo ""
        read -p "    Type 'PURGE' to confirm: " confirm
        if [ "$confirm" != "PURGE" ]; then
            print_warn "Purge cancelled. Containers were stopped but data preserved."
            exit 0
        fi

        print_step "Purging data..."

        # Remove encrypted DB and key
        rm -f config/flexedge.db config/flexedge.db-shm config/flexedge.db-wal
        rm -f config/encryption.key
        print_ok "Removed database and encryption key"

        # Remove .env (back it up just in case)
        if [ -f .env ]; then
            BACKUP=".env.purged-$(date +%Y%m%d%H%M%S)"
            mv .env "$BACKUP"
            print_warn "Moved .env to $BACKUP (in case you need Azure creds)"
        fi

        # Remove migration project data
        rm -rf data/projects/
        print_ok "Removed migration project data"

        # Remove Docker images
        docker rmi $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -i flexedge) 2>/dev/null || true
        print_ok "Removed Docker images"

        # Remove certbot volumes
        docker volume rm $(docker volume ls -q | grep -i certbot) 2>/dev/null || true
        print_ok "Removed certbot volumes"

        echo ""
        print_color "$GREEN" "    ✓ Full uninstall complete. Project files remain on disk."
        echo ""
        echo "    To start fresh: ./deploy.sh"
    else
        echo ""
        print_color "$GREEN" "    ✓ Containers stopped. Your data is preserved:"
        echo "      - config/flexedge.db          (database)"
        echo "      - config/encryption.key       (encryption key)"
        echo "      - .env                         (Azure AD credentials)"
        echo "      - data/projects/              (migration data)"
        echo ""
        echo "    To restart:           ./deploy.sh"
        echo "    To purge everything:  ./deploy.sh --uninstall --purge"
    fi
    exit 0
fi

# ── Update mode ──────────────────────────────────────────────────────────
if [ "$UPDATE_ONLY" = true ]; then
    print_step "Updating FlexEdgeAdmin..."

    cd "$PROJECT_DIR"
    git pull --rebase 2>/dev/null || print_warn "Git pull failed (not a git repo or no remote)"

    if [ "$USE_TLS" = true ]; then
        docker compose $COMPOSE_BASE $COMPOSE_PROD up -d --build
    else
        docker compose $COMPOSE_BASE up -d --build
    fi

    print_ok "Update complete!"
    exit 0
fi

# ── Step 1: Install Docker ──────────────────────────────────────────────
print_step "Checking Docker installation..."

if command -v docker &> /dev/null; then
    print_ok "Docker is installed: $(docker --version)"
else
    print_warn "Docker not found. Installing..."

    # Docker official install script
    curl -fsSL https://get.docker.com | sh

    # Add current user to docker group (takes effect on next login)
    sudo usermod -aG docker "$USER" 2>/dev/null || true

    print_ok "Docker installed: $(docker --version)"
    print_warn "You may need to log out and back in for docker group membership"
fi

# Check Docker Compose
if docker compose version &> /dev/null; then
    print_ok "Docker Compose is available"
else
    print_err "Docker Compose plugin not found. Install it:"
    echo "    sudo apt install docker-compose-plugin"
    exit 1
fi

# ── Step 2: Create config files from templates ──────────────────────────
print_step "Setting up configuration files..."

cd "$PROJECT_DIR"

# Note: tenants.json and users.json are no longer required.
# All configuration is managed via the web Admin Portal (stored in encrypted DB).
# Legacy JSON files can be imported via Admin Portal → "Import from JSON" button.

# .env — check if it exists or if azure-setup.sh should be used
if [ ! -f .env ]; then
    # Check if Azure CLI is available — offer to run azure-setup.sh
    if command -v az &>/dev/null; then
        echo ""
        print_color "$YELLOW" "    No .env file found. You can create one automatically"
        print_color "$YELLOW" "    using the Azure setup script (recommended)."
        echo ""
        read -p "    Run Azure setup now? (Y/n) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            bash "$PROJECT_DIR/scripts/azure-setup.sh"
        fi
    fi

    # If azure-setup.sh wasn't run or isn't available, create from template
    if [ ! -f .env ]; then
        cp config/.env.example .env

        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/REPLACE_WITH_64_HEX_CHARS/$SECRET_KEY/" .env
        else
            sed -i "s/REPLACE_WITH_64_HEX_CHARS/$SECRET_KEY/" .env
        fi

        print_warn "Created .env with auto-generated FLASK_SECRET_KEY"
        print_warn "EDIT .env with your Azure AD credentials"
        print_warn "  Or run: ./scripts/azure-setup.sh  (automates Azure AD setup)"
    fi
else
    print_ok ".env already exists"
fi

# Create data directory
mkdir -p data/projects
mkdir -p conf-files

# ── Step 3: Validate configuration ─────────────────────────────────────
print_step "Validating configuration..."

NEEDS_EDIT=false

if grep -q "REPLACE" .env 2>/dev/null; then
    print_warn ".env still has placeholder values (Azure AD credentials needed)"
    NEEDS_EDIT=true
fi

if [ "$NEEDS_EDIT" = true ]; then
    echo ""
    print_color "$YELLOW" "    Please edit .env before starting the application."
    echo "    Required in .env:"
    echo "      - AZURE_TENANT_ID      → your Azure AD / Entra ID tenant UUID"
    echo "      - AZURE_CLIENT_ID      → App Registration client ID"
    echo "      - AZURE_CLIENT_SECRET  → App Registration client secret"
    echo ""
    echo "    After starting, open the browser to complete the setup wizard."
    echo "    Tenants, users, and API keys are configured via the Admin Portal."
    echo ""
    read -p "    Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "    Edit .env and run ./deploy.sh again."
        exit 0
    fi
fi

# ── Step 4: Build and start ────────────────────────────────────────────
print_step "Building and starting FlexEdgeAdmin..."

if [ "$USE_TLS" = true ]; then
    docker compose $COMPOSE_BASE $COMPOSE_PROD up -d --build
    echo ""
    print_ok "FlexEdgeAdmin is running with nginx reverse proxy"
    echo ""
    echo "    Next steps:"
    echo "    1. Ensure your domain DNS points to this server's IP"
    echo "    2. Obtain a TLS certificate:"
    echo ""
    echo "       docker compose $COMPOSE_BASE $COMPOSE_PROD \\"
    echo "         run --rm certbot certonly --webroot -w /var/www/certbot \\"
    echo "         -d YOUR_DOMAIN --email YOUR_EMAIL --agree-tos --non-interactive"
    echo ""
    echo "    3. Restart nginx: docker compose $COMPOSE_BASE $COMPOSE_PROD restart nginx"
    echo "    4. Open https://YOUR_DOMAIN → login with Azure AD → setup wizard"
    echo "    5. Use the Admin Portal to add tenants, API keys, and users"
else
    docker compose $COMPOSE_BASE up -d --build
    echo ""
    print_ok "FlexEdgeAdmin is running (dev mode, no TLS)"
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost')
    echo ""
    echo "    Access: http://${SERVER_IP}:${PORT:-5000}"
    echo ""
    echo "    First visit: login with Azure AD → setup wizard creates your admin account"
    echo "    Then:        Admin Portal (/admin/) → add tenants, API keys, users"
fi

echo ""
print_color "$GREEN" "Useful commands:"
echo "    docker compose $COMPOSE_BASE logs -f              # View logs"
echo "    docker compose $COMPOSE_BASE down                 # Stop"
echo "    ./deploy.sh --update                              # Update & rebuild"
echo ""
