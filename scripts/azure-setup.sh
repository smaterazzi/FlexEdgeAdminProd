#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  FlexEdgeAdmin — Azure Entra ID Setup Script
#
#  Automates the entire Microsoft Entra ID (Azure AD) configuration:
#    1. App Registration (OIDC confidential client)
#    2. Redirect URI configuration (web platform)
#    3. ID token enablement
#    4. Client secret creation
#    5. API permissions (Microsoft Graph: openid, email, profile)
#    6. Admin consent grant
#    7. .env file generation with all values ready
#
#  Prerequisites:
#    - Azure CLI installed and logged in (az login)
#    - Sufficient permissions (Application Administrator or Global Admin)
#
#  Usage:
#    ./scripts/azure-setup.sh                    # Interactive
#    ./scripts/azure-setup.sh --app-name "Foo"   # Override app name
#    ./scripts/azure-setup.sh --domain x.com     # Set production domain
#
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${CYAN}[azure-setup]${NC} $1"; }
ok()    { echo -e "${GREEN}  ✓ $1${NC}"; }
warn()  { echo -e "${YELLOW}  ⚠ $1${NC}"; }
fail()  { echo -e "${RED}  ✗ $1${NC}"; }

ask() {
    local prompt="$1"
    local default="$2"
    local varname="$3"
    local current="${!varname:-}"

    if [[ -n "$current" ]]; then
        read -rp "  ${prompt} [${current}]: " input
        eval "$varname=\"${input:-$current}\""
    elif [[ -n "$default" ]]; then
        read -rp "  ${prompt} [${default}]: " input
        eval "$varname=\"${input:-$default}\""
    else
        read -rp "  ${prompt}: " input
        eval "$varname=\"$input\""
    fi
}

# ── Paths ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Parse CLI arguments ─────────────────────────────────────────────────
APP_NAME=""
DOMAIN=""
SKIP_CONSENT=false

ARGS=("$@")
for i in "${!ARGS[@]}"; do
    case "${ARGS[$i]}" in
        --app-name)   APP_NAME="${ARGS[$((i+1))]:-}" ;;
        --domain)     DOMAIN="${ARGS[$((i+1))]:-}" ;;
        --skip-consent) SKIP_CONSENT=true ;;
        --help|-h)
            echo "Usage: ./scripts/azure-setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --app-name NAME    App Registration display name (default: FlexEdgeAdmin)"
            echo "  --domain DOMAIN    Production domain for redirect URI"
            echo "  --skip-consent     Skip admin consent (if you lack Global Admin)"
            echo "  --help             Show this help"
            exit 0
            ;;
    esac
done

# ═══════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  FlexEdgeAdmin — Azure Entra ID Setup${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 0: Check prerequisites
# ═══════════════════════════════════════════════════════════════════════════

log "Checking prerequisites..."

if ! command -v az &>/dev/null; then
    fail "Azure CLI (az) not found. Install it first:"
    echo "    https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
    echo ""
    echo "  macOS:   brew install azure-cli"
    echo "  Ubuntu:  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
    exit 1
fi
ok "Azure CLI installed: $(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo 'unknown')"

# Check login
if ! az account show &>/dev/null 2>&1; then
    warn "Not logged in to Azure CLI. Opening login..."
    az login --only-show-errors
fi

ACCOUNT_INFO=$(az account show -o json 2>/dev/null)
CURRENT_USER=$(echo "$ACCOUNT_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('user',{}).get('name','unknown'))" 2>/dev/null || echo "unknown")
CURRENT_SUB=$(echo "$ACCOUNT_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name','unknown'))" 2>/dev/null || echo "unknown")
CURRENT_TENANT=$(echo "$ACCOUNT_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tenantId',''))" 2>/dev/null || echo "")

ok "Logged in as:  ${CURRENT_USER}"
ok "Subscription:  ${CURRENT_SUB}"
ok "Tenant ID:     ${CURRENT_TENANT}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 1: Collect parameters
# ═══════════════════════════════════════════════════════════════════════════

log "Step 1: Configuration"
echo ""

# App name
APP_NAME="${APP_NAME:-FlexEdgeAdmin}"
ask "App Registration name" "FlexEdgeAdmin" APP_NAME

# Port for dev redirect URI
PORT="${PORT:-8088}"
ask "Development port" "8088" PORT

# Production domain (optional)
if [[ -z "$DOMAIN" ]]; then
    ask "Production domain (leave empty for dev-only)" "" DOMAIN
fi

# Build redirect URIs
REDIRECT_URIS="http://localhost:${PORT}/auth/callback"
if [[ -n "$DOMAIN" ]]; then
    REDIRECT_URIS="${REDIRECT_URIS} https://${DOMAIN}/auth/callback"
fi

echo ""
echo -e "  ${BOLD}Redirect URIs to configure:${NC}"
for uri in $REDIRECT_URIS; do
    echo -e "    ${GREEN}→${NC} $uri"
done
echo ""

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 2: Create or find App Registration
# ═══════════════════════════════════════════════════════════════════════════

log "Step 2: App Registration"

EXISTING_APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [[ -n "$EXISTING_APP_ID" && "$EXISTING_APP_ID" != "None" ]]; then
    CLIENT_ID="$EXISTING_APP_ID"
    ok "App '${APP_NAME}' already exists: ${CLIENT_ID}"

    # Update redirect URIs
    log "Updating redirect URIs..."
    az ad app update \
        --id "$CLIENT_ID" \
        --web-redirect-uris $REDIRECT_URIS \
        --only-show-errors 2>/dev/null
    ok "Redirect URIs updated"
else
    log "Creating app registration '${APP_NAME}'..."

    APP_RESULT=$(az ad app create \
        --display-name "$APP_NAME" \
        --web-redirect-uris $REDIRECT_URIS \
        --sign-in-audience "AzureADMyOrg" \
        -o json 2>&1)

    if [[ $? -ne 0 ]]; then
        fail "Failed to create app registration:"
        echo "  $APP_RESULT"
        exit 1
    fi

    CLIENT_ID=$(echo "$APP_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('appId',''))" 2>/dev/null)

    if [[ -z "$CLIENT_ID" ]]; then
        fail "Could not extract appId from response."
        exit 1
    fi

    ok "App registered: ${CLIENT_ID}"

    # Create service principal
    log "Creating service principal..."
    az ad sp create --id "$CLIENT_ID" --only-show-errors -o none 2>/dev/null || true
    ok "Service principal created"
fi

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 3: Enable ID tokens
# ═══════════════════════════════════════════════════════════════════════════

log "Step 3: Enabling ID tokens (required for OIDC)"

# Enable ID tokens via the web section of the app manifest
az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications(appId='${CLIENT_ID}')" \
    --headers "Content-Type=application/json" \
    --body '{"web":{"implicitGrantSettings":{"enableIdTokenIssuance":true}}}' \
    --only-show-errors 2>/dev/null \
    && ok "ID tokens enabled" \
    || warn "Could not enable ID tokens via API — enable manually in Azure Portal → Authentication"

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 4: Create client secret
# ═══════════════════════════════════════════════════════════════════════════

log "Step 4: Client secret"

SECRET_LABEL="flexedge-$(date +%Y%m%d)"

log "Creating client secret '${SECRET_LABEL}' (2-year expiry)..."

SECRET_RESULT=$(az ad app credential reset \
    --id "$CLIENT_ID" \
    --display-name "$SECRET_LABEL" \
    --years 2 \
    --append \
    -o json 2>/dev/null)

if [[ $? -ne 0 || -z "$SECRET_RESULT" ]]; then
    fail "Failed to create client secret. Check permissions."
    fail "You may need Application Administrator or Global Admin role."
    exit 1
fi

CLIENT_SECRET=$(echo "$SECRET_RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('password') or d.get('secretText') or '')
" 2>/dev/null)

if [[ -z "$CLIENT_SECRET" ]]; then
    fail "Could not extract secret value from response."
    exit 1
fi

ok "Client secret created (expires in 2 years)"
echo ""
echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${YELLOW}║  IMPORTANT: Save the client secret — it cannot be retrieved ║${NC}"
echo -e "  ${YELLOW}║  again from Azure after this moment.                        ║${NC}"
echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 5: API permissions (Microsoft Graph: openid, email, profile)
# ═══════════════════════════════════════════════════════════════════════════

log "Step 5: API permissions"

# Microsoft Graph well-known IDs
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

# Delegated permission IDs for Microsoft Graph v1.0:
PERM_OPENID="37f7f235-527c-4136-accd-4a02d197296e"
PERM_EMAIL="64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
PERM_PROFILE="14dad69e-099b-42c9-810b-d002981feec1"

log "Adding Microsoft Graph delegated permissions: openid, email, profile..."

for PERM_ID in "$PERM_OPENID" "$PERM_EMAIL" "$PERM_PROFILE"; do
    az ad app permission add \
        --id "$CLIENT_ID" \
        --api "$GRAPH_APP_ID" \
        --api-permissions "${PERM_ID}=Scope" \
        --only-show-errors -o none 2>/dev/null || true
done
ok "Permissions added: openid, email, profile"

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 6: Grant admin consent
# ═══════════════════════════════════════════════════════════════════════════

if [[ "$SKIP_CONSENT" = false ]]; then
    log "Step 6: Admin consent"

    log "Granting admin consent for API permissions..."

    # Small delay — Azure needs a moment to propagate the permissions
    sleep 3

    az ad app permission admin-consent \
        --id "$CLIENT_ID" \
        --only-show-errors -o none 2>/dev/null \
        && ok "Admin consent granted" \
        || {
            warn "Could not grant admin consent automatically."
            warn "This requires Global Admin or Privileged Role Administrator."
            echo ""
            echo -e "  ${BOLD}Manual step:${NC} Go to Azure Portal → Entra ID → App Registrations"
            echo "    → ${APP_NAME} → API permissions → Grant admin consent"
            echo ""
        }
else
    warn "Skipping admin consent (--skip-consent). Grant it manually in Azure Portal."
fi

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 7: Generate FLASK_SECRET_KEY
# ═══════════════════════════════════════════════════════════════════════════

log "Step 7: Generating Flask session secret..."

FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
    || openssl rand -hex 32 2>/dev/null \
    || head -c 32 /dev/urandom | xxd -p | tr -d '\n')

ok "Flask secret key generated"

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 8: Write .env file
# ═══════════════════════════════════════════════════════════════════════════

log "Step 8: Writing .env file"

ENV_FILE="$PROJECT_ROOT/.env"
GENERATED_DATE=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

# Backup existing .env if present
if [[ -f "$ENV_FILE" ]]; then
    BACKUP="${ENV_FILE}.backup-$(date +%Y%m%d%H%M%S)"
    cp "$ENV_FILE" "$BACKUP"
    warn "Existing .env backed up to: $(basename "$BACKUP")"
fi

cat > "$ENV_FILE" <<ENVEOF
# FlexEdgeAdmin — Environment Variables
# Generated by azure-setup.sh on ${GENERATED_DATE}
# DO NOT commit this file to git.

# ── Flask ─────────────────────────────────────────────────────────────────
FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
FLASK_DEBUG=0
PORT=${PORT}

# ── Microsoft Entra ID (Azure AD) ────────────────────────────────────────
# App Registration: ${APP_NAME}
# Created: ${GENERATED_DATE}
AZURE_TENANT_ID=${CURRENT_TENANT}
AZURE_CLIENT_ID=${CLIENT_ID}
AZURE_CLIENT_SECRET=${CLIENT_SECRET}

# ── Database ─────────────────────────────────────────────────────────────
DATABASE_URL=sqlite:////config/flexedge.db
ENCRYPTION_KEY_FILE=/config/encryption.key

# ── App branding (optional) ──────────────────────────────────────────────
APP_TITLE=FlexEdgeAdmin

# ── TLS / Production (only needed for docker-compose.prod.yml) ───────────
DOMAIN=${DOMAIN:-admin.yourdomain.com}
CERTBOT_EMAIL=${CURRENT_USER}
ENVEOF

chmod 600 "$ENV_FILE"
ok "Written: .env (chmod 600)"

# ═══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Azure Setup Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  App Registration"
echo "  ─────────────────"
echo "  Name:          ${APP_NAME}"
echo "  Tenant ID:     ${CURRENT_TENANT}"
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET:0:8}...  (full value in .env)"
echo "  ID Tokens:     Enabled"
echo "  Permissions:   openid, email, profile (delegated)"
echo ""
echo "  Redirect URIs"
echo "  ─────────────"
for uri in $REDIRECT_URIS; do
    echo "    → $uri"
done
echo ""
echo "  Files"
echo "  ─────"
echo "  .env:          ${ENV_FILE} (ready to use)"
echo ""
echo -e "${BOLD}  Next steps:${NC}"
echo ""
echo "    1. Start FlexEdgeAdmin:"
echo "       make dev"
echo ""
echo "    2. Open http://localhost:${PORT}"
echo "       → Login with your Azure AD account"
echo "       → Setup wizard creates your admin account"
echo ""
echo "    3. Use Admin Portal (/admin/) to add:"
echo "       → SMC tenants (server connections)"
echo "       → API keys (encrypted)"
echo "       → Users (assigned to tenants)"
echo ""
if [[ -n "$DOMAIN" ]]; then
    echo "    4. For production deployment:"
    echo "       make prod"
    echo "       → Then set up TLS (see docs/deployment-guide.md)"
    echo ""
fi
echo -e "  ${YELLOW}Remember: rotate the client secret before it expires (2 years).${NC}"
echo ""
