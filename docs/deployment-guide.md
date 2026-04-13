# FlexEdgeAdmin — Deployment Guide

Step-by-step guide to deploy FlexEdgeAdmin on a VPS (Ubuntu 22.04+).

## Prerequisites

- A VPS with Ubuntu 22.04+ and SSH access (e.g., Hetzner, DigitalOcean, AWS EC2)
- A domain name pointed at the server's IP (for HTTPS)
- A Microsoft Entra ID (Azure AD) App Registration (for user authentication)
- Your Forcepoint SMC server URL and at least one API key

## Quick Start (Automated)

```bash
# 1. Clone the repository on your server
git clone https://github.com/smaterazzi/production.git /opt/flexedge-admin
cd /opt/flexedge-admin

# 2. Run the deployment script
chmod +x deploy.sh
./deploy.sh
```

The script will:

1. Install Docker and Docker Compose if not present
2. Create `.env` from template and generate a Flask secret key
3. Build and start all services (including nginx with TLS support)

After the script finishes:

1. Edit `.env` with your Azure AD credentials
2. Restart: `./deploy.sh --update`
3. Open your browser and log in — the setup wizard will guide you through the rest

## Manual Setup

### 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group membership to take effect
```

### 2. Clone and Configure

```bash
cd /opt/flexedge-admin

# Only .env is needed before first start
cp config/.env.example .env
```

### 3. Azure AD Setup + .env

**Automated (recommended):**

```bash
./scripts/azure-setup.sh
```

This single command handles everything:

1. Creates a Microsoft Entra ID App Registration ("FlexEdgeAdmin")
2. Configures redirect URIs (localhost for dev, your domain for prod)
3. Enables ID tokens (required for OIDC login)
4. Creates a client secret (2-year expiry)
5. Adds Microsoft Graph permissions: `openid`, `email`, `profile`
6. Grants admin consent for the permissions
7. Generates a Flask session secret key
8. Writes a complete `.env` file with all values

Prerequisites: Azure CLI (`az login`) + Application Administrator or Global Admin role.

Options:
```bash
./scripts/azure-setup.sh --domain admin.yourcompany.com   # Add production redirect URI
./scripts/azure-setup.sh --app-name "My Admin"            # Custom app name
./scripts/azure-setup.sh --skip-consent                   # Skip admin consent (do manually)
```

**Manual (if Azure CLI is not available):**

1. Copy `.env`: `cp config/.env.example .env`
2. Generate Flask secret: `python3 -c "import secrets; print(secrets.token_hex(32))"`
3. In Azure Portal → Entra ID → App Registrations → New Registration:
   - Name: `FlexEdgeAdmin`
   - Redirect URI: `https://admin.yourcompany.com/auth/callback`
   - Authentication → enable **ID tokens**
   - Certificates & Secrets → create a Client Secret
   - API Permissions → add delegated: `openid`, `email`, `profile` → Grant admin consent
4. Copy Tenant ID, Client ID, Client Secret to `.env`

### 5. Start Services

**Development (no TLS, port 5000):**

```bash
make dev
# or: docker compose -f docker/docker-compose.yml up --build
```

**Production (with nginx + TLS):**

```bash
make prod
# or: docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml up -d --build
```

### 6. First-Run Setup Wizard

On first start, the application automatically:

- Creates the SQLite database at `config/flexedge.db`
- Generates the encryption key at `config/encryption.key`

When you open the browser:

1. You are redirected to Microsoft login (Azure AD)
2. After authentication, the **Setup Wizard** appears
3. Click **"Create Admin Account & Start"** — your Azure AD email becomes the first admin
4. You are redirected to the **Admin Portal** (`/admin/`)

The setup wizard is a one-time page — it becomes permanently inaccessible after the first admin is created.

### 7. Configure via Admin Portal

After setup, use the Admin Portal at `/admin/` to:

1. **Add a Tenant** — your SMC server connection (slug, URL, domain, SSL settings)
2. **Add an API Key** — paste the SMC API key (it will be encrypted and stored; plaintext shown only once)
3. **Add Users** — enter their Azure AD email, assign a role (admin/viewer), and link them to a tenant + API key

Users can now log in via Azure AD, select their assigned SMC tenant, choose a domain, and start browsing.

### 8. Set Up TLS (Production Only)

After starting services, obtain a Let's Encrypt certificate:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml \
  run --rm certbot certonly --webroot -w /var/www/certbot \
  -d admin.yourcompany.com --email admin@yourcompany.com \
  --agree-tos --non-interactive

# Restart nginx to load the certificate
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml restart nginx
```

Certbot auto-renews certificates every 12 hours via the certbot sidecar container.

## Migrating from JSON Config (v1.x)

If you previously used `config/tenants.json` and `config/users.json`:

1. Place both files in the `config/` directory
2. Log in as admin and go to `/admin/`
3. Click **"Import from JSON"** on the dashboard
4. The migration imports tenants, users, API keys, and access mappings
5. Existing entries are skipped (safe to run multiple times)

After migration, JSON files are no longer needed. You can remove them or keep them as a backup.

## Updating

```bash
cd /opt/flexedge-admin
git pull
./deploy.sh --update
# or: make update
```

This pulls the latest code and rebuilds the Docker image. The database and encryption key are preserved (they live in the `config/` volume).

## Uninstalling

```bash
# Stop and remove containers — preserves database, encryption key, .env
./deploy.sh --uninstall

# Full clean slate — DELETES all data, requires typing "PURGE" to confirm
./deploy.sh --uninstall --purge
```

`--uninstall` is safe and reversible — just run `./deploy.sh` again to restart with all your data intact.

`--purge` is **destructive and irreversible**:

- Deletes `config/flexedge.db` (all tenants, users, encrypted API keys)
- Deletes `config/encryption.key` (without it, even DB backups are unreadable)
- Backs up `.env` to `.env.purged-<timestamp>` (in case you need Azure creds)
- Deletes `data/projects/` (migration project data)
- Removes Docker images and certbot TLS volumes

Use `--purge` only when you want a true fresh start (e.g., before running a test deployment, or after rotating to a new Azure tenant).

## CLI Usage via Docker

CLI tools are available inside the running container:

```bash
# Test connection
docker compose -f docker/docker-compose.yml exec flexedge-web \
  python /app/cli/connect.py --tenant prod --api-key YOUR_KEY

# List firewalls
docker compose -f docker/docker-compose.yml exec flexedge-web \
  python /app/cli/firewall.py --tenant prod --api-key YOUR_KEY list

# Or use the Makefile shortcut
make cli CMD="--tenant prod --api-key YOUR_KEY"
```

To avoid passing `--api-key` every time, set `SMC_API_KEY` and `DEFAULT_TENANT` in `.env`:

```bash
# In .env:
SMC_API_KEY=your-cli-api-key
DEFAULT_TENANT=prod

# Then:
docker compose -f docker/docker-compose.yml exec flexedge-web \
  python /app/cli/connect.py
```

## Backup & Restore

### Critical files

| File | Purpose | Recovery without it |
| ---- | ------- | ------------------- |
| `config/flexedge.db` | SQLite database (tenants, users, encrypted API keys) | All admin config lost |
| `config/encryption.key` | Fernet encryption key (binary FXEK format) | API keys in DB become unreadable |
| `.env` | Azure AD credentials, Flask secret | Must be recreated manually |

### Backup via Admin Portal

The easiest method: go to `/admin/` and click **"Download Backup"**. This creates a ZIP containing `flexedge.db` and `encryption.key`.

### Backup via command line

```bash
#!/bin/bash
BACKUP_DIR="/opt/backups/flexedge-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"
cp config/flexedge.db config/encryption.key .env "$BACKUP_DIR/"
cp -r data/projects/ "$BACKUP_DIR/projects/" 2>/dev/null
echo "Backup saved to $BACKUP_DIR"
```

### Restore

1. Place `flexedge.db` and `encryption.key` in the `config/` directory
2. Place `.env` at the project root
3. Start the application: `make dev` or `make prod`
4. All tenants, users, and API keys are restored

Without `encryption.key`, the API keys stored in the database are permanently irrecoverable. This is by design.

## Troubleshooting

### Container won't start

```bash
# Check logs
docker compose -f docker/docker-compose.yml logs -f flexedge-web

# Common issues:
# - "Encryption key file not found" → first run should auto-generate it;
#   check that config/ directory is writable and mounted correctly
# - "FLASK_SECRET_KEY is not set" → generate: python3 -c "import secrets; print(secrets.token_hex(32))"
# - Azure AD errors → check AZURE_TENANT_ID, CLIENT_ID, CLIENT_SECRET in .env
```

### Login redirects to wrong URL

If behind a reverse proxy, ensure the proxy sets `X-Forwarded-Proto: https` and `X-Forwarded-For` headers. The app includes `ProxyFix` middleware for this. The nginx config in `docker/nginx.conf` handles this automatically.

### Setup wizard doesn't appear

The setup wizard only shows when the database has zero users. If you need to re-run setup:

```bash
# Remove the database (WARNING: deletes all admin config)
rm config/flexedge.db
# Restart
make dev
```

### SMC connection fails

```bash
# Test from inside the container
docker compose -f docker/docker-compose.yml exec flexedge-web \
  python -c "import requests; r = requests.get('https://smc.yourcompany.com:8082', verify=False); print(r.status_code)"
```

Check that the VPS can reach the SMC server (firewall rules, network routing).

### TLS certificate issues

```bash
# Check certificate status
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml \
  exec certbot certbot certificates

# Force renewal
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml \
  exec certbot certbot renew --force-renewal
```

## Publishing a Clean Release

The development repository may contain client-specific migration scripts and data. To publish a sanitized, generic version for public use or distribution:

```bash
# Build, commit, and push to the public repo (default)
./scripts/pack-release.sh

# Build and commit locally without pushing
./scripts/pack-release.sh --no-push

# Use a custom commit message
./scripts/pack-release.sh --message "v2.1.0 — admin portal improvements"
```

### What the release packer does

1. Copies all product code (`cli/`, `webapp/`, `shared/`, `docker/`, `config/*.example`) to `./production/`
2. Sanitizes client-specific references (firewall names, IP ranges, server URLs)
3. Removes client-specific files (`scripts/`, `docs/webapp/` archived docs)
4. Runs an automated verification scan — aborts if any leaked secrets, real server URLs, or client names are found
5. Commits to the production repo (preserves `.git` and remote config across rebuilds)
6. Pushes to the configured remote (unless `--no-push`)

### First-time setup

```bash
# After the first pack, configure the public remote:
cd production
git remote add origin https://github.com/smaterazzi/production.git
cd ..

# From now on, pack-release.sh will push automatically
./scripts/pack-release.sh
```

### Updating the public release

```bash
# Make changes on main, then:
./scripts/pack-release.sh --message "v2.1.0 — description of changes"
```

The `production/` folder is gitignored on the main branch and has its own independent git history.

## Architecture Overview

```
Internet → nginx (TLS) → gunicorn (Flask) → SMC API
                ↑                  ↑
         certbot (renew)    SQLite DB (encrypted)
```

- **nginx**: Reverse proxy, TLS termination, security headers
- **gunicorn**: WSGI server running the Flask app (2 workers, 120s timeout)
- **certbot**: Automatic Let's Encrypt certificate renewal
- **Flask app**: FlexEdgeAdmin — Admin Portal + SMC Explorer + Migration Manager
- **SQLite**: Tenant, user, and API key storage with Fernet field-level encryption
- **CLI tools**: Available inside the container via `docker exec`
