# FlexEdgeAdmin — Deployment Guide

Three deployment options depending on your infrastructure. All three deliver the same product; pick the one that fits your setup.

| Option | Best for | nginx/TLS | Complexity |
| ------ | -------- | --------- | ---------- |
| [1. Standalone](#option-1--standalone-install-no-docker) | Dedicated VM, no Docker | Managed by you (nginx + certbot on host) | Medium |
| [2. Docker + nginx](#option-2--standalone-docker-with-nginx) | Single-purpose VPS | Handled by compose (nginx + certbot containers) | Low |
| [3. Coolify / Traefik](#option-3--docker-behind-coolify--traefik) | Multi-website host | Handled by Coolify automatically | Low |

---

## Prerequisites (all options)

- Ubuntu 22.04+ / Debian 12+ server with SSH access
- A domain name pointed at the server's public IP (optional for dev)
- A Microsoft Entra ID (Azure AD) App Registration — see [Azure AD setup](#azure-ad-setup)
- Your Forcepoint SMC server URL and at least one API key

---

## Azure AD Setup

Works the same for all three deployment options.

**Automated (recommended):**

```bash
./scripts/azure-setup.sh --domain admin.yourcompany.com
```

This creates the App Registration, enables ID tokens, creates a client secret, adds `openid`/`email`/`profile` permissions, grants admin consent, and writes `.env`. Requires Azure CLI (`az login`) and Application Administrator role.

**Manual:** see [CLAUDE.md § Azure AD App Registration](../CLAUDE.md#azure-ad-app-registration).

The resulting `.env` must contain `FLASK_SECRET_KEY`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.

---

## Option 1 — Standalone install (no Docker)

Native Python install behind the system's nginx. Best when Docker isn't an option or you prefer native services.

### What the installer does

1. Installs Python 3.12, nginx, certbot
2. Creates a `flexedge` system user (no login, no home)
3. Installs code to `/opt/flexedge/`, creates a venv, installs dependencies
4. Creates `/etc/flexedge/.env` with a generated Flask secret
5. Creates a systemd service (`flexedge.service`) binding gunicorn to `127.0.0.1:5000`
6. Writes nginx site config proxying to gunicorn
7. Enables and starts both services

### Steps

```bash
# 1. Clone the production repo
git clone https://github.com/smaterazzi/FlexEdgeAdminProd.git /opt/flexedge-src
cd /opt/flexedge-src

# 2. Run the installer (requires sudo)
sudo ./scripts/install-standalone.sh --domain admin.yourcompany.com

# 3. Configure Azure AD — either via the automation script:
./scripts/azure-setup.sh --domain admin.yourcompany.com
# then copy AZURE_* values from ./.env into /etc/flexedge/.env

# 4. Restart the service to pick up credentials
sudo systemctl restart flexedge.service

# 5. Obtain TLS certificate
sudo certbot --nginx -d admin.yourcompany.com

# 6. Open https://admin.yourcompany.com → setup wizard
```

### Service management

```bash
sudo systemctl status flexedge          # check status
sudo systemctl restart flexedge         # restart after .env changes
sudo journalctl -u flexedge -f          # follow logs
sudo nano /etc/flexedge/.env            # edit config
```

### File layout

| Path | Purpose |
| ---- | ------- |
| `/opt/flexedge/` | Application code, venv, templates |
| `/etc/flexedge/.env` | Environment variables (chmod 640, owned by `flexedge`) |
| `/etc/flexedge/flexedge.db` | SQLite database (auto-created on first run) |
| `/etc/flexedge/encryption.key` | Fernet encryption key (auto-generated) |
| `/etc/systemd/system/flexedge.service` | systemd unit |
| `/etc/nginx/sites-available/flexedge` | nginx site config |

### Updating

```bash
cd /opt/flexedge-src
git pull
sudo ./scripts/install-standalone.sh    # idempotent — preserves /etc/flexedge/
sudo systemctl restart flexedge
```

### Uninstalling

```bash
sudo systemctl disable --now flexedge
sudo rm /etc/systemd/system/flexedge.service
sudo rm /etc/nginx/sites-enabled/flexedge /etc/nginx/sites-available/flexedge
sudo systemctl reload nginx
sudo rm -rf /opt/flexedge
# Keep /etc/flexedge/ if you want to preserve the DB + key for later restore
sudo userdel flexedge
```

---

## Option 2 — Standalone Docker with nginx

Single-purpose server where you run the full stack via docker compose. nginx + certbot are containerised alongside the app.

### Steps

```bash
# 1. Clone the production repo
git clone https://github.com/smaterazzi/FlexEdgeAdminProd.git /opt/flexedge-admin
cd /opt/flexedge-admin

# 2. Automated setup (installs Docker, configures Azure, starts everything)
./deploy.sh

# Or manually:
cp config/.env.example .env
./scripts/azure-setup.sh
make prod
```

### Production stack

- `flexedge-web` — gunicorn + Flask on internal port 5000
- `nginx` — reverse proxy with TLS termination (ports 80, 443)
- `certbot` — auto-renews Let's Encrypt certificates every 12h

### First-time TLS setup

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml \
  run --rm certbot certonly --webroot -w /var/www/certbot \
  -d admin.yourcompany.com --email admin@yourcompany.com \
  --agree-tos --non-interactive

docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml restart nginx
```

### Updating

```bash
cd /opt/flexedge-admin
git pull
./deploy.sh --update
```

### Local development

For local development on a workstation, skip nginx/TLS and run in foreground with live logs:

```bash
./deploy.sh --dev     # or: make dev
```

Same guided bootstrap as production (Docker check, `.env` creation, optional `azure-setup.sh`), then `docker compose up --build` attached — Ctrl+C to stop. Access the app at `http://localhost:5000`.

For CI or background use, `./deploy.sh --no-tls` runs the same stack detached.

### Uninstalling

```bash
./deploy.sh --uninstall         # stop containers, keep data
./deploy.sh --uninstall --purge # also delete DB, key, images (irreversible)
```

---

## Option 3 — Docker behind Coolify / Traefik

Best for multi-website hosts. Coolify (a self-hosted Heroku alternative) uses Traefik under the hood and automates TLS, routing, and deployments across many apps on one server.

### 3a. Install Coolify on your server (one-time)

SSH to a fresh Ubuntu 22.04+ VPS and run:

```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

The installer sets up Docker, Traefik, the Coolify dashboard, and a persistent database. After ~2 minutes, it prints a URL like `http://<your-server-ip>:8000` — open it and create the root admin account.

### 3b. Configure a server in Coolify

1. Coolify dashboard → **Servers** → **Add a Server**
2. If running on the same server as Coolify itself, use the default `localhost` server
3. Otherwise, add a remote server via SSH key

### 3c. Deploy FlexEdgeAdmin

1. **New Resource** → **Docker Compose Empty** (or **Public Repository**)

2. Choose **Public Repository**:
   - **Repository URL**: `https://github.com/smaterazzi/FlexEdgeAdminProd.git`
   - **Branch**: `main`
   - **Base Directory**: `/`
   - **Docker Compose Location**: `/docker/docker-compose.coolify.yml`

3. Click **Save** → Coolify parses the compose file

4. In the **Environment Variables** tab, set:

   ```
   FLASK_SECRET_KEY=<generate: python3 -c "import secrets; print(secrets.token_hex(32))">
   AZURE_TENANT_ID=<from Entra ID>
   AZURE_CLIENT_ID=<from App Registration>
   AZURE_CLIENT_SECRET=<from Certificates & Secrets>
   APP_TITLE=FlexEdgeAdmin
   ```

5. In the **Domains** field (under General), set your FQDN:

   ```
   https://admin.yourcompany.com
   ```

   Coolify automatically:
   - Generates Traefik labels on the container
   - Requests a Let's Encrypt certificate
   - Configures HTTP→HTTPS redirect
   - Routes traffic to the container's port 5000

6. In the **Storages** tab, confirm the two persistent volumes are present:
   - `flexedge-config` → mounted at `/config` (DB + encryption key)
   - `flexedge-data` → mounted at `/app/data/projects` (migration data)

7. Click **Deploy** — Coolify pulls the repo, builds the image, starts the container, and provisions TLS

8. **Important Azure AD step**: before users can log in, set the redirect URI in your App Registration to `https://admin.yourcompany.com/auth/callback` (if not already configured by `azure-setup.sh --domain`)

### 3d. First-run setup

1. Open `https://admin.yourcompany.com`
2. Log in with Azure AD → setup wizard creates the first admin
3. Admin Portal (`/admin/`) → add tenants, API keys, users

### 3e. How new releases reach your customers

The release pipeline has two stages:

**Stage 1 — Publisher (you):**

```bash
# On your dev machine, when you're ready to publish:
./scripts/pack-release.sh --message "v2.1.1 — bug fix"
```

This runs the leak scan, stamps `.version.json` into the release with version + commit + build date, then commits and pushes to [github.com/smaterazzi/FlexEdgeAdminProd](https://github.com/smaterazzi/FlexEdgeAdminProd).

**Stage 2 — Customer Coolify pulls the update:**

Two ways, both fine:

- **Manual** — customer clicks **Redeploy** in the app view in Coolify. Coolify pulls the latest commit from the public repo, rebuilds the Docker image, starts a new container. The sidebar then shows the new version.
- **Automatic (webhook)** — customer enables *"Automatic Deployment"* in the app's Coolify **General** settings, then adds the Coolify-provided webhook URL as a GitHub webhook on the public repo. Every push to `FlexEdgeAdminProd` triggers an immediate redeploy. You can combine this with deploy-on-branch if you want a "staging" vs "main" split.

### Verifying your customers are on the latest version

```bash
# What you just published:
grep -m1 -o '## \[[^]]*\]' CHANGELOG.md   # → ## [2.1.1]
git rev-parse --short HEAD                 # → abc1234

# What a customer's server reports:
curl -s https://customer.example.com/version | jq
```

If the customer's `commit` matches what you just pushed, the update landed. If not, it's one of:

- Their Coolify app hasn't been redeployed yet — tell them to click **Redeploy** (or enable auto-deploy)
- They're pinned to a specific branch/tag in their Coolify config — check the app's *Git Source* settings
- Their image cache is stale — in Coolify, use **Rebuild** (not just Redeploy) to force a fresh `docker build`

### 3f. Updating

- **Automatic**: In Coolify, enable **Auto Deploy** and set a webhook on the GitHub repo → every push triggers a new build
- **Manual**: Coolify dashboard → the app → click **Redeploy**

### 3g. Backup

- The `flexedge-config` volume contains both the database and the encryption key — back this up regularly
- Coolify → **Backups** tab → enable automated backups or configure S3 target

### Why this compose file has no nginx

`docker-compose.coolify.yml` intentionally omits nginx and certbot because:

- Coolify runs Traefik on ports 80/443 for *all* apps on the host — only one reverse proxy allowed
- Coolify injects Traefik routing labels automatically when you set the Domain
- TLS certificates are managed by Traefik's ACME provider, shared across all your apps

If you try to use `docker-compose.prod.yml` (which has nginx) with Coolify, port 80/443 will conflict with Traefik.

---

## CLI Usage via Docker (options 2 & 3)

```bash
# In standalone Docker:
docker compose -f docker/docker-compose.yml exec flexedge-web \
  python /app/cli/connect.py --tenant prod --api-key YOUR_KEY

# In Coolify — use the "Terminal" button in the app's UI, or:
docker exec -it flexedge-admin python /app/cli/connect.py --tenant prod --api-key YOUR_KEY
```

For Option 1 (standalone), CLI tools run natively:

```bash
sudo -u flexedge /opt/flexedge/cli/smc.sh --tenant prod connect
```

---

## Backup & Restore

### Critical files

| File | Purpose | Without it |
| ---- | ------- | ---------- |
| `flexedge.db` | SQLite database | All admin config lost |
| `encryption.key` | Fernet encryption key | API keys become unreadable |
| `.env` | Azure AD credentials, Flask secret | Must be recreated manually |

### Location by deployment

| Option | Path |
| ------ | ---- |
| Standalone | `/etc/flexedge/` |
| Docker + nginx | `<project>/config/` |
| Coolify | Persistent volume `flexedge-config` (mounted at `/config` in container) |

### Backup methods

- **Admin Portal → Backup**: downloads a ZIP with `flexedge.db` + `encryption.key` (works in all 3 options)
- **Manual**: copy the files from the location above to secure storage
- **Coolify**: use the built-in backup feature with S3 target

### Restore

Place `flexedge.db`, `encryption.key`, and `.env` in the correct location, then restart. All tenants, users, and API keys are restored.

Without `encryption.key`, API keys stored in the database are permanently irrecoverable. This is by design.

---

## TLS Manager — certbot integration

The TLS Manager feature (`/tls/*`, admin-only) automates TLS certificate deployment onto Forcepoint NGFW engines. It reads certbot-managed certificates from `/etc/letsencrypt/live/` inside the application container.

### Workflow

1. **Issue certificates with certbot** for each service behind a firewall (see per-deployment-option setup below)
2. **Track** — open **TLS Manager → Certificates**; discovered certificates can be tracked with one click
3. **Deploy** — **TLS Manager → Deploy**: pick the tracked certificate, a tenant (from Admin Portal), an API key, a target engine, then fill the service name + public/private IPv4
4. **Execute** — the pipeline imports the cert as a `TLSServerCredential`, creates `{service}-PublicIPv4` / `{service}-PrivateIPv4` host objects, assigns the credential to the engine's TLS inspection, creates an HTTPS access rule with deep inspection + file filtering + decryption in section `Service {name} - TLS Protection`, and uploads the policy
5. **Auto-renewal** — wire the deploy-hook (below) so every certbot renewal re-runs the full pipeline automatically

### Certbot setup per deployment option

### Option 1 — Standalone

Certbot is already installed on the host (used for the webapp's own TLS). The `/etc/letsencrypt` directory is directly accessible to the Python process.

No extra configuration needed. Issue a certificate for each service you want to protect:

```bash
sudo certbot certonly --standalone -d service1.yourcompany.com
sudo certbot certonly --standalone -d service2.yourcompany.com
```

They appear automatically in **TLS Manager → Certificates**.

### Option 2 — Docker + nginx

The main image now bundles `certbot`. The `docker/docker-compose.yml` mounts `/etc/letsencrypt:/etc/letsencrypt:ro` into the `flexedge-web` container, so certificates managed by the existing `certbot` container are visible to TLS Manager without extra steps.

To issue a certificate for a *target service* (not the webapp itself):

```bash
docker compose -f docker/docker-compose.yml \
  run --rm certbot certonly --webroot -w /var/www/certbot \
  -d service.yourcompany.com
```

### Option 3 — Coolify / Traefik

The webapp's own TLS is handled by Traefik and does not use certbot. To use TLS Manager, either:

1. Run certbot on the **host** and bind-mount `/etc/letsencrypt:/etc/letsencrypt:ro` into the Coolify container (add under "Persistent Storage" in Coolify UI)
2. Or run a dedicated certbot sidecar container that writes to a shared volume mounted into the FlexEdgeAdmin container

### Renewal hook

Whichever option you use, wire certbot's deploy-hook to FlexEdgeAdmin so deployments re-execute after each renewal:

1. **TLS Manager → Renewal Hook** — shows the ready-to-install shell script + the API token
2. Copy the script to `/etc/letsencrypt/renewal-hooks/deploy/flexedge-tls-renew.sh` and `chmod +x`, or click **Install Automatically** (requires write access to the hooks dir from the container — works natively in Options 1 and 2)

The script calls `POST /tls/api/renew` with the renewed domain. All deployments linked to that certificate (and with auto-renew enabled) are re-deployed automatically, including SMC policy upload.

### Troubleshooting TLS Manager

**No certificates in "Discovered"** — check the container can read `/etc/letsencrypt/live/`:

```bash
docker exec flexedge-admin ls /etc/letsencrypt/live/
```

Permission denied means the volume mount is missing or read-only is blocking access. Verify `docker/docker-compose.yml` has the mount and certbot has issued at least one certificate.

**Deployment fails with "SMC login failed"** — check the TLS dashboard's Activity Log for the full error. Most likely the tenant's Default Domain in Admin Portal doesn't match what the API key can access. For domain-scoped keys, the Admin Portal connection form auto-suggests the domain name from the API client name.

**An engine is missing from the dropdown** — the engine list covers all SMC types (`single_fw`, `fw_cluster`, `single_layer2`, `layer2_cluster`, `virtual_fw`, `master_engine`, `single_ips`, `virtual_ips`, `virtual_firewall_layer2`, `cloud_single_fw`). If an engine is still missing:

- Check the API key has the engine listed as a *granted element* in SMC Management Client → Administration → Access Rights → API Clients → *key* → Permissions
- Check the engine belongs to the same admin domain as the tenant's configured login domain
- The Activity Log records every `fetch_engines` query with the full returned list

**"Could not determine active policy" warning** — the engine has no installed policy. Run `firewall policy-upload --name <engine>` via CLI first, or assign a policy in SMC Management Client.

**Renewal webhook returns 401** — the token in the deploy-hook script no longer matches `/config/.tls_api_token`. Regenerate the script from **TLS Manager → Renewal Hook** and re-install it.

**Deployment succeeds but TLS inspection doesn't work** — verify the policy was actually uploaded (check the "Upload" step detail), the engine's TLS inspection is enabled in SMC Management Client (*{engine} → Add-Ons → TLS Inspection*), and the access rule isn't shadowed by a higher-priority rule (new rules are inserted at position 1 by default but the policy may have higher-priority rules above the auto-managed section).

---

## Publishing a Clean Release

The development repository may contain client-specific migration scripts and data. To publish a sanitized version to the public repo:

```bash
./scripts/pack-release.sh                       # Build, commit, push (default)
./scripts/pack-release.sh --no-push             # Build and commit only
./scripts/pack-release.sh --message "v2.1.0"    # Custom commit message
```

The script builds a clean `./FlexEdgeAdminProd/` folder, sanitizes client data, runs a leak-detection scan, commits, and pushes to `https://github.com/smaterazzi/FlexEdgeAdminProd.git`. See [CLAUDE.md § Publishing & Release](../CLAUDE.md#publishing--release) for the full workflow.

---

## Verifying the running version

Three ways to confirm which build is actually live on a given server:

**1. Web UI sidebar** — every page shows `v{version} ({commit})` in the footer. Hover for the full commit SHA and ISO build date. Click to open `/version` JSON.

**2. `/version` endpoint** (unauthenticated, safe for monitoring):

```bash
curl -s https://admin.example.com/version | jq
```

Returns:

```json
{
  "version":     "2.1.0",
  "commit":      "ba60b5b",
  "commit_full": "ba60b5b0abc...",
  "build_date":  "2026-04-22T01:02:32Z",
  "display":     "v2.1.0 (ba60b5b) 2026-04-22"
}
```

**3. Docker env** — inspect what was baked into the image at build time:

```bash
docker exec flexedge-admin env | grep FLEXEDGE_
```

### Compare against the source repo

```bash
# Short commit of the latest code:
git log -1 --format="%h %ci %s"

# Latest released version in CHANGELOG:
grep -m1 -o '## \[[^]]*\]' CHANGELOG.md
```

If the `/version` `commit` matches your local `git rev-parse --short HEAD`, the deployed build corresponds to your source tree. If it shows `"commit": "unknown"`, the image was built bypassing `deploy.sh` / `make dev` / `make prod` (e.g. raw `docker compose build`), so the metadata wasn't injected. Rebuild via `./deploy.sh` to fix.

---

## Troubleshooting

### Container/service won't start

```bash
# Docker (options 2 & 3)
docker compose -f docker/docker-compose.yml logs -f flexedge-web

# Standalone (option 1)
sudo journalctl -u flexedge.service -n 50
```

Common issues:

- `FLASK_SECRET_KEY is not set` → generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- `Encryption key file not found` → ensure `config/` directory is writable
- `Azure AD errors` → verify `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` in `.env`

### Login redirects to wrong URL

The app runs behind a reverse proxy in all three options. The proxy must set `X-Forwarded-Proto: https` and `X-Forwarded-For` headers. The app includes `ProxyFix` middleware to handle this — nginx, Traefik/Coolify, and Apache all set these headers by default.

If Azure AD reports "redirect URI mismatch": confirm the exact URL in the App Registration matches what the app generates. For Coolify, it must be `https://<your-domain>/auth/callback`.

### Setup wizard doesn't appear

The setup wizard only shows when the database has zero users. To re-run setup:

```bash
# Option 1 — standalone
sudo systemctl stop flexedge
sudo rm /etc/flexedge/flexedge.db
sudo systemctl start flexedge

# Option 2 — docker + nginx
rm config/flexedge.db; make dev

# Option 3 — Coolify
# Use the "Terminal" to delete /config/flexedge.db, then redeploy
```

### SMC connection fails

Verify the server can reach your Forcepoint SMC (firewall, VPN, routing). From inside the container (options 2, 3):

```bash
docker exec flexedge-admin python -c \
  "import requests; print(requests.get('https://smc.yourcompany.com:8082', verify=False).status_code)"
```

### TLS certificate issues (option 2 only)

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml \
  exec certbot certbot certificates

# Force renewal
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml \
  exec certbot certbot renew --force-renewal
```

For Coolify (option 3), TLS is managed automatically by Traefik — check the app's **Logs** tab in Coolify if certificates aren't appearing.

---

## Architecture Summary

| Component | Option 1 (Standalone) | Option 2 (Docker+nginx) | Option 3 (Coolify) |
| --------- | --------------------- | ----------------------- | ------------------ |
| Reverse proxy | nginx (host) | nginx container | Traefik (Coolify) |
| TLS | certbot (host) | certbot container | Traefik + Let's Encrypt |
| App server | gunicorn (systemd) | gunicorn (container) | gunicorn (container) |
| Database | SQLite in `/etc/flexedge/` | SQLite in bind mount | SQLite in named volume |
| Process manager | systemd | Docker `restart: unless-stopped` | Coolify |
| Logs | `journalctl` | `docker compose logs` | Coolify UI |
| Updates | `git pull && installer` | `./deploy.sh --update` | Coolify Redeploy / webhook |
