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
5. Creates a systemd service (`flexedge.service`) binding gunicorn to `127.0.0.1:8088`
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

- `flexedge-web` — gunicorn + Flask on internal port 8088
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

Same guided bootstrap as production (Docker check, `.env` creation, optional `azure-setup.sh`), then `docker compose up --build` attached — Ctrl+C to stop. Access the app at `http://localhost:8088`.

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
   - Routes traffic to the container's port 8088

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

**Automated (recommended)** — pass `--verify <URL>` to `pack-release.sh` and it polls the customer's `/version` endpoint after pushing until the new commit shows up:

```bash
# Single customer
./scripts/pack-release.sh --verify https://admin.customer1.com

# Multiple customers in one run
./scripts/pack-release.sh \
    --message "v2.1.1 — urgent fix" \
    --verify https://admin.customerA.com \
    --verify https://admin.customerB.com

# Increase timeout per URL (default is 30 seconds)
./scripts/pack-release.sh --verify-timeout 120 --verify https://admin.customer.com
```

The script polls each URL every 10 seconds. When the `/version` endpoint's `commit` matches the commit you just pushed, it's flagged **OK**. If it never matches within the timeout, it's flagged **FAIL** with the last-seen version for debugging. Summary example:

```
    Customer verification:
      OK   https://admin.customerA.com  →  v2.1.1 (abc1234)
      FAIL https://admin.customerB.com  →  stuck on v2.1.0 (004c724)
```

**Manual** — if you don't want the script to wait:

```bash
# What you just published:
grep -m1 -o '## \[[^]]*\]' CHANGELOG.md   # → ## [2.1.1]
git rev-parse --short HEAD                 # → abc1234

# What a customer's server reports:
curl -s https://customer.example.com/version | jq
```

If the customer's `commit` doesn't match what you pushed, the update hasn't landed yet:

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
| `data/projects/` | Migration project manifests + uploaded FortiGate `.conf` files | In-flight migrations lost (audit V1, 2026-05-29 — included in `/admin/backup` since LE.5.a) |
| `/config/letsencrypt/` | Certbot state: account keys, lineages (live/archive), renewal config | Operator must re-register at LE AND re-issue every cert (LE.5.a, 2026-05-29 — included in `/admin/backup`) |

### Location by deployment

| Option | Path |
| ------ | ---- |
| Standalone | `/etc/flexedge/` + `/var/lib/flexedge/projects/` (or `$FLEXEDGE_PROJECTS_DIR`) |
| Docker + nginx | `<project>/config/` + `<project>/data/projects/` (bind-mounted to `/app/data/projects/` in container) |
| Coolify | Persistent volume `flexedge-config` (mounted at `/config`) + persistent volume for `/app/data/projects/` |

### Backup methods

- **Admin Portal → Backup** (LE.5.a, 2026-05-29): downloads a ZIP with `flexedge.db` + `encryption.key` + the full `/config/letsencrypt/` tree (accounts / live / archive / renewal) + `data/projects/`. Restore is reissue-free for LE certs and preserves in-flight migrations. `.env` is the only critical file NOT in the ZIP (it contains operator-supplied secrets like Azure AD credentials — re-create from `config/.env.example` after restore).
- **Manual**: copy `flexedge.db`, `encryption.key`, `.env`, `/config/letsencrypt/`, AND `data/projects/` from the location above to secure storage.
- **Coolify**: use the built-in backup feature with S3 target; make sure the `data/projects/` volume AND the `/config/letsencrypt/` subtree are in the backup set.

### Restore

Place `flexedge.db`, `encryption.key`, `.env`, `/config/letsencrypt/`, and `data/projects/` in the correct location, then restart. All tenants, users, API keys, LE certs (no re-issuance needed), and in-flight migration projects are restored.

Without `encryption.key`, API keys stored in the database are permanently irrecoverable. This is by design.

---

## Local verification without Azure AD (audit V3, 2026-05-29)

Sometimes you need to drive authenticated routes from a shell — to verify a fix, reproduce a bug, or smoke-test before a deploy — and standing up a full Entra ID app registration for every local checkout is overkill. The **dev auth bypass** synthesises a session for a configured email address, letting `curl` / `httpie` / Flask test client reach every `@login_required` route without OIDC.

### Activation (dev only)

Set **both** of these env vars before starting the app:

```bash
export FLASK_DEBUG=1
export FEA_DEV_AUTH_BYPASS_EMAIL=verify@example.com   # any email
```

The two-key gate is intentional. A single env var would be too easy to leave on in a Coolify config; requiring `FLASK_DEBUG=1` ties activation to the same flag that already disables `SESSION_COOKIE_SECURE` and other dev affordances.

When active, the boot log shows a banner:

```text
═════════════════════════════════════════════════════════════
  DEV AUTH BYPASS IS ACTIVE — Entra ID login is SKIPPED.
  Every request becomes user=verify@example.com.
  Set both FLASK_DEBUG=0 AND unset FEA_DEV_AUTH_BYPASS_EMAIL
  to disable. NEVER ship a production image with this on.
═════════════════════════════════════════════════════════════
```

The bypass also disables the setup wizard — `/setup` returns HTTP 503 with a flash explaining why. Bootstrap a real Super Admin via genuine Entra ID first, **then** turn the bypass on for verification work.

### Production guards

1. The Docker image ships with `FLASK_DEBUG=0`; the bypass cannot activate.
2. The `FEA_DEV_AUTH_BYPASS_EMAIL` env var is not in `.env.example` and not documented in the production deployment paths.
3. Every authenticated request emits a `WARNING` log line naming the bypass email and the route — accidental activation in production would show up in audit logs immediately.
4. The setup wizard refuses to run while the bypass is active, so a bypassed login cannot become Super Admin.

### Companion: CSRF for `curl` POST flows

The web UI sends a CSRF token in every form via the `<meta name="csrf-token">` injection in `base.html`. For shell-driven POSTs (where extracting the token is friction), the test client typically sets `app.config['WTF_CSRF_ENABLED'] = False`. There is no env-var equivalent today; if `curl`-driven POST verification becomes common, file a follow-up to wire a `FEA_DEV_DISABLE_CSRF=1` flag gated by the same `FLASK_DEBUG=1` check.

---

## TLS Manager — certbot integration

The TLS Manager feature (`/tls/*`, admin-only) automates TLS certificate deployment onto Forcepoint NGFW engines. It can either:

- Read certbot-managed certificates from `${CERTBOT_LIVE_DIR}` (default `/config/letsencrypt/live`) — the **legacy flow**, where you run certbot yourself (on the host or as a sidecar) and FEA discovers what's there; OR
- Drive certbot itself via the built-in **Let's Encrypt CRUD** UI at `/tls/letsencrypt/*` (Roadmap item 5, landed 2026-05-11) — operator submits a request through the web UI, FEA's queue runner spawns `certbot certonly` against `/config/letsencrypt/`, and the resulting lineage is picked up by the same TLS deploy pipeline.

Both flows share the same `ManagedCertificate` table; you can mix them on the same deployment.

### Let's Encrypt CRUD setup (recommended for new deployments)

The FEA Docker image bundles `certbot` and runs it under the unprivileged gunicorn user. To avoid the "Read-only file system: `/etc/letsencrypt/.certbot.lock`" failure mode, **certbot is redirected to `/config/letsencrypt/` and siblings** — all subdirectories of the existing `/config/` bind-mount that's already in `docker/docker-compose.yml`:

| Env var | Default | What lives here |
| ------- | ------- | --------------- |
| `CERTBOT_CONFIG_DIR` | `/config/letsencrypt` | Account keys, cert lineage (`live/`, `archive/`, `renewal/`) |
| `CERTBOT_WORK_DIR` | `/config/letsencrypt-work` | Transient state during issuance |
| `CERTBOT_LOGS_DIR` | `/config/letsencrypt-logs` | Per-run certbot logs |
| `CERTBOT_WEBROOT` | `/config/letsencrypt-webroot` | HTTP-01 challenge files; FEA's Flask app serves them at `/.well-known/acme-challenge/<token>` |
| `CERTBOT_LIVE_DIR` | `${CERTBOT_CONFIG_DIR}/live` | Where the TLS Manager's `certbot_reader` scans for trackable certs |

All five paths are env-overridable from `.env`. The defaults Just Work for the standard Docker deployment because `/config/` is already mounted writable.

**HTTP-01 challenge proxy.** Let's Encrypt's validation servers fetch `http://<your-fqdn>/.well-known/acme-challenge/<token>` during issuance. nginx/Traefik in front of FEA MUST forward this path to FEA's gunicorn (the path lives on FEA's Flask app — see `acme_challenge_bp` in [webapp/letsencrypt_manager.py](../webapp/letsencrypt_manager.py)). For nginx, add this `location` block before any catch-all:

```nginx
location /.well-known/acme-challenge/ {
    proxy_pass http://flexedge-web:8088;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

For Traefik, the default `PathPrefix(`/`)` rule already covers the path — no extra config needed.

**Operator flow.** Open `/tls/letsencrypt`, accept the LE TOS in the one-shot account wizard, configure the per-FEA-Domain glob allowlist on `/tls/letsencrypt/patterns` (e.g. `*.prod.example.com`), then click **New cert**. Domain Admin or higher with the `letsencrypt` bypass feature gets instant issuance via a watcher card; otherwise the request goes through the standard change-management queue at `/changes/`. On success the cert appears in **TLS Manager → Certificates** ready to deploy.

### Legacy / external certbot integration

If you'd rather run certbot yourself (on the host, as a sidecar container, or via an existing managed-certs pipeline) and just have FEA discover the output, set `CERTBOT_LIVE_DIR` in `.env` to point at your existing lineage directory (typically `/etc/letsencrypt/live`) and ensure the FEA container can read it.

#### Workflow

1. **Issue certificates with certbot** for each service behind a firewall (see per-deployment-option setup below)
2. **Track** — open **TLS Manager → Certificates**; discovered certificates can be tracked with one click
3. **Deploy** — **TLS Manager → Deploy**: pick the tracked certificate, a tenant (from Admin Portal), an API key, a target engine, then fill the service name + public/private IPv4
4. **Execute** — the pipeline imports the cert as a `TLSServerCredential`, creates `{service}-PublicIPv4` / `{service}-PrivateIPv4` host objects, assigns the credential to the engine's TLS inspection, creates an HTTPS access rule with deep inspection + file filtering + decryption in section `Service {name} - TLS Protection`, and uploads the policy
5. **Auto-renewal** — wire the deploy-hook (below) so every certbot renewal re-runs the full pipeline automatically

#### Certbot setup per deployment option

#### Option 1 — Standalone

Certbot is already installed on the host (used for the webapp's own TLS). The `/etc/letsencrypt` directory is directly accessible to the Python process. Set `CERTBOT_LIVE_DIR=/etc/letsencrypt/live` in `/etc/flexedge/.env`.

No extra configuration needed. Issue a certificate for each service you want to protect:

```bash
sudo certbot certonly --standalone -d service1.yourcompany.com
sudo certbot certonly --standalone -d service2.yourcompany.com
```

They appear automatically in **TLS Manager → Certificates**.

#### Option 2 — Docker + nginx

The main image now bundles `certbot`. If you keep the legacy flow, the `docker/docker-compose.yml` would mount `/etc/letsencrypt:/etc/letsencrypt:ro` into the `flexedge-web` container so certificates managed by the existing host `certbot` are visible to TLS Manager — and you'd set `CERTBOT_LIVE_DIR=/etc/letsencrypt/live` in `.env` to override the new default.

To issue a certificate for a *target service* (not the webapp itself):

```bash
docker compose -f docker/docker-compose.yml \
  run --rm certbot certonly --webroot -w /var/www/certbot \
  -d service.yourcompany.com
```

#### Option 3 — Coolify / Traefik

The webapp's own TLS is handled by Traefik and does not use certbot. To use TLS Manager via the legacy flow, either:

1. Run certbot on the **host** and bind-mount `/etc/letsencrypt:/etc/letsencrypt:ro` into the Coolify container (add under "Persistent Storage" in Coolify UI), then set `CERTBOT_LIVE_DIR=/etc/letsencrypt/live` in `.env`
2. Or run a dedicated certbot sidecar container that writes to a shared volume mounted into the FlexEdgeAdmin container

For Coolify deployments the **Let's Encrypt CRUD flow above is usually simpler** — FEA owns everything under `/config/letsencrypt/` and the host doesn't need certbot at all.

### Renewal hook

Whichever option you use, wire certbot's deploy-hook to FlexEdgeAdmin so deployments re-execute after each renewal:

1. **TLS Manager → Renewal Hook** — shows the ready-to-install shell script + the API token
2. Copy the script to `/etc/letsencrypt/renewal-hooks/deploy/flexedge-tls-renew.sh` and `chmod +x`, or click **Install Automatically** (requires write access to the hooks dir from the container — works natively in Options 1 and 2)

The script calls `POST /tls/api/renew` with the renewed domain. All deployments linked to that certificate (and with auto-renew enabled) are re-deployed automatically, including SMC policy upload.

### Troubleshooting TLS Manager

**No certificates in "Discovered"** — check the container can read `${CERTBOT_LIVE_DIR}` (default `/config/letsencrypt/live`):

```bash
docker exec flexedge-admin ls ${CERTBOT_LIVE_DIR:-/config/letsencrypt/live}
```

Empty result + new-flow: no certs issued yet — submit one at `/tls/letsencrypt/new`. Empty result + legacy-flow: verify `CERTBOT_LIVE_DIR` in `.env` points at your external lineage directory and the bind-mount exposes it (read-only is fine for the legacy flow). Permission denied on the new flow: see the next entry.

**Let's Encrypt CRUD fails with "Read-only file system: `/etc/letsencrypt/.certbot.lock`"** — certbot was launched against its compiled-in defaults instead of `/config/`. This was the LE.2 first-run bug surfaced 2026-05-11; the fix is in `webapp/letsencrypt_certbot.py` which now passes explicit `--config-dir` / `--work-dir` / `--logs-dir` to every invocation. If you hit this, your container is running pre-hotfix code — pull the latest image and restart.

**Let's Encrypt CRUD fails with "unauthorized" / HTTP-01 challenge timeout** — Let's Encrypt couldn't fetch the challenge file. Verify:

- `http://<your-fqdn>/.well-known/acme-challenge/test` is reachable from the public internet (port 80 open, DNS pointing at the FEA host, no upstream HTTPS-only redirect)
- nginx/Traefik forwards `/.well-known/acme-challenge/*` to FEA's gunicorn (the proxy rule shown earlier in this section)
- The `CERTBOT_WEBROOT` directory exists and is writable inside the container (`ls /config/letsencrypt-webroot` from `docker exec`)

**Deployment fails with "SMC login failed"** — check the TLS dashboard's Activity Log for the full error. Most likely the tenant's Default Domain in Admin Portal doesn't match what the API key can access. For domain-scoped keys, the Admin Portal connection form auto-suggests the domain name from the API client name.

**An engine is missing from the dropdown** — the engine list covers all SMC types (`single_fw`, `fw_cluster`, `single_layer2`, `layer2_cluster`, `virtual_fw`, `master_engine`, `single_ips`, `virtual_ips`, `virtual_firewall_layer2`, `cloud_single_fw`). If an engine is still missing:

- Check the API key has the engine listed as a *granted element* in SMC Management Client → Administration → Access Rights → API Clients → *key* → Permissions
- Check the engine belongs to the same admin domain as the tenant's configured login domain
- The Activity Log records every `fetch_engines` query with the full returned list

**"Could not determine active policy" warning** — the engine has no installed policy. Run `firewall policy-upload --name <engine>` via CLI first, or assign a policy in SMC Management Client.

**Renewal webhook returns 401** — the token in the deploy-hook script no longer matches `/config/.tls_api_token`. Regenerate the script from **TLS Manager → Renewal Hook** and re-install it.

**Deployment succeeds but TLS inspection doesn't work** — verify the policy was actually uploaded (check the "Upload" step detail), the engine's TLS inspection is enabled in SMC Management Client (*{engine} → Add-Ons → TLS Inspection*), and the access rule isn't shadowed by a higher-priority rule (new rules are inserted at position 1 by default but the policy may have higher-priority rules above the auto-managed section).

---

## DHCP Reservation Manager

The DHCP Manager (`/dhcp/*`, admin-only) lets operators define MAC-to-IP reservations on engines with the internal DHCP server enabled. The SMC REST API doesn't expose DHCP reservations, so the feature combines two storage layers:

- **SMC Host elements** = source of truth (`Host.name`, `Host.address`, MAC stored in `Host.comment` via the marker `[flexedge:mac=aa:bb:cc:dd:ee:ff]`).
- **Per-node SSH** = the deployment surface — Phase 4 will write `host { }` blocks into `/data/config/base/dhcp-server.conf` on each cluster node. Phase 1c (shipped) sets up the SSH credentials; Phase 1b reads `dhcpd.leases` from each node.

**Phase status as of v2.2.0-dev:** scope discovery, reservation CRUD, SSH credentials, and lease viewer are live. Engine-side reservation push (Phase 4) lands once the [Phase 0 lab test](DHCP-Phase0-LabTest.md) confirms `dhcp-server.conf` survives policy operations on a real cluster.

### Operator workflow

1. **Set the FEA source IP per tenant** — DHCP Manager → Credentials, Card 1. Click the magnifier to auto-detect FlexEdgeAdmin's public IP, or type whatever IP the engine will see when FEA connects (LAN IP if on the same private subnet). One-time per tenant.
2. **Discover scopes** — DHCP Manager → Scopes → pick a tenant + API key + engine → Discover. Every interface (and VLAN child) with the internal DHCP server enabled appears as a row. Enable the scope to start managing it.
3. **Discover the cluster** — Credentials page, Card 2: pick the same tenant + key + engine → Discover nodes. FlexEdge enumerates each node's NDIs (Node Dedicated IPs) by walking the engine's physical-interface config, and detects whether the cluster uses **Node-Initiated Contact** (via the `reverse_connection` flag).
4. **Install the SSH allow rule** — the rule install card shows checkboxes per candidate IP, one per node. SMC-initiated cluster: all pre-checked (one rule covers the whole cluster). Node-initiated cluster: explicit selection required (the engine's primary mgmt IP usually isn't reachable from FEA in this mode). Click **Install rule + push** to create the `flexedge-dhcp-mgmt-ssh-<engine>` rule with all chosen IPs as destinations and push the policy.
5. **Bulk-enroll nodes** — green **Enroll all (N)** button at the top of the cluster nodes section enrolls every unenrolled node in one batch: ONE SMC session, ONE per-engine lock, parallel-friendly. For each node FlexEdge sets a 64-char random root password via `change_ssh_pwd` and SSH-connects to capture the host fingerprint. Operator never types or sees a password. Per-node Auto-enroll buttons remain for surgical single-node operations.
6. **Add reservations** — back on the scope detail page, **New reservation** opens the Host CRUD form. The MAC is stored as a marker in the SMC Host's `comment`. To import existing Host elements that already carry the marker, click **Sync from SMC**.
7. **Inspect leases** — scope detail → **View leases**. Reads `/spool/dhcp-server/dhcpd.leases` from every enrolled cluster node, merges them, and cross-checks each lease against tracked reservations: green badge = matches, red = IP mismatch with reservation, grey = pool client.
8. **Deploy reservations to the engine** — pending Phase 4. Today the **Deploy** button on the scope page logs the intent only.

### Subnet active-discovery scan

The lease viewer (`/dhcp/scopes/<id>/leases`) carries a **Scan subnet** button next to Refresh. Clicking it runs a parallel ICMP sweep + arping fallback from the cluster's primary verified node, then joins the results with `dhcpd.leases` to classify every IP into one of six discovery states. In-pool responders without a lease (typically static IPs or new clients) are promoted into the upper table where they can be ticked and added to reservations directly. Out-of-pool responders appear in a separate "Discovered hosts" card below.

The button opens a small modal with three range options (Scope / Full subnet / Custom range). Anything bigger than /24 requires an explicit confirmation; hard cap at 4096 hosts (= /20). The scan runs in a background thread with a live progress bar + 10-line rolling log so big subnets don't block the page.

Full guide with the legend, filter buttons, and troubleshooting: [DHCP-SubnetScan.md](DHCP-SubnetScan.md).

### Summary view

The DHCP Manager dashboard (`/dhcp/`) gives at-a-glance health of the whole feature:

- **Top stats row** — tracked scopes / enabled / total reservations / out-of-sync.
- **Credentials stats row** — enrolled engines / total node credentials / verified (with red "N failing" badge if any) / SSH allow rules in policies.
- **Enrolled clusters & nodes table** — one row per (tenant, engine) showing node count + chip list (`n0, n1, n2`), status pills (green ok / red failing), rule name with multi-IP indicator (`+N more`), and last-verified timestamp. Direct link to the credentials page for management.

### Required SMC API permissions

The API key used for DHCP Manager must allow:

- Reading engine config (`engine.physical_interface`, `engine.nodes[i].interface_status`)
- Reading and editing the active policy (`fw_policy.fw_ipv4_access_rules.create / .delete`, `engine.upload`)
- Calling `node.ssh(enable=...)` and `node.change_ssh_pwd(...)` per cluster node — typically only **admin-role** API clients have these rights

If the key lacks `change_ssh_pwd` permission, auto-enrollment fails with the SMC error in the activity log. Either grant the right or use a key that has it.

### Network requirements (untrusted-zone deployments)

FlexEdgeAdmin is often deployed on a different network than the engines (Coolify host, dedicated VM, etc.). For SSH to work, the engine must accept port 22 from FEA's egress IP. The DHCP Manager handles this by installing an SSH allow rule on the engine's policy at enrollment time:

- **Source** = the tenant's `flexedge_source_ip` (the IP the engine sees from FEA).
- **Destination** = a Host element pointing to the chosen engine interface IP.
- **Service** = TCP/22.
- **Action** = Allow.
- **Lifetime** = until you click **Remove SSH rule** OR delete the last credential for that engine. Both paths re-upload the policy.

Intermediate firewalls (between FEA and the engine) are out of scope — the operator owns those.

### Security model (Phase 1c)

| Layer | Mechanism |
| ----- | --------- |
| Authentication | Password (Fernet-encrypted in DB), generated by FlexEdge — operator never sees it |
| Server identity | Host fingerprint pinned at first contact; `paramiko.MissingHostKeyPolicy` rejects mismatches |
| `authorized_keys` | NOT modified — engine config is left untouched |
| Audit | Every SMC API call carries a comment with operator email + FEA hostname (visible in Management Client policy audit log) |
| Concurrency | Per-engine `threading.Lock` prevents simultaneous `change_ssh_pwd` calls |
| Recovery | A3 path — when a verify call fails with `paramiko.AuthenticationException`, the credential row gets a **Force re-bootstrap** button that rotates the password again via SMC |

### Troubleshooting DHCP Manager

**Discovery returns 0 scopes on an engine you know has DHCP active** — hit the diagnostic endpoint:

```text
GET /dhcp/api/tenants/<TID>/api-keys/<KID>/engines/<engine>/interfaces/debug
```

It dumps the raw SMC interface JSON plus the walker's per-level decisions. If `dhcp_here` is `false` on a level you expect, share the JSON shape and the parser can be extended (it currently handles top-level + node-nested + dict/string config values).

**"Tenant FEA source IP not configured" error during rule install** — set it on the Credentials page, Card 1, before enrolling.

**SSH bootstrap fails at `connect` stage** — the SSH allow rule is in place but the path is still blocked. Check intermediate firewalls between FEA and the engine. The TCP probe is short (10s default) and aborts cleanly without mutating the engine.

**SSH bootstrap fails at `change_pwd` stage** — usually permission. The API key needs admin rights to call `node.change_ssh_pwd`. Check the activity log for the SMC error message.

**Re-verify says "host key mismatch"** — the engine's host key changed (typically a re-image). Click **Force re-bootstrap** — TOFU re-captures the new fingerprint and rotates the password.

**Re-verify says "AUTH_FAIL"** — someone changed root's password out of band. Click **Force re-bootstrap** — the password is rotated via SMC API and re-stored.

**Manual rule removal refused with "credentials still depend on it"** — delete the credentials first; the rule auto-tears-down when the last one goes.

**Rule shown as "found in our records but missing from policy"** — admin removed it from Management Client. The credentials page surfaces a banner with **Recreate rule** button.

For the per-phase test procedures, see [DHCP-Phase0-LabTest.md](DHCP-Phase0-LabTest.md), [DHCP-Phase1-Testing.md](DHCP-Phase1-Testing.md), and [DHCP-Phase3-Testing.md](DHCP-Phase3-Testing.md). For the subnet active-discovery scan, see [DHCP-SubnetScan.md](DHCP-SubnetScan.md).

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
