# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.2.0-dev] - 2026-04-25

### Added — DHCP Reservation Manager (in progress — phases 0, 1, 1b, 1c, 2, 3, 4 landed)

**Phase 4 — engine-side reservation push (2026-04-25):**

- **`webapp/dhcp_pusher.py`** — new module: renders FlexEdge-managed reservations as ISC dhcpd `host { hardware ethernet ...; fixed-address ...; }` blocks, merges them into `/data/config/base/dhcp-server.conf` between `# FLEXEDGE-RESERVATIONS-BEGIN` / `# FLEXEDGE-RESERVATIONS-END` markers (idempotent: replaces existing block in place), and atomically writes via `put_file()` (tmp + posix_rename). SMC's subnet block is never touched — host blocks at top level work because ISC matches them by IP into the surrounding subnet.
- **Per-node orchestration** — `push_scope_to_engine(scope_id, operator_email, action)` runs against every cluster node in order: TCP probe → credential verify → read current file → render + merge → atomic write → re-read verify (sha256 round-trip) → best-effort `pkill -HUP` reload. Each node gets a `DhcpDeployment` audit row with sha256_before/after, unified diff (trimmed to 200 lines), duration, and any reload warning. Reservation rows flip to `synced` on full success, `error` on partial / total failure (with `last_error` populated).
- **Pre-flight guard** — `_check_preconditions()` blocks the push if the scope isn't `enabled_in_flexedge`, any cluster node lacks a verified credential, or the SSH allow rule is missing — surfacing a clear operator-facing message + `dhcp_activity_logs` row instead of attempting and failing per-node.
- **Wired into existing routes** — `POST /dhcp/scopes/<id>/deploy` and `POST /dhcp/scopes/<id>/resync` now call the pusher (replacing the Phase-3 stubs that only flashed warnings). The existing "Deploy to engine" button on `scope_detail.html` works without template changes.
- **Per-node failure isolation** — failures on one node never abort the loop; aggregate status is `ok` (all nodes), `partial` (some), or `failed` (none). Operator gets per-node detail in flash messages and the deployment-history card.
- **Reload best effort** — `pkill -HUP` against `dhcp-server` then `dhcpd` (Forcepoint engines run the daemon under either name); if neither matches we surface a warning and tell the operator to refresh the policy in SMC. Never fails the deployment over a reload issue.

**Cluster-wide enrollment + summary view (UX iteration, late Apr 2026):**

**Cluster-wide enrollment + summary view (UX iteration, late Apr 2026):**

- **Multi-IP SSH allow rule** — `add_ssh_access_rule(... destination_ips: list)` now creates one rule with N Host elements (`<rule_name>-dst-0`, `<rule_name>-dst-1`, …) so a single rule covers every cluster node. Multi-checkbox picker in the UI; SMC-initiated cluster pre-checks all IPs, node-initiated requires explicit operator selection. Cleanup symmetrically removes both the new `-dst-<n>` shape and the legacy single `-dst` shape.
- **Bulk enrollment** — new `POST /credentials/bootstrap-batch` endpoint enrolls every unenrolled node for an engine within ONE `smc_session` and ONE per-engine lock. Green "Enroll all (N)" button at the top of the cluster nodes section reads each node form's data and submits a single POST. Per-node "Auto-enroll" buttons retained for surgical operations.
- **Dashboard summary** — `/dhcp/` now has a second stats row (Enrolled engines, Total node credentials, Verified, SSH allow rules in policies) and an "Enrolled clusters & nodes" table grouped by (tenant, engine) showing node count, status pills, rule name with multi-IP indicator (`+N more`), and last-verified timestamp.
- **NDI-based node discovery** — `list_cluster_nodes()` now walks `engine.physical_interface` config (instead of the runtime `interface_status` probe that returned empty). Picks up `NodeInterface` and `SingleNodeInterface` entries from physical + VLAN children, groups by `nodeid`. Skips `cluster_virtual_interface` (CVI) — those are shared cluster IPs, not per-node targets.
- **Node-initiated contact detection** — new `is_node_initiated_contact()` reads the `reverse_connection` flag on every primary mgmt interface (the SDK's name for what the SMC GUI calls "Node-Initiated Contact"). Banner in the rule install card; per-node IP picker requires explicit selection vs auto-suggesting the primary mgt IP.

- **Phase 1c — Auto-enrollment via SMC API**. Replaces the Phase 1 password-prompt flow.
  - **No password ever typed by the operator.** FlexEdgeAdmin generates a 64-char random root password and sets it via SMC's `node.change_ssh_pwd` endpoint.
  - **No public-key install.** Auth is **password-only** (Fernet-encrypted in DB, pinned host fingerprint), engine `authorized_keys` left untouched.
  - **SSH allow rule** auto-installed on the engine's active policy (name `flexedge-dhcp-mgmt-ssh-<engine>`), with operator-confirmed source IP. Rule is removed when last credential for the engine is deleted, or via a manual "Remove SSH rule" button. Detected if removed externally — banner asks operator to recreate.
  - **Per-engine concurrency lock** prevents two enrollments racing on the same node's password.
  - **A3 recovery path**: when verify fails with `paramiko.AuthenticationException` (someone changed root pw out of band), an operator-confirmed "Force re-bootstrap" button rotates the password again via SMC API.
  - **Pre-flight TCP probe** to the chosen node IP before mutating anything — fails fast with a clear error if the rule push didn't open the path.
  - **Public-IP probe** (api.ipify.org / ifconfig.me / icanhazip) suggests the FEA source IP per tenant; operator confirms or overrides.
- **Schema changes (auto-migrating on boot)**:
  - `tenants.flexedge_source_ip` (new column, ALTER TABLE on existing DBs).
  - `dhcp_engine_credentials` — replaces `public_key_openssh` + `private_key_pem` with `encrypted_password`. Existing key-based rows from earlier dev-only Phase 1 are dropped on first boot of the new schema (logged warning); re-enroll affected nodes.
  - `dhcp_engine_ssh_access` (new) — tracks the FlexEdge-managed SSH allow rule per engine with the rule name as the stable lookup tag.
- **CLAUDE.md DB schema section** to be updated in Phase 6 along with all docs.

### Phase summary (cumulative across earlier 2.2.0-dev iterations)

- **Phase 0** — [docs/DHCP-Phase0-LabTest.md](docs/DHCP-Phase0-LabTest.md): operator-ready procedure to verify whether `/data/config/base/dhcp-server.conf` survives policy refresh/upload/reboot. Gates Phase 4.
- **Phase 2** — DB tables `dhcp_scopes`, `dhcp_reservations`, `dhcp_deployments`, `dhcp_activity_logs`, `dhcp_engine_credentials`, `dhcp_engine_ssh_access`.
- **Phase 3** — DHCP Manager Blueprint at `/dhcp/*` (admin-only): scope discovery (recursive walker handling multiple DHCP-config shapes), reservation CRUD with `[flexedge:mac=...]` marker on SMC Host comment, sync-from-SMC, deploy stub, diagnostic endpoint, activity log.
- **Phase 1b** — Cluster lease viewer: ISC `dhcpd.leases` parser, per-engine cluster lease table with reservation cross-check (mismatch flagged red).

### Changed — DHCP Reservation Manager

- `webapp/models.py` docstring updated to list the new DHCP tables.
- Sidebar nav gained a "DHCP Manager" section (admin-only).
- `docs/DHCP-ResrvationStrategy.md` → `docs/DHCP-ReservationStrategy.md` (filename typo fix via `git mv`).

## [2.1.0] - 2026-04-15

### Added

- **TLS Manager** — new admin-only feature (`/tls/*`) that automates TLS certificate lifecycle for Forcepoint NGFW engines, bridging Let's Encrypt (certbot) with the SMC API:
  - Track certbot-managed certificates (reads `/etc/letsencrypt/live/`)
  - Deploy pipeline: import cert as `TLSServerCredential`, create host objects, assign to engine TLS inspection, create access rule with deep inspection + file filtering + decryption, upload policy
  - Reuses existing `Tenant` + `ApiKey` models — no duplicate SMC connection config
  - Renewal webhook (`POST /tls/api/renew`, Bearer-token auth) callable by certbot's deploy-hook
  - In-app deploy-hook generator + auto-installer (writes to `/etc/letsencrypt/renewal-hooks/deploy/`)
  - Activity log on dashboard: every operation, full error details, filterable by status
  - Supports domain-scoped API keys (keys that can't enumerate admin domains use their API client name as a domain hint)
- **Certbot in the main Docker image** — `apt install certbot` added to `docker/Dockerfile`
- **`/etc/letsencrypt` volume mount** added to `docker/docker-compose.yml` (read-only)
- **New DB tables** (auto-created on first boot): `managed_certificates`, `tls_deployments`, `tls_deployment_logs`, `tls_activity_logs`
- **Documentation**: TLS Manager feature documented inline in `CLAUDE.md` (developer reference) and `docs/deployment-guide.md` (operator setup + troubleshooting) — same treatment as Admin Portal and Migration Manager

### Changed

- Sidebar nav now includes a "TLS Manager" section (admin-only)
- `CLAUDE.md` updated with the TLS Manager feature description and DB schema additions

### Fixed

- **Engine discovery in TLS Manager** now covers all SMC engine types via a three-stage cascade: (1) generic `Engine.objects.all()`, (2) per-subclass enumeration (Layer 2 / cluster / virtual / master / IPS / cloud), (3) **raw REST fallback** against `/elements/engine_clusters` and every specific-type endpoint. Each engine gets a list of which stages saw it, exposed via the new diagnostic endpoint. Previously only `Layer3Firewall` and `FirewallCluster` were queried.
- **Deploy.sh path with spaces** — the script now uses relative compose paths with an upfront `cd "$PROJECT_DIR"`, fixing the "unknown docker command" word-splitting bug when the project lives under a folder with spaces (e.g. iCloud Drive).

### Added — developer/operator visibility

- **Running build version in the web UI** — sidebar footer now shows `v{version} ({commit})` with a tooltip containing the full commit SHA and ISO build date. Click the version to open the `/version` JSON endpoint.
- **New `/version` endpoint** — returns `{version, commit, commit_full, build_date, display}` as JSON. Unauthenticated, safe for monitoring / uptime checks.
- **Version metadata injection** — `deploy.sh` auto-computes `FLEXEDGE_VERSION` (from CHANGELOG.md top entry), `FLEXEDGE_COMMIT` (short git SHA), `FLEXEDGE_COMMIT_FULL`, `FLEXEDGE_BUILD_DATE` (UTC ISO-8601) before `docker compose build` and passes them as build args. Dockerfile accepts the args and bakes them into `ENV`. `shared/version.py` reads env vars first, falls back to a committed `.version.json` file (stamped by `pack-release.sh`), then to live `git` commands, and finally to CHANGELOG parsing for the version string.
- **Coolify-compatible version stamping** — `scripts/pack-release.sh` writes a `.version.json` file into `FlexEdgeAdminProd/` on every release, containing `version`, `commit`, `commit_full`, and `build_date`. The Dockerfile copies it into the image via a glob wildcard (`COPY .version.jso[n] ./` — silent when the file is absent in the private repo). Coolify customers building directly from the public repo get the correct version displayed in the UI without any Coolify-side configuration.
- **Customer deployment verification** — `pack-release.sh --verify <URL>` polls `<URL>/version` every 5 seconds after pushing until the customer's running build matches the pushed commit. Repeatable (pass `--verify` multiple times for several customers), with a configurable `--verify-timeout` (default 30 seconds). Prints per-customer OK / FAIL summary at the end. Useful for confirming Coolify redeploys landed.
- **TLS engine-fetch activity logging** — every `/api/tenants/<id>/api-keys/<id>/engines` call now writes an entry to `tls_activity_logs` with the returned engine list, so you can see from the dashboard what the API returned without re-opening the browser inspector.
- **New TLS diagnostic endpoint** `/tls/api/tenants/<tid>/api-keys/<kid>/engines/debug` — returns the full engine list with per-source attribution (which discovery stage saw each engine), used for troubleshooting missing-engine cases.

### Removed

- Standalone `FlexEdgeTLSManagement/` folder and its `.gitignore` entry (merged into the main webapp as a Blueprint)

### Changed — developer ergonomics

- `deploy.sh --dev` — new explicit dev flag that runs the guided bootstrap (Docker check, `.env` setup, Azure AD prompt), then `docker compose up --build` in the **foreground** with live logs (Ctrl+C to stop)
- `make dev` now routes through `./deploy.sh --dev` so first-time setup works without manually creating `.env`. Previously it failed if `.env` was missing.
- `make prod` now routes through `./deploy.sh` (production with TLS)
- `make dev-raw` / `make prod-raw` — new escape hatches for the raw `docker compose` commands (CI, debugging) that skip the bootstrap
- `--no-tls` kept as a detached (background) dev mode for CI/automation

## [2.0.0] - 2026-04-12

### Added

- **Three deployment options** documented and supported:
  - **Standalone**: new `scripts/install-standalone.sh` — native install with
    Python venv at `/opt/flexedge/`, config at `/etc/flexedge/`, systemd service
    (`flexedge.service`), nginx site config, certbot-ready
  - **Docker + nginx**: unchanged `./deploy.sh` flow (full stack via compose)
  - **Coolify / Traefik**: new `docker/docker-compose.coolify.yml` — no bundled
    nginx/certbot (Coolify handles TLS, routing, Let's Encrypt via Traefik)
  - Full 3-option comparison table and per-option instructions in
    `docs/deployment-guide.md`
- **Uninstall support** in `deploy.sh`:
  - `--uninstall` — stop/remove containers, preserve all data and config
  - `--uninstall --purge` — full clean slate: deletes DB, encryption key, .env,
    Docker images, certbot volumes (requires typing "PURGE" to confirm)
- **Azure setup automation** (`scripts/azure-setup.sh`) — single command to:
  - Create Entra ID App Registration with OIDC configuration
  - Enable ID tokens, set redirect URIs (dev + production)
  - Create client secret (2-year expiry)
  - Add Microsoft Graph permissions (openid, email, profile)
  - Grant admin consent
  - Generate Flask secret key
  - Write complete `.env` file
  - Flags: `--domain`, `--app-name`, `--skip-consent`
  - Integrated into `deploy.sh` (offers to run automatically)
- **Admin Portal** (`/admin/`) — web-based CRUD for tenants, users, and API keys
  - Tenant management: create, edit, soft-delete SMC server connections
  - User management: create, edit, role assignment (admin/viewer), tenant access mapping
  - API Key management: Fernet-encrypted storage, one-time plaintext display on creation, revoke
  - Backup: download ZIP of database + encryption key from Admin Portal
  - JSON Migration: one-click import from legacy `tenants.json` + `users.json`
  - Admin dashboard with stats, backup, and migration controls
- **Encrypted database** — SQLite with Fernet field-level encryption (AES-128-CBC + HMAC-SHA256)
  - Binary encryption key file (`FXEK` magic header format) auto-generated on first run
  - Without the key file, encrypted API keys are permanently irrecoverable (by design)
  - SQLite WAL mode enabled for concurrent read performance
  - Database schema: `tenants`, `users`, `api_keys`, `user_tenant_access` tables
- **Setup wizard** — one-time `/setup` page on first run
  - Requires Azure AD login first (security: only valid Azure AD users can claim admin)
  - Creates the first admin user, then becomes permanently inaccessible
- **DB-backed data layer** — user profiles and tenant config read from DB with JSON fallback
  - `webapp/user_manager.py` queries DB first, falls back to `users.json`
  - `shared/tenant_config.py` queries DB first, falls back to `tenants.json`
  - CLI tools automatically use JSON fallback (no Flask context needed)
- **New files**: `webapp/admin.py`, `webapp/setup.py`, `webapp/models.py`, `webapp/db_init.py`,
  `shared/encryption.py`, `shared/db.py`, 10 admin templates

### Changed

- **Configuration model** — JSON files replaced by Admin Portal as primary config method
  - `.env` is the only file to edit before first start (Azure AD credentials)
  - Tenants, users, and API keys managed via web UI instead of JSON files
- **Docker volumes** — `config/` directory mounted as a whole (contains DB + key + legacy JSONs)
- **deploy.sh** — no longer creates `tenants.json` / `users.json`; points users to setup wizard
- **requirements.txt** — added `flask-sqlalchemy>=3.1`, `cryptography>=42.0`
- **`.gitignore`** — added `*.db`, `encryption.key`
- **Sidebar** — admin link visible only to admin-role users
- **`scripts/pack-release.sh`** — production release packer
  - Builds a clean `./production/` folder with zero client-specific data
  - Sanitizes firewall names, IP ranges, server URLs, client references
  - Automated verification scan — aborts on any leaked secrets
  - `--no-push` flag to skip pushing (default: commit and push)
  - `--message "msg"` for custom commit messages
  - Preserves `production/.git` across rebuilds (remote config, history retained)

### Security

- Removed `__pycache__/connect.cpython-314.pyc` from git tracking
- Sanitized `scripts/service_mapping.json` (replaced real SMC URL with placeholder)
- Sanitized `config/smc_config.yml.example` (removed client name)
- `production/` folder gitignored — clean public release with no git history leak

---

## [1.0.0] - 2026-04-12

### Added

- **FlexEdgeAdmin branding** — unified project identity replacing "SMC Explorer"
- **Shared tenant configuration** (`shared/tenant_config.py`) — single source of truth
  for SMC connection definitions, used by both CLI and webapp
  - `config/tenants.json` defines URL, SSL, timeout, domain per tenant
  - API keys remain per-user (in `users.json` for web, env var for CLI)
- **Unified Docker setup** — single image containing webapp + CLI + migration scripts
  - `docker/Dockerfile` — python:3.12-slim with gunicorn
  - `docker/docker-compose.yml` — development compose
  - `docker/docker-compose.prod.yml` — production overlay with nginx + certbot TLS
  - `docker/nginx.conf` — reverse proxy with security headers
- **Deployment automation**
  - `deploy.sh` — one-command VPS setup (installs Docker, creates configs, starts services)
  - `Makefile` — convenience targets (dev, prod, stop, logs, cli, update)
  - `docs/deployment-guide.md` — complete operator guide
- **Configuration templates** — `.example` files for all secrets
  - `config/tenants.json.example`, `config/users.json.example`
  - `config/.env.example`, `config/config.ini.example`
- **APP_TITLE env var** — customizable branding per deployment

### Changed

- **Repository restructured** into `cli/`, `webapp/`, `shared/`, `scripts/`, `config/`, `docker/`, `docs/`
- **CLI connect.py** — now supports `--tenant` flag + `SMC_API_KEY` env var; falls back to legacy `config.ini`
- **CLI smc.sh** — passes `--tenant` flag, sets PYTHONPATH, venv at project root
- **webapp/user_manager.py** — resolves tenant references from `tenants.json`; backward compatible with old embedded `smc_url` format
- **users.json format** — profiles now reference tenants by ID instead of embedding full connection details
- Unified `requirements.txt` at project root (merged CLI + webapp deps)

### Security

- Removed `config.ini` from git tracking (contained real API key)
- All secret files added to `.gitignore`: `config.ini`, `tenants.json`, `users.json`, `.env`, `smc_config.yml`
- Docker never bakes secrets into images — always volume-mounted

---

## [0.3.0] - 2026-04-11

### Added

- **Microsoft Entra ID OIDC login** — all webapp routes protected
- **Multi-user support** — per-user SMC API profiles via `users.json`
- **SMC admin domain selection** per session
- **ProxyFix** for correct HTTPS redirect URIs behind reverse proxies

---

## [0.2.0] - 2026-03-11

### Added

- **SMC Explorer webapp** — read-only browser for all SMC objects and policies
- **Migration Manager** — 7-step guided FortiGate-to-Forcepoint migration workflow
- **NAT rules migration** — SNAT dynamic, DNAT static, combined
- **IPsec VPN migration** — profiles, gateways, sites, PolicyVPN
- **Docker deployment** — Dockerfile, docker-compose.yml

---

## [0.1.0] - 2026-01-20

### Added

- Initial CLI tools: `connect.py`, `inquiry.py`, `firewall.py`, `smc.sh`
- Firewall management: list, show, interfaces, add/delete/update interface, VLAN, policy refresh/upload
- Object query and inspection with type/name filtering
- Cluster support: CVI, NDI, multi-node configuration
- Documentation: guides for each CLI module
