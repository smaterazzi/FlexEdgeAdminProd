# FlexEdgeAdmin

Forcepoint NGFW administration platform — web UI + CLI tools, managed via the SMC (Security Management Center) API. All configuration is managed through an encrypted database with a web-based Admin Portal.

## Project Structure

```
FlexEdgeAdmin/
├── cli/                        # Command-line tools
│   ├── connect.py              # SMC session management (--tenant support)
│   ├── firewall.py             # Firewall management CLI
│   ├── inquiry.py              # Object query/inspection CLI
│   └── smc.sh                  # CLI launcher script
├── webapp/                     # Flask web application
│   ├── app.py                  # Routes: Explorer + Migration + Admin
│   ├── admin.py                # Admin Portal Blueprint (CRUD routes)
│   ├── setup.py                # One-time setup wizard
│   ├── models.py               # SQLAlchemy models (Tenant, User, ApiKey, Access)
│   ├── db_init.py              # Database initialization on first run
│   ├── smc_client.py           # Read-only SMC API wrapper
│   ├── auth.py                 # Entra ID OIDC authentication
│   ├── user_manager.py         # User/profile manager (DB-first, JSON fallback)
│   ├── fgt_parser.py           # FortiGate config parser
│   ├── dedup_engine.py         # Object deduplication engine
│   ├── rule_converter.py       # FortiGate → Forcepoint rule converter
│   ├── smc_writer.py           # SMC object/rule creation
│   ├── project_manager.py      # Migration project CRUD
│   └── templates/              # Jinja2 templates (dark Bootstrap 5)
│       ├── admin/              # Admin portal templates
│       ├── auth/               # Login, profile/domain selection
│       └── migration/          # Migration workflow templates
├── shared/                     # Shared Python modules
│   ├── encryption.py           # Fernet encryption (key mgmt, encrypt/decrypt)
│   ├── db.py                   # Flask-SQLAlchemy instance
│   └── tenant_config.py        # Tenant config loader (DB-first, JSON fallback)
├── config/                     # Runtime config (gitignored except .example files)
│   ├── .env.example            # Environment variable template
│   ├── tenants.json.example    # Legacy tenant config template
│   ├── users.json.example      # Legacy user config template
│   ├── config.ini.example      # Legacy CLI config template
│   ├── flexedge.db             # SQLite database (auto-created, gitignored)
│   └── encryption.key          # Fernet key file (auto-created, gitignored)
├── docker/                     # Docker infrastructure
│   ├── Dockerfile              # Unified image (web + CLI + scripts)
│   ├── docker-compose.yml      # Development compose
│   ├── docker-compose.prod.yml # Production overlay (nginx + TLS)
│   └── nginx.conf              # Reverse proxy config
├── docs/                       # Documentation
│   ├── deployment-guide.md     # Full operator deployment guide
│   ├── cli/                    # CLI tool guides (connect, inquiry, firewall)
│   └── webapp/                 # Webapp docs (migration, deployment)
├── deploy.sh                   # One-command server setup script
├── Makefile                    # Convenience targets
├── requirements.txt            # Python dependencies
├── .gitignore
├── CLAUDE.md                   # This file
├── CHANGELOG.md
└── README.md
```

## Quick Start

### Docker (recommended)

```bash
# 1. Set up Azure AD and generate .env (automated — requires Azure CLI)

# 2. Start
make dev                 # Development mode (port 5000)
# or
./deploy.sh              # Full automated setup on VPS (offers to run azure-setup.sh)

# 3. Open browser → login via Azure AD → setup wizard creates first admin
# 4. Admin Portal (/admin/) → add tenants, API keys, users
```

If you prefer manual setup: `cp config/.env.example .env` and fill in Azure AD credentials by hand.

### CLI Tools (standalone, no Docker required)

```bash
cd cli
./smc.sh setup                                       # Install deps
SMC_API_KEY=xxx ./smc.sh --tenant prod connect       # Test connection
./smc.sh --tenant prod firewall list                 # List firewalls
./smc.sh help firewall                               # Module help
```

CLI tools read tenants from the database when inside Docker, or from `config/tenants.json` when running standalone.

## Configuration

### First-Run Setup

On first start, the application:
1. Creates the SQLite database (`config/flexedge.db`)
2. Generates the encryption key (`config/encryption.key`)
3. Shows a setup wizard at `/setup` (requires Azure AD login)
4. The first authenticated user becomes the admin

After setup, all configuration is managed through the **Admin Portal** (`/admin/`).

### Admin Portal (`/admin/`)

Only accessible to admin-role users. Provides:

- **Tenants** — CRUD for SMC server connections (slug, URL, SSL, timeout, domain)
- **API Keys** — create, revoke; encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256); plaintext shown only once at creation
- **Users** — create, edit; assign Azure AD users to tenants with specific API keys
- **Backup** — download ZIP of database + encryption key
- **JSON Migration** — one-click import from legacy `tenants.json` + `users.json`

### Encryption

- **Algorithm**: Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256)
- **Key file**: `config/encryption.key` — binary format with `FXEK` magic header
- **Generated**: automatically on first run; never regenerated
- **Critical**: without this file, API keys in the database are irrecoverable
- **Backup strategy**: `config/flexedge.db` + `config/encryption.key` = full restore

### Environment Variables (.env)

Copy `config/.env.example` to `.env` at project root. Required variables:

| Variable | Purpose |
| -------- | ------- |
| `FLASK_SECRET_KEY` | Session signing key (auto-generated by deploy.sh) |
| `AZURE_TENANT_ID` | Microsoft Entra ID tenant UUID |
| `AZURE_CLIENT_ID` | App Registration client ID |
| `AZURE_CLIENT_SECRET` | App Registration client secret |

Optional:

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `DATABASE_URL` | `sqlite:////config/flexedge.db` | Database path |
| `ENCRYPTION_KEY_FILE` | `/config/encryption.key` | Encryption key path |
| `APP_TITLE` | `FlexEdgeAdmin` | Customizable UI branding |
| `PORT` | `5000` | Listening port |
| `DOMAIN` | — | Domain for TLS certificate |
| `CERTBOT_EMAIL` | — | Email for Let's Encrypt |

### Azure AD App Registration

**Automated (recommended):**

```bash
```

This creates the App Registration, enables ID tokens, creates a client secret, adds permissions (openid, email, profile), grants admin consent, and writes `.env` — all in one command. Requires Azure CLI (`az`) and Application Administrator or Global Admin permissions.

**Manual (if automated setup is not possible):**

1. Azure Portal → Entra ID → App Registrations → New Registration
2. Name: "FlexEdgeAdmin"
3. Redirect URI: `https://your-domain/auth/callback` (or `http://localhost:5000/auth/callback` for dev)
4. Authentication → enable **ID tokens**
5. Certificates & Secrets → create a Client Secret (note: shown only once)
6. API Permissions → add Microsoft Graph delegated: `openid`, `email`, `profile` → Grant admin consent
7. Copy Tenant ID, Client ID, Client Secret to `.env`

### Legacy JSON Config (optional)

For migration from older versions, `config/tenants.json` and `config/users.json` can be imported via Admin Portal. CLI tools also support JSON fallback when running outside Docker. Example formats are in `config/*.example`.

## Web Application

### SMC Explorer

Browse all SMC objects in a dark-themed Bootstrap 5 UI:
- Zones, hosts, networks, address ranges, FQDNs, groups
- TCP/UDP/IP/ICMP services, service groups
- Firewall policies with rule viewer (color-coded actions, sections)
- Sandbox validation checks

### Migration Manager

7-step guided workflow to import FortiGate `.conf` files into Forcepoint SMC:
1. Upload FortiGate config
2. Review parsed objects
3. Configure target SMC
4. Deduplication analysis
5. Rule conversion
6. Human validation (select which rules to import)
7. Import execution with detailed log

### Admin Portal

See [Configuration > Admin Portal](#admin-portal-admin) above.

## CLI Tools

| Command | Description |
| ------- | ----------- |
| `connect` | Test SMC connection |
| `inquiry --list-types` | List available object types |
| `inquiry --type host --name web` | Query objects by type/name |
| `firewall list` | List all firewalls |
| `firewall show --name FW01` | Show firewall details |
| `firewall interfaces --name FW01` | List interfaces |
| `firewall add-interface` | Add Layer 3 interface |
| `firewall add-vlan` | Add VLAN sub-interface |
| `firewall refresh --name FW01` | Quick policy refresh |
| `firewall upload --name FW01` | Full policy upload |
| `firewall pending --name FW01` | View/manage pending changes |

## Docker

Single image containing web app + CLI + migration scripts.

```bash
# Development (port 5000, no TLS)
make dev

# Production (nginx + Let's Encrypt TLS)
make prod

# View logs
make logs

# Stop
make stop

# CLI inside container
docker compose -f docker/docker-compose.yml exec flexedge-web \
  python /app/cli/connect.py --tenant prod --api-key YOUR_KEY

# Update (pull latest + rebuild)
make update
```

## Database Schema

```
tenants              SMC server connections
  id, slug, name, smc_url, verify_ssl, timeout, default_domain, api_version, is_active

users                Authenticated users (from Azure AD)
  id, email, display_name, role (admin|viewer), is_active

api_keys             Encrypted SMC API keys
  id, name, encrypted_key, key_hash, tenant_id, created_by_id, is_active, last_used_at

user_tenant_access   Junction: user → tenant → api_key
  id, user_id, tenant_id, api_key_id, is_default
```

## Publishing & Release

The private repo (`main` branch) contains client-specific migration scripts and data. To publish a clean, generic version:

```bash
# Build, commit, and push to the public repo (default)

# Build only, don't push

# Custom commit message
```

The script:
1. Copies all product code to `./production/` (gitignored on main)
2. Sanitizes client-specific references (firewall names, IPs, URLs)
4. Runs an automated scan for leaked secrets, server URLs, and client names
5. Aborts if any sensitive data is detected
6. Commits and pushes to the production repo's remote

**First-time setup** (once):
```bash
cd production
git remote add origin https://github.com/smaterazzi/production.git
cd ..
```

The `production/.git` directory is preserved across rebuilds — remote config and history persist.

## Key Constraints

- **Never push policy to engine without review** — all policy changes must be reviewed in SMC Management Client first
- **Encryption key is critical** — without `config/encryption.key`, API keys are irrecoverable. Back it up.
- Secrets are never in git — `.env`, `*.db`, `encryption.key` are gitignored
- Config is volume-mounted into Docker, never baked into the image
