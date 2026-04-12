# FlexEdgeAdmin

Forcepoint NGFW administration platform with web UI, CLI tools, and a web-based Admin Portal — powered by the SMC (Security Management Center) API.

## Features

- **Admin Portal** — web-based management of tenants, users, and API keys with encrypted database storage
- **SMC Explorer** — browse SMC objects, policies, and services in a dark-themed Bootstrap 5 UI
- **Migration Manager** — 7-step guided workflow to import FortiGate configs into Forcepoint SMC
- **CLI Tools** — command-line firewall management, object queries, and connection testing
- **Encrypted at rest** — API keys stored with Fernet encryption (AES-128-CBC + HMAC-SHA256)
- **Multi-tenant, multi-user** — Microsoft Entra ID (Azure AD) authentication with per-user SMC profiles
- **Docker-ready** — single image with nginx reverse proxy and Let's Encrypt TLS

## Quick Start

### Docker (recommended)

```bash
git clone <repo-url> && cd FlexEdgeAdmin

# 1. Set up Azure AD automatically (requires Azure CLI)
./scripts/azure-setup.sh

# 2. Start
make dev

# 3. Open http://localhost:5000
#    → Login with Azure AD → Setup wizard creates your admin account
#    → Admin Portal: add tenants, create API keys, invite users
```

Or use the automated VPS deployment (offers to run Azure setup):

```bash
./deploy.sh              # Installs Docker, runs Azure setup, starts services
./deploy.sh --no-tls     # Development mode (no nginx/TLS)
```

### CLI only (no Docker)

```bash
cd cli
./smc.sh setup
SMC_API_KEY=your-key ./smc.sh --tenant prod connect
./smc.sh --tenant prod firewall list
```

## How It Works

1. **First run** — the app creates a SQLite database and a binary encryption key file
2. **Setup wizard** (`/setup`) — the first Azure AD user to log in becomes the administrator
3. **Admin Portal** (`/admin/`) — admins add SMC tenants (server connections), create encrypted API keys, and assign users
4. **User login** — users authenticate via Azure AD, select their assigned SMC tenant and domain, then browse/manage the firewall
5. **Backup** — download a ZIP of the database + encryption key from the Admin Portal

## Documentation

- [Deployment Guide](docs/deployment-guide.md) — full VPS setup with TLS, Azure AD, troubleshooting
- [CLI: connect](docs/cli/connect.md) | [inquiry](docs/cli/inquiry.md) | [firewall](docs/cli/firewall.md)
- [Migration Guide](docs/webapp/MIGRATION.md)
- [CLAUDE.md](CLAUDE.md) — full project structure, configuration reference, database schema

## Configuration

Only `.env` is required before first start. Everything else is managed via the Admin Portal.

| What | Where | How |
| ---- | ----- | --- |
| Azure AD credentials | `.env` | Edit before first start |
| SMC tenants | Admin Portal `/admin/tenants` | Create via web UI |
| API keys | Admin Portal `/admin/api-keys` | Create via web UI (encrypted) |
| Users | Admin Portal `/admin/users` | Create via web UI |
| Encryption key | `config/encryption.key` | Auto-generated on first run |
| Database | `config/flexedge.db` | Auto-created on first run |

For migration from older JSON-based config: use Admin Portal → "Import from JSON".

## Publishing a Release

The development repo may contain client-specific data. Use the release packer to build a clean public version:

```bash
./scripts/pack-release.sh                       # Build, commit, push (default)
./scripts/pack-release.sh --no-push             # Build + commit only
./scripts/pack-release.sh --message "v2.1.0"    # Custom commit message
```

The script copies product code to `./production/`, strips all client-specific data, runs an automated leak scan, and pushes to the production repo's remote. See [CLAUDE.md](CLAUDE.md#publishing--release) for details.

## License

Proprietary — Be TakeOff Sagl
