# FlexEdgeAdmin

Forcepoint NGFW administration platform with web UI, CLI tools, and a web-based Admin Portal — powered by the SMC (Security Management Center) API.

## Features

- **Admin Portal** — web-based management of tenants, users, and API keys with encrypted database storage
- **SMC Explorer** — browse SMC objects, policies, and services in a dark-themed Bootstrap 5 UI
- **Migration Manager** — 7-step guided workflow to import FortiGate configs into Forcepoint SMC
- **TLS Manager** — automated certbot → Forcepoint TLS credential lifecycle, engine assignment, inspection rules, and auto-renewal on cert renewal (setup in [deployment guide](docs/deployment-guide.md#tls-manager--certbot-integration))
- **DHCP Manager** — manages MAC→IP reservations on engines with the internal DHCP server enabled. Reservations live as SMC Host objects (MAC stored inline as `[flexedge:mac=...]` in the comment). Auto-managed SSH-allow rule + per-node password rotation via SMC API; cluster-wide lease viewer; engine-side reservation push pending Phase 4 (see [DHCP-ReservationStrategy.md](docs/DHCP-ReservationStrategy.md))
- **CLI Tools** — command-line firewall management, object queries, and connection testing
- **Encrypted at rest** — API keys stored with Fernet encryption (AES-128-CBC + HMAC-SHA256)
- **Multi-tenant, multi-user** — Microsoft Entra ID (Azure AD) authentication with per-user SMC profiles
- **Docker-ready** — single image with nginx reverse proxy and Let's Encrypt TLS

## Deployment Options

Pick the one that fits your infrastructure. Full instructions in [docs/deployment-guide.md](docs/deployment-guide.md).

| Option | Best for | Guide |
| ------ | -------- | ----- |
| **Standalone** (no Docker) | Native install on a dedicated VM with system nginx | [Option 1](docs/deployment-guide.md#option-1--standalone-install-no-docker) |
| **Docker + nginx** | Single-purpose VPS, full stack in compose | [Option 2](docs/deployment-guide.md#option-2--standalone-docker-with-nginx) |
| **Coolify / Traefik** | Multi-website host, PaaS-style management | [Option 3](docs/deployment-guide.md#option-3--docker-behind-coolify--traefik) |

## Quick Start

```bash
git clone https://github.com/smaterazzi/FlexEdgeAdminProd.git FlexEdgeAdmin && cd FlexEdgeAdmin

# Option 1: Standalone (native install + nginx + systemd)
sudo ./scripts/install-standalone.sh --domain admin.yourcompany.com

# Option 2: Docker with bundled nginx + certbot
./deploy.sh                  # Full production install (Docker, TLS, Azure setup)
./deploy.sh --dev            # Dev mode: port 8088, foreground, live logs
make dev                     # Same as --dev, shorter

# Option 3: Coolify — use docker/docker-compose.coolify.yml via the Coolify UI
```

First visit:
1. Log in with Azure AD → Setup wizard creates your admin account
2. Admin Portal (`/admin/`) → add tenants, create API keys, invite users

**Check the running version:** sidebar footer shows `v{version} ({commit})`, or `curl https://admin.example.com/version` returns JSON. See [CLAUDE.md § Build Version](CLAUDE.md#build-version) for details.

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

The script copies product code to `./FlexEdgeAdminProd/`, strips all client-specific data, runs an automated leak scan, and pushes to [github.com/smaterazzi/FlexEdgeAdminProd](https://github.com/smaterazzi/FlexEdgeAdminProd). Never push `main` to a public remote — git history contains historical secrets. See [CLAUDE.md](CLAUDE.md#publishing--release) for full details.

## License

Proprietary — Be TakeOff Sagl
