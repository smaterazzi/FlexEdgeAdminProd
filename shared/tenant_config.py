"""
FlexEdgeAdmin — Shared tenant configuration loader.

Primary source: SQLite database (when running inside Flask app context).
Fallback: tenants.json file (for CLI tools or migration period).

Tenant defines: name, smc_url, verify_ssl, timeout, domain.
API key is NOT stored per-tenant — it comes from the user profile (webapp)
or environment variable / CLI flag (CLI tools).
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TENANTS_PATH = os.environ.get(
    "TENANTS_CONFIG",
    str(Path(__file__).resolve().parent.parent / "config" / "tenants.json"),
)


@dataclass
class TenantConfig:
    name: str
    smc_url: str
    verify_ssl: bool = False
    timeout: int = 120
    domain: str = ""
    api_version: str | None = None

    def to_smc_cfg(self, api_key: str) -> dict:
        """Build the config dict expected by smc_client.smc_session()."""
        cfg = {
            "smc_url": self.smc_url,
            "api_key": api_key,
            "verify_ssl": self.verify_ssl,
            "timeout": self.timeout,
            "retry_on_busy": True,
        }
        if self.domain:
            cfg["domain"] = self.domain
        if self.api_version:
            cfg["api_version"] = self.api_version
        return cfg

    def to_cli_kwargs(self, api_key: str) -> dict:
        """Build keyword arguments for the CLI connect.connect() function."""
        from urllib.parse import urlparse

        parsed = urlparse(self.smc_url)
        return {
            "address": parsed.hostname,
            "port": parsed.port or (8082 if parsed.scheme == "https" else 8080),
            "api_key": api_key,
            "ssl": parsed.scheme == "https",
            "verify_ssl": self.verify_ssl,
            "domain": self.domain or None,
            "api_version": self.api_version,
            "timeout": self.timeout,
        }


# ── DB-backed lookup ────────────────────────────────────────────────────

def _get_tenant_from_db(tenant_slug: str) -> TenantConfig | None:
    """Try loading a tenant from the database. Returns None if unavailable."""
    try:
        from flask import current_app
        if current_app is None or "sqlalchemy" not in current_app.extensions:
            return None
    except (RuntimeError, ImportError):
        return None

    from webapp.models import Tenant
    t = Tenant.query.filter_by(slug=tenant_slug, is_active=True).first()
    if not t:
        return None
    return TenantConfig(
        name=t.name,
        smc_url=t.smc_url,
        verify_ssl=t.verify_ssl,
        timeout=t.timeout,
        domain=t.default_domain,
        api_version=t.api_version,
    )


def _load_tenants_from_db() -> dict[str, TenantConfig]:
    """Load all tenants from DB. Returns empty dict if DB unavailable."""
    try:
        from flask import current_app
        if current_app is None or "sqlalchemy" not in current_app.extensions:
            return {}
    except (RuntimeError, ImportError):
        return {}

    from webapp.models import Tenant
    tenants = {}
    for t in Tenant.query.filter_by(is_active=True).all():
        tenants[t.slug] = TenantConfig(
            name=t.name,
            smc_url=t.smc_url,
            verify_ssl=t.verify_ssl,
            timeout=t.timeout,
            domain=t.default_domain,
            api_version=t.api_version,
        )
    return tenants


# ── JSON fallback ───────────────────────────────────────────────────────

def _load_tenants_from_json(path: str | None = None) -> dict[str, TenantConfig]:
    """Load tenants from tenants.json file."""
    tenants_path = path or DEFAULT_TENANTS_PATH

    if not os.path.isfile(tenants_path):
        return {}

    with open(tenants_path, "r") as f:
        raw = json.load(f)

    tenants = {}
    for tid, data in raw.items():
        if tid.startswith("_"):
            continue
        tenants[tid] = TenantConfig(
            name=data.get("name", tid),
            smc_url=data["smc_url"],
            verify_ssl=data.get("verify_ssl", False),
            timeout=data.get("timeout", 120),
            domain=data.get("domain", ""),
            api_version=data.get("api_version"),
        )
    return tenants


# ── Public API (DB-first, JSON fallback) ────────────────────────────────

def load_tenants(path: str | None = None) -> dict[str, TenantConfig]:
    """Load all tenant definitions. Tries DB first, falls back to JSON.

    Returns {tenant_slug: TenantConfig}.
    """
    db_tenants = _load_tenants_from_db()
    if db_tenants:
        return db_tenants
    json_tenants = _load_tenants_from_json(path)
    if not json_tenants:
        raise FileNotFoundError(
            f"No tenants found in database or JSON file.\n"
            f"Use the admin portal or copy config/tenants.json.example to config/tenants.json."
        )
    return json_tenants


def get_tenant(tenant_id: str, path: str | None = None) -> TenantConfig:
    """Get a single tenant by slug. Tries DB first, falls back to JSON.

    Raises KeyError if not found in either source.
    """
    # Try DB first
    db_tenant = _get_tenant_from_db(tenant_id)
    if db_tenant:
        return db_tenant

    # Fallback to JSON
    json_tenants = _load_tenants_from_json(path)
    if tenant_id in json_tenants:
        return json_tenants[tenant_id]

    available = ", ".join(sorted(json_tenants.keys())) if json_tenants else "(none)"
    raise KeyError(
        f"Tenant '{tenant_id}' not found. Available tenants: {available}"
    )
