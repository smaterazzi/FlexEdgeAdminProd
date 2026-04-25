"""
FlexEdgeAdmin — User profile manager.

Primary data source: SQLite database (via SQLAlchemy models).
Fallback: users.json + tenants.json (for migration period or CLI without DB).

The public interface is unchanged:
  get_user_profiles(email) -> list[dict]
  get_user_role(email) -> str
  is_admin(email) -> bool
"""

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

USERS_FILE = os.environ.get(
    "USERS_CONFIG",
    str(Path(__file__).resolve().parent.parent / "config" / "users.json"),
)


# ── DB-backed implementations ───────────────────────────────────────────

def _db_available() -> bool:
    """Check if we're inside a Flask app context with a working DB."""
    try:
        from flask import current_app
        return current_app is not None and "sqlalchemy" in current_app.extensions
    except (RuntimeError, ImportError):
        return False


def _get_user_from_db(email: str):
    """Return the User model instance or None."""
    from webapp.models import User
    return User.query.filter(
        User.email == email.lower().strip(),
        User.is_active.is_(True),
    ).first()


def _get_profiles_from_db(email: str) -> list:
    """Return resolved profile dicts from the database."""
    user = _get_user_from_db(email)
    if not user:
        return []

    profiles = []
    for access in user.tenant_accesses:
        t = access.tenant
        k = access.api_key
        if not t.is_active or not k.is_active:
            continue
        profiles.append({
            "name": t.name,
            "smc_url": t.smc_url,
            "api_key": k.decrypted_key,
            "verify_ssl": t.verify_ssl,
            "timeout": t.timeout,
            "domain": t.default_domain,
            "tenant": t.slug,
        })
    return profiles


def _get_role_from_db(email: str) -> str:
    """Return user role from DB."""
    user = _get_user_from_db(email)
    return user.role if user else "viewer"


# ── JSON fallback implementations ───────────────────────────────────────

def _load_users_json() -> dict:
    """Return the raw users dict from users.json."""
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON in users config: %s", exc)
        return {}


def _find_user_json(email: str) -> dict | None:
    """Case-insensitive lookup in users.json."""
    needle = email.lower().strip()
    for key, value in _load_users_json().items():
        if key.lower().strip() == needle:
            return value
    return None


def _resolve_profile_json(profile: dict) -> dict:
    """Resolve a tenant reference from JSON into a full profile."""
    if "smc_url" in profile:
        return profile

    tenant_id = profile.get("tenant")
    if not tenant_id:
        return profile

    try:
        from shared.tenant_config import get_tenant
        tenant = get_tenant(tenant_id)
        return {
            "name": profile.get("name", tenant.name),
            "smc_url": tenant.smc_url,
            "api_key": profile["api_key"],
            "verify_ssl": tenant.verify_ssl,
            "timeout": tenant.timeout,
            "domain": tenant.domain,
            "tenant": tenant_id,
        }
    except (KeyError, FileNotFoundError) as exc:
        log.error("Failed to resolve tenant '%s': %s", tenant_id, exc)
        return profile


def _get_profiles_from_json(email: str) -> list:
    config = _find_user_json(email)
    if not config:
        return []
    return [_resolve_profile_json(p) for p in config.get("profiles", [])]


def _get_role_from_json(email: str) -> str:
    config = _find_user_json(email)
    return (config or {}).get("role", "viewer")


# ── Public API (DB-first, JSON fallback) ────────────────────────────────

def get_user_profiles(email: str) -> list:
    """Return the list of SMC profiles available to the user.

    Each profile is a dict: {name, smc_url, api_key, verify_ssl, timeout, domain, tenant}.
    Returns [] if the user is not found.
    """
    if _db_available():
        profiles = _get_profiles_from_db(email)
        if profiles:
            return profiles
    return _get_profiles_from_json(email)


def get_user_role(email: str) -> str:
    """Return the user's role ('admin' or 'viewer'). Defaults to 'viewer'."""
    if _db_available():
        user = _get_user_from_db(email)
        if user:
            return user.role
    return _get_role_from_json(email)


def is_admin(email: str) -> bool:
    """Return True if the user has the 'admin' role."""
    return get_user_role(email) == "admin"


def user_exists_in_db(email: str) -> bool:
    """Check if a user exists in the database (active or not)."""
    if not _db_available():
        return False
    from webapp.models import User
    return User.query.filter(User.email == email.lower().strip()).first() is not None


def is_active_profile_valid(profile: dict | None) -> bool:
    """Verify that a session's active_profile still maps to an active ApiKey.

    The session caches a snapshot of the resolved profile, including the
    plaintext API key. If an admin revokes that key (in `/admin/api-keys`)
    the cached profile keeps working until the user re-selects, which leads
    to confusing ``SMCConnectionError: No session found`` failures when the
    SMC SDK rejects the revoked credential mid-session.

    This helper hashes the cached plaintext and confirms a matching
    ``ApiKey`` row with ``is_active=True`` still exists. Designed for
    ``@profile_required`` to call once per request; the hash + DB lookup
    are both indexed and effectively free.

    Behavior when the DB layer is unavailable (CLI / JSON-fallback mode):
    returns ``True`` so legacy deployments don't lock themselves out.
    """
    if not profile:
        return False
    if not _db_available():
        return True   # Fall through for JSON-fallback / non-Flask callers.

    api_key = (profile.get("api_key") or "").strip()
    if not api_key:
        return False

    from webapp.models import ApiKey
    from shared.encryption import hash_value
    return ApiKey.query.filter_by(
        key_hash=hash_value(api_key), is_active=True,
    ).first() is not None
