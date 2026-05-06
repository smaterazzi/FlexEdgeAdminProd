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
    """Return resolved profile dicts from the database.

    Phase B.2c: reads from `user.domain_accesses` (UserDomainAccess) —
    the canonical scope-grant table. Each row resolves to one profile in
    the operator's `/select-profile` list. Server fields are pulled from
    `domain.api_key` (Phase A absorbed those onto api_keys); SMC admin
    domain name from `domain.smc_domain_name`.

    The returned `tenant` key holds `domain.slug` (Phase A preserved each
    legacy Tenant.slug onto its derived Domain), so `cli/connect.py
    --tenant prod` keeps resolving the same context as before.
    """
    user = _get_user_from_db(email)
    if not user:
        return []

    profiles = []
    for access in user.domain_accesses:
        d = access.domain
        if d is None or not d.is_active:
            continue
        k = d.api_key
        if k is None or not k.is_active:
            continue
        profiles.append({
            "name": d.display_name,
            "smc_url": k.smc_url,
            "api_key": k.decrypted_key,
            "verify_ssl": k.verify_ssl,
            "timeout": k.timeout,
            "domain": d.smc_domain_name,
            "tenant": d.slug,
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
    """Return True if the user has admin-level access in the active Domain.

    Phase B (Change Management, refined 2026-05-01) widened the role
    model. Admin-level resolves True if ANY of:

      1. Legacy `User.role='admin'` — kept for backward compat (the
         setup wizard still writes this; the Phase A migration also
         promotes the lowest-id legacy admin to is_super_admin=True).
      2. `User.is_super_admin=True` — Super Admin, sees every Domain.
      3. `UserDomainAccess.role` IN ('global_admin', 'admin') for the
         active Domain — Per-Domain Global Admin or Domain Admin.

    Existing `@admin_required` decorators (admin.py / dhcp_manager.py /
    tls_manager.py / engines_manager.py) call this and remain correct:
    today's admins (Super Admin + pre-existing Global Admins) all
    satisfy at least one branch on every Domain they're assigned to.

    For finer-grained checks (Super vs Global vs Domain vs Operator),
    use `webapp.auth_roles.is_super_admin()` / `is_global_admin()` /
    `is_domain_admin()` / `is_domain_operator()` — they expose the full
    role hierarchy and respect `g.domain`.
    """
    role_str = get_user_role(email)
    if role_str == "admin":
        return True

    if not _db_available():
        return False
    user = _get_user_from_db(email)
    if user is None:
        return False
    if getattr(user, "is_super_admin", False):
        return True

    # Per-Domain admin (Global Admin or Domain Admin) in the active Domain.
    try:
        from flask import g
        from webapp.models import UserDomainAccess
        domain = getattr(g, "domain", None)
        if domain is None:
            return False
        access = UserDomainAccess.query.filter_by(
            user_id=user.id, domain_id=domain.id,
        ).first()
        return bool(access and access.role in ("global_admin", "admin"))
    except Exception:
        return False


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
