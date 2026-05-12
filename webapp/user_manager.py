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

    Super Admin special case: per the role spec, Super Admin sees every
    Domain "including ones added later" — so they're not gated on
    explicit UserDomainAccess rows. Every active Domain with an active
    ApiKey appears in their profile list. This also self-heals the
    bootstrap-admin scenario where the Multi-Domain Revamp backfill
    didn't produce UDA rows for the original sole admin.

    The returned `tenant` key holds `domain.slug` (Phase A preserved each
    legacy Tenant.slug onto its derived Domain), so `cli/connect.py
    --tenant prod` keeps resolving the same context as before.
    """
    user = _get_user_from_db(email)
    if not user:
        return []

    def _to_profile(d):
        k = d.api_key
        if k is None or not k.is_active:
            return None
        # H2 (audit fix-up, 2026-05-09): plaintext API key is intentionally
        # NOT included here. ``tenant`` (= Domain.slug) is the resolution
        # key — `app.py:_resolve_active_domain` populates `g.api_key_obj`
        # per-request, and `active_api_key_plaintext()` decrypts on demand.
        # Keeping the cookie cleartext-free reduces XSS / cookie-shadowing
        # blast radius.
        return {
            "name": d.display_name,
            "smc_url": k.smc_url,
            "verify_ssl": k.verify_ssl,
            "timeout": k.timeout,
            "domain": d.smc_domain_name,
            "tenant": d.slug,
        }

    if getattr(user, "is_super_admin", False):
        from webapp.models import Domain
        profiles = []
        for d in Domain.query.filter_by(is_active=True).all():
            p = _to_profile(d)
            if p is not None:
                profiles.append(p)
        return profiles

    profiles = []
    for access in user.domain_accesses:
        d = access.domain
        if d is None or not d.is_active:
            continue
        p = _to_profile(d)
        if p is not None:
            profiles.append(p)
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

    H2 (audit fix-up, 2026-05-09): no longer requires the plaintext API key
    to be in the session. Resolves via the profile's ``tenant`` slug
    (= Domain.slug) → Domain → ApiKey.is_active. Same revocation-detection
    behaviour, no plaintext exposure.

    Designed for ``@profile_required`` to call once per request; one
    indexed DB lookup per call.

    Backward-compat fallback: if the slug isn't resolvable but the profile
    has an ``api_key`` field (JSON-fallback / older sessions), use the
    legacy hash-the-plaintext check so existing sessions don't get evicted
    on first load after the upgrade.

    Behavior when the DB layer is unavailable (CLI / JSON-fallback mode):
    returns ``True`` so legacy deployments don't lock themselves out.
    """
    if not profile:
        return False
    if not _db_available():
        return True   # Fall through for JSON-fallback / non-Flask callers.

    slug = (profile.get("tenant") or "").strip()
    if slug:
        from webapp.models import Domain
        d = Domain.query.filter_by(slug=slug, is_active=True).first()
        if d is not None and d.api_key is not None and d.api_key.is_active:
            return True
        # Slug present but Domain inactive or its key revoked → invalid.
        # Only fall through to the legacy hash check if the slug couldn't
        # be resolved at all (truly old/JSON-fallback profile shape).
        if d is not None or Domain.query.filter_by(slug=slug).first() is not None:
            return False

    # Legacy fallback: hash the cached plaintext (older sessions).
    api_key = (profile.get("api_key") or "").strip()
    if not api_key:
        return False

    from webapp.models import ApiKey
    from shared.encryption import hash_value
    return ApiKey.query.filter_by(
        key_hash=hash_value(api_key), is_active=True,
    ).first() is not None


# ── Plaintext API key resolver (H2 — keeps key out of the session cookie)

def active_api_key_plaintext(profile: dict | None = None) -> str:
    """Return the plaintext API key for the request's active Domain.

    Resolution order (H2 audit fix-up, 2026-05-09):
      1. ``g.api_key_obj.decrypted_key`` — populated by ``app.py``'s
         ``_resolve_active_domain`` before-request hook from the session's
         ``active_profile["tenant"]`` slug. This is the canonical path —
         no plaintext in the session cookie, one Fernet decrypt per call.
      2. ``profile["api_key"]`` — legacy fallback for JSON-fallback /
         older sessions / out-of-Flask callers. Returns whatever the
         profile carries.
      3. Empty string if nothing resolves. Caller decides whether to raise.

    Pass ``profile`` explicitly for callers that already have the dict
    handy (cheaper than a session lookup). Otherwise falls through to
    ``session.get('active_profile')``.
    """
    try:
        from flask import g
        api_key_obj = getattr(g, "api_key_obj", None)
        if api_key_obj is not None and getattr(api_key_obj, "is_active", False):
            return api_key_obj.decrypted_key or ""
    except Exception:
        pass
    if profile is None:
        try:
            from flask import session
            profile = session.get("active_profile") or {}
        except Exception:
            profile = {}
    return (profile.get("api_key") or "").strip()
