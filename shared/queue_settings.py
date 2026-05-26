"""Per-domain, per-user "bypass queue" settings.

Spec: docs/ChangeManagementProcess.md (bypass queue section, 2026-05-01).

Two row shapes in `feature_bypass_settings`:

  * **Domain capability** (`user_id IS NULL`) — permission gate:
    `True` allows Domain Admins of the domain to grant per-user bypass
    for the feature. Does NOT change operator behavior on its own.

  * **Per-user override** (`user_id IS NOT NULL`) — actual behavior:
    when `enabled=True` the user's actions on that feature in that
    domain bypass the queue (auto-push regardless of role tier; queue
    row is deleted on success).

Lookup hierarchy (most specific wins):
  1. Per-user override — if a row exists, use it.
  2. Otherwise → False (queue is the default).

The domain-capability row is NOT consulted by the lookup; it only
gates UI editing rights for Domain Admins. Super and Global Admins can
edit per-user bypass without the capability flag.

Public API
----------

  should_bypass_queue(feature, *, domain=None, user_email=None) -> bool
    The operative check used in queue helpers. Resolves `domain` from
    `g.domain` and `user_email` from the Flask session when omitted.

  is_capability_enabled(domain, feature) -> bool
    True iff the domain-capability row says ON.

  can_edit_capability(domain, feature, *, user_email=None) -> bool
    True iff the named user (or the current session user) is a Domain
    Admin in `domain` (or higher).

  can_edit_user_bypass(domain, feature, *, user_email=None) -> bool
    True iff the user can grant/revoke per-user bypass for `domain`
    on `feature`. Super/Global Admins always can; Domain Admins can
    only when `is_capability_enabled(domain, feature)` is True.

  set_capability(domain, feature, enabled, by_email)
  set_user_bypass(domain, target_user, feature, enabled, by_email)
    Mutators. Audit-emit `audit("admin", "queue_bypass.set", ...)`.

Bypass feature registry
-----------------------

The set of features that participate in the bypass system. Used by the
admin UI to render the matrix. Independent of `feature_source` /
`platform_log` feature names — bypass naming is finer-grained because
operators may want to bypass routine work (`dhcp_reservation`) without
bypassing rare operations (`dhcp_credentials`).
"""

import logging
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)


# ── Bypass feature registry ───────────────────────────────────────────────

# (key, label) pairs. The label shows up in the admin UI matrix.
_BYPASS_FEATURES: list[tuple[str, str]] = [
    ("dhcp_reservation",  "DHCP — reservation CRUD (create / edit / delete)"),
    ("dhcp_credentials",  "DHCP — credentials SSH rule install / remove + policy upload"),
    ("tls_deploy",        "TLS — certificate deployment pipeline"),
    ("migration_dhcp",    "Migration — DHCP reservation import"),
    ("migration_object",  "Migration — FortiGate object import (hosts / networks / services / groups)"),
    ("migration_rule",    "Migration — FortiGate firewall rule + section import"),
    ("migration_nat",     "Migration — FortiGate NAT rule import"),
    ("migration_vpn",     "Migration — FortiGate VPN topology (profiles / gateways / sites / PolicyVPN)"),
    # Roadmap item 5 / Phase LE.2 (2026-05-11): Let's Encrypt cert ops
    # (request / renew / revoke). One feature key for all three op types —
    # bypass behaviour is identical and operators reason about "cert ops"
    # as a single capability.
    ("letsencrypt",       "Let's Encrypt — cert request / renew / revoke"),
]


def list_bypass_features() -> list[tuple[str, str]]:
    """Return [(key, label), ...] for the admin UI matrix."""
    return list(_BYPASS_FEATURES)


def is_known_bypass_feature(name: str) -> bool:
    return any(k == name for k, _ in _BYPASS_FEATURES)


# ── Resolution helpers ────────────────────────────────────────────────────

def _resolve_domain(domain):
    if domain is not None:
        return domain
    try:
        from flask import g, has_request_context
        if has_request_context():
            return getattr(g, "domain", None)
    except Exception:
        pass
    return None


def _resolve_user_email(email: Optional[str]) -> str:
    if email:
        return email.strip().lower()
    try:
        from flask import session, has_request_context
        if has_request_context():
            info = session.get("user") or {}
            return (info.get("email") or "").strip().lower()
    except Exception:
        pass
    return ""


def _user_by_email(email: str):
    if not email:
        return None
    try:
        from webapp.models import User
        return User.query.filter_by(email=email).first()
    except Exception:
        return None


# ── Lookup ────────────────────────────────────────────────────────────────

def should_bypass_queue(feature: str, *, domain=None,
                        user_email: Optional[str] = None) -> bool:
    """Return True iff this user's actions on `feature` in `domain` bypass.

    Resolution: only the per-user override row is consulted. When
    absent, returns False (queue is the default).

    Best-effort: any DB error returns False so operators never get
    silently elevated by a hiccup. Out-of-band callers (no Flask
    context, no domain, no user) also return False.
    """
    domain = _resolve_domain(domain)
    if domain is None:
        return False
    email = _resolve_user_email(user_email)
    if not email:
        return False
    user = _user_by_email(email)
    if user is None:
        return False
    try:
        from webapp.models import FeatureBypassSetting
        row = (FeatureBypassSetting.query
               .filter_by(domain_id=domain.id, user_id=user.id,
                          feature=feature)
               .first())
        return bool(row and row.enabled)
    except Exception as exc:
        log.debug("should_bypass_queue: lookup failed (%s): %s", feature, exc)
        return False


def is_capability_enabled(domain, feature: str) -> bool:
    """True iff the domain-capability row for `feature` says ON.

    Domain capability is the permission gate, not a behavior toggle.
    Used by `can_edit_user_bypass` to decide whether a Domain Admin
    can grant per-user bypass.
    """
    domain = _resolve_domain(domain)
    if domain is None:
        return False
    try:
        from webapp.models import FeatureBypassSetting
        row = (FeatureBypassSetting.query
               .filter_by(domain_id=domain.id, user_id=None,
                          feature=feature)
               .first())
        return bool(row and row.enabled)
    except Exception:
        return False


# ── Authority checks ──────────────────────────────────────────────────────

def can_edit_capability(domain, feature: str, *,
                        user_email: Optional[str] = None) -> bool:
    """True iff the user can flip the domain-capability flag for feature.

    Allowed: Domain Admin in `domain`, Global Admin, Super Admin.
    """
    domain = _resolve_domain(domain)
    if domain is None:
        return False
    try:
        from webapp.auth_roles import (
            is_super_admin, is_global_admin, is_domain_admin,
        )
        # is_domain_admin returns True for Super + Global + Domain in
        # the active domain. If `domain != g.domain` we fall back to a
        # cross-domain check: Domain Admin only acts on their own
        # Domain, so we require the requested `domain` to match the
        # active one.
        from flask import g, has_request_context
        active_domain = (getattr(g, "domain", None)
                         if has_request_context() else None)
        if is_super_admin() or is_global_admin():
            return True
        if is_domain_admin() and active_domain is not None \
                and active_domain.id == domain.id:
            return True
        return False
    except Exception:
        return False


def can_edit_user_bypass(domain, feature: str, *,
                         user_email: Optional[str] = None) -> bool:
    """True iff the user can grant/revoke per-user bypass for `feature`.

    Super and Global Admins can always edit.
    Domain Admins can only edit when domain capability is ON.
    """
    domain = _resolve_domain(domain)
    if domain is None:
        return False
    try:
        from webapp.auth_roles import (
            is_super_admin, is_global_admin, is_domain_admin,
        )
        if is_super_admin() or is_global_admin():
            return True
        if is_domain_admin():
            return is_capability_enabled(domain, feature)
        return False
    except Exception:
        return False


# ── Mutators ──────────────────────────────────────────────────────────────

def _audit_change(action: str, target: str, detail: str,
                  by_email: str = "") -> None:
    """Emit `audit('admin', 'queue_bypass.<action>', ...)` if logging is up."""
    try:
        from shared.logging import audit
        audit(
            feature="admin",
            action=f"queue_bypass.{action}",
            target=target,
            detail=detail,
            user_email=by_email or None,
        )
    except Exception as exc:
        log.warning("queue_bypass: audit emit failed (%s): %s", action, exc)


def set_capability(domain, feature: str, enabled: bool,
                   by_email: str = "") -> None:
    """Upsert the domain-capability row for `feature`."""
    if domain is None:
        raise ValueError("set_capability: domain required")
    if not is_known_bypass_feature(feature):
        raise ValueError(f"Unknown bypass feature: {feature!r}")

    from shared.db import db
    from webapp.models import FeatureBypassSetting
    row = (FeatureBypassSetting.query
           .filter_by(domain_id=domain.id, user_id=None, feature=feature)
           .first())
    by_id = _user_id_for_email(by_email)
    if row is None:
        row = FeatureBypassSetting(
            domain_id=domain.id, user_id=None,
            feature=feature, enabled=bool(enabled),
            updated_by_id=by_id,
        )
        db.session.add(row)
    else:
        row.enabled = bool(enabled)
        row.updated_by_id = by_id
        row.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    _audit_change(
        action="capability",
        target=f"{getattr(domain, 'slug', domain.id)}/{feature}",
        detail=f"capability_enabled={enabled} by={by_email or '?'}",
        by_email=by_email,
    )


def set_user_bypass(domain, target_user, feature: str, enabled: bool,
                    by_email: str = "") -> None:
    """Upsert the per-user bypass row for `feature`.

    `target_user` is the User instance whose bypass is being toggled
    (NOT the editor — that's `by_email`).
    """
    if domain is None or target_user is None:
        raise ValueError("set_user_bypass: domain and target_user required")
    if not is_known_bypass_feature(feature):
        raise ValueError(f"Unknown bypass feature: {feature!r}")

    from shared.db import db
    from webapp.models import FeatureBypassSetting
    row = (FeatureBypassSetting.query
           .filter_by(domain_id=domain.id, user_id=target_user.id,
                      feature=feature)
           .first())
    by_id = _user_id_for_email(by_email)
    if row is None:
        row = FeatureBypassSetting(
            domain_id=domain.id, user_id=target_user.id,
            feature=feature, enabled=bool(enabled),
            updated_by_id=by_id,
        )
        db.session.add(row)
    else:
        row.enabled = bool(enabled)
        row.updated_by_id = by_id
        row.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    _audit_change(
        action="user",
        target=(f"{getattr(domain, 'slug', domain.id)}/{feature}/"
                f"{target_user.email}"),
        detail=f"enabled={enabled} by={by_email or '?'}",
        by_email=by_email,
    )


def _user_id_for_email(email: str) -> Optional[int]:
    if not email:
        return None
    user = _user_by_email(email)
    return user.id if user else None


# ── UI listing helpers ────────────────────────────────────────────────────

def list_user_bypasses(domain, target_user) -> dict[str, bool]:
    """Return `{feature: enabled}` for all per-user rows of `target_user`
    in `domain`. Missing features default to False.
    """
    out = {k: False for k, _ in _BYPASS_FEATURES}
    if domain is None or target_user is None:
        return out
    try:
        from webapp.models import FeatureBypassSetting
        rows = (FeatureBypassSetting.query
                .filter_by(domain_id=domain.id, user_id=target_user.id)
                .all())
        for r in rows:
            out[r.feature] = bool(r.enabled)
    except Exception:
        pass
    return out


def list_domain_capabilities(domain) -> dict[str, bool]:
    """Return `{feature: enabled}` for all domain-capability rows of `domain`.
    """
    out = {k: False for k, _ in _BYPASS_FEATURES}
    if domain is None:
        return out
    try:
        from webapp.models import FeatureBypassSetting
        rows = (FeatureBypassSetting.query
                .filter_by(domain_id=domain.id, user_id=None)
                .all())
        for r in rows:
            out[r.feature] = bool(r.enabled)
    except Exception:
        pass
    return out
