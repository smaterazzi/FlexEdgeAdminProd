"""
FlexEdgeAdmin — four-tier role resolver and decorators.

Implements the Q10 role model from `docs/ChangeManagementProcess.md`,
refined 2026-05-01 to make Global Admin per-Domain rather than literally
global:

  * SUPER ADMIN     — `User.is_super_admin = True`
                       Singular bootstrap admin. Sees every Domain (no
                       UserDomainAccess required), and is the only role
                       allowed to perform cross-Domain infrastructure
                       operations (Tenant / API Key / Domain CRUD).
                       Set by the setup wizard on the first user.
  * GLOBAL ADMIN    — `UserDomainAccess.role = 'global_admin'`
                       Per-Domain. Full power within assigned Domains —
                       Confirm/Revoke for `to_be_deleted` queue items,
                       and Domain Admin / Operator role management within
                       that Domain. NOT visible across Domains they're
                       not assigned to.
  * DOMAIN ADMIN    — `UserDomainAccess.role = 'admin'`
                       Per-Domain. Full CRUD on Domain-scoped objects,
                       can invite Operators (Q13). Cannot Confirm
                       deletes — that's Global / Super Admin only.
  * DOMAIN OPERATOR — `UserDomainAccess.role = 'operator'`
                       Per-Domain. CRU only — deletes go through the
                       change-mgmt queue tagged `to_be_deleted`,
                       awaiting a Global / Super Admin confirm/revoke.
  * VIEWER          — no Domain Access record (or User.is_active=False).
                       Read-only. Cannot mutate anything.

Phase A backfill ensured that today's admins keep working: the lowest-id
legacy admin becomes Super Admin (sees everything), and any additional
legacy admins keep `UserDomainAccess.role='global_admin'` for their
assigned Domains. Domain Admin / Operator are introduced incrementally
(via the Phase H invite flow).

Public API
----------

  current_role_for_active_domain() -> Role
      Resolve the highest role the request's user has in the active Domain.

  is_super_admin() -> bool             # only True for Super Admin
  is_global_admin() -> bool            # Super Admin OR Domain Global Admin
  is_domain_admin() -> bool            # ... OR Domain Admin
  is_domain_operator() -> bool         # ... OR Domain Operator
  has_domain_access() -> bool

  @super_admin_required                — only Super Admin
  @global_admin_required               — Super Admin OR Global Admin in active Domain
  @domain_admin_required               — ... OR Domain Admin in active Domain
  @domain_operator_required            — ... OR Domain Operator in active Domain

Decorators redirect unauthenticated users to /login, return 403 for
authenticated users without the required role (with a flash + safe redirect).
"""

import logging
from enum import IntEnum
from functools import wraps
from typing import Optional

from flask import (
    g, session, redirect, url_for, flash, request,
)

log = logging.getLogger(__name__)


class Role(IntEnum):
    """Ordered role tiers — higher value = more permissions.

    The IntEnum ordering lets `current_role >= Role.DOMAIN_ADMIN`-style
    checks express "this role or higher".
    """
    VIEWER = 0
    DOMAIN_OPERATOR = 10
    DOMAIN_ADMIN = 20
    GLOBAL_ADMIN = 30      # per-Domain (UserDomainAccess.role='global_admin')
    SUPER_ADMIN = 40       # cross-Domain bootstrap admin (User.is_super_admin)


# ── Resolution ────────────────────────────────────────────────────────────

def _current_user_row():
    """Return the authenticated User row, or None.

    Cached on `g` per request so multiple decorator/template calls don't
    each round-trip the DB. The cache is keyed by email so a session that
    changes user (logout/login within a request — extremely unlikely)
    still sees the right row.
    """
    info = session.get("user") or {}
    email = (info.get("email") or "").strip().lower()
    if not email:
        return None
    cached_email = getattr(g, "_role_user_email", None)
    if cached_email == email:
        return getattr(g, "_role_user_row", None)
    try:
        from webapp.models import User
        row = User.query.filter_by(email=email, is_active=True).first()
    except Exception:
        row = None
    g._role_user_email = email
    g._role_user_row = row
    return row


def _active_domain_id() -> Optional[int]:
    """Active Domain id from the before_request hook in app.py."""
    domain = getattr(g, "domain", None)
    return getattr(domain, "id", None)


def _domain_access_for_user(user_id: int, domain_id: int):
    """One-row lookup of UserDomainAccess(user_id, domain_id)."""
    try:
        from webapp.models import UserDomainAccess
        return UserDomainAccess.query.filter_by(
            user_id=user_id, domain_id=domain_id,
        ).first()
    except Exception:
        return None


def current_role_for_active_domain() -> Role:
    """Resolve the highest Role the current user has in the active Domain.

    Resolution order:
      1. User.is_super_admin → SUPER_ADMIN regardless of Domain.
      2. UserDomainAccess.role for active Domain → matching tier.
      3. No access record → VIEWER.

    Result cached on `g` per request so a chain of decorators + template
    `is_domain_admin` checks doesn't repeatedly hit the DB.
    """
    cached = getattr(g, "_resolved_role", None)
    if cached is not None:
        return cached

    user = _current_user_row()
    if user is None:
        g._resolved_role = Role.VIEWER
        return Role.VIEWER

    if getattr(user, "is_super_admin", False):
        g._resolved_role = Role.SUPER_ADMIN
        return Role.SUPER_ADMIN

    domain_id = _active_domain_id()
    if domain_id is None:
        # Authenticated but no Domain selected. We cannot evaluate per-Domain
        # roles, so collapse to VIEWER. Routes that need a role still
        # redirect them through profile selection elsewhere.
        g._resolved_role = Role.VIEWER
        return Role.VIEWER

    access = _domain_access_for_user(user.id, domain_id)
    if access is None:
        g._resolved_role = Role.VIEWER
        return Role.VIEWER

    role_str = (access.role or "").lower()
    if role_str == "global_admin":
        g._resolved_role = Role.GLOBAL_ADMIN
    elif role_str == "admin":
        g._resolved_role = Role.DOMAIN_ADMIN
    elif role_str == "operator":
        g._resolved_role = Role.DOMAIN_OPERATOR
    else:
        g._resolved_role = Role.VIEWER
    return g._resolved_role


def is_super_admin() -> bool:
    """True only for Super Admin (the platform bootstrap user)."""
    return current_role_for_active_domain() == Role.SUPER_ADMIN


def is_global_admin() -> bool:
    """True for Domain Global Admin AND for Super Admin."""
    return current_role_for_active_domain() >= Role.GLOBAL_ADMIN


def is_domain_admin() -> bool:
    """True for Domain Admin and every higher tier."""
    return current_role_for_active_domain() >= Role.DOMAIN_ADMIN


def is_domain_operator() -> bool:
    """True for any role that can mutate Domain-scoped data — Operator / Admin / GA / Super."""
    return current_role_for_active_domain() >= Role.DOMAIN_OPERATOR


def has_domain_access() -> bool:
    """User has any role for the active Domain. Alias for `is_domain_operator`."""
    return is_domain_operator()


# ── Decorators ────────────────────────────────────────────────────────────

def _require_login(view, *args, **kwargs):
    """If unauthenticated, redirect to /login. Returns the redirect or
    None when authenticated.
    """
    if "user" not in session:
        return redirect(url_for("auth.login", next=request.url))
    return None


def _forbid(message: str = "You don't have permission to access this page."):
    flash(message, "danger")
    return redirect(url_for("index"))


def super_admin_required(view):
    """Decorator: only Super Admin (User.is_super_admin=True) may proceed.

    Used by cross-Domain infrastructure routes (Tenant / API Key / Domain
    CRUD) — actions that aren't scoped to one Domain.
    """
    @wraps(view)
    def decorated(*args, **kwargs):
        unauth = _require_login(view)
        if unauth is not None:
            return unauth
        if not is_super_admin():
            log.warning("Super-Admin route blocked for %s",
                        (session.get("user") or {}).get("email", "?"))
            return _forbid("This action requires Super Admin privileges.")
        return view(*args, **kwargs)
    return decorated


def global_admin_required(view):
    """Decorator: Super Admin OR Domain Global Admin in the active Domain.

    Used by routes that confirm/revoke `to_be_deleted` queue items, manage
    Domain-level role assignments, etc.
    """
    @wraps(view)
    def decorated(*args, **kwargs):
        unauth = _require_login(view)
        if unauth is not None:
            return unauth
        if not is_global_admin():
            log.warning("Global-Admin route blocked for %s (active domain=%s)",
                        (session.get("user") or {}).get("email", "?"),
                        _active_domain_id())
            return _forbid("Global Admin privileges required for this Domain.")
        return view(*args, **kwargs)
    return decorated


def domain_admin_required(view):
    """Decorator: Super / Global / Domain Admin in the active Domain.

    The drop-in replacement for the legacy `@admin_required` — today's
    admins (Super Admin OR pre-existing Domain Global Admins) all satisfy
    this on every Domain they're assigned to.
    """
    @wraps(view)
    def decorated(*args, **kwargs):
        unauth = _require_login(view)
        if unauth is not None:
            return unauth
        if not is_domain_admin():
            log.warning("Domain-Admin route blocked for %s (active domain=%s)",
                        (session.get("user") or {}).get("email", "?"),
                        _active_domain_id())
            return _forbid("Admin privileges required for this Domain.")
        return view(*args, **kwargs)
    return decorated


def domain_operator_required(view):
    """Decorator: any user with a role in the active Domain (operator / admin / GA / super).

    Used by routes that mutate Domain-scoped data — both Operators and
    Admins satisfy this. The deletion-specific branching (Operator → queue
    as `to_be_deleted`; Admin → direct queue/push) happens inside the
    writer, not the decorator.
    """
    @wraps(view)
    def decorated(*args, **kwargs):
        unauth = _require_login(view)
        if unauth is not None:
            return unauth
        if not is_domain_operator():
            log.warning("Domain-Operator route blocked for %s (active domain=%s)",
                        (session.get("user") or {}).get("email", "?"),
                        _active_domain_id())
            return _forbid("You need a role in this Domain to perform this action.")
        return view(*args, **kwargs)
    return decorated
