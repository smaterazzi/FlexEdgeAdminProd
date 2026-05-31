"""
Microsoft Entra ID (Azure AD) OIDC authentication for FlexEdgeAdmin.

Provides:
  auth_bp       — Flask Blueprint (register with app.register_blueprint)
  init_auth()   — call once after app is created to initialise OAuth
  login_required      — decorator: redirect to login if not authenticated
  profile_required    — decorator: implies login + active SMC profile & domain selected

Dev-only auth bypass (audit V3, 2026-05-29):
  When BOTH ``FLASK_DEBUG=1`` AND ``FEA_DEV_AUTH_BYPASS_EMAIL=<email>`` are
  set, ``login_required`` synthesises a session for ``<email>`` without
  going through Entra ID. Lets `curl` / `httpie` flows drive authenticated
  routes for local verification. Two-key gate is intentional — a single
  env var would be too easy to leave on in a Coolify config. Production
  guards:
    * Boot-time WARNING log in webapp/app.py when the bypass is active.
    * Setup wizard refuses to run while the bypass is active so a
      bypassed login can't take over the bootstrap.
"""

import logging
import os
import re
from functools import wraps

from flask import (
    Blueprint, session, redirect, url_for,
    request, flash, render_template, current_app,
)
from markupsafe import Markup, escape
from authlib.integrations.flask_client import OAuth

log = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)
oauth = OAuth()


def _dev_auth_bypass_email() -> str:
    """Return the dev-bypass email iff both gating env vars are set.

    Empty string means bypass OFF — the production path. Boot-time
    warning emitted in webapp/app.py when this returns non-empty.
    """
    if (os.environ.get("FLASK_DEBUG", "").strip() == "1"
            and os.environ.get("FEA_DEV_AUTH_BYPASS_EMAIL", "").strip()):
        return os.environ["FEA_DEV_AUTH_BYPASS_EMAIL"].strip()
    return ""


def dev_auth_bypass_is_active() -> bool:
    """True iff the V3 dev-auth bypass is currently enabled. Exported
    so the setup wizard can refuse to run (defense-in-depth)."""
    return bool(_dev_auth_bypass_email())


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _aad_tenant_id() -> str:
    return (current_app.config.get("AZURE_TENANT_ID") or "").strip().lower()


def aad_tenant_is_single() -> bool:
    """True iff AZURE_TENANT_ID is a concrete UUID (not common/organizations).

    The OIDC userinfo `tid` claim cannot be safely matched against a
    multi-tenant placeholder, so any deployment configured with
    `common` / `organizations` / `consumers` is reachable from ANY
    Microsoft tenant — the first stranger to find the URL becomes Super
    Admin during setup. Audit fix-up H10 (2026-05-09) — gate the setup
    wizard and the per-login `tid` check on this returning True.
    """
    return bool(_UUID_RE.match(_aad_tenant_id()))


def verify_aad_tid(userinfo: dict) -> bool:
    """Return True iff userinfo's `tid` claim equals AZURE_TENANT_ID.

    Returns False when the tenant is multi-tenant (no concrete UUID
    to match against — fail closed). Audit fix-up H10 (2026-05-09).
    """
    if not aad_tenant_is_single():
        return False
    return (userinfo.get("tid") or "").lower() == _aad_tenant_id()


# ── Initialisation ────────────────────────────────────────────────────────

def init_auth(app):
    """Bind the OAuth client to the Flask app using AZURE_* config values."""
    oauth.init_app(app)
    tenant_id = app.config["AZURE_TENANT_ID"]
    oauth.register(
        name="microsoft",
        client_id=app.config["AZURE_CLIENT_ID"],
        client_secret=app.config["AZURE_CLIENT_SECRET"],
        server_metadata_url=(
            f"https://login.microsoftonline.com/{tenant_id}/v2.0"
            "/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )


# ── Decorators ────────────────────────────────────────────────────────────

def _maybe_synthesise_dev_session() -> bool:
    """V3 dev-auth bypass: synthesise ``session['user']`` when both gating
    env vars are set AND the session is currently empty. Returns True if
    a synthesis happened (the caller should proceed as if logged in).
    Never reaches production: gated by FLASK_DEBUG=1.
    """
    if "user" in session:
        return False
    bypass_email = _dev_auth_bypass_email()
    if not bypass_email:
        return False
    session["user"] = {
        "email": bypass_email,
        "name": "Dev Bypass",
        "oid": "dev-bypass-oid",
        "tid": _aad_tenant_id() or "dev-bypass-tid",
    }
    log.warning(
        "DEV AUTH BYPASS — synthesised session for %s (route=%s). "
        "NEVER expected in production.",
        bypass_email, request.path,
    )
    return True


def login_required(f):
    """Redirect unauthenticated users to /login. V3 dev-bypass aware."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session and not _maybe_synthesise_dev_session():
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated


def profile_required(f):
    """
    Require an authenticated user with an active SMC profile and domain.

    Re-validates the cached profile's API key on every request: if an
    admin revoked the key in /admin/api-keys, the operator's session
    profile (a plaintext snapshot) would otherwise keep failing against
    SMC with "No session found" until they re-selected. We catch that
    here, drop the stale snapshot, and bounce them to /select-profile
    so a fresh resolved profile gets cached.

    Redirects in order: login → select_profile → select_domain → view.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session and not _maybe_synthesise_dev_session():
            return redirect(url_for("auth.login", next=request.url))
        if "active_profile" not in session:
            flash("Select an SMC profile to continue.", "warning")
            return redirect(url_for("select_profile"))

        import user_manager
        if not user_manager.is_active_profile_valid(session.get("active_profile")):
            log.info("Active profile API key is no longer valid for %s — "
                     "clearing session profile",
                     session.get("user", {}).get("email", "?"))
            session.pop("active_profile", None)
            session.pop("active_domain", None)
            flash("Your selected API key is no longer active "
                  "(it may have been revoked). Pick a profile to continue.",
                  "warning")
            return redirect(url_for("select_profile"))

        if "active_domain" not in session:
            flash("Select an SMC domain to continue.", "warning")
            return redirect(url_for("select_domain"))
        return f(*args, **kwargs)
    return decorated


# ── Routes ────────────────────────────────────────────────────────────────

@auth_bp.route("/login")
def login():
    """Show the login page / redirect to Entra ID."""
    if "user" in session:
        return redirect(url_for("index"))
    redirect_uri = url_for("auth.callback", _external=True)
    return oauth.microsoft.authorize_redirect(redirect_uri)


@auth_bp.route("/auth/callback")
def callback():
    """Handle the OAuth2 callback from Microsoft Entra ID."""
    try:
        token = oauth.microsoft.authorize_access_token()
    except Exception as exc:
        log.error("OAuth callback error: %s", exc)
        flash(f"Authentication failed: {exc}", "danger")
        return render_template("auth/login.html")

    userinfo = token.get("userinfo") or {}

    # H10 (audit fix-up, 2026-05-09): verify the token's `tid` claim
    # matches AZURE_TENANT_ID. Without this check, deployments configured
    # with `common`/`organizations` accept tokens from ANY Microsoft tenant
    # — and during setup mode the first stranger to find /setup becomes
    # Super Admin. Fail-closed: if AZURE_TENANT_ID isn't a concrete UUID,
    # the verifier returns False and we refuse the login here.
    if not verify_aad_tid(userinfo):
        log.warning(
            "Login refused for tid=%r (AZURE_TENANT_ID=%r): tid claim does "
            "not match the configured tenant or AZURE_TENANT_ID is not a "
            "single-tenant UUID.",
            userinfo.get("tid"), _aad_tenant_id(),
        )
        flash(
            "Authentication failed: token issuer does not match the "
            "configured Azure tenant. Contact the administrator.",
            "danger",
        )
        session.clear()
        return render_template("auth/login.html")

    email = (
        userinfo.get("email") or userinfo.get("preferred_username", "")
    ).lower().strip()
    name = userinfo.get("name") or email
    sub = userinfo.get("sub", "")

    # M2 (audit fix-up, 2026-05-09): regenerate the session on login.
    # Flask sessions are signed cookies — clearing the dict and re-setting
    # the keys re-issues the cookie with fresh content, making any
    # pre-login fixation attempt's snooped cookie state worthless. Drops
    # any stale `active_profile` / `active_domain` from a previous user
    # on the same browser too.
    session.clear()
    session["user"] = {"email": email, "name": name, "sub": sub}
    session.permanent = True
    log.info("User logged in: %s", email)

    # Setup mode: if no users exist yet, redirect to setup wizard
    if current_app.config.get("SETUP_REQUIRED", False):
        return redirect(url_for("admin_setup.setup"))

    import user_manager
    profiles = user_manager.get_user_profiles(email)
    if not profiles:
        log.warning("Unlisted user attempted login: %s", email)
        # C8 (audit fix-up, 2026-05-09): escape the user-controlled email
        # before mixing with the literal HTML wrapper. Flash render no
        # longer uses |safe globally, so non-HTML flashes are auto-escaped;
        # this one wraps with Markup so the <strong> styling survives.
        flash(
            Markup("<strong>") + escape(email) + Markup("</strong>")
            + " is not authorised. "
            + "Contact the administrator to request access.",
            "danger",
        )
        session.clear()
        return render_template("auth/login.html")

    # If user has exactly one profile, pre-select it and skip the picker.
    # After the Multi-Domain Revamp each profile already pins its
    # smc_domain_name, so we set active_domain here too and land the user
    # straight on the dashboard — no /select-domain detour.
    if len(profiles) == 1:
        only = profiles[0]
        session["active_profile"] = only
        session["active_domain"] = (only.get("domain") or "").strip() or "Shared Domain"
        log.info("User %s auto-selected sole profile '%s' (smc-domain '%s')",
                 email, only.get("name"), session["active_domain"])
        return redirect(url_for("index"))

    return redirect(url_for("select_profile"))


@auth_bp.route("/logout")
def logout():
    """Clear the session and return to the login page."""
    email = session.get("user", {}).get("email", "")
    session.clear()
    log.info("User logged out: %s", email)
    return redirect(url_for("auth.login"))
