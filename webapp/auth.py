"""
Microsoft Entra ID (Azure AD) OIDC authentication for FlexEdgeAdmin.

Provides:
  auth_bp       — Flask Blueprint (register with app.register_blueprint)
  init_auth()   — call once after app is created to initialise OAuth
  login_required      — decorator: redirect to login if not authenticated
  profile_required    — decorator: implies login + active SMC profile & domain selected
"""

import logging
from functools import wraps

from flask import (
    Blueprint, session, redirect, url_for,
    request, flash, render_template, current_app,
)
from authlib.integrations.flask_client import OAuth

log = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)
oauth = OAuth()


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

def login_required(f):
    """Redirect unauthenticated users to /login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
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
        if "user" not in session:
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
    email = (
        userinfo.get("email") or userinfo.get("preferred_username", "")
    ).lower().strip()
    name = userinfo.get("name") or email
    sub = userinfo.get("sub", "")

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
        flash(
            f"<strong>{email}</strong> is not authorised. "
            "Contact the administrator to request access.",
            "danger",
        )
        session.clear()
        return render_template("auth/login.html")

    # If user has exactly one profile, pre-select it and skip profile page
    if len(profiles) == 1:
        session["active_profile"] = profiles[0]
        return redirect(url_for("select_domain"))

    return redirect(url_for("select_profile"))


@auth_bp.route("/logout")
def logout():
    """Clear the session and return to the login page."""
    email = session.get("user", {}).get("email", "")
    session.clear()
    log.info("User logged out: %s", email)
    return redirect(url_for("auth.login"))
