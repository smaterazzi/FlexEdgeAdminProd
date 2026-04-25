"""
FlexEdgeAdmin — Engines Blueprint.

Top-level "Engines" section of the web UI:

    /engines/clusters             read-only list of all engines
    /engines/clusters/<name>      cluster detail (summary + nodes table)
    /engines/credentials          redirect to /dhcp/credentials
    /engines/tools                tools landing
    /engines/tools/scan           Scan tool (Phase C — placeholder for now)
    /engines/nodes/<cred_id>/terminal  in-browser SSH terminal (Phase B)

Phase A: Clusters / Nodes views (read-only). Terminal icon is rendered
but disabled until Phase B is enabled.

Phase B: WebSocket terminal route lives in webapp/engine_terminal.py
and is wired in via init_engines_manager() at app startup.
"""

from __future__ import annotations

import logging
from functools import wraps

from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, session, request,
)

from shared.db import db
from webapp.models import (
    ApiKey, DhcpEngineCredential, Tenant,
)
import engine_inquiry

log = logging.getLogger(__name__)

engines_bp = Blueprint("engines", __name__, url_prefix="/engines")


# ── Access control (mirrors DHCP/TLS pattern) ────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_info = session.get("user")
        if not user_info:
            return redirect(url_for("auth.login", next=request.url))
        import user_manager
        if not user_manager.is_admin(user_info.get("email", "")):
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


def profile_required_admin(f):
    """Combine admin-role + active SMC profile/domain."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("auth.login", next=request.url))
        import user_manager
        if not user_manager.is_admin(session["user"].get("email", "")):
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        if "active_profile" not in session:
            flash("Select an SMC profile to continue.", "warning")
            return redirect(url_for("select_profile"))
        if "active_domain" not in session:
            flash("Select an SMC domain to continue.", "warning")
            return redirect(url_for("select_domain"))
        return f(*args, **kwargs)
    return decorated


# ── Helpers ──────────────────────────────────────────────────────────────

def _user_cfg() -> dict:
    """Build the dict-shaped SMC config from the current session.

    Mirrors ``app.get_user_cfg()`` — duplicated here to avoid importing
    from app.py (circular import on blueprint registration).
    """
    profile = session.get("active_profile") or {}
    if not profile:
        raise ValueError("No SMC profile selected.")
    return {
        "smc_url":      profile["smc_url"],
        "api_key":      profile["api_key"],
        "verify_ssl":   profile.get("verify_ssl", False),
        "timeout":      profile.get("timeout", 120),
        "domain":       session.get("active_domain"),
        "retry_on_busy": True,
    }


def _current_tenant() -> Tenant | None:
    slug = (session.get("active_profile") or {}).get("tenant")
    if not slug:
        return None
    return Tenant.query.filter_by(slug=slug).first()


def _credentials_for_engine(tenant_id: int, engine_name: str) -> dict[int, DhcpEngineCredential]:
    """Map nodeid -> DhcpEngineCredential (only entries with verify_status='ok')."""
    rows = (DhcpEngineCredential.query
            .filter_by(tenant_id=tenant_id, engine_name=engine_name)
            .all())
    return {r.node_id: r for r in rows}


# ── Routes ───────────────────────────────────────────────────────────────

@engines_bp.route("/")
def index():
    """Default landing — bounce to clusters."""
    return redirect(url_for("engines.clusters"))


@engines_bp.route("/clusters")
@profile_required_admin
def clusters():
    try:
        cfg = _user_cfg()
        summary = engine_inquiry.list_clusters(cfg)
    except Exception as exc:
        log.error("clusters list failed: %s", exc)
        return render_template("error.html", message=str(exc))
    return render_template("engines/clusters.html", engines=summary)


@engines_bp.route("/clusters/<path:engine_name>")
@profile_required_admin
def cluster_detail(engine_name):
    try:
        cfg = _user_cfg()
        detail = engine_inquiry.cluster_detail(cfg, engine_name)
    except Exception as exc:
        log.error("cluster_detail(%s) failed: %s", engine_name, exc)
        return render_template("error.html", message=str(exc))

    creds_by_node = {}
    tenant = _current_tenant()
    if tenant:
        creds_by_node = _credentials_for_engine(tenant.id, engine_name)

    return render_template(
        "engines/cluster_detail.html",
        detail=detail,
        creds_by_node=creds_by_node,
    )


@engines_bp.route("/credentials")
@admin_required
def credentials_redirect():
    """Permanent redirect to the canonical DHCP-side credentials page."""
    return redirect(url_for("dhcp.credentials"), code=302)


@engines_bp.route("/tools")
@admin_required
def tools():
    return render_template("engines/tools.html")


@engines_bp.route("/tools/scan")
@admin_required
def tools_scan():
    return render_template("engines/scan_placeholder.html")


@engines_bp.route("/nodes/<int:cred_id>/terminal")
@admin_required
def node_terminal(cred_id):
    """Render the xterm.js terminal page. The WebSocket route lives on the
    Flask-Sock instance — see webapp/engine_terminal.py.
    """
    from webapp.models import DhcpEngineCredential
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if cred is None:
        flash("Credential not found.", "danger")
        return redirect(url_for("engines.clusters"))
    if cred.last_verify_status != "ok":
        flash("This credential is not verified — re-enroll it before using the terminal.",
              "warning")
        return redirect(url_for("dhcp.credentials"))
    try:
        ws_path = url_for("engines.node_terminal_ws", cred_id=cred_id)
    except Exception:
        flash("Terminal WebSocket route is unavailable — flask-sock not installed.",
              "danger")
        return redirect(url_for("engines.clusters"))
    return render_template(
        "engines/terminal.html",
        cred=cred,
        ws_path=ws_path,
    )


# ── Initialization ──────────────────────────────────────────────────────

def init_engines_manager(app):
    """Register the WebSocket terminal route on the shared `Sock` instance.

    Called from app.py after the Flask-Sock instance is created. Phase B
    plumbing lives in webapp/engine_terminal.py.
    """
    try:
        from webapp import engine_terminal
        engine_terminal.register_routes(app)
    except Exception as exc:
        log.error("engine_terminal init failed (terminal will be unavailable): %s", exc)
