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


def _current_domain():
    """Phase B.2: return the active Domain for this request.

    `g.domain` is populated by the `_resolve_active_domain` before-request
    hook in app.py — the slug in `session["active_profile"]["tenant"]`
    resolves a Domain row directly (Phase A migrated each Tenant.slug onto
    the derived Domain.slug, preserving CLI back-compat).
    """
    from flask import g
    return getattr(g, "domain", None)


def _credentials_for_engine(domain_id: int, engine_name: str) -> dict[int, DhcpEngineCredential]:
    """Map SMC's 1-based ``nodeid`` -> DhcpEngineCredential.

    The cluster_detail template looks up creds via
    ``creds_by_node.get(n.nodeid)``, where ``n.nodeid`` is
    ``engine_inquiry.NodeInfo.nodeid`` — an integer pulled from the SDK
    and 1-based by SMC convention (cluster member 1, member 2, ...).

    What we store on the credential row is different:

      * ``node_index`` — 0-based, the Python loop index from
        ``enumerate(engine.nodes)`` at enrollment.
      * ``node_id`` — opaque SMC href-tail / element key (e.g. "47780").
        Looks numeric but is **not** the cluster member nodeid.

    Mapping rule: ``node_index + 1`` IS the SMC 1-based nodeid. We used
    to also try ``int(node_id)`` as a fallback, but that misfired when
    SMC's href tails were numeric — they got mistaken for cluster
    member IDs and the Terminal button stayed grey forever.
    """
    rows = (DhcpEngineCredential.query
            .filter_by(domain_id=domain_id, engine_name=engine_name)
            .all())
    out: dict[int, DhcpEngineCredential] = {}
    for r in rows:
        key = int(getattr(r, "node_index", 0)) + 1
        out[key] = r
    return out


# ── Routes ───────────────────────────────────────────────────────────────

@engines_bp.route("/")
def index():
    """Default landing — bounce to clusters."""
    return redirect(url_for("engines.clusters"))


@engines_bp.route("/clusters")
@profile_required_admin
def clusters():
    """Read-through cached engines list.

    Cache key bundles tenant_id + domain + a short SHA256 of the API
    key (never the plaintext) so concurrent users on different
    tenants/domains never see each other's data. Cache is process-local;
    the operator forces a live SMC fetch via ``?refresh=1`` (wired to
    the "Refresh from SMC" button on the page).
    """
    import hashlib
    from shared.smc_cache import cache_get_or_fetch
    from webapp.models import DhcpEngineSshAccess

    try:
        cfg = _user_cfg()
        domain_obj = _current_domain()
        domain_id = domain_obj.id if domain_obj else 0
        cv = cache_get_or_fetch(
            section="engines.list",
            # Phase B.2: domain_id alone identifies (server, smc-domain, key)
            # — replaces the legacy (tenant_id, domain_name, api_key_hash) tuple.
            key_parts=(domain_id,),
            fetcher=lambda: engine_inquiry.list_clusters(cfg),
            refresh=(request.args.get("refresh") == "1"),
        )
        # Surface which engines have FlexEdge state (creds and/or SSH
        # rule) so the template can show a "Forget" button only when
        # the operator has something to clean up.
        managed_engine_names: set[str] = set()
        if domain_id:
            for c in (DhcpEngineCredential.query
                      .filter_by(domain_id=domain_id).all()):
                managed_engine_names.add(c.engine_name)
            for a in (DhcpEngineSshAccess.query
                      .filter_by(domain_id=domain_id).all()):
                managed_engine_names.add(a.engine_name)
    except Exception as exc:
        log.error("clusters list failed: %s", exc)
        return render_template("error.html", message=str(exc))
    return render_template(
        "engines/clusters.html",
        engines=cv.data,
        cache_meta=cv,
        managed_engine_names=managed_engine_names,
        active_tenant=domain_obj,   # template renders .name — Domain has display_name; alias below
        active_domain=cfg.get("domain") or "",
    )


@engines_bp.route("/clusters/<path:engine_name>/forget", methods=["POST"])
@profile_required_admin
def cluster_forget(engine_name):
    """Forget an engine on the FlexEdgeAdmin side.

    Cleanup:
      1. Delete every ``DhcpEngineCredential`` row for this engine
         (DB-only; nothing to revoke on the engine itself — passwords
         stored here are encrypted secrets).
      2. If a ``DhcpEngineSshAccess`` row exists, remove the SMC rule
         it tracks + the helper Host elements + upload the policy, then
         delete the row.
      3. Invalidate the engines.list cache so the operator's next page
         load reflects the cleaned state.

    The engine itself is **not** affected — it remains in SMC,
    reachable through SMC Management Client, with its production
    policies intact. This is purely a FlexEdge-side cleanup.
    """
    from webapp.models import DhcpEngineSshAccess
    from webapp.smc_dhcp_client import (
        smc_session as smc_dhcp_session,
        remove_ssh_access_rule, policy_upload,
        SMCConfig as DhcpSMCConfig,
    )
    from shared.smc_cache import invalidate

    domain_obj = _current_domain()
    if domain_obj is None:
        flash("No active domain — pick one first.", "warning")
        return redirect(url_for("engines.clusters"))

    creds_to_delete = (DhcpEngineCredential.query
                       .filter_by(domain_id=domain_obj.id, engine_name=engine_name)
                       .all())
    access = (DhcpEngineSshAccess.query
              .filter_by(domain_id=domain_obj.id, engine_name=engine_name)
              .first())

    if not creds_to_delete and not access:
        flash(f"No FlexEdge state on record for engine '{engine_name}'.",
              "info")
        return redirect(url_for("engines.clusters"))

    cred_count = len(creds_to_delete)
    rule_summary = ""
    rule_remove_warning = ""

    # Step 1: SMC-side cleanup of the rule (if any). Done first so a
    # failure here doesn't leave us with orphan SMC state and no DB
    # record pointing at it.
    if access:
        # Need an ApiKey to log into SMC. Use the one tracked on the
        # access row — that's the key originally used to create the rule.
        api_key = db.session.get(ApiKey, access.api_key_id) if access.api_key_id else None
        if api_key is None:
            rule_remove_warning = (
                f"Tenant's API key for the rule is gone — cannot log "
                f"into SMC to remove rule {access.rule_name!r}. "
                f"DB-only cleanup proceeding; remove the rule manually "
                f"in SMC Management Client."
            )
        else:
            # Phase B.2: pull server config from the ApiKey directly
            # (Phase A absorbed those fields onto api_keys).
            cfg = DhcpSMCConfig(
                url=api_key.smc_url,
                api_key=api_key.decrypted_key,
                domain=domain_obj.smc_domain_name or "",
                api_version=api_key.api_version or "",
                verify_ssl=api_key.verify_ssl,
                timeout=api_key.timeout,
            )
            try:
                with smc_dhcp_session(cfg):
                    rule_existed, msg = remove_ssh_access_rule(
                        access.policy_name, access.rule_name)
                    upload_ok = True
                    upload_msg = ""
                    if rule_existed:
                        upload_msg_raw = policy_upload(
                            access.engine_name, access.policy_name)
                        upload_msg = str(upload_msg_raw)
                rule_summary = (
                    f"removed rule {access.rule_name!r}; "
                    f"upload={upload_msg!r}"
                    if rule_existed else
                    f"rule {access.rule_name!r} was already gone"
                )
            except Exception as exc:
                rule_remove_warning = (
                    f"SMC-side cleanup FAILED for rule "
                    f"{access.rule_name!r}: {exc}. DB cleanup will NOT "
                    f"proceed so you can retry. Remove the rule "
                    f"manually in SMC GUI if needed, then click Forget "
                    f"again to clear the DB."
                )
                _log_activity_engines(
                    "engines", "forget", "failed",
                    target=engine_name, detail=str(exc),
                )
                flash(rule_remove_warning, "danger")
                return redirect(url_for("engines.clusters"))

    # Step 2: DB cleanup — creds first, then access row.
    for c in creds_to_delete:
        db.session.delete(c)
    if access:
        db.session.delete(access)
    db.session.commit()

    # Step 3: cache invalidation so the next page load is fresh.
    invalidate("engines.list")

    detail = (f"creds_deleted={cred_count} "
              f"access_deleted={'yes' if access else 'no'} "
              f"{rule_summary}")
    _log_activity_engines("engines", "forget", "ok",
                          target=engine_name, detail=detail)

    msg_parts = [
        f"Forgot engine '{engine_name}' on the FlexEdge side.",
        f"Deleted {cred_count} credential row(s).",
    ]
    if access:
        msg_parts.append(rule_summary or "Removed SMC rule.")
    if rule_remove_warning:
        msg_parts.append(rule_remove_warning)
    flash(" ".join(msg_parts), "success" if not rule_remove_warning else "warning")
    return redirect(url_for("engines.clusters"))


def _log_activity_engines(category, action, status, target="", detail=""):
    """Engines audit-log entry — funnels through the platform log writer.

    Per the standing rule (memory: feedback_logging_standing_rule), every
    feature emits via `shared.logging.audit()`. Engines-namespace rows
    use `feature='engines'`; the legacy category+action pair is composed
    into the platform action string for backwards compatibility with
    existing readers that grep by action name.
    """
    from shared.logging import audit
    audit(feature="engines",
          action=f"{category}.{action}",
          target=target, detail=detail, status=status)


@engines_bp.route("/clusters/<path:engine_name>")
@profile_required_admin
def cluster_detail(engine_name):
    """Render a single cluster's full detail page.

    All work — SMC fetch, DB credential lookup, template render — is wrapped
    in a single try/except. Any exception bubbles up to a friendly
    ``error.html`` page instead of Flask's bare 500 default, *and* gets
    logged with stack trace so we can diagnose without operator screenshots.
    """
    try:
        cfg = _user_cfg()
        detail = engine_inquiry.cluster_detail(cfg, engine_name)

        creds_by_node = {}
        domain_obj = _current_domain()
        if domain_obj:
            creds_by_node = _credentials_for_engine(domain_obj.id, engine_name)

        return render_template(
            "engines/cluster_detail.html",
            detail=detail,
            creds_by_node=creds_by_node,
        )
    except Exception as exc:
        log.exception("cluster_detail(%s) failed", engine_name)
        return render_template(
            "error.html",
            message=f"Could not render cluster detail for {engine_name!r}: "
                    f"{type(exc).__name__}: {exc}",
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
