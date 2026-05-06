"""
FlexEdgeAdmin — SMC Administration & Migration Manager
Web-based browser for Forcepoint SMC objects and policies,
plus a full FortiGate-to-Forcepoint migration workflow.

Authentication
--------------
All routes are protected by Microsoft Entra ID (Azure AD) OIDC.
After login, users select an SMC API profile (from users.json) and then
choose an SMC admin domain — this session context is used for all subsequent
SMC API calls.

Required environment variables
-------------------------------
  AZURE_TENANT_ID      — Azure / Entra ID tenant UUID
  AZURE_CLIENT_ID      — App registration client ID
  AZURE_CLIENT_SECRET  — App registration client secret
  FLASK_SECRET_KEY     — Persistent session signing key (generate once)
  USERS_CONFIG         — Path to users.json (default: ../users.json)

Optional
--------
  SMC_CONFIG   — Fallback smc_config.yml path (legacy; not used by the UI)
  FLASK_DEBUG  — Set to "1" to enable debug mode
  PORT         — Listening port (default 5000)

Routes
------
  /login                         Microsoft Entra ID redirect
  /auth/callback                 OIDC callback
  /logout                        Clear session
  /select-profile                Pick an SMC API profile
  /select-domain                 Pick an SMC admin domain
  /                              Dashboard
  /browse/<type>                 List SMC elements
  /detail/<type>/<name>          Element detail
  /policies                      Policy list
  /policy/<name>                 Policy rules viewer
  /migration/                    Migration projects list
  /migration/new                 Create project (upload .conf)
  /migration/<id>/parsed         View parsed objects
  /migration/<id>/target         Configure SMC target
  /migration/<id>/dedup          Deduplication analysis
  /migration/<id>/rules          Rule conversion + selection
  /migration/<id>/import         Import execution
"""

import logging
import os
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, flash, session, g,
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

# ── Path setup ───────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))
import smc_client
import project_manager
import fgt_parser
from auth import auth_bp, init_auth, login_required, profile_required
import user_manager

# ── App Setup ────────────────────────────────────────────────────────────

app = Flask(__name__)

# Stable secret key — must be set via env var in production
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
if not os.environ.get("FLASK_SECRET_KEY"):
    app.logger.warning(
        "FLASK_SECRET_KEY is not set — sessions will be invalidated on restart. "
        "Set this env var for production deployments."
    )

app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,   # 16 MB upload limit
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # CSRF — enabled app-wide via flask-wtf. Bearer-token webhooks
    # (TLS / DHCP renew endpoints) are explicitly exempted at the route.
    WTF_CSRF_TIME_LIMIT=None,                # token valid for the session lifetime
    WTF_CSRF_SSL_STRICT=False,               # ProxyFix terminates TLS upstream
    # Entra ID / OAuth settings (required)
    AZURE_TENANT_ID=os.environ.get("AZURE_TENANT_ID", ""),
    AZURE_CLIENT_ID=os.environ.get("AZURE_CLIENT_ID", ""),
    AZURE_CLIENT_SECRET=os.environ.get("AZURE_CLIENT_SECRET", ""),
)

# Trust X-Forwarded-* headers from reverse proxies (nginx, traefik, etc.)
# so that url_for(_external=True) produces correct HTTPS URLs in Docker.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ── CSRF protection (app-wide) ──────────────────────────────────────────
# Every state-changing POST/PUT/PATCH/DELETE must carry a csrf_token form
# field OR an X-CSRFToken header. Bearer-token webhook endpoints exempt
# themselves explicitly via @csrf.exempt at the route definition site.
csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def _handle_csrf_error(e):
    """Surface CSRF failures as a flash + redirect rather than a 400 dump."""
    log.warning("CSRF rejection on %s %s: %s", request.method, request.path, e.description)
    if request.is_json or request.headers.get("Accept", "").startswith("application/json"):
        return jsonify(error="CSRF token missing or invalid"), 400
    flash("Your form session expired or was tampered with. Please retry.", "danger")
    return redirect(request.referrer or url_for("index")), 303

# ── Logging ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

# ── Database ────────────────────────────────────────────────────────────

from shared.db import db

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{Path(__file__).resolve().parent.parent / 'config' / 'flexedge.db'}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

from webapp.db_init import init_database
init_database(app)

from webapp.models import enable_wal_mode
enable_wal_mode(app)

# Register every platform feature in the log registry. The /admin/log-settings
# page lists these in stable insertion order, exposing a per-feature on/off
# toggle. New features must register themselves here at boot.
from shared.logging import register_feature
register_feature("dhcp",      "DHCP Manager")
register_feature("tls",       "TLS Manager")
register_feature("engines",   "Engines")
register_feature("migration", "Migration")
register_feature("optimizer", "Rule Optimizer")
register_feature("admin",     "Admin Portal")
register_feature("auth",      "Authentication")
register_feature("changes",   "Change Management")
register_feature("system",    "System")

# ── Auth ─────────────────────────────────────────────────────────────────

init_auth(app)
app.register_blueprint(auth_bp)

# ── Setup wizard (one-time, before admin blueprint) ─────────────────────

from setup import setup_bp
app.register_blueprint(setup_bp)

from admin import admin_bp
app.register_blueprint(admin_bp)

# ── TLS Manager ──────────────────────────────────────────────────────────

from tls_manager import tls_bp, init_tls_manager
app.config.setdefault("CONFIG_DIR", str(Path(__file__).resolve().parent.parent / "config"))
app.config.setdefault("CERTBOT_LIVE_DIR",
                      os.environ.get("CERTBOT_LIVE_DIR", "/etc/letsencrypt/live"))
init_tls_manager(app)
app.register_blueprint(tls_bp)

# ── DHCP Manager ─────────────────────────────────────────────────────────

from dhcp_manager import dhcp_bp, init_dhcp_manager
init_dhcp_manager(app)
app.register_blueprint(dhcp_bp)

# ── CSRF exemptions for Bearer-token webhook endpoints ──────────────────
# These routes authenticate via @require_api_token (Authorization: Bearer ...)
# called by certbot deploy-hook scripts and external schedulers. They never
# carry session cookies, so CSRF doesn't apply.
for _endpoint in ("tls.api_renew", "tls.api_check_renewals"):
    _view = app.view_functions.get(_endpoint)
    if _view is not None:
        csrf.exempt(_view)

# ── Engines (clusters, credentials link, tools, terminal) ───────────────

from engines_manager import engines_bp, init_engines_manager
app.register_blueprint(engines_bp)
init_engines_manager(app)

# ── Change Management Queue ─────────────────────────────────────────────
# Operator-facing UI for the two-phase commit queue. Backed by the push
# runner in shared/queue_runner.py. Spec: docs/ChangeManagementProcess.md.

from webapp.changes import changes_bp, init_changes_blueprint
app.register_blueprint(changes_bp)
init_changes_blueprint(app)


# ── Session-based SMC config ─────────────────────────────────────────────

def get_user_cfg() -> dict:
    """
    Build the SMC config dict from the current user's session.
    Raises ValueError if no profile/domain has been selected yet.
    """
    profile = session.get("active_profile")
    if not profile:
        raise ValueError("No SMC profile selected. Please choose a profile first.")
    return {
        "smc_url":      profile["smc_url"],
        "api_key":      profile["api_key"],
        "verify_ssl":   profile.get("verify_ssl", False),
        "timeout":      profile.get("timeout", 120),
        "domain":       session.get("active_domain"),
        "retry_on_busy": True,
    }


@app.before_request
def _resolve_active_domain():
    """Phase B.2: derive `g.domain` from the existing session shape.

    Today's session carries `active_profile["tenant"]` (the slug) — Phase A
    backfilled each old Tenant.slug onto the derived Domain.slug, so the
    same value resolves a Domain row directly. This populates `g.domain`
    and `g.api_key_obj` for the duration of the request so feature code
    can switch from `Tenant.query.filter_by(slug=...)` to `g.domain.id`
    without touching the auth flow itself.

    Failures are silent — `g.domain` stays None and the route handlers
    fall back to legacy tenant lookups.
    """
    g.domain = None
    g.api_key_obj = None
    profile = session.get("active_profile") or {}
    slug = profile.get("tenant")
    if not slug:
        return
    try:
        from webapp.models import Domain
        d = Domain.query.filter_by(slug=slug).first()
        if d is not None and d.is_active:
            g.domain = d
            g.api_key_obj = d.api_key
    except Exception:
        # before_request must never raise — leave g.domain unset.
        pass


def _current_domain():
    """Return the active Domain for this request, or None if not set.

    Prefer this over `_current_tenant_row()` going forward — every feature
    table now carries `domain_id`, and `g.domain` is populated by the
    `_resolve_active_domain` before-request hook.
    """
    return getattr(g, "domain", None)


def stamp_domain_scope(row):
    """Phase B.2 write-side helper: stamp the active Domain scope onto a
    new feature row.

    Sets `domain_id` (canonical, going forward) AND populates legacy
    `tenant_id` + `api_key_id` (still NOT NULL on existing rows in
    operational tables until Phase B.3 drops them). Safe to call on any
    row whether or not those columns exist on its model.

    Returns the row for easy chaining: ``db.session.add(stamp_domain_scope(MyRow(...)))``.
    """
    domain = getattr(g, "domain", None)
    if domain is None:
        return row
    if hasattr(row, "domain_id") and row.domain_id is None:
        row.domain_id = domain.id
    api_key = domain.api_key
    if api_key is not None:
        if hasattr(row, "api_key_id") and row.api_key_id is None:
            row.api_key_id = api_key.id
        if hasattr(row, "tenant_id") and row.tenant_id is None:
            row.tenant_id = api_key.tenant_id
    return row


@app.context_processor
def inject_globals():
    """
    Inject template globals: element_types, cfg (may be None), current user info.
    """
    cfg = None
    if session.get("active_profile") and session.get("active_domain"):
        try:
            cfg = get_user_cfg()
        except Exception:
            pass
    current_user = session.get("user")
    current_user_role = "viewer"
    if current_user:
        current_user_role = user_manager.get_user_role(current_user.get("email", ""))

    # Phase B (Change Management, refined 2026-05-01) — fine-grained role
    # resolution against the active Domain. The legacy
    # `current_user_role == 'admin'` check in templates keeps working
    # unchanged for backward compatibility; new templates can use the
    # more specific flags exposed below.
    from webapp.auth_roles import (
        is_super_admin as _is_super_admin,
        is_global_admin as _is_global_admin,
        is_domain_admin as _is_domain_admin,
        is_domain_operator as _is_domain_operator,
        current_role_for_active_domain,
    )
    try:
        _resolved_role = current_role_for_active_domain()
        _is_sa, _is_ga, _is_da, _is_do = (
            _is_super_admin(), _is_global_admin(),
            _is_domain_admin(), _is_domain_operator(),
        )
        # Surface the legacy 'admin'/'viewer' string so existing templates
        # (sidebar admin section gate, optimizer review queue) keep
        # rendering the same as before for today's admins.
        if _is_da:
            current_user_role = "admin"
        _role_name = _resolved_role.name.lower()
    except Exception:
        _is_sa = _is_ga = _is_da = _is_do = False
        _role_name = "viewer"
    # Resolve the user's available Domains once per request so the topbar
    # switcher can render without an extra DB round-trip per template tag.
    available_profiles = []
    if current_user:
        if hasattr(g, "_available_profiles"):
            available_profiles = g._available_profiles
        else:
            try:
                available_profiles = user_manager.get_user_profiles(
                    current_user.get("email", "")
                )
            except Exception:
                available_profiles = []
            g._available_profiles = available_profiles

    return {
        "element_types":    smc_client.ELEMENT_TYPES,
        "cfg":              cfg,
        "current_user":     current_user,
        "current_user_role": current_user_role,
        # Phase B role flags — legacy `current_user_role == 'admin'` still
        # works for the existing sidebar gate; new templates should prefer
        # these specific flags. Each flag is "this tier OR HIGHER":
        # is_super_admin → super only; is_global_admin → super + GA;
        # is_domain_admin → super + GA + admin; is_domain_operator → any role.
        "is_super_admin":    _is_sa,
        "is_global_admin":   _is_ga,
        "is_domain_admin":   _is_da,
        "is_domain_operator": _is_do,
        "current_role":      _role_name,
        "active_profile":   session.get("active_profile"),
        "active_domain":    session.get("active_domain"),
        "active_domain_obj": getattr(g, "domain", None),
        "available_profiles": available_profiles,
        "app_title":        os.environ.get("APP_TITLE", "FlexEdgeAdmin"),
        "setup_required":   app.config.get("SETUP_REQUIRED", False),
        "build_version":    _build_version,
        # Phase E.1 (Q12) — to_be_deleted strikethrough lookup. Templates
        # call `is_smc_to_be_deleted(href_or_name)` and toggle the
        # `.smc-to-be-deleted` CSS class on listing rows. Lookup is
        # request-scoped (one query per page, lazy on first call).
        "is_smc_to_be_deleted": _is_smc_to_be_deleted,
        # Phase E.2 — bypass queue lookup for per-feature listing badges.
        # `bypass_active(feature)` returns True iff the current user is
        # configured to bypass the queue for `feature` in the active
        # Domain. Listing pages use this to show a "Bypass active" badge
        # so the operator knows their next action will commit immediately.
        "bypass_active": _bypass_active,
        # Phase G — per-row drift badge lookup. Templates call
        # `smc_drift_state(href_or_name)` and render a small badge
        # ('drifted' / 'gone') beside the row. Returns None for clean
        # or untracked elements. Lazy + cached per request.
        "smc_drift_state": _smc_drift_state,
    }


def _to_be_deleted_set():
    """Lazily load the set of (href, name) flagged is_to_be_deleted in active Domain.

    Cached on `g` per request so a listing with N rows runs ONE query
    instead of N. Returns a set containing every href AND every name
    that's flagged — templates can call `is_smc_to_be_deleted(x)` with
    either identifier without knowing which.

    Falls through to the empty set when there's no active Domain or the
    SmcObject table isn't reachable yet (early-boot, JSON-fallback).
    """
    if hasattr(g, "_to_be_deleted_set"):
        return g._to_be_deleted_set
    flagged = set()
    try:
        domain = getattr(g, "domain", None)
        if domain is not None:
            from webapp.models import SmcObject
            rows = (SmcObject.query
                    .filter_by(domain_id=domain.id, is_to_be_deleted=True)
                    .with_entities(SmcObject.smc_href, SmcObject.smc_name)
                    .all())
            for href, name in rows:
                if href:
                    flagged.add(href)
                if name:
                    flagged.add(name)
    except Exception:
        # Non-fatal: fall through to empty set (no strikethrough rendered).
        pass
    g._to_be_deleted_set = flagged
    return flagged


def _is_smc_to_be_deleted(href_or_name):
    """Template helper — True when this SMC element has a queued delete pending."""
    if not href_or_name:
        return False
    return href_or_name in _to_be_deleted_set()


def _drift_state_map():
    """Lazily load the {href|name → drift_state} map for the active Domain.

    Returns ONE dict (cached on `g`) covering every non-clean SmcObject
    row, so listing pages can call `smc_drift_state(...)` per-row
    without re-querying.
    """
    if hasattr(g, "_drift_state_map"):
        return g._drift_state_map
    out: dict = {}
    try:
        domain = getattr(g, "domain", None)
        if domain is not None:
            from shared.smc_drift import drifted_keys_for_domain
            out = drifted_keys_for_domain(domain) or {}
    except Exception:
        out = {}
    g._drift_state_map = out
    return out


def _smc_drift_state(href_or_name):
    """Template helper — return 'drifted' / 'gone' / None for an SMC element.

    Pass either the smc_href or the smc_name (whichever the template has
    handy). Returns None for clean / untracked / unknown elements so
    templates can use `{% if smc_drift_state(x) %}` directly.
    """
    if not href_or_name:
        return None
    return _drift_state_map().get(href_or_name)


def _bypass_active(feature: str) -> bool:
    """Template helper — True iff the current user bypasses queue for `feature`.

    Cached on `g` per request: a listing page that calls this once is
    free to call it again on every row (memoized).
    """
    if not feature:
        return False
    cache = getattr(g, "_bypass_active_cache", None)
    if cache is None:
        cache = {}
        g._bypass_active_cache = cache
    if feature in cache:
        return cache[feature]
    try:
        from shared.queue_settings import should_bypass_queue
        cache[feature] = should_bypass_queue(feature)
    except Exception:
        cache[feature] = False
    return cache[feature]


def _bypass_push_migration_batch(bypass_feature: str, audit_feature: str,
                                 correlation_id: str, enqueued_count: int,
                                 import_log: dict) -> None:
    """Bypass-push a migration batch (objects / rules / NAT) inline.

    Shared helper for the migration import route. When per-user bypass
    is on for `bypass_feature` in the active Domain, this:
      1. Looks up every `pending_changes` row in the active Domain with
         `state='queued'` and `source_correlation_id=correlation_id`.
      2. Calls `push_batch` on the whole group (halt-on-failure per Q4).
      3. Deletes successfully-pushed rows and emits a per-row
         `<audit_feature>.<op>.bypass_queue` audit marker.
      4. Stamps `import_log` with `<audit_feature>_bypass_*` counters
         for the import-summary template.

    Failed rows stay so the operator can retry from `/changes/`.
    """
    if not correlation_id or enqueued_count <= 0:
        return
    try:
        from shared.queue_settings import should_bypass_queue
        if not should_bypass_queue(bypass_feature):
            return
    except Exception:
        return

    active_dom = getattr(g, "domain", None)
    if active_dom is None:
        return

    from shared.queue_runner import push_batch
    from webapp.models import PendingChange
    from shared.logging import audit

    batch_q = PendingChange.query.filter_by(
        domain_id=active_dom.id, state="queued", scope="main",
        source_correlation_id=correlation_id,
        feature_source="migration",
    )
    batch_ids = [r.id for r in batch_q.all()]
    if not batch_ids:
        return

    batch_result = push_batch(batch_ids)
    deleted = 0
    for cid in batch_ids:
        ch = db.session.get(PendingChange, cid)
        if ch is None:
            continue
        if ch.state in ("pushed", "applied"):
            try:
                audit(
                    feature=audit_feature,
                    action=f"{ch.operation}.bypass_queue",
                    target=f"#{cid}",
                    detail=("bypass_queue=True; queue row deleted on "
                            f"success (was change_id={cid})"),
                    source_correlation_id=correlation_id,
                    domain_id=ch.domain_id,
                )
            except Exception:
                pass
            db.session.delete(ch)
            deleted += 1
    db.session.commit()

    import_log[f"{audit_feature}_bypass_pushed"] = (
        batch_result.applied + batch_result.pushed
    )
    import_log[f"{audit_feature}_bypass_failed"] = batch_result.failed
    import_log[f"{audit_feature}_bypass_deleted"] = deleted
    import_log[f"{audit_feature}_bypass_active"] = True
    import_log["entries"].append({"level": "info", "msg": (
        f"{audit_feature} bypass mode — pushed inline: "
        f"applied={batch_result.applied + batch_result.pushed} "
        f"failed={batch_result.failed} "
        f"deleted_on_success={deleted}.")})


from shared.version import get_version
_build_version = get_version()


@app.template_filter("from_json")
def _jinja_from_json(value):
    """Parse a JSON string in templates. Returns {} on failure.

    Used by the Change Queue's expanded-detail panel to surface the
    `steps` array from bundle handlers (deploy_tls, install_ssh_rule).
    """
    if not value:
        return {}
    try:
        import json as _json
        return _json.loads(value)
    except Exception:
        return {}


@app.route("/version")
def version_info():
    """Return JSON build version — safe to hit unauthenticated for health checks."""
    from flask import jsonify
    return jsonify(_build_version)


# ═══════════════════════════════════════════════════════════════════════════
#  PROFILE & DOMAIN SELECTION
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/select-profile", methods=["GET", "POST"])
@login_required
def select_profile():
    """Let the user choose which SMC API profile (= Domain) to use.

    Phase B.3 simplification: each profile dict already carries the SMC
    admin-domain name (Domain.smc_domain_name), so we set both
    `active_profile` AND `active_domain` here in one shot — no need for
    the user to walk through /select-domain (which fetches the live SMC
    domain list and was a leftover from the pre-revamp two-step flow).
    """
    email = session["user"]["email"]
    profiles = user_manager.get_user_profiles(email)

    if request.method == "POST":
        idx = request.form.get("profile_index", type=int)
        if idx is None or idx < 0 or idx >= len(profiles):
            flash("Invalid profile selection.", "danger")
            return render_template("auth/select_profile.html", profiles=profiles)
        chosen = profiles[idx]
        session["active_profile"] = chosen
        # Auto-set active_domain from the Domain's pinned smc_domain_name.
        # Falls back to "Shared Domain" if somehow blank — old JSON-fallback
        # profiles may not carry the field.
        session["active_domain"] = (chosen.get("domain") or "").strip() or "Shared Domain"
        log.info(
            "User %s selected profile '%s' (smc-domain '%s')",
            email, chosen.get("name"), session["active_domain"],
        )
        return redirect(url_for("index"))

    return render_template("auth/select_profile.html", profiles=profiles)


@app.route("/switch-domain", methods=["POST"])
@login_required
def switch_domain():
    """Topbar Domain switcher endpoint.

    Reloads the same `(active_profile, active_domain)` shape that
    `/select-profile` POST uses, but accepts a slug of any Domain the
    logged-in user has UserDomainAccess for. Drops the SMC read cache so
    the next page load fetches against the new Domain's API key.
    Bounces back to the referring page (or `/` if none).
    """
    slug = (request.form.get("slug") or "").strip()
    if not slug:
        flash("Pick a Domain to switch to.", "warning")
        return redirect(request.referrer or url_for("index"))

    email = session["user"]["email"]
    profiles = user_manager.get_user_profiles(email)
    chosen = next((p for p in profiles if p.get("tenant") == slug), None)
    if chosen is None:
        log.warning("User %s tried to switch to Domain slug '%s' "
                    "they don't have access to", email, slug)
        flash("You do not have access to that Domain.", "danger")
        return redirect(request.referrer or url_for("index"))

    session["active_profile"] = chosen
    session["active_domain"] = (chosen.get("domain") or "").strip() or "Shared Domain"

    # Cached SMC reads belonged to the previous Domain — drop everything.
    try:
        from shared.smc_cache import invalidate_all
        invalidate_all()
    except Exception:
        pass

    log.info("User %s switched to Domain '%s' (smc-domain '%s')",
             email, chosen.get("name"), session["active_domain"])
    flash(f"Switched to {chosen.get('name')}.", "success")
    return redirect(request.referrer or url_for("index"))


@app.route("/select-domain", methods=["GET", "POST"])
@login_required
def select_domain():
    """LEGACY fallback after the Multi-Domain Revamp.

    Today's `/select-profile` already sets `session["active_domain"]`
    from the picked Domain's pinned `smc_domain_name`, so this page is
    only reached if:
      * the user typed the URL manually, or
      * a legacy JSON-fallback profile resolved without a smc-domain.

    Kept routable for those edge cases. The fetched list is whatever
    SMC returns for the API key's actual permissions — no FlexEdge-side
    cache.
    """
    if "active_profile" not in session:
        flash("Select a profile first.", "warning")
        return redirect(url_for("select_profile"))

    profile = session["active_profile"]
    domains = []
    error = None

    if request.method == "POST":
        chosen = request.form.get("domain", "").strip()
        if not chosen:
            flash("Please select a domain.", "warning")
        else:
            session["active_domain"] = chosen
            log.info(
                "User %s selected domain '%s' on profile '%s'",
                session["user"]["email"], chosen, profile["name"],
            )
            return redirect(url_for("index"))

    # Fetch domain list from SMC
    try:
        cfg = {
            "smc_url":    profile["smc_url"],
            "api_key":    profile["api_key"],
            "verify_ssl": profile.get("verify_ssl", False),
            "timeout":    profile.get("timeout", 60),
        }
        domains = smc_client.list_domains(cfg)
    except Exception as exc:
        log.error("Could not fetch domains: %s", exc)
        error = str(exc)
        domains = [{"name": "Shared Domain", "href": ""}]

    return render_template(
        "auth/select_domain.html",
        profile=profile,
        domains=domains,
        error=error,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  SMC EXPLORER ROUTES  (read-only — require profile + domain)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
@profile_required
def index():
    """Dashboard — connection info and element type menu."""
    return render_template("index.html")


@app.route("/browse/<type_key>")
@profile_required
def browse(type_key):
    """List all elements of a given type."""
    if type_key not in smc_client.ELEMENT_TYPES:
        return redirect(url_for("index"))
    filter_text = request.args.get("q", "").strip()
    fgt_only = request.args.get("fgt", "0") == "1"
    label = smc_client.ELEMENT_TYPES[type_key]["label"]
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            elements = smc_client.list_elements(type_key, filter_text, fgt_only)
    except Exception as e:
        log.error("SMC connection error: %s", e)
        return render_template("error.html", message=str(e))
    return render_template(
        "browse.html", type_key=type_key, label=label,
        elements=elements, filter_text=filter_text,
        fgt_only=fgt_only, count=len(elements),
    )


@app.route("/detail/<type_key>/<path:element_name>")
@profile_required
def detail(type_key, element_name):
    """Show full detail for a single element."""
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            data = smc_client.get_element_detail(type_key, element_name)
    except Exception as e:
        return render_template("error.html", message=str(e))
    label = smc_client.ELEMENT_TYPES.get(type_key, {}).get("label", type_key)
    return render_template("detail.html", type_key=type_key, label=label, element=data)


@app.route("/policies")
@profile_required
def policies():
    """List all firewall policies."""
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            policy_list = smc_client.list_policies()
    except Exception as e:
        return render_template("error.html", message=str(e))
    return render_template("policies.html", policies=policy_list)


@app.route("/policy/<path:policy_name>")
@profile_required
def policy_rules(policy_name):
    """Show all rules in a firewall policy."""
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            rules = smc_client.get_policy_rules(policy_name)
    except Exception as e:
        return render_template("error.html", message=str(e))
    sections = [r for r in rules if r.get("is_section")]
    access_rules = [r for r in rules if not r.get("is_section")]
    disabled = [r for r in access_rules if r.get("is_disabled")]
    return render_template(
        "policy_rules.html", policy_name=policy_name,
        rules=rules, total_rules=len(access_rules),
        total_sections=len(sections), disabled_count=len(disabled),
    )


# ── JSON API (read-only) ────────────────────────────────────────────────

@app.route("/api/elements/<type_key>")
@profile_required
def api_elements(type_key):
    filter_text = request.args.get("q", "").strip()
    fgt_only = request.args.get("fgt", "0") == "1"
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            elements = smc_client.list_elements(type_key, filter_text, fgt_only)
        return jsonify({"status": "ok", "type": type_key, "count": len(elements), "elements": elements})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/policy/<path:policy_name>/rules")
@profile_required
def api_policy_rules(policy_name):
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            rules = smc_client.get_policy_rules(policy_name)
        return jsonify({"status": "ok", "policy": policy_name, "rules": rules})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
#  MIGRATION ROUTES  (require login; use project-stored target, not session cfg)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/migration/")
@login_required
def migration_projects():
    """List all migration projects."""
    projects = project_manager.list_projects()
    return render_template("migration/projects.html", projects=projects)


@app.route("/migration/new", methods=["GET", "POST"])
@login_required
def migration_new():
    """Create a new migration project from a FortiGate config file."""
    if request.method == "GET":
        return render_template("migration/new_project.html")

    name = request.form.get("name", "").strip()
    file = request.files.get("config_file")

    if not name:
        flash("Project name is required.", "danger")
        return render_template("migration/new_project.html")
    if not file or not file.filename:
        flash("Please upload a FortiGate .conf file.", "danger")
        return render_template("migration/new_project.html")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".conf") as tmp:
        file.save(tmp.name)
        project = project_manager.create_project(name, tmp.name, file.filename)

    try:
        source_path = project_manager.get_source_path(project["id"])
        parsed = fgt_parser.parse_fortigate_config(str(source_path))
        project_manager.save_parsed_objects(project["id"], parsed)
        project_manager.update_project(project["id"], {
            "status": "parsed",
            "source_hostname": parsed.get("hostname", ""),
            "stats": parsed.get("stats", {}),
        })
        flash(f"Project '{name}' created and config parsed successfully.", "success")
    except Exception as e:
        project_manager.update_project(project["id"], {"status": "error", "error": str(e)})
        flash(f"Config parsing failed: {e}", "danger")

    return redirect(url_for("migration_parsed", project_id=project["id"]))


@app.route("/migration/<project_id>/parsed")
@login_required
def migration_parsed(project_id):
    """View parsed objects from the FortiGate config."""
    project = project_manager.get_project(project_id)
    if not project:
        flash("Project not found.", "danger")
        return redirect(url_for("migration_projects"))
    parsed = project_manager.get_parsed_objects(project_id)
    if not parsed:
        flash("Config not yet parsed.", "warning")
        return redirect(url_for("migration_projects"))
    tab = request.args.get("tab", "policies")
    return render_template("migration/parsed.html", project=project, parsed=parsed, tab=tab)


@app.route("/migration/<project_id>/target", methods=["GET", "POST"])
@login_required
def migration_target(project_id):
    """Configure SMC target for migration."""
    project = project_manager.get_project(project_id)
    if not project:
        flash("Project not found.", "danger")
        return redirect(url_for("migration_projects"))

    if request.method == "POST":
        target = {
            "smc_url":       request.form.get("smc_url", "").strip(),
            "api_key":       request.form.get("api_key", "").strip(),
            "domain":        request.form.get("domain", "").strip(),
            "verify_ssl":    request.form.get("verify_ssl") == "on",
            "policy_name":   request.form.get("policy_name", "").strip(),
            "object_prefix": request.form.get("object_prefix", "FGT-").strip(),
        }
        project_manager.update_project(project_id, {"target": target})
        flash("Target configuration saved.", "success")
        return redirect(url_for("migration_dedup", project_id=project_id))

    # Pre-populate from saved target, then fall back to the session profile
    target = project.get("target", {})
    if not target.get("smc_url"):
        profile = session.get("active_profile", {})
        target = {
            "smc_url":       profile.get("smc_url", ""),
            "api_key":       profile.get("api_key", ""),
            "domain":        session.get("active_domain", ""),
            "verify_ssl":    profile.get("verify_ssl", False),
            "policy_name":   "Migration from Fortinet",
            "object_prefix": "FGT-",
        }
    return render_template(
        "migration/target_config.html", project=project, target=target,
    )


@app.route("/migration/<project_id>/dhcp-map", methods=["GET", "POST"])
@login_required
def migration_dhcp_map(project_id):
    """Map FortiGate DHCP servers to target SMC scopes.

    Phase B of the FortiGate DHCP migration: persists a mapping
    ``{ fg_server_id: target_scope_id | "skip" }`` into the project's
    ``target.dhcp_mappings`` dict. Phase D's importer reads this when
    creating SMC Hosts and DhcpReservation rows.

    The page is opt-in (operator hits it from the parsed-objects DHCP
    tab) — no DHCP servers means the wizard goes straight from target
    config to dedup as before.
    """
    from webapp.dhcp_readiness import find_tenant_for_target, list_scope_options

    project = project_manager.get_project(project_id)
    if not project:
        flash("Project not found.", "danger")
        return redirect(url_for("migration_projects"))

    parsed = project_manager.get_parsed_objects(project_id)
    if not parsed:
        flash("Config not yet parsed.", "warning")
        return redirect(url_for("migration_projects"))

    fg_servers = parsed.get("dhcp_servers", [])
    if not fg_servers:
        flash("No DHCP servers in this configuration — nothing to map.", "info")
        return redirect(url_for("migration_parsed",
                                project_id=project_id, tab="dhcp"))

    target = project.get("target") or {}

    if request.method == "POST":
        new_mappings = {}
        for srv in fg_servers:
            field = f"map_{srv['id']}"
            value = request.form.get(field, "").strip()
            if not value or value == "skip":
                new_mappings[str(srv["id"])] = "skip"
            else:
                # Coerce scope_id to int; reject unknown
                try:
                    new_mappings[str(srv["id"])] = int(value)
                except ValueError:
                    new_mappings[str(srv["id"])] = "skip"
        target["dhcp_mappings"] = new_mappings
        project_manager.update_project(project_id, {"target": target})
        flash(
            f"DHCP mapping saved ({sum(1 for v in new_mappings.values() if v != 'skip')} "
            f"of {len(fg_servers)} FG scopes mapped).",
            "success",
        )
        # Continue to dedup — the migration wizard's natural next step
        return redirect(url_for("migration_dedup", project_id=project_id))

    # GET: build the form data
    tenant = find_tenant_for_target(target)
    if tenant is None and target.get("smc_url") and target.get("api_key"):
        # Make the empty scope list explainable to the operator.
        flash(
            "Could not resolve this migration project's SMC URL + API key "
            "to a single tenant. Check Admin Portal: either no tenant "
            "exists for this SMC URL, or multiple tenants share it and "
            "none owns the matching API key. Add or update the tenant "
            "and re-open this page.",
            "warning",
        )
    scope_options = list_scope_options(tenant) if tenant else []
    saved_mappings = (target.get("dhcp_mappings") or {})

    return render_template(
        "migration/dhcp_map.html",
        project=project,
        fg_servers=fg_servers,
        scope_options=scope_options,
        saved_mappings=saved_mappings,
        tenant=tenant,
        target=target,
    )


@app.route("/migration/<project_id>/dedup")
@login_required
def migration_dedup(project_id):
    """Run deduplication and show results."""
    project = project_manager.get_project(project_id)
    if not project:
        flash("Project not found.", "danger")
        return redirect(url_for("migration_projects"))
    parsed = project_manager.get_parsed_objects(project_id)
    if not parsed:
        flash("Config not yet parsed.", "warning")
        return redirect(url_for("migration_parsed", project_id=project_id))

    force = request.args.get("force", "0") == "1"
    dedup = project_manager.get_dedup_results(project_id)

    if not dedup or force:
        target = project.get("target", {})
        if not target.get("smc_url"):
            flash("Configure SMC target first.", "warning")
            return redirect(url_for("migration_target", project_id=project_id))
        cfg = {
            "smc_url":       target["smc_url"],
            "api_key":       target["api_key"],
            "domain":        target.get("domain"),
            "verify_ssl":    target.get("verify_ssl", False),
            "timeout":       120,
            "retry_on_busy": True,
        }
        try:
            import dedup_engine
            dedup = dedup_engine.run_dedup(parsed, cfg, target_dict=target)
            project_manager.save_dedup_results(project_id, dedup)
            project_manager.update_project(project_id, {"status": "validated"})
            flash("Deduplication analysis complete.", "success")
        except Exception as e:
            flash(f"Deduplication failed: {e}", "danger")
            return render_template(
                "migration/dedup.html",
                project=project, dedup=None, error=str(e),
            )

    dedup_stats = {}
    for category in ("addresses", "services", "address_groups", "service_groups", "nat_hosts"):
        items = dedup.get(category, [])
        dedup_stats[category] = {
            "total":  len(items),
            "create": sum(1 for i in items if i["action"] == "create"),
            "reuse":  sum(1 for i in items if i["action"] == "reuse"),
            "skip":   sum(1 for i in items if i["action"] == "skip"),
        }

    # DHCP reservations have a different shape (nested per FG scope) — compute
    # dedicated stats so the UI's stat-card row stays balanced.
    dhcp_entries = dedup.get("dhcp_reservations", []) or []
    dhcp_total_reservations = sum(len(e.get("reservations", [])) for e in dhcp_entries)
    dhcp_selected = sum(1 for e in dhcp_entries
                        for r in e.get("reservations", []) if r.get("selected"))
    dhcp_conflicts = sum(1 for e in dhcp_entries
                         for r in e.get("reservations", [])
                         if r.get("match_type") in ("mac_conflict", "ip_conflict"))
    dedup_stats["dhcp_reservations"] = {
        "total": dhcp_total_reservations,
        "create": dhcp_selected,
        "reuse": sum(1 for e in dhcp_entries
                     for r in e.get("reservations", [])
                     if r.get("match_type") == "already_migrated"),
        "skip": dhcp_conflicts,
    }

    tab = request.args.get("tab", "addresses")
    return render_template(
        "migration/dedup.html",
        project=project, dedup=dedup, dedup_stats=dedup_stats, tab=tab,
    )


@app.route("/migration/<project_id>/dedup/update", methods=["POST"])
@login_required
def migration_dedup_update(project_id):
    """Update dedup action for a specific object (AJAX)."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data"}), 400
    category   = data.get("category")
    parsed_name = data.get("parsed_name")
    new_action  = data.get("action")
    if not all([category, parsed_name, new_action]):
        return jsonify({"status": "error", "message": "Missing fields"}), 400
    dedup = project_manager.get_dedup_results(project_id)
    if not dedup:
        return jsonify({"status": "error", "message": "No dedup results"}), 404
    key_field = "ip" if category == "nat_hosts" else "parsed_name"
    for entry in dedup.get(category, []):
        if entry.get(key_field) == parsed_name:
            entry["action"] = new_action
            break
    project_manager.save_dedup_results(project_id, dedup)
    return jsonify({"status": "ok"})


@app.route("/migration/<project_id>/dhcp/update", methods=["POST"])
@login_required
def migration_dhcp_update(project_id):
    """Toggle DHCP-reservation selection (AJAX).

    Body: {fg_server_id: <int>, fg_res_id: <str>, selected: <bool>,
           action?: <str>}
    Optional ``action`` lets the operator flip a conflict to
    ``conflict_overwrite`` (so the importer treats it as an explicit
    overwrite of the existing Host) — UI button does this in one click.
    """
    data = request.get_json() or {}
    fg_server_id = data.get("fg_server_id")
    fg_res_id    = str(data.get("fg_res_id", ""))
    new_selected = bool(data.get("selected"))
    new_action   = data.get("action")
    if fg_server_id is None or not fg_res_id:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    dedup = project_manager.get_dedup_results(project_id)
    if not dedup:
        return jsonify({"status": "error", "message": "No dedup results"}), 404

    found = False
    for entry in dedup.get("dhcp_reservations", []):
        if str(entry.get("fg_server_id")) != str(fg_server_id):
            continue
        for r in entry.get("reservations", []):
            if str(r.get("fg_id", "")) == fg_res_id:
                r["selected"] = new_selected
                if new_action:
                    r["action"] = new_action
                found = True
                break
        if found:
            break

    if not found:
        return jsonify({"status": "error", "message": "Reservation not found"}), 404

    project_manager.save_dedup_results(project_id, dedup)
    return jsonify({"status": "ok"})


@app.route("/migration/<project_id>/rules")
@login_required
def migration_rules(project_id):
    """View converted rules and select which to import."""
    project = project_manager.get_project(project_id)
    if not project:
        flash("Project not found.", "danger")
        return redirect(url_for("migration_projects"))
    parsed = project_manager.get_parsed_objects(project_id)
    dedup  = project_manager.get_dedup_results(project_id)
    if not parsed or not dedup:
        flash("Run deduplication first.", "warning")
        return redirect(url_for("migration_dedup", project_id=project_id))

    force = request.args.get("force", "0") == "1"
    converted = project_manager.get_converted_rules(project_id)
    if not converted or force:
        try:
            import rule_converter
            converted = rule_converter.convert_policies(parsed, dedup)
            if parsed.get("vpn_tunnels"):
                vpn_result = rule_converter.convert_vpn_tunnels(parsed, dedup)
                converted["vpn_configs"] = vpn_result.get("vpn_configs", [])
                converted["vpn_stats"]   = vpn_result.get("stats", {})
            project_manager.save_converted_rules(project_id, converted)
            project_manager.update_project(project_id, {"status": "ready"})
        except Exception as e:
            flash(f"Rule conversion failed: {e}", "danger")
            return redirect(url_for("migration_dedup", project_id=project_id))
    return render_template("migration/rules.html", project=project, converted=converted)


@app.route("/migration/<project_id>/rules/update", methods=["POST"])
@login_required
def migration_rules_update(project_id):
    """Update rule selection (AJAX)."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data"}), 400
    converted = project_manager.get_converted_rules(project_id)
    if not converted:
        return jsonify({"status": "error", "message": "No converted rules"}), 404
    selections = data.get("selections", {})
    for section in converted.get("sections", []):
        for rule in section.get("rules", []):
            fgt_id_str = str(rule["fgt_id"])
            if fgt_id_str in selections:
                rule["selected"] = selections[fgt_id_str]
    project_manager.save_converted_rules(project_id, converted)
    return jsonify({"status": "ok"})


@app.route("/migration/<project_id>/nat-rules/update", methods=["POST"])
@login_required
def migration_nat_rules_update(project_id):
    """Update NAT rule selection (AJAX)."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data"}), 400
    converted = project_manager.get_converted_rules(project_id)
    if not converted:
        return jsonify({"status": "error", "message": "No converted rules"}), 404
    selections = data.get("selections", {})
    for rule in converted.get("nat_rules", []):
        fgt_id_str = str(rule["fgt_id"])
        if fgt_id_str in selections:
            rule["selected"] = selections[fgt_id_str]
    project_manager.save_converted_rules(project_id, converted)
    return jsonify({"status": "ok"})


@app.route("/migration/<project_id>/vpn/update", methods=["POST"])
@login_required
def migration_vpn_update(project_id):
    """Update VPN tunnel selection (AJAX)."""
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data"}), 400
    converted = project_manager.get_converted_rules(project_id)
    if not converted:
        return jsonify({"status": "error", "message": "No converted rules"}), 404
    selections = data.get("selections", {})
    for vpn in converted.get("vpn_configs", []):
        if vpn["name"] in selections:
            vpn["selected"] = selections[vpn["name"]]
    project_manager.save_converted_rules(project_id, converted)
    return jsonify({"status": "ok"})


@app.route("/migration/<project_id>/import", methods=["GET", "POST"])
@login_required
def migration_import(project_id):
    """Import execution page."""
    project = project_manager.get_project(project_id)
    if not project:
        flash("Project not found.", "danger")
        return redirect(url_for("migration_projects"))

    if request.method == "POST":
        import_type = request.form.get("import_type", "all")
        # Opt-in policy install on the engine after the rules are created.
        # Default OFF (matches the project safety constraint
        # "Never push policy to engine without review"). When ticked, we
        # call Engine(...).upload(policy=...) right after the import loop
        # so the new rules become live without an extra trip to SMC GUI.
        auto_install_policy = request.form.get("auto_install_policy") == "on"
        target = project.get("target", {})
        if not target.get("smc_url"):
            flash("Configure SMC target first.", "warning")
            return redirect(url_for("migration_target", project_id=project_id))
        cfg = {
            "smc_url":       target["smc_url"],
            "api_key":       target["api_key"],
            "domain":        target.get("domain"),
            "verify_ssl":    target.get("verify_ssl", False),
            "timeout":       120,
            "retry_on_busy": True,
        }
        parsed    = project_manager.get_parsed_objects(project_id)
        dedup     = project_manager.get_dedup_results(project_id)
        converted = project_manager.get_converted_rules(project_id)
        import_log = {
            "entries": [],
            "objects_created": 0, "objects_skipped": 0, "objects_errors": 0,
            "rules_created": 0, "rules_errors": 0,
            "nat_created": 0, "nat_errors": 0,
            "vpn_profiles": 0, "vpn_gateways": 0, "vpn_policies": 0, "vpn_errors": 0,
            "dhcp_scopes_processed": 0, "dhcp_scopes_skipped": 0,
            "dhcp_reservations_created": 0, "dhcp_reservations_updated": 0,
            "dhcp_reservations_skipped": 0, "dhcp_reservations_errors": 0,
            "policy_install_status": "not_requested",   # not_requested | ok | failed | skipped
            "policy_install_message": "",
            "status": "running",
        }
        try:
            import smc_writer
            if import_type in ("all", "objects") and parsed and dedup:
                # Phase E.2 (Q20) — objects go through the queue with
                # `migration_object_writer.enqueue_object_imports`. The
                # legacy SMC-direct `smc_writer.create_objects` is no
                # longer called for the import path. Rules / NAT / VPN
                # below still use smc_writer.* until those convert.
                from webapp.migration_object_writer import (
                    enqueue_object_imports,
                )
                obj_result = enqueue_object_imports(
                    parsed, dedup, getattr(g, "domain", None), project_id,
                )
                import_log["entries"].extend(obj_result.get("entries", []))
                import_log["objects_created"] = obj_result.get("objects_created", 0)
                import_log["objects_skipped"] = obj_result.get("objects_skipped", 0)
                import_log["objects_errors"]  = obj_result.get("objects_errors", 0)
                # Surface the queue correlation id so the import-summary
                # template can show the same "Open Change Queue" CTA the
                # DHCP path already uses, AND reuse the bypass-mode path
                # below so admins-with-bypass push immediately.
                import_log["objects_changes_enqueued"] = obj_result.get("changes_enqueued", 0)
                import_log["objects_correlation_id"]   = obj_result.get("correlation_id", "")
                import_log["objects_by_type"]          = obj_result.get("by_type", {})

                # Bypass mode (per-user, per-domain on `migration_object`):
                # immediately push the whole batch + delete successful
                # rows. Failed rows stay so the operator can retry from
                # /changes/. Same pattern as `migration_dhcp` below.
                try:
                    from shared.queue_settings import should_bypass_queue
                    is_bypass_obj = should_bypass_queue("migration_object")
                except Exception:
                    is_bypass_obj = False
                obj_corr = obj_result.get("correlation_id", "")
                if is_bypass_obj and obj_corr and obj_result.get("changes_enqueued", 0) > 0:
                    from shared.queue_runner import push_batch
                    from webapp.models import PendingChange
                    from shared.logging import audit
                    active_dom = getattr(g, "domain", None)
                    if active_dom is not None:
                        # Only push the OBJECT rows in this batch — the
                        # DHCP rows (if any) get their own bypass check
                        # below. Objects use feature_source='migration'.
                        batch_q = PendingChange.query.filter_by(
                            domain_id=active_dom.id, state="queued",
                            scope="main",
                            source_correlation_id=obj_corr,
                            feature_source="migration",
                        )
                        batch_ids = [r.id for r in batch_q.all()]
                        if batch_ids:
                            batch_result = push_batch(batch_ids)
                            deleted = 0
                            for cid in batch_ids:
                                ch = db.session.get(PendingChange, cid)
                                if ch is None:
                                    continue
                                if ch.state in ("pushed", "applied"):
                                    try:
                                        audit(
                                            feature="migration_object",
                                            action=f"{ch.operation}.bypass_queue",
                                            target=f"#{cid}",
                                            detail=("bypass_queue=True; queue "
                                                    "row deleted on success "
                                                    f"(was change_id={cid})"),
                                            source_correlation_id=obj_corr,
                                            domain_id=ch.domain_id,
                                        )
                                    except Exception:
                                        pass
                                    db.session.delete(ch)
                                    deleted += 1
                            db.session.commit()
                            import_log["objects_bypass_pushed"] = (
                                batch_result.applied + batch_result.pushed
                            )
                            import_log["objects_bypass_failed"] = batch_result.failed
                            import_log["objects_bypass_deleted"] = deleted
                            import_log["objects_bypass_active"] = True
                            import_log["entries"].append({"level": "info", "msg": (
                                f"Object bypass mode — pushed inline: "
                                f"applied={batch_result.applied + batch_result.pushed} "
                                f"failed={batch_result.failed} "
                                f"deleted_on_success={deleted}.")})
            if import_type in ("all", "rules") and converted:
                # Phase E.2 — rules go through the queue. Sections enqueue
                # before their rules; the natural created_at order ensures
                # objects (already enqueued above) push first.
                from webapp.migration_rule_writer import enqueue_rule_imports
                policy_name = target.get("policy_name", "Migration from Fortinet")
                rule_result = enqueue_rule_imports(
                    converted, getattr(g, "domain", None), project_id,
                    policy_name,
                )
                import_log["entries"].extend(rule_result.get("entries", []))
                import_log["rules_created"] = rule_result.get("rules_created", 0)
                import_log["rules_errors"]  = rule_result.get("rules_errors", 0)
                import_log["sections_created"] = rule_result.get("sections_created", 0)
                import_log["rules_changes_enqueued"] = rule_result.get("changes_enqueued", 0)
                import_log["rules_correlation_id"]   = rule_result.get("correlation_id", "")
                _bypass_push_migration_batch(
                    "migration_rule", "rule",
                    rule_result.get("correlation_id", ""),
                    rule_result.get("changes_enqueued", 0),
                    import_log,
                )
            if import_type in ("all", "nat") and converted and dedup:
                # Phase E.2 — NAT rules go through the queue. Pre-resolves
                # IPs → SMC Host names from the dedup map at enqueue time.
                from webapp.migration_rule_writer import enqueue_nat_rule_imports
                policy_name = target.get("policy_name", "Migration from Fortinet")
                nat_result  = enqueue_nat_rule_imports(
                    converted, dedup, getattr(g, "domain", None), project_id,
                    policy_name,
                )
                import_log["entries"].extend(nat_result.get("entries", []))
                import_log["nat_created"] = nat_result.get("nat_created", 0)
                import_log["nat_errors"]  = nat_result.get("nat_errors", 0)
                import_log["nat_changes_enqueued"] = nat_result.get("changes_enqueued", 0)
                import_log["nat_correlation_id"]   = nat_result.get("correlation_id", "")
                _bypass_push_migration_batch(
                    "migration_nat", "nat_rule",
                    nat_result.get("correlation_id", ""),
                    nat_result.get("changes_enqueued", 0),
                    import_log,
                )
            if import_type in ("all", "vpn") and converted and converted.get("vpn_configs"):
                # Phase E.2 — VPN goes through the queue. ONE row per
                # VPN config; the bundle handler runs the 6-step
                # pipeline (profile / gateway / endpoint / site /
                # PolicyVPN / topology) inside the queue runner's SMC
                # session. Last remaining migration tier converted.
                from webapp.migration_vpn_writer import enqueue_vpn_imports
                engine_name = target.get("engine_name")
                vpn_result  = enqueue_vpn_imports(
                    converted, getattr(g, "domain", None),
                    project_id, engine_name,
                )
                import_log["entries"].extend(vpn_result.get("entries", []))
                import_log["vpn_profiles"] = vpn_result.get("vpn_profiles", 0)
                import_log["vpn_gateways"] = vpn_result.get("gateways", 0)
                import_log["vpn_policies"] = vpn_result.get("vpn_policies", 0)
                import_log["vpn_errors"]   = vpn_result.get("vpn_errors", 0)
                import_log["vpn_changes_enqueued"] = vpn_result.get("changes_enqueued", 0)
                import_log["vpn_correlation_id"]   = vpn_result.get("correlation_id", "")
                _bypass_push_migration_batch(
                    "migration_vpn", "vpn",
                    vpn_result.get("correlation_id", ""),
                    vpn_result.get("changes_enqueued", 0),
                    import_log,
                )

            # DHCP migration — Phase E.2 (Q20): writer now ENQUEUES instead
            # of calling SMC directly. The summary still surfaces the same
            # counts; operators visit /changes/?source=migration:<id> to
            # push the staged batch.
            if (import_type in ("all", "dhcp")
                    and parsed and parsed.get("dhcp_servers")
                    and dedup and dedup.get("dhcp_reservations")):
                from migration_dhcp_writer import import_dhcp_reservations
                dhcp_result = import_dhcp_reservations(
                    parsed, dedup, target, project_id,
                )
                import_log["entries"].extend(dhcp_result.get("entries", []))
                import_log["dhcp_scopes_processed"]      = dhcp_result.get("scopes_processed", 0)
                import_log["dhcp_scopes_skipped"]        = dhcp_result.get("scopes_skipped", 0)
                import_log["dhcp_reservations_created"]  = dhcp_result.get("reservations_created", 0)
                import_log["dhcp_reservations_updated"]  = dhcp_result.get("reservations_updated", 0)
                import_log["dhcp_reservations_skipped"]  = dhcp_result.get("reservations_skipped", 0)
                import_log["dhcp_reservations_errors"]   = dhcp_result.get("reservations_errors", 0)
                # Phase E.2 — surface the queue correlation id so the
                # import-summary template can render a "Visit Change Queue"
                # CTA pointing at /changes/?source=<corr>.
                import_log["dhcp_changes_enqueued"] = dhcp_result.get("changes_enqueued", 0)
                import_log["dhcp_correlation_id"]   = dhcp_result.get("correlation_id", "")

                # Bypass mode (per-user, per-domain on `migration_dhcp`):
                # immediately push the whole batch + delete successful
                # rows + emit `*.bypass_queue` audit markers. Failed rows
                # stay so the operator can retry from /changes/.
                try:
                    from shared.queue_settings import should_bypass_queue
                    is_bypass_mig = should_bypass_queue("migration_dhcp")
                except Exception:
                    is_bypass_mig = False
                corr = dhcp_result.get("correlation_id", "")
                if is_bypass_mig and corr:
                    from shared.queue_runner import push_all_for_domain
                    from webapp.models import PendingChange
                    from shared.logging import audit
                    # Find every queued change in this batch (filter by
                    # correlation id explicitly so we don't push other
                    # rows from concurrent activity).
                    batch_q = PendingChange.query.filter_by(
                        domain_id=getattr(g, "domain", None).id,
                        state="queued", scope="main",
                        source_correlation_id=corr,
                    )
                    batch_ids = [r.id for r in batch_q.all()]
                    if batch_ids:
                        from shared.queue_runner import push_batch
                        batch_result = push_batch(batch_ids)
                        # Sweep DB rows for successfully pushed changes.
                        deleted = 0
                        for cid in batch_ids:
                            ch = db.session.get(PendingChange, cid)
                            if ch is None:
                                continue
                            if ch.state in ("pushed", "applied"):
                                try:
                                    audit(
                                        feature="migration_dhcp",
                                        action=f"{ch.operation}.bypass_queue",
                                        target=f"#{cid}",
                                        detail=("bypass_queue=True; queue "
                                                "row deleted on success "
                                                f"(was change_id={cid})"),
                                        source_correlation_id=corr,
                                        domain_id=ch.domain_id,
                                    )
                                except Exception:
                                    pass
                                db.session.delete(ch)
                                deleted += 1
                        db.session.commit()
                        import_log["dhcp_bypass_pushed"] = (
                            batch_result.applied + batch_result.pushed
                        )
                        import_log["dhcp_bypass_failed"] = batch_result.failed
                        import_log["dhcp_bypass_deleted"] = deleted
                        import_log["dhcp_bypass_active"] = True
                        import_log["entries"].append({"level": "info", "msg": (
                            f"DHCP bypass mode — pushed inline: "
                            f"applied={batch_result.applied + batch_result.pushed} "
                            f"failed={batch_result.failed} "
                            f"deleted_on_success={deleted}.")})

            import_log["status"] = "done"

            # ── Two-step push: optional policy install on the engine ────
            # Up to here we've created rules / NAT / VPN config in the SMC
            # POLICY DATABASE — but the engine is still running its old
            # policy. To activate the new rules the policy must be
            # installed on the engine. Safety-first: only do it if the
            # operator opted in via the checkbox.
            policy_name = target.get("policy_name", "Migration from Fortinet")
            engine_name = target.get("engine_name") or ""
            mutated_rules = (import_log["rules_created"] > 0
                             or import_log["nat_created"] > 0)

            if auto_install_policy:
                if not engine_name:
                    import_log["policy_install_status"] = "skipped"
                    import_log["policy_install_message"] = (
                        "Auto-install was requested but no engine_name is "
                        "configured for this project."
                    )
                    import_log["entries"].append({
                        "level": "warning",
                        "msg": ("⚠ Policy install SKIPPED — no engine_name "
                                "in target config. Install manually via SMC "
                                "Management Client."),
                    })
                elif not mutated_rules:
                    import_log["policy_install_status"] = "skipped"
                    import_log["policy_install_message"] = (
                        "Auto-install was requested but no rules / NAT were "
                        "created in this run, so an install would be a no-op."
                    )
                    import_log["entries"].append({
                        "level": "info",
                        "msg": ("ℹ Policy install skipped — no rule changes "
                                "were made in this import."),
                    })
                else:
                    try:
                        from smc_tls_client import policy_upload
                        with smc_client.smc_session(cfg):
                            upload_msg = policy_upload(engine_name, policy_name)
                        import_log["policy_install_status"] = "ok"
                        import_log["policy_install_message"] = str(upload_msg)
                        import_log["entries"].append({
                            "level": "info",
                            "msg": (f"✓ Policy '{policy_name}' installed on engine "
                                    f"'{engine_name}'. Rules are now LIVE."),
                        })
                    except Exception as exc:
                        import_log["policy_install_status"] = "failed"
                        import_log["policy_install_message"] = str(exc)
                        import_log["entries"].append({
                            "level": "error",
                            "msg": (f"✗ Policy install on '{engine_name}' FAILED: "
                                    f"{exc}. Rules ARE in the policy database "
                                    f"but the engine is still running the old "
                                    f"policy. Fix and retry, or install manually "
                                    f"via SMC Management Client."),
                        })
            else:
                # Operator did NOT tick auto-install: tell them clearly
                # what to do next so they don't think the import "didn't
                # work" when they look at the engine.
                if mutated_rules:
                    import_log["entries"].append({
                        "level": "warning",
                        "msg": (f"NEXT STEP: open SMC Management Client → "
                                f"policy '{policy_name}' → right-click → "
                                f"'Install Policy' on engine "
                                f"'{engine_name or '<configure target engine first>'}' "
                                f"to activate the {import_log['rules_created']} "
                                f"new rule(s). Until you do, the engine is "
                                f"still running its previous policy."),
                    })

            project_manager.update_project(project_id, {"status": "imported"})

            # Flash message: differentiate the three outcomes so the
            # operator knows whether the engine is live yet.
            install_state = import_log["policy_install_status"]
            n_rules = import_log["rules_created"]
            n_nat   = import_log["nat_created"]
            if install_state == "ok":
                flash(
                    f"Import completed AND policy installed on "
                    f"'{engine_name}'. {n_rules} rule(s) + {n_nat} NAT "
                    f"rule(s) are now live on the engine.",
                    "success",
                )
            elif install_state == "failed":
                flash(
                    f"Import created {n_rules} rule(s) in policy "
                    f"'{policy_name}', BUT the auto-install on "
                    f"'{engine_name}' failed: "
                    f"{import_log['policy_install_message']}. "
                    f"The engine is still running the old policy — fix the "
                    f"error and retry, or install manually in SMC GUI.",
                    "danger",
                )
            elif install_state == "skipped":
                flash(
                    f"Import completed: {n_rules} rule(s) + {n_nat} NAT "
                    f"rule(s) created in policy '{policy_name}'. "
                    f"Auto-install was skipped — "
                    f"{import_log['policy_install_message']}",
                    "warning",
                )
            elif mutated_rules:
                # Operator imported rules but didn't tick auto-install.
                flash(
                    f"Import completed: {n_rules} rule(s) + {n_nat} NAT "
                    f"rule(s) created in policy '{policy_name}'. "
                    f"⚠ The engine is NOT yet running them — open SMC "
                    f"Management Client and install the policy on engine "
                    f"'{engine_name or '(set engine in target config)'}' "
                    f"to activate. (Or re-run with 'Auto-install' ticked.)",
                    "warning",
                )
            else:
                flash("Import completed.", "success")
        except Exception as e:
            import_log["status"] = "error"
            import_log["entries"].append({"level": "error", "msg": str(e)})
            flash(f"Import failed: {e}", "danger")
        project_manager.save_import_log(project_id, import_log)
        return redirect(url_for("migration_import", project_id=project_id))

    import_log        = project_manager.get_import_log(project_id)
    converted         = project_manager.get_converted_rules(project_id)
    selected_count    = 0
    nat_selected_count = 0
    vpn_selected_count = 0
    if converted:
        for section in converted.get("sections", []):
            selected_count += sum(1 for r in section.get("rules", []) if r.get("selected"))
        nat_selected_count = sum(1 for r in converted.get("nat_rules", []) if r.get("selected"))
        vpn_selected_count = sum(1 for v in converted.get("vpn_configs", []) if v.get("selected"))
    return render_template(
        "migration/import.html",
        project=project, import_log=import_log,
        selected_count=selected_count,
        nat_selected_count=nat_selected_count,
        vpn_selected_count=vpn_selected_count,
    )


@app.route("/migration/<project_id>/delete", methods=["POST"])
@login_required
def migration_delete(project_id):
    """Delete a migration project."""
    project_manager.delete_project(project_id)
    flash("Project deleted.", "info")
    return redirect(url_for("migration_projects"))


# ── Migration API ────────────────────────────────────────────────────────

@app.route("/api/migration/<project_id>/status")
@login_required
def api_migration_status(project_id):
    project = project_manager.get_project(project_id)
    if not project:
        return jsonify({"status": "error", "message": "Not found"}), 404
    return jsonify({"status": "ok", "project": project})


@app.route("/api/migration/<project_id>/import-log")
@login_required
def api_migration_import_log(project_id):
    log_data = project_manager.get_import_log(project_id)
    if not log_data:
        return jsonify({"status": "ok", "log": None})
    return jsonify({"status": "ok", "log": log_data})


# ═══════════════════════════════════════════════════════════════════════════
#  RULE OPTIMIZER
# ═══════════════════════════════════════════════════════════════════════════

import json as _json
from admin import admin_required
import rule_optimizer
from webapp.models import OptimizationSubmission, Tenant, User


def _current_user_row():
    info = session.get("user") or {}
    email = (info.get("email") or "").lower().strip()
    if not email:
        return None
    return User.query.filter_by(email=email).first()


def _current_tenant_row():
    profile = session.get("active_profile") or {}
    slug = profile.get("tenant")
    if not slug:
        return None
    return Tenant.query.filter_by(slug=slug).first()


@app.route("/optimize")
@profile_required
def optimize_list():
    """Pick a policy to analyze; show this user's own submissions."""
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            policy_list = smc_client.list_policies()
    except Exception as e:
        return render_template("error.html", message=str(e))

    me = _current_user_row()
    my_subs = []
    domain_id = g.domain.id if getattr(g, "domain", None) else None
    if me and domain_id is not None:
        my_subs = (OptimizationSubmission.query
                   .filter_by(submitted_by_id=me.id, domain_id=domain_id)
                   .order_by(OptimizationSubmission.submitted_at.desc())
                   .limit(20).all())

    return render_template("optimize/list.html",
                           policies=policy_list,
                           my_submissions=my_subs)


def _fetch_policy_for_analysis(policy_name):
    """Fetch both access + NAT rules in a single SMC session."""
    cfg = get_user_cfg()
    with smc_client.smc_session(cfg):
        access = smc_client.get_policy_rules(policy_name)
        nat = smc_client.get_policy_nat_rules(policy_name)
    return access, nat


@app.route("/optimize/<path:policy_name>")
@profile_required
def optimize_report(policy_name):
    """Run the analyzer live against the selected policy."""
    try:
        access, nat = _fetch_policy_for_analysis(policy_name)
    except Exception as e:
        return render_template("error.html", message=str(e))

    result = rule_optimizer.analyze_policy(policy_name, access, nat)
    return render_template("optimize/report.html",
                           policy_name=policy_name,
                           result=result)


@app.route("/optimize/<path:policy_name>/submit", methods=["POST"])
@profile_required
def optimize_submit(policy_name):
    """Snapshot current findings and persist them for admin review."""
    me = _current_user_row()
    tenant = _current_tenant_row()
    if not tenant:
        flash("Cannot resolve the active tenant from your session.", "danger")
        return redirect(url_for("optimize_report", policy_name=policy_name))

    try:
        access, nat = _fetch_policy_for_analysis(policy_name)
    except Exception as e:
        flash(f"Failed to re-fetch rules for submission: {e}", "danger")
        return redirect(url_for("optimize_report", policy_name=policy_name))

    result = rule_optimizer.analyze_policy(policy_name, access, nat)
    if not result["findings"]:
        flash("No findings to submit — this policy looks clean.", "info")
        return redirect(url_for("optimize_report", policy_name=policy_name))

    sub = OptimizationSubmission(
        tenant_id=tenant.id,                                    # legacy — kept until B.3
        domain_id=g.domain.id if getattr(g, "domain", None) else None,
        policy_name=policy_name,
        submitted_by_id=me.id if me else None,
        findings_json=_json.dumps(result),
        finding_count=len(result["findings"]),
        status="pending",
    )
    db.session.add(sub)
    db.session.commit()
    log.info("Optimization submission #%s created by %s for policy %s",
             sub.id, (me.email if me else "?"), policy_name)
    flash(f"Submitted {sub.finding_count} finding(s) for admin review (#{sub.id}).", "success")
    return redirect(url_for("optimize_list"))


@app.route("/optimize/submissions")
@admin_required
def optimize_submissions():
    """Admin inbox: pending submissions first, then decided ones.

    Scoped to the active Domain — the inbox shows only submissions made
    against policies in the current Domain. Submissions from other Domains
    the admin has access to are reviewed after switching context.
    """
    domain_id = g.domain.id if getattr(g, "domain", None) else None
    if domain_id is None:
        pending, decided = [], []
    else:
        pending = (OptimizationSubmission.query
                   .filter_by(status="pending", domain_id=domain_id)
                   .order_by(OptimizationSubmission.submitted_at.desc()).all())
        decided = (OptimizationSubmission.query
                   .filter(OptimizationSubmission.status != "pending",
                           OptimizationSubmission.domain_id == domain_id)
                   .order_by(OptimizationSubmission.reviewed_at.desc().nullslast())
                   .limit(50).all())
    return render_template("optimize/submissions.html",
                           pending=pending, decided=decided)


def _load_submission_payload(sub):
    """Read the submission JSON, accepting both the old flat-list format
    (Phase 1) and the new ``analyze_policy`` dict format (Phase 1.5+)."""
    try:
        raw = _json.loads(sub.findings_json)
    except Exception:
        return {"findings": [], "disabled_rules": [],
                "access": {"rule_count": 0, "disabled_count": 0,
                           "summary": {"exact_duplicate": 0,
                                       "shadowed_same_action": 0}},
                "nat": {"rule_count": 0, "disabled_count": 0,
                        "summary": {"exact_duplicate": 0,
                                    "shadowed_same_action": 0}}}
    if isinstance(raw, list):
        # Legacy: a flat list of findings (access only, no NAT awareness).
        for f in raw:
            f.setdefault("rule_kind", "access")
        return {"findings": raw, "disabled_rules": [],
                "access": {"rule_count": 0, "disabled_count": 0,
                           "summary": {"exact_duplicate": 0,
                                       "shadowed_same_action": 0}},
                "nat": {"rule_count": 0, "disabled_count": 0,
                        "summary": {"exact_duplicate": 0,
                                    "shadowed_same_action": 0}}}
    return raw


def _load_submission_in_active_domain(sub_id):
    """Fetch an optimizer submission, scoped to the active Domain.

    404s on cross-Domain access — never reveal that a row exists in
    another Domain. Same hardening logic as `/optimize/submissions`
    list view + the sidebar pending-count badge: the admin sees only
    submissions tied to the Domain currently in `g.domain`.
    """
    from flask import abort
    sub = OptimizationSubmission.query.get_or_404(sub_id)
    domain_id = g.domain.id if getattr(g, "domain", None) else None
    if domain_id is None or sub.domain_id != domain_id:
        abort(404)
    return sub


@app.route("/optimize/submissions/<int:sub_id>")
@admin_required
def optimize_submission_detail(sub_id):
    sub = _load_submission_in_active_domain(sub_id)
    payload = _load_submission_payload(sub)
    return render_template("optimize/submission_detail.html",
                           submission=sub, payload=payload,
                           findings=payload["findings"])


@app.route("/optimize/submissions/<int:sub_id>/decide", methods=["POST"])
@admin_required
def optimize_submission_decide(sub_id):
    """Record per-finding decisions + close the submission."""
    sub = _load_submission_in_active_domain(sub_id)
    payload = _load_submission_payload(sub)
    findings = payload["findings"]

    for f in findings:
        fid = f.get("id", "")
        decision = request.form.get(f"decision_{fid}", "").strip().lower()
        note = request.form.get(f"note_{fid}", "").strip()
        if decision in ("approved", "rejected"):
            f["decision"] = decision
            f["decision_note"] = note
        else:
            f["decision"] = None
            f["decision_note"] = note

    admin_notes = request.form.get("admin_notes", "").strip()
    close = request.form.get("action") == "close"

    me = _current_user_row()
    sub.findings_json = _json.dumps(payload)
    sub.admin_notes = admin_notes
    sub.reviewed_by_id = me.id if me else None
    from datetime import datetime, timezone as _tz
    sub.reviewed_at = datetime.now(_tz.utc)
    sub.status = "closed" if close else "reviewed"
    db.session.commit()

    flash(f"Saved decisions for submission #{sub.id}.", "success")
    return redirect(url_for("optimize_submission_detail", sub_id=sub.id))


@app.context_processor
def inject_optimizer_pending_count():
    """Expose pending-submission count for the sidebar badge (admin only).

    Scoped to the active Domain so the badge reflects the inbox the admin
    will actually see when they click into the Review Queue.
    """
    try:
        info = session.get("user")
        if not info or not user_manager.is_admin(info.get("email", "")):
            return {"optimizer_pending_count": 0}
        domain_id = g.domain.id if getattr(g, "domain", None) else None
        if domain_id is None:
            return {"optimizer_pending_count": 0}
        return {"optimizer_pending_count":
                OptimizationSubmission.query
                .filter_by(status="pending", domain_id=domain_id).count()}
    except Exception:
        return {"optimizer_pending_count": 0}


# ═══════════════════════════════════════════════════════════════════════════
#  PLATFORM LOGS
# ═══════════════════════════════════════════════════════════════════════════

def _strip_args(args, *keys):
    """Jinja helper: copy a request.args MultiDict minus the given keys.

    Used to build "remove this filter" links and toggle anchors that
    flip a boolean URL flag without dragging it through unchanged.
    """
    out = {}
    for k, v in args.items(multi=False):
        if k in keys:
            continue
        out[k] = v
    return out


app.jinja_env.globals["strip_args"] = _strip_args


@app.route("/logs")
@admin_required
def logs_index():
    """Unified platform logs viewer (admin only).

    Reads from `platform_logs` — the canonical funnel established by the
    standing rule (memory: feedback_logging_standing_rule). Per-feature
    activity tables are no longer written, only read for legacy backfill.

    Filtering: feature, level, status, since-hours, free-text. Default
    scope is the active Domain plus rows with `domain_id IS NULL`
    (system events). Toggle `active_only=0` to widen to every Domain
    the operator has access to.
    """
    from datetime import datetime, timezone, timedelta
    from webapp.models import PlatformLog, Domain
    from shared.logging import list_features, current_log_mode

    feature = (request.args.get("feature") or "").strip()
    level   = (request.args.get("level") or "").strip()
    status  = (request.args.get("status") or "").strip()
    q       = (request.args.get("q") or "").strip()
    try:
        since_hours = int(request.args.get("since_hours", "24"))
    except ValueError:
        since_hours = 24
    try:
        limit = max(50, min(2000, int(request.args.get("limit", "200"))))
    except ValueError:
        limit = 200
    active_only_raw = (request.args.get("active_only") or "1").strip()
    active_only = active_only_raw not in ("0", "false", "off", "")

    qry = PlatformLog.query
    if feature:
        qry = qry.filter(PlatformLog.feature == feature)
    if level in ("audit", "op"):
        qry = qry.filter(PlatformLog.level == level)
    if status:
        qry = qry.filter(PlatformLog.status == status)
    if since_hours > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        qry = qry.filter(PlatformLog.timestamp >= cutoff)
    if q:
        like = f"%{q}%"
        qry = qry.filter((PlatformLog.target.ilike(like)) |
                         (PlatformLog.detail.ilike(like)) |
                         (PlatformLog.action.ilike(like)))

    if active_only:
        active_id = g.domain.id if getattr(g, "domain", None) else None
        if active_id is None:
            qry = qry.filter(PlatformLog.domain_id.is_(None))
        else:
            qry = qry.filter((PlatformLog.domain_id == active_id) |
                             (PlatformLog.domain_id.is_(None)))
    else:
        # Show every Domain the user has access to + system rows.
        email = (session.get("user") or {}).get("email", "")
        my_profiles = user_manager.get_user_profiles(email)
        my_domain_slugs = [p.get("tenant") for p in my_profiles if p.get("tenant")]
        if my_domain_slugs:
            my_domain_ids = [d.id for d in
                             Domain.query.filter(Domain.slug.in_(my_domain_slugs)).all()]
            qry = qry.filter(PlatformLog.domain_id.in_(my_domain_ids) |
                             PlatformLog.domain_id.is_(None))
        else:
            qry = qry.filter(PlatformLog.domain_id.is_(None))

    total_count = qry.count()
    logs = qry.order_by(PlatformLog.timestamp.desc()).limit(limit).all()

    return render_template(
        "logs/index.html",
        logs=logs,
        total_count=total_count,
        features=list_features(),
        log_mode=current_log_mode(),
        active_only=active_only,
        filters={
            "feature": feature, "level": level, "status": status,
            "q": q, "since_hours": since_hours,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="FlexEdgeAdmin — SMC Administration")
    parser.add_argument("--host",  default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port",  type=int, default=int(os.environ.get("PORT", 5000)))
    parser.add_argument("--debug", action="store_true",
                        default=os.environ.get("FLASK_DEBUG", "0") == "1")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)
