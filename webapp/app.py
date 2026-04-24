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
  /sandbox                       Sandbox validation
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
    redirect, url_for, flash, session,
)
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
    # Entra ID / OAuth settings (required)
    AZURE_TENANT_ID=os.environ.get("AZURE_TENANT_ID", ""),
    AZURE_CLIENT_ID=os.environ.get("AZURE_CLIENT_ID", ""),
    AZURE_CLIENT_SECRET=os.environ.get("AZURE_CLIENT_SECRET", ""),
)

# Trust X-Forwarded-* headers from reverse proxies (nginx, traefik, etc.)
# so that url_for(_external=True) produces correct HTTPS URLs in Docker.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

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
    return {
        "element_types":    smc_client.ELEMENT_TYPES,
        "cfg":              cfg,
        "current_user":     current_user,
        "current_user_role": current_user_role,
        "active_profile":   session.get("active_profile"),
        "active_domain":    session.get("active_domain"),
        "app_title":        os.environ.get("APP_TITLE", "FlexEdgeAdmin"),
        "setup_required":   app.config.get("SETUP_REQUIRED", False),
        "build_version":    _build_version,
    }


from shared.version import get_version
_build_version = get_version()


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
    """Let the user choose which SMC API profile to use this session."""
    email = session["user"]["email"]
    profiles = user_manager.get_user_profiles(email)

    if request.method == "POST":
        idx = request.form.get("profile_index", type=int)
        if idx is None or idx < 0 or idx >= len(profiles):
            flash("Invalid profile selection.", "danger")
            return render_template("auth/select_profile.html", profiles=profiles)
        session["active_profile"] = profiles[idx]
        session.pop("active_domain", None)   # reset domain when profile changes
        return redirect(url_for("select_domain"))

    return render_template("auth/select_profile.html", profiles=profiles)


@app.route("/select-domain", methods=["GET", "POST"])
@login_required
def select_domain():
    """
    Fetch available domains from the selected SMC profile and let the user
    pick the one they want to work in.
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


@app.route("/sandbox")
@profile_required
def sandbox():
    """Sandbox mode — dry-run validation of the migration policy."""
    policy_name = request.args.get("policy", "Migration from Fortinet")
    report = None
    error = None
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            report = smc_client.sandbox_rules_check(policy_name)
    except Exception as e:
        error = str(e)
    return render_template(
        "sandbox.html", report=report, error=error, policy_name=policy_name,
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


@app.route("/api/sandbox")
@profile_required
def api_sandbox():
    policy_name = request.args.get("policy", "Migration from Fortinet")
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            report = smc_client.sandbox_rules_check(policy_name)
        return jsonify({"status": "ok", **report})
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
            dedup = dedup_engine.run_dedup(parsed, cfg)
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
            "status": "running",
        }
        try:
            import smc_writer
            if import_type in ("all", "objects") and parsed and dedup:
                obj_result = smc_writer.create_objects(parsed, dedup, cfg)
                import_log["entries"].extend(obj_result.get("entries", []))
                import_log["objects_created"] = obj_result.get("objects_created", 0)
                import_log["objects_skipped"] = obj_result.get("objects_skipped", 0)
                import_log["objects_errors"]  = obj_result.get("objects_errors", 0)
            if import_type in ("all", "rules") and converted:
                policy_name = target.get("policy_name", "Migration from Fortinet")
                rule_result = smc_writer.create_rules(converted, cfg, policy_name)
                import_log["entries"].extend(rule_result.get("entries", []))
                import_log["rules_created"] = rule_result.get("rules_created", 0)
                import_log["rules_errors"]  = rule_result.get("rules_errors", 0)
            if import_type in ("all", "nat") and converted and dedup:
                policy_name = target.get("policy_name", "Migration from Fortinet")
                nat_result  = smc_writer.create_nat_rules(converted, dedup, cfg, policy_name)
                import_log["entries"].extend(nat_result.get("entries", []))
                import_log["nat_created"] = nat_result.get("nat_created", 0)
                import_log["nat_errors"]  = nat_result.get("nat_errors", 0)
            if import_type in ("all", "vpn") and converted and converted.get("vpn_configs"):
                engine_name = target.get("engine_name")
                vpn_result  = smc_writer.create_vpn_infrastructure(converted, cfg, engine_name)
                import_log["entries"].extend(vpn_result.get("entries", []))
                import_log["vpn_profiles"] = vpn_result.get("vpn_profiles", 0)
                import_log["vpn_gateways"] = vpn_result.get("gateways", 0)
                import_log["vpn_policies"] = vpn_result.get("vpn_policies", 0)
                import_log["vpn_errors"]   = vpn_result.get("vpn_errors", 0)
            import_log["status"] = "done"
            project_manager.update_project(project_id, {"status": "imported"})
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
    if me:
        my_subs = (OptimizationSubmission.query
                   .filter_by(submitted_by_id=me.id)
                   .order_by(OptimizationSubmission.submitted_at.desc())
                   .limit(20).all())

    return render_template("optimize/list.html",
                           policies=policy_list,
                           my_submissions=my_subs)


@app.route("/optimize/<path:policy_name>")
@profile_required
def optimize_report(policy_name):
    """Run the analyzer live against the selected policy."""
    try:
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            rules = smc_client.get_policy_rules(policy_name)
    except Exception as e:
        return render_template("error.html", message=str(e))

    result = rule_optimizer.analyze_rules(policy_name, rules)
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
        cfg = get_user_cfg()
        with smc_client.smc_session(cfg):
            rules = smc_client.get_policy_rules(policy_name)
    except Exception as e:
        flash(f"Failed to re-fetch rules for submission: {e}", "danger")
        return redirect(url_for("optimize_report", policy_name=policy_name))

    result = rule_optimizer.analyze_rules(policy_name, rules)
    if not result["findings"]:
        flash("No findings to submit — this policy looks clean.", "info")
        return redirect(url_for("optimize_report", policy_name=policy_name))

    sub = OptimizationSubmission(
        tenant_id=tenant.id,
        policy_name=policy_name,
        submitted_by_id=me.id if me else None,
        findings_json=_json.dumps(result["findings"]),
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
    """Admin inbox: pending submissions first, then decided ones."""
    pending = (OptimizationSubmission.query
               .filter_by(status="pending")
               .order_by(OptimizationSubmission.submitted_at.desc()).all())
    decided = (OptimizationSubmission.query
               .filter(OptimizationSubmission.status != "pending")
               .order_by(OptimizationSubmission.reviewed_at.desc().nullslast())
               .limit(50).all())
    return render_template("optimize/submissions.html",
                           pending=pending, decided=decided)


@app.route("/optimize/submissions/<int:sub_id>")
@admin_required
def optimize_submission_detail(sub_id):
    sub = OptimizationSubmission.query.get_or_404(sub_id)
    try:
        findings = _json.loads(sub.findings_json)
    except Exception:
        findings = []
    return render_template("optimize/submission_detail.html",
                           submission=sub, findings=findings)


@app.route("/optimize/submissions/<int:sub_id>/decide", methods=["POST"])
@admin_required
def optimize_submission_decide(sub_id):
    """Record per-finding decisions + close the submission."""
    sub = OptimizationSubmission.query.get_or_404(sub_id)
    try:
        findings = _json.loads(sub.findings_json)
    except Exception:
        findings = []

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
    sub.findings_json = _json.dumps(findings)
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
    """Expose pending-submission count to the sidebar badge (admin only)."""
    try:
        info = session.get("user")
        if not info or not user_manager.is_admin(info.get("email", "")):
            return {"optimizer_pending_count": 0}
        return {"optimizer_pending_count":
                OptimizationSubmission.query.filter_by(status="pending").count()}
    except Exception:
        return {"optimizer_pending_count": 0}


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
