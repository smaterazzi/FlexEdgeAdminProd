"""
FlexEdgeAdmin — TLS Manager Blueprint.

Admin-only feature that automates TLS certificate lifecycle for Forcepoint
NGFW engines. Bridges Let's Encrypt (certbot) with the SMC API:
  - Tracks certbot-managed certificates
  - Deploys them as TLSServerCredential on firewall engines
  - Creates host objects + policy rules with deep inspection
  - Auto-redeploys on certbot renewal via webhook

Routes mounted at /tls/*
"""
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app, jsonify,
)

from shared.db import db
from webapp.certbot_reader import discover_certificates, file_sha256
from webapp.models import (
    ApiKey, ManagedCertificate, Tenant,
    TLSActivityLog, TLSDeployment, TLSDeploymentLog,
)
from webapp.smc_tls_client import (
    SMCConfig, smc_session,
    list_domains, validate_domain, list_engines,
    list_tls_credentials, get_engine_tls_credentials, remove_tls_from_engine,
)
from webapp.tls_deployer import run_deployment
from webapp.tls_scheduler import (
    check_all_certificates, generate_deploy_hook,
    handle_renewal_webhook, install_deploy_hook,
)

log = logging.getLogger(__name__)

tls_bp = Blueprint("tls", __name__, url_prefix="/tls")


# ── Access control ──────────────────────────────────────────────────────

def admin_required(f):
    """Require authenticated user with admin role."""
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


def require_api_token(f):
    """Decorator for webhook endpoints: Bearer token auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401
        if auth[7:] != current_app.config.get("TLS_API_TOKEN"):
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated


def _log_activity(category: str, action: str, status: str,
                  target: str = "", detail: str = ""):
    db.session.add(TLSActivityLog(
        category=category, action=action, status=status,
        target=target, detail=detail[:4000],
    ))
    db.session.commit()


def _smc_cfg_from_tenant(tenant: Tenant, api_key: ApiKey,
                         domain_override: str = None) -> SMCConfig:
    return SMCConfig(
        url=tenant.smc_url,
        api_key=api_key.decrypted_key,
        domain=domain_override if domain_override is not None else (tenant.default_domain or ""),
        api_version=tenant.api_version or "",
        verify_ssl=tenant.verify_ssl,
        timeout=tenant.timeout,
    )


# ── Initialization ──────────────────────────────────────────────────────

def init_tls_manager(app):
    """Call from app startup to register TLS_API_TOKEN for webhook auth."""
    token_file = Path(app.config.get("CONFIG_DIR", "/config")) / ".tls_api_token"
    if token_file.exists():
        app.config["TLS_API_TOKEN"] = token_file.read_text().strip()
    else:
        token = secrets.token_urlsafe(32)
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token)
        try:
            token_file.chmod(0o600)
        except Exception:
            pass
        app.config["TLS_API_TOKEN"] = token


# ── Dashboard ───────────────────────────────────────────────────────────

@tls_bp.route("/")
@admin_required
def dashboard():
    certificates = ManagedCertificate.query.all()
    deployments = (TLSDeployment.query
                   .order_by(TLSDeployment.last_deployed_at.desc().nullslast())
                   .all())
    deploy_logs = (TLSDeploymentLog.query
                   .order_by(TLSDeploymentLog.created_at.desc()).limit(20).all())
    activity_logs = (TLSActivityLog.query
                     .order_by(TLSActivityLog.created_at.desc()).limit(50).all())
    return render_template(
        "tls/dashboard.html",
        certificates=certificates,
        deployments=deployments,
        deploy_logs=deploy_logs,
        activity_logs=activity_logs,
    )


# ── Certificates ────────────────────────────────────────────────────────

@tls_bp.route("/certificates")
@admin_required
def certificates_list():
    managed = ManagedCertificate.query.all()
    live_dir = current_app.config.get("CERTBOT_LIVE_DIR", "/etc/letsencrypt/live")
    discovered = discover_certificates(live_dir)
    managed_domains = {c.domain for c in managed}
    return render_template(
        "tls/certificates.html",
        managed=managed, discovered=discovered,
        managed_domains=managed_domains, live_dir=live_dir,
    )


@tls_bp.route("/certificates/track", methods=["POST"])
@admin_required
def certificates_track():
    domain = request.form["domain"]
    lineage = request.form["lineage_path"]
    if ManagedCertificate.query.filter_by(domain=domain).first():
        flash(f"Certificate for {domain} is already tracked.", "info")
    else:
        fullchain = Path(lineage) / "fullchain.pem"
        cert = ManagedCertificate(
            domain=domain, certbot_lineage=lineage,
            last_cert_hash=file_sha256(str(fullchain)) if fullchain.exists() else "",
            last_checked_at=datetime.now(timezone.utc),
        )
        db.session.add(cert)
        db.session.commit()
        _log_activity("certificate", "track", "ok", domain, f"lineage={lineage}")
        flash(f"Now tracking certificate for {domain}.", "success")
    return redirect(url_for("tls.certificates_list"))


@tls_bp.route("/certificates/<int:cert_id>/untrack", methods=["POST"])
@admin_required
def certificates_untrack(cert_id):
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert:
        domain = cert.domain
        db.session.delete(cert)
        db.session.commit()
        _log_activity("certificate", "untrack", "ok", domain)
        flash(f"Stopped tracking {domain}.", "warning")
    return redirect(url_for("tls.certificates_list"))


# ── Deployments ─────────────────────────────────────────────────────────

@tls_bp.route("/deploy", methods=["GET", "POST"])
@admin_required
def deploy_form():
    if request.method == "POST":
        dep = TLSDeployment(
            certificate_id=int(request.form["certificate_id"]),
            tenant_id=int(request.form["tenant_id"]),
            api_key_id=int(request.form["api_key_id"]),
            engine_name=request.form["engine_name"],
            service_name=request.form["service_name"],
            public_ipv4=request.form["public_ipv4"],
            private_ipv4=request.form["private_ipv4"],
            auto_renew=request.form.get("auto_renew") == "on",
        )
        db.session.add(dep)
        db.session.commit()
        _log_activity("deploy", "create", "ok", dep.service_name,
                      f"tenant={dep.tenant_id} engine={dep.engine_name}")
        flash(f"Deployment created for {dep.service_name}.", "success")
        return redirect(url_for("tls.deploy_execute", deployment_id=dep.id))

    certificates = ManagedCertificate.query.all()
    tenants = Tenant.query.filter_by(is_active=True).order_by(Tenant.name).all()
    return render_template(
        "tls/deploy.html", certificates=certificates, tenants=tenants,
    )


@tls_bp.route("/deploy/<int:deployment_id>/execute", methods=["GET", "POST"])
@admin_required
def deploy_execute(deployment_id):
    dep = db.session.get(TLSDeployment, deployment_id)
    if not dep:
        flash("Deployment not found.", "danger")
        return redirect(url_for("tls.dashboard"))

    result = None
    if request.method == "POST":
        result = run_deployment(dep.id, action="deploy")
        if result.success:
            _log_activity("deploy", "execute", "ok", dep.service_name,
                          f"engine={dep.engine_name} steps={len(result.steps)}")
            flash("Deployment successful!", "success")
        else:
            _log_activity("deploy", "execute", "error", dep.service_name,
                          f"engine={dep.engine_name} — {result.error}\n{result.steps}")
            flash(f"Deployment failed: {result.error}", "danger")

    return render_template("tls/deploy_execute.html", deployment=dep, result=result)


@tls_bp.route("/deploy/<int:deployment_id>/delete", methods=["POST"])
@admin_required
def deploy_delete(deployment_id):
    dep = db.session.get(TLSDeployment, deployment_id)
    if dep:
        name = dep.service_name
        db.session.delete(dep)
        db.session.commit()
        _log_activity("deploy", "delete", "ok", name)
        flash("Deployment removed.", "warning")
    return redirect(url_for("tls.dashboard"))


# ── AJAX endpoints for deploy form ───────────────────────────────────────

@tls_bp.route("/api/tenants/<int:tenant_id>/api-keys")
@admin_required
def api_tenant_keys(tenant_id):
    keys = ApiKey.query.filter_by(tenant_id=tenant_id, is_active=True).all()
    return jsonify([{"id": k.id, "name": k.name} for k in keys])


@tls_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines")
@admin_required
def api_tenant_engines(tenant_id, key_id):
    tenant = db.session.get(Tenant, tenant_id)
    key = db.session.get(ApiKey, key_id)
    if not tenant or not key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg_from_tenant(tenant, key)
    try:
        with smc_session(cfg):
            engines = list_engines()
        return jsonify(engines)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@tls_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/<engine_name>/tls")
@admin_required
def api_engine_tls(tenant_id, key_id, engine_name):
    tenant = db.session.get(Tenant, tenant_id)
    key = db.session.get(ApiKey, key_id)
    if not tenant or not key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg_from_tenant(tenant, key)
    try:
        with smc_session(cfg):
            creds = get_engine_tls_credentials(engine_name)
        return jsonify(creds)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@tls_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/<engine_name>/tls/<cred_name>/remove",
              methods=["POST"])
@admin_required
def api_remove_engine_tls(tenant_id, key_id, engine_name, cred_name):
    tenant = db.session.get(Tenant, tenant_id)
    key = db.session.get(ApiKey, key_id)
    if not tenant or not key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg_from_tenant(tenant, key)
    try:
        with smc_session(cfg):
            remove_tls_from_engine(engine_name, cred_name)
        _log_activity("deploy", "remove_tls", "ok", f"{engine_name}/{cred_name}")
        return jsonify({"status": "removed"})
    except Exception as e:
        _log_activity("deploy", "remove_tls", "error", f"{engine_name}/{cred_name}", str(e))
        return jsonify({"error": str(e)}), 500


# ── Renewal webhook (certbot deploy-hook) ────────────────────────────────

@tls_bp.route("/api/renew", methods=["POST"])
@require_api_token
def api_renew():
    data = request.get_json(force=True)
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "Missing 'domain' field"}), 400
    result = handle_renewal_webhook(domain)
    _log_activity("renewal", "webhook", "ok" if result.get("renewed", 0) > 0 else "warning",
                  domain, str(result))
    return jsonify(result)


@tls_bp.route("/api/check-renewals", methods=["POST"])
@require_api_token
def api_check_renewals():
    results = check_all_certificates()
    return jsonify({"checked": len(results), "results": results})


# ── Deploy hook management ───────────────────────────────────────────────

@tls_bp.route("/hook")
@admin_required
def hook_view():
    api_url = request.host_url.rstrip("/")
    api_token = current_app.config.get("TLS_API_TOKEN", "")
    hook_script = generate_deploy_hook(api_url, api_token)
    return render_template("tls/hook.html",
                           api_url=api_url, api_token=api_token,
                           hook_script=hook_script)


@tls_bp.route("/hook/install", methods=["POST"])
@admin_required
def hook_install():
    api_url = request.form.get("api_url", request.host_url.rstrip("/"))
    api_token = current_app.config.get("TLS_API_TOKEN", "")
    hook_dir = request.form.get("hook_dir", "/etc/letsencrypt/renewal-hooks/deploy")
    try:
        path = install_deploy_hook(api_url, api_token, hook_dir)
        _log_activity("system", "install_hook", "ok", path)
        flash(f"Deploy hook installed: {path}", "success")
    except Exception as e:
        _log_activity("system", "install_hook", "error", hook_dir, str(e))
        flash(f"Failed to install hook: {e}", "danger")
    return redirect(url_for("tls.hook_view"))


# ── History ──────────────────────────────────────────────────────────────

@tls_bp.route("/history")
@admin_required
def history():
    logs = (TLSDeploymentLog.query
            .order_by(TLSDeploymentLog.created_at.desc()).limit(100).all())
    return render_template("tls/history.html", logs=logs)
