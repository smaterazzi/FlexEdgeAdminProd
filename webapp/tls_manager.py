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
import hmac
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app, jsonify, g,
)

from shared.db import db
from webapp.auth_roles import domain_admin_required
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
    check_all_certificates, generate_deploy_hook, generate_token_file,
    handle_renewal_webhook, install_deploy_hook, DEFAULT_TOKEN_FILE,
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
    """Decorator for webhook endpoints: Bearer token auth.

    C6 + M15 (audit fix-up, 2026-05-09):
      * Use ``hmac.compare_digest`` to compare the presented token with
        the configured one — constant-time comparison prevents byte-by-byte
        timing-attack token recovery.
      * Refuse with HTTP 503 when the configured token is empty / None.
        Without this guard a misconfigured deploy (token-file write
        failed, env var unset) would coerce ``None`` into the comparison
        and reject everything as "Invalid token" — the failure mode is
        indistinguishable from "wrong token from caller". 503 makes the
        misconfiguration unambiguous in the logs.
    """
    import hmac
    @wraps(f)
    def decorated(*args, **kwargs):
        configured = current_app.config.get("TLS_API_TOKEN") or ""
        if not configured:
            # An unconfigured webhook MUST refuse outright — `!=` against
            # an empty string would let any non-empty Bearer through if
            # the token was misconfigured to "". Surface 503 so the
            # operator's deploy-hook test fails loudly.
            return jsonify({"error": "Webhook token not configured on server"}), 503
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401
        presented = auth[7:]
        if not hmac.compare_digest(presented.encode("utf-8"),
                                   configured.encode("utf-8")):
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated


def _log_activity(category: str, action: str, status: str,
                  target: str = "", detail: str = ""):
    """Funnel a TLS audit-log entry through the platform log writer.

    See dhcp_manager._log_activity for the same routing rule.
    """
    from shared.logging import audit
    feature = "system" if category == "system" else "tls"
    audit(feature=feature,
          action=f"{category}.{action}",
          target=target, detail=detail, status=status)


def _read_tls_activity_for_dashboard(domain_id, limit: int = 50):
    """Return legacy-shaped activity rows for the TLS dashboard.

    Reads from the unified PlatformLog (tls_activity_logs is no longer
    written; rows backfilled at boot). Re-projects each row into a
    SimpleNamespace exposing `created_at / category / action / status /
    target` so the existing dashboard template renders unchanged.
    """
    from types import SimpleNamespace
    from webapp.models import PlatformLog
    q = PlatformLog.query.filter(PlatformLog.feature.in_(["tls", "system"]))
    if domain_id is not None:
        q = q.filter((PlatformLog.domain_id == domain_id) |
                     (PlatformLog.domain_id.is_(None)))
    rows = q.order_by(PlatformLog.timestamp.desc()).limit(limit).all()
    out = []
    for r in rows:
        if "." in (r.action or ""):
            cat, act = r.action.split(".", 1)
        else:
            cat, act = (r.feature or "?"), (r.action or "")
        out.append(SimpleNamespace(
            id=r.id, created_at=r.timestamp,
            category=cat, action=act,
            status=r.status, target=r.target, detail=r.detail,
        ))
    return out


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

def _certs_in_active_domain(domain_id):
    """ManagedCertificate rows visible inside the given Domain.

    A cert is visible if EITHER:
      * It has at least one `TLSDeployment` whose `domain_id` matches
        (Path I — historical LE-issued / manually-tracked certs).
      * It was directly created inside the Domain (its own `domain_id`
        column matches — LE Phase 1+2 stamps this, and the PFX-import
        flow (2026-05-31) does too). This shows a freshly imported
        cert in the Domain it was uploaded into, even before the
        operator has wired up any deployment.

    An operator in Domain B never sees a cert that was both stamped to
    Domain A AND only deployed in Domain A.

    Returns an empty list when ``domain_id is None`` (no active Domain).
    """
    if domain_id is None:
        return []
    via_deployment = (
        ManagedCertificate.query
        .join(TLSDeployment,
              TLSDeployment.certificate_id == ManagedCertificate.id)
        .filter(TLSDeployment.domain_id == domain_id)
    )
    via_own_domain = (
        ManagedCertificate.query
        .filter(ManagedCertificate.domain_id == domain_id)
    )
    return (via_deployment.union(via_own_domain)
            .order_by(ManagedCertificate.domain.asc())
            .all())


@tls_bp.route("/")
@admin_required
def dashboard():
    domain = getattr(g, "domain", None)
    domain_id = domain.id if domain is not None else None

    # Domain-scoped via the linked TLSDeployment rows. A cert tracked
    # but never deployed in this Domain stays hidden — visit
    # /tls/deploy to deploy it for the first time.
    certificates = _certs_in_active_domain(domain_id)

    if domain_id is None:
        deployments, deploy_logs, activity_logs = [], [], []
    else:
        deployments = (TLSDeployment.query
                       .filter_by(domain_id=domain_id)
                       .order_by(TLSDeployment.last_deployed_at.desc().nullslast())
                       .all())
        deploy_logs = (TLSDeploymentLog.query
                       .join(TLSDeployment, TLSDeploymentLog.deployment_id == TLSDeployment.id)
                       .filter(TLSDeployment.domain_id == domain_id)
                       .order_by(TLSDeploymentLog.created_at.desc()).limit(20).all())
        # Activity feed sourced from the unified platform log (legacy
        # tls_activity_logs is read-only post-backfill).
        activity_logs = _read_tls_activity_for_dashboard(domain_id, limit=50)
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
    domain = getattr(g, "domain", None)
    domain_id = domain.id if domain is not None else None
    # Same Path I scoping as the dashboard — only certs deployed in the
    # active Domain are visible here. Discovered (untracked) certs from
    # the certbot live dir are still listed; they're host-level, not
    # Domain-level.
    managed = _certs_in_active_domain(domain_id)
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


@tls_bp.route("/certificates/import-pfx", methods=["GET", "POST"])
@admin_required
def certificates_import_pfx():
    """Upload a PKCS#12 (.pfx) bundle and register it as a tracked cert.

    Replaces the manual ``openssl pkcs12`` procedure documented in
    ``docs/PFX2CER.md``. The bundle is parsed in-process via
    ``webapp.pfx_import.parse_pfx``; on success the PEM files are
    written into ``${FEA_PFX_DIR}/<slug>/`` and a ``ManagedCertificate``
    row is created (or replaced, on re-import of the same CN). The
    existing ``/tls/deploy`` pipeline picks the cert up unchanged.
    """
    from webapp import pfx_import

    if request.method == "GET":
        return render_template("tls/import_pfx.html")

    pfx_file = request.files.get("pfx_file")
    if pfx_file is None or not pfx_file.filename:
        flash("No PFX file uploaded.", "danger")
        return redirect(url_for("tls.certificates_import_pfx"))
    password = request.form.get("password", "")
    domain_override = (request.form.get("domain_override") or "").strip().lower()

    # Audit P6 (2026-06-11): cap the upload before buffering the whole
    # bundle in memory. Real-world enterprise .pfx files are <100 KB;
    # 10 MB is generous headroom for absurd CA chains.
    _PFX_MAX_BYTES = 10 * 1024 * 1024
    try:
        pfx_bytes = pfx_file.read(_PFX_MAX_BYTES + 1)
    except Exception as exc:
        flash(f"Failed to read uploaded file: {exc}", "danger")
        return redirect(url_for("tls.certificates_import_pfx"))
    if len(pfx_bytes) > _PFX_MAX_BYTES:
        flash("PFX file too large (max 10 MB) — that is not a valid "
              "PKCS#12 bundle.", "danger")
        return redirect(url_for("tls.certificates_import_pfx"))

    try:
        parsed = pfx_import.parse_pfx(pfx_bytes, password)
    except pfx_import.PfxImportError as exc:
        _log_activity("certificate", "import_pfx", "error",
                      pfx_file.filename or "<unnamed>", str(exc))
        flash(str(exc), "danger")
        return redirect(url_for("tls.certificates_import_pfx"))

    # Domain: explicit override > CN > first SAN. Reject if none is
    # usable — we need it for the unique constraint on ManagedCertificate.
    cn = (parsed.metadata.get("subject_cn") or "").strip().lower()
    sans = [s.strip().lower() for s in parsed.metadata.get("san_domains") or [] if s]
    if domain_override:
        cert_domain = domain_override
    elif cn:
        cert_domain = cn
    elif sans:
        cert_domain = sans[0]
    else:
        flash("PFX has neither a Common Name nor a SAN — provide an "
              "explicit domain override.", "danger")
        return redirect(url_for("tls.certificates_import_pfx"))

    # Refuse to clobber a Let's Encrypt-tracked row from this UI. The
    # operator must untrack the LE cert first to keep the LE lineage
    # at /config/letsencrypt/live/<fqdn>/ clean.
    existing = ManagedCertificate.query.filter_by(domain=cert_domain).first()
    if existing is not None and existing.challenge_type in ("http01", "dns01_manual"):
        flash(
            f"A Let's Encrypt certificate for {cert_domain} is already "
            "tracked. Untrack it first (or pick a different domain "
            "override) — re-importing would conflict with the LE "
            "lifecycle.", "danger",
        )
        return redirect(url_for("tls.certificates_import_pfx"))

    try:
        lineage_path, fullchain_hash = pfx_import.save_parsed_pfx(
            parsed, cert_domain,
        )
    except Exception as exc:
        log.exception("PFX save failed for %s", cert_domain)
        _log_activity("certificate", "import_pfx", "error", cert_domain,
                      f"save failed: {exc}")
        flash(f"Failed to save PFX files to disk: {exc}", "danger")
        return redirect(url_for("tls.certificates_import_pfx"))

    now = datetime.now(timezone.utc)
    active_domain = getattr(g, "domain", None)
    active_domain_id = active_domain.id if active_domain is not None else None
    if existing is None:
        cert = ManagedCertificate(
            domain=cert_domain,
            certbot_lineage=str(lineage_path),
            last_cert_hash=fullchain_hash,
            last_checked_at=now,
            status="active",
            challenge_type="pfx_import",
            is_staging=False,
            # Stamp the active Domain so the cert is visible on
            # /tls/certificates immediately (before any TLSDeployment
            # exists). Matches the LE.1 stamping pattern.
            domain_id=active_domain_id,
        )
        db.session.add(cert)
        action_word = "imported"
    else:
        # Re-import of a PFX-tracked cert — refresh paths + hash.
        # Keep `domain_id` if previously set; only fill it in for
        # legacy rows where it was NULL.
        existing.certbot_lineage = str(lineage_path)
        existing.last_cert_hash = fullchain_hash
        existing.last_checked_at = now
        existing.status = "active"
        existing.last_error = ""
        if existing.domain_id is None and active_domain_id is not None:
            existing.domain_id = active_domain_id
        cert = existing
        action_word = "reimported"
    db.session.commit()

    valid_to = parsed.metadata.get("valid_to")
    expires = valid_to.strftime("%Y-%m-%d") if valid_to else "unknown"
    _log_activity("certificate", "import_pfx", "ok", cert_domain,
                  f"action={action_word} lineage={lineage_path} "
                  f"expires={expires} cn={cn!r}")
    flash(
        f"PFX {action_word} for {cert_domain} (expires {expires}). "
        "Deploy it from /tls/deploy.", "success",
    )
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

    # The deploy form is a write-side picker — the operator may be
    # creating the FIRST deployment of a tracked cert into the active
    # Domain, in which case Path I scoping (subquery via TLSDeployment)
    # would hide every never-deployed-here cert and produce an empty
    # dropdown (chicken-and-egg). Show every tracked cert; the actual
    # TLSDeployment row gets stamped with the active Domain on submit.
    certificates = (ManagedCertificate.query
                    .order_by(ManagedCertificate.domain.asc()).all())
    # Domain-Scoping: only the active Domain's bound Tenant in the
    # picker. Operator never sees another Domain's Tenant here.
    domain = getattr(g, "domain", None)
    bound_tenant_id = (domain.api_key.tenant_id
                       if domain is not None and domain.api_key is not None
                       else None)
    tenants = ([] if bound_tenant_id is None
               else Tenant.query
                          .filter_by(id=bound_tenant_id, is_active=True)
                          .all())
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
    tls_running = None

    # H8 (audit fix-up, 2026-05-09): consume the post-deploy scan_jobs
    # report when the page reloads after the watcher polled "done".
    tls_scan_id = (request.args.get("tls_scan_id") or "").strip()
    if tls_scan_id and request.method == "GET":
        from webapp import tls_deploy_jobs
        user_email = (session.get("user") or {}).get("email", "")
        status = tls_deploy_jobs.get_status(tls_scan_id, user_email=user_email)
        if status is None:
            flash("TLS deploy job not found or expired.", "info")
        elif status["state"] == "running":
            tls_running = status
        elif status["state"] == "failed":
            flash(f"TLS deploy worker failed: "
                  f"{status.get('error') or 'unknown error'}", "danger")
            tls_deploy_jobs.discard(tls_scan_id, user_email=user_email)
        else:  # done
            push_result = tls_deploy_jobs.consume_report(
                tls_scan_id, user_email=user_email,
            )
            change_id = (status.get("change_id") if status else None) or 0
            is_bypass_done = bool(status.get("is_bypass") if status else False)
            db.session.refresh(dep)
            from webapp.smc_tls_client import DeployResult
            result = DeployResult(
                success=(dep.last_status == "deployed"),
                error=dep.last_error or "",
                tls_credential_name=dep.tls_credential_name or "",
                host_public_name=dep.host_public_name or "",
                host_private_name=dep.host_private_name or "",
                policy_rule_name=dep.policy_rule_name or "",
                policy_section_name=dep.policy_section_name or "",
            )
            if push_result is not None and getattr(push_result, "success", False):
                _log_activity("deploy", "execute", "ok", dep.service_name,
                              f"via_queue=True bypass={is_bypass_done} "
                              f"engine={dep.engine_name} change_id={change_id}")
                flash(f"Deployment successful (queue change #{change_id}).",
                      "success")
            else:
                err = (getattr(push_result, "error", "")
                       or dep.last_error
                       or "Unknown")
                _log_activity("deploy", "execute", "error", dep.service_name,
                              f"via_queue=True bypass={is_bypass_done} "
                              f"engine={dep.engine_name} — {err}")
                flash(f"Deployment failed (queue change #{change_id}): "
                      f"{err}. Retry from the Change Queue.", "danger")

    if request.method == "POST":
        # Phase E.2 — enqueue + auto-push for admins (Q15/a + Q19/b).
        # ONE queue row carries the whole 5-step pipeline; the queue UI
        # surfaces the per-step status in the expanded detail panel.
        from webapp.models import PendingChange
        import json as _json

        if dep.domain_id is None:
            flash("Deployment has no Domain on file — fix it via Admin Portal.",
                  "danger")
            return render_template("tls/deploy_execute.html",
                                   deployment=dep, result=None)

        change = PendingChange(
            domain_id=dep.domain_id,
            user_id=None,  # set lazily by the runner via session
            scope="main",
            operation="deploy_tls",
            payload_json=_json.dumps({
                "deployment_id": dep.id,
                "action": "deploy",
            }),
            feature_source="tls",
            source_correlation_id=f"tls_deployment:{dep.id}",
            state="queued",
        )
        db.session.add(change)
        db.session.flush()
        # Resolve the queue row's user from session for the audit trail.
        try:
            from flask import session as _sess
            from webapp.models import User
            email = ((_sess.get("user") or {}).get("email") or "").strip().lower()
            if email:
                u = User.query.filter_by(email=email).first()
                if u is not None:
                    change.user_id = u.id
        except Exception:
            pass
        db.session.commit()

        # Auto-push for admins (Q15/a) or for users with per-user bypass
        # on `tls_deploy`. For non-admins-without-bypass this is an
        # admin-only route normally, but the helper handles both.
        from webapp.auth_roles import is_domain_admin
        is_bypass = False
        try:
            from shared.queue_settings import should_bypass_queue
            is_bypass = should_bypass_queue("tls_deploy")
        except Exception:
            is_bypass = False

        if is_domain_admin() or is_bypass:
            # H8 (audit fix-up, 2026-05-09): spawn the queue push in a
            # daemon thread so the request returns instantly. The watcher
            # card on deploy_execute.html polls /tls/deploy/<id>/status
            # and reloads when the worker calls mark_done.
            from webapp.tls_deploy_jobs import start_deploy
            user_email = ((session.get("user") or {}).get("email") or "").strip()
            try:
                scan_id = start_deploy(
                    change_id=change.id,
                    deployment_id=dep.id,
                    service_name=dep.service_name,
                    user_email=user_email,
                    is_bypass=is_bypass,
                )
            except Exception as exc:
                log.exception("deploy_execute: failed to spawn job")
                flash(f"Deploy failed to start: {exc}", "danger")
                return redirect(url_for("tls.deploy_execute",
                                        deployment_id=dep.id))
            return redirect(url_for("tls.deploy_execute",
                                    deployment_id=dep.id,
                                    tls_scan_id=scan_id))
        else:
            _log_activity("deploy", "execute.queued", "ok", dep.service_name,
                          f"engine={dep.engine_name} change_id={change.id}")
            flash(f"Deployment queued (change #{change.id}). "
                  f"Push from the Change Queue.", "info")
            return redirect(url_for("changes.index",
                                    source=f"tls_deployment:{dep.id}"))

    return render_template("tls/deploy_execute.html",
                           deployment=dep, result=result,
                           tls_running=tls_running)


@tls_bp.route("/deploy/<int:deployment_id>/status")
@admin_required
def deploy_status(deployment_id):
    """JSON poll target for the TLS deploy watcher card."""
    from webapp import tls_deploy_jobs
    scan_id = (request.args.get("id") or "").strip()
    user_email = (session.get("user") or {}).get("email", "")
    status = tls_deploy_jobs.get_status(scan_id, user_email=user_email)
    if status is None:
        return jsonify({"state": "missing"}), 404
    return jsonify(status)


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
        # Phase 0 cross-feature reuse: hit the shared ``engines`` cache
        # populated by /engines/clusters. Same SMC server / same active
        # Domain → instant cascade load when operator visited Engines first.
        from webapp import domain_objects
        domain = getattr(g, "domain", None)
        engines_list, _cv = domain_objects.engines(domain, cfg)
        engines = [
            {"name": e.name, "type": e.typeof, "href": e.href,
             "sources": ["cache"]}
            for e in engines_list
        ]
        _log_activity("deploy", "fetch_engines", "ok", f"{tenant.name}/{key.name}",
                      f"Returned {len(engines)} engine(s): " +
                      ", ".join(f"{e['name']} ({e['type']})" for e in engines))
        return jsonify(engines)
    except Exception as e:
        _log_activity("deploy", "fetch_engines", "error",
                      f"{tenant.name}/{key.name}", str(e))
        return jsonify({"error": str(e)}), 500


@tls_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/debug")
@admin_required
def api_tenant_engines_debug(tenant_id, key_id):
    """Diagnostic: return all engines with per-source attribution so we can
    see exactly which discovery stage saw each engine (generic / subclass /
    raw REST). Useful when an engine is expected but not appearing."""
    tenant = db.session.get(Tenant, tenant_id)
    key = db.session.get(ApiKey, key_id)
    if not tenant or not key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg_from_tenant(tenant, key)
    try:
        with smc_session(cfg):
            engines = list_engines(debug=True)
        return jsonify({
            "tenant": tenant.name,
            "domain": tenant.default_domain,
            "count": len(engines),
            "engines": engines,
        })
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
    # M3 (audit fix-up, 2026-05-09): script no longer carries the token
    # inline. The view shows TWO files now: the hook script (chmod 0700)
    # and a sibling token file (chmod 0600) the script sources. The
    # auto-installer at /tls/hook/install renders both with the right
    # permissions; manual installers copy each block to the path shown.
    hook_script = generate_deploy_hook(api_url, DEFAULT_TOKEN_FILE)
    token_file_content = generate_token_file(api_token)
    return render_template("tls/hook.html",
                           api_url=api_url, api_token=api_token,
                           hook_script=hook_script,
                           token_file_content=token_file_content,
                           token_file_path=DEFAULT_TOKEN_FILE)


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


# ── Cert expirations dashboard + SMTP alerts (2026-05-31) ───────────────

@tls_bp.route("/expirations")
@domain_admin_required
def expirations_dashboard():
    """Per-Domain cert-expiration dashboard with auto-alert sweep."""
    from webapp import cert_expirations
    domain = getattr(g, "domain", None)
    domain_id = domain.id if domain is not None else None
    views = cert_expirations.build_views_for_domain(domain_id)
    user_email = (session.get("user") or {}).get("email", "")
    # Lazy-sweep — fires once per hour from any visit; never raises.
    # Runs in a background thread since audit P1 (2026-06-11) so the
    # page render never waits on SMTP.
    sweep_started = cert_expirations.ensure_lazy_expiration_sweep(
        triggered_by_user_email=user_email,
    )
    smtp_cfg = None
    if domain_id is not None:
        from webapp.models import SmtpConfig
        smtp_cfg = SmtpConfig.query.filter_by(domain_id=domain_id).first()
    return render_template(
        "tls/expirations.html",
        views=views, sweep_started=sweep_started, smtp_cfg=smtp_cfg,
    )


@tls_bp.route("/expirations/notifications")
@domain_admin_required
def expirations_notifications():
    """Audit-style log of every cert-expiration alert sent."""
    from webapp import cert_expirations
    domain = getattr(g, "domain", None)
    domain_id = domain.id if domain is not None else None
    rows = cert_expirations.recent_notifications(domain_id, limit=200)
    return render_template(
        "tls/expiration_notifications.html",
        rows=rows,
    )


@tls_bp.route("/expirations/sweep", methods=["POST"])
@domain_admin_required
def expirations_sweep_now():
    """Operator-clicked manual sweep (bypasses the 1h gate)."""
    from webapp import cert_expirations
    user_email = (session.get("user") or {}).get("email", "")
    try:
        report = cert_expirations.sweep_all_domains(
            triggered_by_user_email=user_email,
        )
        cert_expirations.mark_swept_now()
        flash(f"Sweep complete — considered {report.certs_considered} cert(s), "
              f"sent {report.sends_ok} ok / {report.sends_failed} failed.",
              "success" if report.sends_failed == 0 else "warning")
    except Exception as exc:
        log.exception("manual expirations sweep failed")
        flash(f"Sweep failed: {exc}", "danger")
    return redirect(url_for("tls.expirations_dashboard"))


@tls_bp.route("/smtp", methods=["GET", "POST"])
@domain_admin_required
def smtp_config():
    """Per-Domain SMTP configuration CRUD."""
    from webapp.models import SmtpConfig
    from webapp import cert_expirations

    domain = getattr(g, "domain", None)
    if domain is None:
        flash("Pick a Domain before configuring SMTP.", "warning")
        return redirect(url_for("tls.dashboard"))

    cfg = SmtpConfig.query.filter_by(domain_id=domain.id).first()

    if request.method == "POST":
        host = (request.form.get("host") or "").strip()
        port_raw = (request.form.get("port") or "587").strip()
        try:
            port = int(port_raw)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            flash(f"Port must be 1–65535 (got {port_raw!r}).", "danger")
            return redirect(url_for("tls.smtp_config"))
        security = (request.form.get("security") or "starttls").strip().lower()
        if security not in ("starttls", "ssl", "plain"):
            security = "starttls"
        if security == "plain":
            from webapp.smtp_sender import plain_mode_refusal
            refusal = plain_mode_refusal(host, port) if host else ""
            if refusal:
                flash(f"Refusing plain (no TLS) mode: {refusal}", "danger")
                return redirect(url_for("tls.smtp_config"))
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password", "")
        # Preserve existing password when the field is blank on edit —
        # operators commonly leave it empty to avoid retyping. Empty
        # password on a fresh row is a legitimate config (open relay).
        keep_password = (cfg is not None and not password
                         and (request.form.get("keep_password") == "1"))
        from_address = (request.form.get("from_address") or "").strip()
        from_name = (request.form.get("from_name") or "FlexEdgeAdmin").strip()
        recipients_csv = (request.form.get("recipients_csv") or "").strip()
        thresholds_csv = (request.form.get("thresholds_csv") or "30,14,7,3,1").strip()
        is_active = request.form.get("is_active") == "on"

        if not host:
            flash("SMTP host is required.", "danger")
            return redirect(url_for("tls.smtp_config"))
        if not from_address or "@" not in from_address:
            flash("From address is required (and must look like an email).",
                  "danger")
            return redirect(url_for("tls.smtp_config"))
        if "@" not in from_address.split("@", 1)[-1]:
            # Already covered by the above; guarding against pure-domain inputs.
            pass

        # Validate recipients + thresholds at form-handling time so the
        # operator sees an immediate refusal rather than discovering
        # the silent skip on the next sweep.
        recipients = cert_expirations.parse_recipients(recipients_csv)
        if not recipients:
            flash("At least one alert recipient is required.", "danger")
            return redirect(url_for("tls.smtp_config"))
        bad = [r for r in recipients if "@" not in r]
        if bad:
            flash(f"Invalid recipient(s): {', '.join(bad)}", "danger")
            return redirect(url_for("tls.smtp_config"))
        thresholds = cert_expirations.parse_thresholds(thresholds_csv)
        if not thresholds:
            flash("At least one threshold (positive integer days) is required.",
                  "danger")
            return redirect(url_for("tls.smtp_config"))

        if cfg is None:
            cfg = SmtpConfig(domain_id=domain.id)
            db.session.add(cfg)
        cfg.host = host
        cfg.port = port
        cfg.security = security
        cfg.username = username
        if not keep_password:
            cfg.encrypted_password = password
        cfg.from_address = from_address
        cfg.from_name = from_name
        cfg.recipients_csv = ",".join(recipients)
        cfg.thresholds_csv = ",".join(str(t) for t in thresholds)
        cfg.is_active = is_active
        db.session.commit()
        _log_activity("smtp", "save", "ok", host,
                      f"port={port} security={security} "
                      f"recipients={len(recipients)} thresholds={thresholds_csv}")
        flash("SMTP configuration saved.", "success")
        return redirect(url_for("tls.smtp_config"))

    return render_template("tls/smtp.html", cfg=cfg)


@tls_bp.route("/smtp/test", methods=["POST"])
@domain_admin_required
def smtp_test():
    """Send a smoke-test email using the saved SMTP config."""
    from webapp.models import SmtpConfig
    from webapp.smtp_sender import SmtpSettings, send_smtp
    from webapp import cert_expirations

    domain = getattr(g, "domain", None)
    if domain is None:
        flash("Pick a Domain first.", "warning")
        return redirect(url_for("tls.dashboard"))
    cfg = SmtpConfig.query.filter_by(domain_id=domain.id).first()
    if cfg is None or not cfg.is_active:
        flash("Save and activate the SMTP config first.", "warning")
        return redirect(url_for("tls.smtp_config"))
    recipients = cert_expirations.parse_recipients(cfg.recipients_csv)
    if not recipients:
        flash("No recipients configured.", "warning")
        return redirect(url_for("tls.smtp_config"))

    settings = SmtpSettings(
        host=cfg.host, port=cfg.port, security=cfg.security,
        username=cfg.username, password=cfg.encrypted_password or "",
        from_address=cfg.from_address, from_name=cfg.from_name,
    )
    subject = "[FlexEdgeAdmin] SMTP smoke test"
    text_body = (
        "This is a smoke test from FlexEdgeAdmin's TLS expiration alerter.\n"
        f"Domain : {domain.display_name or domain.slug}\n"
        f"From   : {cfg.from_address}\n"
        f"Time   : {datetime.now(timezone.utc).isoformat()}\n\n"
        "If you received this, the SMTP configuration is working and "
        "cert-expiration alerts can be delivered to this address list.\n"
    )
    result = send_smtp(
        settings=settings, to_addrs=recipients,
        subject=subject, body_text=text_body,
    )
    cfg.last_test_at = datetime.now(timezone.utc)
    cfg.last_test_status = "ok" if result.ok else "failed"
    cfg.last_test_error = result.error
    db.session.commit()
    if result.ok:
        suffix = " (DRY RUN — no email was sent)" if result.dry_run else ""
        flash(f"SMTP test sent to {len(recipients)} recipient(s){suffix}.",
              "success")
        _log_activity("smtp", "test", "ok",
                      f"{cfg.host}:{cfg.port}",
                      f"recipients={len(recipients)} dry_run={result.dry_run}")
    else:
        flash(f"SMTP test failed: {result.error}", "danger")
        _log_activity("smtp", "test", "error",
                      f"{cfg.host}:{cfg.port}", result.error)
    return redirect(url_for("tls.smtp_config"))


# ── History ──────────────────────────────────────────────────────────────

@tls_bp.route("/history")
@admin_required
def history():
    domain = getattr(g, "domain", None)
    domain_id = domain.id if domain is not None else None
    if domain_id is None:
        logs = []
    else:
        logs = (TLSDeploymentLog.query
                .join(TLSDeployment, TLSDeploymentLog.deployment_id == TLSDeployment.id)
                .filter(TLSDeployment.domain_id == domain_id)
                .order_by(TLSDeploymentLog.created_at.desc()).limit(100).all())
    return render_template("tls/history.html", logs=logs)
