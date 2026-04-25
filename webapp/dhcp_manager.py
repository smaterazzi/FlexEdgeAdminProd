"""
FlexEdgeAdmin — DHCP Reservation Manager Blueprint.

Admin-only feature that manages MAC-to-IP reservations on Forcepoint NGFW
engines with the internal DHCP server enabled. The SMC API does not expose
DHCP reservations, so SMC Host elements are used as the source of truth
(MAC stored inside Host.comment via a `[flexedge:mac=...]` marker). The
actual push of `host { }` blocks into `/data/config/base/dhcp-server.conf`
on each cluster node is handled by Phase 4 (`dhcp_deployer.py`).

Routes mounted at /dhcp/*

Phase 3 scope (this file):
  - Dashboard + activity log
  - Scope discovery & enable/disable
  - Host CRUD (reservations)
  - AJAX cascade: tenant → api-key → engine → scopes
  - "Deploy" button is wired but hands off to a placeholder until Phase 4.
"""
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps
from ipaddress import ip_address, ip_network
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app, jsonify,
)

from shared.db import db
from webapp.models import (
    ApiKey, DhcpActivityLog, DhcpDeployment, DhcpEngineCredential,
    DhcpEngineSshAccess, DhcpReservation, DhcpScope, Tenant,
)
from webapp.smc_dhcp_client import (
    SMCConfig, smc_session,
    DhcpHostView, DhcpScopeInfo,
    list_scopes_for_engine, list_cluster_nodes, dump_engine_interfaces,
    is_node_initiated_contact,
    host_create, host_update, host_delete, host_get, host_list_by_scope,
    is_valid_mac, normalize_mac,
    find_ssh_access_rule, find_active_policy,
)
from webapp.smc_tls_client import list_engines, smc_error_detail
from webapp.dhcp_ssh import (
    SSHTarget, SSHCredential, FingerprintMismatch,
    verify_credential, is_auth_failure,
    get_file as ssh_get_file,
)
from webapp.dhcp_bootstrap import (
    engine_bootstrap_lock,
    probe_public_ip, preflight, install_ssh_rule, upload_policy,
    remove_rule, enroll_node, force_reset_password,
    rule_name_for,
)
from webapp.dhcp_leases import parse_dhcpd_leases, merge_cluster_leases

log = logging.getLogger(__name__)

dhcp_bp = Blueprint("dhcp", __name__, url_prefix="/dhcp")


# ── Access control ──────────────────────────────────────────────────────

def admin_required(f):
    """Require authenticated user with admin role (mirrors TLS Manager)."""
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
        if auth[7:] != current_app.config.get("DHCP_API_TOKEN"):
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated


def _log_activity(category: str, action: str, status: str,
                  target: str = "", detail: str = ""):
    db.session.add(DhcpActivityLog(
        category=category, action=action, status=status,
        target=target, detail=(detail or "")[:4000],
    ))
    db.session.commit()


def _smc_cfg(tenant: Tenant, api_key: ApiKey) -> SMCConfig:
    return SMCConfig(
        url=tenant.smc_url,
        api_key=api_key.decrypted_key,
        domain=tenant.default_domain or "",
        api_version=tenant.api_version or "",
        verify_ssl=tenant.verify_ssl,
        timeout=tenant.timeout,
    )


def _scope_or_404(scope_id: int) -> DhcpScope:
    scope = db.session.get(DhcpScope, scope_id)
    if not scope:
        flash("Scope not found.", "danger")
        return None
    return scope


# ── Initialization ──────────────────────────────────────────────────────

def init_dhcp_manager(app):
    """Ensure the Bearer token for webhook endpoints exists on disk.

    Matches the TLS Manager's `/config/.tls_api_token` convention, but with a
    separate token so DHCP and TLS scopes can be rotated independently.
    """
    token_file = Path(app.config.get("CONFIG_DIR", "/config")) / ".dhcp_api_token"
    if token_file.exists():
        app.config["DHCP_API_TOKEN"] = token_file.read_text().strip()
    else:
        token = secrets.token_urlsafe(32)
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token)
        try:
            token_file.chmod(0o600)
        except Exception:
            pass
        app.config["DHCP_API_TOKEN"] = token


# ── Dashboard ───────────────────────────────────────────────────────────

@dhcp_bp.route("/")
@admin_required
def dashboard():
    scopes = DhcpScope.query.order_by(DhcpScope.engine_name, DhcpScope.interface_id).all()
    activity_logs = (DhcpActivityLog.query
                     .order_by(DhcpActivityLog.created_at.desc()).limit(50).all())
    reservation_counts = {
        s.id: s.reservations.count() for s in scopes
    }
    out_of_sync = {
        s.id: s.reservations.filter(DhcpReservation.status != "synced").count()
        for s in scopes
    }

    # Credential / cluster summary stats
    creds = DhcpEngineCredential.query.all()
    accesses = DhcpEngineSshAccess.query.all()
    enrolled_engines = {(c.tenant_id, c.engine_name) for c in creds}
    healthy_creds = sum(1 for c in creds if c.last_verify_status == "ok")
    unhealthy_creds = sum(1 for c in creds if c.last_verify_status == "failed")

    return render_template(
        "dhcp/dashboard.html",
        scopes=scopes,
        reservation_counts=reservation_counts,
        out_of_sync=out_of_sync,
        activity_logs=activity_logs,
        creds=creds,
        accesses=accesses,
        enrolled_engine_count=len(enrolled_engines),
        total_credential_count=len(creds),
        healthy_cred_count=healthy_creds,
        unhealthy_cred_count=unhealthy_creds,
        ssh_rule_count=len(accesses),
    )


# ── Scopes ──────────────────────────────────────────────────────────────

@dhcp_bp.route("/scopes")
@admin_required
def scopes_list():
    scopes = DhcpScope.query.order_by(DhcpScope.engine_name, DhcpScope.interface_id).all()
    tenants = Tenant.query.filter_by(is_active=True).order_by(Tenant.name).all()
    return render_template("dhcp/scopes.html", scopes=scopes, tenants=tenants)


@dhcp_bp.route("/scopes/discover", methods=["POST"])
@admin_required
def scopes_discover():
    """Enumerate DHCP-enabled interfaces on a given engine + upsert them."""
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        flash("Tenant or API key not found.", "danger")
        return redirect(url_for("dhcp.scopes_list"))

    cfg = _smc_cfg(tenant, api_key)
    target = f"{tenant.name}/{api_key.name}/{engine_name}"
    try:
        with smc_session(cfg):
            found = list_scopes_for_engine(engine_name)

        added, updated = 0, 0
        now = datetime.now(timezone.utc)
        for info in found:
            existing = DhcpScope.query.filter_by(
                tenant_id=tenant.id,
                engine_name=engine_name,
                interface_id=info.interface_id,
            ).first()
            if existing:
                existing.api_key_id = api_key.id
                existing.interface_label = info.interface_label or existing.interface_label
                existing.subnet_cidr = info.subnet_cidr or existing.subnet_cidr
                existing.gateway = info.gateway or existing.gateway
                existing.dhcp_pool_start = info.dhcp_pool_start or existing.dhcp_pool_start
                existing.dhcp_pool_end = info.dhcp_pool_end or existing.dhcp_pool_end
                existing.last_synced_from_smc_at = now
                updated += 1
            else:
                db.session.add(DhcpScope(
                    tenant_id=tenant.id,
                    api_key_id=api_key.id,
                    engine_name=engine_name,
                    interface_id=info.interface_id,
                    interface_label=info.interface_label,
                    subnet_cidr=info.subnet_cidr,
                    gateway=info.gateway,
                    dhcp_pool_start=info.dhcp_pool_start,
                    dhcp_pool_end=info.dhcp_pool_end,
                    enabled_in_flexedge=False,
                    last_synced_from_smc_at=now,
                ))
                added += 1
        db.session.commit()
        _log_activity("scope", "discover", "ok", target,
                      f"Found {len(found)} scope(s); added {added}, updated {updated}.")
        if found:
            flash(f"Discovered {len(found)} scope(s) on {engine_name} "
                  f"({added} new, {updated} updated).", "success")
        else:
            flash(f"No DHCP-enabled scopes found on {engine_name}. "
                  f"If you expected some, hit the diagnostic endpoint "
                  f"/dhcp/api/tenants/{tenant.id}/api-keys/{api_key.id}/"
                  f"engines/{engine_name}/interfaces/debug to inspect the "
                  f"raw SMC JSON and file an update to the parser.",
                  "warning")
    except Exception as exc:
        db.session.rollback()
        _log_activity("scope", "discover", "failed", target, smc_error_detail(exc))
        flash(f"Discovery failed: {exc}", "danger")
    return redirect(url_for("dhcp.scopes_list"))


@dhcp_bp.route("/scopes/<int:scope_id>/enable", methods=["POST"])
@admin_required
def scope_enable(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    scope.enabled_in_flexedge = True
    db.session.commit()
    _log_activity("scope", "enable", "ok",
                  f"{scope.engine_name}/{scope.interface_id}", scope.subnet_cidr)
    flash(f"Scope {scope.subnet_cidr} enabled.", "success")
    return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))


@dhcp_bp.route("/scopes/<int:scope_id>/disable", methods=["POST"])
@admin_required
def scope_disable(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    scope.enabled_in_flexedge = False
    db.session.commit()
    _log_activity("scope", "disable", "ok",
                  f"{scope.engine_name}/{scope.interface_id}", scope.subnet_cidr)
    flash(f"Scope {scope.subnet_cidr} disabled.", "info")
    return redirect(url_for("dhcp.scopes_list"))


@dhcp_bp.route("/scopes/<int:scope_id>/delete", methods=["POST"])
@admin_required
def scope_delete(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    target = f"{scope.engine_name}/{scope.interface_id}"
    cidr = scope.subnet_cidr
    db.session.delete(scope)
    db.session.commit()
    _log_activity("scope", "delete", "ok", target, cidr)
    flash(f"Scope {cidr} deleted from FlexEdge tracking (SMC is untouched).", "info")
    return redirect(url_for("dhcp.scopes_list"))


@dhcp_bp.route("/scopes/<int:scope_id>")
@admin_required
def scope_detail(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    reservations = (DhcpReservation.query
                    .filter_by(scope_id=scope.id)
                    .order_by(DhcpReservation.ip_address).all())
    recent_deploys = (DhcpDeployment.query
                      .filter_by(scope_id=scope.id)
                      .order_by(DhcpDeployment.created_at.desc()).limit(10).all())
    return render_template(
        "dhcp/scope_detail.html",
        scope=scope,
        reservations=reservations,
        recent_deploys=recent_deploys,
    )


@dhcp_bp.route("/scopes/<int:scope_id>/sync", methods=["POST"])
@admin_required
def scope_sync_hosts(scope_id):
    """Reconcile DhcpReservation rows with Host elements in SMC for this scope.

    Walks every Host whose address falls inside the scope CIDR, reads the
    MAC marker from the comment, and upserts a DhcpReservation row. Hosts
    without a marker are ignored (they're normal hosts, not reservations).
    Local rows whose Host disappeared are flagged status='error'.
    """
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    tenant = db.session.get(Tenant, scope.tenant_id)
    api_key = db.session.get(ApiKey, scope.api_key_id)
    cfg = _smc_cfg(tenant, api_key)
    target = f"{scope.engine_name}/{scope.interface_id} {scope.subnet_cidr}"

    try:
        with smc_session(cfg):
            hosts = host_list_by_scope(scope.subnet_cidr)
        known_names = set()
        added, updated = 0, 0
        for h in hosts:
            if not h.mac_address:
                continue  # not a reservation
            known_names.add(h.name)
            res = DhcpReservation.query.filter_by(
                scope_id=scope.id, smc_host_name=h.name,
            ).first()
            if res:
                changed = (res.ip_address != h.address
                           or res.mac_address != h.mac_address
                           or res.smc_host_href != h.href)
                res.ip_address = h.address
                res.mac_address = h.mac_address
                res.smc_host_href = h.href
                if changed:
                    res.status = "out_of_sync"
                updated += 1
            else:
                db.session.add(DhcpReservation(
                    scope_id=scope.id,
                    smc_host_name=h.name,
                    smc_host_href=h.href,
                    ip_address=h.address,
                    mac_address=h.mac_address,
                    status="out_of_sync",
                ))
                added += 1

        # Stale rows → Host disappeared from SMC
        for res in DhcpReservation.query.filter_by(scope_id=scope.id).all():
            if res.smc_host_name not in known_names:
                res.status = "error"
                res.last_error = "Host no longer present in SMC"

        db.session.commit()
        _log_activity("scope", "sync_hosts", "ok", target,
                      f"added={added}, updated={updated}")
        flash(f"Synced {added + updated} reservation(s) from SMC "
              f"({added} new, {updated} updated).", "success")
    except Exception as exc:
        db.session.rollback()
        _log_activity("scope", "sync_hosts", "failed", target, smc_error_detail(exc))
        flash(f"Sync failed: {exc}", "danger")
    return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))


# ── Reservations (Host CRUD) ─────────────────────────────────────────────

@dhcp_bp.route("/scopes/<int:scope_id>/reservations/new", methods=["GET", "POST"])
@admin_required
def reservation_new(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    if request.method == "GET":
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=None, host_view=None)

    name = request.form["name"].strip()
    address = request.form["address"].strip()
    mac = request.form["mac_address"].strip()
    ipv6 = request.form.get("ipv6_address", "").strip()
    secondary_raw = request.form.get("secondary", "").strip()
    secondary = [s.strip() for s in secondary_raw.split(",") if s.strip()]
    comment = request.form.get("comment", "").strip()
    tools_profile_ref = request.form.get("tools_profile_ref", "").strip()

    # Validation
    errors = _validate_reservation(scope, name, address, mac, ipv6, secondary,
                                   exclude_reservation_id=None)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template(
            "dhcp/reservation_form.html",
            scope=scope, reservation=None, host_view=None,
            form_values=request.form,
        )

    mac_norm = normalize_mac(mac)
    tenant = db.session.get(Tenant, scope.tenant_id)
    api_key = db.session.get(ApiKey, scope.api_key_id)
    cfg = _smc_cfg(tenant, api_key)
    target = f"{scope.engine_name}/{scope.interface_id}/{name}"

    try:
        with smc_session(cfg):
            view = host_create(
                name=name, address=address, mac_address=mac_norm,
                ipv6_address=ipv6, secondary=secondary,
                tools_profile_ref=tools_profile_ref, comment=comment,
            )

        res = DhcpReservation(
            scope_id=scope.id,
            smc_host_name=view.name,
            smc_host_href=view.href,
            ip_address=view.address,
            mac_address=mac_norm,
            status="pending",
        )
        db.session.add(res)
        db.session.commit()
        _log_activity("reservation", "create", "ok", target,
                      f"MAC={mac_norm} IP={address}")
        flash(f"Reservation {name} created.", "success")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))
    except Exception as exc:
        db.session.rollback()
        _log_activity("reservation", "create", "failed", target, smc_error_detail(exc))
        flash(f"Create failed: {exc}", "danger")
        return render_template(
            "dhcp/reservation_form.html",
            scope=scope, reservation=None, host_view=None,
            form_values=request.form,
        )


@dhcp_bp.route("/reservations/<int:reservation_id>/edit", methods=["GET", "POST"])
@admin_required
def reservation_edit(reservation_id):
    res = db.session.get(DhcpReservation, reservation_id)
    if not res:
        flash("Reservation not found.", "danger")
        return redirect(url_for("dhcp.scopes_list"))
    scope = res.scope
    tenant = db.session.get(Tenant, scope.tenant_id)
    api_key = db.session.get(ApiKey, scope.api_key_id)
    cfg = _smc_cfg(tenant, api_key)

    host_view = None
    try:
        with smc_session(cfg):
            host_view = host_get(res.smc_host_name)
    except Exception as exc:
        flash(f"Could not read Host from SMC: {exc}", "warning")

    if request.method == "GET":
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=res, host_view=host_view)

    address = request.form["address"].strip()
    mac = request.form["mac_address"].strip()
    ipv6 = request.form.get("ipv6_address", "").strip()
    secondary_raw = request.form.get("secondary", "").strip()
    secondary = [s.strip() for s in secondary_raw.split(",") if s.strip()]
    comment = request.form.get("comment", "").strip()
    tools_profile_ref = request.form.get("tools_profile_ref", "").strip()

    errors = _validate_reservation(scope, res.smc_host_name, address, mac,
                                   ipv6, secondary,
                                   exclude_reservation_id=res.id)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=res, host_view=host_view,
                               form_values=request.form)

    mac_norm = normalize_mac(mac)
    target = f"{scope.engine_name}/{scope.interface_id}/{res.smc_host_name}"

    try:
        with smc_session(cfg):
            view = host_update(
                name=res.smc_host_name,
                address=address, ipv6_address=ipv6, secondary=secondary,
                tools_profile_ref=tools_profile_ref, comment=comment,
                mac_address=mac_norm,
            )
        res.ip_address = view.address
        res.mac_address = mac_norm
        res.smc_host_href = view.href
        res.status = "out_of_sync"      # needs re-deploy to engine
        db.session.commit()
        _log_activity("reservation", "update", "ok", target,
                      f"MAC={mac_norm} IP={address}")
        flash(f"Reservation {res.smc_host_name} updated.", "success")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))
    except Exception as exc:
        db.session.rollback()
        _log_activity("reservation", "update", "failed", target, smc_error_detail(exc))
        flash(f"Update failed: {exc}", "danger")
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=res, host_view=host_view,
                               form_values=request.form)


@dhcp_bp.route("/reservations/<int:reservation_id>/delete", methods=["POST"])
@admin_required
def reservation_delete(reservation_id):
    res = db.session.get(DhcpReservation, reservation_id)
    if not res:
        flash("Reservation not found.", "danger")
        return redirect(url_for("dhcp.scopes_list"))

    scope_id = res.scope_id
    scope = res.scope
    tenant = db.session.get(Tenant, scope.tenant_id)
    api_key = db.session.get(ApiKey, scope.api_key_id)
    cfg = _smc_cfg(tenant, api_key)

    also_delete_host = bool(request.form.get("delete_host"))
    target = f"{scope.engine_name}/{scope.interface_id}/{res.smc_host_name}"

    if also_delete_host:
        try:
            with smc_session(cfg):
                host_delete(res.smc_host_name)
        except Exception as exc:
            _log_activity("reservation", "delete_host", "failed", target,
                          smc_error_detail(exc))
            flash(f"SMC Host delete failed: {exc}", "warning")

    db.session.delete(res)
    db.session.commit()
    _log_activity("reservation", "delete", "ok", target,
                  f"host_deleted={also_delete_host}")
    flash("Reservation removed.", "info")
    return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))


# ── Deploy (stub — full implementation lands with Phase 4) ───────────────

@dhcp_bp.route("/scopes/<int:scope_id>/deploy", methods=["POST"])
@admin_required
def scope_deploy(scope_id):
    return _run_push(scope_id, action="push")


@dhcp_bp.route("/scopes/<int:scope_id>/resync", methods=["POST"])
@admin_required
def scope_resync(scope_id):
    """Manual re-sync button.

    Per operator preference (Phase 3 plan question 3), the sync loop is
    operator-triggered via this button instead of a post-policy-upload
    webhook. Phase 4 — same path as deploy, just a different audit action.
    """
    return _run_push(scope_id, action="resync")


def _run_push(scope_id: int, action: str):
    """Shared deploy/resync handler — orchestrates the SSH push and
    surfaces results as flash messages + activity-log rows.
    """
    from webapp.dhcp_pusher import push_scope_to_engine

    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    target = f"{scope.engine_name}/{scope.interface_id}"
    operator = _operator_email()

    _log_activity("deploy", action, "info", target,
                  f"{action.capitalize()} starting for scope {scope.id}.")

    result = push_scope_to_engine(scope.id, operator, action=action)

    if result.overall_status == "blocked":
        flash(f"Deployment blocked: {result.blocked_reason}", "warning")
        _log_activity("deploy", action, "blocked", target,
                      f"Blocked: {result.blocked_reason}")
    elif result.overall_status == "ok":
        flash(f"Deploy succeeded on all {result.successful_nodes} node(s). "
              f"Pushed {result.nodes[0].reservations_count if result.nodes else 0} "
              f"reservation(s).", "success")
        _log_activity("deploy", action, "ok", target,
                      f"OK on {result.successful_nodes}/{len(result.nodes)} nodes.")
    elif result.overall_status == "partial":
        failed = ", ".join(f"node {n.node_index}: {n.error}"
                           for n in result.nodes if n.status != "ok")
        flash(f"Partial success: {result.successful_nodes}/{len(result.nodes)} "
              f"nodes pushed. Failures: {failed}", "warning")
        _log_activity("deploy", action, "partial", target,
                      f"Partial: {result.successful_nodes}/{len(result.nodes)} "
                      f"OK. Failures: {failed}")
    else:
        failed = "; ".join(f"node {n.node_index}: {n.error}"
                           for n in result.nodes) or "no nodes attempted"
        flash(f"Deploy failed on all nodes. {failed}", "danger")
        _log_activity("deploy", action, "failed", target,
                      f"Failed on all nodes: {failed}")

    # Surface any reload warnings as additional flashes.
    for n in result.nodes:
        if n.reload_warning:
            flash(f"Node {n.node_index}: dhcpd reload warning — "
                  f"{n.reload_warning}", "warning")

    return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))


# ── SSH credentials (Phase 1c — auto-enrollment via SMC API) ────────────

def _cred_to_target(cred_row: DhcpEngineCredential) -> SSHTarget:
    return SSHTarget(hostname=cred_row.hostname, port=cred_row.ssh_port,
                     username=cred_row.ssh_username)


def _cred_to_payload(cred_row: DhcpEngineCredential) -> SSHCredential:
    return SSHCredential(
        password=cred_row.encrypted_password,
        host_fingerprint=cred_row.host_fingerprint,
    )


def _operator_email() -> str:
    return (session.get("user") or {}).get("email", "")


def _audit_comment(action: str, engine_name: str = "") -> str:
    op = _operator_email() or "unknown"
    suffix = f" engine={engine_name}" if engine_name else ""
    return f"FlexEdgeAdmin {action} by {op}{suffix}"


@dhcp_bp.route("/credentials", methods=["GET"])
@admin_required
def credentials_list():
    creds = (DhcpEngineCredential.query
             .order_by(DhcpEngineCredential.engine_name,
                       DhcpEngineCredential.node_index).all())
    accesses = (DhcpEngineSshAccess.query
                .order_by(DhcpEngineSshAccess.engine_name).all())
    tenants = Tenant.query.filter_by(is_active=True).order_by(Tenant.name).all()
    # Group credentials by (tenant, engine) for the per-engine UI
    creds_by_engine: dict[tuple[int, str], list] = {}
    for c in creds:
        creds_by_engine.setdefault((c.tenant_id, c.engine_name), []).append(c)
    accesses_by_engine = {(a.tenant_id, a.engine_name): a for a in accesses}
    return render_template(
        "dhcp/credentials.html",
        credentials=creds,
        creds_by_engine=creds_by_engine,
        accesses_by_engine=accesses_by_engine,
        tenants=tenants,
    )


# ── Source-IP detection ────────────────────────────────────────────────

@dhcp_bp.route("/credentials/source-ip/probe", methods=["POST"])
@admin_required
def credentials_probe_source_ip():
    """AJAX: try public-IP echo services and return the suggestion +
    attempt log so the operator can see what we tried."""
    detected, log_lines = probe_public_ip()
    return jsonify({"detected": detected or "", "attempts": log_lines})


@dhcp_bp.route("/tenants/<int:tenant_id>/source-ip", methods=["POST"])
@admin_required
def tenant_save_source_ip(tenant_id):
    tenant = db.session.get(Tenant, tenant_id)
    if not tenant:
        flash("Tenant not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    new_ip = request.form.get("source_ip", "").strip()
    if new_ip:
        # Validate
        from ipaddress import ip_address
        try:
            ip_address(new_ip)
        except ValueError:
            flash(f"Invalid IP {new_ip!r}.", "danger")
            return redirect(url_for("dhcp.credentials_list"))
    tenant.flexedge_source_ip = new_ip
    db.session.commit()
    _log_activity("system", "set_source_ip", "ok", tenant.name,
                  f"flexedge_source_ip={new_ip!r}")
    flash(f"Saved FEA source IP for {tenant.name}: {new_ip or '(empty)'}", "success")
    return redirect(url_for("dhcp.credentials_list"))


# ── Discover nodes (cascade to populate the wizard) ────────────────────

@dhcp_bp.route("/credentials/discover-nodes", methods=["POST"])
@admin_required
def credentials_discover_nodes():
    """AJAX: given tenant+key+engine, return cluster node list + interface
    IPs + current SSH-rule state so the operator can pick a destination IP
    and decide whether to install a rule.
    """
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    if not tenant.flexedge_source_ip:
        return jsonify({"error": (
            f"Tenant {tenant.name!r} has no FlexEdge source IP configured. "
            f"Set it first using the 'Source IP' card at the top of the page."
        )}), 400
    cfg = _smc_cfg(tenant, api_key)
    try:
        with smc_session(cfg):
            nodes = list_cluster_nodes(engine_name)
            node_initiated = is_node_initiated_contact(engine_name)
            try:
                policy_name = find_active_policy(engine_name)
            except Exception as exc:
                policy_name = ""
                policy_error = str(exc)
            else:
                policy_error = ""
            rule_present = False
            if policy_name:
                rule_present = find_ssh_access_rule(policy_name, rule_name_for(engine_name)) is not None
        existing_creds = {
            c.node_id: c
            for c in DhcpEngineCredential.query
                .filter_by(tenant_id=tenant_id, engine_name=engine_name).all()
        }
        access_row = DhcpEngineSshAccess.query.filter_by(
            tenant_id=tenant_id, engine_name=engine_name,
        ).first()

        out_nodes = []
        for n in nodes:
            enrolled = existing_creds.get(n.node_id)
            # Per the operator spec:
            #   - node-initiated cluster → operator MUST pick from the
            #     candidate list (we don't auto-pick because primary_mgt
            #     may not be reachable from FEA).
            #   - SMC-initiated cluster → primary_mgt IP is the natural
            #     target (SMC reaches it, so FEA likely can too).
            candidates = [
                {
                    "address": a.address,
                    "interface_id": a.interface_id,
                    "network_value": a.network_value,
                    "is_primary_mgt": a.is_primary_mgt,
                    "is_outgoing": a.is_outgoing,
                } for a in n.addresses if a.address
            ]
            suggested = "" if node_initiated else n.primary_address
            out_nodes.append({
                "node_index": n.node_index,
                "node_id": n.node_id,
                "name": n.name,
                "smc_nodeid": n.nodeid,
                "primary_mgt_address": n.primary_address,
                "candidates": candidates,
                "suggested_address": suggested,
                "already_enrolled": enrolled is not None,
                "enrolled_hostname": enrolled.hostname if enrolled else "",
                "last_verify_status": enrolled.last_verify_status if enrolled else "",
            })

        # Aggregate destination-IP picker for the rule install:
        # node-initiated → all candidate IPs across the cluster
        # SMC-initiated  → just the primary_mgt IP per node
        rule_destinations = []
        seen = set()
        for n in nodes:
            if node_initiated:
                for a in n.addresses:
                    if a.address and a.address not in seen:
                        rule_destinations.append({
                            "address": a.address,
                            "label": f"node {n.node_index} ({n.name}) — {a.interface_id} — {a.address}"
                                     + (" [primary mgt]" if a.is_primary_mgt else ""),
                        })
                        seen.add(a.address)
            else:
                if n.primary_address and n.primary_address not in seen:
                    rule_destinations.append({
                        "address": n.primary_address,
                        "label": f"node {n.node_index} ({n.name}) — {n.primary_address} [primary mgt]",
                    })
                    seen.add(n.primary_address)

        return jsonify({
            "nodes": out_nodes,
            "node_initiated_contact": node_initiated,
            "rule_destinations": rule_destinations,
            "policy_name": policy_name,
            "policy_error": policy_error,
            "rule_name": rule_name_for(engine_name),
            "rule_present_in_policy": rule_present,
            "rule_db_record": {
                "destination_ip": access_row.destination_ip if access_row else "",
                "fea_source_ip": access_row.fea_source_ip if access_row else "",
                "created_by": access_row.created_by_email if access_row else "",
                "created_at": access_row.created_at.strftime("%Y-%m-%d %H:%M") if access_row else "",
            } if access_row else None,
            "rule_externally_removed": (
                access_row is not None and policy_name and not rule_present
            ),
            "tenant_source_ip": tenant.flexedge_source_ip,
        })
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


# ── SSH rule lifecycle (per engine) ────────────────────────────────────

@dhcp_bp.route("/credentials/rule/install", methods=["POST"])
@admin_required
def credentials_rule_install():
    """Install (or detect existing) the SSH allow rule + push policy.

    Accepts multiple destination IPs (one per cluster node) via either a
    repeated `destination_ip` form field or a single comma-separated
    `destination_ips`. The rule covers all of them so cluster nodes can be
    enrolled in one batch.
    """
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()

    # Multi-IP collection: prefer multi-valued `destination_ip` (browsers
    # send each checked checkbox), fall back to comma-separated CSV.
    raw_list = request.form.getlist("destination_ip")
    if not raw_list:
        csv = request.form.get("destination_ips", "")
        raw_list = [x.strip() for x in csv.split(",") if x.strip()]
    destination_ips = [ip.strip() for ip in raw_list if ip and ip.strip()]
    # Deduplicate while preserving order
    seen, dedup = set(), []
    for ip in destination_ips:
        if ip not in seen:
            seen.add(ip); dedup.append(ip)
    destination_ips = dedup
    if not destination_ips:
        flash("Pick at least one destination IP for the SSH rule.", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        flash("Tenant or API key not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    source_ip = tenant.flexedge_source_ip
    if not source_ip:
        flash("Tenant FEA source IP not configured.", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    cfg = _smc_cfg(tenant, api_key)
    target_label = f"{engine_name} ({len(destination_ips)} dest IP(s))"
    try:
        with engine_bootstrap_lock(engine_name):
            with smc_session(cfg):
                result = install_ssh_rule(
                    engine_name=engine_name,
                    source_ip=source_ip,
                    destination_ips=destination_ips,
                    created_by_email=_operator_email(),
                    fea_hostname=request.host or "",
                )
                if not result.ok:
                    _log_activity("ssh", "install_rule", "failed", target_label, result.error)
                    flash(f"Install rule failed: {result.error}", "danger")
                    return redirect(url_for("dhcp.credentials_list"))

                # Persist DB record. The model's destination_ip column
                # holds a comma-separated list (SQLite ignores VARCHAR
                # length, so it fits any reasonable cluster size).
                access = DhcpEngineSshAccess.query.filter_by(
                    tenant_id=tenant_id, engine_name=engine_name,
                ).first()
                now = datetime.now(timezone.utc)
                csv_dst = ",".join(destination_ips)
                if access:
                    access.api_key_id = api_key_id
                    access.policy_name = result.policy_name
                    access.rule_name = result.rule_name
                    access.rule_href = result.rule_href
                    access.fea_source_ip = source_ip
                    access.destination_ip = csv_dst
                    access.created_by_email = access.created_by_email or _operator_email()
                    access.last_seen_in_policy_at = now
                else:
                    db.session.add(DhcpEngineSshAccess(
                        tenant_id=tenant_id, api_key_id=api_key_id,
                        engine_name=engine_name,
                        policy_name=result.policy_name,
                        rule_name=result.rule_name,
                        rule_href=result.rule_href,
                        fea_source_ip=source_ip,
                        destination_ip=csv_dst,
                        created_by_email=_operator_email(),
                        last_seen_in_policy_at=now,
                    ))
                db.session.commit()

                if result.already_present:
                    flash(f"Rule {result.rule_name} already exists in policy "
                          f"{result.policy_name}. Skipping policy upload.",
                          "info")
                    _log_activity("ssh", "install_rule", "ok", target_label,
                                  f"already present: {result.rule_name}")
                    return redirect(url_for("dhcp.credentials_list"))

                # Push policy so the rule actually takes effect
                upload_ok, upload_msg = upload_policy(engine_name, result.policy_name)
                if not upload_ok:
                    _log_activity("ssh", "policy_upload", "failed", target_label, upload_msg)
                    flash(f"Rule created but policy upload failed: {upload_msg}", "danger")
                    return redirect(url_for("dhcp.credentials_list"))

                _log_activity("ssh", "install_rule", "ok", target_label,
                              f"rule={result.rule_name} policy={result.policy_name} "
                              f"upload={upload_msg}")
                flash(f"Installed rule {result.rule_name} in policy "
                      f"{result.policy_name} and uploaded.", "success")
    except Exception as exc:
        _log_activity("ssh", "install_rule", "failed", target_label, str(exc))
        flash(f"Install rule failed: {exc}", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/rule/remove", methods=["POST"])
@admin_required
def credentials_rule_remove():
    """Manual rule removal — operator-triggered.

    Refuses if any credentials still reference this engine. The auto-cleanup
    on last-credential-deletion path is in `credentials_delete`.
    """
    tenant_id = int(request.form["tenant_id"])
    engine_name = request.form["engine_name"].strip()
    access = DhcpEngineSshAccess.query.filter_by(
        tenant_id=tenant_id, engine_name=engine_name,
    ).first()
    if not access:
        flash("No managed SSH rule on record for this engine.", "info")
        return redirect(url_for("dhcp.credentials_list"))

    creds_remaining = DhcpEngineCredential.query.filter_by(
        tenant_id=tenant_id, engine_name=engine_name,
    ).count()
    if creds_remaining > 0:
        flash(f"Refusing to remove SSH rule: {creds_remaining} credential(s) "
              f"still depend on it. Delete them first.", "warning")
        return redirect(url_for("dhcp.credentials_list"))

    _do_rule_teardown(access)
    return redirect(url_for("dhcp.credentials_list"))


def _do_rule_teardown(access: DhcpEngineSshAccess) -> None:
    """Internal: remove our rule from policy, push policy, delete DB row.
    Used by manual removal AND last-credential-deletion auto cleanup.
    """
    tenant = db.session.get(Tenant, access.tenant_id)
    api_key = db.session.get(ApiKey, access.api_key_id)
    if not tenant or not api_key:
        flash("Tenant or API key gone — cannot remove rule from SMC; "
              "removing local record only.", "warning")
        db.session.delete(access)
        db.session.commit()
        return
    cfg = _smc_cfg(tenant, api_key)
    target = f"{access.engine_name} rule={access.rule_name}"
    try:
        with engine_bootstrap_lock(access.engine_name):
            with smc_session(cfg):
                ok, msg = remove_rule(access.engine_name, access.policy_name)
                if not ok:
                    _log_activity("ssh", "remove_rule", "failed", target, msg)
                    flash(f"Remove rule failed: {msg}", "danger")
                    return
                upload_ok, upload_msg = upload_policy(access.engine_name, access.policy_name)
                if not upload_ok:
                    _log_activity("ssh", "policy_upload", "failed", target, upload_msg)
                    flash(f"Rule removed but policy upload failed: {upload_msg}", "danger")
                    return
        db.session.delete(access)
        db.session.commit()
        _log_activity("ssh", "remove_rule", "ok", target,
                      f"removed + policy uploaded: {upload_msg}")
        flash(f"Removed rule {access.rule_name} and uploaded policy.", "success")
    except Exception as exc:
        _log_activity("ssh", "remove_rule", "failed", target, str(exc))
        flash(f"Remove rule failed: {exc}", "danger")


# ── Per-node bootstrap (auto via SMC change_ssh_pwd) ───────────────────

@dhcp_bp.route("/credentials/bootstrap", methods=["POST"])
@admin_required
def credentials_bootstrap():
    """Enroll one node:
       1. TCP probe to verify path is open
       2. SMC: enable SSH on the node
       3. SMC: change_ssh_pwd to a fresh 64-char random
       4. SSH-connect with TOFU fingerprint capture
       5. Verify with the captured fingerprint pinned
       6. Persist the credential (password Fernet-encrypted)
    """
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()
    node_index = int(request.form["node_index"])
    node_id = request.form["node_id"].strip()
    node_name = request.form.get("node_name", "").strip()
    hostname = request.form["hostname"].strip()
    ssh_port = int(request.form.get("ssh_port", "22"))
    ssh_username = request.form.get("ssh_username", "root").strip() or "root"

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        flash("Tenant or API key not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    target = SSHTarget(hostname=hostname, port=ssh_port, username=ssh_username)
    cfg = _smc_cfg(tenant, api_key)
    target_label = f"{engine_name}/node{node_index}@{hostname}"
    audit = _audit_comment("auto-enrollment", engine_name)

    try:
        with engine_bootstrap_lock(engine_name):
            with smc_session(cfg):
                result = enroll_node(
                    engine_name=engine_name, node_index=node_index,
                    target=target, audit_comment=audit,
                )
        if not result.ok:
            _log_activity("ssh", f"bootstrap_{result.failed_at_stage}",
                          "failed", target_label, result.error)
            flash(f"Bootstrap failed at stage '{result.failed_at_stage}': "
                  f"{result.error}", "danger")
            return redirect(url_for("dhcp.credentials_list"))

        # Persist credential
        existing = DhcpEngineCredential.query.filter_by(
            tenant_id=tenant_id, engine_name=engine_name, node_id=node_id,
        ).first()
        now = datetime.now(timezone.utc)
        if existing:
            existing.api_key_id = api_key_id
            existing.node_index = node_index
            existing.node_name = node_name or existing.node_name
            existing.hostname = hostname
            existing.ssh_port = ssh_port
            existing.ssh_username = ssh_username
            existing.encrypted_password = result.new_password
            existing.host_fingerprint = result.host_fingerprint
            existing.last_verified_at = now
            existing.last_verify_status = "ok"
            existing.last_error = ""
        else:
            db.session.add(DhcpEngineCredential(
                tenant_id=tenant_id, api_key_id=api_key_id,
                engine_name=engine_name, node_index=node_index,
                node_id=node_id, node_name=node_name,
                hostname=hostname, ssh_port=ssh_port, ssh_username=ssh_username,
                encrypted_password=result.new_password,
                host_fingerprint=result.host_fingerprint,
                last_verified_at=now, last_verify_status="ok",
            ))
        db.session.commit()
        _log_activity("ssh", "bootstrap", "ok", target_label,
                      f"fingerprint={result.host_fingerprint}")
        flash(f"Enrolled {engine_name} node {node_index} ({hostname}). "
              f"Fingerprint: {result.host_fingerprint}", "success")
    except Exception as exc:
        _log_activity("ssh", "bootstrap", "failed", target_label, str(exc))
        flash(f"Bootstrap failed: {exc}", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/bootstrap-batch", methods=["POST"])
@admin_required
def credentials_bootstrap_batch():
    """Enroll multiple cluster nodes for one engine in a single transaction.

    Form data shape (one engine, N nodes):
      tenant_id, api_key_id, engine_name
      node_count
      node_<i>_index, node_<i>_id, node_<i>_name, node_<i>_hostname,
      node_<i>_ssh_port, node_<i>_ssh_username

    Aggregates per-node results, persists each successful credential, and
    returns a summary flash. The whole batch runs inside ONE smc_session
    and ONE per-engine lock acquisition — significantly faster than N
    sequential single-node calls.
    """
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()
    try:
        node_count = int(request.form.get("node_count", "0"))
    except ValueError:
        node_count = 0
    if node_count <= 0:
        flash("No nodes specified for batch enrollment.", "warning")
        return redirect(url_for("dhcp.credentials_list"))

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        flash("Tenant or API key not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    cfg = _smc_cfg(tenant, api_key)
    audit = _audit_comment("auto-enrollment (batch)", engine_name)

    # Pre-collect node specs from form (so we don't need form access inside the lock)
    specs: list[dict] = []
    for i in range(node_count):
        prefix = f"node_{i}_"
        host = request.form.get(prefix + "hostname", "").strip()
        if not host:
            continue
        try:
            specs.append({
                "node_index": int(request.form[prefix + "index"]),
                "node_id":    request.form.get(prefix + "id", "").strip(),
                "node_name":  request.form.get(prefix + "name", "").strip(),
                "hostname":   host,
                "port":       int(request.form.get(prefix + "ssh_port", "22")),
                "username":   request.form.get(prefix + "ssh_username", "root").strip() or "root",
            })
        except (KeyError, ValueError) as exc:
            _log_activity("ssh", "bootstrap_batch", "failed",
                          f"{engine_name}/node{i}", f"bad form data: {exc}")

    if not specs:
        flash("No valid node specs in batch.", "warning")
        return redirect(url_for("dhcp.credentials_list"))

    successes, failures = 0, 0
    detail_lines: list[str] = []

    try:
        with engine_bootstrap_lock(engine_name, timeout=180):
            with smc_session(cfg):
                for spec in specs:
                    target_label = f"{engine_name}/node{spec['node_index']}@{spec['hostname']}"
                    target = SSHTarget(hostname=spec["hostname"], port=spec["port"],
                                       username=spec["username"])
                    try:
                        result = enroll_node(
                            engine_name=engine_name,
                            node_index=spec["node_index"],
                            target=target, audit_comment=audit,
                        )
                    except Exception as exc:
                        failures += 1
                        detail_lines.append(f"node{spec['node_index']}: exception: {exc}")
                        _log_activity("ssh", "bootstrap", "failed", target_label, str(exc))
                        continue

                    if not result.ok:
                        failures += 1
                        detail_lines.append(
                            f"node{spec['node_index']}: failed at "
                            f"{result.failed_at_stage} — {result.error}"
                        )
                        _log_activity("ssh", f"bootstrap_{result.failed_at_stage}",
                                      "failed", target_label, result.error)
                        continue

                    # Persist this credential
                    existing = DhcpEngineCredential.query.filter_by(
                        tenant_id=tenant_id, engine_name=engine_name,
                        node_id=spec["node_id"],
                    ).first()
                    now = datetime.now(timezone.utc)
                    if existing:
                        existing.api_key_id = api_key_id
                        existing.node_index = spec["node_index"]
                        existing.node_name = spec["node_name"] or existing.node_name
                        existing.hostname = spec["hostname"]
                        existing.ssh_port = spec["port"]
                        existing.ssh_username = spec["username"]
                        existing.encrypted_password = result.new_password
                        existing.host_fingerprint = result.host_fingerprint
                        existing.last_verified_at = now
                        existing.last_verify_status = "ok"
                        existing.last_error = ""
                    else:
                        db.session.add(DhcpEngineCredential(
                            tenant_id=tenant_id, api_key_id=api_key_id,
                            engine_name=engine_name,
                            node_index=spec["node_index"],
                            node_id=spec["node_id"], node_name=spec["node_name"],
                            hostname=spec["hostname"], ssh_port=spec["port"],
                            ssh_username=spec["username"],
                            encrypted_password=result.new_password,
                            host_fingerprint=result.host_fingerprint,
                            last_verified_at=now, last_verify_status="ok",
                        ))
                    db.session.commit()
                    successes += 1
                    detail_lines.append(f"node{spec['node_index']}: ok ({result.host_fingerprint})")
                    _log_activity("ssh", "bootstrap", "ok", target_label,
                                  f"fingerprint={result.host_fingerprint}")
    except Exception as exc:
        _log_activity("ssh", "bootstrap_batch", "failed", engine_name, str(exc))
        flash(f"Batch enrollment aborted: {exc}", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    _log_activity("ssh", "bootstrap_batch",
                  "ok" if failures == 0 else ("partial" if successes else "failed"),
                  engine_name,
                  f"successes={successes} failures={failures}\n" + "\n".join(detail_lines))

    if successes and not failures:
        flash(f"Batch enrolled {successes} node(s) on {engine_name}.", "success")
    elif successes and failures:
        flash(f"Partial: {successes} succeeded, {failures} failed on {engine_name}. "
              f"See activity log for per-node detail.", "warning")
    else:
        flash(f"Batch enrollment failed for all {failures} node(s) on {engine_name}. "
              f"See activity log.", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/<int:cred_id>/verify", methods=["POST"])
@admin_required
def credentials_verify(cred_id):
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if not cred:
        flash("Credential not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    ok, err = verify_credential(_cred_to_target(cred), _cred_to_payload(cred))
    cred.last_verified_at = datetime.now(timezone.utc)
    cred.last_verify_status = "ok" if ok else "failed"
    cred.last_error = "" if ok else err
    db.session.commit()
    target_label = f"{cred.engine_name}/node{cred.node_index}@{cred.hostname}"
    _log_activity("ssh", "verify", "ok" if ok else "failed", target_label, err)
    if ok:
        flash(f"{cred.engine_name} node {cred.node_index} reachable.", "success")
    elif is_auth_failure(err):
        flash(f"Authentication failed for {target_label} — the password "
              f"may have been changed externally. Click 'Force re-bootstrap' "
              f"to issue a new password via SMC.", "danger")
    else:
        flash(f"Verification failed: {err}", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/<int:cred_id>/force-reset", methods=["POST"])
@admin_required
def credentials_force_reset(cred_id):
    """A3 recovery: rotate the password via SMC, re-verify, store the new one.

    Used when verify fails with auth-failure (someone changed root pw out
    of band). Operator-confirmed: a button on the credential row is the
    only trigger.
    """
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if not cred:
        flash("Credential not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    tenant = db.session.get(Tenant, cred.tenant_id)
    api_key = db.session.get(ApiKey, cred.api_key_id)
    if not tenant or not api_key:
        flash("Tenant or API key gone.", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    cfg = _smc_cfg(tenant, api_key)
    target = _cred_to_target(cred)
    target_label = f"{cred.engine_name}/node{cred.node_index}@{cred.hostname}"

    try:
        with engine_bootstrap_lock(cred.engine_name):
            with smc_session(cfg):
                result = force_reset_password(
                    engine_name=cred.engine_name,
                    node_index=cred.node_index,
                    target=target,
                    existing_fingerprint=cred.host_fingerprint,
                    audit_comment=_audit_comment("force-reset", cred.engine_name),
                )
        if not result.ok:
            _log_activity("ssh", "force_reset", "failed", target_label, result.error)
            flash(f"Force re-bootstrap failed at '{result.failed_at_stage}': "
                  f"{result.error}", "danger")
            return redirect(url_for("dhcp.credentials_list"))

        cred.encrypted_password = result.new_password
        if result.host_fingerprint:
            cred.host_fingerprint = result.host_fingerprint
        cred.last_verified_at = datetime.now(timezone.utc)
        cred.last_verify_status = "ok"
        cred.last_error = ""
        db.session.commit()
        _log_activity("ssh", "force_reset", "ok", target_label,
                      f"fingerprint={cred.host_fingerprint}")
        flash(f"Password rotated and verified on {target_label}.", "success")
    except Exception as exc:
        _log_activity("ssh", "force_reset", "failed", target_label, str(exc))
        flash(f"Force re-bootstrap failed: {exc}", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/<int:cred_id>/delete", methods=["POST"])
@admin_required
def credentials_delete(cred_id):
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if not cred:
        flash("Credential not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    target_label = f"{cred.engine_name}/node{cred.node_index}@{cred.hostname}"
    tenant_id = cred.tenant_id
    engine_name = cred.engine_name
    db.session.delete(cred)
    db.session.commit()
    _log_activity("ssh", "delete", "ok", target_label,
                  "Local credential removed. Note: the rotated password is still "
                  "set on the node — re-bootstrap to rotate again.")
    flash(f"Credential removed for {target_label}.", "info")

    # Auto-cleanup: if no credentials remain for this engine, tear down the SSH rule
    remaining = DhcpEngineCredential.query.filter_by(
        tenant_id=tenant_id, engine_name=engine_name,
    ).count()
    if remaining == 0:
        access = DhcpEngineSshAccess.query.filter_by(
            tenant_id=tenant_id, engine_name=engine_name,
        ).first()
        if access:
            flash(f"Last credential for {engine_name} removed — tearing down "
                  f"the SSH allow rule {access.rule_name}.", "info")
            _do_rule_teardown(access)
    return redirect(url_for("dhcp.credentials_list"))


# ── Leases viewer (Phase 1b) ─────────────────────────────────────────────

LEASE_FILE = "/spool/dhcp-server/dhcpd.leases"


@dhcp_bp.route("/scopes/<int:scope_id>/leases")
@admin_required
def scope_leases(scope_id):
    """Read dhcpd.leases from every enrolled node for this scope's engine,
    parse, merge, and display the consolidated view.

    One row per (MAC, IP) pair, with which nodes saw the lease. Cross-checks
    against reservations so the UI can flag a lease that deviates from its
    tracked reservation.
    """
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    creds = (DhcpEngineCredential.query
             .filter_by(tenant_id=scope.tenant_id,
                        engine_name=scope.engine_name)
             .order_by(DhcpEngineCredential.node_index).all())
    if not creds:
        flash(f"No SSH credentials enrolled for {scope.engine_name}. "
              f"Go to Credentials to enroll each cluster node first.", "warning")
        return redirect(url_for("dhcp.credentials_list"))

    reservations = (DhcpReservation.query.filter_by(scope_id=scope.id).all())
    res_by_mac = {r.mac_address: r for r in reservations}

    per_node_results: dict[int, list] = {}
    fetch_errors: dict[int, str] = {}
    for cred in creds:
        target = _cred_to_target(cred)
        payload = _cred_to_payload(cred)
        try:
            raw = ssh_get_file(target, payload, LEASE_FILE)
            per_node_results[cred.node_index] = parse_dhcpd_leases(raw.decode(errors="replace"))
            _log_activity("ssh", "read_leases", "ok",
                          f"{cred.engine_name}/node{cred.node_index}",
                          f"{len(per_node_results[cred.node_index])} lease blocks")
        except Exception as exc:
            fetch_errors[cred.node_index] = str(exc)
            _log_activity("ssh", "read_leases", "failed",
                          f"{cred.engine_name}/node{cred.node_index}", str(exc))

    merged = merge_cluster_leases(per_node_results) if per_node_results else []

    # Annotate each merged row with reservation cross-check
    for row in merged:
        match = res_by_mac.get(row["mac"])
        if match:
            row["reservation_id"] = match.id
            row["reservation_host"] = match.smc_host_name
            row["reservation_ip"] = match.ip_address
            row["reservation_matches"] = (match.ip_address == row["ip"])
        else:
            row["reservation_id"] = None
            row["reservation_host"] = ""
            row["reservation_ip"] = ""
            row["reservation_matches"] = None

    now = datetime.now(timezone.utc)
    return render_template(
        "dhcp/leases.html",
        scope=scope, leases=merged,
        nodes=creds, fetch_errors=fetch_errors,
        now=now, lease_file_path=LEASE_FILE,
    )


# ── History + activity ───────────────────────────────────────────────────

@dhcp_bp.route("/history")
@admin_required
def history():
    deployments = (DhcpDeployment.query
                   .order_by(DhcpDeployment.created_at.desc()).limit(200).all())
    return render_template("dhcp/history.html", deployments=deployments)


@dhcp_bp.route("/activity")
@admin_required
def activity():
    logs = (DhcpActivityLog.query
            .order_by(DhcpActivityLog.created_at.desc()).limit(500).all())
    return render_template("dhcp/activity.html", logs=logs)


# ── AJAX helpers ─────────────────────────────────────────────────────────

@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys")
@admin_required
def api_tenant_keys(tenant_id):
    keys = ApiKey.query.filter_by(tenant_id=tenant_id, is_active=True).all()
    return jsonify([{"id": k.id, "name": k.name} for k in keys])


@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines")
@admin_required
def api_tenant_engines(tenant_id, key_id):
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg(tenant, api_key)
    try:
        with smc_session(cfg):
            engines = list_engines()
        return jsonify(engines)
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/<engine_name>/interfaces/debug")
@admin_required
def api_engine_interfaces_debug(tenant_id, key_id, engine_name):
    """Return the raw physical_interface JSON plus what the parser extracted.

    Use this when scope discovery returns 0 to inspect the actual shape of
    the SMC API payload (it varies slightly between engine types / versions).
    """
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg(tenant, api_key)
    try:
        with smc_session(cfg):
            payload = dump_engine_interfaces(engine_name)
        return jsonify(payload)
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/<engine_name>/scopes")
@admin_required
def api_engine_scopes(tenant_id, key_id, engine_name):
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg(tenant, api_key)
    try:
        with smc_session(cfg):
            scopes = list_scopes_for_engine(engine_name)
            nodes = list_cluster_nodes(engine_name)
        return jsonify({
            "scopes": [
                {
                    "interface_id": s.interface_id,
                    "interface_label": s.interface_label,
                    "subnet_cidr": s.subnet_cidr,
                    "gateway": s.gateway,
                    "dhcp_pool_start": s.dhcp_pool_start,
                    "dhcp_pool_end": s.dhcp_pool_end,
                    "default_lease_time": s.default_lease_time,
                } for s in scopes
            ],
            "nodes": [
                {
                    "node_index": n.node_index,
                    "node_id": n.node_id,
                    "name": n.name,
                    "primary_address": n.primary_address,
                } for n in nodes
            ],
        })
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


# ── Validation ───────────────────────────────────────────────────────────

def _validate_reservation(scope, name, address, mac, ipv6, secondary,
                          exclude_reservation_id):
    errors: list[str] = []
    if not name:
        errors.append("Name is required.")
    if not address:
        errors.append("Address is required.")
    if not mac or not is_valid_mac(mac):
        errors.append("MAC address is required in the form aa:bb:cc:dd:ee:ff.")

    # IP in scope CIDR?
    if scope.subnet_cidr:
        try:
            net = ip_network(scope.subnet_cidr, strict=False)
            if address and ip_address(address) not in net:
                errors.append(
                    f"IP {address} is outside the scope CIDR {scope.subnet_cidr}."
                )
        except ValueError:
            pass

    # Secondary addresses
    for s in secondary:
        try:
            ip_address(s)
        except ValueError:
            errors.append(f"Invalid secondary IP: {s!r}.")

    # IPv6 optional
    if ipv6:
        try:
            ip_address(ipv6)
        except ValueError:
            errors.append(f"Invalid IPv6 address: {ipv6!r}.")

    # DB-level uniqueness in scope
    if not errors and mac:
        try:
            mac_norm = normalize_mac(mac)
        except ValueError:
            mac_norm = mac
        q = DhcpReservation.query.filter_by(scope_id=scope.id, mac_address=mac_norm)
        if exclude_reservation_id is not None:
            q = q.filter(DhcpReservation.id != exclude_reservation_id)
        if q.first():
            errors.append(f"MAC {mac_norm} is already reserved in this scope.")

        q2 = DhcpReservation.query.filter_by(scope_id=scope.id, ip_address=address)
        if exclude_reservation_id is not None:
            q2 = q2.filter(DhcpReservation.id != exclude_reservation_id)
        if q2.first():
            errors.append(f"IP {address} is already reserved in this scope.")

    return errors
