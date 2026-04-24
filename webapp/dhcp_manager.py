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
    ApiKey, DhcpActivityLog, DhcpDeployment, DhcpReservation,
    DhcpScope, Tenant,
)
from webapp.smc_dhcp_client import (
    SMCConfig, smc_session,
    DhcpHostView, DhcpScopeInfo,
    list_scopes_for_engine, list_cluster_nodes, dump_engine_interfaces,
    host_create, host_update, host_delete, host_get, host_list_by_scope,
    is_valid_mac, normalize_mac,
)
from webapp.smc_tls_client import list_engines, smc_error_detail

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
    return render_template(
        "dhcp/dashboard.html",
        scopes=scopes,
        reservation_counts=reservation_counts,
        out_of_sync=out_of_sync,
        activity_logs=activity_logs,
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
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    target = f"{scope.engine_name}/{scope.interface_id}"
    _log_activity("deploy", "push", "info", target,
                  "Deploy requested; awaiting Phase 4 (SSH deployer).")
    flash("Deploy is not wired yet — Phase 4 (SSH-based engine sync) is pending. "
          "Reservations are stored in SMC and ready for the deployer.", "warning")
    return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))


@dhcp_bp.route("/scopes/<int:scope_id>/resync", methods=["POST"])
@admin_required
def scope_resync(scope_id):
    """Manual re-sync button.

    Per operator preference (Phase 3 plan question 3), the sync loop is
    operator-triggered via this button instead of a post-policy-upload
    webhook. Phase 4 wires this to the actual deployer.
    """
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    target = f"{scope.engine_name}/{scope.interface_id}"
    _log_activity("deploy", "resync", "info", target,
                  "Re-sync requested; awaiting Phase 4 (SSH deployer).")
    flash("Re-sync queued. The engine-side sync runs once Phase 4 lands.",
          "warning")
    return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))


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
