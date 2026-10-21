"""
FlexEdgeAdmin — NetSight (Extreme Site Engine) connection per Domain (RA-B,
docs/RemoteAgents.md § Data model).

Super-Admin CRUD at /admin/netsight/* plus a routing-aware "Test" button:
the Site Engine host is resolved to an IP and handed to
`shared.agent_router.pick_executor` by `webapp.netsight_objects.run_query`
(RA-C): "local" runs `NetSightClient.connect_check()` in the request thread,
"agent" enqueues a `netsight-query` task carrying a one-shot `secret_ref`
and waits for the result, "refused" surfaces the router's reason verbatim.

The client secret is Fernet-encrypted at rest (`EncryptedString`); on the
agent path it travels only through `GET /agent/secret` (single read, 60 s).
"""

import ipaddress
import logging
import re

from flask import Blueprint, flash, redirect, render_template, request, url_for

from shared.db import db
from shared.logging import audit, register_feature
from shared.netsight_client import normalise_fingerprint
from webapp.netsight_objects import NetSightUnavailable, invalidate_netsight, run_query_detailed
from webapp.auth_roles import super_admin_required
from webapp.models import Domain, NetSightConnection

log = logging.getLogger(__name__)

netsight_admin_bp = Blueprint("netsight_admin", __name__, url_prefix="/admin/netsight")

TEST_TIMEOUT_S = 10
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def init_netsight_manager(app):
    register_feature("netsight", "NetSight (Extreme Site Engine)")


def _valid_host(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))


def _domain_or_none(domain_id: int):
    domain = Domain.query.get(domain_id)
    if domain is None:
        flash("Unknown Domain.", "warning")
    return domain


# ── Routes ───────────────────────────────────────────────────────────────

@netsight_admin_bp.route("/")
@super_admin_required
def netsight_list():
    domains = Domain.query.order_by(Domain.display_name).all()
    conns = {c.domain_id: c for c in NetSightConnection.query.all()}
    items = [{"domain": d, "conn": conns.get(d.id)} for d in domains]
    return render_template("admin/netsight.html", items=items)


@netsight_admin_bp.route("/<int:domain_id>", methods=["GET", "POST"])
@super_admin_required
def netsight_edit(domain_id):
    domain = _domain_or_none(domain_id)
    if domain is None:
        return redirect(url_for("netsight_admin.netsight_list"))
    conn = NetSightConnection.query.filter_by(domain_id=domain.id).first()
    form = {
        "host": conn.host if conn else "",
        "port": str(conn.port if conn else 8443),
        "client_id": conn.client_id if conn else "",
        "cert_sha256": conn.cert_sha256 if conn else "",
    }
    if request.method == "POST":
        form = {k: (request.form.get(k) or "").strip() for k in form}
        secret = (request.form.get("client_secret") or "").strip()
        errors = []
        if not _valid_host(form["host"]):
            errors.append("Host must be a hostname or an IP address.")
        try:
            port = int(form["port"])
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            errors.append("Port must be between 1 and 65535.")
            port = 8443
        if not form["client_id"]:
            errors.append("Client ID is required.")
        fp = normalise_fingerprint(form["cert_sha256"])
        if not re.fullmatch(r"[0-9a-f]{64}", fp):
            errors.append("Certificate fingerprint is mandatory: 64 hex characters (SHA-256), "
                          "colons optional. FlexEdge pins the Site Engine certificate — there is "
                          "no web equivalent of the CLI's --insecure.")
        if conn is None and not secret:
            errors.append("Client secret is required for a new connection.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("admin/netsight_form.html", domain=domain, conn=conn, form=form)

        created = conn is None
        if created:
            conn = NetSightConnection(domain_id=domain.id)
            db.session.add(conn)
        conn.host = form["host"]
        conn.port = port
        conn.client_id = form["client_id"]
        conn.set_cert_sha256(fp)
        if secret:
            conn.client_secret = secret
        conn.last_error = ""
        db.session.commit()
        invalidate_netsight(domain)
        audit("netsight", "connection.save", target=domain.slug,
              detail=f"{conn.host}:{conn.port} client_id={conn.client_id} "
                     f"{'created' if created else 'updated'}"
                     f"{' secret rotated' if (secret and not created) else ''}",
              domain_id=domain.id)
        flash(f"NetSight connection for {domain.display_name} saved.", "success")
        return redirect(url_for("netsight_admin.netsight_list"))

    return render_template("admin/netsight_form.html", domain=domain, conn=conn, form=form)


@netsight_admin_bp.route("/<int:domain_id>/delete", methods=["POST"])
@super_admin_required
def netsight_delete(domain_id):
    domain = _domain_or_none(domain_id)
    if domain is None:
        return redirect(url_for("netsight_admin.netsight_list"))
    conn = NetSightConnection.query.filter_by(domain_id=domain.id).first()
    if conn is None:
        flash("No NetSight connection for that Domain.", "warning")
        return redirect(url_for("netsight_admin.netsight_list"))
    target = f"{conn.host}:{conn.port}"
    db.session.delete(conn)
    db.session.commit()
    invalidate_netsight(domain)
    audit("netsight", "connection.delete", target=domain.slug, detail=target,
          domain_id=domain.id)
    flash(f"NetSight connection for {domain.display_name} deleted.", "success")
    return redirect(url_for("netsight_admin.netsight_list"))


@netsight_admin_bp.route("/<int:domain_id>/test", methods=["POST"])
@super_admin_required
def netsight_test(domain_id):
    domain = _domain_or_none(domain_id)
    if domain is None:
        return redirect(url_for("netsight_admin.netsight_list"))
    conn = NetSightConnection.query.filter_by(domain_id=domain.id).first()
    if conn is None:
        flash("No NetSight connection for that Domain — create one first.", "warning")
        return redirect(url_for("netsight_admin.netsight_list"))
    back = redirect(url_for("netsight_admin.netsight_list"))
    target = f"{conn.host}:{conn.port}"

    try:
        res, decision = run_query_detailed(domain, "connect", timeout_s=TEST_TIMEOUT_S)
    except NetSightUnavailable as exc:
        flash(exc.reason, "warning" if exc.kind == "refused" else "danger")
        audit("netsight", "connection.test", target=domain.slug, status="error",
              detail=f"{target} {exc.kind}: {exc.reason}", domain_id=domain.id,
              source_correlation_id=exc.task_id)
        return back

    where = f"via agent {decision.agent_name}" if decision.kind == "agent" else "locally"
    roots = (res or {}).get("roots") or {}
    summary = ", ".join(f"{k}={v}" for k, v in roots.items()) or "no roots probed"
    if (res or {}).get("ok"):
        # run_query already stamped last_ok_at / last_error
        flash(f"NetSight {target} OK {where} in {res.get('elapsed_ms', 0)} ms — all NBI roots "
              f"readable ({', '.join(roots)}).", "success")
        audit("netsight", "connection.test", target=domain.slug, status="ok",
              detail=f"{target} {where} {res.get('elapsed_ms', 0)}ms {summary}",
              domain_id=domain.id)
    else:
        err = (res or {}).get("error") or "unknown error"
        flash(f"NetSight {target} test failed {where}: {err}", "danger")
        audit("netsight", "connection.test", target=domain.slug, status="error",
              detail=f"{target} {where}: {err} ({summary})", domain_id=domain.id)
    return back
