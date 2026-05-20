"""HTTP routes for /engines/scans/* — engine scan history.

Phase 1 surface:
  GET  /engines/scans                       History list
  GET  /engines/scans/<id>                  Detail view
  POST /engines/scans/<id>/comment          Update comment
  POST /engines/scans/<id>/star             Toggle starred
  POST /engines/scans/<id>/delete           Hard delete
  POST /engines/scans/bulk-star             Multi-row star
  POST /engines/scans/bulk-delete           Multi-row delete
  POST /engines/scans/admin/sweep           Manual retention sweep
  POST /engines/scans/admin/settings        Update retention settings
  GET  /engines/scans/<id>.csv              CSV export of one scan

Phase 2/3/4 routes (compare / graph / schedules) are spec'd but not
yet implemented — see docs/Engines-ScanHistory.md.
"""

from __future__ import annotations

import csv
import logging
from functools import wraps
from io import StringIO

from flask import (
    Blueprint, Response, flash, g, jsonify, redirect, render_template,
    request, session, url_for,
)

from webapp.scan_history import service, retention, compare as compare_mod

log = logging.getLogger("scan_history.routes")

scan_history_bp = Blueprint(
    "scan_history",
    __name__,
    url_prefix="/engines/scans",
    template_folder="templates",
)


# ── Auth decorator (mirror engines_manager.profile_required_admin) ──

def profile_required_admin(f):
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


def _current_domain():
    return getattr(g, "domain", None)


def _user_email() -> str:
    return (session.get("user") or {}).get("email", "")


# ── History list ────────────────────────────────────────────────────────

@scan_history_bp.route("/", methods=["GET"])
@profile_required_admin
def history():
    """List scans for the active Domain. Filters via querystring."""
    domain = _current_domain()
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("engines.clusters"))

    # Lazy hourly retention sweep — best effort, runs only when due.
    retention.ensure_lazy_sweep(domain)

    engine_name = (request.args.get("engine") or "").strip() or None
    iface_label = (request.args.get("iface") or "").strip() or None
    starred_only = request.args.get("starred") == "1"
    try:
        since_days = int(request.args.get("days") or "0") or None
    except ValueError:
        since_days = None
    try:
        page = max(1, int(request.args.get("page") or "1"))
    except ValueError:
        page = 1
    page_size = 50
    offset = (page - 1) * page_size

    scans = service.list_scans(domain,
                               engine_name=engine_name,
                               iface_label=iface_label,
                               starred_only=starred_only,
                               since_days=since_days,
                               limit=page_size,
                               offset=offset)
    total = service.count_scans(domain,
                                engine_name=engine_name,
                                iface_label=iface_label,
                                starred_only=starred_only,
                                since_days=since_days)

    # Build the (engine, iface) facet for the filter dropdowns. Cheap —
    # one indexed query, distinct over the scope columns.
    from webapp.models import EngineScanRecord
    from sqlalchemy import distinct
    from shared.db import db
    facets_q = (db.session.query(
                    EngineScanRecord.engine_name,
                    EngineScanRecord.source_iface_label)
                .filter(EngineScanRecord.domain_id == domain.id)
                .distinct()
                .order_by(EngineScanRecord.engine_name.asc(),
                          EngineScanRecord.source_iface_label.asc()))
    facets = [{"engine": e, "iface": i} for e, i in facets_q.all()]

    settings = service.get_settings()
    return render_template(
        "scan_history/history.html",
        scans=scans,
        total=total,
        page=page,
        page_size=page_size,
        facets=facets,
        settings=settings,
        f_engine=engine_name or "",
        f_iface=iface_label or "",
        f_starred=starred_only,
        f_days=since_days or 0,
    )


# ── Detail ──────────────────────────────────────────────────────────────

@scan_history_bp.route("/<int:scan_id>", methods=["GET"])
@profile_required_admin
def detail(scan_id: int):
    domain = _current_domain()
    rec = service.get_scan(domain, scan_id)
    if rec is None:
        flash("Scan not found (or not in your active Domain).", "warning")
        return redirect(url_for("scan_history.history"))
    hosts = service.get_hosts(rec)

    # TODO #2: render port → service-name labels on each open-port badge.
    # Pulls from the cached SMC tcp/udp_services lists; empty dict on
    # any failure so the table still renders with bare port numbers.
    port_services_map: dict[int, str] = {}
    try:
        from webapp.engines_manager import resolve_port_services, _user_cfg
        domain_id = domain.id if domain else 0
        port_services_map = resolve_port_services(domain_id, _user_cfg())
    except Exception as exc:
        log.warning("port_services_map build failed: %s", exc)

    return render_template("scan_history/detail.html",
                           scan=rec, hosts=hosts,
                           port_services_map=port_services_map)


# ── Per-row mutators ────────────────────────────────────────────────────

@scan_history_bp.route("/<int:scan_id>/comment", methods=["POST"])
@profile_required_admin
def update_comment(scan_id: int):
    domain = _current_domain()
    comment = (request.form.get("comment") or "")[:4000]
    if service.set_comment(domain, scan_id, comment, _user_email()):
        flash("Comment updated.", "success")
    else:
        flash("Scan not found.", "warning")
    return redirect(url_for("scan_history.detail", scan_id=scan_id))


@scan_history_bp.route("/<int:scan_id>/star", methods=["POST"])
@profile_required_admin
def toggle_star(scan_id: int):
    domain = _current_domain()
    rec = service.get_scan(domain, scan_id)
    if rec is None:
        flash("Scan not found.", "warning")
        return redirect(url_for("scan_history.history"))
    new_state = not bool(rec.starred)
    service.set_starred(domain, scan_id, new_state, _user_email())
    flash(f"Scan #{scan_id} {'starred' if new_state else 'unstarred'}.", "info")
    nxt = request.form.get("next") or url_for("scan_history.detail", scan_id=scan_id)
    return redirect(nxt)


@scan_history_bp.route("/<int:scan_id>/delete", methods=["POST"])
@profile_required_admin
def delete(scan_id: int):
    domain = _current_domain()
    if service.delete_scan(domain, scan_id, _user_email()):
        flash(f"Scan #{scan_id} deleted.", "info")
    else:
        flash("Scan not found.", "warning")
    return redirect(url_for("scan_history.history"))


# ── Bulk ops ────────────────────────────────────────────────────────────

@scan_history_bp.route("/bulk-star", methods=["POST"])
@profile_required_admin
def bulk_star():
    domain = _current_domain()
    ids = [int(x) for x in request.form.getlist("scan_ids") if x.isdigit()]
    starred = request.form.get("action") != "unstar"
    n = service.bulk_set_starred(domain, ids, starred, _user_email())
    flash(f"{n} scan(s) {'starred' if starred else 'unstarred'}.", "info")
    return redirect(url_for("scan_history.history"))


@scan_history_bp.route("/bulk-delete", methods=["POST"])
@profile_required_admin
def bulk_delete():
    domain = _current_domain()
    ids = [int(x) for x in request.form.getlist("scan_ids") if x.isdigit()]
    n = service.bulk_delete(domain, ids, _user_email())
    flash(f"{n} scan(s) deleted.", "info")
    return redirect(url_for("scan_history.history"))


# ── Admin: retention ────────────────────────────────────────────────────

@scan_history_bp.route("/admin/sweep", methods=["POST"])
@profile_required_admin
def admin_sweep():
    domain = _current_domain()
    rep = retention.sweep_retention(domain)
    retention.mark_swept_now()
    flash(f"Retention sweep: deleted {rep.deleted}, kept {rep.kept_recent} "
          f"recent + {rep.kept_starred} starred (mode={rep.mode}, value={rep.value}).",
          "info")
    return redirect(url_for("scan_history.history"))


@scan_history_bp.route("/admin/settings", methods=["POST"])
@profile_required_admin
def admin_settings():
    mode = (request.form.get("mode") or "").strip().lower()
    raw_val = request.form.get("value") or "0"
    try:
        value = int(raw_val)
    except ValueError:
        flash("Retention value must be a positive integer.", "danger")
        return redirect(url_for("scan_history.history"))
    try:
        service.set_settings(mode, value, _user_email())
        flash(f"Retention updated: keep {value} {mode}.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("scan_history.history"))


# ── Compare (Phase 2) ───────────────────────────────────────────────────

@scan_history_bp.route("/compare", methods=["GET", "POST"])
@profile_required_admin
def compare():
    """Render a diff view across 2-10 scans of the same scope.

    Accepts scan IDs from either:
      - POST form `scan_ids[]` (from the bulk-action button on the
        history list — a normal form submit so the browser handles it),
      - GET querystring `ids=1,2,3` (deep-linkable).
    """
    domain = _current_domain()
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("engines.clusters"))

    if request.method == "POST":
        ids = [int(x) for x in request.form.getlist("scan_ids") if x.isdigit()]
    else:
        raw = request.args.get("ids") or ""
        ids = []
        for tok in raw.split(","):
            tok = tok.strip()
            if tok.isdigit():
                ids.append(int(tok))

    report = compare_mod.compare_scans(domain, ids)
    if report.error:
        flash(report.error, "warning")
        # Send the operator back to history with their previous filter intact
        # if they came in via a POST. GETs with a bad querystring also bounce.
        return redirect(url_for("scan_history.history"))

    from shared.logging import op
    op(service.FEATURE, "compare.view",
       target=f"{report.scope_engine}/{report.scope_iface}",
       detail=f"ids={','.join(str(s.id) for s in report.scans)}",
       user_email=_user_email())
    return render_template("scan_history/compare.html", report=report)


# ── Time graph (Phase 3) ────────────────────────────────────────────────

@scan_history_bp.route("/graph", methods=["GET"])
@profile_required_admin
def graph():
    """Render the time-series chart page. Filters drive both this page
    and the JSON feed below."""
    domain = _current_domain()
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("engines.clusters"))

    engine_name = (request.args.get("engine") or "").strip() or None
    iface_label = (request.args.get("iface") or "").strip() or None
    try:
        since_days = int(request.args.get("days") or "30") or None
    except ValueError:
        since_days = 30

    # Same facet query as the history list — feeds the dropdowns.
    from webapp.models import EngineScanRecord
    from shared.db import db
    facets_q = (db.session.query(
                    EngineScanRecord.engine_name,
                    EngineScanRecord.source_iface_label)
                .filter(EngineScanRecord.domain_id == domain.id)
                .distinct()
                .order_by(EngineScanRecord.engine_name.asc(),
                          EngineScanRecord.source_iface_label.asc()))
    facets = [{"engine": e, "iface": i} for e, i in facets_q.all()]

    from shared.logging import op
    op(service.FEATURE, "graph.view",
       target=f"{engine_name or '*'}/{iface_label or '*'}",
       detail=f"days={since_days}",
       user_email=_user_email())

    return render_template(
        "scan_history/graph.html",
        facets=facets,
        f_engine=engine_name or "",
        f_iface=iface_label or "",
        f_days=since_days or 30,
    )


@scan_history_bp.route("/graph.json", methods=["GET"])
@profile_required_admin
def graph_json():
    """JSON feed consumed by the inline SVG renderer on /graph."""
    domain = _current_domain()
    if domain is None:
        return jsonify({"error": "no active domain"}), 400
    engine_name = (request.args.get("engine") or "").strip() or None
    iface_label = (request.args.get("iface") or "").strip() or None
    try:
        since_days = int(request.args.get("days") or "30") or None
    except ValueError:
        since_days = 30
    points = service.aggregate_for_graph(
        domain,
        engine_name=engine_name,
        iface_label=iface_label,
        since_days=since_days,
    )
    return jsonify({
        "points": points,
        "engine": engine_name or "",
        "iface": iface_label or "",
        "since_days": since_days or 0,
    })


# ── CSV export ──────────────────────────────────────────────────────────

@scan_history_bp.route("/<int:scan_id>.csv", methods=["GET"])
@profile_required_admin
def export_csv(scan_id: int):
    domain = _current_domain()
    rec = service.get_scan(domain, scan_id)
    if rec is None:
        flash("Scan not found.", "warning")
        return redirect(url_for("scan_history.history"))
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "icmp_reply", "arp_reply", "mac", "hostname",
                "open_ports", "closed_ports"])
    for h in service.get_hosts(rec):
        w.writerow([h.ip, "1" if h.icmp_reply else "0",
                    "1" if h.arp_reply else "0",
                    h.mac, h.hostname,
                    h.open_ports_csv, h.closed_ports_csv])
    fname = (f"scan-{rec.id}-{rec.engine_name}-"
             f"{rec.source_iface_label}-{rec.started_at:%Y%m%d-%H%M}.csv")
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
