"""
FlexEdgeAdmin — Switches (RA-C, docs/RemoteAgents.md § Phase C).

Read-only view of the switches an Extreme Site Engine (NetSight) manages
for the active Domain: inventory list → per-device Ports / VLANs tabs.
Every read goes through `webapp/netsight_objects.py` (the single NetSight
read entry point — routing to a remote agent or local execution + the
`netsight.*` cache sections happen there), so this module is pure
presentation: resolve the Domain, call the accessor, render, and turn a
`NetSightUnavailable` into an operator-readable alert instead of a 500.

Blueprint `switches_bp` at /switches, Domain Admin or higher.
"""

import ipaddress
import logging

from flask import (Blueprint, abort, flash, g, jsonify, redirect, render_template, request,
                   session, url_for)

from webapp.auth_roles import domain_admin_required

log = logging.getLogger(__name__)

switches_bp = Blueprint("switches", __name__, url_prefix="/switches")


def _current_domain():
    """`g.domain` is populated by the app-level before-request hook."""
    return getattr(g, "domain", None)


def _refresh_requested() -> bool:
    return request.args.get("refresh") == "1"


def _unavailable_view(exc) -> dict:
    """Template-friendly shape of a NetSightUnavailable."""
    return {"kind": getattr(exc, "kind", "failed"),
            "reason": getattr(exc, "reason", None) or str(exc)}


def _is_ipv4(value) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).version == 4
    except ValueError:
        return False


@switches_bp.route("/")
@domain_admin_required
def switches_list():
    # Lazy import: netsight_objects pulls in the agent pool + router; keeping
    # it inside the view also means this module imports cleanly on its own.
    from webapp.netsight_objects import NetSightUnavailable, netsight_devices

    domain = _current_domain()
    devices, cache_meta, unavailable = [], None, None
    if domain is None:
        unavailable = {"kind": "no_domain",
                       "reason": "No Domain selected — pick a profile first."}
    else:
        try:
            devices, cache_meta = netsight_devices(domain, refresh=_refresh_requested())
        except NetSightUnavailable as exc:
            unavailable = _unavailable_view(exc)
        except Exception as exc:  # noqa: BLE001 — never 500 on an inquiry page
            log.exception("switches list failed for domain %s", getattr(domain, "slug", "?"))
            unavailable = {"kind": "failed", "reason": str(exc)[:300]}

    return render_template("switches/list.html",
                           devices=devices or [], cache_meta=cache_meta,
                           unavailable=unavailable, domain=domain)


@switches_bp.route("/<ip>")
@domain_admin_required
def switch_detail(ip):
    from webapp.netsight_objects import (
        NetSightUnavailable, netsight_device, netsight_ports, netsight_vlans,
    )
    from shared.netsight_client import portlist_from_hex

    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        abort(400, "not an IP address")

    domain = _current_domain()
    if domain is None:
        return render_template("switches/detail.html", ip=ip, device=None,
                               device_error={"kind": "no_domain",
                                             "reason": "No Domain selected — pick a profile first."},
                               ports=None, ports_error=None, vlans=None, vlans_error=None,
                               cache_meta=None, domain=None), 200

    refresh = _refresh_requested()

    # Each tab is fetched on its own so one failure never blanks the others.
    def _fetch(accessor):
        try:
            return accessor(domain, ip, refresh=refresh), None
        except NetSightUnavailable as exc:
            return (None, None), _unavailable_view(exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("switch %s accessor %s failed", ip, accessor.__name__)
            return (None, None), {"kind": "failed", "reason": str(exc)[:300]}

    (device, cache_meta), device_error = _fetch(netsight_device)
    (ports_payload, _), ports_error = _fetch(netsight_ports)
    (vlan_rows, _), vlans_error = _fetch(netsight_vlans)

    ports = None
    if ports_payload is not None:
        raw_ports = (ports_payload or {}).get("ports") or []
        ports = []
        for p in raw_ports:
            row = dict(p or {})
            nb = row.get("portNeighborAddress") or ""
            row["neighbor_is_switch"] = _is_ipv4(nb)
            ports.append(row)

    vlans = None
    if vlan_rows is not None:
        vlans = []
        for v in vlan_rows or []:
            row = dict(v or {})
            row["egress_decoded"] = portlist_from_hex(row.get("dot1qVlanStaticEgressPorts") or "")
            row["untagged_decoded"] = portlist_from_hex(row.get("dot1qVlanStaticUntaggedPorts") or "")
            vlans.append(row)

    return render_template("switches/detail.html",
                           ip=ip, device=device, device_error=device_error,
                           sys_name=(ports_payload or {}).get("sysName") if ports_payload else None,
                           ports=ports, ports_error=ports_error,
                           vlans=vlans, vlans_error=vlans_error,
                           cache_meta=cache_meta, domain=domain)


# ── VLAN consistency check (NS2) ─────────────────────────────────────────

def _user_email() -> str:
    return (session.get("user") or {}).get("email", "")


def _user_id():
    from webapp.models import User
    email = _user_email()
    user = User.query.filter_by(email=email).first() if email else None
    return user.id if user else None


@switches_bp.route("/vlan-check")
@domain_admin_required
def vlan_check():
    """Firewall interface ↔ switch port VLAN comparison for the active Domain.
    `?job=<id>` shows the LLDP discovery watcher; on completion the summary
    is flashed and the page reloads clean."""
    from webapp import vlan_check as vc
    from webapp import vlan_check_jobs
    from webapp.models import SwitchPortLink
    from webapp.netsight_objects import NetSightUnavailable, netsight_devices, netsight_ports

    domain = _current_domain()
    if domain is None:
        return render_template("switches/vlan_check.html", domain=None, rows=[],
                               counts={}, devices=[], job=None, smc_error=None,
                               unavailable={"kind": "no_domain",
                                            "reason": "No Domain selected — pick a profile first."},
                               fw_errors=[], switch_errors={})

    job = None
    job_id = (request.args.get("job") or "").strip()
    if job_id:
        job = vlan_check_jobs.get_status(job_id, user_email=_user_email())
        if job and job["state"] == "done":
            summary = vlan_check_jobs.consume_report(job_id, user_email=_user_email()) or {}
            flash("LLDP discovery: %s switch(es) read, %s link(s) seen — %s added, %s updated, "
                  "%s removed%s%s." % (
                      summary.get("switches", 0), summary.get("found", 0), summary.get("added", 0),
                      summary.get("updated", 0), summary.get("removed", 0),
                      f", {summary['manual_conflicts']} conflict(s) with manual links (manual kept)"
                      if summary.get("manual_conflicts") else "",
                      f", {summary['switch_errors']} switch(es) failed"
                      if summary.get("switch_errors") else ""),
                  "warning" if summary.get("switch_errors") else "success")
            return redirect(url_for("switches.vlan_check"))
        if job and job["state"] == "failed":
            flash(f"LLDP discovery failed: {job.get('error')}", "danger")
            return redirect(url_for("switches.vlan_check"))
        if job is None:
            flash("That discovery run is no longer available.", "secondary")
            return redirect(url_for("switches.vlan_check"))

    refresh = _refresh_requested()
    smc_error, fw_rows, fw_errors = None, [], []
    try:
        fw_rows, fw_errors = vlan_check_jobs.collect_firewall_ports(domain, refresh=refresh)
    except Exception as exc:  # noqa: BLE001
        log.exception("vlan check: SMC inventory failed for %s", domain.slug)
        smc_error = str(exc)[:300]

    devices, unavailable = [], None
    try:
        devices, _cv = netsight_devices(domain)
    except NetSightUnavailable as exc:
        unavailable = _unavailable_view(exc)
    except Exception as exc:  # noqa: BLE001
        unavailable = {"kind": "failed", "reason": str(exc)[:300]}
    names = {d.get("ip"): d.get("sysName") or d.get("ip") for d in devices or []}

    links = {(r.engine_name, r.node_index, r.interface_id): r
             for r in SwitchPortLink.query.filter_by(domain_id=domain.id).all()}
    payloads, switch_errors = {}, {}
    if unavailable is None:
        for ip in sorted({r.switch_ip for r in links.values()}):
            try:
                payloads[ip], _ = netsight_ports(domain, ip, refresh=refresh)
            except NetSightUnavailable as exc:
                switch_errors[ip] = exc.reason or str(exc)
            except Exception as exc:  # noqa: BLE001
                switch_errors[ip] = str(exc)[:200]

    rows = []
    counts = {"ok": 0, "extra": 0, "missing": 0, "no_port": 0, "unknown": 0, "unmapped": 0}
    for fw in fw_rows:
        link = links.get(vc.port_key(fw))
        result = None
        if link is None:
            counts["unmapped"] += 1
        elif link.switch_ip in payloads:
            result = vc.compare(fw, vc.find_port(payloads[link.switch_ip], link.port_name))
            counts[result["status"]] += 1
        else:
            counts["unknown"] += 1
        sw_port = vc.find_port(payloads.get(link.switch_ip), link.port_name) if link else None
        rows.append({"fw": fw, "link": link, "result": result, "switch_port": sw_port,
                     "switch_name": names.get(link.switch_ip, link.switch_ip) if link else "",
                     "switch_error": switch_errors.get(link.switch_ip) if link else None})

    return render_template("switches/vlan_check.html", domain=domain, rows=rows,
                           counts=counts, job=job,
                           devices=sorted(devices or [], key=lambda d: str(d.get("sysName") or d.get("ip") or "")),
                           smc_error=smc_error, unavailable=unavailable,
                           fw_errors=fw_errors, switch_errors=switch_errors)


@switches_bp.route("/vlan-check/discover", methods=["POST"])
@domain_admin_required
def vlan_check_discover():
    from webapp import vlan_check_jobs
    domain = _current_domain()
    if domain is None:
        return redirect(url_for("switches.vlan_check"))
    job_id = vlan_check_jobs.start_discovery(domain=domain, user_email=_user_email())
    return redirect(url_for("switches.vlan_check", job=job_id))


@switches_bp.route("/vlan-check/job/<job_id>")
@domain_admin_required
def vlan_check_job(job_id):
    from webapp import vlan_check_jobs
    status = vlan_check_jobs.get_status(job_id, user_email=_user_email())
    if status is None:
        return jsonify({"ok": False, "error": "unknown job"}), 404
    return jsonify({"ok": True, "state": status["state"], "progress": status["progress"],
                    "total": status["total"], "log_tail": status["log_tail"],
                    "error": status["error"]})


@switches_bp.route("/vlan-check/ports/<ip>")
@domain_admin_required
def vlan_check_ports(ip):
    """Port names of one switch, for the Map dialog's picker."""
    from webapp.netsight_objects import NetSightUnavailable, netsight_ports
    domain = _current_domain()
    if domain is None or not _is_ipv4(ip):
        return jsonify({"ok": False, "error": "bad request"}), 400
    try:
        payload, _ = netsight_ports(domain, str(ipaddress.ip_address(ip.strip())))
    except NetSightUnavailable as exc:
        return jsonify({"ok": False, "error": exc.reason or str(exc)}), 502
    ports = [{"name": p.get("portName") or "", "alias": p.get("portAlias") or "",
              "tagged": p.get("vlans") or "", "untagged": p.get("untag") or ""}
             for p in (payload or {}).get("ports") or [] if p.get("portName")]
    return jsonify({"ok": True, "ports": ports})


@switches_bp.route("/vlan-check/links", methods=["POST"])
@domain_admin_required
def vlan_check_link_save():
    """Pin (or re-pin) a firewall port to a switch port. A manual link
    replaces an LLDP one on the same firewall port."""
    from shared.db import db
    from shared.logging import audit
    from webapp import vlan_check as vc
    from webapp import vlan_check_jobs
    from webapp.models import SwitchPortLink
    from webapp.netsight_objects import NetSightUnavailable, netsight_devices, netsight_ports

    domain = _current_domain()
    if domain is None:
        return redirect(url_for("switches.vlan_check"))
    f = request.form
    engine = (f.get("engine_name") or "").strip()
    iface = (f.get("interface_id") or "").strip()
    port_name = (f.get("port_name") or "").strip()
    try:
        node_index = int(f.get("node_index") or 0)
        switch_ip = str(ipaddress.ip_address((f.get("switch_ip") or "").strip()))
    except ValueError:
        flash("Pick a switch and a firewall interface.", "danger")
        return redirect(url_for("switches.vlan_check"))

    try:
        fw_rows, _ = vlan_check_jobs.collect_firewall_ports(domain)
        devices, _ = netsight_devices(domain)
        payload, _ = netsight_ports(domain, switch_ip)
    except NetSightUnavailable as exc:
        flash(f"Can't validate the link: {exc.reason or exc}", "danger")
        return redirect(url_for("switches.vlan_check"))
    except Exception as exc:  # noqa: BLE001
        flash(f"Can't validate the link: {exc}", "danger")
        return redirect(url_for("switches.vlan_check"))
    if (engine, node_index, iface) not in {vc.port_key(r) for r in fw_rows}:
        flash("That firewall interface isn't in this Domain's inventory.", "danger")
        return redirect(url_for("switches.vlan_check"))
    if switch_ip not in {d.get("ip") for d in devices or []}:
        flash(f"{switch_ip} isn't a switch managed by this Domain's Site Engine.", "danger")
        return redirect(url_for("switches.vlan_check"))
    if vc.find_port(payload, port_name) is None:
        flash(f"Switch {switch_ip} has no port named '{port_name}'.", "danger")
        return redirect(url_for("switches.vlan_check"))

    row = SwitchPortLink.query.filter_by(domain_id=domain.id, engine_name=engine,
                                         node_index=node_index, interface_id=iface).first()
    if row is None:
        row = SwitchPortLink(domain_id=domain.id, engine_name=engine,
                             node_index=node_index, interface_id=iface)
        db.session.add(row)
    previous = f"{row.switch_ip} {row.port_name} ({row.source})" if row.switch_ip else "-"
    row.switch_ip, row.port_name, row.source = switch_ip, port_name, "manual"
    row.last_seen_at, row.created_by_id = None, _user_id()
    db.session.commit()
    audit("netsight", "link.map", target=f"{engine} n{node_index} if{iface}",
          detail=f"{switch_ip} {port_name} (was {previous})")
    flash(f"{engine} node {node_index} interface {iface} → {switch_ip} {port_name}.", "success")
    return redirect(url_for("switches.vlan_check"))


@switches_bp.route("/vlan-check/links/<int:link_id>/delete", methods=["POST"])
@domain_admin_required
def vlan_check_link_delete(link_id):
    from shared.db import db
    from shared.logging import audit
    from webapp.models import SwitchPortLink

    domain = _current_domain()
    row = db.session.get(SwitchPortLink, link_id)
    if domain is None or row is None or row.domain_id != domain.id:
        flash("Link not found.", "secondary")
        return redirect(url_for("switches.vlan_check"))
    target = f"{row.engine_name} n{row.node_index} if{row.interface_id}"
    detail = f"{row.switch_ip} {row.port_name} ({row.source})"
    db.session.delete(row)
    db.session.commit()
    audit("netsight", "link.unmap", target=target, detail=detail, status="warning")
    flash(f"Link removed: {target} ↔ {detail}.", "success")
    return redirect(url_for("switches.vlan_check"))
