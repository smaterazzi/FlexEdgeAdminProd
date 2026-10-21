"""VLAN consistency check (NS2) — data glue + LLDP discovery job.

`collect_firewall_ports(domain)` turns the Domain's cached SMC inventory
(`engines` + `cluster` sections) into `vlan_check.firewall_ports` rows.
`start_discovery(...)` runs the LLDP walk in a daemon thread on the generic
`webapp.scan_jobs` runtime (same shape as `drift_jobs`): every up switch's
ports are re-read from NetSight (`netsight_ports(refresh=True)`, so the
check page then reads them from cache), neighbour addresses are matched
against firewall node addresses, and `apply_discovery` upserts
`SwitchPortLink(source='lldp')` rows. Manual links always win.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import current_app

from webapp import scan_jobs
from webapp.vlan_check import firewall_ports, lldp_links

log = logging.getLogger(__name__)


def collect_firewall_ports(domain, *, refresh: bool = False):
    """`(rows, errors)` — one row per (engine, node, physical interface).
    Per-engine failures are listed, not raised; an unreachable SMC raises."""
    from webapp import domain_objects
    from webapp.dhcp_manager import _smc_cfg_dict

    cfg = _smc_cfg_dict(domain)
    engines, _cv = domain_objects.engines(domain, cfg, refresh=refresh)
    rows, errors = [], []
    for eng in engines or []:
        try:
            _detail, ccv = domain_objects.cluster(domain, cfg, eng.name, refresh=refresh)
            rows.extend(firewall_ports(eng.name, (ccv.data if ccv else None) or {}))
        except Exception as exc:  # noqa: BLE001 — one bad engine never blanks the page
            errors.append(f"{eng.name}: {exc}")
    return rows, errors


def apply_discovery(domain_id: int, found: list, queried_switches: set) -> dict:
    """Upsert LLDP links. A manual link on the same firewall port is never
    overwritten (counted as a conflict when it points elsewhere). LLDP rows
    whose switch answered this run but no longer shows the neighbour are
    removed; rows on switches that failed this run are kept."""
    from shared.db import db
    from webapp.models import SwitchPortLink

    now = datetime.now(timezone.utc)
    existing = {(r.engine_name, r.node_index, r.interface_id): r
                for r in SwitchPortLink.query.filter_by(domain_id=domain_id).all()}
    summary = {"found": len(found), "added": 0, "updated": 0, "unchanged": 0,
               "removed": 0, "manual_conflicts": 0}
    found_keys = set()
    for link in found:
        key = (link["engine"], int(link["node_index"]), str(link["interface_id"]))
        found_keys.add(key)
        row = existing.get(key)
        if row is not None and row.source == "manual":
            if (row.switch_ip, row.port_name) != (link["switch_ip"], link["port_name"]):
                summary["manual_conflicts"] += 1
            continue
        if row is None:
            db.session.add(SwitchPortLink(
                domain_id=domain_id, engine_name=key[0], node_index=key[1],
                interface_id=key[2], switch_ip=link["switch_ip"],
                port_name=link["port_name"], source="lldp", last_seen_at=now))
            summary["added"] += 1
        else:
            changed = (row.switch_ip, row.port_name) != (link["switch_ip"], link["port_name"])
            row.switch_ip, row.port_name, row.last_seen_at = link["switch_ip"], link["port_name"], now
            summary["updated" if changed else "unchanged"] += 1
    for key, row in existing.items():
        if row.source == "lldp" and key not in found_keys and row.switch_ip in queried_switches:
            db.session.delete(row)
            summary["removed"] += 1
    db.session.commit()
    return summary


def start_discovery(*, domain, user_email: str) -> str:
    """Spawn the LLDP walk for `domain`. Returns the job id."""
    domain_id = domain.id
    label = getattr(domain, "display_name", None) or getattr(domain, "slug", "") or f"#{domain_id}"
    job_id = scan_jobs.register_job(feature="netsight", user_email=user_email, total=1,
                                    extra={"domain_id": domain_id, "domain_label": label})
    app = current_app._get_current_object()

    def _runner(_job_id: str) -> None:
        with app.app_context():
            from shared.db import db
            from shared.logging import audit
            from webapp.models import Domain
            from webapp.netsight_objects import (
                NetSightUnavailable, netsight_devices, netsight_ports,
            )
            d = db.session.get(Domain, domain_id)
            if d is None:
                scan_jobs.mark_failed(_job_id, f"Domain #{domain_id} no longer exists")
                return
            fw_ports, fw_errors = collect_firewall_ports(d)
            scan_jobs.append_log(_job_id, f"{len(fw_ports)} firewall interface(s) from SMC"
                                 + (f", {len(fw_errors)} engine error(s)" if fw_errors else ""))
            try:
                devices, _cv = netsight_devices(d, refresh=True)
            except NetSightUnavailable as exc:
                scan_jobs.mark_failed(_job_id, exc.reason or str(exc))
                return
            up = [x for x in devices or [] if x.get("up") and x.get("ip")]
            scan_jobs.update_extra(_job_id, total=max(len(up), 1))
            switches, ok, failed = {}, set(), []
            for dev in up:
                ip = dev["ip"]
                try:
                    payload, _ = netsight_ports(d, ip, refresh=True)
                    switches[ip] = payload
                    ok.add(ip)
                except NetSightUnavailable as exc:
                    if exc.kind in ("refused", "no_connection"):
                        scan_jobs.mark_failed(_job_id, exc.reason or str(exc))
                        return
                    failed.append(ip)
                    scan_jobs.append_log(_job_id, f"{ip}: {exc.reason or exc}")
                scan_jobs.update_progress(_job_id, delta=1)
            links = lldp_links(fw_ports, switches)
            for link in links:
                scan_jobs.append_log(_job_id, "LLDP: %s node %s if %s → %s %s" % (
                    link["engine"], link["node_index"], link["interface_id"],
                    link["switch_ip"], link["port_name"]))
            summary = apply_discovery(domain_id, links, ok)
            summary.update(switches=len(up), switch_errors=len(failed),
                           firewall_ports=len(fw_ports), engine_errors=len(fw_errors))
            audit("netsight", "lldp.discover", target=d.slug,
                  detail=" ".join(f"{k}={v}" for k, v in summary.items()),
                  status="warning" if failed or fw_errors else "ok",
                  user_email=user_email, domain_id=domain_id,
                  source_correlation_id=_job_id)
            scan_jobs.mark_done(_job_id, summary)

    scan_jobs.spawn_runner(job_id, _runner)
    log.info("vlan_check_jobs: LLDP discovery %s started for %s", job_id, label)
    return job_id


get_status = scan_jobs.get_status
consume_report = scan_jobs.consume_report
