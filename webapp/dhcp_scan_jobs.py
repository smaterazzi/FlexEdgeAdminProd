"""DHCP subnet scan — background-job glue.

Thin wrapper around the generic `webapp.scan_jobs` runtime: builds a
DHCP-specific runner closure that calls
`dhcp_subnet_scan._run_scan_streaming`, routes each event through the
shared progress / log / counter primitives, and on completion stashes
a `ScanReport` for the leases route to consume.

Public API is unchanged from the original DHCP-only runtime — the
DHCP routes import `start_scan / get_status / consume_report / discard`
and don't know the runtime is shared with the engines scan tool.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from webapp import scan_jobs
from webapp.dhcp_ssh import SSHTarget, SSHCredential
from webapp.dhcp_subnet_scan import (
    ScanReport, HostScanResult, _run_scan_streaming,
)

log = logging.getLogger(__name__)


def start_scan(*, target: SSHTarget, cred: SSHCredential,
               ip_list: list[str], subnet_cidr: str,
               scope_id: int, user_email: str,
               source_node_index: int, source_node_hostname: str,
               batch_size: int = 32,
               ping_timeout_s: int = 1,
               arping_timeout_s: int = 1,
               exec_timeout_s: int = 600) -> str:
    """Kick off a DHCP subnet scan in a daemon thread. Returns the scan_id."""

    scan_id = scan_jobs.register_job(
        feature="dhcp",
        user_email=user_email,
        total=len(ip_list),
        extra={
            "scope_id": scope_id,
            "subnet_cidr": subnet_cidr,
            "source_node_index": source_node_index,
            "source_node_hostname": source_node_hostname,
            "phase2_pending": 0,
            "phase2_done": 0,
        },
    )
    # Live-result accumulator — kept in a closure so the runner can
    # build the final ScanReport without re-parsing.
    results: dict[str, HostScanResult] = {}

    def _on_event(ev: dict) -> None:
        ip = ev.get("ip", "")
        st = ev.get("state", "")
        mac = ev.get("mac", "")
        r = results.get(ip) or HostScanResult(ip=ip)
        if st == "ICMP_OK":
            if not r.icmp_reply:
                scan_jobs.increment(scan_id, "icmp_replies")
            r.icmp_reply = True
            r.arp_reply = True
            if mac and not r.mac:
                r.mac = mac
            scan_jobs.update_progress(scan_id)
            scan_jobs.append_log(scan_id,
                                 f"{ip}  ICMP reply" + (f"  {mac}" if mac else ""))
        elif st == "ICMP_FAIL":
            scan_jobs.update_progress(scan_id)
            scan_jobs.increment_extra(scan_id, "phase2_pending")
        elif st == "ARP_OK":
            if not r.arp_reply:
                scan_jobs.increment(scan_id, "arp_replies")
            r.arp_reply = True
            r.mac = mac
            scan_jobs.increment_extra(scan_id, "phase2_done")
            scan_jobs.append_log(scan_id,
                                 f"{ip}  ARP reply (firewalled)  {mac}")
        elif st == "SILENT":
            scan_jobs.increment_extra(scan_id, "phase2_done")
        elif st == "NO_ROUTE":
            scan_jobs.increment_extra(scan_id, "phase2_done")
            scan_jobs.append_log(scan_id, f"{ip}  no route on engine")
        results[ip] = r

    def _runner(_scan_id: str) -> None:
        live_results, icmp, arp, err = _run_scan_streaming(
            target, cred, ip_list=ip_list,
            batch_size=batch_size,
            ping_timeout_s=ping_timeout_s,
            arping_timeout_s=arping_timeout_s,
            exec_timeout_s=exec_timeout_s,
            on_event=_on_event,
        )
        started_at = scan_jobs.get_started_at(scan_id)
        finished_at = datetime.now(timezone.utc)
        duration_ms = (
            int((finished_at - started_at).total_seconds() * 1000)
            if started_at else 0
        )
        report = ScanReport(
            scope_id=scope_id, subnet_cidr=subnet_cidr,
            started_at=started_at, finished_at=finished_at,
            duration_ms=duration_ms,
            source_node_index=source_node_index,
            source_node_hostname=source_node_hostname,
            targets=len(ip_list),
            icmp_replies=icmp,
            arp_replies=arp,
            error=err,
            results=live_results or results,
        )
        if err:
            scan_jobs.mark_failed(scan_id, err)
        else:
            scan_jobs.append_log(scan_id, (
                f"complete: ICMP={icmp} ARP={arp} "
                f"silent={max(0, len(live_results) - icmp - arp)}"
            ))
            scan_jobs.mark_done(scan_id, report)

    scan_jobs.spawn_runner(scan_id, _runner)
    log.info("dhcp_scan_jobs: started scan_id=%s scope=%s targets=%d "
             "via node%s (%s)",
             scan_id, scope_id, len(ip_list),
             source_node_index, source_node_hostname)
    return scan_id


# Re-export the shared status / consume / discard helpers so existing
# DHCP routes import from `webapp.dhcp_scan_jobs` keep working unchanged.
get_status = scan_jobs.get_status
consume_report = scan_jobs.consume_report
discard = scan_jobs.discard
