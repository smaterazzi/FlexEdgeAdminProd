"""Engine scan tool — background-job glue.

Thin wrapper around the generic `webapp.scan_jobs` runtime: builds an
engine-scan-specific runner closure that calls
`engine_scan._run_scan`, routes each event through the shared
progress / log / counter primitives, and on completion stashes an
`EngineScanReport` for the tools_scan route to consume.

Mirrors `dhcp_scan_jobs` exactly — only the runner contents differ.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from webapp import scan_jobs
from webapp.dhcp_ssh import SSHTarget, SSHCredential
from webapp.engine_scan import (
    EngineScanReport, HostResult, _run_scan,
)

log = logging.getLogger(__name__)


def start_scan(*, target: SSHTarget, cred: SSHCredential,
               ip_list: list[str], ports: list[int],
               user_email: str,
               source_node_index: int, source_node_hostname: str,
               source_iface_id: str = "",
               source_iface_name: str = "",
               target_label: str = "",
               batch_size: int = 32,
               ping_timeout_s: int = 1,
               arping_timeout_s: int = 1,
               port_timeout_s: int = 2,
               dns_timeout_s: int = 2,
               exec_timeout_s: int = 900) -> str:
    """Kick off an engine-scan job in a daemon thread. Returns the scan_id.

    Total ops budget: ICMP pass (= len(ip_list)) + arping fallback (a
    subset, so progress jumps a little when those resolve) + port scan
    (reachable_count × len(ports)). We initialise total to the worst-case
    sum so the bar is monotonic; it'll round to 100% slightly early if
    most hosts answer ICMP, which is the common case.
    """

    total = len(ip_list) + (len(ip_list) * len(ports) if ports else 0)
    scan_id = scan_jobs.register_job(
        feature="engines",
        user_email=user_email,
        total=max(total, 1),
        extra={
            "subnet_cidr": target_label,    # for status JSON; arbitrary string ok
            "source_node_index": source_node_index,
            "source_node_hostname": source_node_hostname,
            "source_iface_id": source_iface_id,
            "source_iface_name": source_iface_name,
            "target_label": target_label,
            "ports_scanned": list(ports),
        },
    )

    results: dict[str, HostResult] = {}

    def _on_event(ev: dict) -> None:
        ip = ev.get("ip", "")
        tag = ev.get("tag", "")
        r = results.get(ip) or HostResult(ip=ip)
        if tag == "ICMP_OK":
            if not r.icmp_reply:
                scan_jobs.increment(scan_id, "icmp_replies")
            r.icmp_reply = True
            r.arp_reply = True
            mac = ev.get("mac") or ""
            if mac and not r.mac:
                r.mac = mac
            scan_jobs.update_progress(scan_id)
            scan_jobs.append_log(scan_id,
                                 f"{ip}  ICMP reply" + (f"  {mac}" if mac else ""))
        elif tag == "ICMP_FAIL":
            scan_jobs.update_progress(scan_id)
        elif tag == "ARP_OK":
            if not r.arp_reply:
                scan_jobs.increment(scan_id, "arp_replies")
            r.arp_reply = True
            mac = ev.get("mac") or ""
            r.mac = mac
            scan_jobs.append_log(scan_id,
                                 f"{ip}  ARP reply (firewalled)  {mac}")
        elif tag == "SILENT":
            pass
        elif tag == "NO_ROUTE":
            scan_jobs.append_log(scan_id, f"{ip}  no route on engine")
        elif tag == "PORT":
            port = ev.get("port")
            state = ev.get("port_state", "")
            if port is not None:
                r.ports[port] = state
                if state == "open":
                    scan_jobs.increment(scan_id, "ports_open")
                    scan_jobs.append_log(scan_id, f"{ip}:{port}  open")
                else:
                    scan_jobs.increment(scan_id, "ports_closed")
            scan_jobs.update_progress(scan_id)
        elif tag == "HOST":
            hn = ev.get("hostname", "")
            if hn:
                r.hostname = hn
                scan_jobs.increment(scan_id, "hostnames_resolved")
                scan_jobs.append_log(scan_id, f"{ip}  ← {hn}")
        results[ip] = r

    def _runner(_scan_id: str) -> None:
        live_results, counters, err = _run_scan(
            target, cred, ip_list=ip_list, ports=ports,
            batch_size=batch_size,
            ping_timeout_s=ping_timeout_s,
            arping_timeout_s=arping_timeout_s,
            port_timeout_s=port_timeout_s,
            dns_timeout_s=dns_timeout_s,
            exec_timeout_s=exec_timeout_s,
            on_event=_on_event,
        )
        started_at = scan_jobs.get_started_at(scan_id)
        finished_at = datetime.now(timezone.utc)
        duration_ms = (
            int((finished_at - started_at).total_seconds() * 1000)
            if started_at else 0
        )
        merged = live_results or results
        report = EngineScanReport(
            started_at=started_at, finished_at=finished_at,
            duration_ms=duration_ms,
            source_node_index=source_node_index,
            source_node_hostname=source_node_hostname,
            source_iface_id=source_iface_id,
            source_iface_name=source_iface_name,
            target_label=target_label,
            targets=len(ip_list),
            ports_scanned=list(ports),
            icmp_replies=counters.get("icmp_replies", 0),
            arp_replies=counters.get("arp_replies", 0),
            hosts_with_open_ports=sum(
                1 for r in merged.values() if r.open_ports),
            error=err,
            results=merged,
        )
        if err:
            scan_jobs.mark_failed(scan_id, err)
        else:
            scan_jobs.append_log(scan_id, (
                f"complete: ICMP={report.icmp_replies} "
                f"ARP={report.arp_replies} "
                f"open-port hosts={report.hosts_with_open_ports}"
            ))
            scan_jobs.mark_done(scan_id, report)

    scan_jobs.spawn_runner(scan_id, _runner)
    log.info("engine_scan_jobs: started scan_id=%s targets=%d ports=%d "
             "via node%s (%s) iface=%s",
             scan_id, len(ip_list), len(ports),
             source_node_index, source_node_hostname, source_iface_id)
    return scan_id


# Re-export shared status / consume / discard.
get_status = scan_jobs.get_status
consume_report = scan_jobs.consume_report
discard = scan_jobs.discard
