"""Background-job runtime for the DHCP subnet scan.

The synchronous `dhcp_subnet_scan.scan_subnet` blocks the request for
the duration of the scan — fine for /24, but the leases page wants a
live progress bar and rolling log. This module wraps the scan in a
daemon thread, keeps shared state in a process-local dict, and exposes
poll-friendly accessors.

Lifecycle
---------

  start_scan(...) -> scan_id            # spawns the worker
  get_status(scan_id, user_email)       # JSON-friendly snapshot, polled
  consume_report(scan_id, user_email)   # one-shot read + remove the job

Cross-worker note: gunicorn `--preload` shares the *initial* dict object
across forked workers, but writes after fork are NOT shared. In the
single-worker-multi-thread case (production today) every poll hits the
same process and works. In a future multi-worker deployment a different
worker may serve the polling request — at which point we'd need an
out-of-process store. For now we accept the constraint and the operator
just clicks Scan again if their poll lands on the wrong worker.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from webapp.dhcp_ssh import SSHTarget, SSHCredential
from webapp.dhcp_subnet_scan import (
    ScanReport, HostScanResult, _run_scan_streaming,
)

log = logging.getLogger(__name__)


# Jobs older than this are evicted on next access — protects against
# unbounded memory growth if a user starts scans and never picks up the
# results.
_TTL = timedelta(minutes=15)
_LOG_TAIL_LINES = 10
_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}


def _now():
    return datetime.now(timezone.utc)


def _cleanup_locked():
    """Evict jobs past TTL. Caller holds _LOCK."""
    now = _now()
    for k in list(_JOBS.keys()):
        if _JOBS[k].get("expires_at", now) < now:
            _JOBS.pop(k, None)


def start_scan(*, target: SSHTarget, cred: SSHCredential,
               ip_list: list[str], subnet_cidr: str,
               scope_id: int, user_email: str,
               source_node_index: int, source_node_hostname: str,
               batch_size: int = 32,
               ping_timeout_s: int = 1,
               arping_timeout_s: int = 1,
               exec_timeout_s: int = 600) -> str:
    """Kick off a scan in a daemon thread. Returns the scan_id."""
    scan_id = uuid4().hex
    state = {
        "scan_id": scan_id,
        "scope_id": scope_id,
        "user_email": user_email,
        "subnet_cidr": subnet_cidr,
        "state": "running",     # running | done | failed
        "progress": 0,
        "total": len(ip_list),
        "log_tail": deque(maxlen=_LOG_TAIL_LINES),
        "icmp_replies": 0,
        "arp_replies": 0,
        "phase2_pending": 0,
        "phase2_done": 0,
        "results": {},          # ip -> HostScanResult
        "source_node_index": source_node_index,
        "source_node_hostname": source_node_hostname,
        "started_at": _now(),
        "finished_at": None,
        "duration_ms": 0,
        "error": "",
        "expires_at": _now() + _TTL,
    }
    with _LOCK:
        _cleanup_locked()
        _JOBS[scan_id] = state

    def _on_event(ev: dict) -> None:
        ip = ev.get("ip", "")
        st = ev.get("state", "")
        mac = ev.get("mac", "")
        with _LOCK:
            s = _JOBS.get(scan_id)
            if s is None:
                return
            r = s["results"].get(ip) or HostScanResult(ip=ip)
            if st == "ICMP_OK":
                if not r.icmp_reply:
                    s["icmp_replies"] += 1
                r.icmp_reply = True
                r.arp_reply = True   # ICMP success implies L2 visibility
                s["progress"] += 1
                s["log_tail"].append(f"{ip}  ICMP reply")
            elif st == "ICMP_FAIL":
                s["progress"] += 1
                s["phase2_pending"] += 1
                # Don't append every silent ping to the log — too noisy.
            elif st == "ARP_OK":
                if not r.arp_reply:
                    s["arp_replies"] += 1
                r.arp_reply = True
                r.mac = mac
                s["phase2_done"] += 1
                s["log_tail"].append(
                    f"{ip}  ARP reply (firewalled)  {mac}")
            elif st == "SILENT":
                s["phase2_done"] += 1
                # Stays silent — don't log per IP, would flood.
            elif st == "NO_ROUTE":
                s["phase2_done"] += 1
                s["log_tail"].append(f"{ip}  no route on engine")
            s["results"][ip] = r

    def _runner():
        try:
            results, icmp, arp, err = _run_scan_streaming(
                target, cred, ip_list=ip_list,
                batch_size=batch_size,
                ping_timeout_s=ping_timeout_s,
                arping_timeout_s=arping_timeout_s,
                exec_timeout_s=exec_timeout_s,
                on_event=_on_event,
            )
        except Exception as exc:
            log.exception("dhcp_scan_jobs: scan_id=%s crashed", scan_id)
            with _LOCK:
                s = _JOBS.get(scan_id)
                if s is not None:
                    s["state"] = "failed"
                    s["error"] = f"crash: {exc}"
                    s["finished_at"] = _now()
                    s["duration_ms"] = int(
                        (s["finished_at"] - s["started_at"]).total_seconds() * 1000)
                    s["expires_at"] = _now() + _TTL
            return

        with _LOCK:
            s = _JOBS.get(scan_id)
            if s is None:
                return
            # Final reconciliation — the streaming callback already wrote
            # most of this, but re-asserting is harmless and protects
            # against any callback hiccup.
            s["results"] = results
            s["icmp_replies"] = icmp
            s["arp_replies"] = arp
            s["progress"] = s["total"]
            if err:
                s["state"] = "failed"
                s["error"] = err
            else:
                s["state"] = "done"
                s["log_tail"].append(
                    f"complete: ICMP={icmp} ARP={arp} "
                    f"silent={max(0, len(results) - icmp - arp)}")
            s["finished_at"] = _now()
            s["duration_ms"] = int(
                (s["finished_at"] - s["started_at"]).total_seconds() * 1000)
            s["expires_at"] = _now() + _TTL

    t = threading.Thread(target=_runner, name=f"dhcp-scan-{scan_id[:8]}",
                         daemon=True)
    t.start()
    log.info("dhcp_scan_jobs: started scan_id=%s scope=%s targets=%d "
             "via node%s (%s)",
             scan_id, scope_id, len(ip_list),
             source_node_index, source_node_hostname)
    return scan_id


def _check_owner(s: dict, user_email: str) -> bool:
    """Don't leak scans across users. Empty user_email = system caller."""
    if not user_email:
        return True
    return (s.get("user_email") or "").lower() == user_email.lower()


def get_status(scan_id: str, user_email: str = "") -> Optional[dict]:
    """JSON-friendly snapshot for the polling endpoint.

    Returns None if the scan_id is unknown, expired, or owned by someone
    else. The endpoint surfaces None as a 404.
    """
    with _LOCK:
        _cleanup_locked()
        s = _JOBS.get(scan_id)
        if s is None or not _check_owner(s, user_email):
            return None
        return {
            "scan_id": s["scan_id"],
            "state": s["state"],
            "progress": s["progress"],
            "total": s["total"],
            "icmp_replies": s["icmp_replies"],
            "arp_replies": s["arp_replies"],
            "phase2_pending": s["phase2_pending"],
            "phase2_done": s["phase2_done"],
            "log_tail": list(s["log_tail"]),
            "subnet_cidr": s["subnet_cidr"],
            "source_node_index": s["source_node_index"],
            "source_node_hostname": s["source_node_hostname"],
            "duration_ms": s["duration_ms"],
            "error": s["error"],
        }


def consume_report(scan_id: str, user_email: str = "") -> Optional[ScanReport]:
    """One-shot read of the final report. Removes the job from memory.

    Returns None if the scan isn't done yet, or unknown, or wrong owner.
    """
    with _LOCK:
        _cleanup_locked()
        s = _JOBS.get(scan_id)
        if s is None or not _check_owner(s, user_email):
            return None
        if s["state"] != "done":
            return None
        # Remove now — caller is consuming.
        _JOBS.pop(scan_id, None)
        return ScanReport(
            scope_id=s["scope_id"],
            subnet_cidr=s["subnet_cidr"],
            started_at=s["started_at"],
            finished_at=s["finished_at"],
            duration_ms=s["duration_ms"],
            source_node_index=s["source_node_index"],
            source_node_hostname=s["source_node_hostname"],
            targets=s["total"],
            icmp_replies=s["icmp_replies"],
            arp_replies=s["arp_replies"],
            error=s["error"],
            results=s["results"],
        )


def discard(scan_id: str, user_email: str = "") -> bool:
    """Forget the scan without consuming results. Used when the operator
    cancels or the leases page renders without consuming."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None or not _check_owner(s, user_email):
            return False
        _JOBS.pop(scan_id, None)
        return True
