"""DHCP subnet active-discovery scan.

Runs from the engine node hosting the served subnet: a parallel ICMP
sweep over a list of target IPs followed by an arping fallback for
those that didn't answer ping. Together that catches three signal
classes per IP:

  * up + reachable             — ICMP ✓  (implies ARP ✓)
  * up + L3-firewalled         — ICMP ✗  ARP ✓
  * off / not present          — ICMP ✗  ARP ✗

Joined with the dhcpd.leases file in the calling route, each IP is
classified into one of six buckets — `classify()` below is the truth
table.

Why run on the engine instead of from the FlexEdgeAdmin container:
the engine has a leg in the served VLAN (it IS the gateway), so its
arping reaches L2. Container is on a management network and would
have no L2 visibility into the served subnet.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_network, ip_address, IPv4Address, IPv4Network
from typing import Callable, Optional

from webapp.dhcp_ssh import SSHTarget, SSHCredential, ssh_connect

log = logging.getLogger(__name__)


# Hard cap on per-scan host count — protects against accidental /16
# sweeps. /20 = 4094 usable hosts, plenty for typical campus VLANs.
MAX_HOSTS = 4096

# Threshold above which the UI requires explicit operator confirmation
# (anything bigger than a /24).
WARN_THRESHOLD_HOSTS = 256


@dataclass
class HostScanResult:
    ip: str
    icmp_reply: bool = False
    arp_reply: bool = False
    mac: str = ""


@dataclass
class ScanReport:
    scope_id: int
    subnet_cidr: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_ms: int = 0
    source_node_index: int = 0
    source_node_hostname: str = ""
    targets: int = 0
    icmp_replies: int = 0
    arp_replies: int = 0
    error: str = ""
    results: dict[str, HostScanResult] = field(default_factory=dict)


# ── Remote shell script ─────────────────────────────────────────────────
#
# Args (passed as positional after `_`):
#   $1 BATCH_SIZE         backgrounded jobs before `wait`
#   $2 PING_TIMEOUT_S     ping -W value (seconds)
#   $3 ARPING_TIMEOUT_S   arping -w value (seconds)
#   $@ (after shift 3)    target IPs
#
# Stdout: one line per IP, in two phases:
#
#   PHASE 1 — ICMP pass:
#     <ip> ICMP_OK
#     <ip> ICMP_FAIL          (the IP is queued for arping)
#
#   PHASE 2 — arping pass over ICMP_FAIL entries:
#     <ip> ARP_OK <mac>
#     <ip> SILENT
#     <ip> NO_ROUTE
#
# Phase 1 emits live as each ping completes (the parallel jobs each
# `printf` to stdout AND append to $TMP atomically — writes <PIPE_BUF
# are atomic on Linux). Phase 2 reads $TMP and emits the final state
# for every ICMP_FAIL entry. Net: the calling Python sees lines as
# they happen, can update progress live, and handles double updates
# for FAIL'd IPs (FAIL → ARP_OK or FAIL → SILENT).
#
# Portable POSIX sh — runs on Forcepoint NGFW BusyBox shells.
#
_SCAN_SCRIPT = r"""
BATCH=$1; PT=$2; AT=$3; shift 3
TMP=$(mktemp 2>/dev/null || echo /tmp/.fea-scan.$$)
: > "$TMP"
n=0
for ip in "$@"; do
    (
        if ping -c 1 -W "$PT" -q "$ip" >/dev/null 2>&1; then
            line="$ip ICMP_OK"
        else
            line="$ip ICMP_FAIL"
        fi
        printf '%s\n' "$line"
        printf '%s\n' "$line" >> "$TMP"
    ) &
    n=$((n+1))
    if [ "$n" -ge "$BATCH" ]; then wait; n=0; fi
done
wait
while IFS= read -r line; do
    set -- $line
    ip=$1; state=$2
    if [ "$state" = "ICMP_FAIL" ]; then
        DEV=$(ip route get "$ip" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1); exit}')
        if [ -z "$DEV" ]; then
            printf '%s NO_ROUTE\n' "$ip"
            continue
        fi
        OUT=$(arping -c 1 -w "$AT" -I "$DEV" "$ip" 2>&1)
        MAC=$(printf '%s\n' "$OUT" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
        if [ -n "$MAC" ]; then
            printf '%s ARP_OK %s\n' "$ip" "$MAC"
        else
            printf '%s SILENT\n' "$ip"
        fi
    fi
done < "$TMP"
rm -f "$TMP"
"""


# ── Target enumeration helpers ─────────────────────────────────────────


def enumerate_subnet_targets(subnet_cidr: str, gateway: str = "") -> list[str]:
    """Every host IP in the subnet, minus network, broadcast, and gateway.

    Skipping the gateway is important: pinging ourselves would always
    return success and clutter the results.
    """
    net = ip_network(subnet_cidr, strict=False)
    if not isinstance(net.network_address, IPv4Address):
        raise ValueError("only IPv4 subnets are supported")
    skip = {net.network_address, net.broadcast_address}
    if gateway:
        try:
            skip.add(ip_address(gateway))
        except ValueError:
            pass
    return [str(h) for h in net.hosts() if h not in skip]


def enumerate_range_targets(start_ip: str, end_ip: str,
                            gateway: str = "",
                            *, subnet_cidr: str = "") -> list[str]:
    """Inclusive IP range. Optionally bounded to a subnet for safety.

    Excludes the gateway IP if it falls inside the range. Raises
    ValueError if start > end, or (when subnet_cidr is given) if either
    endpoint is outside the subnet.
    """
    a = ip_address(start_ip)
    b = ip_address(end_ip)
    if int(a) > int(b):
        raise ValueError(f"start_ip {a} > end_ip {b}")

    if subnet_cidr:
        net = ip_network(subnet_cidr, strict=False)
        if a not in net or b not in net:
            raise ValueError(
                f"range {a}-{b} extends outside subnet {net}")

    skip = set()
    if gateway:
        try:
            skip.add(ip_address(gateway))
        except ValueError:
            pass

    out = []
    cur = int(a)
    end = int(b)
    while cur <= end:
        addr = ip_address(cur)
        if addr not in skip:
            out.append(str(addr))
        cur += 1
    return out


# ── Scan execution ─────────────────────────────────────────────────────


# Callback invoked per output line. Receives a dict shaped like:
#   {"ip": str, "state": "ICMP_OK"|"ICMP_FAIL"|"ARP_OK"|"SILENT"|"NO_ROUTE",
#    "mac": str (only for ARP_OK), "phase": 1 (ICMP_*) or 2 (others)}
# Background jobs use this to update the live progress dict.
EventCallback = Callable[[dict], None]


def _run_scan_streaming(target: SSHTarget, cred: SSHCredential, *,
                        ip_list: list[str],
                        batch_size: int = 32,
                        ping_timeout_s: int = 1,
                        arping_timeout_s: int = 1,
                        exec_timeout_s: int = 600,
                        on_event: Optional[EventCallback] = None,
                        ) -> tuple[dict[str, HostScanResult], int, int, str]:
    """Open SSH, run the scan script, parse stdout line-by-line.

    Returns (results, icmp_replies, arp_replies, error_text). On error
    `results` may be partial. Caller wraps in a ScanReport dataclass.
    """
    cmd_parts = ["sh", "-c", _SCAN_SCRIPT, "_",
                 str(batch_size),
                 str(ping_timeout_s), str(arping_timeout_s)]
    cmd_parts.extend(ip_list)
    cmd = " ".join(shlex.quote(p) for p in cmd_parts)

    try:
        client = ssh_connect(target, cred)
    except Exception as exc:
        return {}, 0, 0, f"SSH connect failed: {exc}"

    results: dict[str, HostScanResult] = {}
    icmp_replies = 0
    arp_replies = 0
    error_text = ""

    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=exec_timeout_s)
        # readline() blocks until a newline arrives — gives us live progress.
        for raw in iter(stdout.readline, ''):
            parts = raw.strip().split()
            if not parts:
                continue
            ip = parts[0]
            state = parts[1] if len(parts) > 1 else "SILENT"
            mac = parts[2].lower() if len(parts) > 2 else ""

            r = results.get(ip) or HostScanResult(ip=ip)
            phase = 1
            if state == "ICMP_OK":
                # ICMP success implies the host is L2-visible — model as
                # both flags so classify() doesn't mistake it for "firewalled".
                r.icmp_reply = True
                r.arp_reply = True
                icmp_replies += 1
            elif state == "ICMP_FAIL":
                # First-pass result; values stay False until Phase 2 updates
                # (or doesn't, leaving the IP in the SILENT bucket).
                pass
            elif state == "ARP_OK":
                r.arp_reply = True
                r.mac = mac
                arp_replies += 1
                phase = 2
            elif state in ("SILENT", "NO_ROUTE"):
                phase = 2
            results[ip] = r

            if on_event is not None:
                try:
                    on_event({
                        "ip": ip, "state": state,
                        "mac": mac, "phase": phase,
                    })
                except Exception:
                    log.exception("on_event callback raised — ignored")

        rc = stdout.channel.recv_exit_status()
        err = stderr.read().decode(errors="replace")
        if rc != 0 and not results:
            error_text = (f"scan script exit={rc} "
                          f"stderr={err.strip()[:300] or '(empty)'}")
    except Exception as exc:
        error_text = f"scan exec failed: {exc}"
    finally:
        try:
            client.close()
        except Exception:
            pass

    return results, icmp_replies, arp_replies, error_text


def scan_subnet(target: SSHTarget, cred: SSHCredential, *,
                ip_list: list[str],
                subnet_cidr: str = "",
                source_node_index: int = 0,
                source_node_hostname: str = "",
                scope_id: int = 0,
                batch_size: int = 32,
                ping_timeout_s: int = 1,
                arping_timeout_s: int = 1,
                exec_timeout_s: int = 600,
                on_event: Optional[EventCallback] = None,
                ) -> ScanReport:
    """Synchronous scan over the supplied ip_list. Returns a ScanReport.

    The credential we hold is root on the Forcepoint engine, so raw-socket
    ICMP and arping work without privilege escalation.

    `subnet_cidr` is only carried into the ScanReport for display — the
    actual targets come from `ip_list`. Callers needing range/subnet
    enumeration use the helpers above.
    """
    started = datetime.now(timezone.utc)
    report = ScanReport(
        scope_id=scope_id, subnet_cidr=subnet_cidr,
        started_at=started, source_node_index=source_node_index,
        source_node_hostname=source_node_hostname,
    )

    if not ip_list:
        report.error = "empty target list"
        report.finished_at = datetime.now(timezone.utc)
        return report

    if len(ip_list) > MAX_HOSTS:
        report.error = (f"target list too large ({len(ip_list)} > "
                        f"{MAX_HOSTS} cap)")
        report.finished_at = datetime.now(timezone.utc)
        return report

    report.targets = len(ip_list)

    log.info("dhcp_subnet_scan: scope=%s targets=%d via %s",
             scope_id, len(ip_list), target.hostname)

    results, icmp, arp, err = _run_scan_streaming(
        target, cred, ip_list=ip_list,
        batch_size=batch_size,
        ping_timeout_s=ping_timeout_s,
        arping_timeout_s=arping_timeout_s,
        exec_timeout_s=exec_timeout_s,
        on_event=on_event,
    )
    report.results = results
    report.icmp_replies = icmp
    report.arp_replies = arp
    report.error = err

    report.finished_at = datetime.now(timezone.utc)
    report.duration_ms = int(
        (report.finished_at - report.started_at).total_seconds() * 1000)
    log.info("dhcp_subnet_scan: scope=%s done in %dms — "
             "icmp=%d arp=%d silent=%d error=%r",
             scope_id, report.duration_ms, icmp, arp,
             max(0, len(results) - icmp - arp),
             err)
    return report


def classify(*, has_lease: bool, lease_active: bool,
             icmp_reply: bool, arp_reply: bool) -> str:
    """6-state taxonomy for a single subnet IP.

    Truth table (one row per state, '*' = either value):

        has_lease  lease_active  icmp  arp   →  state
        ─────────  ────────────  ────  ───      ─────────────────────
            ✓           ✓         ✓    *       active
            ✓           ✓         ✗    ✓       firewalled
            ✓           ✓         ✗    ✗       leased-silent
            ✓           ✗         ✗    ✓       firewalled
            ✓           ✗         ✗    ✗       free
            ✗           —         ✓    *       active-untracked
            ✗           —         ✗    ✓       firewalled-untracked
            ✗           —         ✗    ✗       free
    """
    if arp_reply and not icmp_reply:
        return "firewalled" if has_lease else "firewalled-untracked"
    if icmp_reply:
        return "active" if (has_lease and lease_active) else "active-untracked"
    if has_lease and lease_active:
        return "leased-silent"
    return "free"
