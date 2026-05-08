"""Engines → Tools → Scan — generic node-side network scanner.

Extends the DHCP subnet scan's 2-phase pattern (ICMP + arping) with
two additional phases that produce per-host port and hostname data:

  Phase 1 — ICMP        parallel ping + ip neighbor show for MAC
  Phase 2 — arping      fallback for ICMP-failed IPs (L2 visibility)
  Phase 3 — port scan   nc -z -w1 per (IP, port) for EVERY target
  Phase 4 — RDNS        nslookup per L2-visible host

Phase 3 deliberately ignores Phase 1/2 results — hosts that drop ICMP
and aren't L2-adjacent (firewalled-but-TCP-open machines across a
routed boundary) are exactly the ones the operator wants to find.
Phase 4 stays gated on L2 visibility because reverse-DNS on dead IPs
is just noise.

Output is one event per line (same shape as the DHCP scanner) so the
job runtime can stream progress live:

  <ip> ICMP_OK [<mac>]
  <ip> ICMP_FAIL
  <ip> ARP_OK <mac>
  <ip> SILENT
  <ip> NO_ROUTE
  <ip> PORT <port> open|closed
  <ip> HOST <hostname>

`nmap` is intentionally NOT used — Forcepoint NGFW BusyBox doesn't
ship it. `nc -z` (TCP zero-I/O scan) and `nslookup` are universal in
BusyBox builds, confirmed on the lab cluster on 2026-05-07.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from webapp.dhcp_ssh import SSHTarget, SSHCredential, ssh_connect

log = logging.getLogger(__name__)


MAX_HOSTS = 4096          # = /20
MAX_PORTS = 256
WARN_OPS_THRESHOLD = 8000   # default /24 × 25 ports = 6,375 fits
HARD_OPS_CAP = 16384

# Curated TCP-ports default — locked in 2026-05-07 (see
# docs/Engines-ScanTool.md "Default port list").
DEFAULT_PORTS: tuple[int, ...] = (
    20, 21,                   # FTP
    22,                       # SSH
    23,                       # Telnet
    25,                       # SMTP
    53,                       # DNS (TCP)
    80,                       # HTTP
    110,                      # POP3
    135,                      # RPC
    137, 138, 139,            # NetBIOS
    143,                      # IMAP
    389,                      # LDAP
    443,                      # HTTPS
    445,                      # SMB
    993,                      # IMAPS
    995,                      # POP3S
    1433,                     # MS SQL
    1521,                     # Oracle
    3306,                     # MySQL
    3389,                     # RDP
    5432,                     # PostgreSQL
    5900,                     # VNC
    8080,                     # HTTP-alt / proxy
)


@dataclass
class HostResult:
    ip: str
    icmp_reply: bool = False
    arp_reply: bool = False
    mac: str = ""
    hostname: str = ""
    ports: dict[int, str] = field(default_factory=dict)  # port -> 'open'|'closed'

    @property
    def reachable(self) -> bool:
        return self.icmp_reply or self.arp_reply

    @property
    def open_ports(self) -> list[int]:
        return sorted(p for p, s in self.ports.items() if s == "open")


@dataclass
class EngineScanReport:
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_ms: int = 0
    source_node_index: int = 0
    source_node_hostname: str = ""
    source_iface_id: str = ""
    source_iface_name: str = ""
    target_label: str = ""           # human-readable target description
    targets: int = 0
    ports_scanned: list[int] = field(default_factory=list)
    icmp_replies: int = 0
    arp_replies: int = 0
    hosts_with_open_ports: int = 0
    error: str = ""
    results: dict[str, HostResult] = field(default_factory=dict)


# ── Port-list parsing ───────────────────────────────────────────────────


_PORT_TOKEN_RE = re.compile(r"^\s*(\d+)\s*(?:-\s*(\d+)\s*)?$")


def parse_port_list(raw: str) -> list[int]:
    """Parse a comma- or whitespace-separated list of TCP ports.

    Accepts ranges via ``a-b``. Returns a deduped sorted list. Raises
    ValueError on bad tokens or out-of-range values.
    """
    if not raw or not raw.strip():
        return []
    out: set[int] = set()
    for tok in re.split(r"[,\s]+", raw.strip()):
        if not tok:
            continue
        m = _PORT_TOKEN_RE.match(tok)
        if not m:
            raise ValueError(f"invalid port token: {tok!r}")
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        if a < 1 or b > 65535 or a > b:
            raise ValueError(f"port out of range or reversed: {tok!r}")
        out.update(range(a, b + 1))
    return sorted(out)


# ── Remote shell script ─────────────────────────────────────────────────
#
# Args (after `_`):
#   $1 BATCH                parallel job ceiling
#   $2 PING_TIMEOUT_S
#   $3 ARPING_TIMEOUT_S
#   $4 PORT_TIMEOUT_S       nc -z -w
#   $5 DNS_TIMEOUT_S        unused today (nslookup has no per-call timeout
#                            in BusyBox, but we keep the slot for future use)
#   $6 PORTS_CSV            comma-separated TCP ports, "" = skip Phase 3
#   $@ (after shift 6)      target IPs
#
# Phases stream to stdout AND a TMP file (Phase 1 results so Phase 2 has
# its work list). Each phase emits one line per (IP) or (IP, port). The
# Python parser drives the progress bar from these.
#
# Phase 3 (port scan) probes EVERY target regardless of L1/L2 reply —
# firewalled-but-TCP-open hosts are common (Windows desktops, web
# servers behind firewalls that drop ICMP). Phase 4 (RDNS) only resolves
# hostnames for hosts that did reply, since reverse-DNS on dead IPs is
# noise.
# Every external utility (ping, ip, arping, nc, nslookup, awk, grep,
# head, sed, tr, mktemp, rm) is invoked through `busybox <applet>`
# rather than a bare command name. On Forcepoint NGFW BusyBox builds
# the applet symlinks under /bin are not all present — running plain
# `nc -z` / `arping` / `nslookup` returns "command not found" so the
# script silently records every port as closed and fires no SYN
# packets at all. Going through the `busybox` multi-call binary
# always works because BusyBox itself is on PATH on every engine.
# Shell builtins (printf, echo, [, read, set, wait, for, :) do NOT
# need the prefix — ash handles those directly.
_SCAN_SCRIPT = r"""
BATCH=$1; PT=$2; AT=$3; CT=$4; DT=$5; PORTS=$6; VERBOSE=$7; shift 7
TMP=$(busybox mktemp 2>/dev/null || echo /tmp/.fea-escan.$$)
REACHABLE=$(busybox mktemp 2>/dev/null || echo /tmp/.fea-escan-r.$$)
: > "$TMP"
: > "$REACHABLE"

# Phase 1 — ICMP
n=0
for ip in "$@"; do
    (
        [ "$VERBOSE" = "1" ] && printf 'EXEC busybox ping -c 1 -W %s -q %s\n' "$PT" "$ip"
        if busybox ping -c 1 -W "$PT" -q "$ip" >/dev/null 2>&1; then
            NEIGH=$(busybox ip neighbor show "$ip" 2>/dev/null | busybox head -1)
            MAC=$(printf '%s\n' "$NEIGH" | busybox grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | busybox head -1)
            if [ -n "$MAC" ]; then
                printf '%s ICMP_OK %s\n' "$ip" "$MAC"
            else
                printf '%s ICMP_OK\n' "$ip"
            fi
            printf '%s ICMP_OK\n' "$ip" >> "$TMP"
            printf '%s\n' "$ip" >> "$REACHABLE"
        else
            printf '%s ICMP_FAIL\n' "$ip"
            printf '%s ICMP_FAIL\n' "$ip" >> "$TMP"
        fi
    ) &
    n=$((n+1))
    if [ "$n" -ge "$BATCH" ]; then wait; n=0; fi
done
wait

# Phase 2 — arping fallback for ICMP_FAIL
# CRITICAL: do NOT use `set -- $line` here. That would clobber the
# top-level "$@" (the original target IP list), and Phase 3 below
# does `for ip in "$@"` to iterate every target × every port — if
# Phase 2 ran even once, "$@" would become ("<last_ip>", "<state>")
# and Phase 3 would silently scan only those two "IPs", with
# `nc: bad address 'ICMP_FAIL'` on the second one. We hit exactly
# this bug 2026-05-08 — operator's real-world scans were probing
# < 1% of intended targets because most subnets have many
# ICMP-failing hosts. Read directly into named vars instead.
while read -r ip state; do
    if [ "$state" = "ICMP_FAIL" ]; then
        DEV=$(busybox ip route get "$ip" 2>/dev/null | busybox awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1); exit}')
        if [ -z "$DEV" ]; then
            printf '%s NO_ROUTE\n' "$ip"
            continue
        fi
        [ "$VERBOSE" = "1" ] && printf 'EXEC busybox arping -c 1 -w %s -I %s %s\n' "$AT" "$DEV" "$ip"
        OUT=$(busybox arping -c 1 -w "$AT" -I "$DEV" "$ip" 2>&1)
        MAC=$(printf '%s\n' "$OUT" | busybox grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | busybox head -1)
        if [ -n "$MAC" ]; then
            printf '%s ARP_OK %s\n' "$ip" "$MAC"
            printf '%s\n' "$ip" >> "$REACHABLE"
        else
            printf '%s SILENT\n' "$ip"
        fi
    fi
done < "$TMP"

# Phase 3 — port scan over ALL targets (regardless of L1/L2 reply).
# Hosts that drop ICMP and aren't L2-adjacent (e.g. firewalled servers
# across a routed boundary) can still have open TCP ports — that's the
# whole point of running Tools→Scan against a remote subnet.
#
# TCP probe form: ``busybox timeout $CT busybox nc <ip> <port>
# < /dev/null > /dev/null 2>&1``. The Forcepoint engine BusyBox build
# has a stripped ``nc`` that only supports ``-iN -wN -l -p -f -e`` —
# there is NO ``-z`` (zero-I/O scan) flag. So we open a real
# connection, immediately send EOF from /dev/null (which closes our
# write side), and let the remote close. ``busybox timeout`` wraps
# the call to bound wall-clock time on blackholed targets where the
# kernel's TCP RTO would otherwise stretch past 1s. Exit code:
#   0   = connect succeeded and remote closed within $CT seconds
#   124 = timeout fired (blackholed OR remote refused to close —
#         treated as "closed" either way, the latter is a known
#         false-negative for chatty long-lived services like RDP)
#   1   = connection refused fast (RST received)
# Any non-zero is reported as "closed" by the parser. False-negative
# rate on real-world ports is acceptable; if it becomes a problem
# we'd need a Python-side paramiko TCP probe instead of nc.
if [ -n "$PORTS" ]; then
    for ip in "$@"; do
        for port in $(printf '%s' "$PORTS" | busybox tr ',' ' '); do
            (
                [ "$VERBOSE" = "1" ] && printf 'EXEC busybox timeout %s busybox nc %s %s\n' "$CT" "$ip" "$port"
                if busybox timeout "$CT" busybox nc "$ip" "$port" < /dev/null > /dev/null 2>&1; then
                    printf '%s PORT %s open\n' "$ip" "$port"
                else
                    printf '%s PORT %s closed\n' "$ip" "$port"
                fi
            ) &
            n=$((n+1))
            if [ "$n" -ge "$BATCH" ]; then wait; n=0; fi
        done
    done
    wait
fi

# Phase 4 — RDNS only for L2-visible hosts (reverse-DNS on dead IPs
# is noise; we don't want hostname-result rows for silent targets).
if [ -s "$REACHABLE" ]; then
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        (
            [ "$VERBOSE" = "1" ] && printf 'EXEC busybox nslookup %s\n' "$ip"
            HN=$(busybox nslookup "$ip" 2>/dev/null | busybox awk -F'= ' '/name = / {print $2; exit}' | busybox sed 's/\.$//')
            if [ -n "$HN" ]; then
                printf '%s HOST %s\n' "$ip" "$HN"
            fi
        ) &
        n=$((n+1))
        if [ "$n" -ge "$BATCH" ]; then wait; n=0; fi
    done < "$REACHABLE"
    wait
fi

busybox rm -f "$TMP" "$REACHABLE"
"""


# ── Scan execution ─────────────────────────────────────────────────────


EventCallback = Callable[[dict], None]


def _run_scan(target: SSHTarget, cred: SSHCredential, *,
              ip_list: list[str], ports: list[int],
              batch_size: int = 32,
              ping_timeout_s: int = 1,
              arping_timeout_s: int = 1,
              port_timeout_s: int = 2,
              dns_timeout_s: int = 2,
              exec_timeout_s: int = 900,
              verbose: bool = False,
              on_event: Optional[EventCallback] = None,
              ) -> tuple[dict[str, HostResult], dict, str]:
    """Open SSH, run the scan script, parse stdout line-by-line.

    Returns (results, summary_counters, error_text). On error `results`
    may be partial. Caller wraps in EngineScanReport.

    ``verbose=True`` flips on a $VERBOSE=1 flag in the shell script:
    every network command (ping / arping / nc / nslookup) emits an
    extra ``EXEC <command>`` line BEFORE the command runs, which
    surfaces in the watcher's live log so an operator can confirm
    the script reached each phase. Off by default — verbose mode
    multiplies stdout volume by 2-3× for big scans.
    """
    cmd_parts = ["sh", "-c", _SCAN_SCRIPT, "_",
                 str(batch_size),
                 str(ping_timeout_s), str(arping_timeout_s),
                 str(port_timeout_s), str(dns_timeout_s),
                 ",".join(str(p) for p in ports),
                 "1" if verbose else "0"]
    cmd_parts.extend(ip_list)
    cmd = " ".join(shlex.quote(p) for p in cmd_parts)

    try:
        client = ssh_connect(target, cred)
    except Exception as exc:
        return {}, {}, f"SSH connect failed: {exc}"

    results: dict[str, HostResult] = {}
    counters = {"icmp_replies": 0, "arp_replies": 0,
                "ports_open": 0, "ports_closed": 0,
                "hostnames_resolved": 0}
    error_text = ""

    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=exec_timeout_s)
        for raw in iter(stdout.readline, ''):
            parts = raw.strip().split()
            if not parts:
                continue

            # Verbose-mode trace: shell script emits one
            # ``EXEC <command…>`` line BEFORE each network command in
            # verbose mode. Route as a log event without touching the
            # results dict — it's not tied to a specific IP.
            if parts[0] == "EXEC":
                if on_event is not None:
                    try:
                        on_event({"tag": "EXEC",
                                  "command": " ".join(parts[1:])})
                    except Exception:
                        log.exception("on_event callback raised — ignored")
                continue

            ip = parts[0]
            tag = parts[1] if len(parts) > 1 else "SILENT"
            r = results.get(ip) or HostResult(ip=ip)
            ev: dict = {"ip": ip, "tag": tag}

            if tag == "ICMP_OK":
                if not r.icmp_reply:
                    counters["icmp_replies"] += 1
                r.icmp_reply = True
                r.arp_reply = True
                if len(parts) > 2 and not r.mac:
                    r.mac = parts[2].lower()
                ev["mac"] = r.mac
            elif tag == "ICMP_FAIL":
                pass  # progress only; Phase 2 will resolve
            elif tag == "ARP_OK":
                if not r.arp_reply:
                    counters["arp_replies"] += 1
                r.arp_reply = True
                if len(parts) > 2:
                    r.mac = parts[2].lower()
                ev["mac"] = r.mac
            elif tag == "PORT" and len(parts) >= 4:
                port = int(parts[2])
                state = parts[3].lower()
                r.ports[port] = state
                if state == "open":
                    counters["ports_open"] += 1
                else:
                    counters["ports_closed"] += 1
                ev["port"] = port
                ev["port_state"] = state
            elif tag == "HOST" and len(parts) >= 3:
                r.hostname = parts[2]
                counters["hostnames_resolved"] += 1
                ev["hostname"] = r.hostname
            # SILENT / NO_ROUTE: no fields to update

            results[ip] = r
            if on_event is not None:
                try:
                    on_event(ev)
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

    return results, counters, error_text


def scan(target: SSHTarget, cred: SSHCredential, *,
         ip_list: list[str], ports: list[int],
         source_node_index: int = 0,
         source_node_hostname: str = "",
         source_iface_id: str = "",
         source_iface_name: str = "",
         target_label: str = "",
         batch_size: int = 32,
         ping_timeout_s: int = 1,
         arping_timeout_s: int = 1,
         port_timeout_s: int = 2,
         dns_timeout_s: int = 2,
         exec_timeout_s: int = 900,
         verbose: bool = False,
         on_event: Optional[EventCallback] = None,
         ) -> EngineScanReport:
    """Synchronous engine-side scan. Returns an EngineScanReport.

    The credential we hold is root on the Forcepoint engine, so
    ping / arping / nc raw-socket ops work without privilege escalation.
    """
    started = datetime.now(timezone.utc)
    report = EngineScanReport(
        started_at=started,
        source_node_index=source_node_index,
        source_node_hostname=source_node_hostname,
        source_iface_id=source_iface_id,
        source_iface_name=source_iface_name,
        target_label=target_label,
        ports_scanned=list(ports),
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
    if len(ports) > MAX_PORTS:
        report.error = (f"port list too large ({len(ports)} > "
                        f"{MAX_PORTS} cap)")
        report.finished_at = datetime.now(timezone.utc)
        return report

    report.targets = len(ip_list)

    log.info("engine_scan: targets=%d ports=%d via %s/node%s (%s)",
             len(ip_list), len(ports), target.hostname,
             source_node_index, source_iface_id)

    results, counters, err = _run_scan(
        target, cred, ip_list=ip_list, ports=ports,
        batch_size=batch_size,
        ping_timeout_s=ping_timeout_s,
        arping_timeout_s=arping_timeout_s,
        port_timeout_s=port_timeout_s,
        dns_timeout_s=dns_timeout_s,
        exec_timeout_s=exec_timeout_s,
        verbose=verbose,
        on_event=on_event,
    )
    report.results = results
    report.icmp_replies = counters.get("icmp_replies", 0)
    report.arp_replies = counters.get("arp_replies", 0)
    report.hosts_with_open_ports = sum(
        1 for r in results.values() if r.open_ports)
    report.error = err

    report.finished_at = datetime.now(timezone.utc)
    report.duration_ms = int(
        (report.finished_at - report.started_at).total_seconds() * 1000)
    log.info("engine_scan: done in %dms — icmp=%d arp=%d open_hosts=%d err=%r",
             report.duration_ms, report.icmp_replies, report.arp_replies,
             report.hosts_with_open_ports, err)
    return report
