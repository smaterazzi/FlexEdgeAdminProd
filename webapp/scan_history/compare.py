"""Pure diff helpers for engine scan comparison.

Compares 2+ scans of the SAME (engine_name, source_iface_label) scope and
produces a structured report:

  CompareReport
    scans  : list[ScanSummary]                  column headers, ASC by time
    hosts  : list[HostTimeline]                 row data, IP-sorted
    scope  : str                                "engine / iface"
    mixed_scope : bool                          True if input was rejected

  HostTimeline
    ip            : str
    ip_int        : int                         numeric sort key
    cells         : list[HostCell]              parallel to scans
    has_changes   : bool                        any non-empty delta?
    first_seen_idx: int                         column index of first sighting

  HostCell
    seen          : bool
    icmp          : bool
    arp           : bool
    mac           : str
    hostname      : str
    open_ports    : list[int]                   sorted
    closed_ports  : list[int]                   sorted
    delta_open_added   : list[int]              vs previous-seen cell
    delta_open_removed : list[int]              vs previous-seen cell
    delta_status       : str                    'first'|'unchanged'|'changed'|'gone'

The "previous-seen" semantics: deltas compare each cell against the
nearest earlier cell where `seen` was true. A host that appears for the
first time gets `delta_status='first'`. A host present then absent gets
a synthetic `gone` cell column-side annotation (the cell itself stays
seen=False; we just flag has_changes).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from webapp.models import EngineScanRecord, EngineScanHost
from webapp.scan_history.service import _ip_to_int

log = logging.getLogger("scan_history.compare")

# Hard upper bound — keeps the diff table readable and bounds memory.
MAX_SCANS_PER_COMPARE = 10
MIN_SCANS_PER_COMPARE = 2


# ── Dataclasses ─────────────────────────────────────────────────────────

@dataclass
class ScanSummary:
    id: int
    started_at_iso: str
    started_at_human: str
    starred: bool
    online_ips: int
    hosts_with_open: int
    source: str   # manual|scheduled|api
    comment: str


@dataclass
class HostCell:
    seen: bool = False
    icmp: bool = False
    arp: bool = False
    mac: str = ""
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)
    delta_open_added: list[int] = field(default_factory=list)
    delta_open_removed: list[int] = field(default_factory=list)
    delta_status: str = "unchanged"   # first|unchanged|changed|gone


@dataclass
class HostTimeline:
    ip: str
    ip_int: int
    cells: list[HostCell] = field(default_factory=list)
    has_changes: bool = False
    first_seen_idx: int = -1
    last_hostname: str = ""        # most recent non-empty
    last_mac: str = ""             # most recent non-empty


@dataclass
class CompareReport:
    scans: list[ScanSummary] = field(default_factory=list)
    hosts: list[HostTimeline] = field(default_factory=list)
    scope_engine: str = ""
    scope_iface: str = ""
    error: str = ""    # set when scope guard fails or input invalid

    @property
    def mixed_scope(self) -> bool:
        return self.error.startswith("mixed")


# ── Public API ──────────────────────────────────────────────────────────

def compare_scans(domain, scan_ids: list[int]) -> CompareReport:
    """Build a CompareReport for the given scan IDs.

    Returns a CompareReport with `error` populated when:
      - <2 or >10 scans selected
      - scans cross multiple (engine, iface) scopes
      - any scan id doesn't belong to the active Domain

    Caller is responsible for redirecting / flashing on `report.error`.
    """
    rep = CompareReport()
    if domain is None:
        rep.error = "no active domain"
        return rep

    ids = [int(i) for i in scan_ids if i]
    if len(ids) < MIN_SCANS_PER_COMPARE:
        rep.error = (f"select at least {MIN_SCANS_PER_COMPARE} scans "
                     f"to compare")
        return rep
    if len(ids) > MAX_SCANS_PER_COMPARE:
        rep.error = (f"too many scans selected ({len(ids)} > "
                     f"{MAX_SCANS_PER_COMPARE} hard cap) — narrow the set")
        return rep

    # Fetch records, scope-check, sort ASC by started_at
    records = (EngineScanRecord.query
               .filter(EngineScanRecord.id.in_(ids),
                       EngineScanRecord.domain_id == domain.id)
               .all())
    if len(records) != len(set(ids)):
        rep.error = ("one or more scans not found in your Domain "
                     "(or expired) — refresh the history list")
        return rep

    scopes = {(r.engine_name or "", r.source_iface_label or "") for r in records}
    if len(scopes) > 1:
        rep.error = (f"mixed scope — selected scans span "
                     f"{len(scopes)} different (engine, interface) pairs. "
                     f"Compare only works within one scope.")
        return rep

    scope_engine, scope_iface = scopes.pop() if scopes else ("", "")
    rep.scope_engine = scope_engine
    rep.scope_iface = scope_iface

    records.sort(key=lambda r: (r.started_at, r.id))
    rep.scans = [_summarise(r) for r in records]

    # Pre-fetch all hosts in one round-trip, group by scan_id.
    sids = [r.id for r in records]
    hosts_rows = (EngineScanHost.query
                  .filter(EngineScanHost.scan_id.in_(sids))
                  .all())
    hosts_by_scan: dict[int, dict[str, EngineScanHost]] = {sid: {} for sid in sids}
    for h in hosts_rows:
        hosts_by_scan[h.scan_id][h.ip] = h

    # Union of all IPs across the selected scans.
    all_ips: set[str] = set()
    for d in hosts_by_scan.values():
        all_ips.update(d.keys())

    timelines: list[HostTimeline] = []
    for ip in all_ips:
        timelines.append(_build_timeline(ip, records, hosts_by_scan))

    timelines.sort(key=lambda t: (t.ip_int, t.ip))
    rep.hosts = timelines
    return rep


# ── Internals ───────────────────────────────────────────────────────────

def _summarise(r: EngineScanRecord) -> ScanSummary:
    return ScanSummary(
        id=r.id,
        started_at_iso=r.started_at.isoformat(),
        started_at_human=r.started_at.strftime("%Y-%m-%d %H:%M"),
        starred=bool(r.starred),
        online_ips=int(r.online_ips or 0),
        hosts_with_open=int(r.hosts_with_open or 0),
        source=(r.source or "manual"),
        comment=(r.comment or "")[:160],
    )


def _split_csv_int(raw: Optional[str]) -> list[int]:
    if not raw:
        return []
    out: list[int] = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(int(tok))
        except ValueError:
            continue
    return sorted(set(out))


def _build_timeline(ip: str,
                    records: list[EngineScanRecord],
                    hosts_by_scan: dict[int, dict[str, EngineScanHost]],
                    ) -> HostTimeline:
    timeline = HostTimeline(ip=ip, ip_int=_ip_to_int(ip))
    last_open: Optional[set[int]] = None
    last_seen_idx = -1
    last_hostname = ""
    last_mac = ""

    for idx, rec in enumerate(records):
        h = hosts_by_scan.get(rec.id, {}).get(ip)
        if h is None:
            cell = HostCell(seen=False)
            # Annotate "gone" on the first column where the host disappears
            # after being present in an earlier column.
            if last_seen_idx >= 0 and idx == last_seen_idx + 1:
                cell.delta_status = "gone"
                timeline.has_changes = True
            timeline.cells.append(cell)
            continue

        open_ports = _split_csv_int(h.open_ports_csv)
        closed_ports = _split_csv_int(h.closed_ports_csv)
        cell = HostCell(
            seen=True,
            icmp=bool(h.icmp_reply),
            arp=bool(h.arp_reply),
            mac=h.mac or "",
            hostname=h.hostname or "",
            open_ports=open_ports,
            closed_ports=closed_ports,
        )

        cur = set(open_ports)
        if last_open is None:
            cell.delta_status = "first"
            if timeline.first_seen_idx < 0:
                timeline.first_seen_idx = idx
        else:
            added = sorted(cur - last_open)
            removed = sorted(last_open - cur)
            cell.delta_open_added = added
            cell.delta_open_removed = removed
            if added or removed:
                cell.delta_status = "changed"
                timeline.has_changes = True
            else:
                cell.delta_status = "unchanged"

        if h.hostname:
            last_hostname = h.hostname
        if h.mac:
            last_mac = h.mac
        last_open = cur
        last_seen_idx = idx
        timeline.cells.append(cell)

    timeline.last_hostname = last_hostname
    timeline.last_mac = last_mac
    return timeline
