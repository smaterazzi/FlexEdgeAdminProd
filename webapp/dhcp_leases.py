"""
FlexEdgeAdmin — Parser for ISC DHCP `dhcpd.leases` files.

Forcepoint NGFW engines use ISC DHCP with leases at
`/spool/dhcp-server/dhcpd.leases` on each cluster node (per KB 000015922).
The file is plain text with blocks of the form:

    lease 192.168.10.55 {
      starts 4 2026/04/24 12:00:00;
      ends 4 2026/04/24 14:00:00;
      tstp 4 2026/04/24 14:00:00;
      cltt 4 2026/04/24 12:00:00;
      binding state active;
      next binding state free;
      hardware ethernet aa:bb:cc:dd:ee:ff;
      uid "\\001\\252\\273\\314\\335\\356\\377";
      client-hostname "my-laptop";
      vendor-class-identifier "MSFT 5.0";
    }

This module turns that into a list of `Lease` dataclasses. No SSH, no DB —
just text in, structured data out.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Lease:
    ip: str
    mac: str = ""
    client_hostname: str = ""
    vendor_class_identifier: str = ""
    binding_state: str = ""                   # active | free | expired | abandoned | backup | released
    next_binding_state: str = ""
    starts: Optional[datetime] = None         # UTC
    ends: Optional[datetime] = None           # UTC  (None means "never" aka infinite)
    cltt: Optional[datetime] = None           # client last transaction time
    tstp: Optional[datetime] = None           # time-sent-to-partner (failover)
    uid_hex: str = ""                          # raw uid string as stored
    extras: dict = field(default_factory=dict)


def _parse_isc_timestamp(s: str) -> Optional[datetime]:
    """Parse an ISC DHCP timestamp.

    Formats seen:
      'never'                              → None (infinite)
      '4 2026/04/24 12:00:00'              → weekday + UTC date/time
      'epoch 1714000000; # Thu Apr 24...'  → epoch seconds (some ISC builds)

    Returns a UTC-aware datetime or None.
    """
    s = s.strip().rstrip(";").strip()
    if not s or s.lower() == "never":
        return None
    parts = s.split()
    if parts[0].lower() == "epoch" and len(parts) >= 2:
        try:
            return datetime.fromtimestamp(int(parts[1]), tz=timezone.utc)
        except (ValueError, OSError):
            return None
    # "W YYYY/MM/DD HH:MM:SS" — first field is weekday (we ignore)
    if len(parts) >= 3:
        try:
            return datetime.strptime(
                f"{parts[1]} {parts[2]}", "%Y/%m/%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def parse_dhcpd_leases(content: str) -> list[Lease]:
    """Parse an entire dhcpd.leases file, return leases in file order.

    Duplicate IPs may appear — ISC appends a new lease block every time
    a lease changes; the last one wins. Callers that want "current lease
    per IP" should take the last occurrence of each ip.
    """
    leases: list[Lease] = []
    cur: Optional[dict] = None

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("lease "):
            # "lease 192.168.10.55 {"
            end = line.find("{")
            ip = line[len("lease "):end if end >= 0 else None].strip()
            cur = {"ip": ip}
            continue
        if cur is None:
            continue
        if line.startswith("}"):
            leases.append(_build_lease(cur))
            cur = None
            continue
        # All other fields end in ';'
        body = line.rstrip(";").rstrip()
        if body.startswith("hardware ethernet "):
            cur["mac"] = body[len("hardware ethernet "):].strip().lower()
        elif body.startswith("client-hostname "):
            cur["client_hostname"] = body[len("client-hostname "):].strip().strip('"')
        elif body.startswith("vendor-class-identifier "):
            cur["vendor_class_identifier"] = body[len("vendor-class-identifier "):].strip().strip('"')
        elif body.startswith("binding state "):
            cur["binding_state"] = body[len("binding state "):].strip()
        elif body.startswith("next binding state "):
            cur["next_binding_state"] = body[len("next binding state "):].strip()
        elif body.startswith("starts "):
            cur["starts"] = _parse_isc_timestamp(body[len("starts "):])
        elif body.startswith("ends "):
            cur["ends"] = _parse_isc_timestamp(body[len("ends "):])
        elif body.startswith("cltt "):
            cur["cltt"] = _parse_isc_timestamp(body[len("cltt "):])
        elif body.startswith("tstp "):
            cur["tstp"] = _parse_isc_timestamp(body[len("tstp "):])
        elif body.startswith("uid "):
            cur["uid_hex"] = body[len("uid "):].strip()
        else:
            cur.setdefault("extras", {})
            # Best-effort split key/value for unknown fields
            if " " in body:
                k, v = body.split(" ", 1)
                cur["extras"][k] = v.strip()

    return leases


def _build_lease(d: dict) -> Lease:
    return Lease(
        ip=d.get("ip", ""),
        mac=d.get("mac", ""),
        client_hostname=d.get("client_hostname", ""),
        vendor_class_identifier=d.get("vendor_class_identifier", ""),
        binding_state=d.get("binding_state", ""),
        next_binding_state=d.get("next_binding_state", ""),
        starts=d.get("starts"),
        ends=d.get("ends"),
        cltt=d.get("cltt"),
        tstp=d.get("tstp"),
        uid_hex=d.get("uid_hex", ""),
        extras=d.get("extras", {}),
    )


def latest_per_ip(leases: list[Lease]) -> list[Lease]:
    """Return one Lease per IP — the last occurrence (latest in the file).

    ISC DHCP appends a fresh block on every state change, so the last one
    is the current truth for that IP.
    """
    by_ip: dict[str, Lease] = {}
    for lease in leases:
        by_ip[lease.ip] = lease
    return list(by_ip.values())


def merge_cluster_leases(per_node: dict[int, list[Lease]]) -> list[dict]:
    """Given a {node_index: [leases]} mapping, produce a flat view suitable
    for the UI — one row per (MAC, IP) pair with a `seen_on_nodes` list.

    Entries with binding_state != 'active' are included but flagged so the
    UI can dim them. Lease freshness (`ends` max) determines which node
    owns the current lease when they disagree.
    """
    key_to_entry: dict[tuple[str, str], dict] = {}
    for node_idx, leases in per_node.items():
        current = latest_per_ip(leases)
        for lease in current:
            key = (lease.mac, lease.ip)
            entry = key_to_entry.get(key)
            if not entry:
                entry = {
                    "mac": lease.mac,
                    "ip": lease.ip,
                    "client_hostname": lease.client_hostname,
                    "vendor_class_identifier": lease.vendor_class_identifier,
                    "binding_state": lease.binding_state,
                    "next_binding_state": lease.next_binding_state,
                    "starts": lease.starts,
                    "ends": lease.ends,
                    "cltt": lease.cltt,
                    "seen_on_nodes": [],
                }
                key_to_entry[key] = entry
            entry["seen_on_nodes"].append(node_idx)
            # Prefer the freshest timestamps across nodes
            if lease.ends and (not entry["ends"] or lease.ends > entry["ends"]):
                entry["ends"] = lease.ends
                entry["binding_state"] = lease.binding_state
                entry["next_binding_state"] = lease.next_binding_state
            if lease.client_hostname and not entry["client_hostname"]:
                entry["client_hostname"] = lease.client_hostname
    return sorted(key_to_entry.values(), key=lambda e: e["ip"])
