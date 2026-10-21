"""
FlexEdgeAdmin — VLAN consistency check (NS2): firewall interface ↔ switch port.

Pure logic, no Flask / DB / SMC import, so it unit-tests on plain dicts:

* `firewall_ports(engine_name, cluster)` — one row per (node, physical
  interface) from the cached `domain_objects.cluster` dict: the VLAN ids the
  firewall tags on that interface, whether it also carries untagged
  addresses, its zones, its `lldp_mode`, and the node's addresses on it.
* `lldp_links(fw_ports, switches)` — auto-discovery: a switch port whose
  LLDP neighbour address is one of a firewall node's addresses is the port
  that node interface is plugged into. Forcepoint ships `lldp_mode=disabled`,
  so this finds nothing until an operator enables `send_only` on the
  switch-facing interfaces; manual links (stored by the caller) cover the
  rest.
* `compare(fw_port, switch_port)` — the actual check: VLANs the firewall
  tags but the switch port doesn't carry tagged (`missing`), VLANs the
  switch carries that the firewall doesn't use (`extra`), untagged mismatches.

Switch ports are the NetSight shape returned by `netsight_objects.netsight_ports`
(`portName`, `tagged`, `untagged`, `portAdmin`, `portNeighborAddress`).
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional


def _vlan_int(value) -> Optional[int]:
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return v if 1 <= v <= 4094 else None


def _ip(value) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _int_list(values) -> list:
    out = []
    for v in values or []:
        n = _vlan_int(v)
        if n is not None:
            out.append(n)
    return out


def firewall_ports(engine_name: str, cluster: dict) -> list:
    """Rows `{engine, node_index, node_name, interface_id, vlans, untagged,
    zones, lldp_mode, addresses}` sorted by node, then interface id.

    An address with `nodeid` None (single-node engine, or a cluster CVI) is
    shared by every node; on a multi-node cluster it is kept out of
    `addresses` (it can't tell nodes apart) but still marks the interface
    as untagged."""
    cluster = cluster or {}
    nodes = [n for n in (cluster.get("nodes") or []) if isinstance(n, dict)]
    node_list = [(int(n.get("nodeid") or 0) or 1, n.get("name") or "") for n in nodes] or [(1, "")]
    multi = len(node_list) > 1

    per_iface = {}
    for iface in cluster.get("interfaces") or []:
        iid = str(iface.get("interface_id") or "").strip()
        if not iid:
            continue
        slot = per_iface.setdefault(iid, {"vlans": set(), "untagged": False,
                                          "zones": [], "lldp_mode": "", "addrs": []})
        vlan = _vlan_int(iface.get("vlan_id")) if iface.get("vlan_id") else None
        addrs = [a for a in (iface.get("addresses") or []) if _ip(a.get("address"))]
        if vlan is not None:
            slot["vlans"].add(vlan)
        elif addrs:
            slot["untagged"] = True
        zone = str(iface.get("zone") or "")
        if zone and zone not in slot["zones"]:
            slot["zones"].append(zone)
        if iface.get("lldp_mode") and not slot["lldp_mode"]:
            slot["lldp_mode"] = str(iface["lldp_mode"])
        slot["addrs"].extend(addrs)

    rows = []
    for node_index, node_name in node_list:
        for iid, slot in per_iface.items():
            own = []
            for a in slot["addrs"]:
                nid = a.get("nodeid")
                if (nid is None and not multi) or (nid is not None and int(nid) == node_index):
                    ip = _ip(a.get("address"))
                    if ip not in own:
                        own.append(ip)
            rows.append({
                "engine": engine_name, "node_index": node_index, "node_name": node_name,
                "interface_id": iid, "vlans": sorted(slot["vlans"]),
                "untagged": slot["untagged"], "zones": list(slot["zones"]),
                "lldp_mode": slot["lldp_mode"], "addresses": own,
            })
    rows.sort(key=lambda r: (r["engine"], r["node_index"], _iface_sort_key(r["interface_id"])))
    return rows


def _iface_sort_key(iid: str):
    try:
        return (0, int(iid), "")
    except ValueError:
        return (1, 0, iid)


def port_key(row: dict) -> tuple:
    """Identity of a firewall port — matches `SwitchPortLink`'s unique key."""
    return (row["engine"], int(row["node_index"]), str(row["interface_id"]))


def lldp_links(fw_ports: Iterable[dict], switches: dict) -> list:
    """`switches` = `{switch_ip: {"sysName", "ports": [...]}}`. Returns
    `[{engine, node_index, interface_id, switch_ip, port_name, address}]`.
    An address claimed by more than one firewall port (duplicate config)
    is ambiguous and ignored."""
    owner, ambiguous = {}, set()
    for row in fw_ports:
        for ip in row.get("addresses") or []:
            if ip in owner and owner[ip] != port_key(row):
                ambiguous.add(ip)
            owner.setdefault(ip, port_key(row))
    links, seen = [], set()
    for switch_ip, payload in (switches or {}).items():
        for p in (payload or {}).get("ports") or []:
            nb = _ip(p.get("portNeighborAddress"))
            if not nb or nb in ambiguous or nb not in owner:
                continue
            key = owner[nb]
            if key in seen:
                continue
            seen.add(key)
            links.append({"engine": key[0], "node_index": key[1], "interface_id": key[2],
                          "switch_ip": switch_ip, "port_name": str(p.get("portName") or ""),
                          "address": nb})
    return links


def find_port(switch_payload: Optional[dict], port_name: str) -> Optional[dict]:
    for p in (switch_payload or {}).get("ports") or []:
        if str(p.get("portName") or "") == str(port_name):
            return p
    return None


def compare(fw_port: dict, switch_port: Optional[dict]) -> dict:
    """`{status, missing, extra, untagged_on_switch, notes}` where status is
    `no_port` (link points at a port NetSight doesn't list), `missing`
    (firewall VLAN not carried tagged on the switch port, or an untagged
    mismatch), `extra` (switch carries VLANs the firewall doesn't use —
    usually harmless, listed so trunks can be pruned) or `ok`."""
    if switch_port is None:
        return {"status": "no_port", "missing": [], "extra": [], "untagged_on_switch": [],
                "notes": ["the switch no longer lists this port — re-map it"]}
    fw = set(fw_port.get("vlans") or [])
    tagged = set(_int_list(switch_port.get("tagged")))
    untagged = _int_list(switch_port.get("untagged"))
    notes = []
    as_untagged = sorted(fw & set(untagged))
    missing = sorted(fw - tagged)
    extra = sorted(tagged - fw)
    if as_untagged:
        notes.append("VLAN %s is untagged on the switch but tagged on the firewall"
                     % ", ".join(map(str, as_untagged)))
    untagged_problem = bool(fw_port.get("untagged")) and not untagged
    if untagged_problem:
        notes.append("the firewall has an untagged address here but the switch port "
                     "carries no untagged VLAN")
    if switch_port.get("portAdmin") is False:
        notes.append("switch port is administratively down")
    if missing or untagged_problem:
        status = "missing"
    elif extra:
        status = "extra"
    else:
        status = "ok"
    return {"status": status, "missing": missing, "extra": extra,
            "untagged_on_switch": untagged, "notes": notes}
