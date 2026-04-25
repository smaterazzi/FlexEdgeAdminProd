"""
FlexEdgeAdmin — Engine Inquiry helpers.

Read-only SMC queries that power the Engines section of the web UI.
Wrapped in defensive try/except per data slice so one failing API call
(e.g. an unreachable node returning a routing error) doesn't break
the entire detail page.

Public API:
    list_clusters(cfg)        -> list[EngineSummary]
    cluster_detail(cfg, name) -> ClusterDetail
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from smc.core.engine import Engine

import smc_client                      # dict-shaped smc_session matching get_user_cfg()
from webapp.smc_tls_client import list_engines

log = logging.getLogger(__name__)


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass
class EngineSummary:
    name: str
    typeof: str
    node_count: int = 0
    installed_policy: str = ""
    href: str = ""


@dataclass
class InterfaceAddress:
    address: str = ""
    network_value: str = ""   # CIDR / mask
    nodeid: int | None = None  # which cluster node owns this NDI


@dataclass
class InterfaceInfo:
    interface_id: str = ""
    vlan_id: str = ""           # "" for non-VLAN parent interface
    zone: str = ""
    addresses: list[InterfaceAddress] = field(default_factory=list)


@dataclass
class NodeInfo:
    nodeid: int = 0
    name: str = ""
    engine_version: str = ""
    status_state: str = ""      # e.g. "Online", "Unknown", "Offline"
    status_detail: str = ""     # additional info from appliance_status
    interfaces: list[InterfaceInfo] = field(default_factory=list)


@dataclass
class ClusterDetail:
    name: str = ""
    typeof: str = ""
    href: str = ""
    installed_policy: str = ""
    contact_addresses: list[dict] = field(default_factory=list)
    routing: list[dict] = field(default_factory=list)
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    nodes: list[NodeInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────────

def _safe(call, default, label, errors=None):
    """Call ``call()``; on exception, log and return ``default``.
    If ``errors`` is provided, append a one-line message to it.
    """
    try:
        return call()
    except Exception as exc:
        log.warning("%s failed: %s", label, exc)
        if errors is not None:
            errors.append(f"{label}: {exc}")
        return default


def _extract_nodeid(node_obj) -> int:
    for attr in ("nodeid", "node_id", "key"):
        v = getattr(node_obj, attr, None)
        if isinstance(v, int):
            return v
    # Fall back to data dict
    try:
        d = getattr(node_obj, "data", None)
        if d is not None:
            for k in ("nodeid", "node_id"):
                v = d.get(k)
                if isinstance(v, int):
                    return v
    except Exception:
        pass
    return 0


def _addresses_from_iface_payload(iface_data: dict) -> list[InterfaceAddress]:
    """Extract address list from a physical/vlan interface JSON payload.
    Handles single_node_interface / node_interface / cluster_virtual_interface.
    """
    out: list[InterfaceAddress] = []
    inner = iface_data.get("interfaces") or []
    for entry in inner:
        for key in ("single_node_interface", "node_interface",
                    "cluster_virtual_interface"):
            ndi = entry.get(key)
            if not ndi:
                continue
            out.append(InterfaceAddress(
                address=str(ndi.get("address", "")),
                network_value=str(ndi.get("network_value", "")),
                nodeid=ndi.get("nodeid"),
            ))
    return out


def _walk_interfaces(engine) -> list[InterfaceInfo]:
    """Flatten physical + VLAN sub-interfaces into a single rendered list."""
    out: list[InterfaceInfo] = []
    try:
        for pi in engine.physical_interface:
            try:
                pi_data = getattr(pi, "data", {}) or {}
                # Top-level (untagged) addresses
                top_addrs = _addresses_from_iface_payload(pi_data)
                if top_addrs:
                    out.append(InterfaceInfo(
                        interface_id=str(pi_data.get("interface_id", "") or ""),
                        vlan_id="",
                        zone=str(pi_data.get("zone_ref", "") or ""),
                        addresses=top_addrs,
                    ))
                # VLAN sub-interfaces
                for vlan in (pi_data.get("vlanInterfaces") or []):
                    out.append(InterfaceInfo(
                        interface_id=str(pi_data.get("interface_id", "") or ""),
                        vlan_id=str(vlan.get("vlan_id", "") or ""),
                        zone=str(vlan.get("zone_ref", "") or ""),
                        addresses=_addresses_from_iface_payload(vlan),
                    ))
            except Exception as exc:
                log.debug("interface walk failed for one PI: %s", exc)
                continue
    except Exception as exc:
        log.warning("physical_interface enumeration failed: %s", exc)
    return out


def _node_interfaces(all_ifaces: list[InterfaceInfo], nodeid: int) -> list[InterfaceInfo]:
    """Filter a flat interface list to entries that have an address belonging
    to the given nodeid (or no nodeid, meaning shared / cluster-virtual)."""
    out: list[InterfaceInfo] = []
    for iface in all_ifaces:
        node_addrs = [
            a for a in iface.addresses
            if a.nodeid is None or a.nodeid == nodeid
        ]
        if not node_addrs:
            continue
        out.append(InterfaceInfo(
            interface_id=iface.interface_id,
            vlan_id=iface.vlan_id,
            zone=iface.zone,
            addresses=node_addrs,
        ))
    return out


def _routing_summary(engine, errors: list[str]) -> list[dict]:
    """Return a flat list of routing entries: {network, gateway, type, comment}."""
    out: list[dict] = []
    try:
        for entry in engine.routing.all():
            try:
                out.append({
                    "name": getattr(entry, "name", "") or "",
                    "level": getattr(entry, "level", "") or "",
                    "ip": getattr(entry, "ip", "") or "",
                    "routing_node_element": getattr(entry, "routing_node_element", "") or "",
                })
            except Exception:
                continue
    except Exception as exc:
        errors.append(f"routing: {exc}")
    return out


def _contact_addresses(engine, errors: list[str]) -> list[dict]:
    out: list[dict] = []
    try:
        for ca in engine.contact_addresses:
            try:
                out.append({
                    "interface_id": getattr(ca, "interface_id", "") or "",
                    "interface_ip": getattr(ca, "interface_ip", "") or "",
                    "addresses": [str(a) for a in (getattr(ca, "addresses", None) or [])],
                })
            except Exception:
                continue
    except Exception as exc:
        errors.append(f"contact_addresses: {exc}")
    return out


def _node_status(node, errors: list[str]) -> tuple[str, str]:
    """Return (state, detail). Cheap-ish but does an API call."""
    try:
        st = node.status()
        # ApplianceStatus exposes attributes like .state, .name, .version, .status
        state = (
            getattr(st, "state", None)
            or getattr(st, "status", None)
            or "Unknown"
        )
        detail_parts = []
        for key in ("name", "version", "platform", "configuration_status",
                    "installed_policy"):
            v = getattr(st, key, None)
            if v:
                detail_parts.append(f"{key}={v}")
        return str(state), "; ".join(detail_parts)
    except Exception as exc:
        errors.append(f"status({getattr(node, 'name', '?')}): {exc}")
        return "Unknown", ""


# ── Public API ───────────────────────────────────────────────────────────

def list_clusters(cfg) -> list[EngineSummary]:
    """Return a summary list of every engine visible with the given creds."""
    out: list[EngineSummary] = []
    with smc_client.smc_session(cfg):
        try:
            raw = list_engines()  # list of {name, type, href, sources}
        except Exception as exc:
            log.error("list_engines failed: %s", exc)
            return []

        for entry in raw:
            try:
                eng = Engine(entry["name"])
                node_count = 0
                try:
                    node_count = sum(1 for _ in eng.nodes)
                except Exception:
                    pass
                installed = ""
                try:
                    installed = eng.installed_policy or ""
                except Exception:
                    pass
                out.append(EngineSummary(
                    name=entry["name"],
                    typeof=entry.get("type", ""),
                    node_count=node_count,
                    installed_policy=installed,
                    href=entry.get("href", ""),
                ))
            except Exception as exc:
                log.warning("Could not summarize engine %s: %s",
                            entry.get("name"), exc)
                out.append(EngineSummary(
                    name=entry["name"],
                    typeof=entry.get("type", ""),
                ))
    out.sort(key=lambda s: s.name.lower())
    return out


def cluster_detail(cfg, engine_name: str) -> ClusterDetail:
    """Fetch full cluster detail (best-effort, partial errors tolerated)."""
    detail = ClusterDetail(name=engine_name)
    with smc_client.smc_session(cfg):
        try:
            engine = Engine(engine_name)
        except Exception as exc:
            detail.errors.append(f"engine_load: {exc}")
            return detail

        detail.typeof = getattr(engine, "typeof", "") or ""
        detail.href = getattr(engine, "href", "") or ""
        detail.installed_policy = _safe(
            lambda: engine.installed_policy or "",
            default="", label="installed_policy", errors=detail.errors,
        )

        all_ifaces = _walk_interfaces(engine)
        detail.interfaces = all_ifaces
        detail.routing = _routing_summary(engine, detail.errors)
        detail.contact_addresses = _contact_addresses(engine, detail.errors)

        # Nodes
        try:
            for node in engine.nodes:
                nid = _extract_nodeid(node)
                version = ""
                try:
                    version = (getattr(node, "engine_version", None)
                               or getattr(node, "data", {}).get("engine_version", "")
                               or "")
                except Exception:
                    pass
                state, status_detail = _node_status(node, detail.errors)
                detail.nodes.append(NodeInfo(
                    nodeid=nid,
                    name=getattr(node, "name", "") or f"node-{nid}",
                    engine_version=version,
                    status_state=state,
                    status_detail=status_detail,
                    interfaces=_node_interfaces(all_ifaces, nid),
                ))
        except Exception as exc:
            detail.errors.append(f"nodes: {exc}")

        detail.nodes.sort(key=lambda n: n.nodeid)

    return detail
