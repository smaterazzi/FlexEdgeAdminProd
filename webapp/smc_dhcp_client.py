"""
FlexEdgeAdmin — SMC API client for DHCP reservation operations.

Wraps smc-python to handle:
  - Enumeration of DHCP-enabled interfaces (scopes) on an engine
  - Host element CRUD with full parameter surface
  - MAC marker packing/unpacking in Host comment field
  - Enumeration of cluster nodes for per-node addressing
  - Listing Host elements that fall within a scope's CIDR

The authoritative source of truth for any reservation is the SMC Host element:
  - Host.name      → reservation hostname
  - Host.address   → reserved IPv4 address
  - Host.comment   → free-form operator notes + a [flexedge:mac=...] marker
                     that stores the MAC address. This lets the MAC round-trip
                     through SMC with no schema changes to Forcepoint.
"""
import ipaddress
import logging
import re
from dataclasses import dataclass, field

from smc.core.engine import Engine
from smc.elements.network import Host

from webapp.smc_tls_client import SMCConfig, smc_session, smc_error_detail

logger = logging.getLogger(__name__)

# Re-export so webapp.dhcp_manager can import the session helpers from one place.
__all__ = [
    "SMCConfig", "smc_session", "smc_error_detail",
    "pack_mac_into_comment", "unpack_mac_from_comment",
    "normalize_mac", "is_valid_mac",
    "list_scopes_for_engine", "list_cluster_nodes",
    "host_create", "host_update", "host_delete", "host_list_by_scope",
    "host_get",
    "DhcpScopeInfo", "DhcpClusterNode", "DhcpHostView",
]


# ── MAC marker: round-trip MAC through Host.comment ────────────────────────

# The marker lives on its own line at the end of the comment. Anything before
# it is treated as the operator's free-form notes and preserved on update.
MAC_MARKER_RE = re.compile(r"\[flexedge:mac=([0-9a-fA-F:.\-]{11,17})\]")


def normalize_mac(mac: str) -> str:
    """Normalise to lowercase colon-separated form (aa:bb:cc:dd:ee:ff).

    Accepts `-`, `.`, or `:` separators and any case.
    Raises ValueError if the input does not parse as a 48-bit MAC.
    """
    hex_only = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(hex_only) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    pairs = [hex_only[i:i + 2] for i in range(0, 12, 2)]
    return ":".join(pairs).lower()


def is_valid_mac(mac: str) -> bool:
    try:
        normalize_mac(mac)
        return True
    except ValueError:
        return False


def pack_mac_into_comment(user_comment: str, mac: str) -> str:
    """Produce a Host.comment that carries the MAC alongside operator notes.

    The existing `[flexedge:mac=...]` marker (if any) is stripped before the
    new one is appended, so callers can use this as idempotent "set MAC".
    """
    mac_norm = normalize_mac(mac)
    base = MAC_MARKER_RE.sub("", user_comment or "").rstrip()
    if base:
        return f"{base}\n[flexedge:mac={mac_norm}]"
    return f"[flexedge:mac={mac_norm}]"


def unpack_mac_from_comment(comment: str) -> tuple[str, str | None]:
    """Split a Host.comment into (user_comment_without_marker, mac_or_None).

    MAC is returned normalised, or None if no marker is present.
    """
    if not comment:
        return "", None
    match = MAC_MARKER_RE.search(comment)
    if not match:
        return comment, None
    try:
        mac_norm = normalize_mac(match.group(1))
    except ValueError:
        return comment, None
    cleaned = MAC_MARKER_RE.sub("", comment).rstrip()
    return cleaned, mac_norm


# ── Scope discovery ────────────────────────────────────────────────────────

@dataclass
class DhcpScopeInfo:
    """One DHCP-enabled interface on an engine."""
    engine_name: str
    interface_id: str          # "2" or "2.100" for VLAN
    interface_label: str = ""
    subnet_cidr: str = ""
    gateway: str = ""
    dhcp_pool_start: str = ""
    dhcp_pool_end: str = ""
    default_lease_time: int = 0
    primary_dns: str = ""
    raw: dict = field(default_factory=dict)


def _extract_dhcp_info_from_interface(phys_data: dict, parent_id: str = "") -> list[DhcpScopeInfo]:
    """Walk a physical_interface payload and pull out scopes for every level
    (the interface itself + every VLAN child) where the internal DHCP server
    is enabled.

    The payload shape used here is the one returned by the SMC API's native
    JSON for engine elements — see SMC 7.0 API User Guide page 28:
    `dhcp_server_on_interface`, `default_lease_time`, `dhcp_range_per_node`.
    """
    scopes: list[DhcpScopeInfo] = []
    interface_id = str(phys_data.get("interface_id", parent_id))

    def _extract(data: dict, iface_id: str):
        dhcp_cfg = data.get("dhcp_server_on_interface")
        if not dhcp_cfg or dhcp_cfg == "none":
            return
        if isinstance(dhcp_cfg, dict) and dhcp_cfg.get("dhcp_server_mode") != "server":
            return

        pool_start = ""
        pool_end = ""
        ranges = data.get("dhcp_range_per_node") or []
        if ranges:
            first = ranges[0]
            if isinstance(first, dict):
                pool_range = first.get("dhcp_address_range", "")
            else:
                pool_range = str(first)
            if "-" in pool_range:
                pool_start, pool_end = [p.strip() for p in pool_range.split("-", 1)]

        address = data.get("address") or ""
        network = data.get("network_value") or ""
        cidr = ""
        gateway = ""
        if address and network:
            try:
                net = ipaddress.ip_network(network, strict=False)
                cidr = str(net)
                gateway = address
            except ValueError:
                cidr = network

        scopes.append(DhcpScopeInfo(
            engine_name="",  # caller fills
            interface_id=iface_id,
            interface_label=data.get("comment", "") or f"Interface {iface_id}",
            subnet_cidr=cidr,
            gateway=gateway,
            dhcp_pool_start=pool_start,
            dhcp_pool_end=pool_end,
            default_lease_time=int(data.get("default_lease_time") or 0),
            primary_dns=str(dhcp_cfg.get("primary_dns_server", "") if isinstance(dhcp_cfg, dict) else ""),
            raw=dict(data),
        ))

    for node in phys_data.get("interfaces", []) or []:
        inner = node.get("single_node_interface") or node.get("node_interface") or node
        _extract(inner, interface_id)

    for vlan_wrap in phys_data.get("vlanInterfaces", []) or []:
        vlan = vlan_wrap.get("physical_interface") or vlan_wrap
        vlan_id = str(vlan.get("interface_id", interface_id))
        full_id = f"{interface_id}.{vlan_id}" if vlan_id and vlan_id != interface_id else interface_id
        for node in vlan.get("interfaces", []) or []:
            inner = node.get("single_node_interface") or node.get("node_interface") or node
            _extract(inner, full_id)

    return scopes


def list_scopes_for_engine(engine_name: str) -> list[DhcpScopeInfo]:
    """Return every DHCP-enabled scope on the engine (including VLAN sub-interfaces)."""
    engine = Engine(engine_name)
    scopes: list[DhcpScopeInfo] = []
    for phys in engine.physical_interface:
        try:
            data = phys.data.data if hasattr(phys.data, "data") else dict(phys.data)
        except Exception:
            data = {}
        got = _extract_dhcp_info_from_interface(data)
        for s in got:
            s.engine_name = engine_name
            scopes.append(s)
    return scopes


# ── Cluster nodes ──────────────────────────────────────────────────────────

@dataclass
class DhcpClusterNode:
    node_index: int
    node_id: str = ""
    name: str = ""
    status: str = ""
    primary_address: str = ""     # auto-discovered routable IP


def list_cluster_nodes(engine_name: str) -> list[DhcpClusterNode]:
    """Return one record per node, with node IDs + best-effort primary address.

    The address is discovered from the node's interface status. We pick the
    first non-link-local IPv4 on a non-loopback interface. The Phase 1 SSH
    bootstrap uses this as the default "reach this node at" hint.
    """
    engine = Engine(engine_name)
    nodes: list[DhcpClusterNode] = []
    for idx, n in enumerate(getattr(engine, "nodes", []) or []):
        node_id = ""
        for attr in ("node_id", "nodeid", "key"):
            val = getattr(n, attr, None)
            if val:
                node_id = str(val)
                break
        if not node_id:
            try:
                node_id = n.href.rstrip("/").split("/")[-1]
            except Exception:
                node_id = str(idx)

        address = ""
        try:
            status = n.interface_status
            for row in getattr(status, "interfaces", []) or []:
                candidate = getattr(row, "aggregate_is_active", None)
                addr = getattr(row, "address", "") or ""
                if addr and not addr.startswith("169.254") and not addr.startswith("127."):
                    address = addr
                    break
        except Exception:
            pass

        nodes.append(DhcpClusterNode(
            node_index=idx,
            node_id=node_id,
            name=getattr(n, "name", "") or f"node{idx}",
            status=str(getattr(n, "status", "") or ""),
            primary_address=address,
        ))
    return nodes


# ── Host CRUD ──────────────────────────────────────────────────────────────

@dataclass
class DhcpHostView:
    """Flat view of a Host element — what the CRUD form round-trips."""
    name: str
    address: str = ""
    ipv6_address: str = ""
    secondary: list = field(default_factory=list)
    comment: str = ""                    # already stripped of MAC marker
    mac_address: str | None = None       # extracted from comment marker
    tools_profile_ref: str = ""
    href: str = ""


def _host_to_view(host) -> DhcpHostView:
    data = host.data.data if hasattr(host.data, "data") else dict(host.data)
    raw_comment = data.get("comment", "") or ""
    cleaned, mac = unpack_mac_from_comment(raw_comment)
    return DhcpHostView(
        name=host.name,
        address=data.get("address", "") or "",
        ipv6_address=data.get("ipv6_address", "") or "",
        secondary=list(data.get("secondary", []) or []),
        comment=cleaned,
        mac_address=mac,
        tools_profile_ref=data.get("tools_profile_ref", "") or "",
        href=host.href,
    )


def host_create(name: str, address: str, mac_address: str,
                ipv6_address: str = "", secondary: list | None = None,
                tools_profile_ref: str = "", comment: str = "") -> DhcpHostView:
    """Create a Host element. MAC is packed into comment as a marker."""
    packed = pack_mac_into_comment(comment, mac_address)
    Host.create(
        name=name,
        address=address or None,
        ipv6_address=ipv6_address or None,
        secondary=list(secondary) if secondary else None,
        tools_profile_ref=tools_profile_ref or None,
        comment=packed,
    )
    return _host_to_view(Host(name))


def host_get(name: str) -> DhcpHostView | None:
    try:
        host = Host(name)
        host.href  # force load; raises if missing
        return _host_to_view(host)
    except Exception:
        return None


def host_update(name: str, *,
                address: str | None = None,
                ipv6_address: str | None = None,
                secondary: list | None = None,
                tools_profile_ref: str | None = None,
                comment: str | None = None,
                mac_address: str | None = None) -> DhcpHostView:
    """Update an existing Host element. Only fields passed explicitly are touched.

    Behavior for MAC/comment:
      - If both `comment` and `mac_address` are provided, a new marker is
        added to the given comment.
      - If only `mac_address` is provided, the existing comment (minus any
        existing marker) is preserved and the new marker is appended.
      - If only `comment` is provided, the existing MAC marker on the Host
        is preserved and re-attached to the new comment.
      - If neither is provided, `comment` is left unchanged.
    """
    host = Host(name)
    current = _host_to_view(host)

    payload: dict = {}
    if address is not None:
        payload["address"] = address or None
    if ipv6_address is not None:
        payload["ipv6_address"] = ipv6_address or None
    if secondary is not None:
        payload["secondary"] = list(secondary)
    if tools_profile_ref is not None:
        payload["tools_profile_ref"] = tools_profile_ref or None

    new_user_comment = current.comment if comment is None else comment
    new_mac = current.mac_address if mac_address is None else mac_address
    if comment is not None or mac_address is not None:
        if new_mac:
            payload["comment"] = pack_mac_into_comment(new_user_comment, new_mac)
        else:
            payload["comment"] = new_user_comment or None

    if payload:
        host.update(**payload)
    return _host_to_view(Host(name))


def host_delete(name: str) -> bool:
    try:
        Host(name).delete()
        return True
    except Exception as exc:
        logger.info("Host delete failed for %s: %s", name, smc_error_detail(exc))
        return False


def host_list_by_scope(subnet_cidr: str) -> list[DhcpHostView]:
    """Return every Host whose primary address sits inside the given CIDR.

    We iterate the full Host collection because the SMC API does not support
    subnet filtering on Host. This is fine for typical domain sizes
    (< a few thousand hosts); if it becomes a bottleneck, add a filter on
    the comment marker instead.
    """
    try:
        net = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError:
        return []

    views: list[DhcpHostView] = []
    for host in Host.objects.all():
        try:
            view = _host_to_view(host)
        except Exception:
            continue
        if not view.address:
            continue
        try:
            if ipaddress.ip_address(view.address) in net:
                views.append(view)
        except ValueError:
            continue
    return views
