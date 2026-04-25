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
from smc.elements.service import TCPService
from smc.policy.layer3 import FirewallPolicy
from smc.policy.rule_elements import Action, LogOptions

from webapp.smc_tls_client import (
    SMCConfig, smc_session, smc_error_detail, get_engine_active_policy,
)

logger = logging.getLogger(__name__)

# Re-export so webapp.dhcp_manager can import the session helpers from one place.
__all__ = [
    "SMCConfig", "smc_session", "smc_error_detail",
    "pack_mac_into_comment", "unpack_mac_from_comment",
    "normalize_mac", "is_valid_mac",
    "list_scopes_for_engine", "list_cluster_nodes",
    "dump_engine_interfaces",
    "host_create", "host_update", "host_delete", "host_list_by_scope",
    "host_get",
    "DhcpScopeInfo", "DhcpClusterNode", "DhcpHostView", "NodeAddress",
    "is_node_initiated_contact",
    "set_node_ssh_enabled", "change_node_ssh_password",
    "find_active_policy", "find_ssh_access_rule",
    "add_ssh_access_rule", "remove_ssh_access_rule",
    "policy_upload",
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


def _dhcp_is_active(cfg) -> bool:
    """Return True iff the given `dhcp_server_on_interface` value represents
    an *active* internal DHCP server.

    Handles every shape we've seen in the wild across SMC versions:
      - missing / None / "" / False / "none" → inactive
      - bool True → active
      - string enum like "dhcp_server" → active (anything not in the inactive set)
      - dict with `dhcp_server_mode == "server"` → active
      - dict without a mode key but with pool/range hints → active
    """
    if cfg is None or cfg is False or cfg == "" or cfg == "none":
        return False
    if cfg is True:
        return True
    if isinstance(cfg, dict):
        mode = cfg.get("dhcp_server_mode")
        if mode is not None:
            return str(mode).lower() == "server"
        return bool(
            cfg.get("dhcp_address_range")
            or cfg.get("dhcp_range_per_node")
            or cfg.get("default_gateway")
            or cfg.get("primary_dns_server")
        )
    if isinstance(cfg, str):
        return cfg.lower() not in ("none", "off", "disabled", "no", "false")
    return True


def _find_level_dhcp(level_payload: dict) -> tuple[dict, str, str] | None:
    """Look at a single interface-level payload (either a physical interface
    or a VLAN child) and see if DHCP is active ON THIS LEVEL.

    DHCP config can live in two places depending on engine type / SMC version:
      1. At the interface top level — `level_payload["dhcp_server_on_interface"]`
         (the shape documented in the SMC 7.0 API Guide page 28)
      2. Inside a node entry — `level_payload["interfaces"][N].single_node_interface.dhcp_server_on_interface`
         (seen on some cluster configurations)

    Returns `(dhcp_cfg_dict, address, network_value)` if active, else None.
    The address/network are what we'll use to compute the scope's CIDR.
    """
    # Location 1: interface top level
    cfg = level_payload.get("dhcp_server_on_interface")
    if _dhcp_is_active(cfg):
        cfg_dict = cfg if isinstance(cfg, dict) else {}
        address = level_payload.get("address") or ""
        network = level_payload.get("network_value") or ""
        # If the top level has DHCP but no IP on itself, look for a node IP
        if not (address and network):
            for node in level_payload.get("interfaces", []) or []:
                inner = (node.get("single_node_interface")
                         or node.get("node_interface")
                         or node.get("cluster_virtual_interface")
                         or node)
                if inner.get("address") and inner.get("network_value"):
                    address = inner["address"]
                    network = inner["network_value"]
                    break
        return cfg_dict, address, network

    # Location 2: node-level
    for node in level_payload.get("interfaces", []) or []:
        inner = (node.get("single_node_interface")
                 or node.get("node_interface")
                 or node.get("cluster_virtual_interface")
                 or node)
        inner_cfg = inner.get("dhcp_server_on_interface")
        if _dhcp_is_active(inner_cfg):
            cfg_dict = inner_cfg if isinstance(inner_cfg, dict) else {}
            return cfg_dict, inner.get("address", ""), inner.get("network_value", "")

    return None


def _build_scope(engine_name: str, iface_id: str,
                 level_payload: dict, dhcp_cfg: dict,
                 address: str, network: str) -> DhcpScopeInfo:
    """Construct a DhcpScopeInfo from a resolved DHCP-active interface level."""
    pool_start = ""
    pool_end = ""
    # Pool can be at the top (older shape) or inside dhcp_cfg (newer shape)
    ranges = (level_payload.get("dhcp_range_per_node")
              or dhcp_cfg.get("dhcp_range_per_node")
              or [])
    single_range = dhcp_cfg.get("dhcp_address_range", "")
    if ranges:
        first = ranges[0] if ranges else {}
        pool_range = first.get("dhcp_address_range", "") if isinstance(first, dict) else str(first)
        if "-" in pool_range:
            pool_start, pool_end = [p.strip() for p in pool_range.split("-", 1)]
    elif "-" in single_range:
        pool_start, pool_end = [p.strip() for p in single_range.split("-", 1)]

    cidr = ""
    gateway = ""
    if address and network:
        try:
            net = ipaddress.ip_network(network, strict=False)
            cidr = str(net)
            gateway = address
        except ValueError:
            cidr = network

    lease = int(
        level_payload.get("default_lease_time")
        or dhcp_cfg.get("default_lease_time")
        or 0
    )
    primary_dns = str(dhcp_cfg.get("primary_dns_server", ""))

    return DhcpScopeInfo(
        engine_name=engine_name,
        interface_id=iface_id,
        interface_label=level_payload.get("comment", "") or f"Interface {iface_id}",
        subnet_cidr=cidr,
        gateway=gateway,
        dhcp_pool_start=pool_start,
        dhcp_pool_end=pool_end,
        default_lease_time=lease,
        primary_dns=primary_dns,
        raw=dict(level_payload),
    )


def _walk_interface(level_payload: dict, engine_name: str,
                    parent_iface_id: str = "") -> list[DhcpScopeInfo]:
    """Operator-spec traversal:

      1. If DHCP is active at this level → record a scope.
      2. If this level has VLAN children → descend into each and apply (1).
      3. If no DHCP and no VLANs → skip (naturally; no scope is produced).

    A VLAN child can still contribute a scope even if its parent also did
    (e.g. a physical with a management IP + DHCP, plus VLAN sub-nets each
    with their own DHCP). Both get recorded.
    """
    scopes: list[DhcpScopeInfo] = []
    # When recursed with a composed parent id (e.g. "2.100"), that's the
    # authoritative path — the VLAN's own interface_id is already baked in.
    iface_id = parent_iface_id or str(level_payload.get("interface_id") or "")

    vlans = (level_payload.get("vlanInterfaces")
             or level_payload.get("vlan_interfaces")
             or [])

    # Rule 1: current level
    found = _find_level_dhcp(level_payload)
    if found:
        cfg_dict, address, network = found
        scope = _build_scope(engine_name, iface_id, level_payload,
                             cfg_dict, address, network)
        scopes.append(scope)

    # Rule 3 optimisation: if no DHCP and no VLANs, nothing to do
    if not found and not vlans:
        return scopes

    # Rule 2: descend into VLANs (regardless of whether parent had DHCP)
    for vlan_wrap in vlans:
        vlan = vlan_wrap.get("physical_interface") or vlan_wrap
        vlan_raw_id = vlan.get("interface_id", "")
        # Compose full VLAN id: "<parent>.<vlan_id>", e.g. "2.100"
        if vlan_raw_id and str(vlan_raw_id) != iface_id:
            combined = f"{iface_id}.{vlan_raw_id}"
        else:
            combined = iface_id
        scopes.extend(_walk_interface(vlan, engine_name, combined))

    return scopes


def list_scopes_for_engine(engine_name: str) -> list[DhcpScopeInfo]:
    """Return every DHCP-enabled scope on the engine (physical + VLAN children).

    Traversal (per operator spec):
      - Check DHCP at the physical-interface level.
      - If VLANs exist, recurse into each and apply the same rule.
      - Skip branches with neither DHCP nor VLANs.
    """
    engine = Engine(engine_name)
    scopes: list[DhcpScopeInfo] = []
    visited = 0
    for phys in engine.physical_interface:
        try:
            data = phys.data.data if hasattr(phys.data, "data") else dict(phys.data)
        except Exception:
            data = {}
        visited += 1
        got = _walk_interface(data, engine_name)
        vlans = (data.get("vlanInterfaces") or data.get("vlan_interfaces") or [])
        dhcp_here = _find_level_dhcp(data) is not None
        logger.info(
            "DHCP discovery: engine=%s interface_id=%s dhcp_here=%s vlan_count=%d scopes=%d",
            engine_name,
            data.get("interface_id"),
            dhcp_here,
            len(vlans),
            len(got),
        )
        scopes.extend(got)
    logger.info("DHCP discovery: engine=%s visited=%d total_scopes=%d",
                engine_name, visited, len(scopes))
    return scopes


def dump_engine_interfaces(engine_name: str) -> dict:
    """Diagnostic helper: return the raw interface JSON plus the walker's
    per-level decisions. Use via /dhcp/api/.../engines/<n>/interfaces/debug
    when a scope you expect is not detected.
    """
    engine = Engine(engine_name)
    payload: dict = {"engine_name": engine_name, "interfaces": []}

    def _annotate(level_payload: dict, iface_id: str) -> dict:
        found = _find_level_dhcp(level_payload)
        vlans_raw = (level_payload.get("vlanInterfaces")
                     or level_payload.get("vlan_interfaces")
                     or [])
        annotated_vlans = []
        for vlan_wrap in vlans_raw:
            vlan = vlan_wrap.get("physical_interface") or vlan_wrap
            vlan_raw_id = vlan.get("interface_id", "")
            combined = f"{iface_id}.{vlan_raw_id}" if vlan_raw_id else iface_id
            annotated_vlans.append(_annotate(vlan, combined))
        return {
            "interface_id": iface_id or level_payload.get("interface_id"),
            "dhcp_here": found is not None,
            "dhcp_address": found[1] if found else None,
            "dhcp_network": found[2] if found else None,
            "raw_top_level_keys": sorted(level_payload.keys()),
            "raw_dhcp_value_type": type(level_payload.get("dhcp_server_on_interface")).__name__,
            "raw_dhcp_value_snippet": str(level_payload.get("dhcp_server_on_interface"))[:120],
            "vlan_count": len(vlans_raw),
            "vlan_children": annotated_vlans,
            "raw": level_payload,
        }

    for phys in engine.physical_interface:
        try:
            data = phys.data.data if hasattr(phys.data, "data") else dict(phys.data)
        except Exception:
            data = {}
        iface_id = str(data.get("interface_id") or "")
        payload["interfaces"].append(_annotate(data, iface_id))
    return payload


# ── Cluster nodes ──────────────────────────────────────────────────────────

@dataclass
class NodeAddress:
    """A single static IP assigned to a cluster node on one interface (NDI)."""
    interface_id: str            # "0", "1.100" for VLAN child
    address: str
    network_value: str
    nodeid: int                   # cluster node identifier (1-based in SMC)
    is_primary_mgt: bool = False
    is_outgoing: bool = False
    is_dynamic: bool = False      # True for DHCP-assigned (not a stable target)


@dataclass
class DhcpClusterNode:
    node_index: int               # 0-based for our purposes (engine.nodes[i])
    node_id: str = ""             # SMC's node identifier — survives rename/reorder
    name: str = ""
    nodeid: int = 0               # SMC's nodeid value (matches NodeAddress.nodeid)
    status: str = ""
    addresses: list = field(default_factory=list)    # list[NodeAddress]
    primary_address: str = ""     # the SMC-managed primary mgmt IP (auto target)


def _walk_node_interfaces(level_payload: dict, parent_iface_id: str = ""
                          ) -> list[NodeAddress]:
    """Recursively walk a physical_interface payload and collect every static
    NDI address (SingleNodeInterface or NodeInterface), including VLAN children.

    Skips dynamic (DHCP-assigned) interfaces — they're not stable targets.
    """
    out: list[NodeAddress] = []
    iface_id = parent_iface_id or str(level_payload.get("interface_id") or "")

    # Direct interfaces on this level (each entry wraps a single_node_interface
    # or node_interface; cluster_virtual_interface is the CVI which we skip)
    for entry in level_payload.get("interfaces", []) or []:
        for inner_kind, inner in entry.items():
            if inner_kind not in ("single_node_interface", "node_interface"):
                continue
            if not isinstance(inner, dict):
                continue
            address = inner.get("address") or ""
            network = inner.get("network_value") or ""
            is_dynamic = bool(inner.get("dynamic"))
            if not address and not is_dynamic:
                continue
            out.append(NodeAddress(
                interface_id=iface_id,
                address=address,
                network_value=network,
                nodeid=int(inner.get("nodeid") or 0),
                is_primary_mgt=bool(inner.get("primary_mgt")),
                is_outgoing=bool(inner.get("outgoing")),
                is_dynamic=is_dynamic,
            ))

    # VLAN children
    vlans = (level_payload.get("vlanInterfaces")
             or level_payload.get("vlan_interfaces") or [])
    for vlan_wrap in vlans:
        vlan = vlan_wrap.get("physical_interface") or vlan_wrap
        vlan_raw_id = vlan.get("interface_id", "")
        combined = f"{iface_id}.{vlan_raw_id}" if vlan_raw_id else iface_id
        out.extend(_walk_node_interfaces(vlan, combined))

    return out


def is_node_initiated_contact(engine_name: str) -> bool:
    """Detect whether the engine uses *node-initiated contact* (the engine
    reaches out to SMC rather than SMC reaching in).

    Implementation: check every primary management NodeInterface for the
    `reverse_connection` flag. The SDK's NodeInterface docstring explicitly
    states *"Reverse connection enables engine to contact SMC versus other
    way around"* — which is the SMC term for node-initiated mode.

    Returns False on any error (treat as conservative SMC-initiated default).
    """
    try:
        engine = Engine(engine_name)
        for phys in engine.physical_interface:
            try:
                data = phys.data.data if hasattr(phys.data, "data") else dict(phys.data)
            except Exception:
                continue
            # Walk same as _walk_node_interfaces but return early on a hit
            for entry in data.get("interfaces", []) or []:
                for kind, inner in entry.items():
                    if kind not in ("single_node_interface", "node_interface"):
                        continue
                    if isinstance(inner, dict) and inner.get("primary_mgt"):
                        if inner.get("reverse_connection"):
                            return True
            # Also walk VLAN children
            for vlan_wrap in (data.get("vlanInterfaces")
                              or data.get("vlan_interfaces") or []):
                vlan = vlan_wrap.get("physical_interface") or vlan_wrap
                for entry in vlan.get("interfaces", []) or []:
                    for kind, inner in entry.items():
                        if kind not in ("single_node_interface", "node_interface"):
                            continue
                        if isinstance(inner, dict) and inner.get("primary_mgt"):
                            if inner.get("reverse_connection"):
                                return True
    except Exception as exc:
        logger.info("is_node_initiated_contact(%s): %s", engine_name, exc)
    return False


def list_cluster_nodes(engine_name: str) -> list[DhcpClusterNode]:
    """Return one record per cluster node with **all** static NDI addresses
    (per-node).

    Strategy:
      1. Walk every physical interface (incl. VLAN children) and collect
         every NodeInterface/SingleNodeInterface entry (NDI).
      2. Group entries by `nodeid` — that's the cluster node identifier
         baked into the interface config (1, 2, ... for cluster members).
      3. Map each `engine.nodes[i]` to one of these groups by matching
         the SDK's node attribute ordering.
      4. The "primary address" for each node is the one tagged `primary_mgt`
         (the IP SMC uses to reach the node). For node-initiated clusters
         this may not be reachable from FEA — the operator picks instead.
    """
    engine = Engine(engine_name)

    # Collect every NDI address across all interfaces
    all_addresses: list[NodeAddress] = []
    for phys in engine.physical_interface:
        try:
            data = phys.data.data if hasattr(phys.data, "data") else dict(phys.data)
        except Exception:
            continue
        all_addresses.extend(_walk_node_interfaces(data))

    # Group by nodeid (1-based in SMC). Single-node engines may not assign
    # a nodeid; treat unset as 1.
    by_nodeid: dict[int, list[NodeAddress]] = {}
    for a in all_addresses:
        nid = a.nodeid or 1
        by_nodeid.setdefault(nid, []).append(a)

    # Map engine.nodes (which has display ordering) to our groups
    nodes_meta = list(getattr(engine, "nodes", []) or [])
    out: list[DhcpClusterNode] = []
    for idx, n in enumerate(nodes_meta):
        # Try to extract the node's nodeid from the SDK
        smc_nodeid = 0
        for attr in ("nodeid", "node_id", "key"):
            val = getattr(n, attr, None)
            if val and str(val).isdigit():
                smc_nodeid = int(val)
                break

        # Match group: prefer SDK-reported nodeid, else assume idx+1 (1-based)
        if smc_nodeid in by_nodeid:
            group = by_nodeid[smc_nodeid]
        elif (idx + 1) in by_nodeid:
            group = by_nodeid[idx + 1]
            smc_nodeid = idx + 1
        else:
            # Single-node case — give the node all addresses
            group = list(all_addresses) if len(nodes_meta) == 1 else []

        # Identify primary address: the one tagged primary_mgt
        primary = next((a.address for a in group if a.is_primary_mgt and a.address), "")

        # Stable node_id for our DB (must survive renames). Fall back to href tail.
        node_id = ""
        for attr in ("node_id", "key"):
            val = getattr(n, attr, None)
            if val:
                node_id = str(val)
                break
        if not node_id:
            try:
                node_id = n.href.rstrip("/").split("/")[-1]
            except Exception:
                node_id = str(smc_nodeid or (idx + 1))

        out.append(DhcpClusterNode(
            node_index=idx,
            node_id=node_id,
            name=getattr(n, "name", "") or f"node{idx + 1}",
            nodeid=smc_nodeid or (idx + 1),
            status=str(getattr(n, "status", "") or ""),
            addresses=[a for a in group if a.address],   # drop dynamic-no-address
            primary_address=primary,
        ))

    # Edge case: no engine.nodes reported (very unusual — fallback to address groups)
    if not out and by_nodeid:
        for nid, group in sorted(by_nodeid.items()):
            primary = next((a.address for a in group if a.is_primary_mgt and a.address), "")
            out.append(DhcpClusterNode(
                node_index=nid - 1, node_id=str(nid), name=f"node{nid}",
                nodeid=nid, addresses=[a for a in group if a.address],
                primary_address=primary,
            ))
    return out


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


# ── Node SSH controls (Phase 1c — auto-enrollment) ──────────────────────

def set_node_ssh_enabled(engine_name: str, node_index: int,
                         enabled: bool, comment: str = "") -> None:
    """Enable or disable the SSH daemon on a single cluster node."""
    engine = Engine(engine_name)
    nodes = list(getattr(engine, "nodes", []) or [])
    if node_index >= len(nodes):
        raise ValueError(
            f"Node index {node_index} out of range (engine has {len(nodes)} node(s))"
        )
    nodes[node_index].ssh(enable=enabled, comment=comment or None)


def change_node_ssh_password(engine_name: str, node_index: int,
                             new_password: str, comment: str = "") -> None:
    """Set the root SSH password on a single cluster node via SMC API.

    Underlying call: `node.change_ssh_pwd` from fp-NGFW-SMC-python. Audit
    comment is recorded by SMC and visible in Management Client.
    """
    engine = Engine(engine_name)
    nodes = list(getattr(engine, "nodes", []) or [])
    if node_index >= len(nodes):
        raise ValueError(
            f"Node index {node_index} out of range (engine has {len(nodes)} node(s))"
        )
    nodes[node_index].change_ssh_pwd(new_password, comment=comment or None)


# ── Active policy + SSH-access rule management (Phase 1c) ───────────────

def find_active_policy(engine_name: str) -> str:
    """Return the name of the policy currently installed on the engine.

    Falls back to engine-level installed_policy attribute. Raises
    RuntimeError if no policy is found (caller surfaces as actionable
    error to the operator).
    """
    policy = get_engine_active_policy(engine_name)
    if not policy:
        raise RuntimeError(
            f"No installed policy found on engine {engine_name!r} — "
            f"install a policy in SMC before enrolling SSH credentials."
        )
    if hasattr(policy, "name"):
        return policy.name
    return str(policy)


def find_ssh_access_rule(policy_name: str, rule_name: str) -> dict | None:
    """Locate our managed rule by exact name. Returns
    {name, href, is_disabled, comment} or None if missing.
    """
    policy = FirewallPolicy(policy_name)
    for rule in policy.fw_ipv4_access_rules.all():
        if rule.name == rule_name:
            return {
                "name": rule.name,
                "href": rule.href,
                "is_disabled": rule.is_disabled,
                "comment": rule.comment or "",
            }
    return None


def _ensure_host_for_ip(name: str, ip: str) -> Host:
    """Idempotent: get-or-create a Host element with the given name+IP."""
    try:
        host = Host(name)
        host.href     # force load
        return host
    except Exception:
        Host.create(name=name, address=ip)
        return Host(name)


def add_ssh_access_rule(policy_name: str, rule_name: str,
                        source_ip: str, destination_ips: list[str],
                        comment: str = "") -> str:
    """Insert (at top of rule list) an Allow rule on TCP/22 from source_ip
    to one OR MORE destination IPs in the named policy. Returns the new
    rule's href.

    Idempotent: if a rule with `rule_name` already exists, this returns its
    href without re-adding.

    Each destination IP is wrapped as its own Host element named
    `{rule_name}-dst-<index>` so multi-node clusters end up with one rule
    that targets every node IP.
    """
    if not destination_ips:
        raise ValueError("add_ssh_access_rule requires at least one destination IP")

    existing = find_ssh_access_rule(policy_name, rule_name)
    if existing:
        return existing["href"]

    src_host = _ensure_host_for_ip(f"{rule_name}-src", source_ip)
    dst_hosts: list[Host] = []
    for i, ip in enumerate(destination_ips):
        host_name = f"{rule_name}-dst-{i}"
        dst_hosts.append(_ensure_host_for_ip(host_name, ip))

    policy = FirewallPolicy(policy_name)
    action = Action()
    action.action = "allow"

    log_opts = LogOptions()
    log_opts.log_level = "stored"

    policy.fw_ipv4_access_rules.create(
        name=rule_name,
        sources=[src_host],
        destinations=dst_hosts,
        services=[TCPService("SSH")],
        action=action,
        log_options=log_opts,
        add_pos=1,
        comment=comment[:255] if comment else "",
    )
    after = find_ssh_access_rule(policy_name, rule_name)
    if not after:
        raise RuntimeError(
            f"Created rule {rule_name!r} but cannot find it again — "
            f"policy iteration returned nothing matching the name."
        )
    return after["href"]


def remove_ssh_access_rule(policy_name: str, rule_name: str
                           ) -> tuple[bool, str]:
    """Delete the named rule from the policy. Also tries to remove the
    Host elements we created for it (`-src` and any `-dst-<n>` from
    multi-IP rules, plus the legacy `-dst` from single-IP rules).

    Returns (rule_was_present, message). `rule_was_present=False` if it
    was already gone (still considered success — idempotent).
    """
    policy = FirewallPolicy(policy_name)
    target = None
    for rule in policy.fw_ipv4_access_rules.all():
        if rule.name == rule_name:
            target = rule
            break
    rule_existed = target is not None
    if target:
        try:
            target.delete()
        except Exception as exc:
            return rule_existed, f"rule delete failed: {smc_error_detail(exc)}"

    # Best-effort host cleanup. Cover the legacy single-`-dst` shape and
    # the new multi-`-dst-<n>` shape. Stop at the first missing index for
    # the multi-shape — typical cluster size is 2-4 so iterating ~16 is fine.
    for legacy_suffix in ("-src", "-dst"):
        try:
            Host(f"{rule_name}{legacy_suffix}").delete()
        except Exception:
            pass
    for i in range(16):
        try:
            Host(f"{rule_name}-dst-{i}").delete()
        except Exception:
            pass

    return rule_existed, "ok"


def policy_upload(engine_name: str, policy_name: str | None = None) -> str:
    """Trigger a policy install on the engine. Synchronous-feeling — the
    SDK call returns once the upload task completes."""
    engine = Engine(engine_name)
    if policy_name:
        return str(engine.upload(policy=policy_name))
    return str(engine.upload())
