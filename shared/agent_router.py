"""
FlexEdgeAdmin — remote-agent router (RA-B, docs/RemoteAgents.md § Routing).

Address-based routing on top of the kit's capability/tag routing. The
operator-facing concept is **reachable networks**: a CIDR list the admin
sets per agent in the Portal (never self-declared by the agent), plus
`platform_settings.server_reachable_networks` for the FlexEdge host itself
("pure local execution").

One decision point — `pick_executor(domain, targets, capability)`:

  1. every target IP covered by ONE agent's CIDRs, that agent online, not
     `moved`, not revoked, advertising `capability` → the one with the
     shortest queue wins ("agent");
  2. else the server's own CIDRs cover every target → "local";
  3. else "refused" with a flash-ready reason listing what is uncovered.

v1 never splits a task across executors. Hostnames are NOT resolved here —
callers pass IPs.

Pure module: no webapp import at module load (tests run without Flask).
"""

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

SERVER_NETWORKS_KEY = "server_reachable_networks"
_SPLIT_RE = re.compile(r"[\s,]+")


@dataclass
class RouteDecision:
    kind: str                          # "agent" | "local" | "refused"
    agent_name: Optional[str] = None   # for kind == "agent"
    reason: str = ""                   # human sentence, used verbatim in flashes
    targets: List[str] = field(default_factory=list)   # normalised target IPs
    uncovered: List[str] = field(default_factory=list)  # for "refused"

    @property
    def ok(self) -> bool:
        return self.kind != "refused"


# ── CIDR helpers ─────────────────────────────────────────────────────────

def parse_networks(raw: str) -> List[str]:
    """One CIDR per line / comma / space → normalised, de-duplicated list.
    `ip_network(strict=False)` so `10.0.0.5/24` becomes `10.0.0.0/24`.
    Raises ValueError naming the bad entry."""
    nets, seen = [], set()
    for token in _SPLIT_RE.split(raw or ""):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise ValueError(
                f"'{token}' is not a valid network (use CIDR, e.g. 10.0.0.0/24)")
        text = str(net)
        if text not in seen:
            seen.add(text)
            nets.append(text)
    return nets


def _iface_network(address: str, network_value: str):
    """SMC NDI `network_value` is normally the CIDR ("10.1.0.0/24"); fall back
    to address + dotted mask. None when nothing usable."""
    nv = (network_value or "").strip()
    try:
        if "/" in nv:
            return ipaddress.ip_network(nv, strict=False)
        if address and nv:
            return ipaddress.ip_interface(f"{address.strip()}/{nv}").network
    except ValueError:
        return None
    return None


def interface_networks(clusters) -> List[dict]:
    """Subnets attached to firewall interfaces — candidates for an agent's
    reachable networks (the New-agent picker).

    `clusters` is an iterable of `(engine_name, cluster_dict)` where
    `cluster_dict` is the cached `domain_objects.cluster` shape: `interfaces[]`
    and `nodes[].interfaces[]`, each `{interface_id, vlan_id, zone,
    addresses: [{address, network_value}]}`. Host routes (/32, /128),
    loopback, link-local and unspecified networks are dropped.

    Returns `[{"network": "10.1.0.0/24", "sources": ["FW01 1.42 · Inside", …]}]`
    sorted by address family, then network."""
    found = {}
    for engine_name, detail in clusters:
        detail = detail or {}
        ifaces = list(detail.get("interfaces") or [])
        for node in detail.get("nodes") or []:
            ifaces.extend(node.get("interfaces") or [])
        for iface in ifaces:
            label = str(iface.get("interface_id") or "?")
            if iface.get("vlan_id"):
                label += f".{iface['vlan_id']}"
            source = f"{engine_name} {label}" + (f" · {iface['zone']}" if iface.get("zone") else "")
            for addr in iface.get("addresses") or []:
                net = _iface_network(addr.get("address", ""), addr.get("network_value", ""))
                if (net is None or net.prefixlen == net.max_prefixlen or net.is_loopback
                        or net.is_link_local or net.is_unspecified):
                    continue
                sources = found.setdefault(net, [])
                if source not in sources:
                    sources.append(source)
    ordered = sorted(found, key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return [{"network": str(n), "sources": found[n]} for n in ordered]


def covers(cidrs: Iterable[str], ip: str) -> bool:
    """True when `ip` falls inside any of `cidrs`. Bad entries are skipped."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs or ():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _covers_all(cidrs, targets) -> bool:
    return bool(targets) and all(covers(cidrs, t) for t in targets)


# ── Server-side setting ──────────────────────────────────────────────────

def server_reachable_networks() -> List[str]:
    """`platform_settings.server_reachable_networks` as a list; [] when
    unset or unparsable."""
    try:
        from shared.logging import get_setting
        raw = get_setting(SERVER_NETWORKS_KEY)
        if not raw:
            return []
        value = json.loads(raw)
        if not isinstance(value, list):
            return []
        return parse_networks(" ".join(str(v) for v in value))
    except Exception:
        return []


def set_server_reachable_networks(nets: Iterable[str], by_email: Optional[str] = None) -> List[str]:
    """Validate + persist. Returns the normalised list. Raises ValueError."""
    clean = parse_networks(" ".join(nets or []))
    from shared.logging import set_setting
    set_setting(SERVER_NETWORKS_KEY, json.dumps(clean), by_email=by_email)
    return clean


# ── Routing ──────────────────────────────────────────────────────────────

def _audit(action: str, capability: str, detail: str, status: str = "ok"):
    try:
        from shared.logging import audit
        audit("agents", action, target=capability, detail=detail, status=status)
    except Exception:  # noqa: BLE001 — routing works without an app context
        pass


def _summ(items: List[str], limit: int = 5) -> str:
    items = list(dict.fromkeys(items))
    head = ", ".join(items[:limit])
    extra = len(items) - limit
    return head + (f" +{extra} more" if extra > 0 else "")


def _capability_ids(presence: dict) -> set:
    out = set()
    for c in presence.get("capabilities") or []:
        cid = c if isinstance(c, str) else (c or {}).get("id")
        if cid:
            out.add(str(cid))
    return out


def _has_capability(presence: dict, capability: str) -> bool:
    """The kit agent advertises executors as `task:<type>`; callers ask for
    the bare type. Accept both spellings."""
    ids = _capability_ids(presence)
    return capability in ids or f"task:{capability}" in ids


def _domain_agents(domain):
    from webapp.models import RemoteAgent
    return RemoteAgent.query.filter_by(domain_id=domain.id).order_by(RemoteAgent.name).all()


def pick_executor(domain, targets, capability: str = "ping", *,
                  agents=None, pool=None, server_networks=None) -> RouteDecision:
    """Decide where a task touching `targets` (IP strings) runs.

    `agents`  — override: objects with `.name` + `.reachable_networks`
                (default: the Domain's RemoteAgent rows).
    `pool`    — override: anything with `list_agents()` returning kit-shaped
                rows (`name`, `revoked`, `presence{online,moved,queue,capabilities}`).
    `server_networks` — override for the platform setting.
    """
    slug = getattr(domain, "slug", None) or str(getattr(domain, "id", "?"))

    # 1. normalise targets
    norm = []
    for t in targets or ():
        try:
            norm.append(str(ipaddress.ip_address(str(t).strip())))
        except ValueError:
            reason = f"invalid target '{t}' — expected an IP address"
            _audit("route.refused", capability, reason, "error")
            return RouteDecision("refused", None, reason, norm, [str(t)])
    norm = list(dict.fromkeys(norm))
    if not norm:
        reason = "no targets given"
        _audit("route.refused", capability, reason, "error")
        return RouteDecision("refused", None, reason, [], [])

    # 2. agents of this Domain
    if agents is None:
        agents = _domain_agents(domain)
    if pool is None:
        from webapp.agents_manager import get_pool
        pool = get_pool()
    live = {row.get("name"): row for row in (pool.list_agents() or [])}

    eligible, covering_offline = [], []
    for a in agents:
        nets = list(getattr(a, "reachable_networks", None) or [])
        if not _covers_all(nets, norm):
            continue
        row = live.get(a.name) or {}
        p = row.get("presence") or {}
        if row.get("revoked"):
            continue
        if not p.get("online") or p.get("moved"):
            covering_offline.append(a.name)
            continue
        if capability and not _has_capability(p, capability):
            covering_offline.append(f"{a.name} (no '{capability}' capability)")
            continue
        eligible.append((int(p.get("queue") or 0), a.name))
    if eligible:
        eligible.sort()
        queue, name = eligible[0]
        reason = (f"routed to agent {name} (queue {queue}) — covers "
                  f"{_summ(norm)}")
        _audit("route.agent", capability, reason)
        return RouteDecision("agent", name, reason, norm, [])

    # 3. local execution
    if server_networks is None:
        server_networks = server_reachable_networks()
    if _covers_all(server_networks, norm):
        reason = f"server reaches all {len(norm)} target{'s' if len(norm) != 1 else ''}"
        _audit("route.local", capability, reason)
        return RouteDecision("local", None, reason, norm, [])

    # 4. refused
    union = list(server_networks or [])
    for a in agents:
        union.extend(getattr(a, "reachable_networks", None) or [])
    uncovered = [t for t in norm if not covers(union, t)] or list(norm)
    reason = (f"no online agent in Domain {slug} reaches {_summ(uncovered)} — "
              f"enroll one or declare the network reachable from the server")
    if covering_offline:
        reason += (f" (agent {_summ(covering_offline, 3)} covers them but is offline)"
                   if len(covering_offline) == 1 else
                   f" (agents {_summ(covering_offline, 3)} cover them but are offline)")
    _audit("route.refused", capability, reason, "error")
    return RouteDecision("refused", None, reason, norm, uncovered)
