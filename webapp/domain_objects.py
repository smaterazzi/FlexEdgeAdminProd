"""
FlexEdgeAdmin — Domain-scoped object accessors (Phase 0 of caching review).

Single read entry point for SMC objects, scoped by Domain. Every feature
that needs to know "what engines are in this domain", "what's this
cluster's interface tree", "what hosts/networks/services exist", "what
rules are in this policy" goes through THIS module — not directly into
the SMC client wrappers.

Why a single module:
- One cached entry per (domain, object_type) — every feature that asks
  for the same data gets the same cached result. Visiting
  ``/engines/clusters`` populates the cache; opening DHCP credentials
  or the TLS deploy form afterwards hits the cache instead of paying
  another SMC roundtrip.
- Storage shape: cache holds JSON-serialisable dicts (the SMC API
  response shape, with light extraction for fields that need a live SMC
  attribute lookup). Projection helpers turn those dicts into the
  typed dataclasses callers expect today. New SMC fields appear in the
  cached dict automatically — adding a projection helper exposes them
  to callers without invalidating the cache.
- Section names: short, object-type-keyed (``engines``, ``cluster``,
  ``policy_list``, ``policy``, ``element_list``, ``element``,
  ``dhcp_host``). Domain scoping rides on ``key_parts=(domain.id, ...)``
  so two domains pointing at the same SMC don't share entries.

Public accessors take the SMC config dict (built by the route from the
session) plus the active Domain row. They never touch ``g`` / session —
keeping them callable from background jobs and tests.

Refresh handling: routes pass ``refresh=request.args.get('refresh') == '1'``
to bypass the cache for one read. The freshness footer reads the
returned ``CachedValue`` metadata.
"""
from __future__ import annotations

import logging
from typing import Any

from shared.smc_cache import (
    cache_get_or_fetch, get_loose_ttl, get_quick_ttl,
)

# Re-export the dataclasses so callers can import them from this module
# instead of having to know they live in ``engine_inquiry``. Lets the
# accessor surface stay self-contained.
from webapp.engine_inquiry import (
    EngineSummary, ClusterDetail, NodeInfo, InterfaceInfo, InterfaceAddress,
)

log = logging.getLogger(__name__)


# ── Engines list ─────────────────────────────────────────────────────────

def _fetch_engines_dict(cfg: dict) -> list[dict]:
    """Hit SMC, return [{name, typeof, node_count, installed_policy, href}, ...].

    Single SMC session (smc_global_lock-aware); same enrichment
    ``engine_inquiry.list_clusters`` does today. Returns plain dicts so
    the cache layer can store JSON-serialisable values that survive a
    future Redis swap and SMC API field additions.
    """
    from webapp import engine_inquiry
    summaries = engine_inquiry.list_clusters(cfg)
    return [_engine_summary_to_dict(s) for s in summaries]


def _engine_summary_to_dict(s: EngineSummary) -> dict:
    return {
        "name": s.name,
        "typeof": s.typeof,
        "node_count": s.node_count,
        "installed_policy": s.installed_policy,
        "href": s.href,
    }


def _project_engine_summary(d: dict) -> EngineSummary:
    return EngineSummary(
        name=d.get("name", "") or "",
        typeof=d.get("typeof", "") or "",
        node_count=int(d.get("node_count", 0) or 0),
        installed_policy=d.get("installed_policy", "") or "",
        href=d.get("href", "") or "",
    )


def engines(domain, cfg: dict, *, refresh: bool = False):
    """List of all engines visible to ``domain``.

    Cache section ``engines``, key ``(domain.id,)``, **Loose TTL** (24h
    default) — engine inventory is read-only from FlexEdge's side.
    Returns a tuple ``(list[EngineSummary], CachedValue)`` so the route
    can render its freshness footer from the metadata.
    """
    if domain is None:
        # No active Domain — return empty + a minimal cache_meta stub so
        # templates can still render their freshness section. Falls
        # through to caller's "no profile selected" handling.
        return [], None

    cv = cache_get_or_fetch(
        section="engines",
        key_parts=(domain.id,),
        fetcher=lambda: _fetch_engines_dict(cfg),
        ttl=get_loose_ttl(),
        refresh=refresh,
    )
    raw = cv.data or []
    return [_project_engine_summary(d) for d in raw], cv


# ── Cluster detail (nodes + interfaces + routing + contact addresses) ──

def _fetch_cluster_dict(cfg: dict, engine_name: str) -> dict:
    """Hit SMC, return the cluster's full detail as a JSON-able dict.

    Mirrors ``engine_inquiry.cluster_detail`` but stores the result as
    a plain dict (with nested dicts for nodes / interfaces / routing /
    contact_addresses) so the cache value is serialisable.
    """
    from webapp import engine_inquiry
    detail = engine_inquiry.cluster_detail(cfg, engine_name)
    return _cluster_detail_to_dict(detail)


def _cluster_detail_to_dict(detail: ClusterDetail) -> dict:
    return {
        "name": detail.name,
        "typeof": detail.typeof,
        "href": detail.href,
        "installed_policy": detail.installed_policy,
        "contact_addresses": list(detail.contact_addresses or []),
        "routing": list(detail.routing or []),
        "interfaces": [_iface_to_dict(i) for i in (detail.interfaces or [])],
        "nodes": [_node_to_dict(n) for n in (detail.nodes or [])],
        "errors": list(detail.errors or []),
    }


def _iface_to_dict(i: InterfaceInfo) -> dict:
    return {
        "interface_id": i.interface_id,
        "vlan_id": i.vlan_id,
        "zone": i.zone,
        "addresses": [
            {"address": a.address,
             "network_value": a.network_value,
             "nodeid": a.nodeid}
            for a in (i.addresses or [])
        ],
    }


def _node_to_dict(n: NodeInfo) -> dict:
    return {
        "nodeid": n.nodeid,
        "name": n.name,
        "engine_version": n.engine_version,
        "status_state": n.status_state,
        "status_detail": n.status_detail,
        "interfaces": [_iface_to_dict(i) for i in (n.interfaces or [])],
    }


def _project_iface(d: dict) -> InterfaceInfo:
    return InterfaceInfo(
        interface_id=d.get("interface_id", "") or "",
        vlan_id=d.get("vlan_id", "") or "",
        zone=d.get("zone", "") or "",
        addresses=[
            InterfaceAddress(
                address=a.get("address", "") or "",
                network_value=a.get("network_value", "") or "",
                nodeid=a.get("nodeid"),
            ) for a in (d.get("addresses") or [])
        ],
    )


def _project_node(d: dict) -> NodeInfo:
    return NodeInfo(
        nodeid=int(d.get("nodeid", 0) or 0),
        name=d.get("name", "") or "",
        engine_version=d.get("engine_version", "") or "",
        status_state=d.get("status_state", "") or "",
        status_detail=d.get("status_detail", "") or "",
        interfaces=[_project_iface(i) for i in (d.get("interfaces") or [])],
    )


def _project_cluster_detail(d: dict) -> ClusterDetail:
    return ClusterDetail(
        name=d.get("name", "") or "",
        typeof=d.get("typeof", "") or "",
        href=d.get("href", "") or "",
        installed_policy=d.get("installed_policy", "") or "",
        contact_addresses=list(d.get("contact_addresses") or []),
        routing=list(d.get("routing") or []),
        interfaces=[_project_iface(i) for i in (d.get("interfaces") or [])],
        nodes=[_project_node(n) for n in (d.get("nodes") or [])],
        errors=list(d.get("errors") or []),
    )


def cluster(domain, cfg: dict, engine_name: str, *, refresh: bool = False):
    """Full detail for one engine (nodes + interfaces + routing + contacts).

    Cache section ``cluster``, key ``(domain.id, engine_name)``,
    **Loose TTL** (24h). Returns ``(ClusterDetail, CachedValue)``.
    """
    if domain is None:
        return None, None

    cv = cache_get_or_fetch(
        section="cluster",
        key_parts=(domain.id, engine_name),
        fetcher=lambda: _fetch_cluster_dict(cfg, engine_name),
        ttl=get_loose_ttl(),
        refresh=refresh,
    )
    return _project_cluster_detail(cv.data or {}), cv


# ── Policy list / single policy rules ─────────────────────────────────────

def _fetch_policies_dict(cfg: dict) -> list[dict]:
    from webapp import smc_client
    with smc_client.smc_session(cfg):
        return smc_client.list_policies()


def policies(domain, cfg: dict, *, refresh: bool = False):
    """All firewall policies in this Domain.

    Cache section ``policy_list``, key ``(domain.id,)``, **Loose TTL**
    (24h) — policy creation/deletion is rare and never done via FlexEdge.
    """
    if domain is None:
        return [], None

    cv = cache_get_or_fetch(
        section="policy_list",
        key_parts=(domain.id,),
        fetcher=lambda: _fetch_policies_dict(cfg),
        ttl=get_loose_ttl(),
        refresh=refresh,
    )
    return list(cv.data or []), cv


def _fetch_policy_rules_dict(cfg: dict, policy_name: str) -> list[dict]:
    from webapp import smc_client
    with smc_client.smc_session(cfg):
        return smc_client.get_policy_rules(policy_name)


def policy(domain, cfg: dict, policy_name: str, *, refresh: bool = False):
    """All rules + sections for one firewall policy.

    Cache section ``policy``, key ``(domain.id, policy_name)``,
    **Quick TTL** (1h) — rules ARE writeable through the queue, so the
    queue runner's auto-invalidation needs the shorter TTL as a backstop.
    """
    if domain is None:
        return [], None

    cv = cache_get_or_fetch(
        section="policy",
        key_parts=(domain.id, policy_name),
        fetcher=lambda: _fetch_policy_rules_dict(cfg, policy_name),
        ttl=get_quick_ttl(),
        refresh=refresh,
    )
    return list(cv.data or []), cv


# ── SMC explorer (host/network/service/group/fqdn/...) ────────────────────

def _fetch_elements_dict(cfg: dict, type_key: str,
                          filter_text: str, fgt_only: bool) -> list[dict]:
    from webapp import smc_client
    with smc_client.smc_session(cfg):
        return smc_client.list_elements(type_key, filter_text, fgt_only)


def elements(domain, cfg: dict, type_key: str,
             filter_text: str = "", fgt_only: bool = False,
             *, refresh: bool = False):
    """List of elements of one type (hosts, networks, services, groups, …).

    Cache section ``element_list.<type_key>``, key
    ``(domain.id, filter_text, fgt_only)``, **Quick TTL** (1h) —
    these are queue-mutable. Filtered views don't pollute unfiltered
    cache and vice versa.
    """
    if domain is None:
        return [], None

    cv = cache_get_or_fetch(
        section=f"element_list.{type_key}",
        key_parts=(domain.id, filter_text or "", "fgt" if fgt_only else ""),
        fetcher=lambda: _fetch_elements_dict(cfg, type_key, filter_text, fgt_only),
        ttl=get_quick_ttl(),
        refresh=refresh,
    )
    return list(cv.data or []), cv


def _fetch_element_dict(cfg: dict, type_key: str, element_name: str) -> dict:
    from webapp import smc_client
    with smc_client.smc_session(cfg):
        return smc_client.get_element_detail(type_key, element_name)


def element(domain, cfg: dict, type_key: str, element_name: str,
            *, refresh: bool = False):
    """Detail for a single SMC element by ``(type_key, name)``.

    Cache section ``element.<type_key>``, key ``(domain.id, element_name)``,
    **Quick TTL** (1h). Auto-invalidated by the queue runner after any
    create/update of the same element type.
    """
    if domain is None:
        return None, None

    cv = cache_get_or_fetch(
        section=f"element.{type_key}",
        key_parts=(domain.id, element_name),
        fetcher=lambda: _fetch_element_dict(cfg, type_key, element_name),
        ttl=get_quick_ttl(),
        refresh=refresh,
    )
    return cv.data, cv


# ── DHCP scope discovery ──────────────────────────────────────────────────

def _fetch_scopes_dict(cfg: dict, engine_name: str) -> list[dict]:
    """Hit SMC, return scope info as JSON-able dicts.

    Scope discovery walks the engine's interface tree pulling DHCP-
    specific fields that the generic ``cluster_detail`` projection
    doesn't preserve. Future optimisation: beef up ``cluster``'s raw
    dict to include the full SMC interface payload, then derive scopes
    locally with no second SMC roundtrip. For now, separate fetch.
    """
    from webapp import smc_client, smc_dhcp_client
    with smc_client.smc_session(cfg):
        scopes = smc_dhcp_client.list_scopes_for_engine(engine_name)
    out: list[dict] = []
    for s in scopes:
        # DhcpScopeInfo is a dataclass — convert to dict via __dict__
        # (no nested non-serialisable members in current shape).
        try:
            out.append(dict(s.__dict__))
        except Exception:
            # Fallback: best-effort attr copy.
            out.append({
                k: getattr(s, k) for k in
                ("engine_name", "interface_id", "subnet_cidr", "gateway",
                 "dhcp_pool_start", "dhcp_pool_end")
                if hasattr(s, k)
            })
    return out


def scopes(domain, cfg: dict, engine_name: str, *, refresh: bool = False):
    """DHCP-enabled scopes on one engine.

    Cache section ``scopes``, key ``(domain.id, engine_name)``,
    **Loose TTL** (24h) — scope shape is read-only from FlexEdge.
    Returns ``(list[dict], CachedValue)`` — caller projects to
    ``DhcpScopeInfo`` if needed (kept as dicts here so write-side code
    that only reads a few fields doesn't pay a projection cost).
    """
    if domain is None:
        return [], None

    cv = cache_get_or_fetch(
        section="scopes",
        key_parts=(domain.id, engine_name),
        fetcher=lambda: _fetch_scopes_dict(cfg, engine_name),
        ttl=get_loose_ttl(),
        refresh=refresh,
    )
    return list(cv.data or []), cv


# ── DHCP single-host (used by the reservation editor) ───────────────────

def _fetch_dhcp_host_dict(cfg: dict, host_name: str) -> dict | None:
    from webapp import smc_client, smc_dhcp_client
    with smc_client.smc_session(cfg):
        view = smc_dhcp_client.host_get(host_name)
    if view is None:
        return None
    try:
        return dict(view.__dict__)
    except Exception:
        return {k: getattr(view, k) for k in
                ("name", "href", "address", "comment", "mac_address",
                 "secondary_addresses")
                if hasattr(view, k)}


def _project_dhcp_host(d: dict | None):
    """Reconstruct a DhcpHostView from the cached dict, preserving the
    dataclass shape templates expect."""
    if d is None:
        return None
    from webapp.smc_dhcp_client import DhcpHostView
    fields = DhcpHostView.__dataclass_fields__
    return DhcpHostView(**{k: d[k] for k in d.keys() if k in fields})


def dhcp_host(domain, cfg: dict, host_name: str, *, refresh: bool = False):
    """Single SMC Host element used as a DHCP reservation.

    Cache section ``dhcp_host``, key ``(domain.id, host_name)``,
    **Quick TTL** (1h) — operators edit these directly through the queue.
    Returns ``(DhcpHostView_or_None, CachedValue)``.
    """
    if domain is None:
        return None, None

    cv = cache_get_or_fetch(
        section="dhcp_host",
        key_parts=(domain.id, host_name),
        fetcher=lambda: _fetch_dhcp_host_dict(cfg, host_name),
        ttl=get_quick_ttl(),
        refresh=refresh,
    )
    return _project_dhcp_host(cv.data), cv
