"""
SMC Client — Read-only interface to Forcepoint SMC.

Provides context-managed sessions and exposes typed listing methods
for every SMC element category.

All element references (sources, destinations, services) in rules are
resolved to human-readable names via Element.from_href(), which handles
inherited objects from parent domains transparently.
"""

import os
import logging
import threading
from pathlib import Path
from contextlib import contextmanager

import yaml
from smc import session
from smc.base.model import Element
from smc.elements.network import Host, Network, AddressRange, DomainName, Zone
from smc.elements.group import Group, ServiceGroup
from smc.elements.service import TCPService, UDPService, IPService, ICMPService
from smc.policy.layer3 import FirewallPolicy
from smc.core.engines import Layer3Firewall

log = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────

CONFIG_FILE = os.environ.get(
    "SMC_CONFIG",
    str(Path(__file__).resolve().parent.parent / "smc_config.yml"),
)


def load_config(path=None):
    """Load and return the SMC configuration dictionary."""
    cfg_path = path or CONFIG_FILE
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── Session Management ───────────────────────────────────────────────────

@contextmanager
def smc_session(cfg=None):
    """Context manager that logs in to SMC and yields the session.

    Serialised by the process-wide SMC lock — the smc-python SDK keeps
    session state in a module-level singleton, so concurrent login/logout
    from threaded gunicorn workers would corrupt each other. See
    ``shared/smc_lock.py`` for the gory details.
    """
    from shared.smc_lock import smc_global_lock

    if cfg is None:
        cfg = load_config()

    # Accept both dict and dataclass (SMCConfig) callers.
    _g = (lambda k, d=None: cfg.get(k, d)) if isinstance(cfg, dict) else (lambda k, d=None: getattr(cfg, k, d))

    login_kwargs = {
        "url": _g("smc_url") or _g("url"),
        "api_key": _g("api_key"),
        "verify": _g("verify_ssl", False),
        "timeout": _g("timeout", 120),
    }
    if _g("api_version"):
        login_kwargs["api_version"] = _g("api_version")
    if _g("domain"):
        login_kwargs["domain"] = _g("domain")
    if _g("retry_on_busy", True):
        login_kwargs["retry_on_busy"] = True

    with smc_global_lock():
        session.login(**login_kwargs)
        try:
            yield session
        finally:
            try:
                session.logout()
            except Exception as exc:
                log.warning("smc_session: logout failed (ignored): %s", exc)


# ── Href Resolution Cache ────────────────────────────────────────────────

# Audit L5 (2026-06-11): guarded by a lock — under threaded gunicorn a
# clear_href_cache() racing a resolve_href() iteration raised
# RuntimeError("dictionary changed size during iteration").
_href_cache = {}
_href_cache_lock = threading.Lock()


def resolve_href(href):
    """
    Resolve an SMC href to an element name.
    Uses Element.from_href() which works across domain boundaries,
    resolving inherited objects from parent domains.
    Results are cached per session to avoid redundant API calls.
    """
    if not href:
        return None
    with _href_cache_lock:
        cached = _href_cache.get(href)
    if cached is not None:
        return cached
    try:
        elem = Element.from_href(href)
        if elem:
            info = {"name": elem.name, "type": getattr(elem, "typeof", "")}
            with _href_cache_lock:
                _href_cache[href] = info
            return info
    except Exception as e:
        log.debug(f"Could not resolve href {href}: {e}")
    # Fallback: extract the numeric ID from the href
    fallback = {"name": href.split("/")[-1], "type": "unresolved"}
    with _href_cache_lock:
        _href_cache[href] = fallback
    return fallback


def clear_href_cache():
    """Clear the href resolution cache (call between sessions)."""
    with _href_cache_lock:
        _href_cache.clear()


# ── Element Listing (read-only) ──────────────────────────────────────────

# Registry of browsable element types
ELEMENT_TYPES = {
    "zones":           {"cls": Zone,            "label": "Security Zones"},
    "hosts":           {"cls": Host,            "label": "Hosts"},
    "networks":        {"cls": Network,         "label": "Networks"},
    "address_ranges":  {"cls": AddressRange,    "label": "Address Ranges"},
    "domain_names":    {"cls": DomainName,      "label": "Domain Names (FQDN)"},
    "groups":          {"cls": Group,           "label": "Network Groups"},
    "tcp_services":    {"cls": TCPService,      "label": "TCP Services"},
    "udp_services":    {"cls": UDPService,      "label": "UDP Services"},
    "ip_services":     {"cls": IPService,       "label": "IP Services"},
    "icmp_services":   {"cls": ICMPService,     "label": "ICMP Services"},
    "service_groups":  {"cls": ServiceGroup,    "label": "Service Groups"},
    "fw_policies":     {"cls": FirewallPolicy,  "label": "Firewall Policies"},
    # Legacy entry — kept so the dashboard tile + sidebar item still
    # render. The /browse/l3_firewalls route hard-redirects to
    # /engines/clusters because that page covers every engine type
    # (clusters, virtual engines, IPS, masters), not just the
    # Layer3Firewall subclass we'd see here.
    "l3_firewalls":    {"cls": Layer3Firewall,  "label": "Engines"},
}


def list_elements(type_key, filter_text=None, fgt_only=False):
    """
    List all elements of the given type.

    Returns a list of dicts with at minimum {name, href, type}.
    Extra fields depend on the element type.
    """
    entry = ELEMENT_TYPES.get(type_key)
    if not entry:
        return []

    results = []
    try:
        for elem in entry["cls"].objects.all():
            name = elem.name
            if fgt_only and not name.startswith("FGT-"):
                continue
            if filter_text and filter_text.lower() not in name.lower():
                continue

            row = {
                "name": name,
                "href": getattr(elem, "href", ""),
                "type": type_key,
            }

            # Extract extra detail where available
            try:
                data = elem.data.data if hasattr(elem.data, "data") else {}
            except Exception:
                data = {}

            if type_key == "hosts":
                row["address"] = data.get("address", "")
            elif type_key == "networks":
                row["ipv4_network"] = data.get("ipv4_network", "")
            elif type_key == "address_ranges":
                row["ip_range"] = data.get("ip_range", "")
            elif type_key in ("tcp_services", "udp_services"):
                row["min_dst_port"] = data.get("min_dst_port", "")
                row["max_dst_port"] = data.get("max_dst_port", "")
            elif type_key == "domain_names":
                row["value"] = data.get("value", name)
            elif type_key == "fw_policies":
                # Roadmap item 3 (Batch J, 2026-05-11): surface FW + NAT
                # rule counts so the listing answers "does this policy
                # have NAT rules?" at a glance. Forcepoint SMC has no
                # standalone NATPolicy element; NAT rules live inside
                # each FirewallPolicy. Counting iterates the rule
                # collections — expensive on cold cache but the result
                # is cached at section `element_list.fw_policies`
                # (Quick TTL 1h) so subsequent renders are free.
                row["fw_rule_count"] = None
                row["nat_rule_count"] = None
                try:
                    row["fw_rule_count"] = sum(
                        1 for _ in elem.fw_ipv4_access_rules.all()
                    )
                except Exception as e:
                    log.debug(f"fw rule count for {name} failed: {e}")
                try:
                    row["nat_rule_count"] = sum(
                        1 for _ in elem.fw_ipv4_nat_rules.all()
                    )
                except Exception as e:
                    log.debug(f"nat rule count for {name} failed: {e}")

            # Resolve group members to names
            if type_key in ("groups", "service_groups"):
                row["members"] = _resolve_group_members(elem)

            row["comment"] = data.get("comment", "")
            results.append(row)
    except Exception as e:
        log.error(f"Error listing {type_key}: {e}")
        return [{"name": f"ERROR: {e}", "href": "", "type": type_key, "comment": ""}]

    results.sort(key=lambda r: r["name"].lower())

    # Q21 lazy registry — register every element seen. Best-effort.
    # Uses the explorer's `type_key` (singular form) as smc_type so the
    # registry can group rows by what the operator actually browsed.
    try:
        from shared.smc_registry import register_many
        # Map plural explorer keys to a singular smc_type label.
        type_label = {
            "hosts": "host", "networks": "network",
            "address_ranges": "address_range", "fqdns": "fqdn",
            "domain_names": "domain_name", "zones": "zone",
            "groups": "group",
            "tcp_services": "tcp_service", "udp_services": "udp_service",
            "ip_services": "ip_service", "icmp_services": "icmp_service",
            "service_groups": "service_group",
        }.get(type_key, type_key)
        register_many(None, [
            {"smc_type": type_label,
             "smc_href": r.get("href", ""), "smc_name": r.get("name", "")}
            for r in results if r.get("href")
        ])
    except Exception:
        pass

    return results


def _resolve_group_members(group_elem):
    """Resolve group member hrefs to a list of names."""
    members = []
    try:
        data = group_elem.data.data if hasattr(group_elem.data, "data") else {}
        member_hrefs = data.get("element", [])
        for href in member_hrefs:
            info = resolve_href(href)
            if info:
                members.append(info["name"])
            else:
                members.append(href.split("/")[-1])
    except Exception as e:
        log.debug(f"Could not resolve group members: {e}")
    return members


def get_element_detail(type_key, element_name):
    """
    Return the full data dict for a single element,
    with all href references resolved to human-readable names.
    """
    entry = ELEMENT_TYPES.get(type_key)
    if not entry:
        return None
    try:
        elem = entry["cls"](element_name)
        raw_data = elem.data.data if hasattr(elem.data, "data") else {}
        # Deep-resolve hrefs in the data
        resolved = _resolve_data_hrefs(raw_data)
        return {
            "name": element_name,
            "href": getattr(elem, "href", ""),
            "data": resolved,
        }
    except Exception as e:
        return {"name": element_name, "error": str(e)}


def _resolve_data_hrefs(data):
    """
    Walk a data dict and resolve any href strings to readable names.
    Href strings look like 'http://host:port/version/elements/type/id'.
    """
    if isinstance(data, dict):
        resolved = {}
        for k, v in data.items():
            resolved[k] = _resolve_data_hrefs(v)
        return resolved
    elif isinstance(data, list):
        return [_resolve_data_hrefs(item) for item in data]
    elif isinstance(data, str) and "/elements/" in data:
        # This looks like an SMC href — resolve it
        info = resolve_href(data)
        if info and info["type"] != "unresolved":
            return f"{info['name']}  [{data.split('/')[-2]}]"
        return data
    return data


# ── Policy Rules (read-only) ─────────────────────────────────────────────

def list_policies():
    """List all firewall policies with FW + NAT rule counts.

    Roadmap item 3 (Batch J, 2026-05-11): each result row carries
    `fw_rule_count` and `nat_rule_count` so the canonical listing at
    `/browse/fw_policies` can surface "policies with NAT" without
    forcing the operator to click into each policy.

    Forcepoint SMC has no standalone NATPolicy element — NAT rules live
    inside each FirewallPolicy via `fw_ipv4_nat_rules`. The operator's
    "add NAT policies to the list" request maps to "show how many NAT
    rules each policy contains" alongside the access-rule count.

    Rule counts iterate the rule collections lazily; on the cold-cache
    path that's the cost of `len(list(...))`. The result is cached at
    the `policy_list` section (Loose 24h) so subsequent renders are
    free. Errors counting one policy's rules don't abort the listing —
    that policy just gets `fw_rule_count=None` / `nat_rule_count=None`
    and the template renders a `?` badge.
    """
    results = []
    try:
        for p in FirewallPolicy.objects.all():
            row = {
                "name": p.name,
                "href": getattr(p, "href", ""),
                "fw_rule_count": None,
                "nat_rule_count": None,
            }
            try:
                row["fw_rule_count"] = sum(
                    1 for _ in p.fw_ipv4_access_rules.all()
                )
            except Exception as e:
                log.debug(f"fw rule count for {p.name} failed: {e}")
            try:
                row["nat_rule_count"] = sum(
                    1 for _ in p.fw_ipv4_nat_rules.all()
                )
            except Exception as e:
                log.debug(f"nat rule count for {p.name} failed: {e}")
            results.append(row)
    except Exception as e:
        log.error(f"Error listing policies: {e}")
    return sorted(results, key=lambda r: r["name"].lower())


def _resolve_rule_field(rule_property):
    """
    Resolve a rule's sources/destinations/services property
    to a list of human-readable name strings.

    Uses the library's built-in .all() method which calls
    Element.from_href() internally, correctly resolving
    inherited objects from parent domains.
    """
    try:
        if rule_property.is_any:
            return ["any"]
        if rule_property.is_none:
            return ["none"]
    except AttributeError:
        pass

    names = []
    try:
        for elem in rule_property.all():
            names.append(elem.name)
    except Exception as e:
        log.debug(f"Fallback to href parsing: {e}")
        # Fallback: parse hrefs from raw data
        try:
            raw = rule_property.data if hasattr(rule_property, "data") else {}
            for key in ("src", "dst", "service"):
                for href in raw.get(key, []):
                    info = resolve_href(href)
                    names.append(info["name"] if info else href.split("/")[-1])
        except Exception:
            names.append("(unresolved)")

    return names if names else ["any"]


def _extract_action(rule):
    """Extract the action string from a rule."""
    try:
        action = rule.action
        if hasattr(action, "action"):
            act_val = action.action
            if isinstance(act_val, list):
                return act_val[0] if act_val else ""
            return str(act_val)
        return str(action)
    except Exception:
        pass
    # Fallback to raw data
    try:
        rdata = rule.data.data if hasattr(rule.data, "data") else {}
        act = rdata.get("action", {})
        if isinstance(act, dict):
            act_list = act.get("action", "")
            if isinstance(act_list, list):
                return act_list[0] if act_list else ""
            return str(act_list)
        return str(act)
    except Exception:
        return ""


def _is_rule_section(rule) -> bool:
    """Detect whether a Rule SDK object is actually a section header.

    Sections share the same `typeof` (`fw_ipv4_access_rule`) as regular
    rules — SMC stores them as rule entries that lack the source /
    destination / service fields. The SDK exposes this via the
    `is_rule_section` property; we fall back to a manual data-dict
    check when the property is missing on older SDK builds.
    """
    flag = getattr(rule, "is_rule_section", None)
    if isinstance(flag, bool):
        return flag
    try:
        data = getattr(rule, "data", {}) or {}
        return not any(field in data
                       for field in ("sources", "destinations"))
    except Exception:
        return False


def _section_label(rule) -> str:
    """Best-effort display label for a section header.

    `create_rule_section(name=...)` stores the section name in the
    rule's `comment` field, so that's the primary label. Falls back to
    the SMC-side `name` if no comment was set.
    """
    label = (getattr(rule, "comment", "") or "").strip()
    if label:
        return label
    return getattr(rule, "name", "") or ""


def get_policy_rules(policy_name):
    """
    Return all IPv4 access rules for the given policy.

    All element references (sources, destinations, services) are
    resolved to human-readable names via the SMC library's built-in
    resolution, which works across domain boundaries for inherited objects.
    """
    clear_href_cache()
    rules = []
    try:
        policy = FirewallPolicy(policy_name)
        for rule in policy.fw_ipv4_access_rules.all():
            if _is_rule_section(rule):
                rules.append({
                    "is_section": True,
                    "name": _section_label(rule),
                    "tag": getattr(rule, "tag", ""),
                })
                continue

            # Access rule — resolve all references to names
            rules.append({
                "is_section": False,
                "name": getattr(rule, "name", ""),
                "sources": _resolve_rule_field(rule.sources),
                "destinations": _resolve_rule_field(rule.destinations),
                "services": _resolve_rule_field(rule.services),
                "action": _extract_action(rule),
                "is_disabled": getattr(rule, "is_disabled", False),
                "comment": getattr(rule, "comment", ""),
                "tag": getattr(rule, "tag", ""),
            })
    except Exception as e:
        log.error(f"Error reading policy rules: {e}")
        rules.append({
            "is_section": False,
            "name": f"ERROR: {e}",
            "sources": [], "destinations": [], "services": [],
            "action": "", "is_disabled": False, "comment": "",
        })
    return rules


# ── NAT Rules ────────────────────────────────────────────────────────────

def _nat_target_name(nat_value):
    """Best-effort human name for a NAT translated value."""
    if nat_value is None:
        return ""
    try:
        elem = nat_value.as_element
        if elem is not None:
            return getattr(elem, "name", "")
    except Exception:
        pass
    try:
        return nat_value.ip_descriptor or ""
    except Exception:
        return ""


def _nat_translation_summary(rule):
    """
    Build a deterministic, human-readable string describing the NAT
    translation on this rule. Used as the rule's "action" field for the
    purpose of duplicate detection.

    Examples:
        static_src→Public_NAT_Host
        dynamic_src→1.2.3.4[1024-65535]
        static_dst→10.0.0.5:443
        no_nat
        static_src→A;static_dst→B   (multiple translations)
    """
    parts = []
    try:
        src_static = rule.static_src_nat
        if src_static.has_nat:
            parts.append(f"static_src->{_nat_target_name(src_static.translated_value)}")
    except Exception:
        pass
    try:
        src_dynamic = rule.dynamic_src_nat
        if src_dynamic.has_nat:
            tv = src_dynamic.translated_value
            tgt = _nat_target_name(tv)
            ports = ""
            try:
                if tv and (tv.min_port or tv.max_port):
                    ports = f"[{tv.min_port}-{tv.max_port}]"
            except Exception:
                pass
            parts.append(f"dynamic_src->{tgt}{ports}")
    except Exception:
        pass
    try:
        dst_static = rule.static_dst_nat
        if dst_static.has_nat:
            tv = dst_static.translated_value
            tgt = _nat_target_name(tv)
            port = ""
            try:
                if tv and tv.min_port:
                    port = f":{tv.min_port}"
                    if tv.max_port and tv.max_port != tv.min_port:
                        port = f":{tv.min_port}-{tv.max_port}"
            except Exception:
                pass
            parts.append(f"static_dst->{tgt}{port}")
    except Exception:
        pass

    return ";".join(parts) if parts else "no_nat"


def get_policy_nat_rules(policy_name):
    """
    Return all IPv4 NAT rules for the given policy, with the same shape
    as ``get_policy_rules`` so the optimizer can reuse the same logic.

    The ``action`` field carries the translation summary string (so
    rules with identical match criteria but different translations
    do NOT collapse as duplicates).
    """
    clear_href_cache()
    rules = []
    try:
        policy = FirewallPolicy(policy_name)
        for rule in policy.fw_ipv4_nat_rules.all():
            if _is_rule_section(rule):
                rules.append({
                    "is_section": True,
                    "name": _section_label(rule),
                    "tag": getattr(rule, "tag", ""),
                })
                continue

            rules.append({
                "is_section": False,
                "name": getattr(rule, "name", ""),
                "sources": _resolve_rule_field(rule.sources),
                "destinations": _resolve_rule_field(rule.destinations),
                "services": _resolve_rule_field(rule.services),
                "action": _nat_translation_summary(rule),
                "is_disabled": getattr(rule, "is_disabled", False),
                "comment": getattr(rule, "comment", ""),
                "tag": getattr(rule, "tag", ""),
            })
    except Exception as e:
        log.error(f"Error reading policy NAT rules: {e}")
        rules.append({
            "is_section": False,
            "name": f"ERROR: {e}",
            "sources": [], "destinations": [], "services": [],
            "action": "", "is_disabled": False, "comment": "",
        })
    return rules


# ── Admin Domain Listing ─────────────────────────────────────────────────

def list_domains(cfg):
    """
    Return all SMC admin domains visible with the given API credentials.

    Connects to the SMC root (no domain parameter) so that all domains
    the API key has access to are returned.  The caller's own domain
    filter (if any) is ignored here — this is used to populate the
    domain-selection UI.

    Returns a sorted list of {name, href} dicts.
    On failure returns [{name: 'Shared Domain', href: ''}] as a safe fallback.
    """
    from shared.smc_lock import smc_global_lock

    login_kwargs = {
        "url": cfg["smc_url"],
        "api_key": cfg["api_key"],
        "verify": cfg.get("verify_ssl", False),
        "timeout": cfg.get("timeout", 60),
    }
    if cfg.get("api_version"):
        login_kwargs["api_version"] = cfg["api_version"]
    if cfg.get("retry_on_busy", True):
        login_kwargs["retry_on_busy"] = True
    # Deliberately omit 'domain' so we land on the root / Shared Domain
    # and can enumerate all admin domains.

    with smc_global_lock():
        session.login(**login_kwargs)
        try:
            try:
                from smc.administration.access_rights import AdminDomain
            except ImportError:
                # Older library versions may use a different path
                from smc.core.engine import AdminDomain  # type: ignore

            domains = [
                {"name": d.name, "href": getattr(d, "href", "")}
                for d in AdminDomain.objects.all()
            ]
            # Always include Shared Domain so users without named domains can proceed
            names = {d["name"] for d in domains}
            if "Shared Domain" not in names:
                domains.insert(0, {"name": "Shared Domain", "href": ""})
            return sorted(domains, key=lambda d: d["name"].lower())
        except Exception as exc:
            log.error("Error listing admin domains: %s", exc)
            return [{"name": "Shared Domain", "href": ""}]
        finally:
            try:
                session.logout()
            except Exception:
                pass


# Sandbox / Dry-Run feature removed 2026-04-30 — superseded by the
# Optimizer (live findings on the policy) and the Migration Manager
# (validates rules during the FortiGate import flow). The Sandbox
# only counted disabled / unresolved / sectioned rules — both of the
# replacements do strictly more.
