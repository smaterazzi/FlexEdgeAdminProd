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
    """Context manager that logs in to SMC and yields the session."""
    if cfg is None:
        cfg = load_config()

    login_kwargs = {
        "url": cfg["smc_url"],
        "api_key": cfg["api_key"],
        "verify": cfg.get("verify_ssl", False),
        "timeout": cfg.get("timeout", 120),
    }
    if cfg.get("api_version"):
        login_kwargs["api_version"] = cfg["api_version"]
    if cfg.get("domain"):
        login_kwargs["domain"] = cfg["domain"]
    if cfg.get("retry_on_busy", True):
        login_kwargs["retry_on_busy"] = True

    session.login(**login_kwargs)
    try:
        yield session
    finally:
        session.logout()


# ── Href Resolution Cache ────────────────────────────────────────────────

_href_cache = {}


def resolve_href(href):
    """
    Resolve an SMC href to an element name.
    Uses Element.from_href() which works across domain boundaries,
    resolving inherited objects from parent domains.
    Results are cached per session to avoid redundant API calls.
    """
    if not href:
        return None
    if href in _href_cache:
        return _href_cache[href]
    try:
        elem = Element.from_href(href)
        if elem:
            info = {"name": elem.name, "type": getattr(elem, "typeof", "")}
            _href_cache[href] = info
            return info
    except Exception as e:
        log.debug(f"Could not resolve href {href}: {e}")
    # Fallback: extract the numeric ID from the href
    fallback = {"name": href.split("/")[-1], "type": "unresolved"}
    _href_cache[href] = fallback
    return fallback


def clear_href_cache():
    """Clear the href resolution cache (call between sessions)."""
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
    "l3_firewalls":    {"cls": Layer3Firewall,  "label": "Layer-3 Firewall Engines"},
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

            # Resolve group members to names
            if type_key in ("groups", "service_groups"):
                row["members"] = _resolve_group_members(elem)

            row["comment"] = data.get("comment", "")
            results.append(row)
    except Exception as e:
        log.error(f"Error listing {type_key}: {e}")
        return [{"name": f"ERROR: {e}", "href": "", "type": type_key, "comment": ""}]

    results.sort(key=lambda r: r["name"].lower())
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
    """List all firewall policies."""
    results = []
    try:
        for p in FirewallPolicy.objects.all():
            results.append({"name": p.name, "href": getattr(p, "href", "")})
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
            # Detect rule sections
            rule_type = getattr(rule, "typeof", "")
            if "section" in rule_type.lower():
                rules.append({
                    "is_section": True,
                    "name": getattr(rule, "name", ""),
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
        session.logout()


# ── Sandbox / Dry-Run ────────────────────────────────────────────────────

def sandbox_rules_check(policy_name="Migration from Fortinet"):
    """
    Read the existing policy rules and return a validation report.
    Checks: rule count, disabled rules, unresolved references, section structure.
    """
    rules = get_policy_rules(policy_name)
    sections = [r for r in rules if r.get("is_section")]
    access_rules = [r for r in rules if not r.get("is_section")]
    disabled = [r for r in access_rules if r.get("is_disabled")]
    no_name = [r for r in access_rules if not r.get("name")]

    # Check for unresolved references (names that look like numeric IDs)
    unresolved = []
    for r in access_rules:
        for field in ("sources", "destinations", "services"):
            for name in r.get(field, []):
                if name not in ("any", "none") and name.isdigit():
                    unresolved.append({"rule": r["name"], "field": field, "value": name})

    return {
        "policy_name": policy_name,
        "total_rules": len(access_rules),
        "total_sections": len(sections),
        "sections": [s["name"] for s in sections],
        "disabled_rules": len(disabled),
        "disabled_list": [r["name"] for r in disabled],
        "unnamed_rules": len(no_name),
        "unresolved_refs": unresolved,
        "rules": access_rules,
    }
