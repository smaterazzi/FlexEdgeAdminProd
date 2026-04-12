"""
Rule Converter
===============
Converts FortiGate firewall policies to Forcepoint SMC rule format.

Key transformations:
  - srcaddr/dstaddr names -> dedup'd SMC names
  - service names -> dedup'd SMC service names
  - action: accept -> allow, deny -> discard
  - 'all' dstaddr -> 'any' in SMC
  - 'ALL' service -> 'any' in SMC
  - status=disable -> is_disabled=True
  - global-label -> section grouping
  - FortiGate policy ID embedded in comment
  - internet-service rules flagged for manual review
  - NAT policies -> separate NAT rules (SNAT/DNAT/both)
"""

import logging

log = logging.getLogger(__name__)

# FortiGate built-in address names that map to SMC "any"
ANY_ADDRESSES = {"all", "ALL"}

# FortiGate built-in service names that map to SMC "any"
ANY_SERVICES = {"ALL"}

# Action mapping: FortiGate -> Forcepoint SMC
ACTION_MAP = {
    "accept": "allow",
    "deny": "discard",
    "reject": "refuse",
}


def convert_policies(parsed_objects, dedup_results):
    """Convert FortiGate policies to Forcepoint SMC rule format.

    Args:
        parsed_objects: Output of fgt_parser (contains 'policies')
        dedup_results: Output of dedup_engine (address/service name mapping)

    Returns:
        {
            "sections": [
                {
                    "name": "Section Name",
                    "rules": [
                        {
                            "fgt_id": int,
                            "name": str,
                            "sources": [str],
                            "destinations": [str],
                            "services": [str],
                            "action": str,
                            "is_disabled": bool,
                            "comment": str,
                            "selected": bool,
                            "warnings": [str],
                        }
                    ]
                }
            ],
            "stats": { ... }
        }
    """
    policies = parsed_objects.get("policies", [])

    # Build name lookup from dedup results
    addr_map = _build_address_map(dedup_results.get("addresses", []))
    addr_grp_map = _build_name_map(dedup_results.get("address_groups", []))
    svc_map = _build_service_map(dedup_results.get("services", []))
    svc_grp_map = _build_name_map(dedup_results.get("service_groups", []))

    # Group policies by global_label into sections
    sections = _group_into_sections(policies)

    total_rules = 0
    total_warnings = 0
    total_disabled = 0
    total_internet_svc = 0

    for section in sections:
        converted_rules = []
        for policy in section["_policies"]:
            rule, warnings = _convert_single_policy(
                policy, addr_map, addr_grp_map, svc_map, svc_grp_map
            )
            total_rules += 1
            total_warnings += len(warnings)
            if rule["is_disabled"]:
                total_disabled += 1
            if policy.get("has_internet_service"):
                total_internet_svc += 1
            converted_rules.append(rule)
        section["rules"] = converted_rules
        del section["_policies"]

    # ── Convert NAT rules ──
    nat_rules = _convert_nat_policies(
        policies, parsed_objects, addr_map, addr_grp_map, svc_map, svc_grp_map
    )
    nat_stats = {
        "total_nat_rules": len(nat_rules),
        "snat_only": sum(1 for r in nat_rules if r["nat_type"] == "snat"),
        "dnat_only": sum(1 for r in nat_rules if r["nat_type"] == "dnat"),
        "snat_dnat": sum(1 for r in nat_rules if r["nat_type"] == "snat+dnat"),
    }

    return {
        "sections": sections,
        "nat_rules": nat_rules,
        "stats": {
            "total_rules": total_rules,
            "total_sections": len(sections),
            "total_warnings": total_warnings,
            "total_disabled": total_disabled,
            "total_internet_service": total_internet_svc,
            **nat_stats,
        },
    }


def _build_address_map(dedup_addresses):
    """Build FGT name -> SMC name map from dedup results."""
    mapping = {}
    for entry in dedup_addresses:
        parsed = entry["parsed_name"]
        if entry["action"] == "reuse":
            mapping[parsed] = entry["smc_name"]
        elif entry["action"] == "create":
            mapping[parsed] = entry["smc_name"]
        # 'skip' (builtin) entries remain unmapped
    return mapping


def _build_service_map(dedup_services):
    """Build FGT service name -> SMC name map from dedup results."""
    mapping = {}
    for entry in dedup_services:
        parsed = entry["parsed_name"]
        if entry["action"] == "reuse":
            mapping[parsed] = entry["smc_name"]
        elif entry["action"] == "create":
            mapping[parsed] = entry["smc_name"]
    return mapping


def _build_name_map(dedup_groups):
    """Build FGT group name -> SMC name map."""
    mapping = {}
    for entry in dedup_groups:
        parsed = entry["parsed_name"]
        if entry["action"] in ("reuse", "create"):
            mapping[parsed] = entry["smc_name"]
    return mapping


def _group_into_sections(policies):
    """Group policies into sections by global_label.

    FortiGate only sets global-label on the FIRST policy of each section.
    Subsequent policies have an empty label and inherit the current section.
    Only a non-empty label that differs from the current one starts a new section.
    """
    sections = []
    current_label = None
    current_policies = []

    for policy in policies:
        label = policy.get("global_label", "")
        # Only start a new section when a non-empty label appears
        # that is different from the current section label
        if label and label != current_label:
            if current_policies:
                section_name = current_label or "Ungrouped Rules"
                sections.append({
                    "name": section_name,
                    "_policies": current_policies,
                })
            current_label = label
            current_policies = [policy]
        else:
            current_policies.append(policy)

    # Final section
    if current_policies:
        section_name = current_label or "Ungrouped Rules"
        sections.append({
            "name": section_name,
            "_policies": current_policies,
        })

    return sections


def _map_address(fgt_name, addr_map, addr_grp_map):
    """Map a FortiGate address name to SMC name."""
    if fgt_name in ANY_ADDRESSES:
        return "any"
    if fgt_name in addr_map:
        return addr_map[fgt_name]
    if fgt_name in addr_grp_map:
        return addr_grp_map[fgt_name]
    return fgt_name  # unresolved, keep original


def _map_service(fgt_name, svc_map, svc_grp_map):
    """Map a FortiGate service name to SMC name."""
    if fgt_name in ANY_SERVICES:
        return "any"
    if fgt_name in svc_map:
        return svc_map[fgt_name]
    if fgt_name in svc_grp_map:
        return svc_grp_map[fgt_name]
    return fgt_name  # unresolved, keep original


def _convert_single_policy(policy, addr_map, addr_grp_map, svc_map, svc_grp_map):
    """Convert a single FortiGate policy to SMC rule format.

    Returns (rule_dict, warnings_list).
    """
    warnings = []
    fgt_id = policy.get("id", "?")

    # Map sources
    sources = []
    for s in policy.get("srcaddr", []):
        mapped = _map_address(s, addr_map, addr_grp_map)
        sources.append(mapped)

    # Map destinations
    destinations = []
    for d in policy.get("dstaddr", []):
        mapped = _map_address(d, addr_map, addr_grp_map)
        destinations.append(mapped)

    # Map services
    services = []
    if policy.get("has_internet_service"):
        warnings.append(
            f"Internet-service rule (uses ISDB, not regular services): "
            f"{', '.join(policy.get('internet_service_names', []))}"
        )
        services = ["any"]
    else:
        for s in policy.get("service", []):
            mapped = _map_service(s, svc_map, svc_grp_map)
            services.append(mapped)

    # Collapse "any" lists
    if not sources or sources == ["any"]:
        sources = ["any"]
    if not destinations or destinations == ["any"]:
        destinations = ["any"]
    if not services or services == ["any"]:
        services = ["any"]

    # Map action
    fgt_action = policy.get("action", "deny")
    action = ACTION_MAP.get(fgt_action, "discard")

    # Build comment with FGT policy ID
    orig_comment = policy.get("comment", "").strip()
    src_intf = ", ".join(policy.get("srcintf", []))
    dst_intf = ", ".join(policy.get("dstintf", []))
    comment_parts = [f"FGT ID:{fgt_id}"]
    if src_intf or dst_intf:
        comment_parts.append(f"[{src_intf} -> {dst_intf}]")
    if orig_comment:
        comment_parts.append(orig_comment)
    comment = " | ".join(comment_parts)

    # Rule name
    name = policy.get("name", "")
    if not name:
        name = f"FGT-Policy-{fgt_id}"
        warnings.append("Policy has no name — auto-generated")

    # Disabled flag
    is_disabled = not policy.get("enabled", True)

    # Determine default selection
    selected = not is_disabled and not policy.get("has_internet_service")

    # Additional warnings
    if policy.get("ippool"):
        warnings.append(f"Uses SNAT pool: {policy.get('poolname', '?')}")
    if policy.get("nat") and not policy.get("ippool"):
        warnings.append("NAT enabled (source NAT)")
    if policy.get("groups"):
        warnings.append(f"User/group restriction: {', '.join(policy['groups'])}")

    rule = {
        "fgt_id": fgt_id,
        "name": name,
        "sources": sources,
        "destinations": destinations,
        "services": services,
        "action": action,
        "is_disabled": is_disabled,
        "comment": comment,
        "selected": selected,
        "warnings": warnings,
        # Metadata for display
        "fgt_srcintf": policy.get("srcintf", []),
        "fgt_dstintf": policy.get("dstintf", []),
        "has_internet_service": policy.get("has_internet_service", False),
        "utm_status": policy.get("utm_status", False),
    }
    return rule, warnings


# ═══════════════════════════════════════════════════════════════════════════
#  NAT RULE CONVERSION
# ═══════════════════════════════════════════════════════════════════════════

def _convert_nat_policies(policies, parsed_objects, addr_map, addr_grp_map,
                          svc_map, svc_grp_map):
    """Convert FortiGate NAT policies to Forcepoint NAT rule format.

    Produces one NAT rule per policy that has SNAT (ippool) and/or DNAT (VIP dstaddr).

    Returns list of NAT rule dicts.
    """
    vip_by_name = {v["name"]: v for v in parsed_objects.get("vips", [])}
    pool_by_name = {p["name"]: p for p in parsed_objects.get("ip_pools", [])}

    nat_rules = []
    for policy in policies:
        has_snat = policy.get("has_snat", False)
        has_dnat = policy.get("has_dnat", False)

        # Also detect DNAT from VIP refs if parser didn't enrich
        if not has_dnat:
            for dname in policy.get("dstaddr", []):
                if dname in vip_by_name:
                    has_dnat = True
                    break

        if not has_snat and not has_dnat:
            continue

        fgt_id = policy.get("id", "?")
        warnings = []

        # ── Determine NAT type ──
        if has_snat and has_dnat:
            nat_type = "snat+dnat"
        elif has_dnat:
            nat_type = "dnat"
        else:
            nat_type = "snat"

        # ── Map sources ──
        sources = []
        for s in policy.get("srcaddr", []):
            mapped = _map_address(s, addr_map, addr_grp_map)
            sources.append(mapped)
        if not sources or sources == ["any"]:
            sources = ["any"]

        # ── Map services ──
        services = []
        if policy.get("has_internet_service"):
            services = ["any"]
            warnings.append("Internet-service rule — services set to any")
        else:
            for s in policy.get("service", []):
                mapped = _map_service(s, svc_map, svc_grp_map)
                services.append(mapped)
        if not services or services == ["any"]:
            services = ["any"]

        # ── DNAT: resolve VIP destinations ──
        destinations = []
        static_dst_nat = None
        static_dst_nat_ports = None
        if has_dnat:
            vip_refs = policy.get("vip_refs", [])
            if not vip_refs:
                vip_refs = [vip_by_name[d] for d in policy.get("dstaddr", [])
                            if d in vip_by_name]

            if vip_refs:
                # Use the VIP's extip as the destination (what traffic arrives at)
                for vip in vip_refs:
                    # Destination = extip (the address traffic is sent to)
                    destinations.append(vip["extip"])

                # Use the first VIP's mappedip as the translated destination
                first_vip = vip_refs[0]
                static_dst_nat = first_vip["mappedip"]

                if first_vip.get("portforward"):
                    static_dst_nat_ports = (
                        first_vip.get("extport", ""),
                        first_vip.get("mappedport", ""),
                    )

                if len(vip_refs) > 1:
                    warnings.append(
                        f"Multiple VIPs — only first DNAT mapped; "
                        f"others: {', '.join(v['name'] for v in vip_refs[1:])}"
                    )
        else:
            # No DNAT — map destinations normally
            for d in policy.get("dstaddr", []):
                mapped = _map_address(d, addr_map, addr_grp_map)
                destinations.append(mapped)
        if not destinations or destinations == ["any"]:
            destinations = ["any"]

        # ── SNAT: resolve pool ──
        dynamic_src_nat = None
        dynamic_src_nat_ip = None
        if has_snat:
            poolname = policy.get("poolname", "")
            if isinstance(poolname, list):
                poolname = poolname[0] if poolname else ""
            pool_def = policy.get("pool_def") or pool_by_name.get(poolname)
            if pool_def:
                dynamic_src_nat_ip = pool_def["startip"]
                dynamic_src_nat = pool_def["startip"]
                if pool_def["startip"] != pool_def["endip"]:
                    warnings.append(
                        f"Pool range {pool_def['startip']}-{pool_def['endip']}; "
                        f"using startip only"
                    )
            else:
                warnings.append(f"SNAT pool '{poolname}' not found in config")

        # ── Build comment ──
        orig_comment = policy.get("comment", "").strip()
        src_intf = ", ".join(policy.get("srcintf", []))
        dst_intf = ", ".join(policy.get("dstintf", []))
        comment_parts = [f"FGT ID:{fgt_id}", f"NAT:{nat_type}"]
        if src_intf or dst_intf:
            comment_parts.append(f"[{src_intf} -> {dst_intf}]")
        if orig_comment:
            comment_parts.append(orig_comment)
        comment = " | ".join(comment_parts)

        # ── Rule name ──
        name = policy.get("name", "")
        if not name:
            name = f"FGT-NAT-Policy-{fgt_id}"
        else:
            name = f"NAT-{name}"

        is_disabled = not policy.get("enabled", True)
        selected = not is_disabled and len(warnings) == 0

        nat_rule = {
            "fgt_id": fgt_id,
            "name": name,
            "nat_type": nat_type,
            "sources": sources,
            "destinations": destinations,
            "services": services,
            "is_disabled": is_disabled,
            "comment": comment,
            "selected": selected,
            "warnings": warnings,
            # SNAT fields
            "dynamic_src_nat": dynamic_src_nat,
            "dynamic_src_nat_ip": dynamic_src_nat_ip,
            # DNAT fields
            "static_dst_nat": static_dst_nat,
            "static_dst_nat_ports": static_dst_nat_ports,
            # Metadata
            "fgt_srcintf": policy.get("srcintf", []),
            "fgt_dstintf": policy.get("dstintf", []),
            "poolname": policy.get("poolname", ""),
            "vip_names": [v["name"] for v in policy.get("vip_refs", [])],
        }
        nat_rules.append(nat_rule)

    return nat_rules


# ═══════════════════════════════════════════════════════════════════════════
#  VPN TOPOLOGY CONVERSION
# ═══════════════════════════════════════════════════════════════════════════

def convert_vpn_tunnels(parsed_objects, dedup_results):
    """Convert FortiGate VPN tunnels to Forcepoint SMC VPN topology.

    For each FortiGate Phase 1 tunnel, produces:
      - An ExternalGateway definition (name, endpoint IP)
      - VPN Sites (local + remote subnets)
      - VPN Profile reference (from dedup matching)
      - PolicyVPN topology definition

    Args:
        parsed_objects: Output of fgt_parser (contains 'vpn_tunnels')
        dedup_results: Output of dedup_engine (contains 'vpn_profiles')

    Returns:
        {
            "vpn_configs": [
                {
                    "name": str,
                    "gateway_name": str,
                    "endpoint_ip": str,
                    "vpn_profile": str,
                    "profile_action": "reuse" | "create",
                    "local_subnets": [str],
                    "remote_subnets": [str],
                    "p1_keylife": int,
                    "p2_keylife": int,
                    "psk_auth": bool,
                    "selected": bool,
                    "warnings": [str],
                    "comment": str,
                }
            ],
            "stats": { ... }
        }
    """
    vpn_tunnels = parsed_objects.get("vpn_tunnels", [])
    vpn_profiles = dedup_results.get("vpn_profiles", [])

    # Build profile lookup by tunnel name
    profile_by_tunnel = {p["tunnel_name"]: p for p in vpn_profiles}

    vpn_configs = []
    for tunnel in vpn_tunnels:
        profile_info = profile_by_tunnel.get(tunnel["name"], {})
        warnings = list(profile_info.get("warnings", []))

        # Warn about PTP subnets that should be removed
        ptp_subnets = [s for s in tunnel["local_subnets"] if s.startswith("10.255.255.")]
        if ptp_subnets:
            warnings.append(
                f"PTP subnet(s) {', '.join(ptp_subnets)} should be removed after consolidation"
            )

        # Warn if no Phase 2 entries
        if tunnel["phase2_count"] == 0:
            warnings.append("No Phase 2 entries — tunnel has no traffic selectors")

        config = {
            "name": tunnel["name"],
            "gateway_name": f"FGT-GW-{tunnel['name']}",
            "endpoint_ip": tunnel["remote_gw"],
            "local_gw": tunnel["local_gw"],
            "vpn_profile": profile_info.get("smc_name", f"FGT-VPN-{tunnel['p1_proposal']}-DH{tunnel['p1_dhgrp']}"),
            "profile_action": profile_info.get("action", "create"),
            "profile_capabilities": profile_info.get("required_capabilities", {}),
            # Crypto parameters
            "p1_proposal": tunnel["p1_proposal"],
            "p1_dhgrp": tunnel["p1_dhgrp"],
            "p1_keylife": tunnel["p1_keylife"],
            "p2_proposal": tunnel["p2_proposal"],
            "p2_pfs": tunnel["p2_pfs"],
            "p2_dhgrp": tunnel.get("p2_dhgrp") or tunnel["p1_dhgrp"],
            "p2_keylife": tunnel["p2_keylife"],
            "ike_version": tunnel.get("ike_version", "1"),
            # Subnets
            "local_subnets": tunnel["local_subnets"],
            "remote_subnets": tunnel["remote_subnets"],
            "phase2_count": tunnel["phase2_count"],
            "phase2_entries": tunnel.get("phase2_entries", []),
            # Auth
            "psk_auth": tunnel.get("psk_auth", True),
            "dpd": tunnel.get("dpd", "on-idle"),
            "nattraversal": tunnel.get("nattraversal", "enable"),
            # Selection
            "selected": len(warnings) == 0 or all("weak" in w or "deprecated" in w for w in warnings),
            "warnings": warnings,
            "comment": tunnel.get("comment", ""),
        }
        vpn_configs.append(config)

    return {
        "vpn_configs": vpn_configs,
        "stats": {
            "total_tunnels": len(vpn_configs),
            "total_phase2": sum(c["phase2_count"] for c in vpn_configs),
            "profiles_reuse": sum(1 for c in vpn_configs if c["profile_action"] == "reuse"),
            "profiles_create": sum(1 for c in vpn_configs if c["profile_action"] == "create"),
            "warnings": sum(len(c["warnings"]) for c in vpn_configs),
        },
    }
