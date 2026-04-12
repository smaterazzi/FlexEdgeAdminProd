"""
SMC Writer
===========
Creates objects and firewall rules in Forcepoint SMC.
Extends the read-only smc_client.py with write operations.

Follows the same patterns as 01_create_objects.py and 02_create_rules.py
(safe_create, lazy proxy validation, service mapping).
"""

import logging
from datetime import datetime, timezone

import smc_client

log = logging.getLogger(__name__)


def _safe_create(func, category, log_entries, **kwargs):
    """Attempt to create an SMC element, handling duplicates gracefully.

    Returns: 'created' | 'skipped' | 'error'
    """
    name = kwargs.get("name", "unknown")
    try:
        func(**kwargs)
        log_entries.append({"level": "info", "msg": f"Created {category}: {name}"})
        return "created"
    except Exception as e:
        err_str = str(e).lower()
        if "already exists" in err_str or "duplicate" in err_str or "must be unique" in err_str:
            log_entries.append({"level": "info", "msg": f"Skipped (exists): {name}"})
            return "skipped"
        else:
            log_entries.append({"level": "error", "msg": f"FAILED {category} '{name}': {e}"})
            return "error"


def create_objects(parsed_objects, dedup_results, cfg):
    """Create all objects marked as action='create' in dedup_results.

    Args:
        parsed_objects: Parsed FortiGate objects
        dedup_results: Deduplication results with action per object
        cfg: SMC config dict

    Returns:
        Import log dict with counts and entries
    """
    from smc.elements.network import Host, Network, AddressRange, DomainName
    from smc.elements.group import Group, ServiceGroup
    from smc.elements.service import TCPService, UDPService

    log_entries = []
    counts = {"created": 0, "skipped": 0, "errors": 0}

    # Build lookup for parsed objects by name
    addr_by_name = {a["name"]: a for a in parsed_objects.get("addresses", [])}
    svc_by_name = {s["name"]: s for s in parsed_objects.get("services", [])}

    with smc_client.smc_session(cfg):
        log_entries.append({"level": "info", "msg": "SMC session established"})

        # ── Create Addresses ──
        log_entries.append({"level": "info", "msg": "--- Creating addresses ---"})
        for entry in dedup_results.get("addresses", []):
            if entry["action"] != "create":
                continue
            parsed = addr_by_name.get(entry["parsed_name"])
            if not parsed:
                continue
            smc_name = entry["smc_name"]
            addr_type = parsed["type"]

            if addr_type == "host":
                result = _safe_create(
                    Host.create, "host", log_entries,
                    name=smc_name, address=parsed.get("ip", ""),
                    comment=parsed.get("comment", ""),
                )
            elif addr_type == "subnet":
                cidr = parsed.get("cidr", 24)
                result = _safe_create(
                    Network.create, "network", log_entries,
                    name=smc_name,
                    ipv4_network=f"{parsed.get('subnet', '')}/{cidr}",
                    comment=parsed.get("comment", ""),
                )
            elif addr_type == "iprange":
                result = _safe_create(
                    AddressRange.create, "address_range", log_entries,
                    name=smc_name,
                    ip_range=f"{parsed.get('start_ip', '')}-{parsed.get('end_ip', '')}",
                    comment=parsed.get("comment", ""),
                )
            elif addr_type == "fqdn":
                result = _safe_create(
                    DomainName.create, "fqdn", log_entries,
                    name=smc_name, value=parsed.get("fqdn", ""),
                    comment=parsed.get("comment", ""),
                )
            else:
                log_entries.append({
                    "level": "warning",
                    "msg": f"Unsupported address type '{addr_type}': {smc_name}"
                })
                continue

            if result == "created":
                counts["created"] += 1
            elif result == "skipped":
                counts["skipped"] += 1
            else:
                counts["errors"] += 1

        # ── Create Services ──
        log_entries.append({"level": "info", "msg": "--- Creating services ---"})
        for entry in dedup_results.get("services", []):
            if entry["action"] != "create":
                continue
            parsed = svc_by_name.get(entry["parsed_name"])
            if not parsed:
                continue
            smc_name = entry["smc_name"]
            protocol = parsed.get("protocol", "")

            if protocol in ("TCP", "TCP/UDP"):
                for min_p, max_p in parsed.get("tcp_ports", []):
                    kwargs = {"name": smc_name, "min_dst_port": min_p,
                              "comment": parsed.get("comment", "")}
                    if max_p != min_p:
                        kwargs["max_dst_port"] = max_p
                    result = _safe_create(TCPService.create, "tcp_service",
                                          log_entries, **kwargs)
                    if result == "created":
                        counts["created"] += 1
                    elif result == "skipped":
                        counts["skipped"] += 1
                    else:
                        counts["errors"] += 1

            if protocol in ("UDP", "TCP/UDP"):
                for min_p, max_p in parsed.get("udp_ports", []):
                    kwargs = {"name": smc_name, "min_dst_port": min_p,
                              "comment": parsed.get("comment", "")}
                    if max_p != min_p:
                        kwargs["max_dst_port"] = max_p
                    result = _safe_create(UDPService.create, "udp_service",
                                          log_entries, **kwargs)
                    if result == "created":
                        counts["created"] += 1
                    elif result == "skipped":
                        counts["skipped"] += 1
                    else:
                        counts["errors"] += 1

        # ── Create Address Groups ──
        log_entries.append({"level": "info", "msg": "--- Creating address groups ---"})
        addr_grp_by_name = {g["name"]: g for g in parsed_objects.get("address_groups", [])}
        # Build addr name map from dedup
        addr_name_map = {}
        for e in dedup_results.get("addresses", []):
            if e["action"] in ("reuse", "create"):
                addr_name_map[e["parsed_name"]] = e["smc_name"]

        for entry in dedup_results.get("address_groups", []):
            if entry["action"] != "create":
                continue
            parsed = addr_grp_by_name.get(entry["parsed_name"])
            if not parsed:
                continue
            smc_name = entry["smc_name"]
            members = []
            for m in parsed.get("members", []):
                resolved_name = addr_name_map.get(m, m)
                for cls in [Network, Host, AddressRange, Group, DomainName]:
                    try:
                        elem = cls(resolved_name)
                        _ = elem.href
                        members.append(elem)
                        break
                    except Exception:
                        continue

            try:
                Group.create(name=smc_name, members=members,
                             comment=parsed.get("comment", ""))
                log_entries.append({"level": "info", "msg": f"Created group: {smc_name}"})
                counts["created"] += 1
            except Exception as e:
                err_str = str(e).lower()
                if "already exists" in err_str or "must be unique" in err_str:
                    log_entries.append({"level": "info", "msg": f"Skipped (exists): {smc_name}"})
                    counts["skipped"] += 1
                else:
                    log_entries.append({"level": "error", "msg": f"FAILED group '{smc_name}': {e}"})
                    counts["errors"] += 1

        # ── Create Service Groups ──
        log_entries.append({"level": "info", "msg": "--- Creating service groups ---"})
        svc_grp_by_name = {g["name"]: g for g in parsed_objects.get("service_groups", [])}
        svc_name_map = {}
        for e in dedup_results.get("services", []):
            if e["action"] in ("reuse", "create"):
                svc_name_map[e["parsed_name"]] = e["smc_name"]

        for entry in dedup_results.get("service_groups", []):
            if entry["action"] != "create":
                continue
            parsed = svc_grp_by_name.get(entry["parsed_name"])
            if not parsed:
                continue
            smc_name = entry["smc_name"]
            members = []
            for m in parsed.get("members", []):
                resolved_name = svc_name_map.get(m, m)
                for cls in [TCPService, UDPService, ServiceGroup]:
                    try:
                        svc = cls(resolved_name)
                        _ = svc.href
                        members.append(svc)
                        break
                    except Exception:
                        continue

            try:
                ServiceGroup.create(name=smc_name, members=members,
                                    comment=parsed.get("comment", ""))
                log_entries.append({"level": "info", "msg": f"Created service group: {smc_name}"})
                counts["created"] += 1
            except Exception as e:
                err_str = str(e).lower()
                if "already exists" in err_str or "must be unique" in err_str:
                    log_entries.append({"level": "info", "msg": f"Skipped (exists): {smc_name}"})
                    counts["skipped"] += 1
                else:
                    log_entries.append({"level": "error", "msg": f"FAILED service group '{smc_name}': {e}"})
                    counts["errors"] += 1

        # ── Create NAT Host objects ──
        log_entries.append({"level": "info", "msg": "--- Creating NAT host objects ---"})
        for entry in dedup_results.get("nat_hosts", []):
            if entry["action"] != "create":
                log_entries.append({
                    "level": "info",
                    "msg": f"Reusing existing host for NAT IP {entry['ip']}: {entry['smc_name']}"
                })
                continue
            smc_name = entry["smc_name"]
            ip = entry["ip"]
            result = _safe_create(
                Host.create, "nat_host", log_entries,
                name=smc_name, address=ip,
                comment=f"NAT address ({entry['purpose']}) from {entry['source_name']}",
            )
            if result == "created":
                counts["created"] += 1
            elif result == "skipped":
                counts["skipped"] += 1
            else:
                counts["errors"] += 1

        log_entries.append({"level": "info", "msg": "Object creation complete"})

    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "done",
        "entries": log_entries,
        "objects_created": counts["created"],
        "objects_skipped": counts["skipped"],
        "objects_errors": counts["errors"],
    }


def create_rules(converted_rules, cfg, policy_name):
    """Create firewall rules in SMC from converted rules.

    Only creates rules where selected=True.

    Args:
        converted_rules: Output of rule_converter.convert_policies()
        cfg: SMC config dict
        policy_name: Target policy name in SMC

    Returns:
        Import log dict
    """
    from smc.policy.layer3 import FirewallPolicy
    from smc.elements.network import Host, Network, AddressRange, DomainName
    from smc.elements.group import Group, ServiceGroup
    from smc.elements.service import TCPService, UDPService, IPService

    log_entries = []
    counts = {"rules_created": 0, "sections_created": 0, "rules_errors": 0}

    def _resolve_element(name):
        """Resolve element name to SMC object with validation."""
        if name == "any":
            return None  # handled by SMC as "any"
        for cls in [Network, Host, AddressRange, Group, DomainName]:
            try:
                elem = cls(name)
                _ = elem.href
                return elem
            except Exception:
                continue
        return None

    def _resolve_service(name):
        """Resolve service name to SMC object with validation."""
        if name == "any":
            return None
        for cls in [TCPService, UDPService, IPService, ServiceGroup]:
            try:
                svc = cls(name)
                _ = svc.href
                return svc
            except Exception:
                continue
        return None

    def _resolve_list(names, resolver):
        """Resolve a list of names. Returns 'any' if all unresolvable."""
        if not names or names == ["any"]:
            return "any"
        resolved = []
        for n in names:
            if n == "any":
                return "any"
            obj = resolver(n)
            if obj:
                resolved.append(obj)
        return resolved if resolved else "any"

    with smc_client.smc_session(cfg):
        log_entries.append({"level": "info", "msg": "SMC session established"})

        # Get or create policy
        try:
            policy = FirewallPolicy(policy_name)
            log_entries.append({"level": "info", "msg": f"Using existing policy: {policy_name}"})
        except Exception:
            try:
                FirewallPolicy.create(
                    name=policy_name,
                    template="Firewall Inspection Template",
                )
                policy = FirewallPolicy(policy_name)
                log_entries.append({"level": "info", "msg": f"Created policy: {policy_name}"})
            except Exception as e:
                log_entries.append({"level": "error", "msg": f"Cannot create policy: {e}"})
                return {
                    "status": "error",
                    "entries": log_entries,
                    "rules_created": 0,
                    "rules_errors": 1,
                }

        # Create sections and rules
        for section in converted_rules.get("sections", []):
            section_name = section["name"]
            try:
                policy.fw_ipv4_access_rules.create_rule_section(name=section_name)
                log_entries.append({"level": "info", "msg": f"Section: {section_name}"})
                counts["sections_created"] += 1
            except Exception as e:
                log_entries.append({"level": "warning",
                                    "msg": f"Section '{section_name}': {e}"})

            for rule in section.get("rules", []):
                if not rule.get("selected", False):
                    log_entries.append({
                        "level": "info",
                        "msg": f"Skipped (not selected): {rule['name']}"
                    })
                    continue

                try:
                    sources = _resolve_list(rule["sources"], _resolve_element)
                    destinations = _resolve_list(rule["destinations"], _resolve_element)
                    services = _resolve_list(rule["services"], _resolve_service)

                    policy.fw_ipv4_access_rules.create(
                        name=rule["name"],
                        sources=sources,
                        destinations=destinations,
                        services=services,
                        action=rule.get("action", "allow"),
                        is_disabled=rule.get("is_disabled", False),
                        comment=rule.get("comment", ""),
                    )
                    log_entries.append({
                        "level": "info",
                        "msg": f"Created rule: {rule['name']}"
                    })
                    counts["rules_created"] += 1
                except Exception as e:
                    log_entries.append({
                        "level": "error",
                        "msg": f"FAILED rule '{rule['name']}': {e}"
                    })
                    counts["rules_errors"] += 1

        log_entries.append({"level": "info", "msg": "Rule creation complete"})

    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "done",
        "entries": log_entries,
        "sections_created": counts["sections_created"],
        "rules_created": counts["rules_created"],
        "rules_errors": counts["rules_errors"],
    }


def create_nat_rules(converted_rules, dedup_results, cfg, policy_name):
    """Create NAT rules in SMC from converted NAT rules.

    Only creates rules where selected=True.

    Handles three NAT types:
      - snat: Dynamic source NAT (ippool → Host object)
      - dnat: Static destination NAT (VIP extip → mappedip)
      - snat+dnat: Both source and destination translation

    Args:
        converted_rules: Output of rule_converter.convert_policies()
        dedup_results: Dedup results (for nat_hosts lookup)
        cfg: SMC config dict
        policy_name: Target policy name in SMC

    Returns:
        Import log dict
    """
    from smc.policy.layer3 import FirewallPolicy
    from smc.elements.network import Host, Network, AddressRange, DomainName
    from smc.elements.group import Group, ServiceGroup
    from smc.elements.service import TCPService, UDPService, IPService

    log_entries = []
    counts = {"nat_created": 0, "nat_errors": 0}

    # Build NAT host lookup: ip -> smc_name (for resolving SNAT/DNAT IPs)
    nat_host_map = {}
    for entry in dedup_results.get("nat_hosts", []):
        if entry["action"] in ("reuse", "create"):
            nat_host_map[entry["ip"]] = entry["smc_name"]

    def _resolve_element(name):
        """Resolve element name to SMC object with validation."""
        if name == "any":
            return None
        # First check if it's a raw IP that maps to a NAT host
        if name in nat_host_map:
            name = nat_host_map[name]
        for cls in [Network, Host, AddressRange, Group, DomainName]:
            try:
                elem = cls(name)
                _ = elem.href
                return elem
            except Exception:
                continue
        return None

    def _resolve_service(name):
        """Resolve service name to SMC object with validation."""
        if name == "any":
            return None
        for cls in [TCPService, UDPService, IPService, ServiceGroup]:
            try:
                svc = cls(name)
                _ = svc.href
                return svc
            except Exception:
                continue
        return None

    def _resolve_list(names, resolver):
        """Resolve a list of names. Returns 'any' if all unresolvable."""
        if not names or names == ["any"]:
            return "any"
        resolved = []
        for n in names:
            if n == "any":
                return "any"
            obj = resolver(n)
            if obj:
                resolved.append(obj)
        return resolved if resolved else "any"

    nat_rules = converted_rules.get("nat_rules", [])
    if not nat_rules:
        log_entries.append({"level": "info", "msg": "No NAT rules to create"})
        return {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "done",
            "entries": log_entries,
            "nat_created": 0,
            "nat_errors": 0,
        }

    with smc_client.smc_session(cfg):
        log_entries.append({"level": "info", "msg": "SMC session established for NAT rules"})

        # Get policy
        try:
            policy = FirewallPolicy(policy_name)
            log_entries.append({"level": "info", "msg": f"Using policy: {policy_name}"})
        except Exception as e:
            log_entries.append({"level": "error", "msg": f"Cannot find policy: {e}"})
            return {
                "status": "error",
                "entries": log_entries,
                "nat_created": 0,
                "nat_errors": 1,
            }

        for rule in nat_rules:
            if not rule.get("selected", False):
                log_entries.append({
                    "level": "info",
                    "msg": f"Skipped (not selected): {rule['name']}"
                })
                continue

            try:
                sources = _resolve_list(rule["sources"], _resolve_element)
                destinations = _resolve_list(rule["destinations"], _resolve_element)
                services = _resolve_list(rule["services"], _resolve_service)

                nat_type = rule["nat_type"]
                kwargs = {
                    "name": rule["name"],
                    "sources": sources,
                    "destinations": destinations,
                    "services": services,
                    "is_disabled": rule.get("is_disabled", False),
                    "comment": rule.get("comment", ""),
                }

                # ── SNAT: Dynamic source translation ──
                if nat_type in ("snat", "snat+dnat"):
                    snat_ip = rule.get("dynamic_src_nat_ip", "")
                    if snat_ip:
                        # Resolve to SMC Host object (not just a string name)
                        snat_name = nat_host_map.get(snat_ip, snat_ip)
                        snat_obj = _resolve_element(snat_name)
                        if snat_obj:
                            kwargs["dynamic_src_nat"] = snat_obj
                            kwargs["dynamic_src_nat_ports"] = (1024, 65535)
                        else:
                            log_entries.append({
                                "level": "warning",
                                "msg": f"Cannot resolve SNAT host '{snat_name}' for rule '{rule['name']}'"
                            })

                # ── DNAT: Static destination translation ──
                if nat_type in ("dnat", "snat+dnat"):
                    dnat_ip = rule.get("static_dst_nat", "")
                    if dnat_ip:
                        # Resolve to SMC Host object (not just a string name)
                        dnat_name = nat_host_map.get(dnat_ip, dnat_ip)
                        dnat_obj = _resolve_element(dnat_name)
                        if dnat_obj:
                            kwargs["static_dst_nat"] = dnat_obj
                        else:
                            log_entries.append({
                                "level": "warning",
                                "msg": f"Cannot resolve DNAT host '{dnat_name}' for rule '{rule['name']}'"
                            })

                    # Port forwarding
                    dst_ports = rule.get("static_dst_nat_ports")
                    if dst_ports and dst_ports[0] and dst_ports[1]:
                        kwargs["static_dst_nat_ports"] = dst_ports

                policy.fw_ipv4_nat_rules.create(**kwargs)
                log_entries.append({
                    "level": "info",
                    "msg": f"Created NAT rule [{nat_type}]: {rule['name']}"
                })
                counts["nat_created"] += 1

            except Exception as e:
                log_entries.append({
                    "level": "error",
                    "msg": f"FAILED NAT rule '{rule['name']}': {e}"
                })
                counts["nat_errors"] += 1

        log_entries.append({"level": "info", "msg": "NAT rule creation complete"})

    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "done",
        "entries": log_entries,
        "nat_created": counts["nat_created"],
        "nat_errors": counts["nat_errors"],
    }


def create_vpn_infrastructure(vpn_converted, cfg, engine_name=None):
    """Create VPN profiles, external gateways, sites, and PolicyVPN topology.

    For each selected VPN config:
      1. Create or reuse a VPNProfile (crypto settings)
      2. Create an ExternalGateway with ExternalEndpoint (remote peer IP)
      3. Add VPNSite with remote subnets to the external gateway
      4. Create a PolicyVPN linking the internal engine (central) to external (satellite)

    Args:
        vpn_converted: Output of rule_converter.convert_vpn_tunnels()
        cfg: SMC config dict
        engine_name: Name of the Forcepoint NGFW engine (central gateway).
                     If None, VPN topology is created without central gateway assignment.

    Returns:
        Import log dict
    """
    from smc.vpn.policy import PolicyVPN
    from smc.vpn.elements import VPNProfile, ExternalGateway
    from smc.elements.network import Host, Network

    log_entries = []
    counts = {"vpn_profiles": 0, "gateways": 0, "vpn_policies": 0, "errors": 0}

    vpn_configs = vpn_converted.get("vpn_configs", [])
    if not vpn_configs:
        log_entries.append({"level": "info", "msg": "No VPN configurations to create"})
        return {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "done",
            "entries": log_entries,
            **counts,
        }

    # Track created profiles to avoid duplicates (multiple tunnels may share same crypto)
    created_profiles = {}

    with smc_client.smc_session(cfg):
        log_entries.append({"level": "info", "msg": "SMC session established for VPN creation"})

        for config in vpn_configs:
            if not config.get("selected", False):
                log_entries.append({
                    "level": "info",
                    "msg": f"Skipped (not selected): {config['name']}"
                })
                continue

            tunnel_name = config["name"]
            log_entries.append({"level": "info", "msg": f"--- Processing VPN: {tunnel_name} ---"})

            # ── Step 1: VPN Profile ──
            profile_name = config["vpn_profile"]
            profile_obj = None
            if config["profile_action"] == "reuse":
                try:
                    profile_obj = VPNProfile(profile_name)
                    _ = profile_obj.href
                    log_entries.append({
                        "level": "info",
                        "msg": f"Reusing VPN Profile: {profile_name}"
                    })
                except Exception:
                    log_entries.append({
                        "level": "warning",
                        "msg": f"Cannot find VPN Profile '{profile_name}' — will create"
                    })
                    config["profile_action"] = "create"

            if config["profile_action"] == "create":
                if profile_name in created_profiles:
                    profile_obj = created_profiles[profile_name]
                    log_entries.append({
                        "level": "info",
                        "msg": f"Reusing already-created VPN Profile: {profile_name}"
                    })
                else:
                    try:
                        caps = config.get("profile_capabilities", {})
                        VPNProfile.create(
                            name=profile_name,
                            capabilities=caps,
                            sa_life_time=config.get("p1_keylife", 86400),
                            tunnel_life_time_seconds=config.get("p2_keylife", 28800),
                        )
                        profile_obj = VPNProfile(profile_name)
                        created_profiles[profile_name] = profile_obj
                        counts["vpn_profiles"] += 1
                        log_entries.append({
                            "level": "info",
                            "msg": f"Created VPN Profile: {profile_name}"
                        })
                    except Exception as e:
                        err_str = str(e).lower()
                        if "already exists" in err_str or "must be unique" in err_str:
                            try:
                                profile_obj = VPNProfile(profile_name)
                                log_entries.append({
                                    "level": "info",
                                    "msg": f"VPN Profile already exists: {profile_name}"
                                })
                            except Exception:
                                pass
                        else:
                            log_entries.append({
                                "level": "error",
                                "msg": f"FAILED creating VPN Profile '{profile_name}': {e}"
                            })
                            counts["errors"] += 1
                            continue

            # ── Step 2: External Gateway + Endpoint ──
            gw_name = config["gateway_name"]
            try:
                ExternalGateway.create(name=gw_name, trust_all_cas=True)
                log_entries.append({"level": "info", "msg": f"Created External Gateway: {gw_name}"})
                counts["gateways"] += 1
            except Exception as e:
                err_str = str(e).lower()
                if "already exists" in err_str or "must be unique" in err_str:
                    log_entries.append({"level": "info", "msg": f"Gateway already exists: {gw_name}"})
                else:
                    log_entries.append({"level": "error", "msg": f"FAILED creating gateway '{gw_name}': {e}"})
                    counts["errors"] += 1
                    continue

            # Add endpoint (remote IP)
            try:
                gw = ExternalGateway(gw_name)
                gw.external_endpoint.create(
                    name=f"{gw_name}-EP",
                    address=config["endpoint_ip"],
                )
                log_entries.append({
                    "level": "info",
                    "msg": f"Created endpoint {config['endpoint_ip']} on {gw_name}"
                })
            except Exception as e:
                err_str = str(e).lower()
                if "already exists" in err_str or "must be unique" in err_str:
                    log_entries.append({"level": "info", "msg": f"Endpoint already exists on {gw_name}"})
                else:
                    log_entries.append({"level": "warning", "msg": f"Endpoint creation issue: {e}"})

            # Add VPN site with remote subnets
            try:
                gw = ExternalGateway(gw_name)
                site_elements = []
                for subnet_cidr in config.get("remote_subnets", []):
                    # Try to resolve as existing Network object
                    resolved = False
                    for cls in [Network, Host]:
                        try:
                            for elem in cls.objects.filter(subnet_cidr):
                                site_elements.append(elem)
                                resolved = True
                                break
                        except Exception:
                            continue
                    if not resolved:
                        # Create a temporary Network for the VPN site
                        net_name = f"FGT-VPN-{tunnel_name}-{subnet_cidr.replace('/', '_')}"
                        try:
                            Network.create(
                                name=net_name,
                                ipv4_network=subnet_cidr,
                                comment=f"VPN site network for {tunnel_name}",
                            )
                            site_elements.append(Network(net_name))
                            log_entries.append({"level": "info", "msg": f"Created VPN network: {net_name}"})
                        except Exception as e2:
                            err2 = str(e2).lower()
                            if "already exists" in err2 or "must be unique" in err2:
                                try:
                                    site_elements.append(Network(net_name))
                                except Exception:
                                    pass
                            else:
                                log_entries.append({"level": "warning", "msg": f"Cannot create network {net_name}: {e2}"})

                if site_elements:
                    gw.vpn_site.create(
                        name=f"{gw_name}-Site",
                        site_element=site_elements,
                    )
                    log_entries.append({
                        "level": "info",
                        "msg": f"Created VPN Site on {gw_name} with {len(site_elements)} networks"
                    })
            except Exception as e:
                err_str = str(e).lower()
                if "already exists" in err_str or "must be unique" in err_str:
                    log_entries.append({"level": "info", "msg": f"VPN Site already exists on {gw_name}"})
                else:
                    log_entries.append({"level": "warning", "msg": f"VPN Site issue on {gw_name}: {e}"})

            # ── Step 3: PolicyVPN ──
            vpn_policy_name = f"FGT-VPN-{tunnel_name}"
            try:
                vpn_kwargs = {"name": vpn_policy_name, "nat": True}
                if profile_obj:
                    vpn_kwargs["vpn_profile"] = profile_obj
                PolicyVPN.create(**vpn_kwargs)
                log_entries.append({
                    "level": "info",
                    "msg": f"Created PolicyVPN: {vpn_policy_name}"
                })
                counts["vpn_policies"] += 1

                # Add external gateway as satellite
                try:
                    vpn = PolicyVPN(vpn_policy_name)
                    vpn.open()
                    vpn.add_satellite_gateway(ExternalGateway(gw_name))

                    # Add internal engine as central gateway if specified
                    if engine_name:
                        try:
                            from smc.core.engines import Layer3Firewall
                            engine = Layer3Firewall(engine_name)
                            vpn.add_central_gateway(engine)
                            log_entries.append({
                                "level": "info",
                                "msg": f"Added central gateway: {engine_name}"
                            })
                        except Exception as eng_err:
                            log_entries.append({
                                "level": "warning",
                                "msg": f"Cannot add engine '{engine_name}' as central: {eng_err}"
                            })

                    vpn.save()
                    vpn.close()
                    log_entries.append({
                        "level": "info",
                        "msg": f"VPN topology configured: {vpn_policy_name}"
                    })
                except Exception as topo_err:
                    log_entries.append({
                        "level": "warning",
                        "msg": f"VPN topology issue for {vpn_policy_name}: {topo_err}"
                    })
                    try:
                        vpn.close()
                    except Exception:
                        pass

            except Exception as e:
                err_str = str(e).lower()
                if "already exists" in err_str or "must be unique" in err_str:
                    log_entries.append({"level": "info", "msg": f"PolicyVPN already exists: {vpn_policy_name}"})
                else:
                    log_entries.append({"level": "error", "msg": f"FAILED PolicyVPN '{vpn_policy_name}': {e}"})
                    counts["errors"] += 1

        log_entries.append({"level": "info", "msg": "VPN infrastructure creation complete"})

    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "done",
        "entries": log_entries,
        "vpn_profiles": counts["vpn_profiles"],
        "gateways": counts["gateways"],
        "vpn_policies": counts["vpn_policies"],
        "vpn_errors": counts["errors"],
    }
