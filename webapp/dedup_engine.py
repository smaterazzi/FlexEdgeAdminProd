"""
Deduplication Engine
=====================
Compares parsed FortiGate objects against live SMC inventory.

For each parsed object, determines:
  - action: 'create' | 'reuse' | 'skip'
  - smc_match: name of matching SMC element (if found)
  - smc_name: proposed name for creation (with FGT- prefix)

Matching strategies:
  1. Exact name match (with and without FGT- prefix)
  2. IP/subnet match for addresses
  3. Port match for services
  4. Built-in object detection
"""

import logging

log = logging.getLogger(__name__)


def run_dedup(parsed_objects, cfg, target_dict=None):
    """Run deduplication against the SMC.

    Args:
        parsed_objects: Output of fgt_parser.parse_fortigate_config()
        cfg: SMC config dict (from smc_config.yml)
        target_dict: Optional migration project ``target`` dict — used to
            compute DHCP reservation dedup against the mapped target scopes.
            When omitted, ``dhcp_reservations`` is empty.

    Returns:
        {
            "addresses": [...],
            "address_groups": [...],
            "services": [...],
            "service_groups": [...],
            "nat_hosts": [...],
            "vpn_profiles": [...],
            "dhcp_reservations": [...],   # one entry per FG dhcp server
        }
        Each entry: {parsed_name, smc_match, match_type, action, smc_name, ...}
    """
    import smc_client

    with smc_client.smc_session(cfg):
        # Fetch all existing SMC elements for comparison
        smc_hosts = {e["name"]: e for e in smc_client.list_elements("hosts")}
        smc_networks = {e["name"]: e for e in smc_client.list_elements("networks")}
        smc_ranges = {e["name"]: e for e in smc_client.list_elements("address_ranges")}
        smc_fqdns = {e["name"]: e for e in smc_client.list_elements("domain_names")}
        smc_groups = {e["name"]: e for e in smc_client.list_elements("groups")}
        smc_tcp = {e["name"]: e for e in smc_client.list_elements("tcp_services")}
        smc_udp = {e["name"]: e for e in smc_client.list_elements("udp_services")}
        smc_svc_groups = {e["name"]: e for e in smc_client.list_elements("service_groups")}

    # Build reverse indexes for IP/port matching
    ip_index = {}  # ip -> smc_name
    for name, elem in smc_hosts.items():
        if addr := elem.get("address"):
            ip_index[addr] = name
    for name, elem in smc_networks.items():
        if subnet := elem.get("ipv4_network"):
            ip_index[subnet] = name

    port_index = {}  # (proto, min, max) -> smc_name
    for name, elem in smc_tcp.items():
        min_p = elem.get("min_dst_port")
        max_p = elem.get("max_dst_port", min_p)
        if min_p is not None:
            port_index[("TCP", int(min_p), int(max_p or min_p))] = name
    for name, elem in smc_udp.items():
        min_p = elem.get("min_dst_port")
        max_p = elem.get("max_dst_port", min_p)
        if min_p is not None:
            port_index[("UDP", int(min_p), int(max_p or min_p))] = name

    # All SMC names for quick lookup
    all_smc_names = set()
    all_smc_names.update(smc_hosts.keys(), smc_networks.keys(), smc_ranges.keys())
    all_smc_names.update(smc_fqdns.keys(), smc_groups.keys())
    all_smc_names.update(smc_tcp.keys(), smc_udp.keys(), smc_svc_groups.keys())

    results = {
        "addresses": _dedup_addresses(
            parsed_objects.get("addresses", []),
            all_smc_names, ip_index,
        ),
        "address_groups": _dedup_address_groups(
            parsed_objects.get("address_groups", []),
            all_smc_names,
        ),
        "services": _dedup_services(
            parsed_objects.get("services", []),
            all_smc_names, port_index,
        ),
        "service_groups": _dedup_service_groups(
            parsed_objects.get("service_groups", []),
            all_smc_names,
        ),
        "nat_hosts": _dedup_nat_hosts(
            parsed_objects, all_smc_names, ip_index,
        ),
        "vpn_profiles": _dedup_vpn_profiles(
            parsed_objects.get("vpn_tunnels", []),
        ),
        "dhcp_reservations": _dedup_dhcp_reservations(
            parsed_objects, target_dict or {},
        ),
    }

    return results


def _dedup_addresses(addresses, smc_names, ip_index):
    """Deduplicate addresses against SMC."""
    results = []
    for addr in addresses:
        name = addr["name"]
        entry = {
            "parsed_name": name,
            "type": addr["type"],
            "smc_match": None,
            "match_type": "none",
            "action": "create",
            "smc_name": name,  # default: use as-is
            "details": {},
        }

        # Skip built-in objects
        if addr.get("builtin"):
            entry["action"] = "skip"
            entry["match_type"] = "builtin"
            results.append(entry)
            continue

        # 1. Exact name match
        if name in smc_names:
            entry["smc_match"] = name
            entry["match_type"] = "exact_name"
            entry["action"] = "reuse"
            entry["smc_name"] = name
            results.append(entry)
            continue

        # 2. FGT-prefixed name match
        fgt_name = f"FGT-{name}" if not name.startswith("FGT-") else name
        if fgt_name in smc_names:
            entry["smc_match"] = fgt_name
            entry["match_type"] = "fgt_prefix"
            entry["action"] = "reuse"
            entry["smc_name"] = fgt_name
            results.append(entry)
            continue

        # 3. IP-based match
        if addr["type"] == "host" and addr.get("ip"):
            if addr["ip"] in ip_index:
                entry["smc_match"] = ip_index[addr["ip"]]
                entry["match_type"] = "ip_match"
                entry["action"] = "reuse"
                entry["smc_name"] = ip_index[addr["ip"]]
                results.append(entry)
                continue

        if addr["type"] == "subnet" and addr.get("subnet") and addr.get("cidr"):
            cidr_key = f"{addr['subnet']}/{addr['cidr']}"
            if cidr_key in ip_index:
                entry["smc_match"] = ip_index[cidr_key]
                entry["match_type"] = "subnet_match"
                entry["action"] = "reuse"
                entry["smc_name"] = ip_index[cidr_key]
                results.append(entry)
                continue

        # 4. No match — needs creation
        entry["action"] = "create"
        entry["smc_name"] = name
        if addr["type"] == "host":
            entry["details"] = {"ip": addr.get("ip", "")}
        elif addr["type"] == "subnet":
            entry["details"] = {
                "subnet": addr.get("subnet", ""),
                "mask": addr.get("mask", ""),
                "cidr": addr.get("cidr", 0),
            }
        elif addr["type"] == "iprange":
            entry["details"] = {
                "start_ip": addr.get("start_ip", ""),
                "end_ip": addr.get("end_ip", ""),
            }
        elif addr["type"] == "fqdn":
            entry["details"] = {"fqdn": addr.get("fqdn", "")}
        results.append(entry)

    return results


def _dedup_address_groups(groups, smc_names):
    """Deduplicate address groups against SMC."""
    results = []
    for grp in groups:
        name = grp["name"]
        members = grp["members"]
        if not isinstance(members, list):
            members = [members] if isinstance(members, str) else []
        entry = {
            "parsed_name": name,
            "members": members,
            "smc_match": None,
            "match_type": "none",
            "action": "create",
            "smc_name": name,
        }

        if name in smc_names:
            entry["smc_match"] = name
            entry["match_type"] = "exact_name"
            entry["action"] = "reuse"
        elif f"FGT-{name}" in smc_names:
            entry["smc_match"] = f"FGT-{name}"
            entry["match_type"] = "fgt_prefix"
            entry["action"] = "reuse"
            entry["smc_name"] = f"FGT-{name}"

        results.append(entry)
    return results


def _dedup_services(services, smc_names, port_index):
    """Deduplicate services against SMC."""
    results = []
    for svc in services:
        name = svc["name"]
        entry = {
            "parsed_name": name,
            "protocol": svc.get("protocol", ""),
            "smc_match": None,
            "match_type": "none",
            "action": "create",
            "smc_name": name,
            "details": {},
        }

        # Skip built-in
        if svc.get("builtin"):
            entry["action"] = "skip"
            entry["match_type"] = "builtin"
            results.append(entry)
            continue

        # 1. Exact name match
        if name in smc_names:
            entry["smc_match"] = name
            entry["match_type"] = "exact_name"
            entry["action"] = "reuse"
            results.append(entry)
            continue

        # 2. FGT-prefixed name
        fgt_name = f"FGT-{name}" if not name.startswith("FGT-") else name
        if fgt_name in smc_names:
            entry["smc_match"] = fgt_name
            entry["match_type"] = "fgt_prefix"
            entry["action"] = "reuse"
            entry["smc_name"] = fgt_name
            results.append(entry)
            continue

        # 3. Port-based match (TCP/UDP only)
        if svc["protocol"] in ("TCP", "TCP/UDP"):
            for min_p, max_p in svc.get("tcp_ports", []):
                key = ("TCP", min_p, max_p)
                if key in port_index:
                    entry["smc_match"] = port_index[key]
                    entry["match_type"] = "port_match"
                    entry["action"] = "reuse"
                    entry["smc_name"] = port_index[key]
                    break

        if entry["action"] == "create" and svc["protocol"] in ("UDP", "TCP/UDP"):
            for min_p, max_p in svc.get("udp_ports", []):
                key = ("UDP", min_p, max_p)
                if key in port_index:
                    entry["smc_match"] = port_index[key]
                    entry["match_type"] = "port_match"
                    entry["action"] = "reuse"
                    entry["smc_name"] = port_index[key]
                    break

        # Store port details for display
        if svc.get("tcp_ports"):
            entry["details"]["tcp_ports"] = svc["tcp_ports"]
        if svc.get("udp_ports"):
            entry["details"]["udp_ports"] = svc["udp_ports"]
        if svc.get("protocol_number"):
            entry["details"]["protocol_number"] = svc["protocol_number"]

        results.append(entry)
    return results


def _dedup_service_groups(groups, smc_names):
    """Deduplicate service groups against SMC."""
    results = []
    for grp in groups:
        name = grp["name"]
        members = grp["members"]
        if not isinstance(members, list):
            members = [members] if isinstance(members, str) else []
        entry = {
            "parsed_name": name,
            "members": members,
            "smc_match": None,
            "match_type": "none",
            "action": "create",
            "smc_name": name,
        }

        if grp.get("builtin"):
            entry["action"] = "skip"
            entry["match_type"] = "builtin"
        elif name in smc_names:
            entry["smc_match"] = name
            entry["match_type"] = "exact_name"
            entry["action"] = "reuse"
        elif f"FGT-{name}" in smc_names:
            entry["smc_match"] = f"FGT-{name}"
            entry["match_type"] = "fgt_prefix"
            entry["action"] = "reuse"
            entry["smc_name"] = f"FGT-{name}"

        results.append(entry)
    return results


def _dedup_nat_hosts(parsed_objects, smc_names, ip_index):
    """Deduplicate Host objects needed for NAT translations.

    Collects all unique IPs from:
      - IP pool startip (SNAT translated address)
      - VIP extip (DNAT destination, the address traffic arrives at)
      - VIP mappedip (DNAT translated destination, the real internal IP)

    For each IP, checks if a Host with that IP already exists in SMC.
    """
    # Collect unique IPs with their purpose
    nat_ips = {}  # ip -> {"purpose": str, "source_name": str}

    for pool in parsed_objects.get("ip_pools", []):
        ip = pool.get("startip", "")
        if ip and ip not in nat_ips:
            nat_ips[ip] = {
                "purpose": "snat_pool",
                "source_name": pool["name"],
                "host_name": f"FGT-SNAT-{ip}",
            }

    for vip in parsed_objects.get("vips", []):
        extip = vip.get("extip", "")
        if extip and extip not in nat_ips:
            nat_ips[extip] = {
                "purpose": "vip_extip",
                "source_name": vip["name"],
                "host_name": f"FGT-VIP-EXT-{extip}",
            }
        mappedip = vip.get("mappedip", "")
        if mappedip and mappedip not in nat_ips:
            nat_ips[mappedip] = {
                "purpose": "vip_mappedip",
                "source_name": vip["name"],
                "host_name": f"FGT-VIP-INT-{mappedip}",
            }

    results = []
    for ip, info in nat_ips.items():
        entry = {
            "ip": ip,
            "purpose": info["purpose"],
            "source_name": info["source_name"],
            "proposed_name": info["host_name"],
            "smc_match": None,
            "match_type": "none",
            "action": "create",
            "smc_name": info["host_name"],
        }

        # Check if a Host with this IP already exists
        if ip in ip_index:
            entry["smc_match"] = ip_index[ip]
            entry["match_type"] = "ip_match"
            entry["action"] = "reuse"
            entry["smc_name"] = ip_index[ip]
        # Check by proposed name
        elif info["host_name"] in smc_names:
            entry["smc_match"] = info["host_name"]
            entry["match_type"] = "name_match"
            entry["action"] = "reuse"
            entry["smc_name"] = info["host_name"]

        results.append(entry)
    return results


# ═══════════════════════════════════════════════════════════════════════════
#  DHCP RESERVATION DEDUP (DB-only, no SMC session)
# ═══════════════════════════════════════════════════════════════════════════

def _dedup_dhcp_reservations(parsed_objects, target_dict):
    """Per-FG-DHCP-server dedup against the existing ``dhcp_reservations``
    rows on the mapped target scope.

    Pure DB lookup — no SMC API calls. Reads ``target.dhcp_mappings``
    written by Phase B's mapping step. Each FG DHCP server produces one
    result entry; reservations within are individually classified.

    Match logic per reservation:
      - same MAC + same IP  → ``already_migrated`` (skip)
      - same MAC + diff IP  → ``mac_conflict``     (manual review)
      - diff MAC + same IP  → ``ip_conflict``      (manual review)
      - none                → ``create``           (selected by default)

    Returns ``[]`` if there are no FG DHCP servers parsed, or if no
    Flask app context (CLI / test mode) — keeps the function safe to call
    outside a Flask request.
    """
    fg_servers = parsed_objects.get("dhcp_servers", [])
    if not fg_servers:
        return []

    try:
        from flask import current_app
        if current_app is None or "sqlalchemy" not in current_app.extensions:
            return [_unmapped_entry(s, "no Flask DB context") for s in fg_servers]
    except (RuntimeError, ImportError):
        return [_unmapped_entry(s, "no Flask DB context") for s in fg_servers]

    from webapp.models import DhcpScope, DhcpReservation
    from webapp.dhcp_readiness import is_scope_ready

    mappings = (target_dict or {}).get("dhcp_mappings", {}) or {}

    results = []
    for srv in fg_servers:
        target_id_raw = mappings.get(str(srv["id"]), "skip")

        # Skip / unmapped — surface as a row so the operator sees it
        if target_id_raw in ("skip", "", None):
            results.append(_unmapped_entry(srv, "not mapped — will be skipped at import"))
            continue

        try:
            scope_id = int(target_id_raw)
        except (TypeError, ValueError):
            results.append(_unmapped_entry(srv, f"invalid mapping value: {target_id_raw!r}"))
            continue

        scope = DhcpScope.query.get(scope_id)
        if not scope:
            results.append(_unmapped_entry(srv,
                f"target scope {scope_id} not found (deleted?)"))
            continue

        ready, missing = is_scope_ready(scope_id)

        # Index existing reservations on the target scope
        existing = DhcpReservation.query.filter_by(scope_id=scope_id).all()
        by_mac = {r.mac_address.lower(): r for r in existing}
        by_ip = {r.ip_address: r for r in existing}

        reservations = []
        for r in srv.get("reservations", []):
            mac = (r.get("mac") or "").lower()
            ip = r.get("ip", "")
            entry = {
                "fg_id": r.get("id", ""),
                "ip": ip,
                "mac": mac,
                "description": r.get("description", ""),
                "smc_match": None,
                "match_type": "none",
                "action": "create",
                "selected": ready,        # only auto-select if scope is ready
                "warnings": [],
            }

            existing_match = by_mac.get(mac)
            if existing_match:
                snap = {
                    "host_name": existing_match.smc_host_name,
                    "ip": existing_match.ip_address,
                    "mac": existing_match.mac_address,
                }
                entry["smc_match"] = snap
                if existing_match.ip_address == ip:
                    entry["match_type"] = "already_migrated"
                    entry["action"] = "skip"
                    entry["selected"] = False
                    entry["warnings"].append(
                        f"Already migrated as Host {existing_match.smc_host_name}"
                    )
                else:
                    entry["match_type"] = "mac_conflict"
                    entry["action"] = "conflict_skip"
                    entry["selected"] = False
                    entry["warnings"].append(
                        f"MAC already used by {existing_match.smc_host_name} "
                        f"at {existing_match.ip_address} — manual review"
                    )
            elif ip in by_ip:
                existing_match = by_ip[ip]
                entry["smc_match"] = {
                    "host_name": existing_match.smc_host_name,
                    "ip": existing_match.ip_address,
                    "mac": existing_match.mac_address,
                }
                entry["match_type"] = "ip_conflict"
                entry["action"] = "conflict_skip"
                entry["selected"] = False
                entry["warnings"].append(
                    f"IP already used by {existing_match.smc_host_name} "
                    f"(MAC {existing_match.mac_address}) — manual review"
                )

            if not ready:
                entry["selected"] = False
                entry["warnings"].append(
                    f"Target scope not DHCP-ready: {', '.join(missing)}"
                )

            reservations.append(entry)

        results.append({
            "fg_server_id": srv["id"],
            "fg_interface": srv.get("interface", ""),
            "fg_subnet_cidr": srv.get("subnet_cidr", ""),
            "target_scope_id": scope_id,
            "target_scope_label": (
                f"{scope.engine_name} / port {scope.interface_id} "
                f"— {scope.subnet_cidr}"
            ),
            "target_scope_ready": ready,
            "target_scope_ready_missing": missing,
            "reservations": reservations,
        })
    return results


def _unmapped_entry(srv, reason):
    """Render an FG DHCP server that has no actionable target — operator
    sees it in the dedup UI, can go back to /dhcp-map to fix it.
    """
    return {
        "fg_server_id": srv["id"],
        "fg_interface": srv.get("interface", ""),
        "fg_subnet_cidr": srv.get("subnet_cidr", ""),
        "target_scope_id": None,
        "target_scope_label": "",
        "target_scope_ready": False,
        "target_scope_ready_missing": [reason],
        "reservations": [],
    }


# ═══════════════════════════════════════════════════════════════════════════
#  VPN PROFILE MATCHING
# ═══════════════════════════════════════════════════════════════════════════

# FortiGate proposal -> (ike_enc_flag, ike_hash_flag, ipsec_enc_flag, ipsec_hash_flag)
_PROPOSAL_MAP = {
    "3des-md5":      ("triple_des", "md5", "triple_des", "md5"),
    "3des-sha1":     ("triple_des", "sha1", "triple_des", "sha1"),
    "3des-sha256":   ("triple_des", "sha2", "triple_des", "sha2"),
    "aes128-md5":    ("aes128", "md5", "aes128", "md5"),
    "aes128-sha1":   ("aes128", "sha1", "aes128", "sha1"),
    "aes128-sha256": ("aes128", "sha2", "aes128", "sha2"),
    "aes256-md5":    ("aes256", "md5", "aes256", "md5"),
    "aes256-sha1":   ("aes256", "sha1", "aes256", "sha1"),
    "aes256-sha256": ("aes256", "sha2", "aes256", "sha2"),
    "aes256gcm":     ("aes_gcm_256", None, "aes_gcm_256", None),
}

# FortiGate DH group number -> SMC capability flag number
_DH_GROUP_MAP = {
    "1": "1", "2": "2", "5": "5",
    "14": "14", "15": "15", "16": "16",
    "19": "19", "20": "20", "21": "21",
}

# Crypto weakness flags
_WEAK_CRYPTO = {
    "3des": "3DES is deprecated (Sweet32 attack)",
    "md5": "MD5 integrity is broken (collision attacks)",
}
_WEAK_DH = {"1", "2", "5"}


def proposal_to_capabilities(proposal, dhgrp, pfs_dhgrp=None):
    """Convert FortiGate proposal + DH group to SMC VPNProfile capability flags.

    Returns (capabilities_dict, warnings_list).
    """
    enc_ike, hash_ike, enc_ipsec, hash_ipsec = _PROPOSAL_MAP.get(
        proposal, ("aes256", "sha2", "aes256", "sha2")
    )
    dh = _DH_GROUP_MAP.get(str(dhgrp), "14")
    pfs_dh = _DH_GROUP_MAP.get(str(pfs_dhgrp or dhgrp), dh)

    caps = {
        f"{enc_ike}_for_ike": True,
        f"{enc_ipsec}_for_ipsec": True,
        f"dh_group_{dh}_for_ike": True,
        f"pfs_dh_group_{pfs_dh}_for_ipsec": True,
        "esp_for_ipsec": True,
        "ike_v1": True,
        "main_mode": True,
        "sa_per_net": True,
    }
    if hash_ike:
        caps[f"{hash_ike}_for_ike"] = True
    if hash_ipsec:
        caps[f"{hash_ipsec}_for_ipsec"] = True

    # Crypto strength warnings
    warnings = []
    for weak_key, msg in _WEAK_CRYPTO.items():
        if weak_key in enc_ike or (hash_ike and weak_key in hash_ike):
            warnings.append(msg)
    if str(dhgrp) in _WEAK_DH:
        warnings.append(f"DH Group {dhgrp} is weak (< 2048-bit)")

    return caps, warnings


def _profile_matches(profile_data, required_caps):
    """Check if an SMC VPN Profile supports all required capabilities."""
    profile_caps = profile_data.get("capabilities", {})
    for flag, value in required_caps.items():
        if value and not profile_caps.get(flag, False):
            return False
    return True


def _dedup_vpn_profiles(vpn_tunnels):
    """Match FortiGate VPN proposals against existing SMC VPN Profiles.

    For each VPN tunnel, determines:
      - required capabilities
      - whether an existing SMC profile matches
      - crypto strength warnings
    """
    if not vpn_tunnels:
        return []

    # Fetch existing VPN profiles from SMC
    existing_profiles = []
    try:
        from smc.vpn.elements import VPNProfile
        for p in VPNProfile.objects.all():
            try:
                existing_profiles.append({
                    "name": p.name,
                    "href": p.href,
                    "capabilities": p.data.get("capabilities", {}),
                    "sa_life_time": p.data.get("sa_life_time", 86400),
                    "tunnel_life_time_seconds": p.data.get("tunnel_life_time_seconds", 28800),
                })
            except Exception:
                continue
    except Exception as e:
        log.warning(f"Cannot fetch VPN profiles from SMC: {e}")

    results = []
    for tunnel in vpn_tunnels:
        required_caps, warnings = proposal_to_capabilities(
            tunnel["p1_proposal"],
            tunnel["p1_dhgrp"],
            tunnel.get("p2_dhgrp") or tunnel["p1_dhgrp"],
        )

        # Try to find a matching existing profile
        match_name = None
        match_type = "none"
        for profile in existing_profiles:
            if _profile_matches(profile, required_caps):
                match_name = profile["name"]
                match_type = "capability_match"
                break

        proposed_name = f"FGT-VPN-{tunnel['p1_proposal']}-DH{tunnel['p1_dhgrp']}"

        entry = {
            "tunnel_name": tunnel["name"],
            "remote_gw": tunnel["remote_gw"],
            "proposal": tunnel["p1_proposal"],
            "dhgrp": tunnel["p1_dhgrp"],
            "p2_proposal": tunnel["p2_proposal"],
            "p2_dhgrp": tunnel.get("p2_dhgrp") or tunnel["p1_dhgrp"],
            "p1_keylife": tunnel["p1_keylife"],
            "p2_keylife": tunnel["p2_keylife"],
            "required_capabilities": required_caps,
            "smc_match": match_name,
            "match_type": match_type,
            "action": "reuse" if match_name else "create",
            "smc_name": match_name or proposed_name,
            "warnings": warnings,
            "phase2_count": tunnel["phase2_count"],
            "local_subnets": tunnel["local_subnets"],
            "remote_subnets": tunnel["remote_subnets"],
        }
        results.append(entry)

    return results
