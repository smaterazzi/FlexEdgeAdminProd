"""
FortiGate Configuration File Parser
====================================
Parses FortiOS 7.2 .conf files into a normalized JSON data model.

Extracts:
  - system interfaces and zones
  - firewall addresses (subnet, iprange, fqdn)
  - firewall address groups
  - firewall services (TCP, UDP, ICMP, IP)
  - firewall service groups
  - firewall policies (enabled + disabled)
  - firewall VIPs (DNAT)
  - firewall IP pools (SNAT)

Usage:
    from fgt_parser import parse_fortigate_config
    result = parse_fortigate_config("/path/to/config.conf")
"""

import re
import ipaddress
from pathlib import Path


# ── Known FortiGate built-in objects (not to be migrated) ────────────────

BUILTIN_ADDRESSES = {
    "all", "none", "FABRIC_DEVICE", "FIREWALL_AUTH_PORTAL_ADDRESS",
    "SSLVPN_TUNNEL_ADDR1", "login.microsoftonline.com",
    "login.microsoft.com", "login.windows.net",
}

BUILTIN_SERVICES = {
    "ALL", "ALL_ICMP", "ALL_ICMP6", "ALL_TCP", "ALL_UDP",
    "HTTP", "HTTPS", "DNS", "SSH", "TELNET", "FTP", "SMTP",
    "SMTPS", "POP3", "POP3S", "IMAP", "IMAPS", "NTP", "SNMP",
    "PING", "TRACEROUTE", "GRE", "IKE", "AH", "ESP",
    "SAMBA", "SMB", "LDAP", "LDAP_UDP", "KERBEROS",
    "DCE-RPC", "RDP", "RADIUS", "DHCP", "H323",
    "SYSLOG", "TFTP", "TIMESTAMP",
}

BUILTIN_SERVICE_GROUPS = {
    "Email Access", "Windows AD", "Web Access",
    "Exchange Server",
}


# ═══════════════════════════════════════════════════════════════════════════
#  LOW-LEVEL CONFIG PARSER
# ═══════════════════════════════════════════════════════════════════════════

def _tokenize_value(raw):
    """Parse a FortiOS value string into a list of tokens.

    Handles:
      - Quoted strings: "hello world" -> ['hello world']
      - Mixed: "DNS" "HTTP" 53 -> ['DNS', 'HTTP', '53']
      - Unquoted: accept -> ['accept']
    """
    tokens = []
    i = 0
    while i < len(raw):
        if raw[i] == '"':
            # Find closing quote
            j = raw.find('"', i + 1)
            if j == -1:
                # No closing quote — take rest of string
                tokens.append(raw[i + 1:])
                break
            tokens.append(raw[i + 1:j])
            i = j + 1
        elif raw[i] in (' ', '\t'):
            i += 1
        else:
            # Unquoted token
            j = i
            while j < len(raw) and raw[j] not in (' ', '\t', '"'):
                j += 1
            tokens.append(raw[i:j])
            i = j
    return tokens


def _parse_config_blocks(filepath):
    """Parse a FortiGate config file into a tree of config blocks.

    Returns a dict: { "section_path": [ {entry_dict}, ... ], ... }
    Each entry_dict has '_name' (the edit name/id) and all set key-values.

    Nested `config` blocks (e.g. `config reserved-address` inside a DHCP
    server edit) are still flattened into their full path, but each
    nested entry carries a ``_parent_name`` key with the immediate parent
    edit's name so callers can group them. Sets that appear on the parent
    edit *after* a nested ``config ... end`` block correctly attach to
    the parent, not to the synthetic section-settings entry.
    """
    lines = Path(filepath).read_text(encoding="utf-8", errors="replace").splitlines()

    result = {}
    stack = []                  # stack of section names
    entry_stack = []            # parent edits — restored on `end`
    current_entry = None
    current_section = None

    for line in lines:
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        # Handle 'config <section>' — push onto stack
        if stripped.startswith("config "):
            section_name = stripped[7:].strip()
            # If we're inside an edit, remember it so we can restore on `end`
            entry_stack.append(current_entry)
            current_entry = None
            stack.append(section_name)
            current_section = " > ".join(stack)
            if current_section not in result:
                result[current_section] = []
            continue

        # Handle 'end' — pop from stack and restore parent edit (if any)
        if stripped == "end":
            if stack:
                stack.pop()
            current_section = " > ".join(stack) if stack else None
            current_entry = entry_stack.pop() if entry_stack else None
            continue

        # Handle 'edit <name>' — start a new entry
        if stripped.startswith("edit "):
            entry_name_raw = stripped[5:].strip()
            # Remove quotes if present
            if entry_name_raw.startswith('"') and entry_name_raw.endswith('"'):
                entry_name = entry_name_raw[1:-1]
            else:
                entry_name = entry_name_raw
            current_entry = {"_name": entry_name}
            # If we're inside a nested config, link to the immediate parent
            if entry_stack and entry_stack[-1] is not None:
                current_entry["_parent_name"] = entry_stack[-1].get("_name", "")
            if current_section and current_section in result:
                result[current_section].append(current_entry)
            continue

        # Handle 'next' — close current entry
        if stripped == "next":
            current_entry = None
            continue

        # Handle 'set <key> <value...>' — store in current entry or section-level
        if stripped.startswith("set "):
            parts = stripped[4:].split(None, 1)
            if current_entry is not None:
                # Inside an edit block
                if len(parts) == 2:
                    key, val_raw = parts
                    tokens = _tokenize_value(val_raw)
                    if len(tokens) == 1:
                        current_entry[key] = tokens[0]
                    else:
                        current_entry[key] = tokens
                elif len(parts) == 1:
                    current_entry[parts[0]] = True
            elif current_section and current_section in result:
                # Bare 'set' at section level (e.g., config system global)
                # Store as a synthetic entry with _name="_section_settings"
                section_settings = None
                for entry in result[current_section]:
                    if entry.get("_name") == "_section_settings":
                        section_settings = entry
                        break
                if section_settings is None:
                    section_settings = {"_name": "_section_settings"}
                    result[current_section].append(section_settings)
                if len(parts) == 2:
                    key, val_raw = parts
                    tokens = _tokenize_value(val_raw)
                    if len(tokens) == 1:
                        section_settings[key] = tokens[0]
                    else:
                        section_settings[key] = tokens
                elif len(parts) == 1:
                    section_settings[parts[0]] = True
            continue

        # Handle 'unset <key>' — mark as explicitly unset
        if stripped.startswith("unset ") and current_entry is not None:
            key = stripped[6:].strip()
            current_entry[key] = None
            continue

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def _extract_hostname(tree):
    """Extract hostname from 'system global'."""
    for entry in tree.get("system global", []):
        if "hostname" in entry:
            return entry["hostname"]
    return "unknown"


def _extract_interfaces(tree):
    """Extract network interfaces from 'system interface'."""
    interfaces = []
    for entry in tree.get("system interface", []):
        iface = {
            "name": entry["_name"],
            "vdom": entry.get("vdom", "root"),
            "type": entry.get("type", "physical"),
            "role": entry.get("role", ""),
        }
        # Parse IP + mask
        ip_raw = entry.get("ip")
        if ip_raw:
            if isinstance(ip_raw, list) and len(ip_raw) == 2:
                iface["ip"] = ip_raw[0]
                iface["mask"] = ip_raw[1]
            elif isinstance(ip_raw, str):
                iface["ip"] = ip_raw
                iface["mask"] = ""
        # Allowed access
        access = entry.get("allowaccess")
        if access:
            iface["allowaccess"] = access if isinstance(access, list) else [access]
        interfaces.append(iface)
    return interfaces


def _extract_zones(tree):
    """Extract security zones from 'system zone'."""
    zones = []
    for entry in tree.get("system zone", []):
        ifaces = entry.get("interface", [])
        if isinstance(ifaces, str):
            ifaces = [ifaces]
        zones.append({
            "name": entry["_name"],
            "interfaces": ifaces,
            "intrazone": entry.get("intrazone", "deny"),
        })
    return zones


def _classify_address_type(entry):
    """Determine address type: host, subnet, iprange, fqdn, interface-subnet."""
    addr_type = entry.get("type", "")

    if addr_type == "fqdn":
        return "fqdn"
    if addr_type == "iprange":
        return "iprange"
    if addr_type == "interface-subnet":
        return "interface-subnet"

    # Default: check subnet field
    subnet = entry.get("subnet")
    if subnet:
        if isinstance(subnet, list) and len(subnet) == 2:
            ip_str, mask_str = subnet
            # /32 mask = host
            if mask_str == "255.255.255.255":
                return "host"
            return "subnet"
        return "subnet"
    return "unknown"


def _subnet_to_cidr(ip_str, mask_str):
    """Convert IP + dotted mask to CIDR prefix length."""
    try:
        net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        return net.prefixlen
    except (ValueError, TypeError):
        return 0


def _extract_addresses(tree):
    """Extract firewall addresses."""
    addresses = []
    for entry in tree.get("firewall address", []):
        name = entry["_name"]
        addr_type = _classify_address_type(entry)
        is_builtin = name in BUILTIN_ADDRESSES

        addr = {
            "name": name,
            "type": addr_type,
            "builtin": is_builtin,
            "comment": entry.get("comment", ""),
            "uuid": entry.get("uuid", ""),
        }

        if addr_type == "host":
            subnet = entry.get("subnet", [])
            addr["ip"] = subnet[0] if isinstance(subnet, list) else subnet
        elif addr_type == "subnet":
            subnet = entry.get("subnet", [])
            if isinstance(subnet, list) and len(subnet) == 2:
                addr["subnet"] = subnet[0]
                addr["mask"] = subnet[1]
                addr["cidr"] = _subnet_to_cidr(subnet[0], subnet[1])
            else:
                addr["subnet"] = subnet if isinstance(subnet, str) else str(subnet)
                addr["mask"] = ""
                addr["cidr"] = 0
        elif addr_type == "iprange":
            addr["start_ip"] = entry.get("start-ip", "")
            addr["end_ip"] = entry.get("end-ip", "")
        elif addr_type == "fqdn":
            addr["fqdn"] = entry.get("fqdn", "")
        elif addr_type == "interface-subnet":
            subnet = entry.get("subnet", [])
            if isinstance(subnet, list) and len(subnet) == 2:
                addr["subnet"] = subnet[0]
                addr["mask"] = subnet[1]
                addr["cidr"] = _subnet_to_cidr(subnet[0], subnet[1])
            addr["interface"] = entry.get("interface", "")

        addresses.append(addr)
    return addresses


def _extract_address_groups(tree):
    """Extract firewall address groups."""
    groups = []
    for entry in tree.get("firewall addrgrp", []):
        members = entry.get("member", [])
        if isinstance(members, str):
            members = [members]
        elif not isinstance(members, list):
            members = []
        groups.append({
            "name": entry["_name"],
            "members": members,
            "comment": entry.get("comment", ""),
            "uuid": entry.get("uuid", ""),
        })
    return groups


def _parse_port_spec(port_str):
    """Parse a FortiGate port specification.

    Formats:
      "53"        -> [(53, 53)]
      "88 464"    -> [(88, 88), (464, 464)]
      "67-68"     -> [(67, 68)]
      "8000-8010" -> [(8000, 8010)]

    Returns list of (min_port, max_port) tuples.
    """
    if not port_str:
        return []

    # Handle list of ports/ranges (space-separated already tokenized)
    if isinstance(port_str, list):
        result = []
        for p in port_str:
            result.extend(_parse_port_spec(p))
        return result

    # Single port or range
    port_str = str(port_str).strip()
    if "-" in port_str:
        parts = port_str.split("-", 1)
        try:
            return [(int(parts[0]), int(parts[1]))]
        except ValueError:
            return []
    else:
        try:
            p = int(port_str)
            return [(p, p)]
        except ValueError:
            return []


def _extract_services(tree):
    """Extract firewall service custom definitions."""
    services = []
    for entry in tree.get("firewall service custom", []):
        name = entry["_name"]
        is_builtin = name in BUILTIN_SERVICES

        svc = {
            "name": name,
            "builtin": is_builtin,
            "category": entry.get("category", ""),
            "comment": entry.get("comment", ""),
        }

        protocol = entry.get("protocol", "")

        if protocol == "ICMP":
            svc["protocol"] = "ICMP"
            svc["icmp_type"] = entry.get("icmptype", None)
        elif protocol == "ICMP6":
            svc["protocol"] = "ICMP6"
        elif protocol == "IP":
            svc["protocol"] = "IP"
            proto_num = entry.get("protocol-number", "0")
            svc["protocol_number"] = int(proto_num) if str(proto_num).isdigit() else 0
        else:
            # TCP/UDP service — may have both tcp and udp port ranges
            tcp_ports = _parse_port_spec(entry.get("tcp-portrange", ""))
            udp_ports = _parse_port_spec(entry.get("udp-portrange", ""))

            if tcp_ports and udp_ports:
                svc["protocol"] = "TCP/UDP"
                svc["tcp_ports"] = tcp_ports
                svc["udp_ports"] = udp_ports
            elif tcp_ports:
                svc["protocol"] = "TCP"
                svc["tcp_ports"] = tcp_ports
            elif udp_ports:
                svc["protocol"] = "UDP"
                svc["udp_ports"] = udp_ports
            else:
                svc["protocol"] = "TCP/UDP"
                svc["tcp_ports"] = []
                svc["udp_ports"] = []

        services.append(svc)
    return services


def _extract_service_groups(tree):
    """Extract firewall service groups."""
    groups = []
    for entry in tree.get("firewall service group", []):
        members = entry.get("member", [])
        if isinstance(members, str):
            members = [members]
        elif not isinstance(members, list):
            members = []
        groups.append({
            "name": entry["_name"],
            "members": members,
            "builtin": entry["_name"] in BUILTIN_SERVICE_GROUPS,
            "comment": entry.get("comment", ""),
        })
    return groups


def _extract_policies(tree):
    """Extract firewall policies."""
    policies = []
    for entry in tree.get("firewall policy", []):
        policy_id = entry["_name"]
        try:
            policy_id = int(policy_id)
        except (ValueError, TypeError):
            pass

        # Normalize list fields
        def _as_list(val):
            if val is None:
                return []
            if isinstance(val, str):
                return [val]
            return list(val)

        status = entry.get("status", "enable")
        action = entry.get("action", "deny")

        # Check for internet-service (replaces dstaddr + service)
        has_internet_service = entry.get("internet-service") == "enable"
        internet_service_names = _as_list(entry.get("internet-service-name", []))

        policy = {
            "id": policy_id,
            "name": entry.get("name", ""),
            "uuid": entry.get("uuid", ""),
            "status": status,
            "enabled": status != "disable",
            "srcintf": _as_list(entry.get("srcintf")),
            "dstintf": _as_list(entry.get("dstintf")),
            "srcaddr": _as_list(entry.get("srcaddr")),
            "dstaddr": _as_list(entry.get("dstaddr")),
            "service": _as_list(entry.get("service")),
            "action": action,
            "schedule": entry.get("schedule", "always"),
            "nat": entry.get("nat") == "enable",
            "comment": entry.get("comments", entry.get("comment", "")),
            "global_label": entry.get("global-label", ""),
            "has_internet_service": has_internet_service,
            "internet_service_names": internet_service_names,
            # UTM profiles
            "utm_status": entry.get("utm-status") == "enable",
            "av_profile": entry.get("av-profile", ""),
            "ips_sensor": entry.get("ips-sensor", ""),
            "ssl_ssh_profile": entry.get("ssl-ssh-profile", ""),
            # NAT details
            "ippool": entry.get("ippool") == "enable",
            "poolname": entry.get("poolname", ""),
            # VPN
            "groups": _as_list(entry.get("groups")),
        }
        policies.append(policy)
    return policies


def _extract_vips(tree):
    """Extract firewall VIPs (DNAT entries)."""
    vips = []
    for entry in tree.get("firewall vip", []):
        mappedip = entry.get("mappedip", "")
        if isinstance(mappedip, list):
            mappedip = mappedip[0] if mappedip else ""

        vip = {
            "name": entry["_name"],
            "uuid": entry.get("uuid", ""),
            "extip": entry.get("extip", ""),
            "mappedip": mappedip,
            "extintf": entry.get("extintf", "any"),
            "comment": entry.get("comment", ""),
            "portforward": entry.get("portforward") == "enable",
        }
        if vip["portforward"]:
            vip["extport"] = entry.get("extport", "")
            vip["mappedport"] = entry.get("mappedport", "")
        vips.append(vip)
    return vips


def _extract_ip_pools(tree):
    """Extract firewall IP pools (SNAT pools)."""
    pools = []
    for entry in tree.get("firewall ippool", []):
        pool = {
            "name": entry["_name"],
            "type": entry.get("type", "overload"),  # overload (default) or one-to-one
            "startip": entry.get("startip", ""),
            "endip": entry.get("endip", ""),
            "comment": entry.get("comments", entry.get("comment", "")),
        }
        pools.append(pool)
    return pools


# ═══════════════════════════════════════════════════════════════════════════
#  DHCP EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════
#
# FortiGate `config system dhcp server` example:
#
#   config system dhcp server
#       edit 1
#           set default-gateway 192.168.10.1
#           set netmask 255.255.255.0
#           set interface "internal"
#           set lease-time 86400
#           set domain "example.local"
#           set dns-server1 8.8.8.8
#           set dns-server2 1.1.1.1
#           set ntp-server1 192.168.10.1
#           set tftp-server "10.0.0.5"
#           set bootfile-name "pxelinux.0"
#           set vci-match enable
#           set vci-string "Lenovo"
#           config ip-range
#               edit 1
#                   set start-ip 192.168.10.50
#                   set end-ip 192.168.10.150
#               next
#           end
#           config reserved-address
#               edit 1
#                   set ip 192.168.10.10
#                   set mac aa:bb:cc:dd:ee:01
#                   set description "printer"
#               next
#           end
#       next
#   end
#
# The parser flattens nested `config ip-range` and `config reserved-address`
# into separate sections (`system dhcp server > ip-range`, etc.) and tags
# each nested entry with `_parent_name` so we can group them back here.

# Known FG fields that have a clean ISC dhcpd equivalent — used both for
# extraction and to know what we WILL push (anything else lands in
# `unsupported_options` so the operator sees what's lossy at import time).
_DHCP_KNOWN_FIELDS = {
    "default-gateway", "netmask", "interface", "lease-time", "domain",
    "dns-server1", "dns-server2", "dns-server3", "dns-server4",
    "ntp-server1", "ntp-server2", "ntp-server3",
    "wins-server1", "wins-server2",
    "tftp-server", "next-server", "bootfile-name",
    "vci-match", "vci-string",
    # Mode flags we record but don't need to map:
    "status", "dns-service", "wifi-ac-service", "ipsec-lease-hold",
    "auto-configuration",
}


def _extract_dhcp_servers(tree):
    """Extract `config system dhcp server` entries with their nested
    ip-range and reserved-address children grouped under each parent.

    Each returned dict is shaped like::

        {
            "id": "1",                      # FG edit id (str)
            "interface": "internal",
            "subnet": "192.168.10.0",       # derived (range start ANDed with netmask)
            "netmask": "255.255.255.0",
            "subnet_cidr": "192.168.10.0/24",
            "default_gateway": "192.168.10.1",
            "domain": "example.local",
            "lease_time": "86400",
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "ntp_servers": [...],
            "wins_servers": [...],
            "tftp_server": "10.0.0.5",
            "next_server": "",
            "bootfile_name": "pxelinux.0",
            "vci_match": True/False,
            "vci_string": "Lenovo",
            "ranges": [{"start_ip": "...", "end_ip": "..."}, ...],
            "reservations": [
                {"id": "1", "ip": "192.168.10.10",
                 "mac": "aa:bb:cc:dd:ee:01",
                 "description": "printer"},
                ...
            ],
            "unsupported_options": ["foo-bar=enable", ...],
            "raw": { ... },                 # full FG entry dict for debugging
        }
    """
    servers = []
    fg_servers = tree.get("system dhcp server", [])
    fg_ranges = tree.get("system dhcp server > ip-range", [])
    fg_resv = tree.get("system dhcp server > reserved-address", [])

    # Group nested entries by their parent server's _name
    ranges_by_parent: dict[str, list[dict]] = {}
    for r in fg_ranges:
        parent = r.get("_parent_name", "")
        ranges_by_parent.setdefault(parent, []).append(r)

    resv_by_parent: dict[str, list[dict]] = {}
    for r in fg_resv:
        parent = r.get("_parent_name", "")
        resv_by_parent.setdefault(parent, []).append(r)

    for entry in fg_servers:
        if entry.get("_name", "").startswith("_"):
            continue   # skip _section_settings synthetic entries
        srv_id = entry["_name"]

        # Coerce list-shaped values (FG sometimes wraps single values in lists)
        def _scalar(key, default=""):
            v = entry.get(key, default)
            if isinstance(v, list):
                return v[0] if v else default
            if isinstance(v, bool):
                return v
            return v

        def _flag(key):
            v = entry.get(key, "disable")
            if isinstance(v, bool):
                return v
            return str(v).lower() == "enable"

        dns = [_scalar("dns-server1"), _scalar("dns-server2"),
               _scalar("dns-server3"), _scalar("dns-server4")]
        dns = [d for d in dns if d]

        ntp = [_scalar("ntp-server1"), _scalar("ntp-server2"),
               _scalar("ntp-server3")]
        ntp = [n for n in ntp if n]

        wins = [_scalar("wins-server1"), _scalar("wins-server2")]
        wins = [w for w in wins if w]

        ranges = []
        for r in ranges_by_parent.get(srv_id, []):
            ranges.append({
                "id": r.get("_name", ""),
                "start_ip": _scalar_of(r, "start-ip"),
                "end_ip": _scalar_of(r, "end-ip"),
            })

        reservations = []
        for r in resv_by_parent.get(srv_id, []):
            reservations.append({
                "id": r.get("_name", ""),
                "ip": _scalar_of(r, "ip"),
                "mac": _normalize_mac(_scalar_of(r, "mac")),
                "description": _scalar_of(r, "description"),
            })

        # Compute subnet for matching against target SMC scopes
        netmask = _scalar("netmask")
        subnet_ip = ""
        subnet_cidr = ""
        if ranges and netmask:
            subnet_ip = _subnet_from_range(ranges[0]["start_ip"], netmask)
            cidr_bits = _netmask_to_prefix(netmask)
            if subnet_ip and cidr_bits is not None:
                subnet_cidr = f"{subnet_ip}/{cidr_bits}"

        # Flag any keys we don't know how to translate
        unsupported = []
        for k, v in entry.items():
            if k in _DHCP_KNOWN_FIELDS or k.startswith("_"):
                continue
            unsupported.append(f"{k}={v}")

        servers.append({
            "id": srv_id,
            "interface": _scalar("interface"),
            "subnet": subnet_ip,
            "netmask": netmask,
            "subnet_cidr": subnet_cidr,
            "default_gateway": _scalar("default-gateway"),
            "domain": _scalar("domain"),
            "lease_time": _scalar("lease-time"),
            "dns_servers": dns,
            "ntp_servers": ntp,
            "wins_servers": wins,
            "tftp_server": _scalar("tftp-server"),
            "next_server": _scalar("next-server"),
            "bootfile_name": _scalar("bootfile-name"),
            "vci_match": _flag("vci-match"),
            "vci_string": _scalar("vci-string"),
            "ranges": ranges,
            "reservations": reservations,
            "unsupported_options": unsupported,
        })

    return servers


def _scalar_of(entry: dict, key: str, default: str = "") -> str:
    """Local helper: read a key from an FG entry, unwrap list, return string."""
    v = entry.get(key, default)
    if isinstance(v, list):
        return v[0] if v else default
    if isinstance(v, bool):
        return "enable" if v else "disable"
    return v if isinstance(v, str) else str(v)


def _normalize_mac(mac: str) -> str:
    """Lowercase colon form: aa:bb:cc:dd:ee:ff (FG sometimes uses dashes)."""
    if not mac:
        return ""
    return mac.strip().lower().replace("-", ":")


def _netmask_to_prefix(netmask: str) -> int | None:
    """255.255.255.0 → 24. Returns None on malformed input."""
    try:
        parts = [int(p) for p in netmask.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        bits = "".join(format(p, "08b") for p in parts)
        # Must be contiguous 1s followed by contiguous 0s
        if "01" in bits:
            return None
        return bits.count("1")
    except (ValueError, AttributeError):
        return None


def _subnet_from_range(ip: str, netmask: str) -> str:
    """Derive the network address from any IP in the subnet + the netmask."""
    try:
        ip_parts = [int(p) for p in ip.split(".")]
        mask_parts = [int(p) for p in netmask.split(".")]
        if len(ip_parts) != 4 or len(mask_parts) != 4:
            return ""
        return ".".join(str(i & m) for i, m in zip(ip_parts, mask_parts))
    except (ValueError, AttributeError):
        return ""


# ═══════════════════════════════════════════════════════════════════════════
#  VPN EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _extract_vpn_phase1(tree):
    """Extract IPsec Phase 1 (IKE) tunnels from 'vpn ipsec phase1-interface'."""
    tunnels = []
    for entry in tree.get("vpn ipsec phase1-interface", []):
        # Parse proposal — can be a single string or list
        proposal = entry.get("proposal", "aes256-sha256")
        if isinstance(proposal, list):
            proposal = proposal[0] if proposal else "aes256-sha256"

        dhgrp = entry.get("dhgrp", "14")
        if isinstance(dhgrp, list):
            dhgrp = dhgrp[0] if dhgrp else "14"

        tunnel = {
            "name": entry["_name"],
            "interface": entry.get("interface", ""),
            "local_gw": entry.get("local-gw", "0.0.0.0"),
            "remote_gw": entry.get("remote-gw", ""),
            "proposal": proposal,
            "dhgrp": str(dhgrp),
            "keylife": int(entry.get("keylife", 86400)),
            "ike_version": entry.get("ike-version", "1"),
            "mode": entry.get("mode", "main"),
            "peertype": entry.get("peertype", "any"),
            "dpd": entry.get("dpd", "on-idle"),
            "dpd_retryinterval": int(entry.get("dpd-retryinterval", 10)),
            "net_device": entry.get("net-device") == "enable",
            "nattraversal": entry.get("nattraversal", "enable"),
            "comment": entry.get("comments", entry.get("comment", "")),
            "psksecret_present": "psksecret" in entry,
        }
        tunnels.append(tunnel)
    return tunnels


def _extract_vpn_phase2(tree):
    """Extract IPsec Phase 2 (IPsec SA) entries from 'vpn ipsec phase2-interface'."""
    entries = []
    for entry in tree.get("vpn ipsec phase2-interface", []):
        proposal = entry.get("proposal", "aes256-sha256")
        if isinstance(proposal, list):
            proposal = proposal[0] if proposal else "aes256-sha256"

        dhgrp = entry.get("dhgrp", "")
        if isinstance(dhgrp, list):
            dhgrp = dhgrp[0] if dhgrp else ""

        p2 = {
            "name": entry["_name"],
            "phase1name": entry.get("phase1name", ""),
            "proposal": proposal,
            "pfs": entry.get("pfs", "enable"),
            "dhgrp": str(dhgrp) if dhgrp else "",
            "keylifeseconds": int(entry.get("keylifeseconds", 43200)),
            "auto_negotiate": entry.get("auto-negotiate") == "enable",
            "comment": entry.get("comments", entry.get("comment", "")),
        }

        # Parse src-subnet and dst-subnet (stored as [ip, mask] lists by tokenizer)
        for field_key, raw_key in [("src_subnet", "src-subnet"), ("dst_subnet", "dst-subnet")]:
            val = entry.get(raw_key, "")
            if isinstance(val, list) and len(val) == 2:
                cidr = _subnet_to_cidr(val[0], val[1])
                p2[field_key] = f"{val[0]}/{cidr}"
            elif isinstance(val, str) and val:
                p2[field_key] = val
            else:
                p2[field_key] = "0.0.0.0/0"

        entries.append(p2)
    return entries


def _build_vpn_summary(phase1_list, phase2_list):
    """Build enriched VPN tunnel summaries by joining Phase1 and Phase2 data."""
    # Group phase2 entries by their phase1name
    p2_by_p1 = {}
    for p2 in phase2_list:
        p1name = p2["phase1name"]
        if p1name not in p2_by_p1:
            p2_by_p1[p1name] = []
        p2_by_p1[p1name].append(p2)

    vpn_tunnels = []
    for p1 in phase1_list:
        p2_entries = p2_by_p1.get(p1["name"], [])

        # Collect unique local and remote subnets
        local_subnets = sorted(set(p2["src_subnet"] for p2 in p2_entries))
        remote_subnets = sorted(set(p2["dst_subnet"] for p2 in p2_entries))

        vpn_tunnels.append({
            "name": p1["name"],
            "remote_gw": p1["remote_gw"],
            "local_gw": p1["local_gw"],
            "interface": p1["interface"],
            "ike_version": p1["ike_version"],
            "mode": p1["mode"],
            # Phase 1 crypto
            "p1_proposal": p1["proposal"],
            "p1_dhgrp": p1["dhgrp"],
            "p1_keylife": p1["keylife"],
            # Phase 2 crypto (from first entry, all should match)
            "p2_proposal": p2_entries[0]["proposal"] if p2_entries else p1["proposal"],
            "p2_pfs": p2_entries[0]["pfs"] if p2_entries else "enable",
            "p2_dhgrp": p2_entries[0]["dhgrp"] if p2_entries else p1["dhgrp"],
            "p2_keylife": p2_entries[0]["keylifeseconds"] if p2_entries else 43200,
            # Metadata
            "dpd": p1["dpd"],
            "nattraversal": p1["nattraversal"],
            "psk_auth": p1["psksecret_present"],
            "comment": p1["comment"],
            # Subnets
            "phase2_count": len(p2_entries),
            "phase2_entries": p2_entries,
            "local_subnets": local_subnets,
            "remote_subnets": remote_subnets,
        })

    return vpn_tunnels


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

def parse_fortigate_config(filepath):
    """Parse a FortiGate .conf file and return a structured dict.

    Returns:
        {
            "hostname": str,
            "interfaces": [...],
            "zones": [...],
            "addresses": [...],
            "address_groups": [...],
            "services": [...],
            "service_groups": [...],
            "policies": [...],
            "vips": [...],
            "ip_pools": [...],
            "stats": { counts by type },
        }
    """
    tree = _parse_config_blocks(filepath)

    hostname = _extract_hostname(tree)
    interfaces = _extract_interfaces(tree)
    zones = _extract_zones(tree)
    addresses = _extract_addresses(tree)
    address_groups = _extract_address_groups(tree)
    services = _extract_services(tree)
    service_groups = _extract_service_groups(tree)
    policies = _extract_policies(tree)
    vips = _extract_vips(tree)
    ip_pools = _extract_ip_pools(tree)
    dhcp_servers = _extract_dhcp_servers(tree)
    vpn_phase1 = _extract_vpn_phase1(tree)
    vpn_phase2 = _extract_vpn_phase2(tree)
    vpn_tunnels = _build_vpn_summary(vpn_phase1, vpn_phase2)

    # Build VIP lookup for policy enrichment
    vip_by_name = {v["name"]: v for v in vips}
    pool_by_name = {p["name"]: p for p in ip_pools}

    # Enrich policies with resolved NAT data
    nat_policies = 0
    for policy in policies:
        # Detect VIP references in dstaddr (DNAT)
        vip_refs = []
        for dname in policy.get("dstaddr", []):
            if dname in vip_by_name:
                vip_refs.append(vip_by_name[dname])
        policy["vip_refs"] = vip_refs
        policy["has_dnat"] = len(vip_refs) > 0

        # Resolve pool definition (SNAT)
        poolname = policy.get("poolname", "")
        if isinstance(poolname, list):
            poolname = poolname[0] if poolname else ""
        pool_def = pool_by_name.get(poolname)
        policy["pool_def"] = pool_def

        # Flag NAT policies
        policy["has_snat"] = policy.get("nat", False) and policy.get("ippool", False)
        if policy.get("nat") or policy.get("has_dnat"):
            nat_policies += 1

    # Compute stats
    enabled_policies = [p for p in policies if p["enabled"]]
    disabled_policies = [p for p in policies if not p["enabled"]]
    custom_addresses = [a for a in addresses if not a["builtin"]]
    custom_services = [s for s in services if not s["builtin"]]

    dhcp_reservations_total = sum(len(s["reservations"]) for s in dhcp_servers)

    stats = {
        "interfaces": len(interfaces),
        "zones": len(zones),
        "addresses": len(addresses),
        "addresses_custom": len(custom_addresses),
        "address_groups": len(address_groups),
        "services": len(services),
        "services_custom": len(custom_services),
        "service_groups": len(service_groups),
        "policies_total": len(policies),
        "policies_enabled": len(enabled_policies),
        "policies_disabled": len(disabled_policies),
        "vips": len(vips),
        "ip_pools": len(ip_pools),
        "nat_policies": nat_policies,
        "vpn_tunnels": len(vpn_tunnels),
        "vpn_phase2_total": len(vpn_phase2),
        "dhcp_servers": len(dhcp_servers),
        "dhcp_reservations": dhcp_reservations_total,
    }

    return {
        "hostname": hostname,
        "interfaces": interfaces,
        "zones": zones,
        "addresses": addresses,
        "address_groups": address_groups,
        "services": services,
        "service_groups": service_groups,
        "policies": policies,
        "vips": vips,
        "ip_pools": ip_pools,
        "dhcp_servers": dhcp_servers,
        "vpn_tunnels": vpn_tunnels,
        "stats": stats,
    }
