"""
SMC Object Inquiry Module
Query and filter objects in the SMC by type and name.
"""

import argparse
import json
import urllib3
from connect import connect, disconnect
from utils import suppress_stdout

# Suppress SSL warnings when verify_ssl is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import SMC element types
from smc.elements.network import Host, Network, AddressRange, Router, DomainName, Zone
from smc.elements.group import Group, ServiceGroup, TCPServiceGroup, UDPServiceGroup
from smc.elements.service import TCPService, UDPService, ICMPService, IPService
from smc.core.engines import Layer3Firewall, FirewallCluster, Layer2Firewall, IPS, MasterEngine
from smc.core.engine import Engine


# Map of available object types
OBJECT_TYPES = {
    # Network elements
    'host': Host,
    'network': Network,
    'address_range': AddressRange,
    'router': Router,
    'domain_name': DomainName,
    'zone': Zone,
    'group': Group,

    # Services
    'tcp_service': TCPService,
    'udp_service': UDPService,
    'icmp_service': ICMPService,
    'ip_service': IPService,
    'service_group': ServiceGroup,

    # Engines/Firewalls
    'firewall': Layer3Firewall,
    'firewall_cluster': FirewallCluster,
    'layer2_firewall': Layer2Firewall,
    'ips': IPS,
    'master_engine': MasterEngine,
}

# Object types grouped by category (single source of truth for listings)
OBJECT_CATEGORIES = {
    'Network Elements': ['host', 'network', 'address_range', 'router', 'domain_name', 'zone', 'group'],
    'Services': ['tcp_service', 'udp_service', 'icmp_service', 'ip_service', 'service_group'],
    'Engines': ['firewall', 'firewall_cluster', 'layer2_firewall', 'ips', 'master_engine'],
}

# Engine types that have extended details
ENGINE_TYPES = OBJECT_CATEGORIES['Engines']


def _serialize_object(obj, object_type, verbose=False, details=False):
    """
    Serialize an SMC object to a dict for JSON output.

    Args:
        obj: The SMC object.
        object_type: The type key from OBJECT_TYPES.
        verbose: Include basic extra attributes.
        details: Include full detail attributes.

    Returns:
        Dict representation of the object.
    """
    data = {"name": obj.name, "type": obj.typeof}

    if hasattr(obj, 'href'):
        data["href"] = obj.href

    if verbose or details:
        if hasattr(obj, 'address'):
            data["address"] = obj.address
        if hasattr(obj, 'ipv4_network'):
            data["ipv4_network"] = str(obj.ipv4_network) if obj.ipv4_network else None
        if hasattr(obj, 'ip_range'):
            data["ip_range"] = obj.ip_range
        if hasattr(obj, 'comment') and obj.comment:
            data["comment"] = obj.comment

    if details:
        # Host details
        if hasattr(obj, 'ipv6_address') and obj.ipv6_address:
            data["ipv6_address"] = obj.ipv6_address
        if hasattr(obj, 'secondary') and obj.secondary:
            data["secondary"] = obj.secondary

        # Network details
        if hasattr(obj, 'ipv6_network') and obj.ipv6_network:
            data["ipv6_network"] = str(obj.ipv6_network)

        # Service details
        if hasattr(obj, 'min_dst_port'):
            data["min_dst_port"] = obj.min_dst_port
        if hasattr(obj, 'max_dst_port') and obj.max_dst_port:
            data["max_dst_port"] = obj.max_dst_port
        if hasattr(obj, 'min_src_port') and obj.min_src_port:
            data["min_src_port"] = obj.min_src_port
        if hasattr(obj, 'max_src_port') and obj.max_src_port:
            data["max_src_port"] = obj.max_src_port
        if hasattr(obj, 'icmp_type'):
            data["icmp_type"] = obj.icmp_type
        if hasattr(obj, 'icmp_code'):
            data["icmp_code"] = obj.icmp_code
        if hasattr(obj, 'protocol_number'):
            data["protocol_number"] = obj.protocol_number

        # Group members
        if hasattr(obj, 'members'):
            try:
                data["members"] = [
                    {"name": m.name, "type": m.typeof}
                    for m in obj.members
                ]
            except Exception:
                data["members"] = []

        # Engine details
        if object_type in ENGINE_TYPES:
            try:
                engine = Engine(obj.name)
                engine_data = {}
                try:
                    engine_data["nodes"] = [
                        {"name": n.name, "nodeid": getattr(n, 'nodeid', None)}
                        for n in engine.nodes
                    ]
                except Exception:
                    pass
                try:
                    engine_data["interfaces"] = []
                    for iface in engine.interface.all():
                        iface_info = {"name": iface.name}
                        if hasattr(iface, 'interface_id'):
                            iface_info["interface_id"] = iface.interface_id
                        if hasattr(iface, 'addresses'):
                            iface_info["addresses"] = list(iface.addresses)
                        engine_data["interfaces"].append(iface_info)
                except Exception:
                    pass
                try:
                    engine_data["routing"] = [str(r) for r in engine.routing.all()]
                except Exception:
                    pass
                try:
                    policy = engine.installed_policy
                    engine_data["installed_policy"] = str(policy) if policy else None
                except Exception:
                    pass
                data["engine"] = engine_data
            except Exception:
                pass

    return data


def list_types():
    """Print all available object types."""
    print("\nAvailable object types:")
    print("-" * 40)

    for category, types in OBJECT_CATEGORIES.items():
        print(f"\n{category}:")
        for t in types:
            print(f"  - {t}")

    return OBJECT_CATEGORIES


def query_objects(object_type: str, name_filter: str = None, limit: int = None):
    """
    Query objects from SMC.

    Args:
        object_type: Type of object to query (e.g., 'host', 'network').
        name_filter: Optional name pattern to filter results.
        limit: Maximum number of results to return.

    Returns:
        List of matching objects.
    """
    if object_type not in OBJECT_TYPES:
        print(f"Error: Unknown object type '{object_type}'")
        list_types()
        return []

    element_class = OBJECT_TYPES[object_type]
    results = []

    try:
        if name_filter:
            objects = element_class.objects.filter(name_filter)
        else:
            objects = element_class.objects.all()

        for obj in objects:
            results.append(obj)
            if limit and len(results) >= limit:
                break

    except Exception as e:
        print(f"Error querying {object_type}: {e}")

    return results


def print_object_details(obj, verbose: bool = False):
    """Print object details."""
    print(f"\n  Name: {obj.name}")
    print(f"  Type: {obj.typeof}")

    if verbose:
        if hasattr(obj, 'address'):
            print(f"  Address: {obj.address}")
        if hasattr(obj, 'ipv4_network'):
            print(f"  Network: {obj.ipv4_network}")
        if hasattr(obj, 'ip_range'):
            print(f"  Range: {obj.ip_range}")
        if hasattr(obj, 'comment') and obj.comment:
            print(f"  Comment: {obj.comment}")
        if hasattr(obj, 'href'):
            print(f"  Href: {obj.href}")


def print_section(title: str, char: str = "-"):
    """Print a section header."""
    print(f"\n{title}")
    print(char * len(title))


def get_engine_details(engine_name: str):
    """
    Get comprehensive details for an engine/firewall.

    Args:
        engine_name: Name of the engine to inspect.
    """
    try:
        engine = Engine(engine_name)
        print(f"\n{'=' * 60}")
        print(f"DETAILED CONFIGURATION: {engine.name}")
        print(f"{'=' * 60}")

        # Basic Info
        print_section("BASIC INFORMATION")
        print(f"  Name: {engine.name}")
        print(f"  Type: {engine.typeof}")
        if hasattr(engine, 'href'):
            print(f"  Href: {engine.href}")
        if hasattr(engine, 'comment') and engine.comment:
            print(f"  Comment: {engine.comment}")

        # Nodes
        print_section("NODES")
        try:
            nodes = list(engine.nodes)
            if nodes:
                for node in nodes:
                    print(f"  - {node.name}")
                    if hasattr(node, 'nodeid'):
                        print(f"      Node ID: {node.nodeid}")
            else:
                print("  No nodes found")
        except Exception as e:
            print(f"  Error fetching nodes: {e}")

        # Interfaces
        print_section("INTERFACES")
        try:
            interfaces = list(engine.interface.all())
            if interfaces:
                for iface in interfaces:
                    print(f"\n  Interface: {iface.name}")
                    if hasattr(iface, 'interface_id'):
                        print(f"    ID: {iface.interface_id}")
                    if hasattr(iface, 'addresses'):
                        addrs = iface.addresses
                        if addrs:
                            print(f"    Addresses: {addrs}")
                    if hasattr(iface, 'zone_ref') and iface.zone_ref:
                        print(f"    Zone: {iface.zone_ref}")
            else:
                print("  No interfaces configured")
        except Exception as e:
            print(f"  Error fetching interfaces: {e}")

        # Routing
        print_section("ROUTING")
        try:
            routes = list(engine.routing.all())
            if routes:
                for route in routes:
                    print(f"  - {route}")
            else:
                print("  No routes configured")
        except Exception as e:
            print(f"  Error fetching routes: {e}")

        # Policy
        print_section("POLICY")
        try:
            if hasattr(engine, 'installed_policy'):
                policy = engine.installed_policy
                if policy:
                    print(f"  Installed Policy: {policy}")
                else:
                    print("  No policy installed")
        except Exception as e:
            print(f"  Error fetching policy: {e}")

        # Pending changes
        print_section("PENDING CHANGES")
        try:
            if hasattr(engine, 'pending_changes'):
                changes = engine.pending_changes
                if hasattr(changes, 'all'):
                    pending = list(changes.all())
                    if pending:
                        for change in pending:
                            print(f"  - {change}")
                    else:
                        print("  No pending changes")
                else:
                    print("  No pending changes")
        except Exception as e:
            print(f"  Error fetching pending changes: {e}")

        # Additional attributes from data
        print_section("RAW DATA (Key Attributes)")
        try:
            if hasattr(engine, 'data'):
                data = engine.data
                important_fields = [
                    'antivirus', 'file_reputation', 'sidewinder_proxy_enabled',
                    'log_server_ref', 'location_ref', 'default_nat', 'dns',
                    'primary_mgt', 'backup_mgt', 'log_spooling_policy'
                ]
                for field in important_fields:
                    if field in data:
                        value = data[field]
                        if value:
                            print(f"  {field}: {value}")
        except Exception as e:
            print(f"  Error fetching raw data: {e}")

    except Exception as e:
        print(f"Error loading engine '{engine_name}': {e}")


def get_host_details(obj):
    """Get detailed info for a Host object."""
    print(f"\n{'=' * 60}")
    print(f"DETAILED CONFIGURATION: {obj.name}")
    print(f"{'=' * 60}")

    print_section("BASIC INFORMATION")
    print(f"  Name: {obj.name}")
    print(f"  Type: {obj.typeof}")
    if hasattr(obj, 'address'):
        print(f"  Address: {obj.address}")
    if hasattr(obj, 'ipv6_address') and obj.ipv6_address:
        print(f"  IPv6 Address: {obj.ipv6_address}")
    if hasattr(obj, 'secondary') and obj.secondary:
        print(f"  Secondary Addresses: {obj.secondary}")
    if hasattr(obj, 'comment') and obj.comment:
        print(f"  Comment: {obj.comment}")
    if hasattr(obj, 'href'):
        print(f"  Href: {obj.href}")


def get_network_details(obj):
    """Get detailed info for a Network object."""
    print(f"\n{'=' * 60}")
    print(f"DETAILED CONFIGURATION: {obj.name}")
    print(f"{'=' * 60}")

    print_section("BASIC INFORMATION")
    print(f"  Name: {obj.name}")
    print(f"  Type: {obj.typeof}")
    if hasattr(obj, 'ipv4_network'):
        print(f"  IPv4 Network: {obj.ipv4_network}")
    if hasattr(obj, 'ipv6_network') and obj.ipv6_network:
        print(f"  IPv6 Network: {obj.ipv6_network}")
    if hasattr(obj, 'comment') and obj.comment:
        print(f"  Comment: {obj.comment}")
    if hasattr(obj, 'href'):
        print(f"  Href: {obj.href}")


def get_group_details(obj):
    """Get detailed info for a Group object."""
    print(f"\n{'=' * 60}")
    print(f"DETAILED CONFIGURATION: {obj.name}")
    print(f"{'=' * 60}")

    print_section("BASIC INFORMATION")
    print(f"  Name: {obj.name}")
    print(f"  Type: {obj.typeof}")
    if hasattr(obj, 'comment') and obj.comment:
        print(f"  Comment: {obj.comment}")

    print_section("GROUP MEMBERS")
    try:
        if hasattr(obj, 'members'):
            members = list(obj.members)
            if members:
                for member in members:
                    print(f"  - {member.name} ({member.typeof})")
            else:
                print("  No members")
        elif hasattr(obj, 'element'):
            elements = obj.element
            if elements:
                for elem in elements:
                    print(f"  - {elem}")
            else:
                print("  No elements")
    except Exception as e:
        print(f"  Error fetching members: {e}")


def get_service_details(obj):
    """Get detailed info for a Service object."""
    print(f"\n{'=' * 60}")
    print(f"DETAILED CONFIGURATION: {obj.name}")
    print(f"{'=' * 60}")

    print_section("BASIC INFORMATION")
    print(f"  Name: {obj.name}")
    print(f"  Type: {obj.typeof}")

    # TCP/UDP specific
    if hasattr(obj, 'min_dst_port'):
        print(f"  Destination Port (min): {obj.min_dst_port}")
    if hasattr(obj, 'max_dst_port') and obj.max_dst_port:
        print(f"  Destination Port (max): {obj.max_dst_port}")
    if hasattr(obj, 'min_src_port') and obj.min_src_port:
        print(f"  Source Port (min): {obj.min_src_port}")
    if hasattr(obj, 'max_src_port') and obj.max_src_port:
        print(f"  Source Port (max): {obj.max_src_port}")

    # ICMP specific
    if hasattr(obj, 'icmp_type'):
        print(f"  ICMP Type: {obj.icmp_type}")
    if hasattr(obj, 'icmp_code'):
        print(f"  ICMP Code: {obj.icmp_code}")

    # IP specific
    if hasattr(obj, 'protocol_number'):
        print(f"  Protocol Number: {obj.protocol_number}")

    if hasattr(obj, 'comment') and obj.comment:
        print(f"  Comment: {obj.comment}")
    if hasattr(obj, 'href'):
        print(f"  Href: {obj.href}")


def get_address_range_details(obj):
    """Get detailed info for an AddressRange object."""
    print(f"\n{'=' * 60}")
    print(f"DETAILED CONFIGURATION: {obj.name}")
    print(f"{'=' * 60}")

    print_section("BASIC INFORMATION")
    print(f"  Name: {obj.name}")
    print(f"  Type: {obj.typeof}")
    if hasattr(obj, 'ip_range'):
        print(f"  IP Range: {obj.ip_range}")
    if hasattr(obj, 'comment') and obj.comment:
        print(f"  Comment: {obj.comment}")
    if hasattr(obj, 'href'):
        print(f"  Href: {obj.href}")


def get_generic_details(obj):
    """Get generic detailed info for any object."""
    print(f"\n{'=' * 60}")
    print(f"DETAILED CONFIGURATION: {obj.name}")
    print(f"{'=' * 60}")

    print_section("BASIC INFORMATION")
    print(f"  Name: {obj.name}")
    print(f"  Type: {obj.typeof}")
    if hasattr(obj, 'href'):
        print(f"  Href: {obj.href}")

    print_section("ALL ATTRIBUTES")
    try:
        if hasattr(obj, 'data'):
            data = obj.data
            for key, value in data.items():
                if value and key not in ['link', 'key']:
                    print(f"  {key}: {value}")
    except Exception as e:
        print(f"  Error fetching data: {e}")


def show_full_details(obj, object_type: str):
    """
    Show full details for an object based on its type.

    Args:
        obj: The SMC object.
        object_type: The type key from OBJECT_TYPES.
    """
    if object_type in ENGINE_TYPES:
        get_engine_details(obj.name)
    elif object_type == 'host':
        get_host_details(obj)
    elif object_type == 'network':
        get_network_details(obj)
    elif object_type == 'address_range':
        get_address_range_details(obj)
    elif object_type in ['group', 'service_group']:
        get_group_details(obj)
    elif object_type in ['tcp_service', 'udp_service', 'icmp_service', 'ip_service']:
        get_service_details(obj)
    else:
        get_generic_details(obj)


def main():
    parser = argparse.ArgumentParser(
        description='Query SMC objects by type and name',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python inquiry.py --type host
  python inquiry.py --type host --name myserver
  python inquiry.py --type network --name "192.168"
  python inquiry.py --type firewall --verbose
  python inquiry.py --type firewall --name MyFirewall --details
  python inquiry.py --list-types

  # JSON output
  python inquiry.py --json --type host --name web
  python inquiry.py --json --type firewall --details
        """
    )

    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON (machine-readable)')
    parser.add_argument(
        '--type', '-t',
        help='Object type to query (e.g., host, network, firewall)'
    )
    parser.add_argument(
        '--name', '-n',
        help='Filter by name (partial match supported)'
    )
    parser.add_argument(
        '--limit', '-l',
        type=int,
        help='Maximum number of results'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show basic detailed object information'
    )
    parser.add_argument(
        '--details', '-d',
        action='store_true',
        help='Show FULL configuration details for each object'
    )
    parser.add_argument(
        '--list-types',
        action='store_true',
        help='List all available object types'
    )

    args = parser.parse_args()
    json_mode = args.json

    # List types and exit
    if args.list_types:
        if json_mode:
            print(json.dumps(OBJECT_CATEGORIES, indent=2))
        else:
            list_types()
        return

    # Require type parameter
    if not args.type:
        parser.print_help()
        print("\nError: --type is required (or use --list-types)")
        return

    # Connect to SMC
    try:
        with suppress_stdout(json_mode):
            connect()
    except Exception as e:
        if json_mode:
            print(json.dumps({"error": f"Connection failed: {e}"}, indent=2))
        else:
            print(f"Connection failed: {e}")
        return

    try:
        if json_mode:
            with suppress_stdout(True):
                results = query_objects(args.type, args.name, args.limit)
            json_result = {
                "type": args.type,
                "filter": args.name,
                "count": len(results),
                "objects": [
                    _serialize_object(obj, args.type, args.verbose, args.details)
                    for obj in results
                ],
            }
            print(json.dumps(json_result, indent=2, default=str))
        else:
            print(f"\nQuerying {args.type} objects" + (f" matching '{args.name}'" if args.name else "") + "...")
            results = query_objects(args.type, args.name, args.limit)

            print(f"\nFound {len(results)} object(s):")
            print("=" * 50)

            for obj in results:
                if args.details:
                    show_full_details(obj, args.type)
                else:
                    print_object_details(obj, args.verbose)

            if not results:
                print("  No objects found.")

    finally:
        with suppress_stdout(json_mode):
            disconnect()


if __name__ == '__main__':
    main()
