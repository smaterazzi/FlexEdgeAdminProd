"""
SMC Firewall Management Module
Manage firewall configurations, interfaces, and policy deployments.
"""

import argparse
import json
import sys
import urllib3
from connect import connect, disconnect
from utils import suppress_stdout
from validators import (
    validate_ip_address, validate_cidr, validate_mac_address,
    validate_vlan_id, validate_mtu, validate_interface_id,
    validate_json_nodes,
)

# Suppress SSL warnings when verify_ssl is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from smc.core.engine import Engine
from smc.core.engines import Layer3Firewall, FirewallCluster


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_cluster_params(cvi_address, nodes, resource_type="interface"):
    """
    Validate that required cluster parameters are present.

    Returns:
        Error message string if validation fails, None if valid.
    """
    if not cvi_address or not nodes:
        return (
            f"Error: Cluster {resource_type}s require --cvi-address and --nodes parameters\n"
            f"       Or use --empty to create {resource_type} without IP configuration"
        )
    return None


def _build_cluster_kwargs(interface_id, cvi_address, cvi_network, network,
                          macaddress, zone, comment, nodes, **extra):
    """Build kwargs dict for cluster interface/VLAN creation."""
    kwargs = {
        'interface_id': interface_id,
        'cluster_virtual': cvi_address,
        'network_value': cvi_network or network,
        'nodes': nodes,
    }
    if macaddress:
        kwargs['macaddress'] = macaddress
    if zone:
        kwargs['zone_ref'] = zone
    if comment:
        kwargs['comment'] = comment
    kwargs.update(extra)
    return kwargs


def _build_empty_kwargs(interface_id, zone=None, comment=None, **extra):
    """Build kwargs dict for an empty interface (no IP)."""
    kwargs = {'interface_id': interface_id}
    if zone:
        kwargs['zone_ref'] = zone
    if comment:
        kwargs['comment'] = comment
    kwargs.update(extra)
    return kwargs


def _build_single_kwargs(interface_id, address, network, zone=None,
                         comment=None, **extra):
    """Build kwargs dict for a single firewall interface."""
    kwargs = {
        'interface_id': interface_id,
        'address': address,
        'network_value': network,
    }
    if zone:
        kwargs['zone_ref'] = zone
    if comment:
        kwargs['comment'] = comment
    kwargs.update(extra)
    return kwargs


def _parse_nodes(nodes_arg):
    """
    Parse and validate the ``--nodes`` JSON argument.

    Returns a ``(nodes, error_result)`` tuple. On success ``error_result`` is
    ``None``; on validation failure ``nodes`` is ``None`` and ``error_result``
    is a ``{"success": False, ...}`` dict ready to be returned/serialized.
    """
    if not nodes_arg:
        return None, None
    try:
        return validate_json_nodes(nodes_arg), None
    except ValueError as e:
        print(f"Error: {e}")
        return None, {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Core Functions
# ---------------------------------------------------------------------------

def list_firewalls(verbose: bool = False):
    """
    List all firewalls in the connected domain.

    Args:
        verbose: Show additional details.

    Returns:
        List of dicts with firewall info.
    """
    print("\nListing Firewalls...")
    print("=" * 70)

    result = []

    print("\n[Single Firewalls]")
    print("-" * 70)
    single_count = 0
    for fw in Layer3Firewall.objects.all():
        entry = {"name": fw.name, "type": fw.typeof, "category": "single"}
        if verbose:
            entry["href"] = fw.href
        result.append(entry)
        single_count += 1
        print(f"  {fw.name}")
        if verbose:
            print(f"    Type: {fw.typeof}")
            print(f"    Href: {fw.href}")

    if single_count == 0:
        print("  (none)")

    print("\n[Firewall Clusters]")
    print("-" * 70)
    cluster_count = 0
    for fw in FirewallCluster.objects.all():
        entry = {"name": fw.name, "type": fw.typeof, "category": "cluster"}
        if verbose:
            entry["href"] = fw.href
        result.append(entry)
        cluster_count += 1
        print(f"  {fw.name}")
        if verbose:
            print(f"    Type: {fw.typeof}")
            print(f"    Href: {fw.href}")

    if cluster_count == 0:
        print("  (none)")

    print(f"\nTotal: {len(result)} firewall(s)")
    return result


def show_firewall(name: str, section: str = None):
    """
    Show detailed information about a firewall.

    Args:
        name: Firewall name.
        section: Optional section to show (basic, nodes, interfaces, routing, policy, all).

    Returns:
        Dict with firewall details, or None on error.
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return None

    is_cluster = 'cluster' in engine.typeof.lower()
    result = {"name": engine.name, "type": engine.typeof, "is_cluster": is_cluster}

    print(f"\n{'=' * 70}")
    print(f"FIREWALL: {engine.name}")
    print(f"{'=' * 70}")

    sections = ['basic', 'nodes', 'interfaces', 'routing', 'policy'] if section == 'all' or section is None else [section]

    if 'basic' in sections:
        basic = {"name": engine.name, "type": engine.typeof, "is_cluster": is_cluster}
        print("\n[Basic Information]")
        print("-" * 70)
        print(f"  Name:           {engine.name}")
        print(f"  Type:           {engine.typeof}")
        print(f"  Is Cluster:     {is_cluster}")
        if hasattr(engine, 'href'):
            basic["href"] = engine.href
            print(f"  Href:           {engine.href}")
        if hasattr(engine, 'comment') and engine.comment:
            basic["comment"] = engine.comment
            print(f"  Comment:        {engine.comment}")

        try:
            if engine.location:
                basic["location"] = engine.location.name
                print(f"  Location:       {engine.location.name}")
        except Exception:
            pass
        try:
            if engine.log_server:
                basic["log_server"] = engine.log_server.name
                print(f"  Log Server:     {engine.log_server.name}")
        except Exception:
            pass
        result["basic"] = basic

    if 'nodes' in sections:
        nodes_data = []
        print("\n[Nodes]")
        print("-" * 70)
        try:
            nodes = list(engine.nodes)
            for node in nodes:
                node_info = {"name": node.name}
                print(f"  - {node.name}")
                if hasattr(node, 'nodeid'):
                    node_info["nodeid"] = node.nodeid
                    print(f"      Node ID: {node.nodeid}")
                nodes_data.append(node_info)
        except Exception as e:
            print(f"  Error: {e}")
        result["nodes"] = nodes_data

    if 'interfaces' in sections:
        ifaces_data = []
        print("\n[Interfaces Summary]")
        print("-" * 70)
        try:
            for iface in engine.physical_interface.all():
                iface_info = {
                    "interface_id": iface.interface_id,
                    "name": iface.name,
                    "addresses": [],
                }
                print(f"  Interface {iface.interface_id}: {iface.name}")
                for addr in iface.addresses:
                    ip, network, nicid = addr
                    iface_info["addresses"].append({
                        "ip": ip, "network": network, "nicid": nicid,
                    })
                    print(f"    - {ip} ({network}) [NIC: {nicid}]")
                ifaces_data.append(iface_info)
        except Exception as e:
            print(f"  Error: {e}")
        result["interfaces"] = ifaces_data

    if 'routing' in sections:
        routes_data = []
        print("\n[Routing]")
        print("-" * 70)
        try:
            routes = list(engine.routing.all())
            for route in routes:
                routes_data.append(str(route))
                print(f"  - {route}")
        except Exception as e:
            print(f"  Error: {e}")
        result["routing"] = routes_data

    if 'policy' in sections:
        policy_data = {}
        print("\n[Policy]")
        print("-" * 70)
        try:
            policy = engine.installed_policy
            if policy:
                policy_data["installed_policy"] = str(policy)
                print(f"  Installed Policy: {policy}")
            else:
                policy_data["installed_policy"] = None
                print("  No policy installed")
        except Exception as e:
            print(f"  Error: {e}")

        try:
            changes = list(engine.pending_changes.all())
            if changes:
                policy_data["pending_changes"] = [str(c) for c in changes]
                print(f"  Pending Changes: {len(changes)}")
                for change in changes:
                    print(f"    - {change}")
            else:
                policy_data["pending_changes"] = []
                print("  Pending Changes: None")
        except Exception as e:
            print(f"  Pending Changes Error: {e}")
        result["policy"] = policy_data

    return result


def list_interfaces(name: str, verbose: bool = False):
    """
    List all interfaces for a firewall.

    Args:
        name: Firewall name.
        verbose: Show detailed interface information.

    Returns:
        List of interface dicts, or None on error.
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return None

    is_cluster = 'cluster' in engine.typeof.lower()
    result = []

    print(f"\n{'=' * 70}")
    print(f"INTERFACES: {engine.name}")
    if is_cluster:
        print("(Cluster - interfaces may have CVI and NDI addresses)")
    print(f"{'=' * 70}")

    try:
        for iface in engine.physical_interface.all():
            iface_data = {
                "interface_id": iface.interface_id,
                "name": iface.name,
                "type": type(iface).__name__,
                "addresses": [],
                "vlans": [],
            }

            print(f"\n[Interface {iface.interface_id}] {iface.name}")
            print("-" * 50)
            print(f"  Type: {type(iface).__name__}")

            if verbose:
                # Zone
                if hasattr(iface, 'zone_ref') and iface.zone_ref:
                    iface_data["zone"] = str(iface.zone_ref)
                    print(f"  Zone: {iface.zone_ref}")

                # Management flags
                flags = []
                if hasattr(iface, 'is_primary_mgt') and iface.is_primary_mgt:
                    flags.append("Primary MGT")
                if hasattr(iface, 'is_backup_mgt') and iface.is_backup_mgt:
                    flags.append("Backup MGT")
                if hasattr(iface, 'is_primary_heartbeat') and iface.is_primary_heartbeat:
                    flags.append("Primary Heartbeat")
                if hasattr(iface, 'is_backup_heartbeat') and iface.is_backup_heartbeat:
                    flags.append("Backup Heartbeat")
                if hasattr(iface, 'is_outgoing') and iface.is_outgoing:
                    flags.append("Outgoing")
                if flags:
                    iface_data["flags"] = flags
                    print(f"  Flags: {', '.join(flags)}")

            # Addresses
            print("  Addresses:")
            for addr in iface.addresses:
                ip, network, nicid = addr
                iface_data["addresses"].append({
                    "ip": ip, "network": network, "nicid": nicid,
                })
                print(f"    - IP: {ip}, Network: {network}, NIC ID: {nicid}")

            # VLANs
            if hasattr(iface, 'has_vlan') and iface.has_vlan:
                print("  VLANs:")
                for vlan in iface.vlan_interface:
                    vlan_data = {"name": vlan.name, "addresses": []}
                    print(f"    - {vlan.name}")
                    if verbose:
                        try:
                            for vlan_addr in vlan.addresses:
                                vip, vnet, vnic = vlan_addr
                                vlan_data["addresses"].append({
                                    "ip": vip, "network": vnet, "nicid": vnic,
                                })
                                print(f"        IP: {vip}, Network: {vnet}, NIC ID: {vnic}")
                        except Exception:
                            pass
                    iface_data["vlans"].append(vlan_data)

            # Cluster specific: CVI and NDI
            if is_cluster and verbose:
                try:
                    if hasattr(iface, 'cluster_virtual_interface'):
                        cvi = iface.cluster_virtual_interface
                        if cvi:
                            iface_data["cvi"] = str(cvi)
                            print(f"  CVI: {cvi}")
                except Exception:
                    pass
                try:
                    if hasattr(iface, 'ndi_interfaces'):
                        ndis = list(iface.ndi_interfaces)
                        if ndis:
                            iface_data["ndi"] = [str(n) for n in ndis]
                            print("  NDI Interfaces:")
                            for ndi in ndis:
                                print(f"    - {ndi}")
                except Exception:
                    pass

            result.append(iface_data)

    except Exception as e:
        print(f"Error listing interfaces: {e}")

    return result


def add_interface(name: str, interface_id: int, address: str = None, network: str = None,
                  zone: str = None, comment: str = None, empty: bool = False,
                  cluster: bool = False,
                  cvi_address: str = None, cvi_network: str = None,
                  macaddress: str = None, nodes: list = None):
    """
    Add a Layer 3 interface to a firewall.

    Args:
        name: Firewall name.
        interface_id: Interface ID number.
        address: IP address (for single FW).
        network: Network in CIDR format.
        zone: Optional zone name.
        comment: Optional comment.
        empty: Create empty interface without IP.
        cluster: Treat as cluster firewall (use CVI/NDI).
        cvi_address: Cluster Virtual IP (cluster only).
        cvi_network: Cluster network (cluster only).
        macaddress: MAC address for CVI (cluster only).
        nodes: List of node configs.

    Returns:
        Dict with success status and message.
    """
    # Validate inputs
    try:
        validate_interface_id(interface_id)
        if address:
            validate_ip_address(address)
        if network:
            validate_cidr(network)
        if cvi_address:
            validate_ip_address(cvi_address)
        if cvi_network:
            validate_cidr(cvi_network)
        if macaddress:
            validate_mac_address(macaddress)
    except ValueError as e:
        print(f"Validation error: {e}")
        return {"success": False, "error": str(e)}

    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    try:
        if cluster:
            if empty:
                kwargs = _build_empty_kwargs(interface_id, zone, comment)
                engine.physical_interface.add(**kwargs)
                msg = f"Successfully added empty cluster interface {interface_id}"
            else:
                err = _validate_cluster_params(cvi_address, nodes, "interface")
                if err:
                    print(err)
                    print("Example: --cvi-address 10.0.0.1 --cvi-network 10.0.0.0/24 --macaddress 02:02:02:02:02:02 \\")
                    print("         --nodes '[{\"address\":\"10.0.0.2\",\"network_value\":\"10.0.0.0/24\",\"nodeid\":1}]'")
                    return {"success": False, "error": "Missing cluster parameters"}
                kwargs = _build_cluster_kwargs(
                    interface_id, cvi_address, cvi_network, network,
                    macaddress, zone, comment, nodes,
                )
                engine.physical_interface.add_layer3_cluster_interface(**kwargs)
                msg = f"Successfully added cluster interface {interface_id} with CVI {cvi_address}"
        else:
            if empty:
                kwargs = _build_empty_kwargs(interface_id, zone, comment)
                engine.physical_interface.add(**kwargs)
                msg = f"Successfully added empty interface {interface_id}"
            else:
                if not address or not network:
                    print("Error: Single firewall interfaces require --address and --network parameters")
                    print("       Or use --empty to create interface without IP configuration")
                    print("Example: --address 10.0.0.1 --network 10.0.0.0/24")
                    return {"success": False, "error": "Missing address/network parameters"}
                kwargs = _build_single_kwargs(interface_id, address, network, zone, comment)
                engine.physical_interface.add_layer3_interface(**kwargs)
                msg = f"Successfully added interface {interface_id} with IP {address}"

        print(msg)
        return {"success": True, "message": msg}

    except Exception as e:
        print(f"Error adding interface: {e}")
        return {"success": False, "error": str(e)}


def add_vlan(name: str, interface_id: int, vlan_id: int, address: str = None,
             network: str = None, zone: str = None, comment: str = None,
             empty: bool = False, cluster: bool = False,
             cvi_address: str = None, cvi_network: str = None,
             macaddress: str = None, nodes: list = None):
    """
    Add a VLAN sub-interface to an existing interface.

    Args:
        name: Firewall name.
        interface_id: Parent interface ID.
        vlan_id: VLAN ID (1-4094).
        address: IP address (for single FW).
        network: Network in CIDR format.
        zone: Optional zone name.
        comment: Optional comment.
        empty: Create empty VLAN without IP.
        cluster: Treat as cluster firewall (use CVI/NDI).
        cvi_address: Cluster Virtual IP (cluster only).
        cvi_network: Cluster network (cluster only).
        macaddress: MAC address for CVI (cluster only).
        nodes: List of node configs (cluster only).

    Returns:
        Dict with success status and message.
    """
    # Validate inputs
    try:
        validate_interface_id(interface_id)
        validate_vlan_id(vlan_id)
        if address:
            validate_ip_address(address)
        if network:
            validate_cidr(network)
        if cvi_address:
            validate_ip_address(cvi_address)
        if cvi_network:
            validate_cidr(cvi_network)
        if macaddress:
            validate_mac_address(macaddress)
    except ValueError as e:
        print(f"Validation error: {e}")
        return {"success": False, "error": str(e)}

    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    try:
        if cluster and not empty:
            err = _validate_cluster_params(cvi_address, nodes, "VLAN")
            if err:
                print(err)
                return {"success": False, "error": "Missing cluster parameters"}
            kwargs = _build_cluster_kwargs(
                interface_id, cvi_address, cvi_network, network,
                macaddress, zone, comment, nodes,
                vlan_id=vlan_id,
            )
            engine.physical_interface.add_layer3_vlan_cluster_interface(**kwargs)
            msg = f"Successfully added VLAN {vlan_id} to interface {interface_id} with CVI {cvi_address}"
        elif empty:
            kwargs = _build_empty_kwargs(interface_id, zone, comment, vlan_id=vlan_id)
            engine.physical_interface.add_layer3_vlan_interface(**kwargs)
            msg = f"Successfully added empty VLAN {vlan_id} to interface {interface_id}"
        else:
            if not address or not network:
                print("Error: Single firewall VLANs require --address and --network parameters")
                print("       Or use --empty to create VLAN without IP configuration")
                return {"success": False, "error": "Missing address/network parameters"}
            kwargs = _build_single_kwargs(
                interface_id, address, network, zone, comment, vlan_id=vlan_id
            )
            engine.physical_interface.add_layer3_vlan_interface(**kwargs)
            msg = f"Successfully added VLAN {vlan_id} to interface {interface_id} with IP {address}"

        print(msg)
        return {"success": True, "message": msg}

    except Exception as e:
        print(f"Error adding VLAN: {e}")
        return {"success": False, "error": str(e)}


def add_ip_address(name: str, interface_id: int, address: str, network: str,
                   vlan_id: int = None, nodeid: int = None):
    """
    Add an IP address to an existing interface or VLAN.

    Args:
        name: Firewall name.
        interface_id: Interface ID.
        address: IP address to add.
        network: Network in CIDR format.
        vlan_id: Optional VLAN ID (if adding to a VLAN).
        nodeid: Node ID for cluster (if adding NDI address).

    Returns:
        Dict with success status and message.
    """
    # Validate inputs
    try:
        validate_interface_id(interface_id)
        validate_ip_address(address)
        validate_cidr(network)
        if vlan_id is not None:
            validate_vlan_id(vlan_id)
    except ValueError as e:
        print(f"Validation error: {e}")
        return {"success": False, "error": str(e)}

    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    try:
        iface = engine.physical_interface.get(interface_id)

        if vlan_id:
            # Find the VLAN interface by exact ID match (not substring)
            # VLAN names are typically "VLAN X.Y" where X is interface_id, Y is vlan_id
            for vlan in iface.vlan_interface:
                # Extract VLAN ID from name (e.g., "VLAN 5.100" -> 100)
                vlan_name = vlan.name
                if "." in vlan_name:
                    try:
                        name_vlan_id = int(vlan_name.split(".")[-1])
                        if name_vlan_id == vlan_id:
                            vlan.add_ip_address(address, network)
                            print(f"Successfully added IP {address} to VLAN {vlan_id} on interface {interface_id}")
                            return True
                    except ValueError:
                        pass
                # Fallback: check if vlan_id matches the interface's vlan_id attribute
                if hasattr(vlan, 'vlan_id') and vlan.vlan_id == vlan_id:
                    vlan.add_ip_address(address, network)
                    msg = f"Successfully added IP {address} to VLAN {vlan_id} on interface {interface_id}"
                    print(msg)
                    return {"success": True, "message": msg}
            msg = f"VLAN {vlan_id} not found on interface {interface_id}"
            print(f"Error: {msg}")
            return {"success": False, "error": msg}
        else:
            iface.add_ip_address(address, network)
            msg = f"Successfully added IP {address} to interface {interface_id}"
            print(msg)
            return {"success": True, "message": msg}

    except Exception as e:
        print(f"Error adding IP address: {e}")
        return {"success": False, "error": str(e)}


def delete_interface(name: str, interface_id: int):
    """
    Delete an interface from a firewall.

    Args:
        name: Firewall name.
        interface_id: Interface ID to delete.

    Returns:
        Dict with success status and message.
    """
    try:
        validate_interface_id(interface_id)
    except ValueError as e:
        print(f"Validation error: {e}")
        return {"success": False, "error": str(e)}

    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    try:
        iface = engine.physical_interface.get(interface_id)
        iface.delete()
        msg = f"Successfully deleted interface {interface_id}"
        print(msg)
        return {"success": True, "message": msg}
    except Exception as e:
        print(f"Error deleting interface: {e}")
        return {"success": False, "error": str(e)}


def update_interface(name: str, interface_id: int, zone: str = None, comment: str = None,
                     mtu: int = None, lldp_mode: str = None, macaddress: str = None,
                     cvi_mode: str = None, qos_mode: str = None):
    """
    Update an existing interface's properties.

    Args:
        name: Firewall name.
        interface_id: Interface ID.
        zone: Zone name (use empty string to remove).
        comment: Comment text.
        mtu: MTU value (400-65535).
        lldp_mode: LLDP mode (disabled, receive_only, send_and_receive, send_only).
        macaddress: MAC address (cluster CVI only).
        cvi_mode: CVI mode (packetdispatch, none) - cluster only.
        qos_mode: QoS mode (no_qos, statistics_only, full_qos, dscp).

    Returns:
        Dict with success status and message.
    """
    # Validate inputs
    try:
        validate_interface_id(interface_id)
        if mtu is not None:
            validate_mtu(mtu)
        if macaddress is not None:
            validate_mac_address(macaddress)
    except ValueError as e:
        print(f"Validation error: {e}")
        return {"success": False, "error": str(e)}

    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    is_cluster = 'cluster' in engine.typeof.lower()

    try:
        iface = engine.physical_interface.get(interface_id)
        updated = []

        # Zone
        if zone is not None:
            if zone == '':
                iface.zone_ref = None
                updated.append("zone (removed)")
            else:
                iface.zone_ref = zone
                updated.append(f"zone={zone}")

        # Comment
        if comment is not None:
            iface.comment = comment
            updated.append(f"comment={'set' if comment else 'cleared'}")

        # MTU (already validated above)
        if mtu is not None:
            iface.mtu = mtu
            updated.append(f"mtu={mtu}")

        # LLDP Mode
        if lldp_mode is not None:
            valid_lldp = ['disabled', 'receive_only', 'send_and_receive', 'send_only']
            if lldp_mode in valid_lldp:
                iface.lldp_mode = lldp_mode
                updated.append(f"lldp_mode={lldp_mode}")
            else:
                print(f"Warning: Invalid LLDP mode '{lldp_mode}', valid: {valid_lldp}")

        # MAC Address (cluster only, already validated above)
        if macaddress is not None:
            if is_cluster:
                iface.macaddress = macaddress
                updated.append(f"macaddress={macaddress}")
            else:
                print("Warning: macaddress is only for cluster interfaces, skipping")

        # CVI Mode (cluster only)
        if cvi_mode is not None:
            if is_cluster:
                valid_cvi = ['packetdispatch', 'none']
                if cvi_mode in valid_cvi:
                    iface.cvi_mode = cvi_mode
                    updated.append(f"cvi_mode={cvi_mode}")
                else:
                    print(f"Warning: Invalid CVI mode '{cvi_mode}', valid: {valid_cvi}")
            else:
                print("Warning: cvi_mode is only for cluster interfaces, skipping")

        # QoS Mode
        if qos_mode is not None:
            valid_qos = ['no_qos', 'statistics_only', 'full_qos', 'dscp']
            if qos_mode in valid_qos:
                try:
                    iface.qos.qos_mode = qos_mode
                    updated.append(f"qos_mode={qos_mode}")
                except Exception as qe:
                    print(f"Warning: Could not set QoS mode: {qe}")
            else:
                print(f"Warning: Invalid QoS mode '{qos_mode}', valid: {valid_qos}")

        if updated:
            iface.update()
            msg = f"Successfully updated interface {interface_id}: {', '.join(updated)}"
            print(msg)
        else:
            msg = f"No changes specified for interface {interface_id}"
            print(msg)

        return {"success": True, "message": msg, "updated": updated}
    except Exception as e:
        print(f"Error updating interface: {e}")
        return {"success": False, "error": str(e)}


def policy_refresh(name: str):
    """
    Refresh the policy on a firewall (quick update without full upload).

    Args:
        name: Firewall name.

    Returns:
        Dict with success status and message.
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    try:
        print(f"Refreshing policy on {name}...")
        result = engine.refresh()
        msg = f"Policy refresh initiated: {result}"
        print(msg)
        return {"success": True, "message": msg}
    except Exception as e:
        print(f"Error refreshing policy: {e}")
        return {"success": False, "error": str(e)}


def policy_upload(name: str, policy: str = None):
    """
    Upload/commit a policy to a firewall.

    Args:
        name: Firewall name.
        policy: Policy name (optional, uses current if not specified).

    Returns:
        Dict with success status and message.
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    try:
        print(f"Uploading policy to {name}...")
        if policy:
            result = engine.upload(policy=policy)
        else:
            result = engine.upload()
        msg = f"Policy upload initiated: {result}"
        print(msg)

        # Check for pending changes after upload
        try:
            changes = list(engine.pending_changes.all())
            if changes:
                print(f"Note: {len(changes)} pending change(s) remain after upload")
        except Exception:
            pass

        return {"success": True, "message": msg}
    except Exception as e:
        print(f"Error uploading policy: {e}")
        return {"success": False, "error": str(e)}


def pending_changes(name: str, approve: bool = False, disapprove: bool = False):
    """
    View or manage pending changes on a firewall.

    Args:
        name: Firewall name.
        approve: Approve all pending changes.
        disapprove: Disapprove all pending changes.

    Returns:
        Dict with changes data and action result.
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return {"success": False, "error": str(e)}

    try:
        changes_obj = engine.pending_changes
        changes = list(changes_obj.all())

        if approve:
            changes_obj.approve_all()
            msg = f"Approved all pending changes on {name}"
            print(msg)
            return {"success": True, "message": msg, "action": "approve"}
        elif disapprove:
            changes_obj.disapprove_all()
            msg = f"Disapproved all pending changes on {name}"
            print(msg)
            return {"success": True, "message": msg, "action": "disapprove"}
        else:
            print(f"\nPending Changes for {name}:")
            print("=" * 50)
            if changes:
                for i, change in enumerate(changes, 1):
                    print(f"  {i}. {change}")
            else:
                print("  No pending changes")
            return {
                "success": True,
                "name": name,
                "changes": [str(c) for c in changes],
                "count": len(changes),
            }
    except Exception as e:
        print(f"Error with pending changes: {e}")
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Manage SMC Firewalls',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  list                    List all firewalls
  show                    Show firewall details
  interfaces              List firewall interfaces
  add-interface           Add a Layer 3 interface
  add-vlan                Add a VLAN sub-interface
  add-ip                  Add IP address to interface
  delete-interface        Delete an interface
  update-interface        Update interface properties
  refresh                 Refresh policy on firewall
  upload                  Upload/commit policy to firewall
  pending                 View/manage pending changes

Examples:
  # List all firewalls
  python firewall.py list

  # Show firewall details
  python firewall.py show --name MyFirewall
  python firewall.py show --name MyFirewall --section interfaces

  # List interfaces
  python firewall.py interfaces --name MyFirewall --verbose

  # Add interface (single firewall)
  python firewall.py add-interface --name FW01 --interface-id 5 --address 10.0.0.1 --network 10.0.0.0/24

  # Add interface (cluster with CVI and NDI)
  python firewall.py add-interface --name CLUSTER01 --interface-id 5 \\
      --cvi-address 10.0.0.1 --cvi-network 10.0.0.0/24 --macaddress 02:02:02:02:02:02 \\
      --nodes '[{"address":"10.0.0.2","network_value":"10.0.0.0/24","nodeid":1}]'

  # Add VLAN
  python firewall.py add-vlan --name FW01 --interface-id 1 --vlan-id 100 \\
      --address 192.168.100.1 --network 192.168.100.0/24

  # Refresh policy
  python firewall.py refresh --name MyFirewall

  # Upload policy
  python firewall.py upload --name MyFirewall

  # View pending changes
  python firewall.py pending --name MyFirewall

  # JSON output
  python firewall.py --json list
  python firewall.py --json show --name MyFirewall
        """
    )

    # Global --json flag
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON (machine-readable)')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # List command
    list_parser = subparsers.add_parser('list', help='List all firewalls')
    list_parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')

    # Show command
    show_parser = subparsers.add_parser('show', help='Show firewall details')
    show_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    show_parser.add_argument('--section', '-s', choices=['basic', 'nodes', 'interfaces', 'routing', 'policy', 'all'],
                            default='all', help='Section to display')

    # Interfaces command
    iface_parser = subparsers.add_parser('interfaces', help='List firewall interfaces')
    iface_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    iface_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed interface info')

    # Add interface command
    add_iface_parser = subparsers.add_parser('add-interface', help='Add a Layer 3 interface')
    add_iface_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    add_iface_parser.add_argument('--interface-id', '-i', type=int, required=True, help='Interface ID')
    add_iface_parser.add_argument('--address', '-a', help='IP address (single firewall)')
    add_iface_parser.add_argument('--network', help='Network (CIDR format)')
    add_iface_parser.add_argument('--zone', '-z', help='Zone name')
    add_iface_parser.add_argument('--comment', '-c', help='Comment')
    add_iface_parser.add_argument('--empty', '-e', action='store_true',
                                  help='Create empty interface without IP (configure later with update-interface/add-ip)')
    add_iface_parser.add_argument('--cluster', '-C', action='store_true',
                                  help='Treat as cluster firewall (requires --cvi-address and --nodes)')
    # Cluster options
    add_iface_parser.add_argument('--cvi-address', help='Cluster Virtual IP (requires --cluster)')
    add_iface_parser.add_argument('--cvi-network', help='Cluster Virtual network (requires --cluster)')
    add_iface_parser.add_argument('--macaddress', help='MAC address for CVI (requires --cluster)')
    add_iface_parser.add_argument('--nodes', help='Node configs as JSON array (requires --cluster)')

    # Add VLAN command
    add_vlan_parser = subparsers.add_parser('add-vlan', help='Add a VLAN sub-interface')
    add_vlan_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    add_vlan_parser.add_argument('--interface-id', '-i', type=int, required=True, help='Parent interface ID')
    add_vlan_parser.add_argument('--vlan-id', '-V', type=int, required=True, help='VLAN ID (1-4094)')
    add_vlan_parser.add_argument('--address', '-a', help='IP address (single firewall)')
    add_vlan_parser.add_argument('--network', help='Network (CIDR format)')
    add_vlan_parser.add_argument('--zone', '-z', help='Zone name')
    add_vlan_parser.add_argument('--comment', '-c', help='Comment')
    add_vlan_parser.add_argument('--empty', '-e', action='store_true',
                                 help='Create empty VLAN without IP (configure later with add-ip)')
    add_vlan_parser.add_argument('--cluster', '-C', action='store_true',
                                 help='Treat as cluster firewall (requires --cvi-address and --nodes)')
    # Cluster options
    add_vlan_parser.add_argument('--cvi-address', help='Cluster Virtual IP (requires --cluster)')
    add_vlan_parser.add_argument('--cvi-network', help='Cluster Virtual network (requires --cluster)')
    add_vlan_parser.add_argument('--macaddress', help='MAC address for CVI (requires --cluster)')
    add_vlan_parser.add_argument('--nodes', help='Node configs as JSON array (requires --cluster)')

    # Add IP command
    add_ip_parser = subparsers.add_parser('add-ip', help='Add IP address to interface')
    add_ip_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    add_ip_parser.add_argument('--interface-id', '-i', type=int, required=True, help='Interface ID')
    add_ip_parser.add_argument('--address', '-a', required=True, help='IP address')
    add_ip_parser.add_argument('--network', required=True, help='Network (CIDR format)')
    add_ip_parser.add_argument('--vlan-id', '-V', type=int, help='VLAN ID (if adding to VLAN)')
    add_ip_parser.add_argument('--nodeid', type=int, help='Node ID (for cluster NDI)')

    # Delete interface command
    del_iface_parser = subparsers.add_parser('delete-interface', help='Delete an interface')
    del_iface_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    del_iface_parser.add_argument('--interface-id', '-i', type=int, required=True, help='Interface ID')

    # Update interface command
    upd_iface_parser = subparsers.add_parser('update-interface', help='Update interface properties')
    upd_iface_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    upd_iface_parser.add_argument('--interface-id', '-i', type=int, required=True, help='Interface ID')
    upd_iface_parser.add_argument('--zone', '-z', help='Zone name (empty string to remove)')
    upd_iface_parser.add_argument('--comment', '-c', help='Comment text')
    upd_iface_parser.add_argument('--mtu', type=int, help='MTU value (400-65535)')
    upd_iface_parser.add_argument('--lldp-mode', choices=['disabled', 'receive_only', 'send_and_receive', 'send_only'],
                                  help='LLDP mode')
    upd_iface_parser.add_argument('--macaddress', help='MAC address (cluster CVI only)')
    upd_iface_parser.add_argument('--cvi-mode', choices=['packetdispatch', 'none'],
                                  help='CVI mode (cluster only)')
    upd_iface_parser.add_argument('--qos-mode', choices=['no_qos', 'statistics_only', 'full_qos', 'dscp'],
                                  help='QoS mode')

    # Refresh command
    refresh_parser = subparsers.add_parser('refresh', help='Refresh policy on firewall')
    refresh_parser.add_argument('--name', '-n', required=True, help='Firewall name')

    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload/commit policy to firewall')
    upload_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    upload_parser.add_argument('--policy', '-p', help='Policy name (optional)')

    # Pending changes command
    pending_parser = subparsers.add_parser('pending', help='View/manage pending changes')
    pending_parser.add_argument('--name', '-n', required=True, help='Firewall name')
    pending_parser.add_argument('--approve', action='store_true', help='Approve all pending changes')
    pending_parser.add_argument('--disapprove', action='store_true', help='Disapprove all pending changes')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    json_mode = args.json
    result = None

    # Connect to SMC
    try:
        with suppress_stdout(json_mode):
            connect()
    except Exception as e:
        if json_mode:
            print(json.dumps({"error": f"Connection failed: {e}"}, indent=2))
        else:
            print(f"Connection failed: {e}")
        sys.exit(1)

    try:
        with suppress_stdout(json_mode):
            # Execute command
            if args.command == 'list':
                result = list_firewalls(args.verbose)

            elif args.command == 'show':
                result = show_firewall(args.name, args.section)

            elif args.command == 'interfaces':
                result = list_interfaces(args.name, args.verbose)

            elif args.command == 'add-interface':
                nodes, err = _parse_nodes(args.nodes)
                result = err or add_interface(
                    args.name, args.interface_id, args.address, args.network,
                    args.zone, args.comment, args.empty, args.cluster,
                    args.cvi_address, args.cvi_network, args.macaddress, nodes
                )

            elif args.command == 'add-vlan':
                nodes, err = _parse_nodes(args.nodes)
                result = err or add_vlan(
                    args.name, args.interface_id, args.vlan_id, args.address,
                    args.network, args.zone, args.comment, args.empty, args.cluster,
                    args.cvi_address, args.cvi_network, args.macaddress, nodes
                )

            elif args.command == 'add-ip':
                result = add_ip_address(
                    args.name, args.interface_id, args.address, args.network,
                    args.vlan_id, args.nodeid
                )

            elif args.command == 'delete-interface':
                result = delete_interface(args.name, args.interface_id)

            elif args.command == 'update-interface':
                result = update_interface(
                    args.name, args.interface_id, args.zone, args.comment,
                    args.mtu, getattr(args, 'lldp_mode', None), args.macaddress,
                    getattr(args, 'cvi_mode', None), getattr(args, 'qos_mode', None)
                )

            elif args.command == 'refresh':
                result = policy_refresh(args.name)

            elif args.command == 'upload':
                result = policy_upload(args.name, args.policy)

            elif args.command == 'pending':
                result = pending_changes(args.name, args.approve, args.disapprove)

    finally:
        with suppress_stdout(json_mode):
            disconnect()

    # JSON output
    if json_mode and result is not None:
        print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
