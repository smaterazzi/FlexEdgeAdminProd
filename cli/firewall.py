"""
SMC Firewall Management Module
Manage firewall configurations, interfaces, and policy deployments.
"""

import argparse
import sys
import urllib3
from connect import connect, disconnect

# Suppress SSL warnings when verify_ssl is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from smc.core.engine import Engine
from smc.core.engines import Layer3Firewall, FirewallCluster


def list_firewalls(verbose: bool = False):
    """
    List all firewalls in the connected domain.

    Args:
        verbose: Show additional details
    """
    print("\nListing Firewalls...")
    print("=" * 70)

    # Get single firewalls
    firewalls = []

    print("\n[Single Firewalls]")
    print("-" * 70)
    for fw in Layer3Firewall.objects.all():
        firewalls.append(('single', fw))
        print(f"  {fw.name}")
        if verbose:
            print(f"    Type: {fw.typeof}")
            print(f"    Href: {fw.href}")

    if not any(f[0] == 'single' for f in firewalls):
        print("  (none)")

    print("\n[Firewall Clusters]")
    print("-" * 70)
    for fw in FirewallCluster.objects.all():
        firewalls.append(('cluster', fw))
        print(f"  {fw.name}")
        if verbose:
            print(f"    Type: {fw.typeof}")
            print(f"    Href: {fw.href}")

    if not any(f[0] == 'cluster' for f in firewalls):
        print("  (none)")

    print(f"\nTotal: {len(firewalls)} firewall(s)")
    return firewalls


def show_firewall(name: str, section: str = None):
    """
    Show detailed information about a firewall.

    Args:
        name: Firewall name
        section: Optional section to show (basic, nodes, interfaces, routing, policy, all)
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return

    is_cluster = 'cluster' in engine.typeof.lower()

    print(f"\n{'=' * 70}")
    print(f"FIREWALL: {engine.name}")
    print(f"{'=' * 70}")

    sections = ['basic', 'nodes', 'interfaces', 'routing', 'policy'] if section == 'all' or section is None else [section]

    if 'basic' in sections:
        print("\n[Basic Information]")
        print("-" * 70)
        print(f"  Name:           {engine.name}")
        print(f"  Type:           {engine.typeof}")
        print(f"  Is Cluster:     {is_cluster}")
        if hasattr(engine, 'href'):
            print(f"  Href:           {engine.href}")
        if hasattr(engine, 'comment') and engine.comment:
            print(f"  Comment:        {engine.comment}")

        # Location and Log Server
        try:
            if engine.location:
                print(f"  Location:       {engine.location.name}")
        except:
            pass
        try:
            if engine.log_server:
                print(f"  Log Server:     {engine.log_server.name}")
        except:
            pass

    if 'nodes' in sections:
        print("\n[Nodes]")
        print("-" * 70)
        try:
            nodes = list(engine.nodes)
            for node in nodes:
                print(f"  - {node.name}")
                if hasattr(node, 'nodeid'):
                    print(f"      Node ID: {node.nodeid}")
        except Exception as e:
            print(f"  Error: {e}")

    if 'interfaces' in sections:
        print("\n[Interfaces Summary]")
        print("-" * 70)
        try:
            for iface in engine.physical_interface.all():
                print(f"  Interface {iface.interface_id}: {iface.name}")
                for addr in iface.addresses:
                    ip, network, nicid = addr
                    print(f"    - {ip} ({network}) [NIC: {nicid}]")
        except Exception as e:
            print(f"  Error: {e}")

    if 'routing' in sections:
        print("\n[Routing]")
        print("-" * 70)
        try:
            routes = list(engine.routing.all())
            for route in routes:
                print(f"  - {route}")
        except Exception as e:
            print(f"  Error: {e}")

    if 'policy' in sections:
        print("\n[Policy]")
        print("-" * 70)
        try:
            policy = engine.installed_policy
            if policy:
                print(f"  Installed Policy: {policy}")
            else:
                print("  No policy installed")
        except Exception as e:
            print(f"  Error: {e}")

        # Pending changes
        try:
            changes = list(engine.pending_changes.all())
            if changes:
                print(f"  Pending Changes: {len(changes)}")
                for change in changes:
                    print(f"    - {change}")
            else:
                print("  Pending Changes: None")
        except Exception as e:
            print(f"  Pending Changes Error: {e}")


def list_interfaces(name: str, verbose: bool = False):
    """
    List all interfaces for a firewall.

    Args:
        name: Firewall name
        verbose: Show detailed interface information
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return

    is_cluster = 'cluster' in engine.typeof.lower()

    print(f"\n{'=' * 70}")
    print(f"INTERFACES: {engine.name}")
    if is_cluster:
        print("(Cluster - interfaces may have CVI and NDI addresses)")
    print(f"{'=' * 70}")

    try:
        for iface in engine.physical_interface.all():
            print(f"\n[Interface {iface.interface_id}] {iface.name}")
            print("-" * 50)
            print(f"  Type: {type(iface).__name__}")

            if verbose:
                # Zone
                if hasattr(iface, 'zone_ref') and iface.zone_ref:
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
                    print(f"  Flags: {', '.join(flags)}")

            # Addresses
            print("  Addresses:")
            for addr in iface.addresses:
                ip, network, nicid = addr
                print(f"    - IP: {ip}, Network: {network}, NIC ID: {nicid}")

            # VLANs
            if hasattr(iface, 'has_vlan') and iface.has_vlan:
                print("  VLANs:")
                for vlan in iface.vlan_interface:
                    print(f"    - {vlan.name}")
                    if verbose:
                        # Try to get VLAN details
                        try:
                            for vlan_addr in vlan.addresses:
                                vip, vnet, vnic = vlan_addr
                                print(f"        IP: {vip}, Network: {vnet}, NIC ID: {vnic}")
                        except:
                            pass

            # Cluster specific: CVI and NDI
            if is_cluster and verbose:
                try:
                    if hasattr(iface, 'cluster_virtual_interface'):
                        cvi = iface.cluster_virtual_interface
                        if cvi:
                            print(f"  CVI: {cvi}")
                except:
                    pass
                try:
                    if hasattr(iface, 'ndi_interfaces'):
                        ndis = list(iface.ndi_interfaces)
                        if ndis:
                            print("  NDI Interfaces:")
                            for ndi in ndis:
                                print(f"    - {ndi}")
                except:
                    pass

    except Exception as e:
        print(f"Error listing interfaces: {e}")


def add_interface(name: str, interface_id: int, address: str = None, network: str = None,
                  zone: str = None, comment: str = None, empty: bool = False,
                  cluster: bool = False,
                  # Cluster-specific parameters
                  cvi_address: str = None, cvi_network: str = None,
                  macaddress: str = None, nodes: list = None):
    """
    Add a Layer 3 interface to a firewall.

    Args:
        name: Firewall name
        interface_id: Interface ID number
        address: IP address (for single FW)
        network: Network in CIDR format
        zone: Optional zone name
        comment: Optional comment
        empty: Create empty interface without IP (can add IP later)
        cluster: Treat as cluster firewall (use CVI/NDI)
        cvi_address: Cluster Virtual IP (cluster only)
        cvi_network: Cluster network (cluster only)
        macaddress: MAC address for CVI (cluster only)
        nodes: List of node configs [{'address':'x.x.x.x','network_value':'x.x.x.x/x','nodeid':1}]
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

    # Use explicit cluster flag instead of auto-detection
    is_cluster = cluster

    try:
        if is_cluster:
            # Cluster interface
            if empty:
                # Create empty cluster interface (no CVI/NDI) - only pass set parameters
                kwargs = {'interface_id': interface_id}
                if zone:
                    kwargs['zone_ref'] = zone
                if comment:
                    kwargs['comment'] = comment
                engine.physical_interface.add(**kwargs)
                print(f"Successfully added empty cluster interface {interface_id}")
            else:
                if not cvi_address or not nodes:
                    print("Error: Cluster interfaces require --cvi-address and --nodes parameters")
                    print("       Or use --empty to create interface without IP configuration")
                    print("Example: --cvi-address 10.0.0.1 --cvi-network 10.0.0.0/24 --macaddress 02:02:02:02:02:02 \\")
                    print("         --nodes '[{\"address\":\"10.0.0.2\",\"network_value\":\"10.0.0.0/24\",\"nodeid\":1}]'")
                    return False
                # Add cluster interface with CVI and NDI - only pass set parameters
                kwargs = {
                    'interface_id': interface_id,
                    'cluster_virtual': cvi_address,
                    'network_value': cvi_network or network,
                    'nodes': nodes
                }
                if macaddress:
                    kwargs['macaddress'] = macaddress
                if zone:
                    kwargs['zone_ref'] = zone
                if comment:
                    kwargs['comment'] = comment
                engine.physical_interface.add_layer3_cluster_interface(**kwargs)
                print(f"Successfully added cluster interface {interface_id} with CVI {cvi_address}")
        else:
            # Single firewall interface
            if empty:
                # Create empty interface (no IP) - only pass set parameters
                kwargs = {'interface_id': interface_id}
                if zone:
                    kwargs['zone_ref'] = zone
                if comment:
                    kwargs['comment'] = comment
                engine.physical_interface.add(**kwargs)
                print(f"Successfully added empty interface {interface_id}")
            else:
                if not address or not network:
                    print("Error: Single firewall interfaces require --address and --network parameters")
                    print("       Or use --empty to create interface without IP configuration")
                    print("Example: --address 10.0.0.1 --network 10.0.0.0/24")
                    return False
                # Only pass set parameters
                kwargs = {
                    'interface_id': interface_id,
                    'address': address,
                    'network_value': network
                }
                if zone:
                    kwargs['zone_ref'] = zone
                if comment:
                    kwargs['comment'] = comment
                engine.physical_interface.add_layer3_interface(**kwargs)
                print(f"Successfully added interface {interface_id} with IP {address}")

        return True

    except Exception as e:
        print(f"Error adding interface: {e}")
        return False


def add_vlan(name: str, interface_id: int, vlan_id: int, address: str = None,
             network: str = None, zone: str = None, comment: str = None,
             empty: bool = False, cluster: bool = False,
             # Cluster-specific parameters
             cvi_address: str = None, cvi_network: str = None,
             macaddress: str = None, nodes: list = None):
    """
    Add a VLAN sub-interface to an existing interface.

    Args:
        name: Firewall name
        interface_id: Parent interface ID
        vlan_id: VLAN ID
        address: IP address (for single FW)
        network: Network in CIDR format
        zone: Optional zone name
        comment: Optional comment
        empty: Create empty VLAN without IP (can add IP later)
        cluster: Treat as cluster firewall (use CVI/NDI)
        cvi_address: Cluster Virtual IP (cluster only)
        cvi_network: Cluster network (cluster only)
        macaddress: MAC address for CVI (cluster only)
        nodes: List of node configs (cluster only)
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

    # Use explicit cluster flag instead of auto-detection
    is_cluster = cluster

    try:
        if is_cluster and not empty:
            # Cluster VLAN with CVI/NDI configuration
            if not cvi_address or not nodes:
                print("Error: Cluster VLANs require --cvi-address and --nodes parameters")
                print("       Or use --empty to create VLAN without IP configuration")
                return False
            # Add VLAN with CVI and NDI for cluster - only pass set parameters
            kwargs = {
                'interface_id': interface_id,
                'vlan_id': vlan_id,
                'cluster_virtual': cvi_address,
                'network_value': cvi_network or network,
                'nodes': nodes
            }
            if macaddress:
                kwargs['macaddress'] = macaddress
            if zone:
                kwargs['zone_ref'] = zone
            if comment:
                kwargs['comment'] = comment
            engine.physical_interface.add_layer3_vlan_cluster_interface(**kwargs)
            print(f"Successfully added VLAN {vlan_id} to interface {interface_id} with CVI {cvi_address}")
        elif empty:
            # Create empty VLAN (no IP) - works for both single and cluster firewalls
            # Note: Always use add_layer3_vlan_interface for empty VLANs since
            # add_layer3_vlan_cluster_interface doesn't support truly empty VLANs
            kwargs = {'interface_id': interface_id, 'vlan_id': vlan_id}
            if zone:
                kwargs['zone_ref'] = zone
            if comment:
                kwargs['comment'] = comment
            engine.physical_interface.add_layer3_vlan_interface(**kwargs)
            print(f"Successfully added empty VLAN {vlan_id} to interface {interface_id}")
        else:
            # Single firewall VLAN with IP
            if not address or not network:
                print("Error: Single firewall VLANs require --address and --network parameters")
                print("       Or use --empty to create VLAN without IP configuration")
                return False
            kwargs = {
                'interface_id': interface_id,
                'vlan_id': vlan_id,
                'address': address,
                'network_value': network
            }
            if zone:
                kwargs['zone_ref'] = zone
            if comment:
                kwargs['comment'] = comment
            engine.physical_interface.add_layer3_vlan_interface(**kwargs)
            print(f"Successfully added VLAN {vlan_id} to interface {interface_id} with IP {address}")

        return True

    except Exception as e:
        print(f"Error adding VLAN: {e}")
        return False


def add_ip_address(name: str, interface_id: int, address: str, network: str,
                   vlan_id: int = None, nodeid: int = None):
    """
    Add an IP address to an existing interface or VLAN.

    Args:
        name: Firewall name
        interface_id: Interface ID
        address: IP address to add
        network: Network in CIDR format
        vlan_id: Optional VLAN ID (if adding to a VLAN)
        nodeid: Node ID for cluster (if adding NDI address)
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

    try:
        # Get the interface
        iface = engine.physical_interface.get(interface_id)

        if vlan_id:
            # Find the VLAN interface
            for vlan in iface.vlan_interface:
                if str(vlan_id) in vlan.name:
                    vlan.add_ip_address(address, network)
                    print(f"Successfully added IP {address} to VLAN {vlan_id} on interface {interface_id}")
                    return True
            print(f"Error: VLAN {vlan_id} not found on interface {interface_id}")
            return False
        else:
            # Add to physical interface
            iface.add_ip_address(address, network)
            print(f"Successfully added IP {address} to interface {interface_id}")
            return True

    except Exception as e:
        print(f"Error adding IP address: {e}")
        return False


def delete_interface(name: str, interface_id: int, force: bool = False, yes: bool = False):
    """
    Delete an interface from a firewall.

    Args:
        name: Firewall name
        interface_id: Interface ID to delete
        force: Skip safety checks and force deletion
        yes: Skip confirmation prompts (use with caution)
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

    try:
        iface = engine.physical_interface.get(interface_id)
    except Exception as e:
        print(f"Error: Could not find interface {interface_id}: {e}")
        return False

    # Collect information about what will be deleted
    objects_to_delete = []
    warnings = []

    # Interface basic info
    objects_to_delete.append(f"Interface {interface_id}: {iface.name}")

    # Check for IP addresses on the interface
    try:
        addresses = list(iface.addresses)
        for addr in addresses:
            ip, network, nicid = addr
            objects_to_delete.append(f"  - IP Address: {ip} ({network})")
    except Exception:
        pass

    # Check for VLANs
    try:
        if hasattr(iface, 'has_vlan') and iface.has_vlan:
            for vlan in iface.vlan_interface:
                objects_to_delete.append(f"  - VLAN: {vlan.name}")
                # Get VLAN addresses
                try:
                    for vlan_addr in vlan.addresses:
                        vip, vnet, vnic = vlan_addr
                        objects_to_delete.append(f"      IP: {vip} ({vnet})")
                except Exception:
                    pass
    except Exception:
        pass

    # Check for routing entries that reference this interface
    try:
        interface_nicids = [str(interface_id)]
        # Also include VLAN nicids (e.g., "5.100" for interface 5, vlan 100)
        if hasattr(iface, 'has_vlan') and iface.has_vlan:
            for vlan in iface.vlan_interface:
                try:
                    # Extract VLAN ID from name like "VLAN 5.100"
                    vlan_nicid = vlan.name.split()[-1] if vlan.name else None
                    if vlan_nicid:
                        interface_nicids.append(vlan_nicid)
                except Exception:
                    pass

        for route in engine.routing.all():
            try:
                route_nicid = str(route.nicid) if hasattr(route, 'nicid') else None
                if route_nicid in interface_nicids:
                    objects_to_delete.append(f"  - Routing entry: {route.name} (nicid: {route_nicid})")
                    warnings.append(f"Routing entry '{route.name}' will be orphaned/deleted")
            except Exception:
                pass
    except Exception as e:
        warnings.append(f"Could not check routing entries: {e}")

    # Display what will be deleted
    print(f"\n{'=' * 60}")
    print(f"DELETE INTERFACE - {name}")
    print(f"{'=' * 60}")
    print("\nThe following objects will be PERMANENTLY DELETED:\n")
    for obj in objects_to_delete:
        print(f"  {obj}")

    if warnings:
        print(f"\n{'!' * 60}")
        print("WARNINGS:")
        for warning in warnings:
            print(f"  ⚠️  {warning}")
        print(f"{'!' * 60}")
        if not force:
            print("\nNote: Use --force to proceed despite warnings.")

    print(f"\n{'=' * 60}")

    # First confirmation
    if not yes:
        print("\n⚠️  This action is DESTRUCTIVE and CANNOT be undone!")
        confirm1 = input("\nAre you sure you want to delete this interface? [y/N]: ").strip().lower()
        if confirm1 != 'y':
            print("Deletion cancelled.")
            return False

        # Second confirmation with interface ID
        confirm2 = input(f"\nType the interface ID ({interface_id}) to confirm deletion: ").strip()
        if confirm2 != str(interface_id):
            print("Interface ID does not match. Deletion cancelled.")
            return False

    # Check for warnings and require --force if not using --yes
    if warnings and not force and not yes:
        print("\nWarnings detected. Use --force to proceed or resolve the warnings first.")
        return False

    # Perform deletion
    try:
        print(f"\nDeleting interface {interface_id}...")
        iface.delete()
        print(f"✓ Successfully deleted interface {interface_id}")

        # Note about policy upload
        print("\nNote: Run 'firewall.py upload --name {name}' to commit changes to the firewall.")
        return True
    except Exception as e:
        print(f"Error deleting interface: {e}")
        return False


def update_interface(name: str, interface_id: int, zone: str = None, comment: str = None,
                     mtu: int = None, lldp_mode: str = None, macaddress: str = None,
                     cvi_mode: str = None, qos_mode: str = None):
    """
    Update an existing interface's properties.

    Args:
        name: Firewall name
        interface_id: Interface ID
        zone: Zone name (use empty string to remove)
        comment: Comment text
        mtu: MTU value (400-65535)
        lldp_mode: LLDP mode (disabled, receive_only, send_and_receive, send_only)
        macaddress: MAC address (cluster CVI only)
        cvi_mode: CVI mode (packetdispatch, none) - cluster only
        qos_mode: QoS mode (no_qos, statistics_only, full_qos, dscp)
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

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

        # MTU (400-65535)
        if mtu is not None:
            if 400 <= mtu <= 65535:
                iface.mtu = mtu
                updated.append(f"mtu={mtu}")
            else:
                print(f"Warning: MTU must be between 400 and 65535, skipping")

        # LLDP Mode
        if lldp_mode is not None:
            valid_lldp = ['disabled', 'receive_only', 'send_and_receive', 'send_only']
            if lldp_mode in valid_lldp:
                iface.lldp_mode = lldp_mode
                updated.append(f"lldp_mode={lldp_mode}")
            else:
                print(f"Warning: Invalid LLDP mode '{lldp_mode}', valid: {valid_lldp}")

        # MAC Address (cluster only)
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
            print(f"Successfully updated interface {interface_id}: {', '.join(updated)}")
        else:
            print(f"No changes specified for interface {interface_id}")

        return True
    except Exception as e:
        print(f"Error updating interface: {e}")
        return False


def policy_refresh(name: str):
    """
    Refresh the policy on a firewall (quick update without full upload).

    Args:
        name: Firewall name
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

    try:
        print(f"Refreshing policy on {name}...")
        result = engine.refresh()
        print(f"Policy refresh initiated: {result}")
        return True
    except Exception as e:
        print(f"Error refreshing policy: {e}")
        return False


def policy_upload(name: str, policy: str = None):
    """
    Upload/commit a policy to a firewall.

    Args:
        name: Firewall name
        policy: Policy name (optional, uses current if not specified)
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

    try:
        print(f"Uploading policy to {name}...")
        if policy:
            result = engine.upload(policy=policy)
        else:
            result = engine.upload()
        print(f"Policy upload initiated: {result}")

        # Check for pending changes after upload
        try:
            changes = list(engine.pending_changes.all())
            if changes:
                print(f"Note: {len(changes)} pending change(s) remain after upload")
        except:
            pass

        return True
    except Exception as e:
        print(f"Error uploading policy: {e}")
        return False


def pending_changes(name: str, approve: bool = False, disapprove: bool = False):
    """
    View or manage pending changes on a firewall.

    Args:
        name: Firewall name
        approve: Approve all pending changes
        disapprove: Disapprove all pending changes
    """
    try:
        engine = Engine(name)
    except Exception as e:
        print(f"Error: Could not find firewall '{name}': {e}")
        return False

    try:
        changes_obj = engine.pending_changes
        changes = list(changes_obj.all())

        if approve:
            changes_obj.approve_all()
            print(f"Approved all pending changes on {name}")
            return True
        elif disapprove:
            changes_obj.disapprove_all()
            print(f"Disapproved all pending changes on {name}")
            return True
        else:
            print(f"\nPending Changes for {name}:")
            print("=" * 50)
            if changes:
                for i, change in enumerate(changes, 1):
                    print(f"  {i}. {change}")
            else:
                print("  No pending changes")
            return True
    except Exception as e:
        print(f"Error with pending changes: {e}")
        return False


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
        """
    )

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
    add_vlan_parser.add_argument('--vlan-id', '-V', type=int, required=True, help='VLAN ID')
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
    del_iface_parser.add_argument('--force', '-f', action='store_true',
                                  help='Force deletion even with routing warnings')
    del_iface_parser.add_argument('--yes', '-y', action='store_true',
                                  help='Skip confirmation prompts (dangerous)')

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

    # Connect to SMC
    try:
        connect()
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    try:
        # Execute command
        if args.command == 'list':
            list_firewalls(args.verbose)

        elif args.command == 'show':
            show_firewall(args.name, args.section)

        elif args.command == 'interfaces':
            list_interfaces(args.name, args.verbose)

        elif args.command == 'add-interface':
            import json
            nodes = json.loads(args.nodes) if args.nodes else None
            add_interface(
                args.name, args.interface_id, args.address, args.network,
                args.zone, args.comment, args.empty, args.cluster,
                args.cvi_address, args.cvi_network, args.macaddress, nodes
            )

        elif args.command == 'add-vlan':
            import json
            nodes = json.loads(args.nodes) if args.nodes else None
            add_vlan(
                args.name, args.interface_id, args.vlan_id, args.address,
                args.network, args.zone, args.comment, args.empty, args.cluster,
                args.cvi_address, args.cvi_network, args.macaddress, nodes
            )

        elif args.command == 'add-ip':
            add_ip_address(
                args.name, args.interface_id, args.address, args.network,
                args.vlan_id, args.nodeid
            )

        elif args.command == 'delete-interface':
            delete_interface(args.name, args.interface_id, args.force, args.yes)

        elif args.command == 'update-interface':
            update_interface(
                args.name, args.interface_id, args.zone, args.comment,
                args.mtu, getattr(args, 'lldp_mode', None), args.macaddress,
                getattr(args, 'cvi_mode', None), getattr(args, 'qos_mode', None)
            )

        elif args.command == 'refresh':
            policy_refresh(args.name)

        elif args.command == 'upload':
            policy_upload(args.name, args.policy)

        elif args.command == 'pending':
            pending_changes(args.name, args.approve, args.disapprove)

    finally:
        disconnect()


if __name__ == '__main__':
    main()
