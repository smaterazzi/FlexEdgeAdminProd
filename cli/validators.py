"""
Input validation utilities for FlexEdgeAdmin.
Provides validation for IP addresses, CIDR networks, MAC addresses,
VLAN IDs, MTU values, and interface IDs.
"""

import ipaddress
import json
import re


def validate_ip_address(ip: str) -> str:
    """
    Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address string to validate.

    Returns:
        Normalized IP address string.

    Raises:
        ValueError: If the IP address is invalid.
    """
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"Invalid IP address: '{ip}'")


def validate_cidr(cidr: str) -> str:
    """
    Validate a CIDR network notation (e.g. '10.0.0.0/24').

    Args:
        cidr: Network in CIDR notation.

    Returns:
        Normalized CIDR string.

    Raises:
        ValueError: If the CIDR notation is invalid.
    """
    try:
        return str(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        raise ValueError(f"Invalid CIDR network: '{cidr}'")


def validate_mac_address(mac: str) -> str:
    """
    Validate a MAC address.

    Accepts formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    (case-insensitive).

    Args:
        mac: MAC address string.

    Returns:
        Normalized lowercase colon-separated MAC address.

    Raises:
        ValueError: If the MAC address format is invalid.
    """
    normalized = mac.replace('-', ':').lower()
    pattern = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
    if not pattern.match(normalized):
        raise ValueError(
            f"Invalid MAC address: '{mac}' (expected format: XX:XX:XX:XX:XX:XX)"
        )
    return normalized


def validate_vlan_id(vlan_id: int) -> int:
    """
    Validate a VLAN ID (valid range: 1-4094).

    Args:
        vlan_id: VLAN identifier.

    Returns:
        The validated VLAN ID.

    Raises:
        ValueError: If the VLAN ID is out of range.
    """
    if not isinstance(vlan_id, int) or vlan_id < 1 or vlan_id > 4094:
        raise ValueError(f"Invalid VLAN ID: {vlan_id} (must be 1-4094)")
    return vlan_id


def validate_mtu(mtu: int) -> int:
    """
    Validate an MTU value (valid range: 400-65535).

    Args:
        mtu: Maximum Transmission Unit value.

    Returns:
        The validated MTU value.

    Raises:
        ValueError: If the MTU is out of range.
    """
    if not isinstance(mtu, int) or mtu < 400 or mtu > 65535:
        raise ValueError(f"Invalid MTU: {mtu} (must be 400-65535)")
    return mtu


def validate_interface_id(interface_id: int) -> int:
    """
    Validate an interface ID (non-negative integer).

    Args:
        interface_id: Interface identifier.

    Returns:
        The validated interface ID.

    Raises:
        ValueError: If the interface ID is negative.
    """
    if not isinstance(interface_id, int) or interface_id < 0:
        raise ValueError(
            f"Invalid interface ID: {interface_id} (must be non-negative integer)"
        )
    return interface_id


def validate_json_nodes(nodes_str: str) -> list:
    """
    Validate and parse a JSON string representing node configurations.

    Expected format: '[{"address":"x.x.x.x","network_value":"x.x.x.x/x","nodeid":1}]'

    Args:
        nodes_str: JSON string of node configurations.

    Returns:
        Parsed list of node configuration dicts.

    Raises:
        ValueError: If JSON is malformed or structure is invalid.
    """
    try:
        nodes = json.loads(nodes_str)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Invalid JSON for --nodes: {e}\n"
            f"Expected format: '[{{\"address\":\"x.x.x.x\",\"network_value\":\"x.x.x.x/x\",\"nodeid\":1}}]'"
        )

    if not isinstance(nodes, list):
        raise ValueError("--nodes must be a JSON array")

    for i, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise ValueError(f"Node {i} must be a JSON object")
        if 'address' not in node:
            raise ValueError(f"Node {i} missing required field 'address'")
        if 'network_value' not in node:
            raise ValueError(f"Node {i} missing required field 'network_value'")
        if 'nodeid' not in node:
            raise ValueError(f"Node {i} missing required field 'nodeid'")

        # Validate the address and network within each node
        validate_ip_address(node['address'])
        validate_cidr(node['network_value'])

    return nodes
