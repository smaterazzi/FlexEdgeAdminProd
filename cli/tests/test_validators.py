"""Tests for the validators module."""

import unittest
import sys
import os

# Add parent directory to path so we can import validators
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validators import (
    validate_ip_address,
    validate_cidr,
    validate_mac_address,
    validate_vlan_id,
    validate_mtu,
    validate_interface_id,
    validate_json_nodes,
)


class TestValidateIPAddress(unittest.TestCase):
    """Tests for validate_ip_address."""

    def test_valid_ipv4(self):
        self.assertEqual(validate_ip_address("10.0.0.1"), "10.0.0.1")
        self.assertEqual(validate_ip_address("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip_address("0.0.0.0"), "0.0.0.0")
        self.assertEqual(validate_ip_address("255.255.255.255"), "255.255.255.255")

    def test_valid_ipv6(self):
        self.assertEqual(validate_ip_address("::1"), "::1")
        self.assertEqual(
            validate_ip_address("2001:db8::1"), "2001:db8::1"
        )
        self.assertEqual(
            validate_ip_address("fe80::1"), "fe80::1"
        )

    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            validate_ip_address("not_an_ip")
        with self.assertRaises(ValueError):
            validate_ip_address("256.1.1.1")
        with self.assertRaises(ValueError):
            validate_ip_address("10.0.0")
        with self.assertRaises(ValueError):
            validate_ip_address("")
        with self.assertRaises(ValueError):
            validate_ip_address("10.0.0.1/24")

    def test_error_message_contains_input(self):
        try:
            validate_ip_address("bad_ip")
        except ValueError as e:
            self.assertIn("bad_ip", str(e))


class TestValidateCIDR(unittest.TestCase):
    """Tests for validate_cidr."""

    def test_valid_cidr(self):
        self.assertEqual(validate_cidr("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(validate_cidr("192.168.1.0/24"), "192.168.1.0/24")
        self.assertEqual(validate_cidr("0.0.0.0/0"), "0.0.0.0/0")
        self.assertEqual(validate_cidr("10.0.0.0/8"), "10.0.0.0/8")

    def test_host_bits_set_normalized(self):
        # strict=False allows host bits, normalizes to network address
        self.assertEqual(validate_cidr("10.0.0.1/24"), "10.0.0.0/24")
        self.assertEqual(validate_cidr("192.168.1.100/16"), "192.168.0.0/16")

    def test_valid_ipv6_cidr(self):
        self.assertEqual(validate_cidr("2001:db8::/32"), "2001:db8::/32")
        self.assertEqual(validate_cidr("::1/128"), "::1/128")

    def test_bare_ip_treated_as_host_network(self):
        # Python's ipaddress treats bare IPs as /32 host networks
        self.assertEqual(validate_cidr("10.0.0.0"), "10.0.0.0/32")

    def test_invalid_cidr(self):
        with self.assertRaises(ValueError):
            validate_cidr("not_a_network")
        with self.assertRaises(ValueError):
            validate_cidr("10.0.0.0/33")
        with self.assertRaises(ValueError):
            validate_cidr("")

    def test_error_message_contains_input(self):
        try:
            validate_cidr("bad_cidr")
        except ValueError as e:
            self.assertIn("bad_cidr", str(e))


class TestValidateMACAddress(unittest.TestCase):
    """Tests for validate_mac_address."""

    def test_valid_colon_separated(self):
        self.assertEqual(
            validate_mac_address("02:02:02:02:02:02"), "02:02:02:02:02:02"
        )
        self.assertEqual(
            validate_mac_address("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff"
        )
        self.assertEqual(
            validate_mac_address("00:00:00:00:00:00"), "00:00:00:00:00:00"
        )

    def test_valid_dash_separated(self):
        self.assertEqual(
            validate_mac_address("02-02-02-02-02-02"), "02:02:02:02:02:02"
        )
        self.assertEqual(
            validate_mac_address("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff"
        )

    def test_case_insensitive(self):
        self.assertEqual(
            validate_mac_address("aA:bB:cC:dD:eE:fF"), "aa:bb:cc:dd:ee:ff"
        )

    def test_invalid_mac(self):
        with self.assertRaises(ValueError):
            validate_mac_address("not_a_mac")
        with self.assertRaises(ValueError):
            validate_mac_address("02:02:02:02:02")  # too short
        with self.assertRaises(ValueError):
            validate_mac_address("02:02:02:02:02:02:02")  # too long
        with self.assertRaises(ValueError):
            validate_mac_address("GG:HH:II:JJ:KK:LL")  # invalid hex
        with self.assertRaises(ValueError):
            validate_mac_address("")

    def test_error_message_contains_input(self):
        try:
            validate_mac_address("bad_mac")
        except ValueError as e:
            self.assertIn("bad_mac", str(e))


class TestValidateVLANID(unittest.TestCase):
    """Tests for validate_vlan_id."""

    def test_valid_range(self):
        self.assertEqual(validate_vlan_id(1), 1)
        self.assertEqual(validate_vlan_id(100), 100)
        self.assertEqual(validate_vlan_id(4094), 4094)

    def test_boundary_values(self):
        self.assertEqual(validate_vlan_id(1), 1)
        self.assertEqual(validate_vlan_id(4094), 4094)

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            validate_vlan_id(0)
        with self.assertRaises(ValueError):
            validate_vlan_id(-1)
        with self.assertRaises(ValueError):
            validate_vlan_id(4095)
        with self.assertRaises(ValueError):
            validate_vlan_id(10000)

    def test_error_message_contains_value(self):
        try:
            validate_vlan_id(9999)
        except ValueError as e:
            self.assertIn("9999", str(e))


class TestValidateMTU(unittest.TestCase):
    """Tests for validate_mtu."""

    def test_valid_range(self):
        self.assertEqual(validate_mtu(400), 400)
        self.assertEqual(validate_mtu(1500), 1500)
        self.assertEqual(validate_mtu(9000), 9000)
        self.assertEqual(validate_mtu(65535), 65535)

    def test_boundary_values(self):
        self.assertEqual(validate_mtu(400), 400)
        self.assertEqual(validate_mtu(65535), 65535)

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            validate_mtu(399)
        with self.assertRaises(ValueError):
            validate_mtu(0)
        with self.assertRaises(ValueError):
            validate_mtu(-1)
        with self.assertRaises(ValueError):
            validate_mtu(65536)

    def test_error_message_contains_value(self):
        try:
            validate_mtu(99)
        except ValueError as e:
            self.assertIn("99", str(e))


class TestValidateInterfaceID(unittest.TestCase):
    """Tests for validate_interface_id."""

    def test_valid_ids(self):
        self.assertEqual(validate_interface_id(0), 0)
        self.assertEqual(validate_interface_id(1), 1)
        self.assertEqual(validate_interface_id(100), 100)

    def test_invalid_ids(self):
        with self.assertRaises(ValueError):
            validate_interface_id(-1)
        with self.assertRaises(ValueError):
            validate_interface_id(-100)


class TestValidateJSONNodes(unittest.TestCase):
    """Tests for validate_json_nodes."""

    def test_valid_single_node(self):
        nodes_str = '[{"address":"10.0.0.2","network_value":"10.0.0.0/24","nodeid":1}]'
        result = validate_json_nodes(nodes_str)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["address"], "10.0.0.2")

    def test_valid_multi_node(self):
        nodes_str = (
            '[{"address":"10.0.0.2","network_value":"10.0.0.0/24","nodeid":1},'
            '{"address":"10.0.0.3","network_value":"10.0.0.0/24","nodeid":2}]'
        )
        result = validate_json_nodes(nodes_str)
        self.assertEqual(len(result), 2)

    def test_invalid_json(self):
        with self.assertRaises(ValueError):
            validate_json_nodes("not json")
        with self.assertRaises(ValueError):
            validate_json_nodes("{bad json}")

    def test_not_array(self):
        with self.assertRaises(ValueError):
            validate_json_nodes('{"address":"10.0.0.1"}')

    def test_missing_address(self):
        with self.assertRaises(ValueError):
            validate_json_nodes('[{"network_value":"10.0.0.0/24","nodeid":1}]')

    def test_missing_network_value(self):
        with self.assertRaises(ValueError):
            validate_json_nodes('[{"address":"10.0.0.1","nodeid":1}]')

    def test_missing_nodeid(self):
        with self.assertRaises(ValueError):
            validate_json_nodes('[{"address":"10.0.0.1","network_value":"10.0.0.0/24"}]')

    def test_invalid_address_in_node(self):
        with self.assertRaises(ValueError):
            validate_json_nodes('[{"address":"bad_ip","network_value":"10.0.0.0/24","nodeid":1}]')

    def test_invalid_network_in_node(self):
        with self.assertRaises(ValueError):
            validate_json_nodes('[{"address":"10.0.0.1","network_value":"bad_cidr","nodeid":1}]')


if __name__ == '__main__':
    unittest.main()
