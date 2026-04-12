# inquiry.py - SMC Object Query Tool

## Overview

The `inquiry.py` script allows you to query and inspect SMC objects by type and name, with options for detailed configuration views.

## Quick Start

```bash
# List available object types
python inquiry.py --list-types

# Query all hosts
python inquiry.py --type host

# Query firewall with details
python inquiry.py --type firewall --name MyFirewall --details
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--type` | `-t` | Object type to query (required) |
| `--name` | `-n` | Filter by name (partial match) |
| `--limit` | `-l` | Maximum number of results |
| `--verbose` | `-v` | Show basic detailed info |
| `--details` | `-d` | Show FULL configuration details |
| `--list-types` | | List all available object types |

## Supported Object Types

### Network Elements

| Type | Description |
|------|-------------|
| `host` | Single IP address objects |
| `network` | Network/subnet objects |
| `address_range` | IP address ranges |
| `router` | Router objects |
| `domain_name` | DNS domain names |
| `zone` | Security zones |
| `group` | Network element groups |

### Services

| Type | Description |
|------|-------------|
| `tcp_service` | TCP port services |
| `udp_service` | UDP port services |
| `icmp_service` | ICMP services |
| `ip_service` | IP protocol services |
| `service_group` | Service groups |

### Engines

| Type | Description |
|------|-------------|
| `firewall` | Layer 3 single firewalls |
| `firewall_cluster` | Firewall clusters |
| `layer2_firewall` | Layer 2 firewalls |
| `ips` | IPS engines |
| `master_engine` | Master engines |

## Usage Examples

### List All Hosts

```bash
python inquiry.py --type host
```

Output:
```
Found 5 object(s):
==================================================
  Name: webserver01
  Type: host

  Name: dbserver01
  Type: host
...
```

### Search by Name (Partial Match)

```bash
python inquiry.py --type host --name "192.168"
```

### Verbose Output

```bash
python inquiry.py --type host --name webserver01 --verbose
```

Output:
```
  Name: webserver01
  Type: host
  Address: 192.168.1.10
  Href: https://smc.example.com:8082/6.10/elements/host/12345
```

### Full Details (Firewalls)

```bash
python inquiry.py --type firewall --name MyFirewall --details
```

Output:
```
============================================================
DETAILED CONFIGURATION: MyFirewall
============================================================

BASIC INFORMATION
-----------------
  Name: MyFirewall
  Type: single_fw
  Href: https://smc.example.com:8082/6.10/elements/single_fw/47779

NODES
-----
  - MyFirewall node 1
      Node ID: 1

INTERFACES
----------
  Interface: Interface 0
    ID: 0
    Addresses: [('192.168.100.201', '192.168.100.0/22', '0')]
...
```

### Limit Results

```bash
python inquiry.py --type tcp_service --limit 10
```

### Show Group Members

```bash
python inquiry.py --type group --name "Web Servers" --details
```

Output includes all group members with their types.

## Detail Levels

| Flag | Information Shown |
|------|-------------------|
| (none) | Name and type only |
| `--verbose` | Name, type, address/network, href |
| `--details` | Full configuration (type-specific) |

### Details by Object Type

| Type | Details Shown |
|------|---------------|
| Firewall/Engine | Nodes, interfaces, routing, policy, pending changes |
| Host | Address, IPv6, secondary addresses |
| Network | IPv4/IPv6 network CIDR |
| Address Range | IP range |
| Group | All group members with types |
| Services | Ports, ICMP type/code, protocol number |
| Other | All raw data attributes |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Connection failed |
| 2 | Invalid arguments |
