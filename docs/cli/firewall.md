# firewall.py - Firewall Management Tool

## Overview

The `firewall.py` script provides comprehensive management of Forcepoint NGFW firewalls, including interface configuration, VLAN management, and policy deployment.

## Quick Start

```bash
# List all firewalls
python firewall.py list

# Show firewall details
python firewall.py show --name MyFirewall

# List interfaces
python firewall.py interfaces --name MyFirewall --verbose

# Refresh policy
python firewall.py refresh --name MyFirewall
```

## Commands

### list

List all firewalls in the connected domain.

```bash
python firewall.py list
python firewall.py list --verbose
```

**Options:**
- `--verbose, -v`: Show additional details (type, href)

**Output:**
```
[Single Firewalls]
----------------------------------------------------------------------
  MyFirewall

[Firewall Clusters]
----------------------------------------------------------------------
  CLUSTER01

Total: 2 firewall(s)
```

---

### show

Display detailed information about a firewall.

```bash
python firewall.py show --name MyFirewall
python firewall.py show --name MyFirewall --section interfaces
```

**Options:**
- `--name, -n`: Firewall name (required)
- `--section, -s`: Section to display: `basic`, `nodes`, `interfaces`, `routing`, `policy`, `all`

**Sections:**
| Section | Information |
|---------|-------------|
| `basic` | Name, type, location, log server |
| `nodes` | Cluster nodes and IDs |
| `interfaces` | Interface summary with addresses |
| `routing` | Routing table entries |
| `policy` | Installed policy and pending changes |

---

### interfaces

List all interfaces with detailed information.

```bash
python firewall.py interfaces --name MyFirewall
python firewall.py interfaces --name MyFirewall --verbose
```

**Options:**
- `--name, -n`: Firewall name (required)
- `--verbose, -v`: Show zones, flags, VLANs, CVI/NDI details

**Output (verbose):**
```
[Interface 0] Interface 0
--------------------------------------------------
  Type: Layer3PhysicalInterface
  Zone: https://smc.example.com/6.10/elements/interface_zone/123
  Flags: Primary MGT, Outgoing
  Addresses:
    - IP: 192.168.100.1, Network: 192.168.100.0/24, NIC ID: 0
  VLANs:
    - VLAN 0.100
        IP: 10.0.100.1, Network: 10.0.100.0/24, NIC ID: 0.100
```

---

### add-interface

Add a Layer 3 interface to a firewall. Supports two workflows:

1. **One-shot creation** - Create interface with IP configuration in one command
2. **Step-by-step** - Create empty interface first, then configure with `update-interface` and `add-ip`

**Single Firewall (with IP):**
```bash
python firewall.py add-interface --name FW01 \
    --interface-id 5 \
    --address 10.0.0.1 \
    --network 10.0.0.0/24 \
    --zone DMZ
```

**Single Firewall (empty, configure later):**
```bash
# Step 1: Create empty interface
python firewall.py add-interface --name FW01 --interface-id 5 --empty

# Step 2: Configure properties
python firewall.py update-interface --name FW01 --interface-id 5 \
    --zone DMZ --mtu 1500 --lldp-mode send_and_receive

# Step 3: Add IP address
python firewall.py add-ip --name FW01 --interface-id 5 \
    --address 10.0.0.1 --network 10.0.0.0/24
```

**Cluster (with CVI and NDI):**
```bash
python firewall.py add-interface --name CLUSTER01 \
    --interface-id 5 --cluster \
    --cvi-address 10.0.0.1 \
    --cvi-network 10.0.0.0/24 \
    --macaddress 02:02:02:02:02:02 \
    --nodes '[{"address":"10.0.0.2","network_value":"10.0.0.0/24","nodeid":1},{"address":"10.0.0.3","network_value":"10.0.0.0/24","nodeid":2}]'
```

**Cluster (empty):**
```bash
python firewall.py add-interface --name CLUSTER01 --interface-id 5 --cluster --empty --zone Internal
```

**Options:**
| Option | Description |
|--------|-------------|
| `--name, -n` | Firewall name (required) |
| `--interface-id, -i` | Interface ID number (required) |
| `--empty, -e` | Create empty interface without IP (configure later) |
| `--cluster, -C` | Treat as cluster firewall (use CVI/NDI configuration) |
| `--address, -a` | IP address (required for single FW unless --empty) |
| `--network` | Network in CIDR format (required unless --empty) |
| `--zone, -z` | Zone name |
| `--comment, -c` | Comment |
| `--cvi-address` | Cluster Virtual IP (requires --cluster) |
| `--cvi-network` | Cluster network (requires --cluster) |
| `--macaddress` | MAC for CVI (requires --cluster) |
| `--nodes` | Node configs as JSON (requires --cluster) |

---

### add-vlan

Add a VLAN sub-interface to an existing interface. Supports the same two workflows as `add-interface`.

**Single Firewall (with IP):**

```bash
python firewall.py add-vlan --name FW01 \
    --interface-id 1 \
    --vlan-id 100 \
    --address 192.168.100.1 \
    --network 192.168.100.0/24 \
    --zone VLAN100
```

**Single Firewall (empty, configure later):**

```bash
# Step 1: Create empty VLAN
python firewall.py add-vlan --name FW01 --interface-id 1 --vlan-id 100 --empty --zone VLAN100

# Step 2: Add IP address later
python firewall.py add-ip --name FW01 --interface-id 1 --vlan-id 100 \
    --address 192.168.100.1 --network 192.168.100.0/24
```

**Cluster (with CVI/NDI):**

```bash
python firewall.py add-vlan --name CLUSTER01 \
    --interface-id 1 \
    --vlan-id 100 --cluster \
    --cvi-address 192.168.100.1 \
    --cvi-network 192.168.100.0/24 \
    --macaddress 02:02:02:02:02:03 \
    --nodes '[{"address":"192.168.100.2","network_value":"192.168.100.0/24","nodeid":1}]'
```

**Cluster (empty, configure later):**

```bash
# Create empty VLAN on cluster - can add CVI/NDI later
python firewall.py add-vlan --name CLUSTER01 --interface-id 1 --vlan-id 100 --cluster --empty --zone VLAN100
```

**Options:**

| Option | Description |
|--------|-------------|
| `--name, -n` | Firewall name (required) |
| `--interface-id, -i` | Parent interface ID (required) |
| `--vlan-id, -V` | VLAN ID (required) |
| `--empty, -e` | Create empty VLAN without IP (configure later) |
| `--cluster, -C` | Treat as cluster firewall (use CVI/NDI configuration) |
| `--address, -a` | IP address (required for single FW unless --empty) |
| `--network` | Network in CIDR format (required unless --empty) |
| `--zone, -z` | Zone name |
| `--comment, -c` | Comment |
| `--cvi-address` | Cluster Virtual IP (requires --cluster) |
| `--cvi-network` | Cluster network (requires --cluster) |
| `--macaddress` | MAC for CVI (requires --cluster) |
| `--nodes` | Node configs as JSON (requires --cluster) |

---

### add-ip

Add an IP address to an existing interface or VLAN.

```bash
# Add to physical interface
python firewall.py add-ip --name FW01 \
    --interface-id 1 \
    --address 10.0.1.1 \
    --network 10.0.1.0/24

# Add to VLAN
python firewall.py add-ip --name FW01 \
    --interface-id 1 \
    --vlan-id 100 \
    --address 10.0.100.1 \
    --network 10.0.100.0/24
```

**Options:**
| Option | Description |
|--------|-------------|
| `--name, -n` | Firewall name (required) |
| `--interface-id, -i` | Interface ID (required) |
| `--address, -a` | IP address (required) |
| `--network` | Network in CIDR format (required) |
| `--vlan-id, -V` | VLAN ID (if adding to VLAN) |
| `--nodeid` | Node ID for cluster NDI |

---

### delete-interface

Delete an interface from a firewall. This command includes safety features:

- Shows all objects that will be deleted (IPs, VLANs, routing entries)
- Requires double confirmation (yes + type interface ID)
- Warns about associated routing entries that may cause commit failures

```bash
# Interactive deletion with confirmation prompts
python firewall.py delete-interface --name FW01 --interface-id 5

# Force deletion despite routing warnings
python firewall.py delete-interface --name FW01 --interface-id 5 --force

# Skip all confirmations (dangerous - use in scripts only)
python firewall.py delete-interface --name FW01 --interface-id 5 --yes --force
```

**Options:**

| Option | Description |
|--------|-------------|
| `--name, -n` | Firewall name (required) |
| `--interface-id, -i` | Interface ID to delete (required) |
| `--force, -f` | Force deletion even with routing warnings |
| `--yes, -y` | Skip confirmation prompts (dangerous) |

**Example output:**

```text
============================================================
DELETE INTERFACE - FW01
============================================================

The following objects will be PERMANENTLY DELETED:

  Interface 5: Interface 5
    - IP Address: 10.0.0.1 (10.0.0.0/24)
    - VLAN: VLAN 5.100
        IP: 10.0.100.1 (10.0.100.0/24)
    - Routing entry: Interface 5 (nicid: 5)

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
WARNINGS:
  ⚠️  Routing entry 'Interface 5' will be orphaned/deleted
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

============================================================

⚠️  This action is DESTRUCTIVE and CANNOT be undone!

Are you sure you want to delete this interface? [y/N]: y

Type the interface ID (5) to confirm deletion: 5

Deleting interface 5...
✓ Successfully deleted interface 5

Note: Run 'firewall.py upload --name FW01' to commit changes to the firewall.
```

⚠️ **Warning:** This is destructive and cannot be undone. Always run `upload` after deletion to commit changes.

---

### update-interface

Update an existing interface's properties. Use this to configure interfaces created with `--empty` or to modify existing interfaces.

**Basic update:**

```bash
python firewall.py update-interface --name FW01 \
    --interface-id 1 \
    --zone NewZone \
    --comment "Updated interface"
```

**Configure MTU and LLDP:**

```bash
python firewall.py update-interface --name FW01 \
    --interface-id 1 \
    --mtu 9000 \
    --lldp-mode send_and_receive
```

**Configure QoS:**

```bash
python firewall.py update-interface --name FW01 \
    --interface-id 1 \
    --qos-mode full_qos
```

**Cluster-specific (CVI mode and MAC):**

```bash
python firewall.py update-interface --name CLUSTER01 \
    --interface-id 1 \
    --cvi-mode packetdispatch \
    --macaddress 02:02:02:02:02:05
```

**Remove zone:**

```bash
python firewall.py update-interface --name FW01 --interface-id 1 --zone ""
```

**Options:**

| Option | Description |
|--------|-------------|
| `--name, -n` | Firewall name (required) |
| `--interface-id, -i` | Interface ID (required) |
| `--zone, -z` | Zone name (empty string to remove) |
| `--comment, -c` | Comment text |
| `--mtu` | MTU value (400-65535) |
| `--lldp-mode` | LLDP mode: `disabled`, `receive_only`, `send_and_receive`, `send_only` |
| `--macaddress` | MAC address (cluster CVI only) |
| `--cvi-mode` | CVI mode: `packetdispatch`, `none` (cluster only) |
| `--qos-mode` | QoS mode: `no_qos`, `statistics_only`, `full_qos`, `dscp` |

**Modifiable Properties:**

| Property | Single FW | Cluster | Notes |
|----------|-----------|---------|-------|
| Zone | ✓ | ✓ | Use empty string to remove |
| Comment | ✓ | ✓ | |
| MTU | ✓ | ✓ | Range: 400-65535, applies to VLANs |
| LLDP Mode | ✓ | ✓ | Requires SMC API 6.6+ |
| MAC Address | ✗ | ✓ | For CVI packet dispatch |
| CVI Mode | ✗ | ✓ | `packetdispatch` or `none` |
| QoS Mode | ✓ | ✓ | Requires engine support |

---

### refresh

Perform a quick policy refresh on the firewall.

```bash
python firewall.py refresh --name MyFirewall
```

**Options:**
- `--name, -n`: Firewall name (required)

Use this for minor updates. For full policy deployment, use `upload`.

---

### upload

Upload/commit a full policy to the firewall.

```bash
# Upload current policy
python firewall.py upload --name MyFirewall

# Upload specific policy
python firewall.py upload --name MyFirewall --policy "New Policy"
```

**Options:**
- `--name, -n`: Firewall name (required)
- `--policy, -p`: Policy name (optional, uses current if not specified)

---

### pending

View or manage pending changes on a firewall.

```bash
# View pending changes
python firewall.py pending --name MyFirewall

# Approve all changes
python firewall.py pending --name MyFirewall --approve

# Disapprove all changes
python firewall.py pending --name MyFirewall --disapprove
```

**Options:**
| Option | Description |
|--------|-------------|
| `--name, -n` | Firewall name (required) |
| `--approve` | Approve all pending changes |
| `--disapprove` | Disapprove all pending changes |

---

## Cluster-Specific Concepts

### CVI (Cluster Virtual Interface)

The shared IP address used for operative traffic across all cluster nodes.

- Specified with `--cvi-address` and `--cvi-network`
- Requires `--macaddress` for packet dispatch load balancing

### NDI (Node Dedicated Interface)

Unique IP addresses for each cluster node, used for:
- Engine-initiated communications
- Management traffic
- Inter-node heartbeat

Specified via `--nodes` JSON array:
```json
[
  {"address": "10.0.0.2", "network_value": "10.0.0.0/24", "nodeid": 1},
  {"address": "10.0.0.3", "network_value": "10.0.0.0/24", "nodeid": 2}
]
```

### MAC Address

Required for CVI when using packet dispatch load balancing.
- Format: `02:xx:xx:xx:xx:xx`
- Must be unique per interface

---

## Workflow Example

### Adding a New VLAN to a Cluster

```bash
# 1. Check current interfaces
python firewall.py interfaces --name CLUSTER01 --verbose

# 2. Add VLAN with CVI and NDI
python firewall.py add-vlan --name CLUSTER01 \
    --interface-id 1 \
    --vlan-id 200 \
    --cvi-address 172.16.200.1 \
    --cvi-network 172.16.200.0/24 \
    --macaddress 02:02:02:02:02:10 \
    --nodes '[{"address":"172.16.200.2","network_value":"172.16.200.0/24","nodeid":1}]' \
    --zone VLAN200

# 3. Verify the change
python firewall.py interfaces --name CLUSTER01 --verbose

# 4. Check pending changes
python firewall.py pending --name CLUSTER01

# 5. Upload policy to apply changes
python firewall.py upload --name CLUSTER01
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Connection or execution failed |
