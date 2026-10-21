#!/usr/bin/env python3
"""
NetSight (Extreme Site Engine / XIQ-SE) Inquiry Tool

Read-only client for the Site Engine GraphQL Northbound Interface (NBI).
Lists the switches NetSight manages, their ports, VLANs and LLDP neighbours,
and exposes the raw schema for exploration.

Credentials are read from config/xiqse.env (gitignored) or the environment:

    XIQSE_HOST=10.0.0.190
    XIQSE_PORT=8443                       # optional
    XIQSE_CLIENT_ID=...                   # Administration -> Client API Access
    XIQSE_CLIENT_SECRET=...
    XIQSE_CERT_SHA256=AA:BB:...           # pin a self-signed server cert
    XIQSE_CA_BUNDLE=/path/ca.pem          # or verify against a CA

Verified against Site Engine 25.08 (2026-10-21): the token endpoint takes
HTTP Basic (client_id:client_secret); /nbi/graphql takes Bearer.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path so `shared` is importable
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from shared.netsight_client import (  # noqa: E402
    NetSightClient, NetSightError, NetSightTlsError, NetSightTransportError,
    portlist_from_hex, tname,
)

DEFAULT_ENV_FILE = Path(__file__).resolve().parent.parent / "config" / "xiqse.env"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_env_file(path):
    """Load KEY=VALUE lines into os.environ without overriding existing vars."""
    path = Path(path)
    if not path.is_file():
        return False
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value
    return True


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def client_from_env(insecure=False):
    """Build a NetSightClient from XIQSE_* env vars (after load_env_file)."""
    missing = [k for k in ("XIQSE_HOST", "XIQSE_CLIENT_ID", "XIQSE_CLIENT_SECRET")
               if not os.environ.get(k)]
    if missing:
        raise NetSightError(
            f"Missing {', '.join(missing)} — set them in {DEFAULT_ENV_FILE} "
            "or the environment")
    if insecure and not os.environ.get("XIQSE_CERT_SHA256"):
        print("WARNING: TLS verification disabled — the client secret is "
              "sent to whoever answers on this address.", file=sys.stderr)
    return NetSightClient(
        host=os.environ["XIQSE_HOST"],
        port=os.environ.get("XIQSE_PORT", "8443"),
        client_id=os.environ["XIQSE_CLIENT_ID"],
        client_secret=os.environ["XIQSE_CLIENT_SECRET"],
        cert_sha256=os.environ.get("XIQSE_CERT_SHA256") or None,
        ca_bundle=os.environ.get("XIQSE_CA_BUNDLE") or None,
        insecure=insecure,
    )


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_table(rows, columns):
    """rows: list of dicts; columns: list of (key, header)."""
    if not rows:
        print("(no results)")
        return
    cells = [[str(r.get(k, "") if r.get(k) is not None else "") for k, _ in columns]
             for r in rows]
    widths = [max(len(h), *(len(c[i]) for c in cells)) for i, (_, h) in enumerate(columns)]
    print("  ".join(h.ljust(w) for (_, h), w in zip(columns, widths)))
    print("  ".join("-" * w for w in widths))
    for c in cells:
        print("  ".join(v.ljust(w) for v, w in zip(c, widths)))


def emit(args, payload, table_fn):
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        table_fn()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_connect(client, args):
    res = client.connect_check()
    if "roots" in res and not res["roots"] and res.get("error"):
        raise NetSightError(res["error"])
    sections = res["roots"]
    payload = {"server": client.base, "token": "ok", "sections": sections}
    emit(args, payload, lambda: (
        print(f"Connected to {client.base} — token OK"),
        print("Section access:"),
        [print(f"  {k:16} {v}") for k, v in sections.items()],
    ))
    return 0 if res["ok"] else 1


def cmd_devices(client, args):
    devs = client.devices()
    if args.family:
        devs = [d for d in devs if args.family.lower() in (d.get("deviceDisplayFamily") or "").lower()]
    if args.down:
        devs = [d for d in devs if not d.get("up")]
    devs.sort(key=lambda d: tuple(int(o) for o in (d.get("ip") or "0.0.0.0").split(".")))
    for d in devs:
        d["state"] = "up" if d.get("up") else "DOWN"
    emit(args, devs, lambda: (
        print_table(devs, [("ip", "IP"), ("sysName", "Name"), ("state", "State"),
                           ("deviceDisplayFamily", "Family"), ("firmware", "Firmware"),
                           ("sitePath", "Site")]),
        print(f"\n{len(devs)} device(s), {sum(1 for d in devs if d.get('up'))} up"),
    ))
    return 0


def cmd_device(client, args):
    dev = client.device(args.ip)
    if not dev:
        raise NetSightError(f"No device with IP {args.ip}")
    emit(args, dev, lambda: (
        [print(f"{k:22} {v}") for k, v in dev.items() if k != "deviceData" and v not in (None, "")],
        [print(f"{k:22} {v}") for k, v in (dev.get("deviceData") or {}).items() if v not in (None, "")],
    ))
    return 0


def cmd_ports(client, args):
    name, ports = client.ports(args.ip)
    if args.neighbors:
        ports = [p for p in ports if p.get("portNeighborAddress")]
    for p in ports:
        p["vlans"] = ",".join(str(v) for v in p.get("tagged") or [])
        p["untag"] = ",".join(str(v) for v in p.get("untagged") or [])
        p["neighbor"] = (f"{p['portNeighborAddress']} {p.get('portNeighborPortName') or ''}".strip()
                         if p.get("portNeighborAddress") else "")
        p["admin"] = "up" if p.get("portAdmin") else "down"
    emit(args, {"device": name, "ports": ports}, lambda: (
        print(f"{name} ({args.ip}) — {len(ports)} port(s)\n"),
        print_table(ports, [("portName", "Port"), ("portAlias", "Alias"), ("admin", "Admin"),
                            ("portPvid", "PVID"), ("untag", "Untagged"), ("vlans", "Tagged"),
                            ("neighbor", "LLDP neighbour")]),
    ))
    return 0


def cmd_vlans(client, args):
    vl = client.vlans(args.ip)
    vl.sort(key=lambda v: v.get("vid") or 0)
    for v in vl:
        v["ports"] = portlist_from_hex(v.pop("dot1qVlanStaticEgressPorts", ""))
        v["untaggedPorts"] = portlist_from_hex(v.pop("dot1qVlanStaticUntaggedPorts", ""))
    emit(args, vl, lambda: print_table(vl, [
        ("vid", "VLAN"), ("name", "Name"), ("primaryIp", "IP"), ("netmask", "Mask"),
        ("vrName", "VR"), ("ports", "Member ports"), ("untaggedPorts", "Untagged")]))
    return 0


def cmd_schema(client, args):
    if args.roots:
        data = client.query("{ __schema { queryType { fields { name description } } } }")
        for f in data["__schema"]["queryType"]["fields"]:
            print(f"{f['name']:30} {f.get('description') or ''}")
    elif args.type:
        q = """query($n: String!) { __type(name: $n) { name kind
                 fields { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
                 enumValues { name }
                 inputFields { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
               } }"""
        t = client.query(q, {"n": args.type})["__type"]
        if not t:
            raise NetSightError(f"Type '{args.type}' not found")
        print(f"# {t['name']} ({t['kind']})")
        for f in t["fields"] or t["inputFields"] or []:
            print(f"{f['name']:30} {tname(f['type'])}")
        for v in t["enumValues"] or []:
            print(v["name"])
    else:
        q = args.query or Path(args.query_file).read_text()
        variables = json.loads(args.variables) if args.variables else None
        print(json.dumps(client.query(q, variables), indent=2))
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="netsight.py",
        description="Query Extreme Site Engine (NetSight) — read-only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  connect                 Test login and report which NBI sections are readable
  devices                 List all managed switches
  device --ip IP          Show one switch in detail
  ports --ip IP           List ports with VLANs and LLDP neighbours
  vlans --ip IP           List VLANs configured on a switch
  schema                  Explore the raw GraphQL schema / run ad-hoc queries

Examples:
  python netsight.py connect
  python netsight.py devices
  python netsight.py devices --family summit --down
  python netsight.py device --ip 10.0.0.12
  python netsight.py ports --ip 10.0.0.12 --neighbors
  python netsight.py vlans --ip 10.0.0.12
  python netsight.py --json devices > switches.json

  python netsight.py schema --roots
  python netsight.py schema --type Device
  python netsight.py schema --query '{ network { sites { name } } }'

Credentials: config/xiqse.env (default) or --env-file, or XIQSE_* env vars.
        """,
    )
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (machine-readable)")
    parser.add_argument("--env-file", default=str(DEFAULT_ENV_FILE),
                        help="KEY=VALUE file with XIQSE_* settings (default: config/xiqse.env)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS verification (credentials can be intercepted)")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    sub.add_parser("connect", help="Test login + section access")

    p = sub.add_parser("devices", help="List managed switches")
    p.add_argument("--family", help="Filter by device family (substring)")
    p.add_argument("--down", action="store_true", help="Only devices that are down")

    p = sub.add_parser("device", help="Show one switch")
    p.add_argument("--ip", required=True, help="Device management IP")

    p = sub.add_parser("ports", help="List ports of a switch")
    p.add_argument("--ip", required=True, help="Device management IP")
    p.add_argument("--neighbors", action="store_true", help="Only ports with an LLDP neighbour")

    p = sub.add_parser("vlans", help="List VLANs of a switch")
    p.add_argument("--ip", required=True, help="Device management IP")

    p = sub.add_parser("schema", help="Explore the GraphQL schema")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--roots", action="store_true", help="List root query fields")
    g.add_argument("--type", help="Describe a GraphQL type")
    g.add_argument("--query", help="Run an inline GraphQL query")
    g.add_argument("--query-file", help="Run a GraphQL query from a file")
    p.add_argument("--variables", help="JSON string of variables for --query / --query-file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    load_env_file(args.env_file)

    handlers = {
        "connect": cmd_connect, "devices": cmd_devices, "device": cmd_device,
        "ports": cmd_ports, "vlans": cmd_vlans, "schema": cmd_schema,
    }
    try:
        client = client_from_env(insecure=args.insecure)
        return handlers[args.command](client, args)
    except NetSightTlsError as exc:
        print(f"TLS verification failed: {exc}\n"
              "Self-signed server? Set XIQSE_CERT_SHA256 to its fingerprint "
              "(openssl s_client ... | openssl x509 -noout -fingerprint -sha256).",
              file=sys.stderr)
        return 2
    except NetSightTransportError as exc:
        print(f"Connection failed: {exc}", file=sys.stderr)
        return 2
    except NetSightError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
