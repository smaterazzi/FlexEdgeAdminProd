"""
FlexEdgeAdmin — Switches (RA-C, docs/RemoteAgents.md § Phase C).

Read-only view of the switches an Extreme Site Engine (NetSight) manages
for the active Domain: inventory list → per-device Ports / VLANs tabs.
Every read goes through `webapp/netsight_objects.py` (the single NetSight
read entry point — routing to a remote agent or local execution + the
`netsight.*` cache sections happen there), so this module is pure
presentation: resolve the Domain, call the accessor, render, and turn a
`NetSightUnavailable` into an operator-readable alert instead of a 500.

Blueprint `switches_bp` at /switches, Domain Admin or higher.
"""

import ipaddress
import logging

from flask import Blueprint, abort, g, render_template, request

from webapp.auth_roles import domain_admin_required

log = logging.getLogger(__name__)

switches_bp = Blueprint("switches", __name__, url_prefix="/switches")


def _current_domain():
    """`g.domain` is populated by the app-level before-request hook."""
    return getattr(g, "domain", None)


def _refresh_requested() -> bool:
    return request.args.get("refresh") == "1"


def _unavailable_view(exc) -> dict:
    """Template-friendly shape of a NetSightUnavailable."""
    return {"kind": getattr(exc, "kind", "failed"),
            "reason": getattr(exc, "reason", None) or str(exc)}


def _is_ipv4(value) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).version == 4
    except ValueError:
        return False


@switches_bp.route("/")
@domain_admin_required
def switches_list():
    # Lazy import: netsight_objects pulls in the agent pool + router; keeping
    # it inside the view also means this module imports cleanly on its own.
    from webapp.netsight_objects import NetSightUnavailable, netsight_devices

    domain = _current_domain()
    devices, cache_meta, unavailable = [], None, None
    if domain is None:
        unavailable = {"kind": "no_domain",
                       "reason": "No Domain selected — pick a profile first."}
    else:
        try:
            devices, cache_meta = netsight_devices(domain, refresh=_refresh_requested())
        except NetSightUnavailable as exc:
            unavailable = _unavailable_view(exc)
        except Exception as exc:  # noqa: BLE001 — never 500 on an inquiry page
            log.exception("switches list failed for domain %s", getattr(domain, "slug", "?"))
            unavailable = {"kind": "failed", "reason": str(exc)[:300]}

    return render_template("switches/list.html",
                           devices=devices or [], cache_meta=cache_meta,
                           unavailable=unavailable, domain=domain)


@switches_bp.route("/<ip>")
@domain_admin_required
def switch_detail(ip):
    from webapp.netsight_objects import (
        NetSightUnavailable, netsight_device, netsight_ports, netsight_vlans,
    )
    from shared.netsight_client import portlist_from_hex

    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        abort(400, "not an IP address")

    domain = _current_domain()
    if domain is None:
        return render_template("switches/detail.html", ip=ip, device=None,
                               device_error={"kind": "no_domain",
                                             "reason": "No Domain selected — pick a profile first."},
                               ports=None, ports_error=None, vlans=None, vlans_error=None,
                               cache_meta=None, domain=None), 200

    refresh = _refresh_requested()

    # Each tab is fetched on its own so one failure never blanks the others.
    def _fetch(accessor):
        try:
            return accessor(domain, ip, refresh=refresh), None
        except NetSightUnavailable as exc:
            return (None, None), _unavailable_view(exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("switch %s accessor %s failed", ip, accessor.__name__)
            return (None, None), {"kind": "failed", "reason": str(exc)[:300]}

    (device, cache_meta), device_error = _fetch(netsight_device)
    (ports_payload, _), ports_error = _fetch(netsight_ports)
    (vlan_rows, _), vlans_error = _fetch(netsight_vlans)

    ports = None
    if ports_payload is not None:
        raw_ports = (ports_payload or {}).get("ports") or []
        ports = []
        for p in raw_ports:
            row = dict(p or {})
            nb = row.get("portNeighborAddress") or ""
            row["neighbor_is_switch"] = _is_ipv4(nb)
            ports.append(row)

    vlans = None
    if vlan_rows is not None:
        vlans = []
        for v in vlan_rows or []:
            row = dict(v or {})
            row["egress_decoded"] = portlist_from_hex(row.get("dot1qVlanStaticEgressPorts") or "")
            row["untagged_decoded"] = portlist_from_hex(row.get("dot1qVlanStaticUntaggedPorts") or "")
            vlans.append(row)

    return render_template("switches/detail.html",
                           ip=ip, device=device, device_error=device_error,
                           sys_name=(ports_payload or {}).get("sysName") if ports_payload else None,
                           ports=ports, ports_error=ports_error,
                           vlans=vlans, vlans_error=vlans_error,
                           cache_meta=cache_meta, domain=domain)
