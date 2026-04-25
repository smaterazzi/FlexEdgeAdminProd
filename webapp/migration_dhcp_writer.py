"""
FlexEdgeAdmin — DHCP migration importer (Phase D of the FortiGate-DHCP plan).

Reads the dedup results produced by ``dedup_engine._dedup_dhcp_reservations``
and:

  1. Calls ``smc_dhcp_client.host_create()`` for every selected reservation
     (or ``host_update()`` to honor an explicit overwrite of a conflicting
     existing reservation), using the SMC config of the *target scope's*
     tenant — not the migration project's. This matters: the migration
     project's ``target.smc_url`` may match many tenants; the actual target
     scope already pins exactly one tenant + api_key pair.
  2. Inserts a ``DhcpReservation`` row with ``source="migration:<project_id>"``
     and ``status="pending"`` so the row shows up in the existing DHCP
     Manager UI exactly like a manually-added one — ready for the Phase 4
     "Deploy" / "Resync" button. **No SSH is touched here.** The migration
     never pushes; it only stages.

Reuses the DHCP Manager primitives end-to-end:

  - ``smc_dhcp_client.host_create`` / ``host_update``  — same comment marker
    ``[flexedge:mac=aa:bb:cc:dd:ee:ff]`` as DHCP Manager UI's manual flow
  - ``smc_dhcp_client.normalize_mac`` — same MAC canonicalisation
  - ``DhcpReservation`` model — same row shape, same uniqueness constraints

Per the locked design (chat 2026-04-25):
  - Imported config wins in staging — but conflicts default to NOT
    selected; the operator must explicitly opt-in to overwrite.
  - Migration never auto-enrolls SSH credentials — un-ready scopes are
    blocked at import with a clear message and a deep link.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def import_dhcp_reservations(parsed_objects, dedup_results, target_dict,
                             project_id):
    """Apply the DHCP migration to SMC + the FlexEdge DB.

    Args:
        parsed_objects:   Output of ``fgt_parser.parse_fortigate_config()``.
        dedup_results:    Output of ``dedup_engine.run_dedup()``. Must
                          include ``dhcp_reservations`` (Phase C output).
        target_dict:      The migration project's ``target`` dict (used
                          only for traceability — actual SMC connection
                          comes from each target scope's tenant).
        project_id:       Migration project id, stamped into
                          ``DhcpReservation.source`` for traceability.

    Returns a dict::

        {
            "entries":               [...log lines...],
            "scopes_processed":      int,
            "scopes_skipped":        int,
            "reservations_created":  int,
            "reservations_updated":  int,
            "reservations_skipped":  int,
            "reservations_errors":   int,
        }

    The caller (``migration_import`` route) merges ``entries`` into the
    overall import log.
    """
    out = {
        "entries": [],
        "scopes_processed": 0,
        "scopes_skipped": 0,
        "reservations_created": 0,
        "reservations_updated": 0,
        "reservations_skipped": 0,
        "reservations_errors": 0,
    }

    dhcp_dedup = (dedup_results or {}).get("dhcp_reservations") or []
    if not dhcp_dedup:
        out["entries"].append({"level": "info",
                               "msg": "DHCP migration: nothing to import."})
        return out

    # Lazy imports — keeps the module importable in tests / CLI contexts
    # that don't have the full Flask + SMC stack on hand.
    from smc_client import smc_session
    from smc_dhcp_client import (
        host_create, host_update, normalize_mac,
    )
    from webapp.models import DhcpScope, DhcpReservation, Tenant, ApiKey
    from shared.db import db

    for entry in dhcp_dedup:
        scope_id = entry.get("target_scope_id")
        fg_id = entry.get("fg_server_id", "?")

        # Skip un-mapped FG scopes (operator chose 'skip' or never mapped)
        if scope_id is None:
            out["scopes_skipped"] += 1
            reason = (entry.get("target_scope_ready_missing") or ["not mapped"])[0]
            out["entries"].append({"level": "info",
                "msg": f"DHCP FG#{fg_id}: {reason} — skipped."})
            continue

        scope = db.session.get(DhcpScope, scope_id)
        if not scope:
            out["scopes_skipped"] += 1
            out["entries"].append({"level": "warning",
                "msg": f"DHCP FG#{fg_id}: target scope {scope_id} not found."})
            continue

        if not entry.get("target_scope_ready"):
            out["scopes_skipped"] += 1
            missing = ", ".join(entry.get("target_scope_ready_missing") or [])
            out["entries"].append({"level": "warning",
                "msg": (f"DHCP FG#{fg_id} → {scope.engine_name}/"
                        f"{scope.interface_id}: scope NOT ready "
                        f"({missing}) — skipped.")})
            continue

        selected = [r for r in entry.get("reservations", [])
                    if r.get("selected")]
        if not selected:
            out["entries"].append({"level": "info",
                "msg": (f"DHCP FG#{fg_id} → {scope.engine_name}/"
                        f"{scope.interface_id}: no reservations selected.")})
            continue

        out["scopes_processed"] += 1

        # Resolve the SMC config from the scope's tenant + api_key.
        tenant: Tenant = db.session.get(Tenant, scope.tenant_id)
        api_key: ApiKey = db.session.get(ApiKey, scope.api_key_id)
        if not tenant or not api_key or not tenant.is_active or not api_key.is_active:
            out["scopes_skipped"] += 1
            out["entries"].append({"level": "warning",
                "msg": (f"DHCP FG#{fg_id}: scope {scope.id}'s tenant or "
                        "api_key is missing/inactive — skipped.")})
            continue

        cfg = {
            "smc_url": tenant.smc_url,
            "api_key": api_key.decrypted_key,
            "verify_ssl": tenant.verify_ssl,
            "timeout": tenant.timeout,
            "domain": tenant.default_domain,
            "retry_on_busy": True,
        }

        # Process all reservations for this scope inside one SMC session.
        try:
            with smc_session(cfg):
                _process_scope_reservations(
                    scope, selected, project_id, out,
                    host_create, host_update, normalize_mac,
                    db, DhcpReservation,
                )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            out["entries"].append({"level": "error",
                "msg": (f"DHCP FG#{fg_id} → {scope.engine_name}/"
                        f"{scope.interface_id}: SMC session failed — {exc}")})
            # The whole scope is now an error — count its selected reservations
            # as errors so the summary numbers reflect reality.
            out["reservations_errors"] += len(selected)

    out["entries"].append({"level": "info", "msg": (
        f"DHCP migration done — created={out['reservations_created']} "
        f"updated={out['reservations_updated']} "
        f"skipped={out['reservations_skipped']} "
        f"errors={out['reservations_errors']} "
        f"scopes={out['scopes_processed']}")})
    return out


def _process_scope_reservations(scope, selected, project_id, out,
                                host_create, host_update, normalize_mac,
                                db, DhcpReservation):
    """Process reservations for one scope inside an open SMC session.

    Each reservation gets its own try/except so a single SMC error doesn't
    abort the whole scope's batch — others still complete.
    """
    source = f"migration:{project_id}"

    for r in selected:
        action = r.get("action", "create")
        ip = r.get("ip", "")
        mac = normalize_mac(r.get("mac", ""))
        desc = (r.get("description") or "").strip()

        try:
            if action == "create":
                host_name = _make_host_name(scope, ip, mac, desc, project_id)
                view = host_create(
                    name=host_name,
                    address=ip,
                    mac_address=mac,
                    comment=desc or f"FortiGate migration #{project_id}",
                )
                row = DhcpReservation(
                    scope_id=scope.id,
                    smc_host_name=view.name,
                    smc_host_href=view.href,
                    ip_address=view.address,
                    mac_address=mac,
                    status="pending",
                    source=source,
                )
                db.session.add(row)
                out["reservations_created"] += 1
                out["entries"].append({"level": "info",
                    "msg": f"  ✓ Created Host {view.name} "
                           f"({ip} / {mac}) on scope {scope.id}"})

            elif action in ("skip", "reuse"):
                out["reservations_skipped"] += 1
                out["entries"].append({"level": "info",
                    "msg": f"  − Skipped {ip} / {mac} (already migrated)"})

            elif action in ("conflict_skip", "conflict_overwrite"):
                # User flipped a conflict to selected=True → treat as overwrite
                # on the existing Host the dedup matched (smc_match.host_name).
                match = r.get("smc_match") or {}
                existing_name = match.get("host_name", "")
                if not existing_name:
                    out["reservations_errors"] += 1
                    out["entries"].append({"level": "error",
                        "msg": f"  ✗ {ip} / {mac}: conflict overwrite requested "
                               "but no existing Host name in dedup — fix manually."})
                    continue

                # Overwrite path: update the existing Host's IP + MAC marker,
                # update or upsert the DhcpReservation row.
                view = host_update(
                    name=existing_name,
                    address=ip,
                    mac_address=mac,
                    comment=desc or f"FortiGate migration #{project_id} (overwrote conflict)",
                )
                existing_row = (DhcpReservation.query
                                .filter_by(scope_id=scope.id,
                                           smc_host_name=existing_name)
                                .first())
                if existing_row:
                    existing_row.ip_address = view.address
                    existing_row.mac_address = mac
                    existing_row.status = "pending"
                    existing_row.last_error = ""
                    existing_row.source = source
                else:
                    db.session.add(DhcpReservation(
                        scope_id=scope.id,
                        smc_host_name=view.name,
                        smc_host_href=view.href,
                        ip_address=view.address,
                        mac_address=mac,
                        status="pending",
                        source=source,
                    ))
                out["reservations_updated"] += 1
                out["entries"].append({"level": "warning",
                    "msg": f"  ⚙ Overwrote {existing_name}: now {ip} / {mac}"})

            else:
                out["reservations_skipped"] += 1
                out["entries"].append({"level": "info",
                    "msg": f"  − Skipped {ip} / {mac} (unknown action {action!r})"})

        except Exception as exc:
            out["reservations_errors"] += 1
            out["entries"].append({"level": "error",
                "msg": f"  ✗ {ip} / {mac}: {type(exc).__name__}: {exc}"})


def _make_host_name(scope, ip, mac, desc, project_id):
    """Generate a stable Host name for a migrated reservation.

    Pattern: ``FGT-DHCP-S<scope_id>-<descr-or-mac>``. SMC limits Host
    names to 256 chars; we cap at 255 to be safe. Non-alphanumeric
    characters in the description are normalised to dashes so the name
    is valid in both SMC and ISC dhcpd.
    """
    import re
    if desc:
        slug = re.sub(r"[^A-Za-z0-9.\-]+", "-", desc).strip("-")[:80]
    else:
        slug = mac.replace(":", "")
    base = f"FGT-DHCP-S{scope.id}-{slug or 'res'}"
    return base[:255]
