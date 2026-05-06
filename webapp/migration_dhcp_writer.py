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
    """Stage the DHCP migration to the FlexEdge change-management queue.

    Phase E.2 (Q20) — the migration writer no longer calls SMC directly.
    It enqueues one ``pending_changes`` row per selected reservation,
    all sharing ``source_correlation_id="migration:<project_id>"`` so
    they group cleanly on ``/changes/?source=migration:<project_id>``.
    The operator presses "Submit" once (the validation flow already
    happened pre-submit); pushing happens from the Change Queue page.

    DB-side ``DhcpReservation`` rows are inserted in ``status='queued'``
    so the operator sees their submission immediately on the scope
    listing (Q16/a). On a successful push, the row transitions to
    ``status='pending'`` (the existing post-create state).

    Args:
        parsed_objects:   Output of ``fgt_parser.parse_fortigate_config()``.
        dedup_results:    Output of ``dedup_engine.run_dedup()``.
        target_dict:      The migration project's ``target`` dict (kept
                          for caller compatibility — no longer used since
                          SMC connection is resolved at push time per
                          row's domain).
        project_id:       Migration project id, stamped into
                          ``DhcpReservation.source`` AND used as the
                          batch correlation id.

    Returns a dict::

        {
            "entries":               [...log lines...],
            "scopes_processed":      int,
            "scopes_skipped":        int,
            "reservations_created":  int,    # enqueued create rows
            "reservations_updated":  int,    # enqueued update rows
            "reservations_skipped":  int,
            "reservations_errors":   int,
            "changes_enqueued":      int,    # total queue rows created
            "correlation_id":        str,    # for /changes/ link
        }
    """
    correlation_id = f"migration:{project_id}"
    out = {
        "entries": [],
        "scopes_processed": 0,
        "scopes_skipped": 0,
        "reservations_created": 0,
        "reservations_updated": 0,
        "reservations_skipped": 0,
        "reservations_errors": 0,
        "changes_enqueued": 0,
        "correlation_id": correlation_id,
    }

    dhcp_dedup = (dedup_results or {}).get("dhcp_reservations") or []
    if not dhcp_dedup:
        out["entries"].append({"level": "info",
                               "msg": "DHCP migration: nothing to import."})
        return out

    from smc_dhcp_client import normalize_mac
    from webapp.models import DhcpScope, DhcpReservation
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

        # Validate Domain + ApiKey are present so the queue handler will
        # be able to push later. Skip whole scope if not.
        domain = scope.domain
        api_key = domain.api_key if domain else None
        if not domain or not api_key or not domain.is_active or not api_key.is_active:
            out["scopes_skipped"] += 1
            out["entries"].append({"level": "warning",
                "msg": (f"DHCP FG#{fg_id}: scope {scope.id}'s Domain or "
                        "ApiKey is missing/inactive — skipped.")})
            continue

        try:
            _enqueue_scope_reservations(
                scope, selected, project_id, correlation_id, out,
                normalize_mac, db, DhcpReservation,
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            out["entries"].append({"level": "error",
                "msg": (f"DHCP FG#{fg_id} → {scope.engine_name}/"
                        f"{scope.interface_id}: enqueue failed — {exc}")})
            out["reservations_errors"] += len(selected)

    out["entries"].append({"level": "info", "msg": (
        f"DHCP migration staged — enqueued={out['changes_enqueued']} "
        f"(created={out['reservations_created']} "
        f"updated={out['reservations_updated']}) "
        f"skipped={out['reservations_skipped']} "
        f"errors={out['reservations_errors']} "
        f"scopes={out['scopes_processed']}. "
        f"Visit /changes/?source={correlation_id} to review + push.")})
    return out


def _enqueue_scope_reservations(scope, selected, project_id, correlation_id,
                                out, normalize_mac, db, DhcpReservation):
    """Stage reservations for one scope into the change-management queue.

    Phase E.2 (Q20) — no SMC mutations happen here. Each selected
    reservation gets:
      1. A ``DhcpReservation`` row inserted in ``status='queued'`` so
         the operator sees it immediately on the scope listing.
      2. A ``pending_changes`` row (``operation='create'`` for new,
         ``operation='update'`` for conflict-overwrite) sharing
         ``correlation_id``. Push happens later from ``/changes/``.

    Per-row failures (validation, DB unique constraint) are isolated
    via try/except — others still enqueue. There's no SMC rollback to
    worry about because no SMC call happens at this stage.
    """
    source = f"migration:{project_id}"

    from webapp.dhcp_reservation_queue import (
        enqueue_reservation_create, enqueue_reservation_update,
    )
    from webapp.models import PendingChange

    for r in selected:
        action = r.get("action", "create")
        ip = r.get("ip", "")
        mac = normalize_mac(r.get("mac", ""))
        desc = (r.get("description") or "").strip()
        comment = desc or f"FortiGate migration #{project_id}"

        try:
            if action == "create":
                host_name = _make_host_name(scope, ip, mac, desc, project_id)

                # Insert DhcpReservation in queued state.
                row = DhcpReservation(
                    scope_id=scope.id,
                    smc_host_name=host_name,
                    smc_host_href="",
                    ip_address=ip,
                    mac_address=mac,
                    status="queued",
                    source=source,
                )
                db.session.add(row)
                db.session.flush()    # get row.id, surface dedupe IntegrityError

                # Enqueue. The helper sets `source_correlation_id` to
                # `dhcp_reservation:<row.id>` by default; we override it
                # below to the migration batch id so all rows group on
                # /changes/.
                change = enqueue_reservation_create(
                    scope=scope, reservation=row,
                    name=host_name, address=ip, mac_address=mac,
                    ipv6_address="", secondary=[],
                    tools_profile_ref="", comment=comment,
                )
                change.source_correlation_id = correlation_id
                db.session.flush()

                out["reservations_created"] += 1
                out["changes_enqueued"] += 1
                out["entries"].append({"level": "info",
                    "msg": (f"  ✓ Queued create Host {host_name} "
                            f"({ip} / {mac}) on scope {scope.id} "
                            f"(change #{change.id})")})

            elif action in ("skip", "reuse"):
                out["reservations_skipped"] += 1
                out["entries"].append({"level": "info",
                    "msg": f"  − Skipped {ip} / {mac} (already migrated)"})

            elif action in ("conflict_skip", "conflict_overwrite"):
                # Overwrite path: the dedup output identified an existing
                # Host with the same identity. We enqueue an `update` for
                # that Host's IP / MAC.
                match = r.get("smc_match") or {}
                existing_name = match.get("host_name", "")
                if not existing_name:
                    out["reservations_errors"] += 1
                    out["entries"].append({"level": "error",
                        "msg": (f"  ✗ {ip} / {mac}: conflict overwrite "
                                f"requested but no existing Host name in "
                                f"dedup — fix manually.")})
                    continue

                # Find or create the local DhcpReservation row that maps
                # to the existing SMC Host.
                existing_row = (DhcpReservation.query
                                .filter_by(scope_id=scope.id,
                                           smc_host_name=existing_name)
                                .first())
                if existing_row is None:
                    # We're going to update an SMC Host we don't have a
                    # local row for. Stamp a row in pending state with
                    # the pre-existing href (we don't have it without
                    # SMC fetch — leave blank, the queue handler will
                    # need to look it up by name on push).
                    existing_row = DhcpReservation(
                        scope_id=scope.id,
                        smc_host_name=existing_name,
                        smc_host_href=match.get("host_href", "") or "",
                        ip_address=ip,
                        mac_address=mac,
                        status="queued",
                        source=source,
                    )
                    db.session.add(existing_row)
                    db.session.flush()
                else:
                    existing_row.status = "queued"
                    existing_row.last_error = ""
                    existing_row.source = source
                    existing_row.ip_address = ip
                    existing_row.mac_address = mac

                change = enqueue_reservation_update(
                    reservation=existing_row,
                    address=ip, mac_address=mac,
                    ipv6_address="", secondary=[],
                    tools_profile_ref="",
                    comment=f"{comment} (overwrote conflict)",
                    previous_address=match.get("ip", ""),
                )
                change.source_correlation_id = correlation_id
                db.session.flush()

                out["reservations_updated"] += 1
                out["changes_enqueued"] += 1
                out["entries"].append({"level": "warning",
                    "msg": (f"  ⚙ Queued overwrite of {existing_name}: "
                            f"now {ip} / {mac} (change #{change.id})")})

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
