"""DHCP reservation ↔ Change-Management queue glue.

Phase E.2 (Round 3): every DHCP reservation create / update / delete goes
through `pending_changes` instead of writing to SMC directly.

Operator role (Q15):
  - Operator       → row enqueues, route redirects to /changes/ with the
                     row focused. The reservation is shown in the scope
                     listing with a "queued" badge (Q16/a) and stays
                     read-only until pushed.
  - Domain Admin+  → row enqueues, then `push_one()` runs INLINE inside
                     the same request. UX feels identical to today
                     (immediate SMC commit + success page).

Push failure (Q17/b):
  - reservation.status = 'push_failed'; last_error holds the formatted
    SMC error; `pending_change_id` is preserved so a "Retry" button on
    the scope page can resubmit.

Naming (Q16):
  - SMC Host name is *derived* from scope context. Operator-typed names
    are still honored (form keeps the field) but become optional. Default
    convention: ``dhcp-<engine>-<ip-with-dashes>``.

Audit comment marker (Q21):
  - Stamped automatically by the queue handler on successful create /
    update — see `webapp/smc_audit_marker.py`.
"""

import json
import logging
import re
from typing import Optional

from shared.db import db
from webapp.models import DhcpReservation, DhcpScope, PendingChange, User

log = logging.getLogger(__name__)


# ── Naming ─────────────────────────────────────────────────────────────

_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slugify_name_part(s: str) -> str:
    """Sanitize a fragment for use inside an SMC element name."""
    if not s:
        return ""
    cleaned = _NAME_SAFE_RE.sub("-", s.strip())
    return cleaned.strip("-").lower() or ""


def derive_smc_host_name(scope: DhcpScope, ip_address: str,
                         operator_supplied: Optional[str] = None) -> str:
    """Pick the SMC Host name for a reservation.

    If the operator typed something, honor it (today's behavior preserved).
    Otherwise derive ``dhcp-<engine>-<ip-dashed>`` from scope + IP.
    """
    op = (operator_supplied or "").strip()
    if op:
        return op
    eng = _slugify_name_part(scope.engine_name) or "engine"
    ip_d = (ip_address or "").replace(".", "-").replace(":", "-")
    return f"dhcp-{eng}-{ip_d}"


# ── User resolution ───────────────────────────────────────────────────

def _current_user_id() -> Optional[int]:
    """Resolve the current Flask-session user's User.id (or None)."""
    try:
        from flask import session, has_request_context
        if not has_request_context():
            return None
        info = session.get("user") or {}
        email = (info.get("email") or "").strip().lower()
        if not email:
            return None
        u = User.query.filter_by(email=email).first()
        return u.id if u else None
    except Exception:
        return None


# ── Enqueue helpers ───────────────────────────────────────────────────

def _build_host_payload(*, name: str, address: str, mac_address: str,
                        ipv6_address: str = "", secondary: list = None,
                        tools_profile_ref: str = "", comment: str = "",
                        audit_previous_value: Optional[str] = None) -> dict:
    """Shape the JSON payload for a host create / update PendingChange."""
    payload = {
        "smc_type": "host",
        "name": name,
        "address": address,
        "mac_address": mac_address,
        "ipv6_address": ipv6_address or "",
        "secondary": list(secondary) if secondary else [],
        "tools_profile_ref": tools_profile_ref or "",
        "comment": comment or "",
    }
    if audit_previous_value is not None:
        payload["audit_previous_value"] = audit_previous_value
    return payload


def enqueue_reservation_create(*, scope: DhcpScope, reservation: DhcpReservation,
                               name: str, address: str, mac_address: str,
                               ipv6_address: str = "",
                               secondary: list = None,
                               tools_profile_ref: str = "",
                               comment: str = "") -> PendingChange:
    """Create a queued PendingChange(operation='create', smc_type='host').

    The DhcpReservation row is expected to already be flushed (so its id
    is available); this function inserts the change, links the
    reservation to it, and leaves both committed in QUEUED state.
    Caller decides whether to auto-push.
    """
    payload = _build_host_payload(
        name=name, address=address, mac_address=mac_address,
        ipv6_address=ipv6_address, secondary=secondary,
        tools_profile_ref=tools_profile_ref, comment=comment,
    )

    change = PendingChange(
        domain_id=scope.domain_id,
        user_id=_current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="create",
        payload_json=json.dumps(payload),
        feature_source="dhcp",
        source_correlation_id=f"dhcp_reservation:{reservation.id}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()

    reservation.pending_change_id = change.id
    reservation.status = "queued"
    reservation.last_error = ""
    db.session.commit()
    return change


def enqueue_reservation_update(*, reservation: DhcpReservation,
                               address: str, mac_address: str,
                               ipv6_address: str = "",
                               secondary: list = None,
                               tools_profile_ref: str = "",
                               comment: str = "",
                               previous_address: Optional[str] = None
                               ) -> PendingChange:
    """Queue an update.

    If the reservation is already in `status='queued'` (its create hasn't
    been pushed yet), Q16/a says we MUTATE THE EXISTING change's payload
    rather than creating a second queue row. That keeps the queue tidy
    and lets the operator iterate on a not-yet-pushed reservation.

    Otherwise (reservation already pushed and live in SMC), a fresh
    `update` change is created.
    """
    payload = _build_host_payload(
        name=reservation.smc_host_name,
        address=address, mac_address=mac_address,
        ipv6_address=ipv6_address, secondary=secondary,
        tools_profile_ref=tools_profile_ref, comment=comment,
        audit_previous_value=previous_address or "",
    )

    if reservation.status == "queued" and reservation.pending_change_id:
        existing = db.session.get(PendingChange, reservation.pending_change_id)
        if existing is not None and existing.state == "queued":
            # Mutate in place (Q16/a — edits to a queued row update the
            # same pending_changes payload, no second row).
            new_payload = dict(payload)
            new_payload["smc_type"] = "host"
            # Preserve the operation type ('create' for first-time, never
            # become 'update' before the create has even pushed).
            existing.payload_json = json.dumps(new_payload)
            existing.push_error_text = ""
            existing.push_error_at = None
            db.session.commit()
            return existing

    # Fresh update for an already-pushed reservation.
    change = PendingChange(
        domain_id=reservation.scope.domain_id,
        user_id=_current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="update",
        payload_json=json.dumps(payload),
        feature_source="dhcp",
        source_correlation_id=f"dhcp_reservation:{reservation.id}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    reservation.pending_change_id = change.id
    reservation.status = "queued"
    reservation.last_error = ""
    db.session.commit()
    return change


def enqueue_reservation_delete(*, reservation: DhcpReservation,
                               operation: str = "delete") -> PendingChange:
    """Queue a delete.

    `operation` is either ``'delete'`` (Domain Admin+: ready to push) or
    ``'to_be_deleted'`` (Operator: marks the SmcObject as flagged for
    deletion across listings; Global Admin must confirm via the queue
    UI before push, per Q12 + Q14).
    """
    if operation not in ("delete", "to_be_deleted"):
        raise ValueError(f"Bad delete operation: {operation!r}")

    payload = {
        "smc_type": "host",
        "name": reservation.smc_host_name,
    }
    change = PendingChange(
        domain_id=reservation.scope.domain_id,
        user_id=_current_user_id(),
        smc_object_id=None,  # set below if the registry already has the row
        scope="main",
        operation=operation,
        payload_json=json.dumps(payload),
        feature_source="dhcp",
        source_correlation_id=f"dhcp_reservation:{reservation.id}",
        state="queued",
    )

    # Best-effort: link the existing SmcObject so the queue UI can show
    # the type+name and Q12 strikethrough fires immediately.
    try:
        from webapp.models import SmcObject
        if reservation.smc_host_href:
            obj = (SmcObject.query
                   .filter_by(domain_id=reservation.scope.domain_id,
                              smc_href=reservation.smc_host_href)
                   .first())
            if obj is None and reservation.smc_host_name:
                obj = (SmcObject.query
                       .filter_by(domain_id=reservation.scope.domain_id,
                                  smc_name=reservation.smc_host_name,
                                  smc_type="host")
                       .first())
            if obj is None:
                # Lazy-register so the queue + strikethrough have something
                # to link against.
                obj = SmcObject(
                    domain_id=reservation.scope.domain_id,
                    smc_href=reservation.smc_host_href,
                    smc_type="host",
                    smc_name=reservation.smc_host_name,
                    managed_by_flexedge=True,
                )
                db.session.add(obj)
                db.session.flush()
            change.smc_object_id = obj.id
            if operation == "to_be_deleted":
                # Q12 — flag now so listings strikethrough across the UI.
                obj.is_to_be_deleted = True
    except Exception:
        log.exception("Could not link SmcObject for reservation #%s",
                      reservation.id)

    db.session.add(change)
    db.session.flush()
    reservation.pending_change_id = change.id
    reservation.last_error = ""
    db.session.commit()
    return change


# ── Auto-push for admins ──────────────────────────────────────────────

def try_auto_push_for_admins(change: PendingChange,
                             reservation: DhcpReservation) -> str:
    """Push the change inline if the current user is Domain Admin+ OR
    if per-user "bypass queue" is enabled for this user on `dhcp_reservation`
    in the active Domain.

    Returns one of:
      * ``'pushed'``       — push succeeded; reservation is now live.
                             When bypass applies, the queue row was also
                             deleted (transient) and a ``*.bypass_queue``
                             audit marker was emitted.
      * ``'queued'``       — current user is Operator without bypass; row
                             stays QUEUED for visible queue review.
      * ``'push_failed'``  — push attempted, SMC rejected; reservation
                             flagged with the error for operator retry.
      * ``'pending_confirm'`` — `to_be_deleted` row, never auto-pushes
                                regardless of role. Awaits Confirm.
    """
    # `to_be_deleted` never auto-pushes — it requires Global Admin Confirm.
    if change.operation == "to_be_deleted":
        return "pending_confirm"

    is_admin = False
    try:
        from webapp.auth_roles import is_domain_admin
        is_admin = is_domain_admin()
    except Exception:
        is_admin = False

    is_bypass = False
    try:
        from shared.queue_settings import should_bypass_queue
        is_bypass = should_bypass_queue("dhcp_reservation")
    except Exception:
        is_bypass = False

    if not (is_admin or is_bypass):
        return "queued"

    from shared.queue_runner import push_one
    result = push_one(change.id)

    db.session.refresh(reservation)
    db.session.refresh(change)

    if result.success:
        # Sync the reservation row from the now-pushed SmcObject.
        if change.smc_object is not None:
            reservation.smc_host_href = change.smc_object.smc_href
            reservation.smc_host_name = change.smc_object.smc_name
        # For 'delete' on success: the reservation row should be removed
        # by the calling route AFTER this returns 'pushed'. We don't
        # touch DB rows here.
        if change.operation in ("create", "update"):
            reservation.status = "pending"
        reservation.last_error = ""
        reservation.pending_change_id = None
        db.session.commit()

        if is_bypass:
            _bypass_cleanup(change, feature="dhcp_reservation")

        return "pushed"

    # Push failed — preserve pending_change_id so a Retry button can
    # resubmit the same row. Bypass mode also leaves the row visible
    # so the operator can recover from /changes/.
    err = (result.error or change.push_error_text or "Unknown SMC error")
    reservation.status = "push_failed"
    reservation.last_error = err
    db.session.commit()
    return "push_failed"


def _bypass_cleanup(change: PendingChange, *, feature: str) -> None:
    """Delete a successfully-pushed queue row + emit the bypass audit marker.

    Called only when ``should_bypass_queue(feature)`` returned True
    AND the push succeeded. Audit log entry stays — that's where the
    durable trail lives. Failure paths NEVER call this (we want the
    queue row visible so the operator can recover).
    """
    try:
        from shared.logging import audit
        audit(
            feature=feature,
            action=f"{change.operation}.bypass_queue",
            target=(f"{change.smc_object.smc_type}:"
                    f"{change.smc_object.smc_name!r}"
                    if change.smc_object else f"#{change.id}"),
            detail=("bypass_queue=True; queue row deleted on success "
                    f"(was change_id={change.id})"),
            source_correlation_id=change.source_correlation_id,
            domain_id=change.domain_id,
        )
    except Exception as exc:
        log.warning("bypass cleanup: audit emit failed: %s", exc)

    try:
        db.session.delete(change)
        db.session.commit()
    except Exception as exc:
        log.warning("bypass cleanup: change row delete failed (#%s): %s",
                    change.id, exc)
        try:
            db.session.rollback()
        except Exception:
            pass
