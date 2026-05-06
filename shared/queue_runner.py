"""Change-management push runner.

Spec: docs/ChangeManagementProcess.md.

Drains `pending_changes` rows whose `state='queued'` (and `scope='main'`)
in (`scheduled_after`, `created_at`) order, executing each against SMC.

State machine
-------------

    QUEUED ──push──► PUSHED ──(engine activation)──► APPLIED
       │              │
       │              └── (SMC error) ──► PUSH_FAILED
       │
       └── (operator clicks Abort) ──► ABORTED
       └── (loses a conflict resolution) ──► ABORTED

Behaviour locked in by Round 2 answers
--------------------------------------

* **Q4 — halt-on-failure batch.** The runner stops at the first
  `push_failed`. Remaining rows stay `queued` for operator review.
* **Q5 — auto cache invalidation.** After a successful PUSH, the
  runner calls `shared.smc_cache.invalidate(...)` for the section
  most-likely-affected by the operation type. Best-effort; failures
  log but do not propagate.

Audit emission (per the standing rule `feedback_logging_standing_rule`)
-----------------------------------------------------------------------

Every state transition emits a `shared.logging.audit("changes", action, …)`
entry with `feature="changes"`, `target=`human-readable identifier,
`source_correlation_id` from the row. Action codes:

* `push.start`     — runner picked up a QUEUED row
* `push.pushed`    — SMC accepted the change; row → PUSHED
* `push.applied`   — engine activated the change; row → APPLIED
* `push.failed`    — SMC rejected; row → PUSH_FAILED
* `push.skipped`   — row not in QUEUED state when picked up (race)
* `abort`          — row → ABORTED (operator cancel)
* `to_be_deleted.confirm` — Global Admin confirmed an Operator-submitted
                            delete; row transitions `to_be_deleted` →
                            `delete` and is then pushed.
* `to_be_deleted.revoke`  — Global Admin revoked; row → ABORTED.

Public API
----------

  push_one(change_id) -> PushResult
  push_batch(change_ids) -> BatchResult       # halt-on-failure
  push_all_for_domain(domain_id) -> BatchResult
  abort_one(change_id, reason="") -> bool
  confirm_to_be_deleted(change_id) -> PushResult
  revoke_to_be_deleted(change_id, reason="") -> bool
  register_handler(operation)(callable)       # decorator

Operation handlers
------------------

Each PendingChange.operation has a registered handler invoked inside an
SMC session. Handler signature::

    def handler(change: PendingChange, cfg: SMCConfig) -> HandlerResult

Phase C ships ONE proof-of-concept handler (`upload_policy`); the
remaining operations (`create`, `update`, `delete`, `create_section`,
`reload_dhcp`) get registered in Phase E when the corresponding
writers move to enqueue.
"""

import logging
import json as _json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

log = logging.getLogger(__name__)


# ── Result types ──────────────────────────────────────────────────────────

@dataclass
class HandlerResult:
    """Per-operation handler return shape.

    `applied` is True when the SMC mutation also activated on the engine
    (e.g. policy upload). False for SMC-only ops where APPLIED isn't a
    distinct state (host create, etc. — those go QUEUED → PUSHED, terminal).
    """
    success: bool = False
    applied: bool = False
    detail: str = ""
    error: str = ""


@dataclass
class PushResult:
    success: bool = False
    failed: bool = False
    skipped: bool = False
    state: str = ""           # "pushed" | "applied" | "push_failed" | "skipped"
    error: str = ""
    detail: str = ""
    change_id: Optional[int] = None


@dataclass
class BatchResult:
    pushed: int = 0
    applied: int = 0
    failed: int = 0
    skipped: int = 0
    aborted_after_halt: int = 0   # remaining rows we stopped before reaching
    results: list = field(default_factory=list)
    halted_at: Optional[int] = None  # change_id where halt-on-failure kicked in


# ── Handler registry ──────────────────────────────────────────────────────

_HANDLERS: dict[str, Callable] = {}


def register_handler(operation: str):
    """Decorator to attach a handler to an operation type."""
    def decorator(fn: Callable) -> Callable:
        if operation in _HANDLERS:
            log.warning("queue_runner: handler for operation=%s being "
                        "replaced (was %s, now %s)",
                        operation, _HANDLERS[operation].__name__, fn.__name__)
        _HANDLERS[operation] = fn
        return fn
    return decorator


def list_registered_operations() -> list[str]:
    return sorted(_HANDLERS.keys())


# ── Internal helpers ──────────────────────────────────────────────────────

def _utcnow():
    return datetime.now(timezone.utc)


def _current_user_id() -> Optional[int]:
    """Best-effort: id of the user driving this push.

    Resolves via the Flask session if we're in a request context.
    Returns None for out-of-band invocations (CLI, scheduler).
    """
    try:
        from flask import session, has_request_context
        if not has_request_context():
            return None
        info = session.get("user") or {}
        email = (info.get("email") or "").strip().lower()
        if not email:
            return None
        from webapp.models import User
        u = User.query.filter_by(email=email).first()
        return u.id if u else None
    except Exception:
        return None


def _describe(change) -> str:
    """Human-readable target string for audit logs."""
    parts = [change.operation]
    if change.smc_object is not None:
        parts.append(f"{change.smc_object.smc_type}:{change.smc_object.smc_name!r}")
    parts.append(f"#{change.id}")
    return " ".join(parts)


def _user_email_for_change(change) -> str:
    """Best-effort: email of the user who originated this change.

    Order of preference: change.user.email (the row's recorded creator),
    Flask session, "system". Used to stamp the Q21 audit marker on SMC
    elements; on push by an admin, this records the *creator* not the
    pusher (so the audit reflects "who decided" rather than "who clicked
    Push", which can be a different person on operator → admin handoff).
    """
    try:
        if change.user is not None and change.user.email:
            return change.user.email
    except Exception:
        pass
    try:
        from flask import session, has_request_context
        if has_request_context():
            user = session.get("user") or {}
            email = (user.get("email") or "").strip()
            if email:
                return email
    except Exception:
        pass
    return "system"


def _smc_cfg_for_change(change):
    """Build an `SMCConfig` from the Domain referenced by the change.

    Reads server-level fields (smc_url, verify_ssl, timeout, api_version)
    from the Domain's ApiKey (Phase A absorbed those onto api_keys), and
    the SMC admin-domain name from `Domain.smc_domain_name`.
    """
    from webapp.smc_tls_client import SMCConfig
    domain = change.domain
    if domain is None:
        raise ValueError(f"PendingChange #{change.id} has no domain")
    ak = domain.api_key
    if ak is None:
        raise ValueError(f"Domain #{domain.id} has no api_key")
    return SMCConfig(
        url=ak.smc_url,
        api_key=ak.decrypted_key,
        domain=domain.smc_domain_name or "",
        api_version=ak.api_version or "",
        verify_ssl=ak.verify_ssl,
        timeout=ak.timeout,
    )


def _audit(action: str, change, *, status: str = "ok", detail: str = ""):
    """Emit a `feature="changes"` audit log entry for a state transition."""
    try:
        from shared.logging import audit
        audit(
            feature="changes", action=action,
            target=_describe(change), detail=detail, status=status,
            source_correlation_id=change.source_correlation_id,
            domain_id=change.domain_id,
        )
    except Exception as exc:
        log.warning("queue_runner: audit emit failed (%s, change=#%s): %s",
                    action, change.id, exc)


def _invalidate_cache_for_change(change):
    """Best-effort: drop SMC read-cache entries that just went stale.

    Mapping is approximate — we err on the side of "drop more than
    needed" rather than "leave a stale row visible". Failures are
    logged but never propagated.
    """
    try:
        from shared import smc_cache
    except Exception:
        return

    smc_type = (change.smc_object.smc_type
                if change.smc_object is not None else "") or ""
    sections = []

    op = change.operation
    if op == "upload_policy":
        # Engine state changed — drop engine + policy caches.
        sections.append(("engines.list", None))
        # Best-effort: invalidate any cached engine detail keyed by the
        # engine name from payload.
        try:
            payload = _json.loads(change.payload_json or "{}")
            engine = payload.get("engine_name")
            if engine:
                sections.append((f"engines.detail.{engine}", None))
            policy = payload.get("policy_name")
            if policy:
                sections.append((f"smc.policy.{policy}", None))
        except Exception:
            pass
    elif smc_type in ("rule", "nat_rule", "section"):
        # Rule lives in a policy — drop the policy cache section.
        sections.append(("smc.policy", None))
    elif smc_type:
        # Plain element types: drop the explorer section that lists them.
        sections.append((f"smc.explorer.{smc_type}", None))

    for section, key_parts in sections:
        try:
            n = smc_cache.invalidate(section, key_parts)
            if n:
                log.debug("queue_runner: invalidated %d cache entry(ies) "
                          "in section=%s", n, section)
        except Exception as exc:
            log.debug("queue_runner: cache invalidate failed for %s: %s",
                      section, exc)


# ── State-transition primitives ──────────────────────────────────────────

def _mark_pushed(change, *, applied: bool, detail: str = ""):
    """QUEUED → PUSHED (or APPLIED). Commits + audits + invalidates cache."""
    from shared.db import db
    new_state = "applied" if applied else "pushed"
    change.state = new_state
    change.transitioned_at = _utcnow()
    change.transitioned_by_id = _current_user_id()
    change.push_error_text = ""
    change.push_error_at = None
    db.session.commit()
    _audit(f"push.{new_state}", change, detail=detail)
    _invalidate_cache_for_change(change)


def _mark_push_failed(change, error: str):
    """QUEUED → PUSH_FAILED. Commits + audits."""
    from shared.db import db
    change.state = "push_failed"
    change.push_error_text = (error or "")[:4000]
    change.push_error_at = _utcnow()
    db.session.commit()
    _audit("push.failed", change, status="failed", detail=error)


def _mark_aborted(change, reason: str = ""):
    """QUEUED|CONFLICT → ABORTED. Commits + audits."""
    from shared.db import db
    change.state = "aborted"
    change.transitioned_at = _utcnow()
    change.transitioned_by_id = _current_user_id()
    if reason:
        change.push_error_text = (reason or "")[:4000]
    db.session.commit()
    _audit("abort", change, detail=reason or "operator abort")


# ── Public API ────────────────────────────────────────────────────────────

def push_one(change_id: int) -> PushResult:
    """Push a single QUEUED PendingChange against SMC.

    Idempotent on race: if a concurrent caller has already moved the
    row out of QUEUED, returns `skipped=True` without touching SMC.
    """
    from webapp.models import PendingChange
    from shared.db import db

    change = db.session.get(PendingChange, change_id)
    if change is None:
        return PushResult(failed=True, error="Change not found",
                          change_id=change_id)

    if change.state != "queued":
        log.debug("push_one: change #%s not queued (state=%s) — skipping",
                  change_id, change.state)
        return PushResult(skipped=True, state=change.state, change_id=change_id,
                          error=f"State is {change.state}, not 'queued'")

    if change.scope != "main":
        # Migration-review rows must be promoted to scope='main' before
        # they can push. The runner refuses to act on review rows.
        return PushResult(skipped=True, change_id=change_id,
                          error=f"Scope is '{change.scope}', not 'main'")

    handler = _HANDLERS.get(change.operation)
    if handler is None:
        msg = f"No handler registered for operation={change.operation!r}"
        _mark_push_failed(change, msg)
        return PushResult(failed=True, change_id=change_id,
                          state="push_failed", error=msg)

    _audit("push.start", change)

    try:
        cfg = _smc_cfg_for_change(change)
    except Exception as exc:
        _mark_push_failed(change, f"SMC config resolution failed: {exc}")
        return PushResult(failed=True, change_id=change_id,
                          state="push_failed", error=str(exc))

    # Run the handler inside an SMC session.
    try:
        from webapp.smc_tls_client import smc_session
        with smc_session(cfg):
            result: HandlerResult = handler(change, cfg)
    except Exception as exc:
        log.exception("queue_runner: handler raised (change=#%s op=%s)",
                      change.id, change.operation)
        _mark_push_failed(change, f"Handler raised: {exc!s}")
        return PushResult(failed=True, change_id=change_id,
                          state="push_failed", error=str(exc))

    if not result.success:
        _mark_push_failed(change, result.error or "handler reported failure")
        return PushResult(failed=True, change_id=change_id,
                          state="push_failed",
                          error=result.error or "handler reported failure")

    _mark_pushed(change, applied=result.applied, detail=result.detail)
    return PushResult(
        success=True, change_id=change_id, detail=result.detail,
        state="applied" if result.applied else "pushed",
    )


def push_batch(change_ids: list[int]) -> BatchResult:
    """Push a batch of QUEUED rows in input order.

    Halt-on-failure (Q4): the first `push_failed` stops processing —
    remaining rows stay QUEUED for the operator to inspect / resolve /
    retry. The result reports the exact id where halt kicked in plus
    the count of rows we did not even try.
    """
    out = BatchResult()
    for i, cid in enumerate(change_ids):
        r = push_one(cid)
        out.results.append(r)
        if r.success:
            if r.state == "applied":
                out.applied += 1
            else:
                out.pushed += 1
        elif r.skipped:
            out.skipped += 1
        elif r.failed:
            out.failed += 1
            out.halted_at = cid
            out.aborted_after_halt = max(0, len(change_ids) - i - 1)
            log.warning("push_batch: halted at change_id=%s (failure: %s); "
                        "%d remaining row(s) untouched",
                        cid, r.error, out.aborted_after_halt)
            break
    return out


def push_all_for_domain(domain_id: int) -> BatchResult:
    """Push every QUEUED row in scope='main' for a Domain, in dep order.

    Order: `(scheduled_after IS NOT NULL ASC, scheduled_after ASC, created_at ASC)`
    — rows without a dependency go first; among those with one, the
    earliest dependency target leads. Within a tier, oldest first.
    """
    from webapp.models import PendingChange
    rows = (PendingChange.query
            .filter_by(domain_id=domain_id, state="queued", scope="main")
            .order_by(
                PendingChange.scheduled_after.is_(None).desc(),  # nulls first
                PendingChange.scheduled_after.asc().nulls_first(),
                PendingChange.created_at.asc(),
            )
            .all())
    return push_batch([r.id for r in rows])


def abort_one(change_id: int, reason: str = "") -> bool:
    """Abort a QUEUED or CONFLICT row. Returns True if state changed."""
    from webapp.models import PendingChange
    from shared.db import db

    change = db.session.get(PendingChange, change_id)
    if change is None:
        return False
    if change.state not in ("queued", "conflict"):
        return False
    _mark_aborted(change, reason=reason)
    return True


def confirm_to_be_deleted(change_id: int) -> PushResult:
    """Global / Super Admin confirms an Operator-submitted delete.

    Transitions the row's operation `to_be_deleted` → `delete`, leaves
    `state='queued'`, then immediately calls `push_one()` so the actual
    SMC delete fires. The `smc_objects.is_to_be_deleted` flag is left in
    place during PUSH so list-views still strikethrough the row; the
    flag is cleared by the `delete` handler on success.
    """
    from webapp.models import PendingChange
    from shared.db import db

    change = db.session.get(PendingChange, change_id)
    if change is None:
        return PushResult(failed=True, error="Change not found",
                          change_id=change_id)
    if change.operation != "to_be_deleted" or change.state != "queued":
        return PushResult(skipped=True, change_id=change_id,
                          error=f"Not a queued to_be_deleted row (op={change.operation}, state={change.state})")

    change.operation = "delete"
    db.session.commit()
    _audit("to_be_deleted.confirm", change,
           detail="Operator-submitted delete confirmed → operation=delete")
    return push_one(change_id)


def revoke_to_be_deleted(change_id: int, reason: str = "") -> bool:
    """Global / Super Admin revokes an Operator-submitted delete.

    Transitions the row to ABORTED and clears the
    `smc_objects.is_to_be_deleted` flag so list-views stop showing
    strikethrough. The object stays in SMC unchanged.
    """
    from webapp.models import PendingChange
    from shared.db import db

    change = db.session.get(PendingChange, change_id)
    if change is None:
        return False
    if change.operation != "to_be_deleted" or change.state != "queued":
        return False

    if change.smc_object is not None:
        change.smc_object.is_to_be_deleted = False
    _mark_aborted(change, reason=reason or "to_be_deleted revoked")
    _audit("to_be_deleted.revoke", change, detail=reason or "revoked")
    return True


# ── Built-in handlers ────────────────────────────────────────────────────
#
# Phase C shipped `upload_policy` as a proof-of-concept. Phase E.1 added
# the remaining built-ins:
#
#   create / update / delete   — dispatch by smc_object.smc_type
#                                (Phase E.2: 'host' is the only type with
#                                a real implementation; more types added
#                                as writers convert to enqueue)
#   to_be_deleted              — never directly pushed; the queue's
#                                Confirm action transitions to 'delete'
#                                via confirm_to_be_deleted(). Direct push
#                                returns a clear error.
#   create_section             — placeholder; populated when smc_writer
#                                section creation is converted (later in E.2)
#
# Q18 (Round 3) decided that DHCP Phase 4 deploy stays OUT of the queue —
# it's an SSH push, not an SMC mutation. No `reload_dhcp` handler exists.

@register_handler("upload_policy")
def _handle_upload_policy(change, cfg) -> HandlerResult:
    """Push a `policy.upload(engine_name)` op against SMC.

    Payload shape: `{"engine_name": "...", "policy_name": "..."}`.
    `policy_name` is optional — the SDK falls back to the engine's
    currently-installed policy when omitted.
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    engine_name = (payload.get("engine_name") or "").strip()
    if not engine_name:
        return HandlerResult(success=False,
                             error="engine_name missing from payload")
    policy_name = (payload.get("policy_name") or "").strip() or None

    try:
        from webapp.smc_tls_client import policy_upload
        msg = policy_upload(engine_name, policy_name)
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))

    detail = f"Policy upload to engine '{engine_name}': {msg}"
    return HandlerResult(success=True, applied=True, detail=detail)


def _smc_type_of(change) -> str:
    """Best-effort: pick the smc_type for type-dispatched ops.

    Prefers `change.smc_object.smc_type`; falls back to a `smc_type` field
    in the payload (useful for migration-import bulk where the SmcObject
    row may not exist yet).
    """
    if change.smc_object is not None and change.smc_object.smc_type:
        return change.smc_object.smc_type
    try:
        payload = _json.loads(change.payload_json or "{}")
        return (payload.get("smc_type") or "").strip()
    except Exception:
        return ""


@register_handler("create")
def _handle_create(change, cfg) -> HandlerResult:
    """Create an SMC element. Dispatches by smc_type.

    Supported types: `host`, `network`, `address_range`, `fqdn`,
    `tcp_service`, `udp_service`, `group` (address group),
    `service_group`. Each handler parses its type-specific payload,
    stamps the Q21 audit comment marker, calls the SMC SDK, and
    reconciles the linked `SmcObject` row.

    Other types raise an explicit "no handler for type" error so an
    early conversion can't silently no-op.
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    smc_type = _smc_type_of(change)
    handler = _CREATE_DISPATCH.get(smc_type)
    if handler is None:
        return HandlerResult(success=False,
                             error=f"No create handler registered for smc_type={smc_type!r}")
    return handler(change, payload)


def _create_host(change, payload: dict) -> HandlerResult:
    """Create an SMC `Host` element + reconcile the SmcObject registry row.

    Stamps the Q21 audit marker into the comment field on success so the
    SMC element carries `[flexedge:audit ts=... user=...]` visible from
    SMC Management Client.
    """
    name = (payload.get("name") or "").strip()
    address = (payload.get("address") or "").strip()
    mac = (payload.get("mac_address") or "").strip()
    if not name or not address:
        return HandlerResult(success=False,
                             error="host.create payload missing name or address")

    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""

    try:
        from webapp.smc_dhcp_client import host_create
        from webapp.smc_audit_marker import pack_audit_into_comment
        # No `prev` on create — there's nothing to compare against.
        stamped_comment = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )
        view = host_create(
            name=name, address=address, mac_address=mac,
            ipv6_address=payload.get("ipv6_address") or "",
            secondary=payload.get("secondary") or [],
            tools_profile_ref=payload.get("tools_profile_ref") or "",
            comment=stamped_comment,
        )
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))

    _reconcile_smc_object(change, smc_type="host",
                          smc_name=view.name, smc_href=view.href,
                          managed_by_flexedge=True)
    return HandlerResult(success=True, applied=False,
                         detail=f"Host {view.name} created at {view.href}")


# ── Generic SMC element create helpers (Phase E.2 non-DHCP migration) ────
#
# These handlers cover the FortiGate migration import object types.
# Each:
#   1. Parses its type-specific payload.
#   2. Stamps the Q21 audit comment marker into the comment field.
#   3. Calls the SMC SDK's `<Class>.create(...)`.
#   4. Reconciles the linked `SmcObject` registry row.
#   5. Treats "already exists" as a soft success (idempotent — operator
#      can re-import without duplicating).

def _treat_create_outcome(exc: Exception) -> tuple[str, bool]:
    """Classify an SMC create exception. Returns (detail, is_idempotent_skip).

    Forcepoint SMC returns various error shapes for "already exists";
    we accept any of them as success because the migration importer
    needs to be safely re-runnable.
    """
    msg = str(exc).lower()
    if ("already exists" in msg or "must be unique" in msg
            or "duplicate" in msg):
        return (f"already exists: {exc}", True)
    return (str(exc), False)


def _create_network(change, payload: dict) -> HandlerResult:
    """Create an SMC `Network` element.

    Payload: {smc_type, name, ipv4_network ("a.b.c.d/M"), comment}
    """
    name = (payload.get("name") or "").strip()
    cidr = (payload.get("ipv4_network") or "").strip()
    if not name or not cidr:
        return HandlerResult(success=False,
                             error="network.create payload missing name or ipv4_network")

    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""
    try:
        from smc.elements.network import Network
        from webapp.smc_audit_marker import pack_audit_into_comment
        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )
        Network.create(name=name, ipv4_network=cidr, comment=stamped)
        href = Network(name).href
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)
        try:
            href = Network(name).href
        except Exception:
            href = ""

    _reconcile_smc_object(change, smc_type="network",
                          smc_name=name, smc_href=href,
                          managed_by_flexedge=True)
    return HandlerResult(success=True, applied=False,
                         detail=f"Network {name} ({cidr})")


def _create_address_range(change, payload: dict) -> HandlerResult:
    """Create an SMC `AddressRange` element.

    Payload: {smc_type, name, ip_range ("a.b.c.d-x.y.z.w"), comment}
    """
    name = (payload.get("name") or "").strip()
    ip_range = (payload.get("ip_range") or "").strip()
    if not name or not ip_range:
        return HandlerResult(success=False,
                             error="address_range.create payload missing name or ip_range")

    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""
    try:
        from smc.elements.network import AddressRange
        from webapp.smc_audit_marker import pack_audit_into_comment
        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )
        AddressRange.create(name=name, ip_range=ip_range, comment=stamped)
        href = AddressRange(name).href
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)
        try:
            href = AddressRange(name).href
        except Exception:
            href = ""

    _reconcile_smc_object(change, smc_type="address_range",
                          smc_name=name, smc_href=href,
                          managed_by_flexedge=True)
    return HandlerResult(success=True, applied=False,
                         detail=f"AddressRange {name} ({ip_range})")


def _create_fqdn(change, payload: dict) -> HandlerResult:
    """Create an SMC `DomainName` (FQDN) element.

    Payload: {smc_type, name, value (the FQDN), comment}
    """
    name = (payload.get("name") or "").strip()
    value = (payload.get("value") or "").strip()
    if not name or not value:
        return HandlerResult(success=False,
                             error="fqdn.create payload missing name or value")

    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""
    try:
        from smc.elements.network import DomainName
        from webapp.smc_audit_marker import pack_audit_into_comment
        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )
        DomainName.create(name=name, value=value, comment=stamped)
        href = DomainName(name).href
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)
        try:
            href = DomainName(name).href
        except Exception:
            href = ""

    _reconcile_smc_object(change, smc_type="fqdn",
                          smc_name=name, smc_href=href,
                          managed_by_flexedge=True)
    return HandlerResult(success=True, applied=False,
                         detail=f"FQDN {name} -> {value}")


def _create_tcp_service(change, payload: dict) -> HandlerResult:
    """Create an SMC `TCPService`. Payload supports a port range.

    Payload: {smc_type, name, min_dst_port, max_dst_port, comment}
    `max_dst_port` optional (defaults to single-port).
    """
    return _create_port_service(change, payload, "tcp")


def _create_udp_service(change, payload: dict) -> HandlerResult:
    """Create an SMC `UDPService`."""
    return _create_port_service(change, payload, "udp")


def _create_port_service(change, payload: dict, kind: str) -> HandlerResult:
    name = (payload.get("name") or "").strip()
    min_p = payload.get("min_dst_port")
    max_p = payload.get("max_dst_port")
    if not name or min_p is None:
        return HandlerResult(success=False,
                             error=f"{kind}_service.create payload missing name or min_dst_port")

    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""
    try:
        if kind == "tcp":
            from smc.elements.service import TCPService as Cls
        else:
            from smc.elements.service import UDPService as Cls
        from webapp.smc_audit_marker import pack_audit_into_comment

        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )
        kwargs = {
            "name": name,
            "min_dst_port": int(min_p),
            "comment": stamped,
        }
        if max_p is not None and int(max_p) != int(min_p):
            kwargs["max_dst_port"] = int(max_p)
        Cls.create(**kwargs)
        href = Cls(name).href
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)
        try:
            from smc.elements.service import TCPService, UDPService
            href = (TCPService(name).href if kind == "tcp"
                    else UDPService(name).href)
        except Exception:
            href = ""

    _reconcile_smc_object(change, smc_type=f"{kind}_service",
                          smc_name=name, smc_href=href,
                          managed_by_flexedge=True)
    return HandlerResult(success=True, applied=False,
                         detail=f"{kind.upper()}Service {name} {min_p}-{max_p or min_p}")


def _create_group(change, payload: dict) -> HandlerResult:
    """Create an SMC address `Group`. Members must already exist in SMC.

    Payload: {smc_type, name, member_names: [...], comment}

    The handler resolves each member by name across the candidate
    classes (Network, Host, AddressRange, Group, DomainName) — same
    lookup the legacy `smc_writer.create_objects` does. Members the
    SDK can't find are skipped with a warning in `detail`.

    For migration imports the group row is enqueued AFTER all member
    address rows, so the natural `created_at` push order ensures
    members exist by the time the handler runs. Halt-on-failure also
    stops the batch if a member create fails.
    """
    name = (payload.get("name") or "").strip()
    member_names = list(payload.get("member_names") or [])
    if not name:
        return HandlerResult(success=False,
                             error="group.create payload missing name")

    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""
    skipped: list[str] = []
    try:
        from smc.elements.network import (
            Network, Host, AddressRange, DomainName,
        )
        from smc.elements.group import Group
        from webapp.smc_audit_marker import pack_audit_into_comment

        members = []
        for m in member_names:
            resolved = None
            for cls in (Network, Host, AddressRange, Group, DomainName):
                try:
                    elem = cls(m)
                    _ = elem.href
                    resolved = elem
                    break
                except Exception:
                    continue
            if resolved is None:
                skipped.append(m)
            else:
                members.append(resolved)

        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )
        Group.create(name=name, members=members, comment=stamped)
        href = Group(name).href
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)
        try:
            href = Group(name).href
        except Exception:
            href = ""

    _reconcile_smc_object(change, smc_type="group",
                          smc_name=name, smc_href=href,
                          managed_by_flexedge=True)
    skip_note = (f" (skipped unresolvable members: {', '.join(skipped)})"
                 if skipped else "")
    return HandlerResult(success=True, applied=False,
                         detail=f"Group {name} with {len(member_names)} member(s){skip_note}")


def _create_service_group(change, payload: dict) -> HandlerResult:
    """Create an SMC `ServiceGroup`. Members must already exist."""
    name = (payload.get("name") or "").strip()
    member_names = list(payload.get("member_names") or [])
    if not name:
        return HandlerResult(success=False,
                             error="service_group.create payload missing name")

    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""
    skipped: list[str] = []
    try:
        from smc.elements.service import TCPService, UDPService
        from smc.elements.group import ServiceGroup
        from webapp.smc_audit_marker import pack_audit_into_comment

        members = []
        for m in member_names:
            resolved = None
            for cls in (TCPService, UDPService, ServiceGroup):
                try:
                    svc = cls(m)
                    _ = svc.href
                    resolved = svc
                    break
                except Exception:
                    continue
            if resolved is None:
                skipped.append(m)
            else:
                members.append(resolved)

        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )
        ServiceGroup.create(name=name, members=members, comment=stamped)
        href = ServiceGroup(name).href
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)
        try:
            href = ServiceGroup(name).href
        except Exception:
            href = ""

    _reconcile_smc_object(change, smc_type="service_group",
                          smc_name=name, smc_href=href,
                          managed_by_flexedge=True)
    skip_note = (f" (skipped unresolvable members: {', '.join(skipped)})"
                 if skipped else "")
    return HandlerResult(success=True, applied=False,
                         detail=f"ServiceGroup {name} with {len(member_names)} member(s){skip_note}")


# Dispatch table consumed by `_handle_create`. The actual table is
# defined further down — AFTER `_create_rule` and `_create_nat_rule`
# are declared (those live below the update/delete/section handlers
# because they need helpers like `_ensure_firewall_policy` that are
# defined after the simpler element handlers). `_handle_create` looks
# the dict up at call time, so its placement doesn't matter at import.


@register_handler("update")
def _handle_update(change, cfg) -> HandlerResult:
    """Update an SMC element. Dispatches by smc_type."""
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    smc_type = _smc_type_of(change)
    if smc_type == "host":
        return _update_host(change, payload)

    return HandlerResult(success=False,
                         error=f"No update handler registered for smc_type={smc_type!r}")


def _update_host(change, payload: dict) -> HandlerResult:
    """Update an SMC Host. Stamps the Q21 audit marker with prev-value
    truncated to 20 chars (most-changed field's prior IP, by convention).
    """
    name = (payload.get("name") or "").strip()
    if not name and change.smc_object is not None:
        name = change.smc_object.smc_name
    if not name:
        return HandlerResult(success=False, error="host.update payload missing name")

    user_email = _user_email_for_change(change)
    # Operator can pass a `previous_value` hint for the audit marker — the
    # caller knows what changed (e.g. "192.168.10.50" → "192.168.10.51"
    # passes prev="192.168.10.50"). Falls back to omitting `prev`.
    prev = payload.get("audit_previous_value")

    try:
        from webapp.smc_dhcp_client import host_update
        from webapp.smc_audit_marker import pack_audit_into_comment

        def _opt(key):
            return payload[key] if key in payload else None

        # If the caller provided a comment, stamp the audit marker on it.
        # If they didn't, leave comment alone (the existing marker stays).
        comment_arg = _opt("comment")
        if comment_arg is not None:
            comment_arg = pack_audit_into_comment(
                comment_arg, user_email=user_email,
                previous_value=prev,
            )

        view = host_update(
            name=name,
            address=_opt("address"),
            ipv6_address=_opt("ipv6_address"),
            secondary=payload.get("secondary"),
            tools_profile_ref=_opt("tools_profile_ref"),
            comment=comment_arg,
            mac_address=_opt("mac_address"),
        )
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))

    _reconcile_smc_object(change, smc_type="host",
                          smc_name=view.name, smc_href=view.href)
    return HandlerResult(success=True, applied=False,
                         detail=f"Host {view.name} updated")


@register_handler("delete")
def _handle_delete(change, cfg) -> HandlerResult:
    """Delete an SMC element. Dispatches by smc_type.

    Payload optional — if `change.smc_object` carries the type+name, the
    payload only needs to be `{}`. For migration-import promote paths the
    payload may carry `{"smc_type": "...", "name": "..."}` instead.

    Idempotent on missing element: the underlying SDK returns False when
    the element is already gone, which we treat as success (the queue's
    intent — "ensure absent" — is satisfied either way).
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    smc_type = _smc_type_of(change)
    name = (payload.get("name") or "").strip()
    if not name and change.smc_object is not None:
        name = change.smc_object.smc_name

    if smc_type == "host":
        return _delete_host(change, name)

    return HandlerResult(success=False,
                         error=f"No delete handler registered for smc_type={smc_type!r}")


def _delete_host(change, name: str) -> HandlerResult:
    if not name:
        return HandlerResult(success=False, error="host.delete payload missing name")
    try:
        from webapp.smc_dhcp_client import host_delete
        existed = host_delete(name)
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))

    _retire_smc_object(change)
    detail = (f"Host {name} deleted from SMC" if existed
              else f"Host {name} already absent in SMC (idempotent)")
    return HandlerResult(success=True, applied=False, detail=detail)


@register_handler("to_be_deleted")
def _handle_to_be_deleted(change, cfg) -> HandlerResult:
    """`to_be_deleted` rows never push directly.

    The queue UI's Confirm action calls `confirm_to_be_deleted()` which
    transitions the row's operation to `delete` and then pushes. Direct
    push_one() on a `to_be_deleted` row is a UX bug — fail loudly so the
    operator sees the cause rather than a silent skip.
    """
    return HandlerResult(
        success=False,
        error=("to_be_deleted rows must be CONFIRMED by a Global Admin "
               "from the Change Queue (which converts the row to "
               "`delete` and pushes). Direct push is not allowed."),
    )


@register_handler("create_section")
def _handle_create_section(change, cfg) -> HandlerResult:
    """Create a rule section header in a Firewall policy (Phase E.2).

    Section creation is a side-effect of the policy's rule list — not a
    standalone SMC element. The Q9 answer says sections are mandatory:
    operator picks the section name + position at submission time.

    Payload: ``{"smc_type": "rule_section", "policy_name": "...",
                "section_name": "..."}``

    Idempotent on duplicate: SMC rejects re-create as already-exists
    which we treat as soft success so a re-run of the same migration
    batch doesn't fail mid-cascade.
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    policy_name = (payload.get("policy_name") or "").strip()
    section_name = (payload.get("section_name") or "").strip()
    if not policy_name or not section_name:
        return HandlerResult(
            success=False,
            error="create_section payload missing policy_name or section_name",
        )

    try:
        policy = _ensure_firewall_policy(policy_name)
        policy.fw_ipv4_access_rules.create_rule_section(name=section_name)
        return HandlerResult(success=True, applied=False,
                             detail=(f"Section '{section_name}' created in "
                                     f"policy '{policy_name}'"))
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if idempotent:
            return HandlerResult(success=True, applied=False,
                                 detail=(f"Section '{section_name}' already "
                                         f"present in '{policy_name}'"))
        return HandlerResult(success=False, error=detail)


def _ensure_firewall_policy(policy_name: str):
    """Find-or-create the FirewallPolicy by name. Returns the SDK obj.

    Used by `create_section`, the rule create handler, and the NAT rule
    handler. Idempotent — find first, create on miss. Raises only when
    SMC rejects the create for a non-already-exists reason.
    """
    from smc.policy.layer3 import FirewallPolicy
    try:
        policy = FirewallPolicy(policy_name)
        _ = policy.href  # force a load to confirm it exists
        return policy
    except Exception:
        pass
    try:
        FirewallPolicy.create(
            name=policy_name,
            template="Firewall Inspection Template",
        )
    except Exception as exc:
        _, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            raise
    return FirewallPolicy(policy_name)


def _resolve_element_name(name: str):
    """Try every candidate SMC class for a network-element name.

    Returns the resolved SDK object or None. Caller decides what to do
    with None (typically: skip + warn, or fall back to "any").
    """
    if not name or name == "any":
        return None
    try:
        from smc.elements.network import (
            Host, Network, AddressRange, DomainName,
        )
        from smc.elements.group import Group
    except Exception:
        return None
    for cls in (Network, Host, AddressRange, Group, DomainName):
        try:
            elem = cls(name)
            _ = elem.href
            return elem
        except Exception:
            continue
    return None


def _resolve_service_name(name: str):
    """Try every candidate SMC service class for a name.

    Returns the resolved SDK object or None.
    """
    if not name or name == "any":
        return None
    try:
        from smc.elements.service import (
            TCPService, UDPService, IPService,
        )
        from smc.elements.group import ServiceGroup
    except Exception:
        return None
    for cls in (TCPService, UDPService, IPService, ServiceGroup):
        try:
            svc = cls(name)
            _ = svc.href
            return svc
        except Exception:
            continue
    return None


def _resolve_member_list(names, *, service: bool = False):
    """Resolve a list of element / service names. Returns 'any' if all
    unresolvable — preserves the legacy `_resolve_list` semantics from
    the SMC-direct rule writer.
    """
    if not names or names == ["any"]:
        return "any"
    resolver = _resolve_service_name if service else _resolve_element_name
    resolved = []
    for n in names:
        if n == "any":
            return "any"
        obj = resolver(n)
        if obj is not None:
            resolved.append(obj)
    return resolved if resolved else "any"


def _create_rule(change, payload: dict) -> HandlerResult:
    """Create a firewall rule in a policy + optional section.

    Payload (all fields except `name` + `policy_name` are optional)::

        {
            "smc_type": "rule",
            "policy_name": "Migration from Fortinet",
            "section_name": "FortiGate VLAN10",   # null/missing = top-level
            "name": "...",
            "sources": ["name1", "name2"]    | "any",
            "destinations": [...]            | "any",
            "services": [...]                | "any",
            "action": "allow"|"discard"|"refuse",
            "is_disabled": false,
            "comment": "..."
        }

    Members are resolved at push time across the candidate SMC classes;
    unresolvable members fall back to "any" (legacy behavior preserved).
    Stamps the Q21 audit comment marker. Idempotent on already-exists
    so the import is safely re-runnable.
    """
    name = (payload.get("name") or "").strip()
    policy_name = (payload.get("policy_name") or "").strip()
    if not name or not policy_name:
        return HandlerResult(
            success=False,
            error="rule.create payload missing name or policy_name",
        )

    section_name = (payload.get("section_name") or "").strip() or None
    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""

    try:
        from webapp.smc_audit_marker import pack_audit_into_comment
        policy = _ensure_firewall_policy(policy_name)

        sources = _resolve_member_list(payload.get("sources"))
        destinations = _resolve_member_list(payload.get("destinations"))
        services = _resolve_member_list(payload.get("services"), service=True)

        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )

        kwargs = {
            "name": name,
            "sources": sources,
            "destinations": destinations,
            "services": services,
            "action": payload.get("action") or "allow",
            "is_disabled": bool(payload.get("is_disabled", False)),
            "comment": stamped,
        }

        # Section creation is idempotent; create it if it's missing
        # (the migration writer enqueues sections separately, but if a
        # caller posts a rule with a section that doesn't exist yet we
        # still want this to recover).
        if section_name:
            try:
                policy.fw_ipv4_access_rules.create_rule_section(name=section_name)
            except Exception as exc:
                _, idempotent = _treat_create_outcome(exc)
                if not idempotent:
                    log.debug("rule.create: section create failed (will let "
                              "rule create proceed): %s", exc)

        policy.fw_ipv4_access_rules.create(**kwargs)
        href = ""  # Rules don't expose a persistent href the way elements do.
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)
        href = ""

    _reconcile_smc_object(change, smc_type="rule",
                          smc_name=name, smc_href=href,
                          managed_by_flexedge=True)
    section_label = (f" (section '{section_name}')" if section_name else "")
    return HandlerResult(
        success=True, applied=False,
        detail=f"Rule '{name}' in policy '{policy_name}'{section_label}",
    )


def _create_nat_rule(change, payload: dict) -> HandlerResult:
    """Create a NAT rule in a Firewall policy.

    Payload::

        {
            "smc_type": "nat_rule",
            "policy_name": "...",
            "name": "...",
            "sources": [...]      | "any",
            "destinations": [...] | "any",
            "services": [...]     | "any",
            "is_disabled": false,
            "comment": "...",
            "nat_type": "snat"|"dnat"|"snat+dnat",
            "dynamic_src_nat_name": "..."  | null,  # pre-resolved Host name
            "static_dst_nat_name":  "..."  | null,  # pre-resolved Host name
            "static_dst_nat_ports": [start, end] | null
        }

    The migration enqueue helper resolves IPs → SMC Host names (via
    the import's NAT-host dedup map) before enqueueing, so the handler
    only needs to look elements up by name.
    """
    name = (payload.get("name") or "").strip()
    policy_name = (payload.get("policy_name") or "").strip()
    if not name or not policy_name:
        return HandlerResult(
            success=False,
            error="nat_rule.create payload missing name or policy_name",
        )

    nat_type = (payload.get("nat_type") or "").strip()
    user_email = _user_email_for_change(change)
    operator_comment = payload.get("comment") or ""
    warnings: list[str] = []

    try:
        from webapp.smc_audit_marker import pack_audit_into_comment
        policy = _ensure_firewall_policy(policy_name)

        sources = _resolve_member_list(payload.get("sources"))
        destinations = _resolve_member_list(payload.get("destinations"))
        services = _resolve_member_list(payload.get("services"), service=True)

        stamped = pack_audit_into_comment(
            operator_comment, user_email=user_email,
            previous_value=None,
        )

        kwargs = {
            "name": name,
            "sources": sources,
            "destinations": destinations,
            "services": services,
            "is_disabled": bool(payload.get("is_disabled", False)),
            "comment": stamped,
        }

        if nat_type in ("snat", "snat+dnat"):
            snat_name = (payload.get("dynamic_src_nat_name") or "").strip()
            if snat_name:
                snat_obj = _resolve_element_name(snat_name)
                if snat_obj is not None:
                    kwargs["dynamic_src_nat"] = snat_obj
                    kwargs["dynamic_src_nat_ports"] = (1024, 65535)
                else:
                    warnings.append(f"unresolvable SNAT host '{snat_name}'")

        if nat_type in ("dnat", "snat+dnat"):
            dnat_name = (payload.get("static_dst_nat_name") or "").strip()
            if dnat_name:
                dnat_obj = _resolve_element_name(dnat_name)
                if dnat_obj is not None:
                    kwargs["static_dst_nat"] = dnat_obj
                else:
                    warnings.append(f"unresolvable DNAT host '{dnat_name}'")
            ports = payload.get("static_dst_nat_ports")
            if ports and isinstance(ports, (list, tuple)) and len(ports) == 2:
                if ports[0] and ports[1]:
                    kwargs["static_dst_nat_ports"] = (ports[0], ports[1])

        policy.fw_ipv4_nat_rules.create(**kwargs)
    except Exception as exc:
        detail, idempotent = _treat_create_outcome(exc)
        if not idempotent:
            return HandlerResult(success=False, error=detail)

    _reconcile_smc_object(change, smc_type="nat_rule",
                          smc_name=name, smc_href="",
                          managed_by_flexedge=True)
    warn = (f" (warnings: {', '.join(warnings)})" if warnings else "")
    return HandlerResult(
        success=True, applied=False,
        detail=f"NAT rule [{nat_type}] '{name}' in '{policy_name}'{warn}",
    )


# Dispatch table consumed by `_handle_create`. Defined here — AFTER
# every `_create_<type>` function — so module import succeeds. New
# types: add an entry + write the `_create_<type>` above.
_CREATE_DISPATCH: dict = {
    "host":           _create_host,
    "network":        _create_network,
    "address_range":  _create_address_range,
    "fqdn":           _create_fqdn,
    "tcp_service":    _create_tcp_service,
    "udp_service":    _create_udp_service,
    "group":          _create_group,
    "service_group":  _create_service_group,
    "rule":           _create_rule,
    "nat_rule":       _create_nat_rule,
}


@register_handler("install_ssh_rule")
def _handle_install_ssh_rule(change, cfg) -> HandlerResult:
    """DHCP credentials — install/refresh SSH allow rule + upload policy.

    Bundle (Q19/b internal-orchestrator pattern):
      1. find-or-create source Host element + dest Host elements
      2. find-or-create the rule in the engine's installed policy
      3. upload the policy to the engine

    Persists / refreshes the `DhcpEngineSshAccess` row on success so
    the credentials wizard can see the rule.

    Payload: {engine_name, source_ip, destination_ips, rule_name?,
              fea_hostname?}
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    engine_name = (payload.get("engine_name") or "").strip()
    source_ip = (payload.get("source_ip") or "").strip()
    dest_ips = list(payload.get("destination_ips") or [])
    if not engine_name or not source_ip or not dest_ips:
        return HandlerResult(
            success=False,
            error="install_ssh_rule payload missing engine_name / source_ip / destination_ips",
        )

    rule_name = (payload.get("rule_name") or "").strip() or None
    fea_hostname = payload.get("fea_hostname") or ""
    user_email = _user_email_for_change(change)

    try:
        from webapp.dhcp_bootstrap import (
            engine_bootstrap_lock, install_ssh_rule, upload_policy,
        )
        from webapp.models import DhcpEngineSshAccess
        from shared.db import db
        from datetime import datetime, timezone

        with engine_bootstrap_lock(engine_name):
            result = install_ssh_rule(
                engine_name=engine_name,
                source_ip=source_ip,
                destination_ips=dest_ips,
                created_by_email=user_email,
                fea_hostname=fea_hostname,
                rule_name=rule_name,
            )
            if not result.ok:
                return HandlerResult(success=False,
                                     error=f"install_ssh_rule failed: {result.error}")

            # Persist DB record. Lookup-by-domain so we don't duplicate.
            access = (DhcpEngineSshAccess.query
                      .filter_by(domain_id=change.domain_id,
                                 engine_name=engine_name)
                      .first())
            now = datetime.now(timezone.utc)
            csv_dst = ",".join(dest_ips)
            if access:
                access.policy_name = result.policy_name
                access.rule_name = result.rule_name
                access.rule_href = result.rule_href
                access.fea_source_ip = source_ip
                access.destination_ip = csv_dst
                access.created_by_email = access.created_by_email or user_email
                access.last_seen_in_policy_at = now
                access.state_refreshed_at = now
            else:
                # Look up the Domain so we can fill the legacy tenant_id /
                # api_key_id columns (still referenced by code reading the
                # access row outside of g.domain context).
                from webapp.models import Domain
                domain = db.session.get(Domain, change.domain_id)
                ak = domain.api_key if domain is not None else None
                db.session.add(DhcpEngineSshAccess(
                    domain_id=change.domain_id,
                    tenant_id=ak.tenant_id if ak is not None else None,
                    api_key_id=ak.id if ak is not None else None,
                    engine_name=engine_name,
                    policy_name=result.policy_name,
                    rule_name=result.rule_name,
                    rule_href=result.rule_href,
                    fea_source_ip=source_ip,
                    destination_ip=csv_dst,
                    created_by_email=user_email,
                    last_seen_in_policy_at=now,
                    state_refreshed_at=now,
                ))
            db.session.commit()

            # Reconcile SmcObject for the rule itself so Q12 + drift
            # detection have a record. Best-effort.
            if result.rule_href:
                _reconcile_smc_object(
                    change, smc_type="rule",
                    smc_name=result.rule_name or "",
                    smc_href=result.rule_href,
                    managed_by_flexedge=True,
                )

            upload_ok, upload_msg = upload_policy(engine_name, result.policy_name)
            if not upload_ok:
                return HandlerResult(
                    success=False,
                    error=(f"Rule {result.rule_name} is in policy "
                           f"{result.policy_name} but the upload to the "
                           f"engine FAILED: {upload_msg}. Engine may be "
                           f"running stale policy."),
                )

        detail = (f"rule={result.rule_name} policy={result.policy_name} "
                  f"already_present={result.already_present} "
                  f"source_ip={source_ip!r} upload={upload_msg}")
        return HandlerResult(success=True, applied=True, detail=detail)
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))


@register_handler("deploy_tls")
def _handle_deploy_tls(change, cfg) -> HandlerResult:
    """TLS Manager — deploy a certificate to an engine (Q19/b bundle).

    ONE queue row that internally orchestrates the 5-step pipeline:
      1. Import TLS credential
      2. Create source + dest Host elements
      3. Assign credential to engine TLS inspection
      4. Find-or-create policy rule
      5. Upload policy to engine

    The expanded detail view on `/changes/` renders the per-step status
    list from `step.detail` so the operator sees what ran in order.

    Payload: `{"deployment_id": N, "action": "deploy"|"renew"|"remove"}`.
    Persists the populated `DeployResult` back into the `TLSDeployment`
    row + creates a `TLSDeploymentLog` entry, exactly like the legacy
    `tls_deployer.run_deployment` did.
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    deployment_id = payload.get("deployment_id")
    action = (payload.get("action") or "deploy").strip()
    if not deployment_id:
        return HandlerResult(success=False,
                             error="deploy_tls payload missing deployment_id")

    try:
        from webapp.models import (
            TLSDeployment, ManagedCertificate, TLSDeploymentLog,
        )
        from webapp.tls_deployer import execute_deployment_inside_session
        from shared.db import db
        from datetime import datetime, timezone

        dep = db.session.get(TLSDeployment, int(deployment_id))
        if dep is None:
            return HandlerResult(success=False,
                                 error=f"TLSDeployment #{deployment_id} not found")
        cert = db.session.get(ManagedCertificate, dep.certificate_id)
        if cert is None:
            return HandlerResult(success=False,
                                 error=f"Certificate #{dep.certificate_id} not found")

        fullchain = f"{cert.certbot_lineage}/fullchain.pem"
        privkey = f"{cert.certbot_lineage}/privkey.pem"

        # Run the 5-step pipeline inside the session opened by push_one().
        result = execute_deployment_inside_session(dep, fullchain, privkey)

        # Persist result into the TLSDeployment row.
        dep.last_deployed_at = datetime.now(timezone.utc)
        dep.last_status = "deployed" if result.success else "failed"
        dep.last_error = result.error or ""
        dep.tls_credential_name = result.tls_credential_name or dep.tls_credential_name
        dep.host_public_name = result.host_public_name or dep.host_public_name
        dep.host_private_name = result.host_private_name or dep.host_private_name
        dep.policy_rule_name = result.policy_rule_name or dep.policy_rule_name
        dep.policy_section_name = result.policy_section_name or dep.policy_section_name

        db.session.add(TLSDeploymentLog(
            deployment_id=dep.id, action=action,
            status="success" if result.success else "failed",
            details=str(result.steps),
        ))
        db.session.commit()

        # Reconcile SmcObject for the rule (so Q12 + drift detection
        # have a record). Best-effort.
        if result.policy_rule_name:
            _reconcile_smc_object(
                change, smc_type="rule",
                smc_name=result.policy_rule_name,
                smc_href="",
                managed_by_flexedge=True,
            )

        if not result.success:
            return HandlerResult(success=False,
                                 error=result.error or "Deployment failed")

        # The expanded queue detail will surface the steps via
        # `change.payload_json` reading; we shove them in alongside
        # the original payload so the queue UI can render them.
        try:
            payload["steps"] = result.steps
            change.payload_json = _json.dumps(payload)
            db.session.commit()
        except Exception:
            pass

        steps_summary = " → ".join(
            f"{s.get('name')}={s.get('status')}" for s in result.steps
        )
        detail = (f"TLS deployment #{dep.id} ({dep.service_name}) "
                  f"on engine {dep.engine_name}: {steps_summary}")
        return HandlerResult(success=True, applied=True, detail=detail)
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))


@register_handler("deploy_vpn")
def _handle_deploy_vpn(change, cfg) -> HandlerResult:
    """FortiGate migration — VPN config deployment (Q19/b bundle).

    ONE queue row per VPN config. The handler drives the 6-step
    pipeline internally (VPN profile → external gateway → endpoint →
    VPN site → PolicyVPN → topology) and writes per-step status into
    `payload.steps[]` so the queue UI's expanded detail panel renders
    the same per-step badges as TLS deploy.

    Payload: ``{"smc_type": "vpn", "config": {...}, "engine_name": "..."}``
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    config = payload.get("config") or {}
    engine_name = (payload.get("engine_name") or "").strip() or None
    tunnel_name = (config.get("name") or "").strip()
    if not tunnel_name:
        return HandlerResult(success=False,
                             error="deploy_vpn payload missing config.name")

    try:
        from webapp.migration_vpn_writer import (
            execute_vpn_pipeline_inside_session,
        )
        result = execute_vpn_pipeline_inside_session(config, engine_name)
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))

    # Reconcile the SmcObject for the PolicyVPN so Q12 + drift have
    # something to attach to.
    if result.policy_name:
        _reconcile_smc_object(
            change, smc_type="policy_vpn",
            smc_name=result.policy_name, smc_href="",
            managed_by_flexedge=True,
        )

    # Persist the per-step trace in payload_json so the queue UI's
    # expanded detail can render the ordered list of sub-steps.
    try:
        payload["steps"] = result.steps
        change.payload_json = _json.dumps(payload)
        from shared.db import db
        db.session.commit()
    except Exception:
        pass

    if not result.success:
        return HandlerResult(success=False,
                             error=result.error or "VPN deployment failed")

    steps_summary = " → ".join(
        f"{s.get('name')}={s.get('status')}" for s in result.steps
    )
    detail = (f"VPN '{tunnel_name}' "
              f"(profile={result.profile_name!r} gw={result.gateway_name!r} "
              f"policy={result.policy_name!r}): {steps_summary}")
    return HandlerResult(success=True, applied=True, detail=detail)


@register_handler("remove_ssh_rule")
def _handle_remove_ssh_rule(change, cfg) -> HandlerResult:
    """DHCP credentials — remove SSH allow rule + upload policy.

    Payload: {engine_name, policy_name?, rule_name?}

    DB-side `DhcpEngineSshAccess` row removal happens in the calling
    route after the push succeeds — keeps retry semantics clean (a
    failed first attempt leaves the access row so retry can find it).
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    engine_name = (payload.get("engine_name") or "").strip()
    if not engine_name:
        return HandlerResult(success=False,
                             error="remove_ssh_rule payload missing engine_name")
    policy_name = (payload.get("policy_name") or "").strip() or None

    try:
        from webapp.dhcp_bootstrap import (
            engine_bootstrap_lock, remove_rule, upload_policy,
        )
        with engine_bootstrap_lock(engine_name):
            ok, msg = remove_rule(engine_name, policy_name)
            if not ok:
                return HandlerResult(success=False, error=f"remove_rule: {msg}")

            upload_ok, upload_msg = upload_policy(engine_name, policy_name)
            if not upload_ok:
                return HandlerResult(
                    success=False,
                    error=(f"Rule removed but policy upload failed: {upload_msg}"),
                )
        return HandlerResult(
            success=True, applied=True,
            detail=f"rule removed + policy uploaded: {upload_msg}",
        )
    except Exception as exc:
        return HandlerResult(success=False, error=str(exc))


# ── SmcObject registry reconciliation ────────────────────────────────────
#
# When a `create` handler succeeds, the SMC element now has an authoritative
# href — we record it (or update the linked SmcObject row in place) so
# Q12 strikethrough, drift detection, and later writers have a consistent
# registry to query.

def _reconcile_smc_object(change, *, smc_type: str, smc_name: str,
                          smc_href: str,
                          managed_by_flexedge: bool | None = None) -> None:
    """Upsert the SmcObject row for this change's target.

    Logic:
      * If `change.smc_object` is already linked, update its href/name.
      * Else look up by (domain_id, smc_href). Create if missing; link.

    Failure swallowed (logged) — registry maintenance is best-effort and
    must never fail the surrounding push.
    """
    try:
        from shared.db import db
        from webapp.models import SmcObject

        if change.smc_object is not None:
            obj = change.smc_object
            obj.smc_type = smc_type or obj.smc_type
            obj.smc_name = smc_name or obj.smc_name
            obj.smc_href = smc_href or obj.smc_href
            if managed_by_flexedge is not None:
                obj.managed_by_flexedge = managed_by_flexedge
            obj.last_seen_at = _utcnow()
            db.session.commit()
            return

        existing = (SmcObject.query
                    .filter_by(domain_id=change.domain_id, smc_href=smc_href)
                    .first())
        if existing is None:
            existing = SmcObject(
                domain_id=change.domain_id,
                smc_href=smc_href,
                smc_type=smc_type,
                smc_name=smc_name,
                managed_by_flexedge=bool(managed_by_flexedge),
            )
            db.session.add(existing)
            db.session.flush()
        else:
            existing.smc_type = smc_type or existing.smc_type
            existing.smc_name = smc_name or existing.smc_name
            existing.last_seen_at = _utcnow()
            if managed_by_flexedge is True:
                existing.managed_by_flexedge = True

        change.smc_object_id = existing.id
        db.session.commit()
    except Exception as exc:
        log.warning("queue_runner: smc_object reconcile failed (change=#%s): %s",
                    change.id, exc)


def _retire_smc_object(change) -> None:
    """Mark the SmcObject row as no-longer-present after a successful delete.

    We DELETE the row rather than soft-flagging — keeping a stale registry
    row would re-surface drift warnings and confuse listings. The audit
    trail in `platform_logs` retains the full history.
    """
    try:
        from shared.db import db
        if change.smc_object is not None:
            db.session.delete(change.smc_object)
            change.smc_object_id = None
            db.session.commit()
    except Exception as exc:
        log.warning("queue_runner: smc_object retire failed (change=#%s): %s",
                    change.id, exc)
