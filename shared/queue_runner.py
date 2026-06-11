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
    """Decorator to attach a handler to an operation type.

    Audit L6 (2026-06-11): a DIFFERENT function re-registering an
    operation now raises instead of silently replacing — that was a
    developer footgun (a copy-pasted handler name would hijack an
    existing operation with only a log line to show for it).
    Re-registering the *same* function stays a no-op so dual import
    paths (``webapp.x`` vs ``x``) don't explode.
    """
    def decorator(fn: Callable) -> Callable:
        existing = _HANDLERS.get(operation)
        if existing is not None:
            # "Same function" = same source location — robust against the
            # module being imported under two names (webapp.x vs x).
            def _loc(f):
                code = getattr(f, "__code__", None)
                return (getattr(code, "co_filename", None),
                        getattr(code, "co_firstlineno", None))
            if _loc(existing) != _loc(fn):
                raise ValueError(
                    f"queue_runner: handler for operation={operation!r} "
                    f"already registered ({existing.__name__}); refusing to "
                    f"replace with {fn.__name__}. Pick a distinct operation "
                    f"name or remove the stale registration."
                )
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


def _audit(action: str, change, *, status: str = "ok", detail: str = "",
           commit: bool = True):
    """Emit a `feature="changes"` audit log entry for a state transition.

    H9 (audit fix-up, 2026-05-09): pass ``commit=False`` to enrol the
    audit row into the caller's open transaction so the state change +
    audit row commit atomically. The caller must then call
    ``db.session.commit()`` to persist both at once.
    """
    try:
        from shared.logging import audit
        audit(
            feature="changes", action=action,
            target=_describe(change), detail=detail, status=status,
            source_correlation_id=change.source_correlation_id,
            domain_id=change.domain_id,
            commit=commit,
        )
    except Exception as exc:
        log.warning("queue_runner: audit emit failed (%s, change=#%s): %s",
                    action, change.id, exc)


def _invalidate_cache_for_change(change):
    """Best-effort: drop SMC read-cache entries that just went stale.

    Mapping is approximate — we err on the side of "drop more than
    needed" rather than "leave a stale row visible". Failures are
    logged but never propagated.

    Phase 0 (2026-05-09): section names are now short / object-type-keyed
    via `webapp.domain_objects`. Old long-form names (``engines.list``,
    ``engines.detail``, ``smc.policy``, ``smc.explorer.<type>``,
    ``smc.element.<type>``) are retired.
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
        # Engine state changed — drop engines + cluster + policy caches.
        # ``cluster`` and ``policy`` are multi-key sections — we drop the
        # specific entry when payload tells us which engine/policy, and
        # fall back to the whole section otherwise (over-invalidate).
        sections.append(("engines", None))
        try:
            payload = _json.loads(change.payload_json or "{}")
            engine = payload.get("engine_name")
            if engine:
                sections.append(
                    ("cluster", (change.domain_id, engine)))
                # Engine config changed → DHCP scope discovery may have
                # shifted too. Cheap to drop, never wrong.
                sections.append(
                    ("scopes", (change.domain_id, engine)))
            policy = payload.get("policy_name")
            if policy:
                sections.append(
                    ("policy", (change.domain_id, policy)))
        except Exception:
            pass
    elif smc_type in ("rule", "nat_rule", "section"):
        # Rule lives in a policy — drop the whole ``policy`` section
        # since we don't always know which policy from the change row.
        sections.append(("policy", None))
    elif smc_type:
        # Plain element types: drop the list + per-element detail so a
        # freshly created/updated element shows up everywhere on next
        # read. Q11 fix (2026-06-12): section names use the PLURAL
        # browse key (`element_list.hosts`), not the registry's singular
        # smc_type — `smc_cache.invalidate_for_smc_type` maps it (and
        # also drops `dhcp_host` for hosts, which back reservations).
        try:
            n = smc_cache.invalidate_for_smc_type(smc_type)
            if n:
                log.debug("queue_runner: invalidated %d cache entry(ies) "
                          "for smc_type=%s", n, smc_type)
        except Exception as exc:
            log.debug("queue_runner: cache invalidate failed for "
                      "smc_type=%s: %s", smc_type, exc)

    for section, key_parts in sections:
        try:
            n = smc_cache.invalidate(section, key_parts)
            if n:
                log.debug("queue_runner: invalidated %d cache entry(ies) "
                          "in section=%s", n, section)
        except Exception as exc:
            log.debug("queue_runner: cache invalidate failed for %s: %s",
                      section, exc)


# ── SMC error humanizer ──────────────────────────────────────────────────
#
# Every handler funnels its failure string through `_mark_push_failed`
# below. Wrapping that one chokepoint with a tiny pattern-matcher means
# every handler — install_ssh_rule, deploy_tls, create_*, upload_policy,
# anything future — automatically picks up clearer remediation hints
# without touching individual handlers.
#
# Patterns are conservative: we prepend a one-liner remediation, then
# include the raw SMC error verbatim so debugging never loses signal.
# Anything unmatched falls through unchanged.

def _humanize_smc_error(exc_msg: str) -> str:
    """Detect well-known SMC failure classes and prepend a remediation
    hint. Returns the unchanged message when nothing matches.
    """
    if not exc_msg:
        return exc_msg
    s = exc_msg.lower()

    # Policy lock contention — another SMC session is editing this
    # policy and holds its lock. Common SMC phrasings observed in the
    # wild:
    #   "policy is locked by user <name>"
    #   "policy <X> is currently locked"
    #   "the element is currently locked by another administrator"
    #   "cannot obtain lock on the policy"
    #   "lock is owned by"
    lock_signals = (
        "policy is locked",
        "is currently locked",
        "currently locked by",
        "locked by another",
        "locked by the user",
        "locked by user",
        "cannot obtain lock",
        "lock is owned by",
        "unable to obtain lock",
    )
    if any(sig in s for sig in lock_signals):
        return ("Policy is locked by another SMC session — somebody is "
                "currently editing it in SMC Management Client (or another "
                "automation holds the lock). Ask the holder to commit or "
                "discard their changes, then retry this row from /changes/. "
                f"[raw: {exc_msg}]")

    return exc_msg


# ── State-transition primitives ──────────────────────────────────────────
#
# C7 + H9 + H11 (audit fix-up, 2026-05-09):
#
# C7: every transition out of a "claimable" state goes through an atomic
#     ``UPDATE pending_changes SET state=<new> WHERE id=? AND state=<old>``
#     and only proceeds when ``rowcount == 1``. SMC ``create`` is not
#     idempotent — without an atomic claim, two threads (or a double-click,
#     or push_batch + a concurrent push_one for the same id) both reach
#     the handler and we get duplicate Hosts / conflicts. The claim adds
#     a transient ``pushing`` state that lives only between push_one()
#     entry and the terminal commit.
# H9: state-transition + audit row commit atomically. Before this fix,
#     ``commit; _audit(...)`` left a short window where a process kill
#     produced PUSHED rows with no audit trail. ``_audit(commit=False)``
#     enrols the audit row into the same session; the surrounding
#     ``db.session.commit()`` lands both rows together.
# H11: implicit. With C7's atomic UPDATE, the stale-read in push_batch
#     (no ``expire_all()`` between iterations) becomes harmless — the
#     UPDATE either claims or returns rowcount=0 and we skip.


def _claim_for_push(change_id: int) -> Optional[str]:
    """Atomically transition a row from QUEUED to PUSHING.

    Returns the prior state (always ``"queued"``) when the claim wins,
    or ``None`` when the row no longer exists in queued state — meaning
    a concurrent worker already claimed / completed / aborted it.
    Caller MUST refresh the in-memory ORM row after a successful claim
    (``db.session.expire_all()`` in caller pattern) so the row's state
    column reflects ``"pushing"`` and any subsequent commit isn't a
    stale-write from earlier read.
    """
    from shared.db import db
    from webapp.models import PendingChange
    rowcount = (
        db.session.query(PendingChange)
        .filter(PendingChange.id == change_id,
                PendingChange.state == "queued")
        .update({"state": "pushing"}, synchronize_session=False)
    )
    db.session.commit()
    if rowcount == 1:
        return "queued"
    return None


def _claim_for_abort(change_id: int) -> Optional[str]:
    """Atomically transition QUEUED|CONFLICT → ABORTED.

    Returns the prior state on success, ``None`` on lost claim.
    """
    from shared.db import db
    from webapp.models import PendingChange
    rowcount = (
        db.session.query(PendingChange)
        .filter(PendingChange.id == change_id,
                PendingChange.state.in_(("queued", "conflict")))
        .update({"state": "aborted"}, synchronize_session=False)
    )
    db.session.commit()
    return "queued_or_conflict" if rowcount == 1 else None


def _mark_pushed(change, *, applied: bool, detail: str = ""):
    """PUSHING → PUSHED (or APPLIED). Atomic with audit row.

    Caller must have already won the claim via ``_claim_for_push``.
    Both the state transition AND the audit row land in one commit so
    a process kill mid-operation can't leave a state-change without an
    audit trail.
    """
    from shared.db import db
    new_state = "applied" if applied else "pushed"
    change.state = new_state
    change.transitioned_at = _utcnow()
    change.transitioned_by_id = _current_user_id()
    change.push_error_text = ""
    change.push_error_at = None
    _audit(f"push.{new_state}", change, detail=detail, commit=False)
    db.session.commit()
    _invalidate_cache_for_change(change)


def _mark_push_failed(change, error: str):
    """PUSHING → PUSH_FAILED. Atomic with audit row.

    Runs the raw error through `_humanize_smc_error` so well-known SMC
    failure classes (policy lock, etc.) get a clearer remediation hint
    prepended before the operator sees them on /changes/. The audit log
    receives the same humanised text so /logs is consistent.
    """
    from shared.db import db
    friendly = _humanize_smc_error(error or "")
    change.state = "push_failed"
    change.push_error_text = friendly[:4000]
    change.push_error_at = _utcnow()
    _audit("push.failed", change, status="failed", detail=friendly,
           commit=False)
    db.session.commit()


def _mark_aborted_via_claim(change, reason: str = ""):
    """Audit-and-stamp helper called AFTER ``_claim_for_abort`` won.

    The state column is already ``aborted`` (set by the atomic claim's
    UPDATE). This stamps the rest of the row's metadata + emits the
    audit entry, atomically with the metadata commit.
    """
    from shared.db import db
    change.transitioned_at = _utcnow()
    change.transitioned_by_id = _current_user_id()
    if reason:
        change.push_error_text = (reason or "")[:4000]
    _audit("abort", change, detail=reason or "operator abort", commit=False)
    db.session.commit()


# ── Public API ────────────────────────────────────────────────────────────

def push_one(change_id: int) -> PushResult:
    """Push a single QUEUED PendingChange against SMC.

    C7 (audit fix-up, 2026-05-09): atomic state-claim. The runner does
    a single ``UPDATE pending_changes SET state='pushing' WHERE id=? AND
    state='queued'``; only the worker whose UPDATE returned ``rowcount=1``
    proceeds to call the SMC handler. A double-clicked Push button or
    parallel push_batch + push_one returns ``skipped=True`` for the
    losing thread instead of double-firing the handler (SMC ``create``
    is not idempotent — duplicate fires produced duplicate Hosts).
    """
    from webapp.models import PendingChange
    from shared.db import db

    change = db.session.get(PendingChange, change_id)
    if change is None:
        return PushResult(failed=True, error="Change not found",
                          change_id=change_id)

    # Soft pre-checks — these don't claim, but they avoid the UPDATE
    # round-trip for rows that obviously aren't pushable.
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

    # Atomic claim — the only race-safe gate before the handler runs.
    if _claim_for_push(change_id) is None:
        log.debug("push_one: change #%s claim lost (concurrent worker won)",
                  change_id)
        return PushResult(skipped=True, change_id=change_id,
                          error="State changed concurrently")
    # Refresh ORM after the bare-SQL UPDATE so subsequent commits aren't
    # stale-writes (H11 — same fix that closes push_batch's stale-read).
    db.session.expire_all()
    change = db.session.get(PendingChange, change_id)
    if change is None:
        return PushResult(failed=True, error="Change vanished after claim",
                          change_id=change_id)

    handler = _HANDLERS.get(change.operation)
    if handler is None:
        msg = f"No handler registered for operation={change.operation!r}"
        _mark_push_failed(change, msg)
        return PushResult(failed=True, change_id=change_id,
                          state="push_failed", error=msg)

    # Audit L12 (2026-06-11): commit=False — the push.start row rides
    # the outcome transaction (_mark_pushed / _mark_push_failed both
    # commit), halving the runner's per-row audit commits. On a
    # process kill mid-handler the start marker is lost along with the
    # outcome, but the stuck state='pushing' row already surfaces that
    # case to operators (C7 UI).
    _audit("push.start", change, commit=False)

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
    """Abort a QUEUED or CONFLICT row. Returns True if state changed.

    C7 (audit fix-up, 2026-05-09): atomic transition — same idempotency
    guarantees as push_one. A user clicking Abort while another worker is
    racing to Push the same row will reliably produce one winner.
    """
    from webapp.models import PendingChange
    from shared.db import db

    if _claim_for_abort(change_id) is None:
        return False
    db.session.expire_all()
    change = db.session.get(PendingChange, change_id)
    if change is None:
        return False
    _mark_aborted_via_claim(change, reason=reason)
    return True


def confirm_to_be_deleted(change_id: int) -> PushResult:
    """Global / Super Admin confirms an Operator-submitted delete.

    Transitions the row's operation `to_be_deleted` → `delete`, leaves
    `state='queued'`, then immediately calls `push_one()` so the actual
    SMC delete fires. The `smc_objects.is_to_be_deleted` flag is left in
    place during PUSH so list-views still strikethrough the row; the
    flag is cleared by the `delete` handler on success.

    C7 (audit fix-up, 2026-05-09): atomic operation flip via UPDATE +
    rowcount==1 check, so a double-Confirm or Confirm-vs-Revoke race
    can't double-trigger.
    """
    from webapp.models import PendingChange
    from shared.db import db

    rowcount = (
        db.session.query(PendingChange)
        .filter(PendingChange.id == change_id,
                PendingChange.operation == "to_be_deleted",
                PendingChange.state == "queued")
        .update({"operation": "delete"}, synchronize_session=False)
    )
    db.session.commit()
    if rowcount != 1:
        change = db.session.get(PendingChange, change_id)
        if change is None:
            return PushResult(failed=True, error="Change not found",
                              change_id=change_id)
        return PushResult(skipped=True, change_id=change_id,
                          error=f"Not a queued to_be_deleted row "
                                f"(op={change.operation}, state={change.state})")

    db.session.expire_all()
    change = db.session.get(PendingChange, change_id)
    _audit("to_be_deleted.confirm", change,
           detail="Operator-submitted delete confirmed → operation=delete")
    return push_one(change_id)


def revoke_to_be_deleted(change_id: int, reason: str = "") -> bool:
    """Global / Super Admin revokes an Operator-submitted delete.

    Transitions the row to ABORTED and clears the
    `smc_objects.is_to_be_deleted` flag so list-views stop showing
    strikethrough. The object stays in SMC unchanged.

    C7 (audit fix-up, 2026-05-09): atomic claim, same idempotency
    guarantees as the other transitions.
    """
    from webapp.models import PendingChange
    from shared.db import db

    rowcount = (
        db.session.query(PendingChange)
        .filter(PendingChange.id == change_id,
                PendingChange.operation == "to_be_deleted",
                PendingChange.state == "queued")
        .update({"state": "aborted"}, synchronize_session=False)
    )
    db.session.commit()
    if rowcount != 1:
        return False

    db.session.expire_all()
    change = db.session.get(PendingChange, change_id)
    if change is None:
        return False
    if change.smc_object is not None:
        change.smc_object.is_to_be_deleted = False
    change.transitioned_at = _utcnow()
    change.transitioned_by_id = _current_user_id()
    if reason:
        change.push_error_text = (reason or "")[:4000]
    _audit("to_be_deleted.revoke", change,
           detail=reason or "revoked", commit=False)
    db.session.commit()
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

            # Persist DB record. Check both new (domain_id) and legacy
            # (tenant_id) uniqueness to avoid hitting the vestigial
            # UNIQUE(tenant_id, engine_name) constraint on a stale row
            # from a previous Domain. Same pattern as credentials + scopes.
            from webapp.models import Domain
            domain = db.session.get(Domain, change.domain_id)
            ak = domain.api_key if domain is not None else None
            legacy_tenant_id = ak.tenant_id if ak is not None else None
            access = (DhcpEngineSshAccess.query
                      .filter_by(domain_id=change.domain_id,
                                 engine_name=engine_name)
                      .first())
            if access is None and legacy_tenant_id is not None:
                access = (DhcpEngineSshAccess.query
                          .filter_by(tenant_id=legacy_tenant_id,
                                     engine_name=engine_name)
                          .first())
            now = datetime.now(timezone.utc)
            csv_dst = ",".join(dest_ips)
            if access:
                access.domain_id = change.domain_id  # backfill if NULL on legacy row
                access.tenant_id = legacy_tenant_id
                access.api_key_id = ak.id if ak is not None else None
                access.policy_name = result.policy_name
                access.rule_name = result.rule_name
                access.rule_href = result.rule_href
                access.fea_source_ip = source_ip
                access.destination_ip = csv_dst
                access.created_by_email = access.created_by_email or user_email
                access.last_seen_in_policy_at = now
                access.state_refreshed_at = now
            else:
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


# ── Let's Encrypt cert lifecycle (Roadmap item 5, Phase LE.2) ────────────
#
# Three discrete ops per Q6c — cert_request, cert_renew, cert_revoke.
# All three drive the certbot subprocess in `webapp/letsencrypt_certbot.py`
# and persist the result into the linked `ManagedCertificate` row.
#
# Note: the SMC session opened by `push_one()` is unused here — cert
# operations don't talk to SMC. The session-open overhead is one-time
# per cert operation and is left as-is to keep the queue handler shape
# uniform.

@register_handler("cert_request")
def _handle_cert_request(change, cfg) -> HandlerResult:
    """Issue a new Let's Encrypt cert via HTTP-01.

    Payload: `{"certificate_id": N}`. The ManagedCertificate row was
    created in pending state by the request route; we look it up,
    run certbot, and persist the outcome.

    Q6 allowlist is re-checked here defensively — the request route
    already validated, but a race or a payload-tamper attempt would
    slip past without this guard.
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    cert_id = payload.get("certificate_id")
    if not cert_id:
        return HandlerResult(success=False,
                             error="cert_request payload missing certificate_id")

    try:
        from shared.db import db
        from webapp.models import ManagedCertificate, AcmeAccount
        from webapp.letsencrypt_certbot import request_certificate
        from webapp.letsencrypt_allowlist import is_fqdn_allowed_for_domain

        cert = db.session.get(ManagedCertificate, int(cert_id))
        if cert is None:
            return HandlerResult(success=False,
                                 error=f"ManagedCertificate #{cert_id} not found")

        # Defensive re-check of the allowlist. If the row was created in
        # one Domain and the change row's domain_id was tampered to
        # point at another, this catches it before certbot fires.
        if change.domain_id != cert.domain_id:
            return HandlerResult(
                success=False,
                error=(f"domain mismatch: change.domain_id={change.domain_id} "
                       f"vs cert.domain_id={cert.domain_id}"),
            )
        if cert.domain_id is not None:
            allowed, reason = is_fqdn_allowed_for_domain(
                cert.domain, cert.domain_id,
            )
            if not allowed:
                cert.status = "failed"
                cert.last_error = f"allowlist refused: {reason}"
                db.session.commit()
                return HandlerResult(
                    success=False,
                    error=f"allowlist refused {cert.domain!r}: {reason}",
                )

        account = db.session.get(AcmeAccount, cert.account_id) if cert.account_id else None
        if account is None:
            # Fall back to the singleton row if account_id wasn't stamped.
            account = AcmeAccount.query.first()
        if account is None:
            cert.status = "failed"
            cert.last_error = "no AcmeAccount configured — run /tls/letsencrypt setup first"
            db.session.commit()
            return HandlerResult(
                success=False,
                error="no AcmeAccount configured (run setup wizard at /tls/letsencrypt first)",
            )

        # LE.4 (2026-05-29) — branch on challenge_type. DNS-01 needs a
        # multi-step flow (open order → operator publishes TXT → resume).
        # The cert stays in status='pending' after this handler returns
        # successfully; the operator-clicked "I've published" path
        # enqueues cert_dns_verify which finalizes.
        if cert.challenge_type == "dns01_manual":
            import base64
            try:
                from webapp.letsencrypt_acme import start_dns01_order, AcmeError
            except ImportError as exc:
                cert.status = "failed"
                cert.last_error = f"ACME library missing — pip install acme: {exc}"
                db.session.commit()
                return HandlerResult(success=False, error=str(exc))
            try:
                details = start_dns01_order(
                    fqdn=cert.domain,
                    is_staging=bool(cert.is_staging or account.is_staging),
                )
            except AcmeError as exc:
                cert.status = "failed"
                cert.last_error = f"DNS-01 order start failed: {exc}"[:1500]
                db.session.commit()
                return HandlerResult(success=False, error=str(exc))
            # Stash everything the verify step needs into the cert row.
            # cert_key_pem is base64'd so the JSON stays ASCII-safe.
            cert.dns_challenge_record_name = details.record_name
            cert.dns_challenge_record_value = details.record_value
            cert.dns_challenge_state = _json.dumps({
                "order_uri": details.order_uri,
                "challenge_uri": details.challenge_uri,
                "authz_uri": details.authz_uri,
                "cert_key_pem_b64": base64.b64encode(details.cert_key_pem).decode("ascii"),
                "stage": "awaiting_dns",
                "ready_at": _utcnow().isoformat(),
            })
            cert.last_error = ""
            cert.last_checked_at = _utcnow()
            db.session.commit()
            return HandlerResult(
                success=True, applied=True,
                detail=(f"DNS-01 order opened for {cert.domain}; "
                        f"operator must publish TXT at {details.record_name} "
                        f"then click verify."),
            )

        result = request_certificate(
            fqdn=cert.domain,
            email=account.email,
            is_staging=bool(cert.is_staging or account.is_staging),
        )

        if result.success:
            cert.status = "active"
            cert.last_error = ""
            cert.certbot_lineage = result.lineage or cert.certbot_lineage
            cert.last_checked_at = _utcnow()
            cert.next_renewal_after = result.next_renewal_after
            db.session.commit()
            return HandlerResult(
                success=True, applied=True,
                detail=(f"issued via {'staging' if cert.is_staging else 'production'} "
                        f"in {result.duration_ms}ms; lineage={result.lineage}"),
            )
        else:
            cert.status = "failed"
            # Keep the tail short enough to fit in audit + UI without
            # truncation drama.
            cert.last_error = (result.error or "certbot failed")[:1500]
            db.session.commit()
            return HandlerResult(
                success=False,
                error=(f"{result.error}\n--- stderr tail ---\n"
                       f"{result.stderr_tail}"),
            )
    except Exception as exc:
        log.exception("cert_request handler raised")
        return HandlerResult(success=False, error=str(exc))


@register_handler("cert_renew")
def _handle_cert_renew(change, cfg) -> HandlerResult:
    """Renew an existing cert. Phase LE.3 wires the scheduler to enqueue
    these automatically; for LE.2 the operator triggers via the "Force
    renew" button on the cert detail page.
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    cert_id = payload.get("certificate_id")
    if not cert_id:
        return HandlerResult(success=False,
                             error="cert_renew payload missing certificate_id")

    try:
        from shared.db import db
        from webapp.models import ManagedCertificate
        from webapp.letsencrypt_certbot import renew_certificate

        cert = db.session.get(ManagedCertificate, int(cert_id))
        if cert is None:
            return HandlerResult(success=False,
                                 error=f"ManagedCertificate #{cert_id} not found")

        result = renew_certificate(
            fqdn=cert.domain,
            is_staging=bool(cert.is_staging),
        )

        if result.success:
            cert.status = "active"
            cert.last_error = ""
            cert.last_checked_at = _utcnow()
            cert.next_renewal_after = result.next_renewal_after
            db.session.commit()
            return HandlerResult(
                success=True, applied=True,
                detail=f"renewed in {result.duration_ms}ms",
            )
        else:
            cert.last_error = (result.error or "certbot renew failed")[:1500]
            # Don't flip status to 'failed' on a renew miss — the cert
            # is still valid until expiry, just the latest renew try
            # didn't land. Operator retries.
            db.session.commit()
            return HandlerResult(
                success=False,
                error=(f"{result.error}\n--- stderr tail ---\n"
                       f"{result.stderr_tail}"),
            )
    except Exception as exc:
        log.exception("cert_renew handler raised")
        return HandlerResult(success=False, error=str(exc))


@register_handler("cert_revoke")
def _handle_cert_revoke(change, cfg) -> HandlerResult:
    """Revoke + delete a cert. UI for this lands in Phase LE.5; the
    handler is registered now so the queue op exists and PendingChange
    rows can carry it.
    """
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    cert_id = payload.get("certificate_id")
    if not cert_id:
        return HandlerResult(success=False,
                             error="cert_revoke payload missing certificate_id")
    reason = (payload.get("reason") or "unspecified").strip()
    # LE.5.b (LE-Q3=B): when True, ORM-delete the cert row after a
    # successful revoke. Chains "Revoke at LE" → "Stop tracking in FEA"
    # into one operator action while keeping the two concepts distinct.
    also_stop_tracking = bool(payload.get("also_stop_tracking", False))

    try:
        from shared.db import db
        from webapp.models import ManagedCertificate
        from webapp.letsencrypt_certbot import revoke_certificate

        cert = db.session.get(ManagedCertificate, int(cert_id))
        if cert is None:
            return HandlerResult(success=False,
                                 error=f"ManagedCertificate #{cert_id} not found")

        fqdn = cert.domain
        result = revoke_certificate(
            fqdn=fqdn,
            is_staging=bool(cert.is_staging),
            reason=reason,
        )

        if result.success:
            if also_stop_tracking:
                # Chain — drop the FEA row. The PendingChange FK is
                # ondelete=SET NULL (models.py) so this row's reference
                # to the cert is cleared automatically. The certbot
                # files on disk are NOT purged here (operator can run
                # certbot delete manually); LE.4 follow-up could add an
                # optional purge_lineage flag mirroring cert_delete.
                db.session.delete(cert)
                db.session.commit()
                return HandlerResult(
                    success=True, applied=True,
                    detail=(f"revoked + stopped tracking in "
                            f"{result.duration_ms}ms (reason={reason})"),
                )
            cert.status = "revoked"
            cert.last_error = ""
            cert.last_checked_at = _utcnow()
            db.session.commit()
            return HandlerResult(
                success=True, applied=True,
                detail=f"revoked in {result.duration_ms}ms (reason={reason})",
            )
        else:
            cert.last_error = (result.error or "certbot revoke failed")[:1500]
            db.session.commit()
            return HandlerResult(
                success=False,
                error=(f"{result.error}\n--- stderr tail ---\n"
                       f"{result.stderr_tail}"),
            )
    except Exception as exc:
        log.exception("cert_revoke handler raised")
        return HandlerResult(success=False, error=str(exc))


@register_handler("cert_dns_verify")
def _handle_cert_dns_verify(change, cfg) -> HandlerResult:
    """LE.4 — operator clicked "I've published the TXT record".

    Reads the order/challenge/authz URIs + the stashed cert private
    key from ``cert.dns_challenge_state`` (JSON blob written by the
    cert_request handler's DNS-01 branch), answers the challenge,
    polls the authz, finalizes the order, and saves the cert files
    in the certbot layout. On success: cert.status='active' +
    certbot_lineage populated + next_renewal_after stamped — same
    shape as a successful HTTP-01 cert.
    """
    import base64
    try:
        payload = _json.loads(change.payload_json or "{}")
    except Exception as exc:
        return HandlerResult(success=False, error=f"Invalid payload JSON: {exc}")

    cert_id = payload.get("certificate_id")
    if not cert_id:
        return HandlerResult(
            success=False, error="cert_dns_verify payload missing certificate_id",
        )

    try:
        from shared.db import db
        from webapp.models import ManagedCertificate
        from webapp.letsencrypt_acme import finalize_dns01_order, AcmeError

        cert = db.session.get(ManagedCertificate, int(cert_id))
        if cert is None:
            return HandlerResult(
                success=False, error=f"ManagedCertificate #{cert_id} not found",
            )
        if cert.challenge_type != "dns01_manual":
            return HandlerResult(
                success=False,
                error=f"cert {cert_id} is not a DNS-01 cert "
                      f"(challenge_type={cert.challenge_type!r})",
            )
        if cert.status != "pending":
            return HandlerResult(
                success=False,
                error=f"cert {cert_id} is in status={cert.status!r}; "
                      "verify only valid for pending DNS-01 certs.",
            )
        if not cert.dns_challenge_state:
            return HandlerResult(
                success=False,
                error="cert has no DNS-01 state stashed — order was never opened",
            )
        try:
            stash = _json.loads(cert.dns_challenge_state)
        except Exception as exc:
            cert.status = "failed"
            cert.last_error = f"cert dns_challenge_state is corrupted: {exc}"
            db.session.commit()
            return HandlerResult(success=False, error=str(exc))

        try:
            cert_key_pem = base64.b64decode(stash["cert_key_pem_b64"])
            lineage, next_renewal_after = finalize_dns01_order(
                fqdn=cert.domain,
                is_staging=bool(cert.is_staging),
                challenge_uri=stash["challenge_uri"],
                authz_uri=stash["authz_uri"],
                order_uri=stash["order_uri"],
                cert_key_pem=cert_key_pem,
            )
        except AcmeError as exc:
            cert.status = "failed"
            cert.last_error = f"DNS-01 verify failed: {exc}"[:1500]
            db.session.commit()
            return HandlerResult(success=False, error=str(exc))

        cert.status = "active"
        cert.certbot_lineage = lineage
        cert.last_error = ""
        cert.last_checked_at = _utcnow()
        cert.next_renewal_after = next_renewal_after
        # Clear the stash now that the order is closed. Record name +
        # value stay for audit / display ("this cert was issued via
        # DNS-01 using TXT _acme-challenge.example.com").
        cert.dns_challenge_state = ""
        db.session.commit()
        return HandlerResult(
            success=True, applied=True,
            detail=(f"DNS-01 verify completed for {cert.domain}; "
                    f"lineage={lineage}"),
        )
    except Exception as exc:
        log.exception("cert_dns_verify handler raised")
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
