"""LE.3 — renewal scheduler (lazy-sweep variant).

Operator answers:
  * LE-Q1 = A — LE.3 is THE orchestrator for renewals.
    `webapp.tls_scheduler.handle_renewal_webhook` stays in service
    as a fallback for operators with existing host-cron deploy-hook
    setups, but new installs run pure LE.3.
  * LE-Q2 = C — ship lazy-sweep first; boot-time daemon thread is
    parked as LE.3b if A proves insufficient.

Mechanics
---------
Every visit to ``/tls/letsencrypt`` (the cert list page) calls
``ensure_lazy_renewal_sweep(domain)``. The sweep is gated by
``was_swept_recently()`` reading ``platform_settings`` key
``letsencrypt_last_sweep_at``; default interval 1h matches the
existing scan_history retention pattern.

When due, the sweep walks every ``ManagedCertificate`` with
``status='active'`` AND ``next_renewal_after`` due (default lead 7
days) and enqueues a ``cert_renew`` queue op for each. Bypass auto-
push routing is handled by ``letsencrypt_queue.try_auto_push_for_admins``
exactly as the operator-clicked Force renew path uses.

Subset semantics
----------------
The sweep runs ACROSS DOMAINS — a single deployment-wide tick. Calling
it from one Domain's page load is fine: every Domain's certs get
considered. Audit emission tags the originating operator's email AND
the deployment-wide scope so the trail is honest. This is the same
pattern as the certbot renewal webhook (E2 exception — renewals cross
Domains by design at the cert level).

Idempotency
-----------
Each ``ManagedCertificate.pending_change_id`` is checked before
enqueuing — a cert with an in-flight renewal queue row is skipped to
avoid stacking duplicates. Renewals that fail leave ``cert.status``
at ``active`` (the queue handler is careful about that — see
``shared.queue_runner._handle_cert_renew``) so the next sweep retries.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from shared.db import db
from shared.logging import audit, get_setting, set_setting
from webapp.models import ManagedCertificate, PendingChange

log = logging.getLogger("letsencrypt.scheduler")


# Settings key for the last-sweep timestamp marker. Stored as ISO 8601
# in ``platform_settings`` so it persists across restarts.
SETTING_LAST_SWEEP_AT = "letsencrypt_last_sweep_at"

# Sweep interval — matches scan_history/retention (1h is well-suited to
# admin-portal usage rhythms and cheap enough on the indexed query).
SWEEP_INTERVAL = timedelta(hours=1)

# Default renewal lead — how soon before ``next_renewal_after`` the
# sweep starts enqueueing. 7 days matches what cert_renew handler
# bakes into ``next_renewal_after`` (60d after issuance / renewal), so
# this lands at ~53 days from issuance — well inside LE's 30-day
# recommended renewal window.
RENEWAL_LEAD = timedelta(days=7)


@dataclass
class SweepReport:
    """What the sweep did. Returned to callers for audit + flash."""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    candidates_considered: int = 0
    enqueued: int = 0
    skipped_in_flight: int = 0
    skipped_missing_lineage: int = 0
    errored: int = 0
    enqueued_change_ids: list[int] = field(default_factory=list)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def was_swept_recently() -> bool:
    """True if the last sweep was less than ``SWEEP_INTERVAL`` ago."""
    raw = get_setting(SETTING_LAST_SWEEP_AT)
    if not raw:
        return False
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (_utcnow() - ts) < SWEEP_INTERVAL


def mark_swept_now() -> None:
    """Stamp the last-sweep marker at now()."""
    set_setting(SETTING_LAST_SWEEP_AT, _utcnow().isoformat())


# Audit P4 (2026-06-11): the sweep used to run inline in the
# /tls/letsencrypt request — when SMC / certbot pushes were slow the
# cert list page stalled behind them. It now spawns a daemon thread;
# the non-blocking module lock prevents double-sweeps when two page
# loads race inside the same gate window.
_sweep_thread_lock = threading.Lock()


def ensure_lazy_renewal_sweep(*, triggered_by_user_email: str = "") -> bool:
    """Spawn a background renewal sweep if the last one was more than
    ``SWEEP_INTERVAL`` ago. Returns True when a sweep was started.

    Best-effort: failures log inside the worker, never raise. Called
    from the cert list route on every page load — operator visibility
    on the cert list page is what keeps renewals fresh in lazy mode;
    the request thread never waits on the sweep itself.
    """
    if was_swept_recently():
        return False
    if not _sweep_thread_lock.acquire(blocking=False):
        return False    # a sweep is already in flight
    try:
        from flask import current_app
        app = current_app._get_current_object()
    except Exception:
        _sweep_thread_lock.release()
        return False

    def _run():
        try:
            with app.app_context():
                try:
                    sweep_due_renewals(
                        triggered_by_user_email=triggered_by_user_email)
                    mark_swept_now()
                except Exception as exc:
                    log.warning("LE renewal sweep failed: %s", exc)
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
        finally:
            _sweep_thread_lock.release()

    threading.Thread(
        target=_run, daemon=True, name="letsencrypt-renewal-sweep",
    ).start()
    return True


def sweep_due_renewals(*, triggered_by_user_email: str = "",
                       lead: timedelta = RENEWAL_LEAD) -> SweepReport:
    """Walk every Domain's active certs and enqueue ``cert_renew`` for
    those due within ``lead`` of ``next_renewal_after``.

    Cross-Domain by design (LE-Q1=A — single orchestrator at
    deployment scope). Audit emission stamps the deployment scope and
    the triggering operator email so the trail is honest.

    Skips certs that already have an in-flight ``pending_change_id``
    to avoid stacking duplicate renewals; the next sweep picks them
    up if the linked queue row terminates as ``push_failed`` (handler
    keeps ``status='active'`` for early-renew failures, so the lazy
    cycle retries).
    """
    report = SweepReport()
    # Avoid lazy imports at the top — circular: queue → scheduler.
    from webapp.letsencrypt_queue import (
        enqueue_cert_renew, try_auto_push_for_admins,
    )

    cutoff = _utcnow() + lead
    # LE.4: DNS-01 certs can't auto-renew (operator has to re-publish
    # the TXT record). Skip them in the sweep — operator hits Force
    # renew on the cert detail page to restart the DNS-01 flow.
    candidates = (
        ManagedCertificate.query
        .filter(ManagedCertificate.status == "active",
                ManagedCertificate.next_renewal_after.isnot(None),
                ManagedCertificate.next_renewal_after <= cutoff,
                ManagedCertificate.challenge_type == "http01")
        .all()
    )
    report.candidates_considered = len(candidates)

    if not candidates:
        report.finished_at = _utcnow()
        return report

    for cert in candidates:
        # Skip certs with an in-flight queue row (renewal already
        # under way or stuck). The cert_delete hygiene fix and the
        # existing FK ondelete=SET NULL keep stale FK refs at bay.
        if cert.pending_change_id is not None:
            ref = db.session.get(PendingChange, cert.pending_change_id)
            if ref is not None and ref.state in ("queued", "pushing"):
                report.skipped_in_flight += 1
                continue
        if not cert.certbot_lineage:
            # Renewal needs an already-issued cert. Shouldn't happen
            # for status=active but defensive.
            report.skipped_missing_lineage += 1
            continue
        try:
            change = enqueue_cert_renew(cert=cert, requested_by_user_id=None)
            report.enqueued += 1
            report.enqueued_change_ids.append(change.id)
            # Reuse the bypass / sync push routing from the existing
            # Force-renew button so the operator-visible behavior is
            # identical — Domain Admin (or anyone with the
            # letsencrypt bypass enabled) gets instant async push.
            try:
                try_auto_push_for_admins(
                    change=change, cert=cert,
                    user_email=triggered_by_user_email or "letsencrypt-scheduler",
                )
            except Exception as push_exc:
                log.warning(
                    "LE scheduler: enqueue ok but auto-push raised for "
                    "cert %d (%s): %s",
                    cert.id, cert.domain, push_exc,
                )
        except Exception as exc:
            log.warning("LE scheduler: enqueue failed for cert %d (%s): %s",
                        cert.id, cert.domain, exc)
            report.errored += 1
            try:
                db.session.rollback()
            except Exception:
                pass

    report.finished_at = _utcnow()

    # One top-level audit row summarising the run. Per-cert enqueue
    # audit rows already fire from each individual route call site;
    # here we record the sweep's own decision-making.
    try:
        audit(
            feature="letsencrypt",
            action="scheduler.sweep",
            target=f"{report.enqueued}/{report.candidates_considered} due",
            detail=(f"enqueued={report.enqueued} "
                    f"skipped_in_flight={report.skipped_in_flight} "
                    f"skipped_missing_lineage={report.skipped_missing_lineage} "
                    f"errored={report.errored} "
                    f"triggered_by={triggered_by_user_email or 'system'}"),
        )
    except Exception:
        pass
    return report
