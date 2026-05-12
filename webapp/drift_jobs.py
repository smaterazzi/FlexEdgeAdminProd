"""Drift scanner — background-job glue.

H6 (audit fix-up, 2026-05-09). Thin wrapper around the generic
`webapp.scan_jobs` runtime: registers a job, spawns a daemon thread
that calls `shared.smc_drift.scan_domain_drift` inside a captured
Flask app context, and routes per-row progress through the shared
progress / log primitives.

Mirrors `dhcp_scan_jobs` / `engine_scan_jobs` exactly — only the
runner contents differ. Same status / consume / discard surface.
"""

from __future__ import annotations

import logging

from flask import current_app

from webapp import scan_jobs

log = logging.getLogger(__name__)


def start_scan(*, domain, user_email: str) -> str:
    """Kick off a drift scan in a daemon thread. Returns the scan_id.

    `domain` must be the SQLAlchemy `Domain` row currently bound to
    the operator's session — we capture its scalar id and re-resolve
    inside the worker's app context so we don't drag the session-bound
    instance across threads.
    """
    from webapp.models import SmcObject
    from shared.smc_drift import scan_domain_drift

    total = (SmcObject.query
             .filter_by(domain_id=domain.id)
             .count())
    label = (getattr(domain, "display_name", None)
             or getattr(domain, "slug", None) or f"Domain #{domain.id}")

    scan_id = scan_jobs.register_job(
        feature="changes",
        user_email=user_email,
        total=max(total, 1),
        extra={
            "domain_id": domain.id,
            "domain_label": label,
            "drift_total": total,
            # Live counters surfaced by the watcher template.
            "drift_clean": 0,
            "drift_drifted": 0,
            "drift_gone": 0,
            "drift_errored": 0,
            "drift_skipped": 0,
        },
    )

    domain_id = domain.id  # capture scalar; SQLAlchemy instance is request-bound
    app = current_app._get_current_object()  # capture for the worker thread

    def _runner(_scan_id: str) -> None:
        with app.app_context():
            from shared.db import db
            from webapp.models import Domain
            d = db.session.get(Domain, domain_id)
            if d is None:
                scan_jobs.mark_failed(
                    _scan_id, f"Domain #{domain_id} no longer exists",
                )
                return

            def _on_progress(checked: int, total: int,
                             smc_name: str, smc_type: str,
                             state: str) -> None:
                # delta=1 — one row processed since the last call.
                scan_jobs.update_progress(_scan_id, delta=1)
                # Bump the per-state counter so the watcher card can
                # show running totals without polling the DB itself.
                key = f"drift_{state}" if state in (
                    "clean", "drifted", "gone", "errored", "skipped",
                ) else "drift_other"
                scan_jobs.increment_extra(_scan_id, key)
                scan_jobs.append_log(
                    _scan_id,
                    f"[{state:8s}] {smc_type or '?':14s} {smc_name or '?'}",
                )

            try:
                report = scan_domain_drift(d, progress_cb=_on_progress)
            except Exception as exc:
                log.exception("drift scan failed")
                scan_jobs.mark_failed(_scan_id, str(exc))
                return

            scan_jobs.append_log(_scan_id, (
                f"complete: clean={report.clean} drifted={report.drifted} "
                f"gone={report.gone} errored={report.errored} "
                f"skipped={report.skipped}"
            ))
            scan_jobs.mark_done(_scan_id, report)

    scan_jobs.spawn_runner(scan_id, _runner)
    log.info("drift_jobs: started scan_id=%s domain=%s total=%d",
             scan_id, label, total)
    return scan_id


# Re-export shared status / consume / discard surface.
get_status = scan_jobs.get_status
consume_report = scan_jobs.consume_report
discard = scan_jobs.discard
