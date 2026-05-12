"""TLS deploy — background-job glue.

H8 (audit fix-up, 2026-05-09). Wraps the synchronous
`shared.queue_runner.push_one` call (which holds the SMC global lock for
30-60s) in a daemon thread so the operator's HTTP request returns
immediately. Renders a watcher card on `deploy_execute.html` while the
pipeline runs; the page reloads to consume the report when done.

Also relocates the bypass-queue cleanup (delete the transient
PendingChange row on success) into the worker so it lands atomically
with the rest of the deploy.
"""

from __future__ import annotations

import logging

from flask import current_app

from webapp import scan_jobs

log = logging.getLogger(__name__)


def start_deploy(*, change_id: int, deployment_id: int,
                 service_name: str, user_email: str,
                 is_bypass: bool) -> str:
    """Kick off a TLS deploy in a daemon thread. Returns the scan_id.

    The 5-step pipeline (import cert → host objects → assign cred →
    create rule → upload policy) lives entirely in the queue runner;
    we just call `push_one(change_id)` from a worker thread. Total=5
    is a coarse approximation — the pipeline emits no per-step events
    today, so the progress bar just goes from 0 to 5 on completion.
    """
    scan_id = scan_jobs.register_job(
        feature="tls_deploy",
        user_email=user_email,
        total=5,
        extra={
            "change_id": change_id,
            "deployment_id": deployment_id,
            "service_name": service_name,
            "is_bypass": bool(is_bypass),
            "tls_overall": "",   # filled at completion: ok|failed
        },
    )

    app = current_app._get_current_object()

    def _runner(_scan_id: str) -> None:
        with app.app_context():
            from shared.queue_runner import push_one
            from shared.db import db
            from webapp.models import PendingChange

            scan_jobs.append_log(
                _scan_id,
                f"Starting TLS deploy pipeline for {service_name} "
                f"(queue change #{change_id})…",
            )
            try:
                push_result = push_one(change_id)
            except Exception as exc:
                log.exception("tls_deploy_jobs: worker failed")
                scan_jobs.mark_failed(_scan_id, str(exc))
                return

            # The pipeline either succeeded fully or failed at one of
            # the 5 steps. Record an aggregate progress hit so the bar
            # snaps to 100% on completion.
            scan_jobs.update_progress(_scan_id, delta=5)

            if push_result.success:
                scan_jobs.append_log(_scan_id, "TLS deploy OK")
                scan_jobs.update_extra(_scan_id, tls_overall="ok")
                # Bypass cleanup — relocated from the request thread so
                # it lands together with the deploy result. The audit
                # marker keeps log queries able to find bypassed runs.
                if is_bypass:
                    try:
                        change = db.session.get(PendingChange, change_id)
                        if change is not None:
                            try:
                                from shared.logging import audit
                                audit(
                                    feature="tls_deploy",
                                    action=f"{change.operation}.bypass_queue",
                                    target=f"deployment#{deployment_id} ({service_name})",
                                    detail=("bypass_queue=True; queue row "
                                            f"deleted on success (was "
                                            f"change_id={change_id})"),
                                    source_correlation_id=change.source_correlation_id,
                                    domain_id=change.domain_id,
                                )
                            except Exception:
                                pass
                            try:
                                db.session.delete(change)
                                db.session.commit()
                            except Exception:
                                db.session.rollback()
                    except Exception:
                        log.exception("tls_deploy_jobs: bypass cleanup raised")
            else:
                scan_jobs.append_log(
                    _scan_id,
                    f"TLS deploy FAILED: {push_result.error or 'unknown error'}",
                )
                scan_jobs.update_extra(_scan_id, tls_overall="failed")

            scan_jobs.mark_done(_scan_id, push_result)

    scan_jobs.spawn_runner(scan_id, _runner)
    log.info("tls_deploy_jobs: started scan_id=%s deployment=%s "
             "change_id=%s bypass=%s",
             scan_id, deployment_id, change_id, is_bypass)
    return scan_id


# Re-export shared status / consume / discard surface.
get_status = scan_jobs.get_status
consume_report = scan_jobs.consume_report
discard = scan_jobs.discard
