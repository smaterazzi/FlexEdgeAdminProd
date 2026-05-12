"""Let's Encrypt cert ops — background-job glue.

Roadmap item 5 / Phase LE.2 (2026-05-11). Thin wrapper around
`webapp.scan_jobs` that wraps `shared.queue_runner.push_one` in a
daemon thread for the bypass-queue auto-push path, so the operator's
HTTP request returns immediately and the watcher card on the cert
detail page polls a JSON status endpoint until done.

Mirrors `webapp.tls_deploy_jobs` exactly — only the feature tag and
the post-success cleanup differ.
"""

from __future__ import annotations

import logging

from flask import current_app

from webapp import scan_jobs

log = logging.getLogger(__name__)


def start_cert_op(*, change_id: int, certificate_id: int,
                  fqdn: str, action: str, user_email: str,
                  is_bypass: bool) -> str:
    """Kick off a cert op (request / renew / revoke) in a daemon thread.

    `action` is one of "cert_request" / "cert_renew" / "cert_revoke" —
    the queue op type, also used as a log/audit tag. `change_id`
    identifies the PendingChange to push; the queue handler reads the
    target ManagedCertificate from the change's payload.

    `is_bypass=True` matches the Phase E.2 bypass-queue semantics: the
    PendingChange row is deleted after a successful push (transient,
    audit marker emitted to platform_logs). For non-bypass calls the
    row stays and goes through normal /changes/ review.
    """
    total_steps = {
        "cert_request": 4,  # validate → certbot exec → parse → persist
        "cert_renew":   3,  # certbot exec → parse → persist
        "cert_revoke":  3,
    }.get(action, 3)

    scan_id = scan_jobs.register_job(
        feature="letsencrypt",
        user_email=user_email,
        total=total_steps,
        extra={
            "change_id": change_id,
            "certificate_id": certificate_id,
            "fqdn": fqdn,
            "action": action,
            "is_bypass": bool(is_bypass),
            "le_overall": "",  # filled at completion: ok|failed
        },
    )

    app = current_app._get_current_object()

    def _runner(_scan_id: str) -> None:
        with app.app_context():
            from shared.queue_runner import push_one
            from shared.db import db
            from webapp.models import PendingChange, ManagedCertificate

            scan_jobs.append_log(
                _scan_id,
                f"{action} for {fqdn} — running queue handler "
                f"(change #{change_id})…",
            )
            try:
                push_result = push_one(change_id)
            except Exception as exc:
                log.exception("letsencrypt_jobs: worker raised")
                scan_jobs.mark_failed(_scan_id, str(exc))
                return

            # Coarse progress hit — handlers don't emit per-step events
            # today (certbot is opaque from the outside), so we just
            # snap the bar to 100% on completion.
            scan_jobs.update_progress(_scan_id, delta=total_steps)

            cert = db.session.get(ManagedCertificate, certificate_id)
            if push_result.success:
                scan_jobs.append_log(_scan_id, f"{action} OK")
                scan_jobs.update_extra(_scan_id, le_overall="ok")
                # Surface the lineage path so the watcher can show
                # where the cert landed.
                if cert is not None and cert.certbot_lineage:
                    scan_jobs.append_log(
                        _scan_id,
                        f"cert lineage: {cert.certbot_lineage}",
                    )
                # Bypass cleanup — delete the transient PendingChange
                # row and emit the Phase E.2 audit marker.
                if is_bypass:
                    try:
                        change = db.session.get(PendingChange, change_id)
                        if change is not None:
                            try:
                                from shared.logging import audit
                                audit(
                                    feature="letsencrypt",
                                    action=f"{action}.bypass_queue",
                                    target=fqdn,
                                    detail=(f"bypass_queue=True; queue row "
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
                        log.exception("letsencrypt_jobs: bypass cleanup raised")
            else:
                err_short = (push_result.error or "unknown error")
                # Surface the first line of the error in the log tail;
                # full error already persisted on cert.last_error by the
                # handler.
                first_line = err_short.splitlines()[0] if err_short else ""
                scan_jobs.append_log(
                    _scan_id, f"{action} FAILED: {first_line}",
                )
                scan_jobs.update_extra(_scan_id, le_overall="failed")

            scan_jobs.mark_done(_scan_id, push_result)

    scan_jobs.spawn_runner(scan_id, _runner)
    log.info("letsencrypt_jobs: started scan_id=%s action=%s fqdn=%s "
             "change_id=%s bypass=%s",
             scan_id, action, fqdn, change_id, is_bypass)
    return scan_id


# Re-export shared status / consume / discard surface.
get_status = scan_jobs.get_status
consume_report = scan_jobs.consume_report
discard = scan_jobs.discard
