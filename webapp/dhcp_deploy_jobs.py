"""DHCP scope deploy — background-job glue.

H7 (audit fix-up, 2026-05-09). Thin wrapper around the generic
`webapp.scan_jobs` runtime: registers a job, spawns a daemon thread
that calls `webapp.dhcp_pusher.push_scope_to_engine` inside a captured
Flask app context, and routes per-node progress through the shared
progress / log primitives.

Mirrors `webapp.drift_jobs` exactly — only the runner contents differ.
"""

from __future__ import annotations

import logging

from flask import current_app

from webapp import scan_jobs

log = logging.getLogger(__name__)


def start_deploy(*, scope_id: int, engine_name: str, action: str,
                 operator_email: str, total_nodes: int) -> str:
    """Kick off a DHCP push in a daemon thread. Returns the scan_id.

    `total_nodes` is the count of `DhcpEngineCredential` rows the caller
    counted at request time — used as the progress denominator.
    `engine_name` is captured into `extra` so the watcher card can
    identify the engine without re-querying.
    """
    scan_id = scan_jobs.register_job(
        feature="dhcp_deploy",
        user_email=operator_email,
        total=max(total_nodes, 1),
        extra={
            "scope_id": scope_id,
            "engine_name": engine_name,
            "action": action,
            "deploy_total_nodes": total_nodes,
            "deploy_done_nodes": 0,
            "deploy_failed_nodes": 0,
            "deploy_overall": "",   # filled at completion: blocked|ok|partial|failed
        },
    )

    app = current_app._get_current_object()  # capture for the worker thread

    def _runner(_scan_id: str) -> None:
        with app.app_context():
            from webapp.dhcp_pusher import push_scope_to_engine

            def _on_progress(*, phase: str, node_index: int,
                             node_hostname: str, total_nodes: int,
                             done_nodes: int, node_result=None) -> None:
                if phase == "start":
                    scan_jobs.append_log(
                        _scan_id,
                        f"node {node_index} ({node_hostname or '?'}) — connecting…",
                    )
                elif phase == "done":
                    scan_jobs.update_progress(_scan_id, delta=1)
                    scan_jobs.update_extra(_scan_id, deploy_done_nodes=done_nodes)
                    if node_result is None:
                        return
                    if node_result.status == "ok":
                        msg = (f"node {node_index} ({node_hostname}) — "
                               f"OK ({node_result.reservations_count} "
                               f"reservation(s), {node_result.duration_ms}ms)")
                        if node_result.reload_warning:
                            msg += f"  ⚠ {node_result.reload_warning}"
                        scan_jobs.append_log(_scan_id, msg)
                    else:
                        scan_jobs.increment_extra(_scan_id, "deploy_failed_nodes")
                        scan_jobs.append_log(
                            _scan_id,
                            f"node {node_index} ({node_hostname}) — "
                            f"FAILED: {node_result.error or 'unknown error'}",
                        )

            try:
                result = push_scope_to_engine(
                    scope_id, operator_email, action=action,
                    dry_run=False, progress_cb=_on_progress,
                )
            except Exception as exc:
                log.exception("dhcp scope_deploy worker failed")
                scan_jobs.mark_failed(_scan_id, str(exc))
                return

            scan_jobs.update_extra(_scan_id, deploy_overall=result.overall_status)
            if result.overall_status == "blocked":
                scan_jobs.append_log(
                    _scan_id,
                    f"BLOCKED: {result.blocked_reason or 'unknown reason'}",
                )
            else:
                scan_jobs.append_log(
                    _scan_id,
                    f"complete: {result.overall_status} — "
                    f"{result.successful_nodes}/{len(result.nodes)} nodes ok",
                )
            scan_jobs.mark_done(_scan_id, result)

    scan_jobs.spawn_runner(scan_id, _runner)
    log.info("dhcp_deploy_jobs: started scan_id=%s scope=%s engine=%s "
             "action=%s nodes=%d",
             scan_id, scope_id, engine_name, action, total_nodes)
    return scan_id


# Re-export shared status / consume / discard surface.
get_status = scan_jobs.get_status
consume_report = scan_jobs.consume_report
discard = scan_jobs.discard
