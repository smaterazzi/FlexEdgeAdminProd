"""
FlexEdgeAdmin — Change Management Queue Blueprint.

Spec: docs/ChangeManagementProcess.md.

Operator-facing UI for the two-phase commit queue. Backed by the push
runner in `shared/queue_runner.py`. No SMC mutation logic lives here —
this blueprint only renders + dispatches to the runner.

Mounted at `/changes/*`.

Routes
------

  GET  /changes/                               List view (Operator+)
  POST /changes/<id>/push                      Single push (Admin+)
  POST /changes/<id>/abort                     Abort (creator OR Admin+)
  POST /changes/<id>/confirm-delete            Confirm to_be_deleted (Global+)
  POST /changes/<id>/revoke-delete             Revoke to_be_deleted (Global+)
  POST /changes/<id>/resolve-conflict          Pick winner of conflict (Admin+)
  POST /changes/push-all                       Bulk push QUEUED (Admin+)
  POST /changes/abort-all                      Bulk abort QUEUED (Admin+)

Visibility model
----------------

* Super Admin sees rows from every Domain (with Domain badge).
* Global / Domain Admin / Operator sees rows from the active Domain only.
* Within a Domain, Operators see all rows but can only Abort their own.

Action buttons surface conditionally per role and per row state — see
the template's `{% if can_push %}` etc. blocks.
"""
import json as _json
import logging
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, jsonify, g, abort,
)

from shared.db import db
from webapp.models import (
    PendingChange, SmcObject, Domain, User,
)
from webapp.auth_roles import (
    Role, current_role_for_active_domain,
    is_super_admin, is_global_admin, is_domain_admin, is_domain_operator,
    domain_admin_required, domain_operator_required, global_admin_required,
)
from shared import queue_runner

log = logging.getLogger(__name__)

changes_bp = Blueprint("changes", __name__, url_prefix="/changes")


# ── Helpers ───────────────────────────────────────────────────────────────

def _current_user_row():
    """Resolve the User row for the request, or None."""
    info = session.get("user") or {}
    email = (info.get("email") or "").strip().lower()
    if not email:
        return None
    return User.query.filter_by(email=email).first()


def _scope_query():
    """Return the base PendingChange query scoped to the user's visibility.

    Super Admin sees everything; everyone else sees only the active
    Domain (operators included — they need to see the queue context to
    understand their own submissions).
    """
    q = PendingChange.query
    if is_super_admin():
        return q
    domain = getattr(g, "domain", None)
    if domain is None:
        # No active Domain context — nothing visible.
        return q.filter(db.false()) if hasattr(db, "false") else q.filter(PendingChange.id == -1)
    return q.filter(PendingChange.domain_id == domain.id)


def _can_act_on(change: PendingChange, action: str) -> bool:
    """Can the current user perform ``action`` on this change row?

    `action` ∈ {'push', 'abort', 'confirm', 'revoke', 'resolve_conflict'}.
    """
    if change is None:
        return False
    me = _current_user_row()
    if me is None:
        return False

    # Domain check first — Super Admin sees every Domain, others only their active one.
    if not is_super_admin():
        domain = getattr(g, "domain", None)
        if domain is None or change.domain_id != domain.id:
            return False

    if action == "push":
        return is_domain_admin()
    if action == "abort":
        # Operator can abort their own. Admin and above can abort anyone's.
        if is_domain_admin():
            return True
        if is_domain_operator() and change.user_id == me.id:
            return True
        return False
    if action == "resolve_conflict":
        return is_domain_admin()
    if action in ("confirm", "revoke"):
        # to_be_deleted Confirm/Revoke is Global Admin or Super Admin.
        return is_global_admin()
    return False


def _flash_push_result(result):
    """Translate a `queue_runner.PushResult` into a flash message."""
    if result is None:
        return
    if result.success:
        flash(f"Change #{result.change_id} {result.state}.", "success")
    elif result.skipped:
        flash(f"Change #{result.change_id} skipped — {result.error or 'state changed'}.",
              "warning")
    elif result.failed:
        flash(f"Change #{result.change_id} push failed: {result.error}",
              "danger")


def _flash_batch_result(batch):
    """Translate a `queue_runner.BatchResult` into a flash message."""
    bits = []
    if batch.applied: bits.append(f"{batch.applied} applied")
    if batch.pushed:  bits.append(f"{batch.pushed} pushed")
    if batch.skipped: bits.append(f"{batch.skipped} skipped")
    if batch.failed:
        bits.append(f"{batch.failed} failed")
        if batch.aborted_after_halt:
            bits.append(f"{batch.aborted_after_halt} untouched (halt-on-failure)")
    if not bits:
        flash("Nothing to do — no QUEUED rows match.", "info")
        return
    cat = "danger" if batch.failed else "success"
    flash("Batch result: " + ", ".join(bits) + ".", cat)


# ── List view ─────────────────────────────────────────────────────────────

@changes_bp.route("/")
@domain_operator_required
def index():
    """Operator-facing queue list. Filterable by scope/state/source/text."""
    scope = (request.args.get("scope") or "main").strip()
    state = (request.args.get("state") or "active").strip()
    correlation = (request.args.get("source") or "").strip()
    q = (request.args.get("q") or "").strip()
    view = (request.args.get("view") or "time").strip()  # 'time' or 'object'

    qry = _scope_query()

    if scope and scope != "all":
        qry = qry.filter(PendingChange.scope == scope)

    if state == "active":
        # Default — show what needs operator attention. ``pushing`` rows
        # are in-flight (atomic claim won, handler running); they're
        # included here so a stuck row from a killed worker is visible
        # even before any operator action is required.
        qry = qry.filter(PendingChange.state.in_(
            ("queued", "pushing", "conflict", "push_failed")))
    elif state and state != "all":
        qry = qry.filter(PendingChange.state == state)

    if correlation:
        qry = qry.filter(PendingChange.source_correlation_id == correlation)

    if q:
        like = f"%{q}%"
        qry = qry.filter(
            (PendingChange.payload_json.ilike(like)) |
            (PendingChange.push_error_text.ilike(like)) |
            (PendingChange.feature_source.ilike(like))
        )

    # M13 (audit fix-up, 2026-05-09): real pagination — was a hard
    # `limit(500)` with a "narrow your filter" footer banner when hit.
    # On a 5000-row queue accumulated over a quarter the older rows
    # were simply unreachable. Now `?page=` with 50/page, total count
    # for the footer pager.
    try:
        page = max(1, int(request.args.get("page") or "1"))
    except ValueError:
        page = 1
    page_size = 50
    total_rows = qry.count()
    rows = (qry.order_by(PendingChange.created_at.desc())
            .limit(page_size)
            .offset((page - 1) * page_size)
            .all())
    total_pages = max(1, (total_rows + page_size - 1) // page_size)

    # Object view: group by smc_object_id (None bucket for create-new ops)
    grouped = {}
    if view == "object":
        for r in rows:
            key = r.smc_object_id or 0
            grouped.setdefault(key, []).append(r)

    # Conflict pairs — for each conflict row, fetch its peer for
    # side-by-side rendering.
    # M7 (audit fix-up, 2026-05-09): batched into one IN query (was one
    # SELECT per conflict row). On a 100-conflict queue this drops 100
    # round-trips to 1.
    peer_by_id = {}
    peer_ids = [r.conflict_with_id for r in rows
                if r.state == "conflict" and r.conflict_with_id]
    if peer_ids:
        peers = (PendingChange.query
                 .filter(PendingChange.id.in_(peer_ids))
                 .all())
        peer_by_pk = {p.id: p for p in peers}
        for r in rows:
            if r.state == "conflict" and r.conflict_with_id:
                peer = peer_by_pk.get(r.conflict_with_id)
                if peer is not None:
                    peer_by_id[r.id] = peer

    # Stats — counts by state for the active scope/Domain.
    # M19 (audit fix-up, 2026-05-09): replaced 7 separate `.count()`
    # queries with one GROUP BY state. On a busy queue (5000+ rows
    # accumulated over a quarter) this drops the index page render
    # from ~7 sequential round-trips to one.
    from sqlalchemy import func
    stats_qry = _scope_query()
    if scope and scope != "all":
        stats_qry = stats_qry.filter(PendingChange.scope == scope)
    state_counts = dict(
        stats_qry.with_entities(
            PendingChange.state, func.count(PendingChange.id),
        ).group_by(PendingChange.state).all()
    )
    stats = {
        state: state_counts.get(state, 0)
        for state in ("queued", "pushing", "conflict", "push_failed",
                      "pushed", "applied", "aborted")
    }

    # Source-correlation buckets (for the filter dropdown).
    correlation_buckets = []
    try:
        rows_corr = (db.session.query(
            PendingChange.source_correlation_id,
            db.func.count(PendingChange.id),
        )
        .filter(PendingChange.source_correlation_id.isnot(None))
        .group_by(PendingChange.source_correlation_id)
        .order_by(db.func.max(PendingChange.created_at).desc())
        .limit(20)
        .all())
        correlation_buckets = [(c, n) for c, n in rows_corr if c]
    except Exception:
        correlation_buckets = []

    # Drift summary for the active Domain — drives the dashboard card.
    drift = {"total": 0, "clean": 0, "drifted": 0, "gone": 0,
             "unknown": 0, "last_check_at": None}
    try:
        from shared.smc_drift import drift_summary
        domain = getattr(g, "domain", None)
        if domain is not None:
            drift = drift_summary(domain)
    except Exception:
        pass

    return render_template(
        "changes/index.html",
        rows=rows,
        grouped=grouped,
        peer_by_id=peer_by_id,
        stats=stats,
        drift=drift,
        filters={
            "scope": scope, "state": state,
            "source": correlation, "q": q, "view": view,
        },
        correlation_buckets=correlation_buckets,
        pagination={
            "page": page,
            "page_size": page_size,
            "total_rows": total_rows,
            "total_pages": total_pages,
        },
        # Action visibility flags for the template — pre-computed once
        # so we don't re-resolve roles per row.
        can_push_global=is_domain_admin(),
        can_confirm_delete=is_global_admin(),
        is_super=is_super_admin(),
        current_user_id=(_current_user_row() or type("U", (), {"id": None})).id,
    )


# ── Per-row actions ──────────────────────────────────────────────────────

@changes_bp.route("/<int:change_id>/push", methods=["POST"])
@domain_admin_required
def row_push(change_id):
    change = db.session.get(PendingChange, change_id)
    if not change or not _can_act_on(change, "push"):
        abort(404)
    result = queue_runner.push_one(change_id)
    _flash_push_result(result)
    return redirect(request.referrer or url_for("changes.index"))


@changes_bp.route("/<int:change_id>/abort", methods=["POST"])
@domain_operator_required
def row_abort(change_id):
    change = db.session.get(PendingChange, change_id)
    if not change or not _can_act_on(change, "abort"):
        abort(404)
    reason = (request.form.get("reason") or "").strip() or "operator abort"
    if queue_runner.abort_one(change_id, reason=reason):
        flash(f"Change #{change_id} aborted.", "warning")
    else:
        flash(f"Change #{change_id} could not be aborted (state may have changed).",
              "info")
    return redirect(request.referrer or url_for("changes.index"))


@changes_bp.route("/<int:change_id>/confirm-delete", methods=["POST"])
@global_admin_required
def row_confirm_delete(change_id):
    change = db.session.get(PendingChange, change_id)
    if not change or not _can_act_on(change, "confirm"):
        abort(404)
    result = queue_runner.confirm_to_be_deleted(change_id)
    _flash_push_result(result)
    return redirect(request.referrer or url_for("changes.index"))


@changes_bp.route("/<int:change_id>/revoke-delete", methods=["POST"])
@global_admin_required
def row_revoke_delete(change_id):
    change = db.session.get(PendingChange, change_id)
    if not change or not _can_act_on(change, "revoke"):
        abort(404)
    reason = (request.form.get("reason") or "").strip()
    if queue_runner.revoke_to_be_deleted(change_id, reason=reason):
        flash(f"Change #{change_id} delete request revoked. The object is no "
              f"longer marked for deletion.", "success")
    else:
        flash(f"Change #{change_id} could not be revoked (state may have changed).",
              "info")
    return redirect(request.referrer or url_for("changes.index"))


@changes_bp.route("/<int:change_id>/resolve-conflict", methods=["POST"])
@domain_admin_required
def row_resolve_conflict(change_id):
    """Pick the winner of a conflict pair.

    Form field `winner` ∈ {'this', 'peer'}. The losing row is ABORTED
    with a reason; the winner returns to QUEUED state ready to push.
    """
    change = db.session.get(PendingChange, change_id)
    if not change or not _can_act_on(change, "resolve_conflict"):
        abort(404)
    if change.state != "conflict":
        flash(f"Change #{change_id} is not in conflict state.", "info")
        return redirect(request.referrer or url_for("changes.index"))

    winner = (request.form.get("winner") or "this").strip()
    peer = (db.session.get(PendingChange, change.conflict_with_id)
            if change.conflict_with_id else None)
    if peer is None:
        # Lone conflict — just unmark it (back to queued).
        change.state = "queued"
        change.conflict_with_id = None
        db.session.commit()
        flash(f"Change #{change_id} conflict cleared (no peer found).", "warning")
        return redirect(request.referrer or url_for("changes.index"))

    if winner == "peer":
        keep, drop = peer, change
    else:
        keep, drop = change, peer

    keep.state = "queued"
    keep.conflict_with_id = None
    db.session.commit()

    queue_runner.abort_one(
        drop.id,
        reason=f"Conflict resolution: change #{keep.id} chosen as winner",
    )

    flash(f"Resolved conflict — change #{keep.id} kept (queued); "
          f"change #{drop.id} aborted.", "success")
    return redirect(request.referrer or url_for("changes.index"))


# ── Bulk actions ─────────────────────────────────────────────────────────

@changes_bp.route("/push-all", methods=["POST"])
@domain_admin_required
def push_all():
    """Push every QUEUED row in scope='main' for the active Domain."""
    domain = getattr(g, "domain", None)
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("changes.index"))
    batch = queue_runner.push_all_for_domain(domain.id)
    _flash_batch_result(batch)
    return redirect(request.referrer or url_for("changes.index"))


@changes_bp.route("/abort-all", methods=["POST"])
@domain_admin_required
def abort_all():
    """Abort every QUEUED row in scope='main' for the active Domain."""
    domain = getattr(g, "domain", None)
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("changes.index"))

    rows = (PendingChange.query
            .filter_by(domain_id=domain.id, scope="main", state="queued")
            .all())
    n_aborted = 0
    for r in rows:
        if queue_runner.abort_one(r.id, reason="bulk abort by admin"):
            n_aborted += 1
    flash(f"Aborted {n_aborted} queued change(s) in this Domain.", "warning")
    return redirect(request.referrer or url_for("changes.index"))


# ── Drift detector (Phase G) ────────────────────────────────────────────

@changes_bp.route("/drift")
@domain_operator_required
def drift_index():
    """Drift list view — every SmcObject row in the active Domain.

    Filterable by drift_state. Default shows non-clean rows (drifted +
    gone) so the operator sees the actionable list first.

    H6 (audit fix-up, 2026-05-09): when called with `?scan_id=X`, render
    the in-progress watcher (state='running'), consume the report and
    flash a summary (state='done'), or flash the error and fall through
    (state='failed') — same UX pattern as the engine + DHCP scan jobs.
    """
    domain = getattr(g, "domain", None)
    state_filter = (request.args.get("state") or "active").strip()

    from webapp.models import SmcObject
    from shared.smc_drift import drift_summary

    # Watcher / consume — `?scan_id=X` is the post-spawn redirect target.
    scan_running = None
    scan_id = (request.args.get("scan_id") or "").strip()
    if scan_id:
        from webapp import drift_jobs
        user_email = (session.get("user") or {}).get("email", "")
        status = drift_jobs.get_status(scan_id, user_email=user_email)
        if status is None:
            flash("Drift scan job not found or expired — start a new one.",
                  "info")
        elif status["state"] == "running":
            scan_running = status
        elif status["state"] == "failed":
            flash(f"Drift scan failed: {status.get('error') or 'unknown error'}",
                  "danger")
            drift_jobs.discard(scan_id, user_email=user_email)
        else:  # done
            report = drift_jobs.consume_report(scan_id, user_email=user_email)
            if report is None:
                flash("Drift scan results expired before they could be loaded.",
                      "warning")
            else:
                bits = []
                if report.clean:    bits.append(f"{report.clean} clean")
                if report.drifted:  bits.append(f"{report.drifted} drifted")
                if report.gone:     bits.append(f"{report.gone} gone")
                if report.errored:  bits.append(f"{report.errored} errored")
                if report.skipped:  bits.append(f"{report.skipped} skipped")
                cat = "info"
                if report.drifted or report.gone:
                    cat = "warning"
                if report.errored:
                    cat = "danger"
                flash(f"Drift scan complete — "
                      f"{', '.join(bits) or 'no rows to scan'}.", cat)

    rows = []
    summary = {"total": 0, "clean": 0, "drifted": 0,
               "gone": 0, "unknown": 0, "last_check_at": None}
    if domain is not None and scan_running is None:
        qry = SmcObject.query.filter_by(domain_id=domain.id)
        if state_filter == "active":
            qry = qry.filter(SmcObject.drift_state.in_(("drifted", "gone")))
        elif state_filter and state_filter != "all":
            qry = qry.filter(SmcObject.drift_state == state_filter)
        rows = (qry.order_by(SmcObject.drift_state.desc(),
                             SmcObject.smc_type.asc(),
                             SmcObject.smc_name.asc())
                .limit(1000)
                .all())
        summary = drift_summary(domain)

    return render_template(
        "changes/drift.html",
        rows=rows, summary=summary,
        filters={"state": state_filter},
        can_scan=is_domain_admin(),
        can_reconcile=is_domain_admin(),
        scan_running=scan_running,
    )


@changes_bp.route("/drift/scan/status")
@domain_operator_required
def drift_scan_status():
    """JSON poll target for the drift watcher card."""
    from webapp import drift_jobs
    scan_id = (request.args.get("id") or "").strip()
    user_email = (session.get("user") or {}).get("email", "")
    status = drift_jobs.get_status(scan_id, user_email=user_email)
    if status is None:
        return jsonify({"state": "missing"}), 404
    return jsonify(status)


@changes_bp.route("/drift/scan", methods=["POST"])
@domain_admin_required
def drift_scan():
    """Spawn a background drift scan against the active Domain.

    H6 (audit fix-up, 2026-05-09): the scan was previously synchronous
    and blocked the request thread for minutes on Domains with thousands
    of tracked objects (gunicorn timeout territory). Now goes via
    `webapp.drift_jobs.start_scan` which mirrors the engine / DHCP scan
    pattern: register-job → daemon thread → watcher card on the drift
    index polls for completion.
    """
    domain = getattr(g, "domain", None)
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("changes.drift_index"))

    from webapp import drift_jobs
    user_email = (session.get("user") or {}).get("email", "")
    try:
        scan_id = drift_jobs.start_scan(domain=domain, user_email=user_email)
    except Exception as exc:
        log.exception("drift_scan: failed to spawn job")
        flash(f"Drift scan failed to start: {exc}", "danger")
        return redirect(url_for("changes.drift_index"))

    # Redirect to the watcher view — the index reads ?scan_id=X and
    # renders a progress card until the job's `done` / `failed`.
    return redirect(url_for("changes.drift_index", scan_id=scan_id))


@changes_bp.route("/drift/<int:smc_object_id>/reconcile", methods=["POST"])
@domain_admin_required
def drift_reconcile(smc_object_id):
    """Re-baseline a drifted row to its current SMC state.

    The operator is asserting "the drift is intentional, accept the
    current SMC state as the new ground truth." last_seen_hash is
    updated to the fresh hash; drift_state flips to 'clean'.
    """
    from webapp.models import SmcObject
    row = db.session.get(SmcObject, smc_object_id)
    if row is None:
        abort(404)
    domain = getattr(g, "domain", None)
    if domain is None or row.domain_id != domain.id:
        if not is_super_admin():
            abort(404)

    from shared.smc_drift import reconcile_one
    if reconcile_one(smc_object_id):
        flash(f"Reconciled {row.smc_type}:{row.smc_name} — "
              f"current SMC state baselined as the new ground truth.",
              "success")
    else:
        flash(f"Could not reconcile {row.smc_type}:{row.smc_name} — "
              f"the element may have been removed from SMC.",
              "warning")
    return redirect(url_for("changes.drift_index"))


# ── JSON / API ───────────────────────────────────────────────────────────

@changes_bp.route("/api/pending-count")
@domain_operator_required
def api_pending_count():
    """JSON: count of rows that need attention in the active Domain.

    Counts main-scope rows in ('queued', 'conflict', 'push_failed') —
    the same buckets that drive the "active" filter on the list page.
    Used by the sidebar/topbar badge to refresh without a page reload.
    """
    qry = _scope_query().filter(
        PendingChange.scope == "main",
        PendingChange.state.in_(("queued", "pushing", "conflict", "push_failed")),
    )
    return jsonify({"pending_count": qry.count()})


# ── Context processor for the sidebar badge ──────────────────────────────

def init_changes_blueprint(app):
    """Wire the per-request pending-count context for the sidebar.

    Called once at app startup. Keeps the badge fresh on every page load
    without each template having to query manually.
    """
    @app.context_processor
    def inject_pending_changes_count():
        try:
            if "user" not in session:
                return {"pending_changes_count": 0}
            from webapp.auth_roles import is_domain_operator as _has_role
            if not _has_role():
                return {"pending_changes_count": 0}
            qry = _scope_query().filter(
                PendingChange.scope == "main",
                PendingChange.state.in_(("queued", "pushing", "conflict", "push_failed")),
            )
            return {"pending_changes_count": qry.count()}
        except Exception:
            return {"pending_changes_count": 0}
