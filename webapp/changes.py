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
        # Default — show what needs operator attention.
        qry = qry.filter(PendingChange.state.in_(("queued", "conflict", "push_failed")))
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

    rows = qry.order_by(PendingChange.created_at.desc()).limit(500).all()

    # Object view: group by smc_object_id (None bucket for create-new ops)
    grouped = {}
    if view == "object":
        for r in rows:
            key = r.smc_object_id or 0
            grouped.setdefault(key, []).append(r)

    # Conflict pairs — for each conflict row, fetch its peer for side-by-side rendering.
    peer_by_id = {}
    for r in rows:
        if r.state == "conflict" and r.conflict_with_id:
            peer = db.session.get(PendingChange, r.conflict_with_id)
            if peer is not None:
                peer_by_id[r.id] = peer

    # Stats — counts by state for the active scope/Domain.
    stats_qry = _scope_query()
    if scope and scope != "all":
        stats_qry = stats_qry.filter(PendingChange.scope == scope)
    stats = {
        "queued":      stats_qry.filter(PendingChange.state == "queued").count(),
        "conflict":    stats_qry.filter(PendingChange.state == "conflict").count(),
        "push_failed": stats_qry.filter(PendingChange.state == "push_failed").count(),
        "pushed":      stats_qry.filter(PendingChange.state == "pushed").count(),
        "applied":     stats_qry.filter(PendingChange.state == "applied").count(),
        "aborted":     stats_qry.filter(PendingChange.state == "aborted").count(),
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
    """
    domain = getattr(g, "domain", None)
    state_filter = (request.args.get("state") or "active").strip()

    from webapp.models import SmcObject
    from shared.smc_drift import drift_summary

    rows = []
    summary = {"total": 0, "clean": 0, "drifted": 0,
               "gone": 0, "unknown": 0, "last_check_at": None}
    if domain is not None:
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
    )


@changes_bp.route("/drift/scan", methods=["POST"])
@domain_admin_required
def drift_scan():
    """Run a fresh drift scan against the active Domain. Synchronous —
    blocks the request until the scan finishes. Domains with thousands
    of tracked objects may take a while; defer to a background task in
    a follow-up if that becomes a problem.
    """
    domain = getattr(g, "domain", None)
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("changes.drift_index"))

    try:
        from shared.smc_drift import scan_domain_drift
        report = scan_domain_drift(domain)
    except Exception as exc:
        log.exception("drift_scan failed")
        flash(f"Drift scan failed: {exc}", "danger")
        return redirect(url_for("changes.drift_index"))

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
    summary = ", ".join(bits) or "no rows to scan"
    flash(f"Drift scan complete — {summary}.", cat)
    return redirect(url_for("changes.drift_index"))


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
        PendingChange.state.in_(("queued", "conflict", "push_failed")),
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
                PendingChange.state.in_(("queued", "conflict", "push_failed")),
            )
            return {"pending_changes_count": qry.count()}
        except Exception:
            return {"pending_changes_count": 0}
