"""DHCP credentials SSH-rule install/remove ↔ Change-Management queue glue.

Phase E.2 (3rd slice) — the rule install + remove flows go through
`pending_changes`. They're admin-only operations today (operators don't
manage credentials), so the auto-push UX (Q15/a) means the operator
sees the same flow as before — the queue row is the audit trail with
Retry capability.

Two new operation types in `pending_changes.operation`:

  * `install_ssh_rule` — bundles into ONE row:
      1. find/create source Host with FEA's source IP
      2. find/create destination Host(s) for cluster nodes
      3. find/create the rule in the engine's installed policy
      4. upload the policy to the engine
    The handler is internal-orchestrator style (Q19/b pattern).

  * `remove_ssh_rule` — bundles into ONE row:
      1. remove the rule from the policy
      2. upload the policy to the engine
    DB-side `DhcpEngineSshAccess` row removal happens in the route
    after a successful push (so retry semantics stay clean).

`upload_policy` (Phase C handler) is reused for the
`/credentials/policy-install` "force upload" button, with auto-push.

Source-IP drift recovery (`overwrite` / `add` source) stays out of
the queue — it's a recovery action on an already-broken rule and the
operator wants the immediate effect; queueing it would just add
latency without meaningful audit benefit (the audit already happens
via `_log_activity`).
"""

import json
import logging
from typing import Optional

from shared.db import db
from webapp.models import PendingChange, User

log = logging.getLogger(__name__)


def _current_user_id() -> Optional[int]:
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


def enqueue_install_ssh_rule(*, domain, engine_name: str,
                             source_ip: str,
                             destination_ips: list,
                             rule_name: Optional[str] = None,
                             fea_hostname: str = "") -> PendingChange:
    payload = {
        "engine_name": engine_name,
        "source_ip": source_ip,
        "destination_ips": list(destination_ips),
        "rule_name": rule_name or "",
        "fea_hostname": fea_hostname or "",
    }
    change = PendingChange(
        domain_id=domain.id,
        user_id=_current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="install_ssh_rule",
        payload_json=json.dumps(payload),
        feature_source="dhcp",
        source_correlation_id=f"dhcp_credentials_rule:{engine_name}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    db.session.commit()
    return change


def enqueue_remove_ssh_rule(*, domain, engine_name: str,
                            policy_name: str = "",
                            rule_name: str = "") -> PendingChange:
    payload = {
        "engine_name": engine_name,
        "policy_name": policy_name or "",
        "rule_name": rule_name or "",
    }
    change = PendingChange(
        domain_id=domain.id,
        user_id=_current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="remove_ssh_rule",
        payload_json=json.dumps(payload),
        feature_source="dhcp",
        source_correlation_id=f"dhcp_credentials_rule:{engine_name}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    db.session.commit()
    return change


def enqueue_policy_upload(*, domain, engine_name: str,
                          policy_name: str = "") -> PendingChange:
    """Reuses the Phase C `upload_policy` handler (already registered)."""
    payload = {
        "engine_name": engine_name,
        "policy_name": policy_name or "",
    }
    change = PendingChange(
        domain_id=domain.id,
        user_id=_current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="upload_policy",
        payload_json=json.dumps(payload),
        feature_source="dhcp",
        source_correlation_id=f"dhcp_credentials_policy:{engine_name}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    db.session.commit()
    return change


def try_auto_push(change: PendingChange) -> str:
    """Push inline if the current user is Domain Admin+ OR if per-user
    bypass is enabled for `dhcp_credentials` in the active Domain.

    Returns one of:
      * 'pushed'      — push succeeded. When bypass applies, the queue
                        row was also deleted (transient) and a
                        ``*.bypass_queue`` audit marker was emitted.
      * 'queued'      — non-admin path without bypass; row stays QUEUED.
      * 'push_failed' — push attempted, failed. Row stays for Retry
                        regardless of bypass state.
    """
    is_admin = False
    try:
        from webapp.auth_roles import is_domain_admin
        is_admin = is_domain_admin()
    except Exception:
        is_admin = False

    is_bypass = False
    try:
        from shared.queue_settings import should_bypass_queue
        is_bypass = should_bypass_queue("dhcp_credentials")
    except Exception:
        is_bypass = False

    if not (is_admin or is_bypass):
        return "queued"

    from shared.queue_runner import push_one
    result = push_one(change.id)

    if result.success:
        if is_bypass:
            _bypass_cleanup(change, feature="dhcp_credentials")
        return "pushed"
    return "push_failed"


def _bypass_cleanup(change: PendingChange, *, feature: str) -> None:
    """Delete a successfully-pushed queue row + emit the bypass audit marker.

    Mirror of the helper in `webapp/dhcp_reservation_queue.py`. Only
    called on success; failure leaves the row for Retry.
    """
    try:
        from shared.logging import audit
        audit(
            feature=feature,
            action=f"{change.operation}.bypass_queue",
            target=f"#{change.id}",
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
