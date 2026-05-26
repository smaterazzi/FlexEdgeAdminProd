"""Let's Encrypt cert ops — queue helpers.

Roadmap item 5 / Phase LE.2 (2026-05-11). Per Q6c, three discrete
queue operations: ``cert_request`` / ``cert_renew`` / ``cert_revoke``.
This module exposes ``enqueue_*`` helpers that the
``webapp.letsencrypt_manager`` blueprint calls when the operator
submits a request via the UI.

Bypass-queue support follows the Phase E.2 pattern: the helper
inspects ``should_bypass_queue("letsencrypt")`` and the caller's role
to decide whether to auto-push inline (via the
``webapp.letsencrypt_jobs`` scan_jobs runner) or leave the row in
``state=queued`` for /changes/ review.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from flask import session

from shared.db import db
from webapp.models import (
    ManagedCertificate, PendingChange, User, Domain, AcmeAccount,
)

log = logging.getLogger(__name__)


def _current_user_id() -> Optional[int]:
    try:
        email = ((session.get("user") or {}).get("email") or "").strip().lower()
        if not email:
            return None
        u = User.query.filter_by(email=email).first()
        return u.id if u else None
    except Exception:
        return None


def enqueue_cert_request(*, fqdn: str, domain: Domain,
                         is_staging: bool,
                         requested_by_user_id: Optional[int] = None,
                         account: Optional[AcmeAccount] = None
                         ) -> tuple[ManagedCertificate, PendingChange]:
    """Create the ManagedCertificate row + a queued cert_request change.

    The caller is responsible for verifying:
      * the operator has Domain Admin (or higher) on `domain`
      * the FQDN passes the per-Domain allowlist
      * an AcmeAccount exists (the setup wizard ran)

    Returns (cert, change) — both committed.
    """
    if account is None:
        account = AcmeAccount.query.first()

    cert = ManagedCertificate(
        domain=fqdn,
        certbot_lineage="",  # filled by the handler on success
        last_cert_hash="",
        domain_id=domain.id,
        requested_by_user_id=requested_by_user_id or _current_user_id(),
        status="pending",
        last_error="",
        is_staging=bool(is_staging or (account and account.is_staging)),
        account_id=account.id if account else None,
        challenge_type="http01",
    )
    db.session.add(cert)
    db.session.flush()  # need cert.id for the source_correlation_id

    payload = {"certificate_id": cert.id}
    change = PendingChange(
        domain_id=domain.id,
        user_id=requested_by_user_id or _current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="cert_request",
        payload_json=json.dumps(payload),
        feature_source="letsencrypt",
        source_correlation_id=f"letsencrypt_cert:{cert.id}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()

    cert.pending_change_id = change.id
    db.session.commit()
    return cert, change


def enqueue_cert_renew(*, cert: ManagedCertificate,
                       requested_by_user_id: Optional[int] = None
                       ) -> PendingChange:
    """Queue a renewal for an existing cert."""
    payload = {"certificate_id": cert.id}
    change = PendingChange(
        domain_id=cert.domain_id,
        user_id=requested_by_user_id or _current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="cert_renew",
        payload_json=json.dumps(payload),
        feature_source="letsencrypt",
        source_correlation_id=f"letsencrypt_cert:{cert.id}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    cert.pending_change_id = change.id
    db.session.commit()
    return change


def enqueue_cert_revoke(*, cert: ManagedCertificate, reason: str = "unspecified",
                        requested_by_user_id: Optional[int] = None
                        ) -> PendingChange:
    """Queue a revoke. UI for this is Phase LE.5; the helper exists now
    so a Phase LE.3 cron sweep (e.g. retire-stale) can call it."""
    payload = {"certificate_id": cert.id, "reason": reason}
    change = PendingChange(
        domain_id=cert.domain_id,
        user_id=requested_by_user_id or _current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="cert_revoke",
        payload_json=json.dumps(payload),
        feature_source="letsencrypt",
        source_correlation_id=f"letsencrypt_cert:{cert.id}",
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    cert.pending_change_id = change.id
    db.session.commit()
    return change


def try_auto_push_for_admins(*, change: PendingChange,
                             cert: ManagedCertificate,
                             user_email: str) -> tuple[bool, Optional[str]]:
    """Bypass-queue auto-push for Domain Admin (and higher).

    Returns ``(spawned, scan_id_or_none)``. ``spawned=True`` means a
    background scan_jobs worker is running the queue handler — the
    caller should redirect to a watcher URL with ``?le_scan_id=<id>``.
    ``spawned=False`` means the user doesn't have bypass; row stays
    queued for /changes/ review.
    """
    try:
        from webapp.auth_roles import is_domain_admin
        from shared.queue_settings import should_bypass_queue
    except Exception:
        log.exception("letsencrypt_queue: auth/bypass import failed")
        return False, None

    is_admin = False
    try:
        is_admin = is_domain_admin()
    except Exception:
        pass
    is_bypass = False
    try:
        is_bypass = should_bypass_queue("letsencrypt")
    except Exception:
        pass
    if not (is_admin or is_bypass):
        return False, None

    try:
        from webapp.letsencrypt_jobs import start_cert_op
        scan_id = start_cert_op(
            change_id=change.id,
            certificate_id=cert.id,
            fqdn=cert.domain,
            action=change.operation,
            user_email=user_email,
            is_bypass=bool(is_bypass),
        )
        return True, scan_id
    except Exception:
        log.exception("letsencrypt_queue: start_cert_op spawn failed")
        return False, None
