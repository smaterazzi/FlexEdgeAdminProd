"""
FlexEdgeAdmin — Per-Domain hard delete (purge).

Super-Admin-only **irreversible** wipe of a single Domain and every feature
row keyed to it. Complements — does not replace — the soft-delete
(deactivate) in ``admin.domain_delete``: that one flips ``is_active=False``
and keeps all data; this one destroys it.

Why a dedicated module (mirrors ``factory_reset.py``)
-----------------------------------------------------
A naive ``DELETE FROM domains WHERE id=X`` with ``PRAGMA foreign_keys=ON``
cascades MOST feature tables, but several use ``ondelete="SET NULL"`` and
would survive as orphans — exactly the data we want gone:

    managed_certificates, cert_expiration_notifications, dhcp_activity_logs,
    tls_activity_logs, engine_terminal_sessions, platform_logs.

So we delete explicitly, in FK-safe order (children → parents), scoped to one
``domain_id``. Indirect children (no ``domain_id`` of their own) are deleted
via their domain-scoped parent's id list.

What gets wiped (scoped to one Domain)
--------------------------------------
DHCP scopes / reservations / deployments / credentials / ssh-access, engine
scan records + hosts, sginfo collections (+ their on-disk archives), terminal
sessions, TLS deployments + logs, managed certificates (+ cert-expiration
notifications), optimizer submissions, change-management smc_objects +
pending_changes, feature bypass settings, cert patterns, smtp config,
user_domain_access grants, the legacy dhcp/tls activity logs, and the
**operational** (``level='op'``) platform_logs rows.

What survives (by design / operator decision)
---------------------------------------------
- **AUDIT-level platform_logs** rows for the Domain. Only the audit trail is
  retained. SQLite SET-NULLs their ``domain_id`` when the Domain row goes, so
  afterwards they render as "system" in ``/logs`` (the Domain no longer exists
  to filter by — that's the natural outcome of keeping them).
- The ``ApiKey`` + ``Tenant`` the Domain pointed at (keys are shared across
  Domains — never destroyed by a single-Domain purge).
- **Certbot lineages on disk** under ``/config/letsencrypt`` (reissue-free;
  kept per operator decision — same default as the LE delete flow).
- Every other Domain and all of its data.

Atomicity: the DB wipe is one transaction. The sginfo archive directory
removals are best-effort after the commit — a partial FS clean leaves stale
archive files but never compromises the DB-side purge.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from shared.db import db
from webapp.models import (
    CertExpirationNotification, DhcpActivityLog, DhcpDeployment,
    DhcpEngineCredential, DhcpEngineSshAccess, DhcpReservation, DhcpScope,
    Domain, DomainCertPattern, EngineScanHost, EngineScanRecord,
    EngineSginfoCollection, EngineTerminalSession, FeatureBypassSetting,
    ManagedCertificate, OptimizationSubmission, PendingChange, PlatformLog,
    SmcObject, SmtpConfig, TLSActivityLog, TLSDeployment, TLSDeploymentLog,
    UserDomainAccess,
)

log = logging.getLogger(__name__)


@dataclass
class PurgeReport:
    domain_id: int
    domain_slug: str
    domain_display: str
    rows_deleted: dict = field(default_factory=dict)
    audit_logs_kept: int = 0
    files_deleted: list = field(default_factory=list)
    files_failed: list = field(default_factory=list)

    @property
    def total_rows_deleted(self) -> int:
        return sum(self.rows_deleted.values())


def _bulk_delete(query) -> int:
    """Run a bulk DELETE for the given filtered query, return rowcount."""
    return int(query.delete(synchronize_session=False) or 0)


def purge_domain(domain: Domain) -> PurgeReport:
    """Hard-delete a single Domain and every feature row keyed to it.

    Keeps audit-level platform_logs (operator decision). Keeps certbot
    lineages + the parent ApiKey/Tenant. Commits in one transaction, then
    best-effort removes the sginfo archive dirs on disk.

    Raises on DB error after rolling back — the caller flashes the message.
    """
    did = domain.id
    report = PurgeReport(
        domain_id=did,
        domain_slug=domain.slug or "",
        domain_display=domain.display_name or domain.slug or f"#{did}",
    )

    # ── Gather parent-id lists for the indirect (no domain_id) children ──
    scope_ids = [s.id for s in
                 DhcpScope.query.filter_by(domain_id=did).all()]
    cred_ids = [c.id for c in
                DhcpEngineCredential.query.filter_by(domain_id=did).all()]
    cert_ids = [c.id for c in
                ManagedCertificate.query.filter_by(domain_id=did).all()]
    tls_deploy_ids = [d.id for d in
                      TLSDeployment.query.filter_by(domain_id=did).all()]
    scan_ids = [s.id for s in
                EngineScanRecord.query.filter_by(domain_id=did).all()]
    sginfo_records = EngineSginfoCollection.query.filter_by(domain_id=did).all()

    try:
        # 1) Indirect children first (deleted via parent-id lists) ────────
        report.rows_deleted["engine_terminal_sessions"] = _bulk_delete(
            EngineTerminalSession.query.filter(
                EngineTerminalSession.credential_id.in_(cred_ids))) \
            if cred_ids else 0
        report.rows_deleted["tls_deployment_logs"] = _bulk_delete(
            TLSDeploymentLog.query.filter(
                TLSDeploymentLog.deployment_id.in_(tls_deploy_ids))) \
            if tls_deploy_ids else 0
        report.rows_deleted["cert_expiration_notifications"] = _bulk_delete(
            CertExpirationNotification.query.filter(
                CertExpirationNotification.certificate_id.in_(cert_ids))) \
            if cert_ids else 0
        report.rows_deleted["dhcp_reservations"] = _bulk_delete(
            DhcpReservation.query.filter(
                DhcpReservation.scope_id.in_(scope_ids))) if scope_ids else 0
        report.rows_deleted["dhcp_deployments"] = _bulk_delete(
            DhcpDeployment.query.filter(
                DhcpDeployment.scope_id.in_(scope_ids))) if scope_ids else 0
        report.rows_deleted["engine_scan_hosts"] = _bulk_delete(
            EngineScanHost.query.filter(
                EngineScanHost.scan_id.in_(scan_ids))) if scan_ids else 0

        # 2) Domain-scoped parents (FK-safe order) ────────────────────────
        report.rows_deleted["tls_deployments"] = _bulk_delete(
            TLSDeployment.query.filter_by(domain_id=did))
        report.rows_deleted["managed_certificates"] = _bulk_delete(
            ManagedCertificate.query.filter_by(domain_id=did))
        report.rows_deleted["dhcp_scopes"] = _bulk_delete(
            DhcpScope.query.filter_by(domain_id=did))
        report.rows_deleted["engine_scan_records"] = _bulk_delete(
            EngineScanRecord.query.filter_by(domain_id=did))
        report.rows_deleted["engine_sginfo_collections"] = _bulk_delete(
            EngineSginfoCollection.query.filter_by(domain_id=did))
        report.rows_deleted["dhcp_engine_credentials"] = _bulk_delete(
            DhcpEngineCredential.query.filter_by(domain_id=did))
        report.rows_deleted["dhcp_engine_ssh_access"] = _bulk_delete(
            DhcpEngineSshAccess.query.filter_by(domain_id=did))
        report.rows_deleted["optimization_submissions"] = _bulk_delete(
            OptimizationSubmission.query.filter_by(domain_id=did))
        # pending_changes before smc_objects (FK chain housekeeping)
        report.rows_deleted["pending_changes"] = _bulk_delete(
            PendingChange.query.filter_by(domain_id=did))
        report.rows_deleted["smc_objects"] = _bulk_delete(
            SmcObject.query.filter_by(domain_id=did))
        report.rows_deleted["feature_bypass_settings"] = _bulk_delete(
            FeatureBypassSetting.query.filter_by(domain_id=did))
        report.rows_deleted["domain_cert_patterns"] = _bulk_delete(
            DomainCertPattern.query.filter_by(domain_id=did))
        report.rows_deleted["smtp_configs"] = _bulk_delete(
            SmtpConfig.query.filter_by(domain_id=did))
        report.rows_deleted["user_domain_access"] = _bulk_delete(
            UserDomainAccess.query.filter_by(domain_id=did))

        # 3) Legacy activity logs (fully removed for the Domain) ───────────
        report.rows_deleted["dhcp_activity_logs"] = _bulk_delete(
            DhcpActivityLog.query.filter_by(domain_id=did))
        report.rows_deleted["tls_activity_logs"] = _bulk_delete(
            TLSActivityLog.query.filter_by(domain_id=did))

        # 4) Unified logs — delete OPERATIONAL rows, KEEP AUDIT rows ───────
        report.audit_logs_kept = int(
            PlatformLog.query
            .filter_by(domain_id=did, level="audit").count())
        report.rows_deleted["platform_logs (op)"] = _bulk_delete(
            PlatformLog.query.filter_by(domain_id=did, level="op"))

        # 5) The Domain row itself. Surviving audit platform_logs get
        #    domain_id SET NULL via the FK at this point.
        report.rows_deleted["domains"] = _bulk_delete(
            Domain.query.filter_by(id=did))

        db.session.commit()
    except Exception:
        db.session.rollback()
        log.exception("domain_purge: DB wipe failed for domain_id=%s", did)
        raise

    # ── Best-effort filesystem cleanup (after commit) ────────────────────
    _wipe_sginfo_archives(sginfo_records, report)

    log.warning(
        "domain_purge COMPLETE — domain=%s (id=%s) rows_deleted=%d "
        "audit_logs_kept=%d files_deleted=%d",
        report.domain_slug, did, report.total_rows_deleted,
        report.audit_logs_kept, len(report.files_deleted),
    )
    return report


def _wipe_sginfo_archives(records, report: PurgeReport) -> None:
    """Remove each purged sginfo collection's on-disk archive directory."""
    if not records:
        return
    try:
        import shutil
        from webapp import engine_sginfo
    except Exception as exc:  # pragma: no cover - import guard
        log.warning("domain_purge: sginfo cleanup unavailable: %s", exc)
        return
    for rec in records:
        try:
            archive_dir = engine_sginfo.archive_root_dir(rec)
        except Exception:
            continue
        try:
            if archive_dir.is_dir():
                shutil.rmtree(archive_dir)
                report.files_deleted.append(str(archive_dir))
        except Exception as exc:
            log.warning("domain_purge: could not delete %s: %s",
                        archive_dir, exc)
            report.files_failed.append(f"{archive_dir}: {exc}")
