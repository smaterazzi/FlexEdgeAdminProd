"""
FlexEdgeAdmin — Factory reset.

Super-Admin-only "wipe the deployment back to factory state, keep me
logged in" tool. Used when a Domain layout has drifted too far to clean
up by hand, when a tenant relationship needs to be redone from scratch,
or when handing the box to a different operator.

What survives the reset
-----------------------
- The Super Admin User row (the one currently invoking the reset).
  Without this, the operator gets locked out of their own deployment.
- ``platform_settings`` rows (log mode, retention, cache TTLs, feature
  toggles). Operator-tuned values are kept; if they want defaults they
  can clear the rows manually after the reset.
- The encryption key file on disk (``config/encryption.key``). Wiping
  it would orphan any backup ZIPs the operator has — keep it stable.
- The .env / Azure AD app config (lives outside the DB, untouched).

What gets wiped
---------------
Every row in every other table. Every filesystem artifact the app owns
under ``/config/`` other than ``flexedge.db`` + ``encryption.key`` +
``platform_settings``. Every in-process cache section.

Atomic-ish: the DB wipe is one transaction. Filesystem wipes are
best-effort after the commit — a partial FS clean leaves stale archive
files but doesn't compromise the DB-side reset.
"""

from __future__ import annotations

import io
import logging
import os
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app

from shared.db import db
from shared.encryption import KEY_FILE
from webapp.models import (
    ApiKey, Domain, DhcpActivityLog, DhcpDeployment, DhcpEngineCredential,
    DhcpEngineSshAccess, DhcpReservation, DhcpScope,
    EngineScanHost, EngineScanRecord, EngineSginfoCollection,
    EngineTerminalSession, FeatureBypassSetting, ManagedCertificate,
    OptimizationSubmission, PendingChange, PlatformLog,
    SmcObject, Tenant, TLSActivityLog, TLSDeployment, TLSDeploymentLog,
    User, UserDomainAccess,
)

log = logging.getLogger(__name__)


# ── Backup (pre-reset snapshot) ──────────────────────────────────────────

def build_backup_zip() -> tuple[bytes, str]:
    """Build a ZIP containing the live DB + encryption key.

    Returns ``(bytes, filename)``. Caller streams it as a download
    BEFORE invoking ``perform_reset`` so the operator has a rollback
    point on disk regardless of what happens next.
    """
    db_path = current_app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    key_path = os.environ.get("ENCRYPTION_KEY_FILE", KEY_FILE)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.isfile(db_path):
            zf.write(db_path, "flexedge.db")
        if os.path.isfile(key_path):
            zf.write(key_path, "encryption.key")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return buf.getvalue(), f"flexedge-pre-reset-backup-{timestamp}.zip"


# ── Reset execution ──────────────────────────────────────────────────────

@dataclass
class ResetReport:
    """What got wiped — surfaced back to the operator after the reset."""
    rows_deleted: dict[str, int] = field(default_factory=dict)
    files_deleted: list[str] = field(default_factory=list)
    files_failed: list[str] = field(default_factory=list)
    cache_sections_cleared: int = 0
    super_admin_email: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    @property
    def total_rows_deleted(self) -> int:
        return sum(self.rows_deleted.values())


# Order matters: FK-constrained children first, parents last. SQLite FK
# enforcement is ON (see [webapp/db_init.py] PRAGMA listener), so an
# out-of-order delete raises.
#
# We delete via ORM ``Model.query.delete(synchronize_session=False)``
# for speed (single bulk DELETE per table) and because we wipe the
# whole table — no row-by-row hook firing needed.
_WIPE_ORDER: list[tuple[str, type[db.Model]]] = [
    # Children of DhcpScope
    ("dhcp_reservations", DhcpReservation),
    ("dhcp_deployments", DhcpDeployment),
    # Children of EngineScanRecord
    ("engine_scan_hosts", EngineScanHost),
    ("engine_scan_records", EngineScanRecord),
    # Other engine artifacts
    ("engine_sginfo_collections", EngineSginfoCollection),
    ("engine_terminal_sessions", EngineTerminalSession),
    # TLS chain
    ("tls_deployment_logs", TLSDeploymentLog),
    ("tls_deployments", TLSDeployment),
    ("managed_certificates", ManagedCertificate),
    # DHCP top-level
    ("dhcp_scopes", DhcpScope),
    ("dhcp_engine_credentials", DhcpEngineCredential),
    ("dhcp_engine_ssh_access", DhcpEngineSshAccess),
    # Change management
    ("pending_changes", PendingChange),
    ("smc_objects", SmcObject),
    # Optimizer
    ("optimization_submissions", OptimizationSubmission),
    # Feature toggles per user
    ("feature_bypass_settings", FeatureBypassSetting),
    # Logs (legacy + unified)
    ("dhcp_activity_logs", DhcpActivityLog),
    ("tls_activity_logs", TLSActivityLog),
    ("platform_logs", PlatformLog),
    # Identity / scope chain — parents come last
    ("user_domain_access", UserDomainAccess),  # special-cased: skip super-admin rows
    ("domains", Domain),
    ("api_keys", ApiKey),
    ("tenants", Tenant),
    ("users", User),                            # special-cased: skip super-admin
]


def perform_reset(*, invoking_user_id: int) -> ResetReport:
    """Wipe every feature-table row, preserving the invoking Super Admin.

    The invoking user must already be validated as Super Admin by the
    caller (``@super_admin_required`` on the route). We don't re-check
    here — this module trusts its caller for the auth decision and just
    does the destructive work.

    Per Q10/2026-05-01 role spec, ``User.is_super_admin = True`` rows
    are also preserved if the operator has manually promoted others.
    Belt-and-suspenders: even if for some reason the invoking user
    isn't flagged ``is_super_admin``, we still keep that exact row so
    they don't get locked out.
    """
    report = ResetReport()
    super_admin = db.session.get(User, invoking_user_id)
    if super_admin is None:
        raise RuntimeError(
            f"invoking_user_id={invoking_user_id} not found in users table — "
            f"refusing reset to avoid lockout"
        )
    report.super_admin_email = super_admin.email

    # IDs of every user we will keep — the invoking user PLUS anyone else
    # flagged is_super_admin. Both their User rows and their
    # UserDomainAccess rows survive (the access rows will dangle once
    # their Domain is deleted; that's fine — they'll be NULL/empty
    # after the cascade and harmless until the operator re-binds them).
    keep_user_ids = {invoking_user_id}
    for u in User.query.filter_by(is_super_admin=True).all():
        keep_user_ids.add(u.id)

    # ── DB wipe ──────────────────────────────────────────────────────
    try:
        for table_name, model in _WIPE_ORDER:
            if model is User:
                # Preserve super-admin user rows.
                deleted = (User.query
                           .filter(~User.id.in_(keep_user_ids))
                           .delete(synchronize_session=False))
            elif model is UserDomainAccess:
                # Preserve access rows belonging to kept users. They'll
                # be FK-orphaned once their Domain is deleted in the
                # same transaction — but UserDomainAccess.domain_id has
                # ondelete=CASCADE, so the cascade removes them
                # automatically when the parent Domain goes. Net effect:
                # all UserDomainAccess rows are gone by the end of this
                # transaction either way. We still skip the explicit
                # delete here for clarity.
                deleted = (UserDomainAccess.query
                           .filter(~UserDomainAccess.user_id.in_(keep_user_ids))
                           .delete(synchronize_session=False))
            else:
                deleted = model.query.delete(synchronize_session=False)
            report.rows_deleted[table_name] = int(deleted or 0)

        # Also bump the kept super-admin row's display name update
        # timestamp so the operator can see the reset reflected in
        # /admin/users.
        super_admin.updated_at = datetime.now(timezone.utc)

        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    # ── Filesystem wipe (best-effort) ────────────────────────────────
    _wipe_filesystem(report)

    # ── In-process cache ─────────────────────────────────────────────
    try:
        from shared.smc_cache import invalidate_all
        report.cache_sections_cleared = invalidate_all()
    except Exception as exc:
        log.warning("factory_reset: invalidate_all() failed: %s", exc)

    # Engine terminal sessions, scan jobs, sginfo workers — module-local
    # in-memory dicts. Survive across requests within a single process,
    # so wipe them too.
    _wipe_in_process_state()

    report.finished_at = datetime.now(timezone.utc)
    log.warning(
        "factory_reset COMPLETE — operator=%s rows_deleted=%d files_deleted=%d",
        report.super_admin_email,
        report.total_rows_deleted,
        len(report.files_deleted),
    )

    # Write a single audit row to the freshly-wiped platform_logs table
    # so the first line of the new deployment's audit trail records
    # what happened. Best-effort — failures here don't undo the reset.
    try:
        from shared.logging import audit
        audit(
            feature="system",
            action="factory_reset",
            target=report.super_admin_email,
            detail=(f"rows_deleted={report.total_rows_deleted} "
                    f"files_deleted={len(report.files_deleted)} "
                    f"cache_sections={report.cache_sections_cleared}"),
            status="ok",
            user_email=report.super_admin_email,
        )
    except Exception:
        pass

    return report


# ── Filesystem cleanup ───────────────────────────────────────────────────

def _wipe_filesystem(report: ResetReport) -> None:
    """Delete on-disk artifacts that the operator selected for wiping.

    sginfo archives, scan log files, and webhook bearer tokens.
    Never touches flexedge.db or encryption.key.
    """
    config_dir = Path(current_app.config.get("CONFIG_DIR") or "/config")

    # sginfo archives
    sginfo_dir = config_dir / "sginfo"
    if sginfo_dir.is_dir():
        for entry in sginfo_dir.iterdir():
            _rm_path_into_report(entry, report)

    # scan log files
    for cand in (
        config_dir / "logs",
        Path("/tmp/flexedge-scan-logs"),
    ):
        if cand.is_dir():
            for f in cand.glob("engine-scan-*.log"):
                _rm_path_into_report(f, report)

    # webhook bearer tokens
    for token_file in (
        config_dir / ".tls_api_token",
        config_dir / ".dhcp_api_token",
    ):
        if token_file.is_file():
            _rm_path_into_report(token_file, report)


def _rm_path_into_report(path: Path, report: ResetReport) -> None:
    """Best-effort delete of a single file or directory, recording the
    outcome on the report."""
    try:
        if path.is_dir():
            import shutil
            shutil.rmtree(path)
        else:
            path.unlink()
        report.files_deleted.append(str(path))
    except Exception as exc:
        log.warning("factory_reset: could not delete %s: %s", path, exc)
        report.files_failed.append(f"{path}: {exc}")


def _wipe_in_process_state() -> None:
    """Best-effort: clear module-local dicts used by background-job runtimes.

    These accumulate state inside the gunicorn worker process; without
    wiping them, the operator could see a phantom "scan in progress"
    badge that maps to a scan whose DB record was just deleted.
    """
    for module_name, attr in (
        ("webapp.scan_jobs", "_JOBS"),
        ("webapp.dhcp_scan_jobs", "_JOBS"),
        ("webapp.scan_jobs", "_CANCEL_HOOKS"),
    ):
        try:
            mod = __import__(module_name, fromlist=[attr])
            d = getattr(mod, attr, None)
            if isinstance(d, dict):
                d.clear()
        except Exception:
            pass


# ── Operator-facing confirmation phrase ──────────────────────────────────

#: Operator must type this literal string into the confirm field, exactly,
#: to authorise the reset. Case-sensitive. Kept short so it's quick to type
#: but specific enough that auto-fill / muscle-memory submissions don't
#: trigger it.
CONFIRM_PHRASE = "RESET"


def is_confirmed(form_value: str | None) -> bool:
    """Strict equality (no trim, no case-fold) on the confirm phrase."""
    return form_value == CONFIRM_PHRASE
