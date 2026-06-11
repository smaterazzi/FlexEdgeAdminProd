"""Cert-expiration dashboard + lazy-sweep alert scheduler (2026-05-31).

Tracks every ``ManagedCertificate`` in the active Domain — both LE-
issued (HTTP-01 / DNS-01) and PFX-imported — and fires SMTP alerts
when a cert's days-to-expiry crosses one of the configured
thresholds (default 30 / 14 / 7 / 3 / 1).

Architecture
------------
The dashboard view (``/tls/expirations``) is the natural place to
hang the sweep — every operator visit fires the gate, the same way
the LE.3 renewal sweep hangs off ``/tls/letsencrypt``. The gate is
guarded by a ``platform_settings`` timestamp (default interval 1h)
so back-to-back page loads don't slam SMTP.

For each cert in scope the sweep:
1. Reads ``<lineage>/cert.pem`` via :func:`webapp.certbot_reader.parse_certificate`
   to get the live ``not_valid_after`` (the DB doesn't cache this —
   a renewed lineage's new expiry shows up on the next sweep).
2. Computes ``days_to_expiry`` (signed — negative if already expired).
3. Selects the smallest threshold T such that ``days_to_expiry <= T``
   AND no ``CertExpirationNotification(cert_id=…, threshold_days=T)``
   row exists yet.
4. Sends one email per selected (cert, threshold). Records the row
   on success (``status='ok'``) OR failure (``status='failed'`` —
   the next sweep retries because the unique constraint upserts via
   "update on failure"). See :func:`_record_outcome`.

Cross-Domain scope
------------------
The sweep walks one Domain at a time (the active one). A cert with
no ``domain_id`` (legacy / untracked-by-Domain) is skipped — there's
no way to know which Domain's SMTP config to use for it. Operators
who want global alerts on legacy rows can set ``domain_id`` via the
admin portal first.

Cross-cert short-circuit: if the Domain has no SmtpConfig (or it's
``is_active=False``), the sweep exits without iterating certs.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from shared.db import db
from shared.logging import audit, get_setting, set_setting
from webapp.certbot_reader import parse_certificate
from webapp.models import (
    CertExpirationNotification, Domain, ManagedCertificate, SmtpConfig,
)
from webapp.smtp_sender import SendResult, SmtpSettings, send_smtp

log = logging.getLogger("cert_expirations")


SETTING_LAST_SWEEP_AT = "tls_expirations_last_sweep_at"
SWEEP_INTERVAL = timedelta(hours=1)

DEFAULT_THRESHOLDS = (30, 14, 7, 3, 1)


# ── Helpers ─────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_thresholds(csv: str) -> list[int]:
    """Parse ``"30,14,7,3,1"`` into a descending sorted list of positive ints.

    Tolerant: ignores blanks, non-integer tokens, and negative values.
    Empty / unparseable input falls back to :data:`DEFAULT_THRESHOLDS`.
    """
    out = []
    seen = set()
    for tok in (csv or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            v = int(tok)
        except ValueError:
            continue
        if v <= 0 or v in seen:
            continue
        seen.add(v)
        out.append(v)
    if not out:
        return list(DEFAULT_THRESHOLDS)
    out.sort(reverse=True)
    return out


def parse_recipients(csv: str) -> list[str]:
    """Parse comma/newline-separated recipients into a deduped list.

    Whitespace-trimmed; case preserved for SMTP routing. Empty inputs
    return ``[]`` so the caller can short-circuit cleanly.
    """
    raw = (csv or "").replace("\n", ",").replace(";", ",")
    out: list[str] = []
    seen: set[str] = set()
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        key = tok.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tok)
    return out


# ── Cert -> days-to-expiry projection ────────────────────────────────────

@dataclass
class CertExpiryView:
    """Operator-facing summary row for the expirations dashboard."""
    cert: ManagedCertificate
    valid_to: datetime | None
    days_to_expiry: int | None              # signed; None when read failed
    source_label: str                       # "PFX" | "LE · HTTP-01" | "LE · DNS-01"
    deployments_count: int
    last_notified_threshold: int | None     # highest threshold already fired
    on_disk_present: bool                   # cert.pem readable?


def _source_label(cert: ManagedCertificate) -> str:
    ct = (cert.challenge_type or "http01").lower()
    if ct == "pfx_import":
        return "PFX"
    if ct == "dns01_manual":
        return "LE · DNS-01"
    return "LE · HTTP-01"


# Audit P2 (2026-06-11): memoise the X.509 parse keyed on the file's
# (mtime_ns, size) — a renewed lineage rewrites cert.pem so the stat
# changes and we re-parse; an unchanged file costs one stat() instead
# of a full read + ASN.1 parse per cert per page render.
_valid_to_memo: dict[str, tuple[tuple[int, int], datetime | None]] = {}
_valid_to_memo_lock = threading.Lock()


def _read_valid_to(cert: ManagedCertificate) -> tuple[datetime | None, bool]:
    """Return (valid_to, on_disk_present). Defensive — never raises."""
    if not cert.certbot_lineage:
        return None, False
    cert_pem = Path(cert.certbot_lineage) / "cert.pem"
    try:
        st = cert_pem.stat()
    except OSError:
        return None, False
    stamp = (st.st_mtime_ns, st.st_size)
    path_key = str(cert_pem)
    with _valid_to_memo_lock:
        hit = _valid_to_memo.get(path_key)
    if hit is not None and hit[0] == stamp:
        return hit[1], True
    try:
        meta = parse_certificate(path_key)
        valid_to = meta.get("valid_to")
        if valid_to is not None and valid_to.tzinfo is None:
            valid_to = valid_to.replace(tzinfo=timezone.utc)
        with _valid_to_memo_lock:
            _valid_to_memo[path_key] = (stamp, valid_to)
        return valid_to, True
    except Exception as exc:
        log.warning("expirations: failed to parse cert %d (%s): %s",
                    cert.id, cert.domain, exc)
        return None, True   # file present but unparseable — surface to UI


def build_views_for_domain(domain_id: int | None) -> list[CertExpiryView]:
    """One ``CertExpiryView`` per cert visible in the active Domain.

    Visibility mirrors the same union the certs list uses:
    direct ``ManagedCertificate.domain_id`` match.
    """
    if domain_id is None:
        return []
    certs = (ManagedCertificate.query
             .filter(ManagedCertificate.domain_id == domain_id)
             .order_by(ManagedCertificate.domain.asc())
             .all())
    out: list[CertExpiryView] = []
    now = _utcnow()
    # Audit P3 (2026-06-11): one grouped query for every cert's highest
    # fired threshold instead of one SELECT per cert in the loop.
    max_threshold_by_cert: dict[int, int] = {}
    if certs:
        rows = (
            db.session.query(
                CertExpirationNotification.certificate_id,
                db.func.max(CertExpirationNotification.threshold_days),
            )
            .filter(
                CertExpirationNotification.certificate_id.in_(
                    [c.id for c in certs]),
                CertExpirationNotification.status == "ok",
            )
            .group_by(CertExpirationNotification.certificate_id)
            .all()
        )
        max_threshold_by_cert = {cid: mx for cid, mx in rows}
    for cert in certs:
        valid_to, on_disk = _read_valid_to(cert)
        if valid_to is not None:
            dte = (valid_to - now).days
        else:
            dte = None
        out.append(CertExpiryView(
            cert=cert,
            valid_to=valid_to,
            days_to_expiry=dte,
            source_label=_source_label(cert),
            deployments_count=cert.deployments.count(),
            last_notified_threshold=max_threshold_by_cert.get(cert.id),
            on_disk_present=on_disk,
        ))
    return out


# ── Sweep ────────────────────────────────────────────────────────────────

@dataclass
class SweepReport:
    """Summary of one sweep run, surfaced to operator + audit log."""
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: datetime | None = None
    domains_considered: int = 0
    domains_skipped_no_smtp: int = 0
    certs_considered: int = 0
    certs_no_threshold_due: int = 0
    certs_missing_lineage: int = 0
    sends_attempted: int = 0
    sends_ok: int = 0
    sends_failed: int = 0


def was_swept_recently() -> bool:
    raw = get_setting(SETTING_LAST_SWEEP_AT)
    if not raw:
        return False
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (_utcnow() - ts) < SWEEP_INTERVAL


def mark_swept_now() -> None:
    set_setting(SETTING_LAST_SWEEP_AT, _utcnow().isoformat())


# Audit P1 (2026-06-11): the lazy sweep used to run inline in the
# /tls/expirations request — N due alerts × up to 30 s SMTP timeout
# each could stall the gunicorn worker. It now runs in a daemon
# thread; the non-blocking module lock keeps two near-simultaneous
# page loads from double-sweeping inside the same gate window.
_sweep_thread_lock = threading.Lock()


def ensure_lazy_expiration_sweep(
    *, triggered_by_user_email: str = "",
) -> bool:
    """Spawn a background sweep if the last one was more than
    ``SWEEP_INTERVAL`` ago. Returns True when a sweep was started.

    Best-effort: failures log inside the worker. Called from the
    ``/tls/expirations`` route on every render so operator activity
    drives the cadence; the request thread never waits on SMTP.
    """
    if was_swept_recently():
        return False
    if not _sweep_thread_lock.acquire(blocking=False):
        return False    # a sweep is already in flight
    try:
        from flask import current_app
        app = current_app._get_current_object()
    except Exception:
        _sweep_thread_lock.release()
        return False

    def _run():
        try:
            with app.app_context():
                try:
                    sweep_all_domains(
                        triggered_by_user_email=triggered_by_user_email)
                    mark_swept_now()
                except Exception as exc:
                    log.warning("expirations sweep failed: %s", exc)
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
        finally:
            _sweep_thread_lock.release()

    threading.Thread(
        target=_run, daemon=True, name="cert-expirations-sweep",
    ).start()
    return True


def _due_threshold_for(cert: ManagedCertificate, days_to_expiry: int,
                       thresholds: list[int]) -> int | None:
    """Pick the smallest unfired threshold T with ``dte <= T``.

    Returns ``None`` when none qualifies (cert still has >max-threshold
    days left, OR the smallest qualifying T has already fired
    ``status='ok'``). Failed rows are eligible for re-fire — same
    threshold gets retried because their status is ``failed``.

    Critical correctness property: once we identify the *smallest*
    qualifying T, we either fire it OR exit. We must NOT scan onward
    to a higher T — that would re-alert on every sweep as the cert
    moves through thresholds (e.g. 5d-to-expiry would alert at T=7
    AND T=14 AND T=30 across consecutive sweeps because each is
    individually "not yet fired"). The smallest qualifying T is the
    operator-meaningful "current bucket"; any larger T is either
    already covered (we fired it earlier in this cert's life) or
    a non-event (no useful "you have 30 days" alert when the cert
    already has 5).
    """
    if not thresholds:
        return None
    asc = sorted(thresholds)
    fired_ok: set[int] = {
        row.threshold_days for row in
        CertExpirationNotification.query
        .filter(CertExpirationNotification.certificate_id == cert.id,
                CertExpirationNotification.status == "ok")
        .all()
    }
    for t in asc:
        if days_to_expiry <= t:
            return t if t not in fired_ok else None
    return None


def _render_alert_body(
    *, view: CertExpiryView, threshold: int, settings: SmtpSettings,
) -> tuple[str, str, str]:
    """Build (subject, text_body, html_body) for one cert+threshold."""
    cert = view.cert
    valid_to_str = (
        view.valid_to.strftime("%Y-%m-%d %H:%M UTC")
        if view.valid_to else "(unknown)"
    )
    dte = view.days_to_expiry
    if dte is None:
        urgency_text = "no expiry available on disk"
    elif dte < 0:
        urgency_text = f"EXPIRED {abs(dte)} day(s) ago"
    elif dte == 0:
        urgency_text = "EXPIRES TODAY"
    elif dte == 1:
        urgency_text = "expires TOMORROW"
    else:
        urgency_text = f"expires in {dte} day(s)"

    subject = (
        f"[FlexEdgeAdmin] {cert.domain} — TLS cert {urgency_text} "
        f"(threshold {threshold}d)"
    )

    deployments_count = view.deployments_count
    text_body = (
        f"FlexEdgeAdmin certificate expiration alert\n"
        f"==========================================\n\n"
        f"Common name : {cert.domain}\n"
        f"Source      : {view.source_label}\n"
        f"Valid until : {valid_to_str}\n"
        f"Status      : {urgency_text}\n"
        f"Threshold   : {threshold} day(s)\n"
        f"Lineage     : {cert.certbot_lineage}\n"
        f"Deployments : {deployments_count}\n\n"
        f"Next steps\n"
        f"----------\n"
    )
    if view.source_label == "PFX":
        text_body += (
            "* Re-export an updated PKCS#12 bundle from your CA tooling.\n"
            "* Upload via /tls/certificates/import-pfx — re-importing the\n"
            "  same Common Name replaces the on-disk files in place.\n"
            "* Re-run /tls/deploy for every linked deployment.\n"
        )
    elif view.source_label == "LE · DNS-01":
        text_body += (
            "* Wildcard certs need manual DNS-01: open the cert detail\n"
            "  page, click Force renew, publish the new TXT record at\n"
            "  the registrar, then click Verify.\n"
        )
    else:
        text_body += (
            "* LE.3 lazy-sweep auto-renews HTTP-01 certs in the\n"
            "  7-day window. If this alert fires AFTER that window\n"
            "  the scheduler couldn't issue — check /tls/letsencrypt\n"
            "  for the linked request and the certbot log tail at\n"
            "  /tls/letsencrypt/log.\n"
        )
    text_body += (
        "\n"
        f"This message was sent by FlexEdgeAdmin on behalf of\n"
        f"{settings.from_name} <{settings.from_address}>.\n"
    )

    html_body = f"""<!DOCTYPE html>
<html><body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; color:#111;">
<h2 style="margin-bottom:.25em;">{cert.domain} — TLS cert {urgency_text}</h2>
<p style="color:#666;margin-top:0;">FlexEdgeAdmin certificate expiration alert · threshold {threshold} day(s)</p>
<table style="border-collapse:collapse;font-size:14px;">
  <tr><td style="padding:4px 12px 4px 0;color:#555;">Common name</td><td style="font-weight:600;">{cert.domain}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#555;">Source</td><td>{view.source_label}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#555;">Valid until</td><td>{valid_to_str}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#555;">Status</td><td><strong>{urgency_text}</strong></td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#555;">Lineage</td><td><code>{cert.certbot_lineage}</code></td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#555;">Deployments</td><td>{deployments_count}</td></tr>
</table>
<p style="color:#888;font-size:12px;margin-top:24px;">Sent by FlexEdgeAdmin on behalf of {settings.from_name} &lt;{settings.from_address}&gt;.</p>
</body></html>"""

    return subject, text_body, html_body


def _settings_from_config(cfg: SmtpConfig) -> SmtpSettings:
    return SmtpSettings(
        host=cfg.host, port=cfg.port,
        security=cfg.security,
        username=cfg.username, password=cfg.encrypted_password or "",
        from_address=cfg.from_address, from_name=cfg.from_name,
    )


def _record_outcome(*, cert_id: int, threshold: int, recipients: list[str],
                    days_to_expiry: int, result: SendResult) -> None:
    """Upsert a CertExpirationNotification row.

    A failed prior row gets updated in place; a successful prior row
    is treated as terminal and never updated again — the cert just
    moves to the next threshold on the next sweep.
    """
    row = (CertExpirationNotification.query
           .filter_by(certificate_id=cert_id, threshold_days=threshold)
           .first())
    if row is None:
        row = CertExpirationNotification(
            certificate_id=cert_id,
            threshold_days=threshold,
            sent_at=_utcnow(),
            status="ok" if result.ok else "failed",
            error=result.error,
            recipients_csv=",".join(recipients),
            days_to_expiry=days_to_expiry,
        )
        db.session.add(row)
    else:
        # Only upgrade failed → ok. Once ok, leave alone.
        if row.status != "ok":
            row.status = "ok" if result.ok else "failed"
            row.error = result.error
            row.sent_at = _utcnow()
            row.recipients_csv = ",".join(recipients)
            row.days_to_expiry = days_to_expiry
    db.session.commit()


def sweep_all_domains(
    *, triggered_by_user_email: str = "",
) -> SweepReport:
    """One sweep across every active Domain that has a usable SmtpConfig."""
    report = SweepReport()
    domains = Domain.query.filter_by(is_active=True).all()
    report.domains_considered = len(domains)
    for d in domains:
        cfg = SmtpConfig.query.filter_by(domain_id=d.id, is_active=True).first()
        if cfg is None:
            report.domains_skipped_no_smtp += 1
            continue
        recipients = parse_recipients(cfg.recipients_csv)
        if not recipients:
            report.domains_skipped_no_smtp += 1
            continue
        thresholds = parse_thresholds(cfg.thresholds_csv)
        settings = _settings_from_config(cfg)
        certs = (ManagedCertificate.query
                 .filter(ManagedCertificate.domain_id == d.id,
                         ManagedCertificate.status == "active")
                 .all())
        report.certs_considered += len(certs)
        for cert in certs:
            valid_to, on_disk = _read_valid_to(cert)
            if valid_to is None:
                report.certs_missing_lineage += 1
                continue
            dte = (valid_to - _utcnow()).days
            threshold = _due_threshold_for(cert, dte, thresholds)
            if threshold is None:
                report.certs_no_threshold_due += 1
                continue
            view = CertExpiryView(
                cert=cert, valid_to=valid_to, days_to_expiry=dte,
                source_label=_source_label(cert),
                deployments_count=cert.deployments.count(),
                last_notified_threshold=None, on_disk_present=on_disk,
            )
            subject, text_body, html_body = _render_alert_body(
                view=view, threshold=threshold, settings=settings,
            )
            report.sends_attempted += 1
            result = send_smtp(
                settings=settings, to_addrs=recipients,
                subject=subject, body_text=text_body, body_html=html_body,
            )
            if result.ok:
                report.sends_ok += 1
            else:
                report.sends_failed += 1
            _record_outcome(
                cert_id=cert.id, threshold=threshold, recipients=recipients,
                days_to_expiry=dte, result=result,
            )
    report.finished_at = _utcnow()
    try:
        audit(
            feature="tls",
            action="expirations.sweep",
            target=f"{report.sends_ok}/{report.sends_attempted} ok",
            detail=(f"domains={report.domains_considered} "
                    f"skipped_no_smtp={report.domains_skipped_no_smtp} "
                    f"certs={report.certs_considered} "
                    f"no_threshold={report.certs_no_threshold_due} "
                    f"missing_lineage={report.certs_missing_lineage} "
                    f"sends_attempted={report.sends_attempted} "
                    f"sends_ok={report.sends_ok} "
                    f"sends_failed={report.sends_failed} "
                    f"triggered_by={triggered_by_user_email or 'system'}"),
            status="ok" if report.sends_failed == 0 else "warning",
        )
    except Exception:
        pass
    return report


# ── Recent-notifications view ────────────────────────────────────────────

def recent_notifications(domain_id: int | None, limit: int = 100):
    """Return latest CertExpirationNotification rows visible in this Domain.

    Joins through ManagedCertificate.domain_id to honor Domain scoping —
    an operator in Domain A never sees Domain B's notification history.
    """
    if domain_id is None:
        return []
    return (CertExpirationNotification.query
            .join(ManagedCertificate,
                  ManagedCertificate.id == CertExpirationNotification.certificate_id)
            .filter(ManagedCertificate.domain_id == domain_id)
            .order_by(CertExpirationNotification.sent_at.desc())
            .limit(limit)
            .all())
