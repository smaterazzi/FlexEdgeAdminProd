"""Retention sweeper for engine scan records.

Two modes (configured via platform_settings):
  count: keep the latest N scans per (engine_name, source_iface_label)
  days:  keep scans newer than N days

Starred rows are NEVER deleted, regardless of mode.

Schedule-anchor preservation (Phase 4): when phase 4 lands, also keep
the most recent record per schedule_id even if it would otherwise be
eligible. Today there are no schedules, so the predicate is a no-op.

Public API:
  sweep_retention(domain) -> SweepReport
  was_swept_recently()    -> bool   (true if last sweep < 1 hour ago)
  mark_swept_now()
  ensure_lazy_sweep(domain) -> SweepReport | None  (if due, sweep & return)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from shared.db import db
from shared.logging import audit, get_setting, set_setting
from webapp.models import EngineScanRecord
from webapp.scan_history import service

log = logging.getLogger("scan_history.retention")


@dataclass
class SweepReport:
    mode: str
    value: int
    deleted: int
    kept_starred: int
    kept_recent: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def was_swept_recently() -> bool:
    """Return True if the last sweep was less than 1 hour ago."""
    raw = get_setting(service.SETTING_LAST_SWEEP_AT)
    if not raw:
        return False
    try:
        ts = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (_utcnow() - ts) < timedelta(hours=1)


def mark_swept_now() -> None:
    """Stamp the last-sweep marker at now()."""
    set_setting(service.SETTING_LAST_SWEEP_AT, _utcnow().isoformat())


def ensure_lazy_sweep(domain) -> SweepReport | None:
    """Run a sweep if the last one was more than 1 hour ago. Best-effort.

    Phase 1 has no background ticker; this lazy check on page load is
    enough to keep retention pruning the table without forcing the
    operator to click anything. Sweeper is cheap (one indexed scan +
    bulk delete).
    """
    if was_swept_recently():
        return None
    try:
        report = sweep_retention(domain)
        mark_swept_now()
        return report
    except Exception as exc:
        log.warning("lazy sweep failed: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def sweep_retention(domain) -> SweepReport:
    """Apply the configured retention rule. Returns a SweepReport.

    `domain` is required so we don't sweep across boundaries the caller
    doesn't expect — every Domain is responsible for its own retention.
    """
    settings = service.get_settings()
    mode = settings["mode"]
    value = settings["value"]

    starred_count = (EngineScanRecord.query
                     .filter(EngineScanRecord.domain_id == domain.id,
                             EngineScanRecord.starred.is_(True))
                     .count())

    if mode == "days":
        cutoff = _utcnow() - timedelta(days=value)
        eligible = (EngineScanRecord.query
                    .filter(EngineScanRecord.domain_id == domain.id,
                            EngineScanRecord.starred.is_(False),
                            EngineScanRecord.started_at < cutoff)
                    .all())
        kept_recent = (EngineScanRecord.query
                       .filter(EngineScanRecord.domain_id == domain.id,
                               EngineScanRecord.starred.is_(False),
                               EngineScanRecord.started_at >= cutoff)
                       .count())
    else:  # count mode — keep latest N per (engine, iface)
        # Group by scope; for each scope, identify rows beyond rank N.
        rows = (EngineScanRecord.query
                .filter(EngineScanRecord.domain_id == domain.id)
                .order_by(EngineScanRecord.engine_name.asc(),
                          EngineScanRecord.source_iface_label.asc(),
                          EngineScanRecord.started_at.desc())
                .all())
        eligible: list[EngineScanRecord] = []
        kept_recent = 0
        per_scope_count: dict[tuple[str, str], int] = {}
        for r in rows:
            scope = (r.engine_name or "", r.source_iface_label or "")
            per_scope_count[scope] = per_scope_count.get(scope, 0) + 1
            rank = per_scope_count[scope]
            if r.starred:
                continue
            if rank <= value:
                kept_recent += 1
            else:
                eligible.append(r)

    deleted = 0
    for r in eligible:
        try:
            db.session.delete(r)
            deleted += 1
        except Exception as exc:
            log.warning("delete scan #%s failed: %s", r.id, exc)
    if deleted:
        db.session.commit()

    audit(service.FEATURE, "retention.sweep",
          target=f"domain={domain.id}",
          detail=(f"mode={mode} value={value} deleted={deleted} "
                  f"kept_starred={starred_count} kept_recent={kept_recent}"))
    return SweepReport(
        mode=mode, value=value,
        deleted=deleted,
        kept_starred=starred_count,
        kept_recent=kept_recent,
    )
