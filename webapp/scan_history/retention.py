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

from sqlalchemy import func

from shared.db import db
from shared.logging import audit, get_setting, set_setting
from webapp.models import EngineScanHost, EngineScanRecord
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
        eligible_ids = [
            row[0] for row in
            (EngineScanRecord.query
             .filter(EngineScanRecord.domain_id == domain.id,
                     EngineScanRecord.starred.is_(False),
                     EngineScanRecord.started_at < cutoff)
             .with_entities(EngineScanRecord.id)
             .all())
        ]
        kept_recent = (EngineScanRecord.query
                       .filter(EngineScanRecord.domain_id == domain.id,
                               EngineScanRecord.starred.is_(False),
                               EngineScanRecord.started_at >= cutoff)
                       .count())
    else:  # count mode — keep latest N per (engine, iface)
        # Audit M6 (2026-06-11): rank rows SQL-side with a window
        # function instead of materialising every ORM row in memory.
        # Rank counts ALL rows per scope (starred included — they
        # occupy retention slots, same as the previous Python logic);
        # only non-starred rows beyond rank N are deleted.
        rk = func.row_number().over(
            partition_by=(EngineScanRecord.engine_name,
                          EngineScanRecord.source_iface_label),
            order_by=EngineScanRecord.started_at.desc(),
        ).label("rk")
        ranked = (db.session.query(
                      EngineScanRecord.id.label("id"),
                      EngineScanRecord.starred.label("starred"),
                      rk)
                  .filter(EngineScanRecord.domain_id == domain.id)
                  .subquery())
        eligible_ids = [
            row[0] for row in
            db.session.query(ranked.c.id)
            .filter(ranked.c.rk > value, ranked.c.starred.is_(False))
            .all()
        ]
        nonstarred_total = (EngineScanRecord.query
                            .filter(EngineScanRecord.domain_id == domain.id,
                                    EngineScanRecord.starred.is_(False))
                            .count())
        kept_recent = nonstarred_total - len(eligible_ids)

    # Audit L10 (2026-06-11): bulk DELETEs instead of per-row ORM
    # deletes — the ORM path issued one child-host DELETE per scan via
    # the cascade. Chunked to stay under SQLite's bind-parameter cap.
    deleted = 0
    _CHUNK = 400
    try:
        for i in range(0, len(eligible_ids), _CHUNK):
            chunk = eligible_ids[i:i + _CHUNK]
            (db.session.query(EngineScanHost)
             .filter(EngineScanHost.scan_id.in_(chunk))
             .delete(synchronize_session=False))
            deleted += (db.session.query(EngineScanRecord)
                        .filter(EngineScanRecord.id.in_(chunk))
                        .delete(synchronize_session=False))
        if deleted:
            db.session.commit()
    except Exception as exc:
        log.warning("retention bulk delete failed: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass

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
