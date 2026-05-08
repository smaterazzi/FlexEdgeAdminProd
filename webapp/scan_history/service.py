"""Scan history persistence + read API.

Public entry points:
  register_scan(domain, report, ...)   → EngineScanRecord
  list_scans(domain, **filters)        → list[EngineScanRecord]
  get_scan(domain, scan_id)            → EngineScanRecord | None
  set_comment(domain, scan_id, comment, user_email)
  set_starred(domain, scan_id, starred, user_email)
  delete_scan(domain, scan_id, user_email)
  get_settings()                       → dict (retention mode + value)
  set_settings(mode, value, user_email)

All mutating calls audit via shared.logging.audit().
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy import insert, select, and_, or_

from shared.db import db
from shared.logging import audit, get_setting, set_setting
from webapp.models import (
    EngineScanRecord,
    EngineScanHost,
    Domain,
)

log = logging.getLogger("scan_history.service")

FEATURE = "engine_scan_history"

# Settings keys (read via shared.logging.get_setting)
SETTING_RETENTION_MODE = "engine_scan_retention_mode"   # "count" | "days"
SETTING_RETENTION_VALUE = "engine_scan_retention_value"
SETTING_LAST_SWEEP_AT = "engine_scan_last_sweep_at"     # ISO8601 utc
DEFAULT_RETENTION_MODE = "count"
DEFAULT_RETENTION_VALUE = "20"


def _ip_to_int(ip: str) -> int:
    """Convert "a.b.c.d" → 32-bit integer for sorting. Lenient on bad input."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return 0
        a, b, c, d = (int(p) for p in parts)
        return (a << 24) | (b << 16) | (c << 8) | d
    except Exception:
        return 0


def _split_iface_label(name: str) -> tuple[str, str, str]:
    """`'1.42'` → ('1', '42', '1.42'). Plain physical iface → ('1', '', '1')."""
    if not name:
        return "", "", ""
    if "." in name:
        head, tail = name.rsplit(".", 1)
        return head, tail, name
    return name, "", name


def register_scan(domain, report, *,
                  user_id: Optional[int] = None,
                  schedule_id: Optional[int] = None,
                  source: str = "manual",
                  source_correlation: str = "") -> Optional[EngineScanRecord]:
    """Persist an EngineScanReport into the DB.

    Returns the inserted EngineScanRecord on success, None on failure.
    Failures are audit-logged but never raised — the caller already has
    the in-memory results, so a missed write degrades gracefully to
    "results visible this session, gone next time".
    """
    if domain is None or report is None:
        return None

    try:
        iface_id, vlan, label = _split_iface_label(report.source_iface_name
                                                   or report.source_iface_id)

        # Online IPs = anything that gave any reply (icmp OR arp).
        online = sum(1 for r in report.results.values()
                     if r.icmp_reply or r.arp_reply)

        rec = EngineScanRecord(
            domain_id=domain.id,
            user_id=user_id,
            schedule_id=schedule_id,
            engine_name=report.target_label.split("/", 1)[0]
                        if "/" in report.target_label else "",
            node_index=report.source_node_index,
            source_iface_id=iface_id,
            source_iface_vlan=vlan,
            source_iface_label=label,
            source_subnet_cidr="",
            target_label=report.target_label,
            target_mode=_infer_target_mode(report.target_label),
            ports_csv=",".join(str(p) for p in report.ports_scanned),
            total_targets=report.targets,
            duration_ms=report.duration_ms,
            icmp_replies=report.icmp_replies,
            arp_replies=report.arp_replies,
            hosts_with_open=report.hosts_with_open_ports,
            online_ips=online,
            source=source,
            source_correlation=source_correlation,
            starred=False,
            comment="",
            started_at=report.started_at,
            finished_at=report.finished_at or report.started_at,
        )
        db.session.add(rec)
        db.session.flush()  # populates rec.id

        if report.results:
            host_rows = []
            for ip, r in report.results.items():
                open_ports = sorted(p for p, s in r.ports.items() if s == "open")
                closed_ports = sorted(p for p, s in r.ports.items() if s == "closed")
                host_rows.append({
                    "scan_id": rec.id,
                    "ip": ip,
                    "ip_int": _ip_to_int(ip),
                    "icmp_reply": bool(r.icmp_reply),
                    "arp_reply": bool(r.arp_reply),
                    "mac": (r.mac or "")[:32],
                    "hostname": (r.hostname or "")[:255],
                    "open_ports_csv": ",".join(str(p) for p in open_ports),
                    "closed_ports_csv": ",".join(str(p) for p in closed_ports),
                })
            db.session.execute(insert(EngineScanHost), host_rows)

        db.session.commit()
        audit(FEATURE, "scan.persist",
              target=f"{rec.engine_name}/{rec.source_iface_label}",
              detail=(f"online={online} ports={len(report.ports_scanned)} "
                      f"targets={rec.total_targets} "
                      f"duration_ms={rec.duration_ms} source={source}"),
              source_correlation_id=source_correlation or None)
        return rec
    except Exception as exc:
        log.warning("register_scan failed: %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass
        try:
            audit(FEATURE, "scan.persist", status="error",
                  target=getattr(report, "target_label", ""),
                  detail=str(exc)[:400],
                  source_correlation_id=source_correlation or None)
        except Exception:
            pass
        return None


def _infer_target_mode(target_label: str) -> str:
    """Heuristic: `→ X/Y` = subnet, `→ A-B` = custom_range, else single_ip."""
    if "/" in (target_label or "").split("→", 1)[-1]:
        return "subnet"
    if "-" in (target_label or "").split("→", 1)[-1]:
        return "custom_range"
    return "single_ip"


def list_scans(domain, *,
               engine_name: Optional[str] = None,
               iface_label: Optional[str] = None,
               starred_only: bool = False,
               since_days: Optional[int] = None,
               limit: int = 100,
               offset: int = 0) -> list[EngineScanRecord]:
    """Return EngineScanRecord rows scoped to the active Domain, newest first."""
    if domain is None:
        return []
    q = (EngineScanRecord.query
         .filter(EngineScanRecord.domain_id == domain.id))
    if engine_name:
        q = q.filter(EngineScanRecord.engine_name == engine_name)
    if iface_label:
        q = q.filter(EngineScanRecord.source_iface_label == iface_label)
    if starred_only:
        q = q.filter(EngineScanRecord.starred.is_(True))
    if since_days and since_days > 0:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        q = q.filter(EngineScanRecord.started_at >= cutoff)
    return (q.order_by(EngineScanRecord.started_at.desc())
             .limit(limit).offset(offset).all())


def count_scans(domain, **filters) -> int:
    """Count rows under the same filter rules as `list_scans` (for paging)."""
    if domain is None:
        return 0
    q = EngineScanRecord.query.filter(EngineScanRecord.domain_id == domain.id)
    if filters.get("engine_name"):
        q = q.filter(EngineScanRecord.engine_name == filters["engine_name"])
    if filters.get("iface_label"):
        q = q.filter(EngineScanRecord.source_iface_label == filters["iface_label"])
    if filters.get("starred_only"):
        q = q.filter(EngineScanRecord.starred.is_(True))
    if filters.get("since_days") and filters["since_days"] > 0:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=filters["since_days"])
        q = q.filter(EngineScanRecord.started_at >= cutoff)
    return q.count()


def get_scan(domain, scan_id: int) -> Optional[EngineScanRecord]:
    """Return one record (must belong to the active Domain), else None."""
    if domain is None or not scan_id:
        return None
    return (EngineScanRecord.query
            .filter(EngineScanRecord.id == scan_id,
                    EngineScanRecord.domain_id == domain.id)
            .first())


def get_hosts(scan: EngineScanRecord) -> list[EngineScanHost]:
    """Return a scan's hosts ordered by numeric IP."""
    if scan is None:
        return []
    return (EngineScanHost.query
            .filter(EngineScanHost.scan_id == scan.id)
            .order_by(EngineScanHost.ip_int.asc(),
                      EngineScanHost.ip.asc())
            .all())


def set_comment(domain, scan_id: int, comment: str,
                user_email: Optional[str] = None) -> bool:
    rec = get_scan(domain, scan_id)
    if rec is None:
        return False
    prev = (rec.comment or "")[:80]
    rec.comment = (comment or "")[:4000]
    db.session.commit()
    audit(FEATURE, "scan.comment",
          target=f"#{rec.id}",
          detail=f"prev={prev!r} new={(rec.comment or '')[:80]!r}",
          user_email=user_email)
    return True


def set_starred(domain, scan_id: int, starred: bool,
                user_email: Optional[str] = None) -> bool:
    rec = get_scan(domain, scan_id)
    if rec is None:
        return False
    rec.starred = bool(starred)
    db.session.commit()
    audit(FEATURE, "scan.star" if starred else "scan.unstar",
          target=f"#{rec.id}",
          detail=f"engine={rec.engine_name} iface={rec.source_iface_label}",
          user_email=user_email)
    return True


def delete_scan(domain, scan_id: int,
                user_email: Optional[str] = None) -> bool:
    rec = get_scan(domain, scan_id)
    if rec is None:
        return False
    label = f"{rec.engine_name}/{rec.source_iface_label}"
    db.session.delete(rec)   # cascade nukes hosts via ondelete=CASCADE
    db.session.commit()
    audit(FEATURE, "scan.delete",
          target=f"#{scan_id}", detail=f"engine={label}",
          user_email=user_email)
    return True


def bulk_set_starred(domain, scan_ids: Iterable[int], starred: bool,
                     user_email: Optional[str] = None) -> int:
    """Star/unstar many at once. Returns rows affected."""
    if domain is None:
        return 0
    ids = [int(i) for i in scan_ids if i]
    if not ids:
        return 0
    rows = (EngineScanRecord.query
            .filter(EngineScanRecord.id.in_(ids),
                    EngineScanRecord.domain_id == domain.id)
            .all())
    for r in rows:
        r.starred = bool(starred)
    db.session.commit()
    if rows:
        audit(FEATURE, "scan.star" if starred else "scan.unstar",
              target=f"bulk[{len(rows)}]",
              detail=f"ids={','.join(str(r.id) for r in rows[:20])}",
              user_email=user_email)
    return len(rows)


def bulk_delete(domain, scan_ids: Iterable[int],
                user_email: Optional[str] = None) -> int:
    """Hard-delete many at once. Returns rows affected."""
    if domain is None:
        return 0
    ids = [int(i) for i in scan_ids if i]
    if not ids:
        return 0
    rows = (EngineScanRecord.query
            .filter(EngineScanRecord.id.in_(ids),
                    EngineScanRecord.domain_id == domain.id)
            .all())
    n = len(rows)
    for r in rows:
        db.session.delete(r)
    db.session.commit()
    if n:
        audit(FEATURE, "scan.delete",
              target=f"bulk[{n}]", detail=f"ids={','.join(str(i) for i in ids[:20])}",
              user_email=user_email)
    return n


# ── Time-series aggregation (Phase 3 — graph) ───────────────────────────

def aggregate_for_graph(domain, *,
                        engine_name: Optional[str] = None,
                        iface_label: Optional[str] = None,
                        since_days: Optional[int] = None,
                        ) -> list[dict]:
    """Return scan rows for the time-series chart, ASC by started_at.

    Each entry: {scan_id, ts (iso utc), ts_ms (epoch), online_ips,
                 hosts_with_open, total_targets, source, starred,
                 engine, iface}. Unfiltered call returns every scan in
                 the active Domain.
    """
    if domain is None:
        return []
    q = (EngineScanRecord.query
         .filter(EngineScanRecord.domain_id == domain.id))
    if engine_name:
        q = q.filter(EngineScanRecord.engine_name == engine_name)
    if iface_label:
        q = q.filter(EngineScanRecord.source_iface_label == iface_label)
    if since_days and since_days > 0:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        q = q.filter(EngineScanRecord.started_at >= cutoff)
    rows = q.order_by(EngineScanRecord.started_at.asc()).all()
    out: list[dict] = []
    for r in rows:
        ts = r.started_at
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        out.append({
            "scan_id": r.id,
            "ts": ts.isoformat(),
            "ts_ms": int(ts.timestamp() * 1000),
            "online_ips": int(r.online_ips or 0),
            "hosts_with_open": int(r.hosts_with_open or 0),
            "total_targets": int(r.total_targets or 0),
            "source": r.source or "manual",
            "starred": bool(r.starred),
            "engine": r.engine_name or "",
            "iface": r.source_iface_label or "",
            "comment": (r.comment or "")[:160],
        })
    return out


# ── Settings ─────────────────────────────────────────────────────────────

def get_settings() -> dict:
    """Return the retention settings (with defaults applied)."""
    mode = (get_setting(SETTING_RETENTION_MODE) or DEFAULT_RETENTION_MODE).lower()
    if mode not in ("count", "days"):
        mode = DEFAULT_RETENTION_MODE
    raw = get_setting(SETTING_RETENTION_VALUE) or DEFAULT_RETENTION_VALUE
    try:
        value = max(1, int(raw))
    except (TypeError, ValueError):
        value = int(DEFAULT_RETENTION_VALUE)
    return {"mode": mode, "value": value}


def set_settings(mode: str, value: int,
                 user_email: Optional[str] = None) -> dict:
    """Persist the retention settings; emit audit; return resolved dict."""
    mode = (mode or "").strip().lower()
    if mode not in ("count", "days"):
        raise ValueError(f"retention mode must be 'count' or 'days', got {mode!r}")
    try:
        value = int(value)
        if value < 1:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError(f"retention value must be a positive int, got {value!r}")
    set_setting(SETTING_RETENTION_MODE, mode, user_email=user_email)
    set_setting(SETTING_RETENTION_VALUE, str(value), user_email=user_email)
    audit(FEATURE, "settings.update", target="retention",
          detail=f"mode={mode} value={value}", user_email=user_email)
    return {"mode": mode, "value": value}
