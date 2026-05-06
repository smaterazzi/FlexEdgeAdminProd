"""Platform-wide log writer + settings helpers.

Implements the standing rule (memory: feedback_logging_standing_rule):
every feature funnels its audit + operational entries through one
platform log system, replacing the per-feature `_log_activity` tables.

Public API
----------

  audit(feature, action, *, target="", detail="", status="ok",
        source_correlation_id=None, user_email=None, domain_id=None)
      Always persisted (level="audit").

  op(feature, action, *, target="", detail="", status="ok",
     source_correlation_id=None, user_email=None, domain_id=None)
      Persisted only when log_mode="verbose" (level="op").

  register_feature(name, label=None)
      Add a feature to the registry — drives the per-feature toggle list
      on /admin/log-settings. Called at app boot.

  list_features() -> list[dict]
      Snapshot of the registered features (name, label).

  is_feature_enabled(feature) -> bool
      Reads the per-feature toggle setting (default ON).

  get_setting(key, default=None) / set_setting(key, value, by_email=None)
      Generic platform-settings access used by the Logs settings page.

  current_log_mode() -> "normal" | "verbose"
  current_retention_days() -> int

Standing behaviour
------------------

* Logging must never break the request. All write paths are wrapped in
  try/except — a write failure is reported to the stdlib logger but
  never propagated to the caller.
* `user_email` and `domain_id` are best-effort: when called from a
  request handler, they're resolved from `session["user"]` and `g.domain`
  respectively. Out-of-band callers (cron sweeps, system bootstrap) end
  up with None for both — those rows render as "system" in the UI.
* Feature toggles default to ON. The /admin/log-settings page may set
  any feature to "off" to suppress its writes entirely.
"""

import logging
from typing import Optional

from flask import g, session, has_request_context

log = logging.getLogger(__name__)


# ── Feature registry ──────────────────────────────────────────────────────
# Populated by register_feature() at app boot. Each entry is
# {"name": str, "label": str}. The Logs settings page lists these in
# stable insertion order.

_FEATURE_REGISTRY: list[dict] = []


def register_feature(name: str, label: Optional[str] = None) -> None:
    """Register a feature name in the platform log registry.

    Idempotent — calling twice with the same name is a no-op.
    """
    name = (name or "").strip()
    if not name:
        return
    for entry in _FEATURE_REGISTRY:
        if entry["name"] == name:
            if label and not entry.get("label"):
                entry["label"] = label
            return
    _FEATURE_REGISTRY.append({"name": name, "label": label or name.title()})


def list_features() -> list[dict]:
    """Snapshot of the feature registry (name + label) in stable order."""
    return [dict(entry) for entry in _FEATURE_REGISTRY]


# ── Settings access (platform_settings table) ────────────────────────────

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """Read a platform_settings value. Returns `default` if the key is unset.

    Falls through gracefully when the DB layer isn't available (CLI / cron
    callers that never imported the Flask app context).
    """
    try:
        from webapp.models import PlatformSetting
        row = PlatformSetting.query.filter_by(key=key).first()
        return row.value if row else default
    except Exception:
        return default


def set_setting(key: str, value: str,
                by_email: Optional[str] = None) -> None:
    """Upsert a platform_settings row.

    Records `updated_by_email` for audit purposes.
    """
    try:
        from shared.db import db
        from webapp.models import PlatformSetting
        row = PlatformSetting.query.filter_by(key=key).first()
        if row is None:
            row = PlatformSetting(key=key, value=str(value),
                                  updated_by_email=by_email)
            db.session.add(row)
        else:
            row.value = str(value)
            row.updated_by_email = by_email
        db.session.commit()
    except Exception as exc:
        log.warning("platform_settings upsert failed (key=%s): %s", key, exc)


def current_log_mode() -> str:
    """Return 'normal' or 'verbose' (default normal)."""
    mode = (get_setting("log_mode", "normal") or "normal").lower()
    return "verbose" if mode == "verbose" else "normal"


def current_retention_days() -> int:
    """Default 90 days when unset; clamped to >= 1."""
    raw = get_setting("log_retention_days", "90") or "90"
    try:
        n = int(raw)
    except ValueError:
        n = 90
    return max(1, n)


def is_feature_enabled(feature: str) -> bool:
    """True if logging for this feature is on (default ON)."""
    raw = get_setting(f"feature_log_{feature}", "on") or "on"
    return raw.strip().lower() != "off"


def set_feature_enabled(feature: str, enabled: bool,
                        by_email: Optional[str] = None) -> None:
    set_setting(f"feature_log_{feature}", "on" if enabled else "off",
                by_email=by_email)


# ── Context resolution helpers ───────────────────────────────────────────

def _resolve_user_email() -> Optional[str]:
    if not has_request_context():
        return None
    info = session.get("user") or {}
    val = (info.get("email") or "").strip()
    return val or None


def _resolve_domain_id() -> Optional[int]:
    if not has_request_context():
        return None
    domain = getattr(g, "domain", None)
    return getattr(domain, "id", None) if domain is not None else None


# ── Write paths ───────────────────────────────────────────────────────────

def audit(feature: str, action: str, *,
          target: str = "", detail: str = "",
          status: str = "ok",
          source_correlation_id: Optional[str] = None,
          user_email: Optional[str] = None,
          domain_id: Optional[int] = None) -> None:
    """Write a level='audit' platform log entry. Always persisted (subject
    to the per-feature toggle).
    """
    _write(level="audit", feature=feature, action=action,
           target=target, detail=detail, status=status,
           source_correlation_id=source_correlation_id,
           user_email=user_email, domain_id=domain_id)


def op(feature: str, action: str, *,
       target: str = "", detail: str = "",
       status: str = "ok",
       source_correlation_id: Optional[str] = None,
       user_email: Optional[str] = None,
       domain_id: Optional[int] = None) -> None:
    """Write a level='op' platform log entry. Persisted only when the
    platform log_mode is 'verbose' (and the feature toggle is ON).
    """
    if current_log_mode() != "verbose":
        return
    _write(level="op", feature=feature, action=action,
           target=target, detail=detail, status=status,
           source_correlation_id=source_correlation_id,
           user_email=user_email, domain_id=domain_id)


def _write(*, level: str, feature: str, action: str,
           target: str, detail: str, status: str,
           source_correlation_id: Optional[str],
           user_email: Optional[str],
           domain_id: Optional[int]) -> None:
    """Inner write — applies the feature toggle, never raises.

    Suppression order: feature toggle off → drop. Otherwise insert.
    Field truncation is defensive (DB columns have soft caps); a feature
    that emits an oversize detail blob still writes successfully.
    """
    feature = (feature or "").strip() or "unknown"
    if not is_feature_enabled(feature):
        return
    try:
        from shared.db import db
        from webapp.models import PlatformLog
        row = PlatformLog(
            level=level if level in ("audit", "op") else "audit",
            feature=feature,
            action=(action or "")[:128] or "unspecified",
            status=(status or "ok")[:16],
            user_email=user_email if user_email is not None else _resolve_user_email(),
            target=(target or "")[:512],
            detail=(detail or "")[:4000],
            domain_id=domain_id if domain_id is not None else _resolve_domain_id(),
            source_correlation_id=((source_correlation_id or "")[:64] or None),
        )
        db.session.add(row)
        db.session.commit()
    except Exception as exc:
        # Log writes must never break the caller — fall back to stdlib.
        log.warning("platform log write failed (feature=%s action=%s): %s",
                    feature, action, exc)
        try:
            from shared.db import db
            db.session.rollback()
        except Exception:
            pass


# ── Retention sweep ──────────────────────────────────────────────────────

def sweep_old_logs(retention_days: Optional[int] = None) -> dict:
    """Delete platform_logs rows older than the retention horizon.

    `system` feature rows that match well-known sentinel actions are
    preserved (Phase 0 validation marker, etc.) — the retention sweep
    must never erase the gate signals that gate Phase 4 deploys.
    """
    if retention_days is None:
        retention_days = current_retention_days()
    try:
        from datetime import datetime, timezone, timedelta
        from shared.db import db
        from webapp.models import PlatformLog
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        # Preserve gate-signal rows.
        preserved_actions = ("phase0_validated",)
        q = PlatformLog.query.filter(
            PlatformLog.timestamp < cutoff,
            ~((PlatformLog.feature == "system")
              & (PlatformLog.action.in_(preserved_actions)))
        )
        deleted = q.delete(synchronize_session=False)
        db.session.commit()
        log.info("platform log sweep: deleted %d rows older than %s",
                 deleted, cutoff.isoformat())
        return {"deleted": deleted, "cutoff": cutoff.isoformat()}
    except Exception as exc:
        log.error("platform log sweep failed: %s", exc)
        try:
            from shared.db import db
            db.session.rollback()
        except Exception:
            pass
        return {"deleted": 0, "error": str(exc)}
