"""Generic background-job runtime for long-running scans.

Both the DHCP subnet scan (`dhcp_scan_jobs`) and the Engines scan tool
(`engine_scan_jobs`) plug their feature-specific scanners into this
runtime. The runtime owns:

  * the module-local `_JOBS` dict (one per scan_id)
  * a `threading.Lock` serialising every read / write
  * a 15-min TTL eviction so abandoned jobs don't leak memory
  * per-job `user_email` ownership (no cross-user leaks across the
    deployment when multiple admins share the same instance)
  * primitives for runners to update progress + log lines + counters
  * a final `report` slot (opaque blob) that callers consume on done

The runtime is intentionally feature-agnostic: it doesn't know what's
being scanned, only that *something* is streaming progress events and
will eventually produce a final report. Each feature module owns its
own `start_scan(...)` function that:

  1. Builds the IP / port / target list from form input
  2. Calls `register_job(...)` to allocate a scan_id + initial state
  3. Spawns a daemon thread that runs the scanner, routing each
     event through `update_progress` / `append_log` / `increment` etc.
  4. On completion calls `mark_done(scan_id, report)` or
     `mark_failed(scan_id, error)`.

The status / consume / discard helpers are shared.

Cross-worker note: as in the original DHCP-only runtime, the dict is
process-local. Single-worker preload + threaded gunicorn = same
process serves all polls. Multi-worker deployments would need an
out-of-process store (Redis / SQLite-backed queue).
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

log = logging.getLogger(__name__)


_TTL = timedelta(minutes=15)
_LOG_TAIL_LINES = 10
_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}

# Cancel hooks per scan_id. Stored OUT of _JOBS so they don't leak into
# the JSON status payload (paramiko Channel objects aren't JSON-friendly,
# and we never want to expose their identity to the browser anyway).
_CANCEL_HOOKS: dict[str, "Callable[[], None]"] = {}


def _now():
    return datetime.now(timezone.utc)


def _cleanup_locked():
    """Evict jobs past TTL. Caller holds _LOCK."""
    now = _now()
    for k in list(_JOBS.keys()):
        if _JOBS[k].get("expires_at", now) < now:
            _JOBS.pop(k, None)


def _check_owner(s: dict, user_email: str) -> bool:
    """Don't leak scans across users. Empty user_email = system caller."""
    if not user_email:
        return True
    return (s.get("user_email") or "").lower() == user_email.lower()


# ── Lifecycle ────────────────────────────────────────────────────────────


def register_job(*, feature: str, user_email: str, total: int,
                 extra: Optional[dict] = None) -> str:
    """Allocate a new scan_id + initial state. Returns the scan_id.

    `feature` is a short tag for log / audit scoping ('dhcp', 'engines').
    `total` is the expected denominator for the progress bar.
    `extra` lets the caller stash feature-specific fields on the state
    dict (e.g. `subnet_cidr`, `source_node_index`) so polling clients
    can render them without an extra round-trip.
    """
    scan_id = uuid4().hex
    state = {
        "scan_id": scan_id,
        "feature": feature,
        "user_email": user_email,
        "state": "running",     # running | done | failed
        "progress": 0,
        "total": total,
        "log_tail": deque(maxlen=_LOG_TAIL_LINES),
        "counters": {},          # feature-specific: icmp_replies, ports_open, ...
        "started_at": _now(),
        "finished_at": None,
        "duration_ms": 0,
        "error": "",
        "report": None,          # final blob, set by mark_done
        "expires_at": _now() + _TTL,
    }
    if extra:
        state.update(extra)
    with _LOCK:
        _cleanup_locked()
        _JOBS[scan_id] = state
    return scan_id


def update_progress(scan_id: str, *, delta: int = 1) -> None:
    """Bump the progress counter by `delta`. Capped at total."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None:
            return
        s["progress"] = min(s["progress"] + delta, s["total"])


def increment(scan_id: str, counter: str, delta: int = 1) -> None:
    """Increment a feature-specific counter (creates it if missing)."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None:
            return
        s["counters"][counter] = s["counters"].get(counter, 0) + delta


def append_log(scan_id: str, line: str) -> None:
    """Append a line to the rolling 10-line log tail."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None:
            return
        s["log_tail"].append(line)


def update_extra(scan_id: str, **kwargs) -> None:
    """Patch feature-specific fields on the state dict (e.g.
    `phase2_pending`, `ports_open`). Used when a single value isn't a
    simple counter."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None:
            return
        s.update(kwargs)


def increment_extra(scan_id: str, key: str, delta: int = 1) -> None:
    """Bump a top-level state field by `delta`. Used for non-counter
    fields like `phase2_pending` / `phase2_done` that the polling UI
    reads directly (vs `counters[*]` which is generic)."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None:
            return
        s[key] = (s.get(key) or 0) + delta


def get_started_at(scan_id: str):
    """Read the started_at timestamp set by register_job. Used by
    runners that need to compute their own duration into the report."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        return s["started_at"] if s else None


def mark_done(scan_id: str, report: Any) -> None:
    """Final state transition for a successful scan. `report` is opaque
    — whatever the feature's consumer expects to read back."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None:
            return
        s["state"] = "done"
        s["report"] = report
        s["progress"] = s["total"]
        s["finished_at"] = _now()
        s["duration_ms"] = int(
            (s["finished_at"] - s["started_at"]).total_seconds() * 1000)
        s["expires_at"] = _now() + _TTL
        _CANCEL_HOOKS.pop(scan_id, None)


def mark_failed(scan_id: str, error: str) -> None:
    """Final state transition for a failed scan."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None:
            return
        s["state"] = "failed"
        s["error"] = error or "unknown error"
        s["finished_at"] = _now()
        s["duration_ms"] = int(
            (s["finished_at"] - s["started_at"]).total_seconds() * 1000)
        s["expires_at"] = _now() + _TTL
        _CANCEL_HOOKS.pop(scan_id, None)


# ── Cancel ──────────────────────────────────────────────────────────────


def register_cancel_hook(scan_id: str, hook: Callable[[], None]) -> None:
    """Register a callback the runner can invoke to interrupt itself.

    The runner registers this when it has something cancellable in
    flight (e.g. a paramiko channel whose ``readline()`` is blocked).
    ``request_cancel(scan_id)`` calls the hook from another thread —
    typically closing the channel forces ``readline()`` to return
    EOF and the runner exits its read loop cleanly.

    Idempotent: re-registering replaces the previous hook. Cleared
    automatically when the job transitions to ``done`` / ``failed``.
    """
    with _LOCK:
        _CANCEL_HOOKS[scan_id] = hook


def request_cancel(scan_id: str, user_email: str = "") -> bool:
    """Mark the scan as cancel-requested and fire its hook.

    Returns True if the hook fired (or no hook was registered but the
    job exists); False if the scan_id is unknown or owned by someone
    else. The caller still has to wait for the runner to notice — by
    the time this returns the runner may not have transitioned yet.
    """
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None or not _check_owner(s, user_email):
            return False
        s["cancel_requested"] = True
        hook = _CANCEL_HOOKS.pop(scan_id, None)
    if hook is not None:
        try:
            hook()
        except Exception:
            log.exception("cancel hook for scan_id=%s raised — ignoring", scan_id)
    return True


def is_cancel_requested(scan_id: str) -> bool:
    """Lightweight check the runner can poll between events."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        return bool(s and s.get("cancel_requested"))


# ── Runner harness ───────────────────────────────────────────────────────


def spawn_runner(scan_id: str, fn) -> None:
    """Spawn a daemon thread that runs `fn(scan_id)`. If `fn` raises,
    the runtime auto-marks the job failed with the exception message.
    """
    def _wrap():
        try:
            fn(scan_id)
        except Exception as exc:
            log.exception("scan_jobs: scan_id=%s crashed", scan_id)
            mark_failed(scan_id, f"crash: {exc}")

    t = threading.Thread(target=_wrap, name=f"scan-{scan_id[:8]}",
                         daemon=True)
    t.start()


# ── Read helpers (status / consume / discard) ───────────────────────────


def get_status(scan_id: str, user_email: str = "") -> Optional[dict]:
    """JSON-friendly snapshot for the polling endpoint.

    Returns None if the scan_id is unknown, expired, or owned by
    someone else. Caller surfaces None as a 404.
    """
    with _LOCK:
        _cleanup_locked()
        s = _JOBS.get(scan_id)
        if s is None or not _check_owner(s, user_email):
            return None
        out = {
            "scan_id": s["scan_id"],
            "feature": s["feature"],
            "state": s["state"],
            "progress": s["progress"],
            "total": s["total"],
            "log_tail": list(s["log_tail"]),
            "counters": dict(s["counters"]),
            "duration_ms": s["duration_ms"],
            "error": s["error"],
        }
        # Pass through any feature-specific extras (e.g. subnet_cidr,
        # source_node_index) that aren't covered by the canonical fields.
        for k, v in s.items():
            if k not in out and k not in ("user_email", "started_at",
                                          "finished_at", "expires_at",
                                          "report"):
                out[k] = v
        return out


def consume_report(scan_id: str, user_email: str = "") -> Optional[Any]:
    """One-shot read of the final report. Removes the job from memory.

    Returns None if the scan isn't done yet, unknown, or wrong owner.
    Whatever the runner stashed via `mark_done(report=...)` comes back
    here — opaque to the runtime, typed by the feature.
    """
    with _LOCK:
        _cleanup_locked()
        s = _JOBS.get(scan_id)
        if s is None or not _check_owner(s, user_email):
            return None
        if s["state"] != "done":
            return None
        _JOBS.pop(scan_id, None)
        return s["report"]


def discard(scan_id: str, user_email: str = "") -> bool:
    """Forget the scan without consuming results. Used when the operator
    cancels or the page renders without consuming."""
    with _LOCK:
        s = _JOBS.get(scan_id)
        if s is None or not _check_owner(s, user_email):
            return False
        _JOBS.pop(scan_id, None)
        return True
