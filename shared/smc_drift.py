"""SMC drift detector — Phase G of the Change Management process.

Compares the registry (`smc_objects.last_seen_hash`) against a fresh SMC
fetch of the same element. Mismatches surface as drift cards on the
queue page and per-row badges on listings, prompting the operator to
either reconcile (re-baseline) or roll back via the queue.

Spec: docs/ChangeManagementProcess.md § Phase G.

Hash is per-type. Each `smc_type` has a whitelist of fields whose
*meaningful* state we care about. Comments have FlexEdge audit markers
stripped before hashing so successful pushes don't immediately mark
their own elements as drifted.

Public API
----------

  compute_drift_hash(smc_type, data) -> str
    Stable SHA-256 of the type's whitelisted fields.

  extract_relevant_fields(smc_type, data) -> dict
    The exact dict that gets hashed. Useful for diff-style detail.

  scan_domain_drift(domain) -> DriftReport
    Opens an SMC session, iterates `smc_objects` for the Domain,
    fetches each, classifies as clean/drifted/gone, updates the rows.

  drift_summary(domain) -> dict
    Fast counts by drift_state for the domain. Used by the dashboard
    card without re-running a scan.

  drifted_keys_for_domain(domain) -> set
    Set of (href OR name) strings flagged drifted/gone — used by the
    Jinja helper that draws per-row badges in feature listings.
"""

from __future__ import annotations

import hashlib
import json as _json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

log = logging.getLogger(__name__)


# FlexEdge marker patterns — duplicated locally so we can strip them
# without pulling in the smc-python SDK (smc_dhcp_client imports it at
# module level). Keep these in sync with webapp/smc_audit_marker.py and
# webapp/smc_dhcp_client.py.
_AUDIT_MARKER_RE = re.compile(
    r"\[\s*flexedge:audit\s+"
    r"ts=[^\s\]]+"
    r"(?:\s+user=[^\s\]]+)?"
    r"(?:\s+prev=\"(?:[^\"\\]|\\.)*\")?"
    r"\s*\]",
    re.IGNORECASE,
)
_MAC_MARKER_RE = re.compile(
    r"\[\s*flexedge:mac=[^\]]+\]",
    re.IGNORECASE,
)


# ── Per-type field whitelists ────────────────────────────────────────────
#
# Hash only the fields we *care* about for drift detection. Volatile
# attributes (`link`, `key`, `system_key`, `mod_time`, `mod_user`,
# `read_only`) are intentionally excluded — they change on every save
# and would force constant false-positive drift.

_HASH_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("name", "address", "ipv6_address", "secondary"),
    "network": ("name", "ipv4_network", "ipv6_network"),
    "address_range": ("name", "ip_range"),
    "fqdn": ("name", "value"),
    "tcp_service": ("name", "min_dst_port", "max_dst_port"),
    "udp_service": ("name", "min_dst_port", "max_dst_port"),
    "ip_service": ("name", "protocol_number"),
    "icmp_service": ("name", "icmp_type", "icmp_code"),
    "group": ("name", "element"),
    "service_group": ("name", "element"),
    # Engines + policies + rules are too volatile and large to hash by
    # default — Phase G covers leaf elements first; rule drift can be
    # added later if needed.
    "engine": ("name",),
    "tls_credential": ("name",),
}

# Types we never hash even if a row exists — they're tracked for
# strikethrough / inventory but not for drift.
_NO_DRIFT_TYPES = frozenset({"engine", "tls_credential", "policy",
                             "rule", "nat_rule", "section"})


def _strip_comment_markers(comment: str) -> str:
    """Remove FlexEdge markers from an SMC element comment.

    Both `[flexedge:mac=...]` and `[flexedge:audit ...]` are stripped so
    the hash is stable across our own writes (which always re-stamp the
    audit marker).
    """
    if not comment:
        return ""
    cleaned = _MAC_MARKER_RE.sub("", comment)
    cleaned = _AUDIT_MARKER_RE.sub("", cleaned)
    return cleaned.strip()


def extract_relevant_fields(smc_type: str, data: dict) -> dict:
    """Return the dict that gets hashed for this element type.

    Falls back to the empty dict for unknown types — they never drift
    until somebody adds them to `_HASH_FIELDS`.
    """
    if not data:
        return {}
    fields = _HASH_FIELDS.get(smc_type or "")
    if not fields:
        return {}
    out: dict[str, Any] = {}
    for f in fields:
        if f not in data:
            continue
        v = data.get(f)
        if isinstance(v, list):
            # Sorted for stability — group members may come back in any order.
            out[f] = sorted([str(x) for x in v])
        elif isinstance(v, dict):
            out[f] = _json.dumps(v, sort_keys=True)
        else:
            out[f] = v
    # Comment is always stripped of FlexEdge markers (audit + mac) so
    # our own writes don't trip drift on the next scan.
    if "comment" in data:
        out["comment"] = _strip_comment_markers(data.get("comment") or "")
    return out


def compute_drift_hash(smc_type: str, data: dict) -> str:
    """Return a stable SHA-256 hex digest of the relevant fields.

    Empty string for types we don't track.
    """
    if (smc_type or "") in _NO_DRIFT_TYPES and smc_type not in _HASH_FIELDS:
        return ""
    relevant = extract_relevant_fields(smc_type, data)
    if not relevant:
        return ""
    blob = _json.dumps(relevant, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _format_diff(old: dict, new: dict) -> str:
    """Build a short human-readable summary of the differences.

    Trimmed to ~480 chars to fit `SmcObject.drift_detail`.
    """
    parts = []
    keys = sorted(set(old) | set(new))
    for k in keys:
        ov = old.get(k)
        nv = new.get(k)
        if ov == nv:
            continue
        ovs = repr(ov) if ov is not None else "—"
        nvs = repr(nv) if nv is not None else "—"
        if len(ovs) > 60: ovs = ovs[:57] + "…"
        if len(nvs) > 60: nvs = nvs[:57] + "…"
        parts.append(f"{k}: {ovs} → {nvs}")
    text = "; ".join(parts)
    return text[:480]


# ── Drift report dataclasses ─────────────────────────────────────────────


@dataclass
class DriftRowResult:
    smc_object_id: int
    smc_type: str
    smc_name: str
    smc_href: str
    state: str          # 'clean' | 'drifted' | 'gone' | 'errored' | 'skipped'
    detail: str = ""    # diff summary or error message


@dataclass
class DriftReport:
    domain_id: int
    domain_label: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    total_rows: int = 0
    checked: int = 0
    clean: int = 0
    drifted: int = 0
    gone: int = 0
    errored: int = 0
    skipped: int = 0
    rows: list[DriftRowResult] = field(default_factory=list)

    def add(self, result: DriftRowResult) -> None:
        self.rows.append(result)
        if result.state == "clean": self.clean += 1
        elif result.state == "drifted": self.drifted += 1
        elif result.state == "gone": self.gone += 1
        elif result.state == "errored": self.errored += 1
        elif result.state == "skipped": self.skipped += 1


# ── SMC element fetch ────────────────────────────────────────────────────

def _fetch_element_data(href: str) -> Optional[dict]:
    """Fetch the SMC element by href. Returns its `data` dict, or None
    if the element is gone (404 / ElementNotFound).

    Raises any other exception so the caller can record `errored`.
    """
    from smc.base.model import Element
    try:
        elem = Element.from_href(href)
    except Exception as exc:
        # Any exception here is treated as gone vs errored by the caller.
        msg = str(exc).lower()
        if "404" in msg or "not found" in msg or "no such" in msg:
            return None
        raise
    if elem is None:
        return None
    try:
        # `.data` lazily fetches the JSON payload from SMC.
        return dict(elem.data)
    except Exception as exc:
        msg = str(exc).lower()
        if "404" in msg or "not found" in msg:
            return None
        raise


# ── Scan ─────────────────────────────────────────────────────────────────


def scan_domain_drift(domain) -> DriftReport:
    """Walk every `smc_objects` row for the Domain and classify drift.

    Updates each row's `drift_state`, `last_drift_check_at`, and
    `drift_detail` in place. On the first scan after Phase G ships,
    every row gets baselined (last_seen_hash populated, state='clean').
    Subsequent scans flip rows to 'drifted' / 'gone' as appropriate.

    Returns a DriftReport summarising the run. The caller (web route or
    CLI sweep) is responsible for committing transactions and emitting
    a top-level audit entry — the row updates are committed inside this
    function to avoid one bad row poisoning the whole batch.
    """
    from shared.db import db
    from webapp.models import SmcObject

    started = datetime.now(timezone.utc)
    label = (getattr(domain, "display_name", None)
             or getattr(domain, "slug", None) or f"Domain #{domain.id}")
    report = DriftReport(domain_id=domain.id, domain_label=label,
                         started_at=started)

    rows = (SmcObject.query
            .filter_by(domain_id=domain.id)
            .order_by(SmcObject.smc_type.asc(), SmcObject.smc_name.asc())
            .all())
    report.total_rows = len(rows)

    if not rows:
        report.finished_at = datetime.now(timezone.utc)
        return report

    # Open one SMC session for the whole scan.
    from webapp.smc_tls_client import SMCConfig, smc_session
    ak = domain.api_key
    if ak is None:
        log.warning("scan_domain_drift: domain #%s has no api_key", domain.id)
        report.finished_at = datetime.now(timezone.utc)
        return report
    cfg = SMCConfig(
        url=ak.smc_url, api_key=ak.decrypted_key,
        domain=domain.smc_domain_name or "",
        api_version=ak.api_version or "",
        verify_ssl=ak.verify_ssl, timeout=ak.timeout,
    )

    now = datetime.now(timezone.utc)
    with smc_session(cfg):
        for row in rows:
            report.checked += 1
            res = _scan_one(row, now)
            report.add(res)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

    report.finished_at = datetime.now(timezone.utc)

    # Best-effort top-level audit entry summarising the run.
    try:
        from shared.logging import audit
        audit(
            feature="changes",
            action="drift.scan",
            target=label,
            detail=(f"checked={report.checked} clean={report.clean} "
                    f"drifted={report.drifted} gone={report.gone} "
                    f"errored={report.errored}"),
            status="ok" if report.errored == 0 else "warn",
            domain_id=domain.id,
        )
    except Exception:
        pass

    return report


def _scan_one(row, now: datetime) -> DriftRowResult:
    """Classify one SmcObject row. Updates the row in place. Caller commits.

    Skip rules:
      * `smc_type` in `_NO_DRIFT_TYPES` and not in `_HASH_FIELDS` → 'skipped'
      * `is_to_be_deleted=True` → 'skipped' (queue is already managing it)
    """
    smc_type = (row.smc_type or "").strip()
    href = row.smc_href or ""

    # Skip types we don't track.
    skip_reason = None
    if smc_type in _NO_DRIFT_TYPES and smc_type not in _HASH_FIELDS:
        skip_reason = f"type {smc_type!r} not tracked for drift"
    elif row.is_to_be_deleted:
        skip_reason = "object is queued for deletion"

    if skip_reason:
        row.drift_state = "unknown"  # Don't pretend we checked.
        row.last_drift_check_at = now
        row.drift_detail = skip_reason
        return DriftRowResult(
            smc_object_id=row.id, smc_type=smc_type,
            smc_name=row.smc_name or "", smc_href=href,
            state="skipped", detail=skip_reason,
        )

    try:
        data = _fetch_element_data(href)
    except Exception as exc:
        row.last_drift_check_at = now
        row.drift_detail = f"fetch failed: {exc}"[:480]
        # Don't flip drift_state on transient errors — leave the prior state.
        return DriftRowResult(
            smc_object_id=row.id, smc_type=smc_type,
            smc_name=row.smc_name or "", smc_href=href,
            state="errored", detail=str(exc),
        )

    if data is None:
        row.drift_state = "gone"
        row.last_drift_check_at = now
        row.drift_detail = "element no longer exists in SMC"
        return DriftRowResult(
            smc_object_id=row.id, smc_type=smc_type,
            smc_name=row.smc_name or "", smc_href=href,
            state="gone", detail="element no longer exists in SMC",
        )

    fresh_hash = compute_drift_hash(smc_type, data)
    fresh_fields = extract_relevant_fields(smc_type, data)

    # Update name from live SMC if it changed.
    live_name = (data.get("name") or "").strip()
    if live_name and row.smc_name != live_name:
        row.smc_name = live_name

    if not row.last_seen_hash:
        # First-ever scan for this row — baseline it without flagging drift.
        row.last_seen_hash = fresh_hash
        row.drift_state = "clean"
        row.last_drift_check_at = now
        row.drift_detail = "baselined on first scan"
        return DriftRowResult(
            smc_object_id=row.id, smc_type=smc_type,
            smc_name=row.smc_name or "", smc_href=href,
            state="clean", detail="baselined",
        )

    if fresh_hash == row.last_seen_hash:
        row.drift_state = "clean"
        row.last_drift_check_at = now
        row.drift_detail = ""
        return DriftRowResult(
            smc_object_id=row.id, smc_type=smc_type,
            smc_name=row.smc_name or "", smc_href=href,
            state="clean",
        )

    # Drift detected. Compute a human-readable diff for the UI.
    # We don't have the old fields stored — only the hash — so the
    # detail here describes the *current* fields the operator should
    # inspect. The previous content is reconstructible from platform
    # logs if needed.
    detail_summary = _summarise_fields(smc_type, fresh_fields)
    row.drift_state = "drifted"
    row.last_drift_check_at = now
    row.drift_detail = detail_summary[:480]
    # Do NOT update last_seen_hash here — the operator must choose to
    # reconcile (which re-baselines) or roll back (queue) explicitly.
    return DriftRowResult(
        smc_object_id=row.id, smc_type=smc_type,
        smc_name=row.smc_name or "", smc_href=href,
        state="drifted", detail=detail_summary,
    )


def _summarise_fields(smc_type: str, fields: dict) -> str:
    """One-liner of the element's current state (used in `drift_detail`)."""
    if not fields:
        return f"{smc_type or 'object'} drifted"
    bits = []
    for k, v in fields.items():
        sv = repr(v) if not isinstance(v, str) else v
        if len(sv) > 60:
            sv = sv[:57] + "…"
        bits.append(f"{k}={sv}")
    return f"now: {' '.join(bits)}"


# ── Reconcile (re-baseline) one row ──────────────────────────────────────


def reconcile_one(smc_object_id: int) -> bool:
    """Re-baseline a drifted row: fetch the element fresh, set
    last_seen_hash to its current hash, mark the row clean.

    Used by the queue UI's "Reconcile" button when the operator decides
    the drift is intentional (someone else made the change in SMC).

    Returns True on success.
    """
    from shared.db import db
    from webapp.models import SmcObject, Domain

    row = db.session.get(SmcObject, smc_object_id)
    if row is None:
        return False
    domain = db.session.get(Domain, row.domain_id)
    if domain is None or domain.api_key is None:
        return False

    from webapp.smc_tls_client import SMCConfig, smc_session
    ak = domain.api_key
    cfg = SMCConfig(
        url=ak.smc_url, api_key=ak.decrypted_key,
        domain=domain.smc_domain_name or "",
        api_version=ak.api_version or "",
        verify_ssl=ak.verify_ssl, timeout=ak.timeout,
    )
    try:
        with smc_session(cfg):
            data = _fetch_element_data(row.smc_href or "")
    except Exception as exc:
        log.warning("reconcile_one: fetch failed for #%s: %s",
                    smc_object_id, exc)
        return False

    if data is None:
        row.drift_state = "gone"
        row.last_drift_check_at = datetime.now(timezone.utc)
        row.drift_detail = "element no longer exists in SMC"
        db.session.commit()
        return False

    fresh_hash = compute_drift_hash(row.smc_type or "", data)
    row.last_seen_hash = fresh_hash
    row.drift_state = "clean"
    row.last_drift_check_at = datetime.now(timezone.utc)
    row.drift_detail = ""
    live_name = (data.get("name") or "").strip()
    if live_name and row.smc_name != live_name:
        row.smc_name = live_name
    db.session.commit()

    try:
        from shared.logging import audit
        audit(
            feature="changes", action="drift.reconcile",
            target=f"{row.smc_type}:{row.smc_name}",
            detail=f"smc_object_id={smc_object_id} re-baselined",
            domain_id=row.domain_id,
        )
    except Exception:
        pass

    return True


# ── Read helpers (no SMC I/O) ────────────────────────────────────────────


def drift_summary(domain) -> dict:
    """Fast counts by drift_state for the domain. No SMC I/O."""
    from shared.db import db
    from webapp.models import SmcObject

    out = {"total": 0, "clean": 0, "drifted": 0,
           "gone": 0, "unknown": 0, "last_check_at": None}
    if domain is None:
        return out
    try:
        rows = (db.session.query(SmcObject.drift_state,
                                 db.func.count(SmcObject.id))
                .filter_by(domain_id=domain.id)
                .group_by(SmcObject.drift_state)
                .all())
        for state, n in rows:
            out["total"] += n
            if state in out:
                out[state] = n
        last = (db.session.query(db.func.max(SmcObject.last_drift_check_at))
                .filter_by(domain_id=domain.id)
                .scalar())
        out["last_check_at"] = last
    except Exception as exc:
        log.debug("drift_summary failed: %s", exc)
    return out


def drifted_keys_for_domain(domain) -> dict:
    """Map href + name → drift_state for every non-clean row in the domain.

    Used by the per-row Jinja badge helper. Returns {} on any failure.
    """
    if domain is None:
        return {}
    try:
        from webapp.models import SmcObject
        rows = (SmcObject.query
                .filter_by(domain_id=domain.id)
                .filter(SmcObject.drift_state.in_(("drifted", "gone")))
                .with_entities(SmcObject.smc_href, SmcObject.smc_name,
                               SmcObject.drift_state)
                .all())
        out: dict = {}
        for href, name, state in rows:
            if href:
                out[href] = state
            if name:
                # Only set name key if not already covered by href —
                # name lookups are a fallback for callers that don't
                # have an href handy.
                out.setdefault(name, state)
        return out
    except Exception:
        return {}
