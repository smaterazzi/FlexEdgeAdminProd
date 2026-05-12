"""OUI vendor database — download / store / lookup.

Maintains a local copy of a MAC-prefix → vendor-name mapping, used by
the engines scan results to show "aa:bb:cc:dd:ee:ff · Cisco Systems"
instead of just the bare MAC. Source URL defaults to maclookup.app's
JSON download per operator preference (2026-05-09); overridable via
``$FEA_OUI_DB_URL``.

Public surface:
    refresh()           download + save + reload (called from the UI button)
    info()              metadata: path, mtime, record count, age
    lookup_vendor(mac)  returns "" if unknown — never raises
    load_db()           one-shot load from disk into the in-memory dict
                        (call once at app boot)

Storage path picks (in order): ``$FEA_OUI_DB_PATH`` → ``/config/oui.json``
→ ``/tmp/flexedge-oui.json``. Write-tested on each candidate so a
read-only ``/config`` mount fails over cleanly.

Format support: parses BOTH the maclookup.app JSON shape AND the
IEEE oui.csv format (auto-detect on download). Field-name variants
across vendors are tolerated (``oui|prefix|mac|macPrefix|assignment``,
``vendor|company|vendorName|companyName|organization``) so a future
URL change has a fighting chance of working without code edits.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import threading
from datetime import datetime, timezone

import requests

log = logging.getLogger(__name__)

DEFAULT_OUI_URL = os.environ.get(
    "FEA_OUI_DB_URL",
    "https://maclookup.app/downloads/json-database/get-db",
)


def oui_db_path() -> str:
    """Pick a writable path for the local OUI DB file."""
    candidates = [
        os.environ.get("FEA_OUI_DB_PATH"),
        "/config/oui.json",
        "/tmp/flexedge-oui.json",
    ]
    for path in candidates:
        if not path:
            continue
        parent = os.path.dirname(path) or "."
        try:
            os.makedirs(parent, exist_ok=True)
            test = path + ".write-test"
            with open(test, "w") as f:
                f.write("")
            os.remove(test)
            return path
        except OSError:
            continue
    return "/tmp/flexedge-oui.json"


_LOOKUP: dict[str, str] = {}
_LOCK = threading.Lock()


# ── Helpers ─────────────────────────────────────────────────────────────


def _normalize_oui(prefix: str) -> str:
    """Return uppercase hex, no separators, exactly first 6 chars."""
    if not prefix:
        return ""
    cleaned = "".join(ch for ch in prefix.upper() if ch in "0123456789ABCDEF")
    return cleaned[:6] if len(cleaned) >= 6 else ""


def _parse_records(raw: bytes) -> dict[str, str]:
    """Try JSON first, fall back to CSV. Return ``{oui6: vendor}``."""
    out: dict[str, str] = {}
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return out

    # ── JSON variants ───────────────────────────────────────────────
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("records", "data", "ouis", "items", "result", "results"):
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                oui = (entry.get("oui") or entry.get("prefix")
                       or entry.get("mac") or entry.get("macPrefix")
                       or entry.get("assignment") or "")
                vendor = (entry.get("vendor") or entry.get("company")
                          or entry.get("vendorName") or entry.get("companyName")
                          or entry.get("organization") or entry.get("companyShortName")
                          or "")
                key = _normalize_oui(oui)
                if key and vendor:
                    out[key] = str(vendor).strip()
            if out:
                return out
    except (json.JSONDecodeError, ValueError):
        pass

    # ── IEEE CSV ────────────────────────────────────────────────────
    try:
        rdr = csv.reader(io.StringIO(text))
        header = next(rdr, [])
        idx_oui = idx_org = -1
        for i, col in enumerate(header):
            cl = (col or "").lower()
            if "assignment" in cl or "mac prefix" in cl or "oui" == cl:
                idx_oui = i
            if "organization" in cl or "vendor" in cl or "company" in cl:
                idx_org = i
        if idx_oui >= 0 and idx_org >= 0:
            for row in rdr:
                if len(row) <= max(idx_oui, idx_org):
                    continue
                key = _normalize_oui(row[idx_oui])
                if key:
                    out[key] = (row[idx_org] or "").strip()
    except Exception as exc:
        log.debug("OUI CSV parse fallback failed: %s", exc)

    return out


def _humanize_age(seconds: float) -> str:
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    days = int(seconds // 86400)
    return f"{days}d ago"


# ── Public API ──────────────────────────────────────────────────────────


def load_db() -> bool:
    """Load DB from disk into the in-memory lookup table."""
    path = oui_db_path()
    if not os.path.exists(path):
        return False
    try:
        with open(path, "rb") as f:
            raw = f.read()
        records = _parse_records(raw)
    except OSError as exc:
        log.warning("OUI DB read failed: %s", exc)
        return False
    if not records:
        log.warning("OUI DB at %s loaded but parsed 0 records", path)
        return False
    with _LOCK:
        _LOOKUP.clear()
        _LOOKUP.update(records)
    log.info("OUI DB loaded: %d records from %s", len(records), path)
    return True


def lookup_vendor(mac: str) -> str:
    """Return the vendor name for a MAC, or "" if unknown.

    Tolerant of any common MAC string format
    (``aa:bb:cc:dd:ee:ff``, ``aabb.ccdd.eeff``, ``aabbccddeeff``,
    upper or lower case). Never raises.
    """
    prefix = _normalize_oui(mac or "")
    if not prefix:
        return ""
    with _LOCK:
        return _LOOKUP.get(prefix, "")


def info() -> dict:
    """DB metadata for the UI status card."""
    path = oui_db_path()
    out = {
        "path": path,
        "source_url": DEFAULT_OUI_URL,
        "exists": os.path.exists(path),
        "size_bytes": 0,
        "mtime": None,
        "age_human": "",
        "record_count": 0,
    }
    with _LOCK:
        out["record_count"] = len(_LOOKUP)
    if out["exists"]:
        try:
            st = os.stat(path)
            out["size_bytes"] = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            out["mtime"] = mtime.isoformat()
            now = datetime.now(timezone.utc)
            out["age_human"] = _humanize_age((now - mtime).total_seconds())
        except OSError:
            pass
    return out


def refresh(url: str = "") -> dict:
    """Download the OUI DB and save to disk. Returns updated info()."""
    target_url = url or DEFAULT_OUI_URL
    path = oui_db_path()
    log.info("OUI DB refresh: GET %s → %s", target_url, path)
    try:
        r = requests.get(target_url, timeout=60,
                         headers={"User-Agent": "FlexEdgeAdmin/oui-refresh"})
        r.raise_for_status()
        content = r.content
    except requests.RequestException as exc:
        return {**info(), "error": f"download failed: {exc}"}
    if len(content) < 1024:
        return {**info(),
                "error": f"download too small ({len(content)} bytes) "
                         f"— check $FEA_OUI_DB_URL"}
    records = _parse_records(content)
    if not records:
        return {**info(),
                "error": "downloaded file produced 0 records — "
                         "format unsupported, check the source URL"}
    try:
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(content)
        os.replace(tmp, path)
    except OSError as exc:
        return {**info(), "error": f"save failed: {exc}"}
    load_db()
    result = info()
    result["error"] = ""
    result["downloaded_records"] = len(records)
    log.info("OUI DB refresh: saved %d records to %s", len(records), path)
    return result
