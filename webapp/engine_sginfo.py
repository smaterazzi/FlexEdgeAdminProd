"""Engine sginfo collection — on-demand per-node diagnostics.

`sginfo` is the SMC-native "give me everything diagnostic" call. The
engine bundles configs, traces, system state, and recent logs into a
gzipped tar archive and ships it back through the SMC management
channel. Works for node-initiated-contact engines because the channel
is engine-originated; the SMC never needs direct IP reachability to
the engine. Same path as the existing `change_ssh_pwd` flow.

This module exposes:

  * ``start_collection(...)`` — creates an ``EngineSginfoCollection``
    DB row in ``status='running'``, kicks off a daemon thread that
    runs ``node.sginfo()`` and writes the archive to
    ``/config/sginfo/<id>/sginfo.gz``. Returns the row id immediately
    so the route can redirect to the watcher.

  * ``list_archive_members(record)`` — returns a sorted list of
    ``{path, size, is_text}`` dicts describing every file inside the
    saved archive. Cached on the DB row as ``member_index_json`` after
    the first successful read.

  * ``read_text_member(record, path) -> (text, encoding, truncated)``
    — extracts a single member from the archive on demand and decodes
    it as text. Caps at 2 MiB per file; larger or non-text members
    are flagged so the viewer offers a download link instead.

  * ``archive_root_dir(record)`` / ``archive_path(record)`` — disk
    path helpers.
"""

from __future__ import annotations

import io
import json
import logging
import os
import tarfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.db import db
from webapp.models import EngineSginfoCollection

log = logging.getLogger(__name__)

# Where archives live on disk. /config is the volume-mounted directory
# (same place flexedge.db and encryption.key live), so archives survive
# container restarts and ride the existing backup workflow.
ARCHIVE_ROOT = Path(os.environ.get("FLEXEDGE_SGINFO_DIR", "/config/sginfo"))

# Per-file viewer cap. Most things in sginfo (configs, recent logs,
# routing dumps, /etc/*, /data/config/*) fit under 2 MiB easily; cores
# and rotated logs blow past it and should be downloaded instead of
# stuffed into a <pre>.
MAX_TEXT_BYTES = 2 * 1024 * 1024

# Heuristic file extensions we'll try to render as text. Anything else
# is offered as download-only.
_TEXT_SUFFIXES = {
    "", ".txt", ".log", ".conf", ".cfg", ".cnf", ".ini", ".yaml", ".yml",
    ".json", ".xml", ".csv", ".sh", ".pl", ".py", ".rb", ".tcl",
    ".rules", ".policy", ".lst", ".tab", ".table",
}


@dataclass
class CollectionStartResult:
    record_id: int
    archive_path: str


# ── Disk layout ─────────────────────────────────────────────────────────

def archive_root_dir(record: EngineSginfoCollection) -> Path:
    return ARCHIVE_ROOT / str(record.id)


def archive_path(record: EngineSginfoCollection) -> Path:
    """Resolve the on-disk archive location for a record.

    Honours the value persisted on the row (so historical archives stay
    findable if ARCHIVE_ROOT is changed later); falls back to the
    canonical layout when the row's column is empty (e.g. while the
    job is still running).
    """
    if record.archive_path:
        return Path(record.archive_path)
    return archive_root_dir(record) / "sginfo.gz"


# ── Public API ──────────────────────────────────────────────────────────

def start_collection(*, domain, engine_name: str,
                     node_index: int, node_name: str = "",
                     include_core_files: bool = False,
                     include_slapcat_output: bool = False,
                     user_id: Optional[int] = None,
                     user_email: str = "") -> CollectionStartResult:
    """Create a queued sginfo collection record and start the worker.

    Returns immediately; the caller is expected to redirect the browser
    to the watcher view, which polls the row's ``status`` until it
    flips to ``done`` or ``failed``.
    """
    record = EngineSginfoCollection(
        domain_id=domain.id,
        user_id=user_id,
        engine_name=engine_name,
        node_index=node_index,
        node_name=node_name or "",
        include_core_files=bool(include_core_files),
        include_slapcat_output=bool(include_slapcat_output),
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.session.add(record)
    db.session.commit()

    _audit("engine_sginfo", "collect.start",
           target=f"{engine_name}/node{node_index}",
           detail=(f"record_id={record.id} core={include_core_files} "
                   f"slapcat={include_slapcat_output} by={user_email}"),
           domain_id=domain.id,
           source_correlation_id=f"sginfo:{record.id}")

    # Capture what the worker thread needs — we can't pass the SQLAlchemy
    # row across threads (different session). The worker reloads it.
    cfg_snapshot = _smc_cfg_for_domain(domain)

    t = threading.Thread(
        target=_run_collection,
        args=(record.id, cfg_snapshot),
        daemon=True,
        name=f"sginfo-{record.id}",
    )
    t.start()

    return CollectionStartResult(
        record_id=record.id,
        archive_path=str(archive_path(record)),
    )


def list_archive_members(record: EngineSginfoCollection) -> list:
    """Return a sorted list of members in the saved archive.

    Caches the result on ``record.member_index_json`` after the first
    successful read so subsequent viewer loads don't re-scan the tar.
    """
    if record.member_index_json:
        try:
            return json.loads(record.member_index_json)
        except Exception:
            pass

    members = _scan_archive_members(archive_path(record))
    try:
        record.member_index_json = json.dumps(members)
        record.member_count = len(members)
        db.session.commit()
    except Exception as exc:
        log.warning("sginfo #%s: cache member index failed: %s",
                    record.id, exc)
        try:
            db.session.rollback()
        except Exception:
            pass
    return members


def read_text_member(record: EngineSginfoCollection, member_path: str
                     ) -> tuple[str, str, bool]:
    """Extract one tar member, decode as text. Returns (text, encoding,
    truncated). Raises on lookup / IO failure; the caller renders an
    error.
    """
    path = archive_path(record)
    if not path.is_file():
        raise FileNotFoundError(f"Archive missing on disk: {path}")

    # `gz` archive; tarfile handles decompression streaming.
    with tarfile.open(path, "r:gz") as tf:
        try:
            ti = tf.getmember(member_path)
        except KeyError as exc:
            raise FileNotFoundError(
                f"Member not in archive: {member_path}") from exc
        if not ti.isfile():
            raise ValueError(
                f"Member is not a regular file: {member_path}")
        f = tf.extractfile(ti)
        if f is None:
            raise IOError(f"Could not extract: {member_path}")
        truncated = ti.size > MAX_TEXT_BYTES
        raw = f.read(MAX_TEXT_BYTES)

    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc), enc, truncated
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8/replace", truncated


def stream_member_bytes(record: EngineSginfoCollection,
                        member_path: str) -> bytes:
    """Return the raw bytes of one tar member (no size cap).

    Used when the operator clicks "Download" on a member — we want the
    full file, even if it's a binary core or a multi-MB log.
    """
    path = archive_path(record)
    if not path.is_file():
        raise FileNotFoundError(f"Archive missing on disk: {path}")
    with tarfile.open(path, "r:gz") as tf:
        ti = tf.getmember(member_path)
        if not ti.isfile():
            raise ValueError(
                f"Member is not a regular file: {member_path}")
        f = tf.extractfile(ti)
        if f is None:
            raise IOError(f"Could not extract: {member_path}")
        return f.read()


def delete_record(record: EngineSginfoCollection) -> None:
    """Remove the archive directory + the DB row. Best-effort on disk."""
    target = archive_root_dir(record)
    rid = record.id
    try:
        if target.is_dir():
            for p in sorted(target.rglob("*"), reverse=True):
                try:
                    if p.is_file() or p.is_symlink():
                        p.unlink(missing_ok=True)
                    elif p.is_dir():
                        p.rmdir()
                except Exception:
                    pass
            try:
                target.rmdir()
            except Exception:
                pass
    except Exception as exc:
        log.warning("sginfo #%s: archive cleanup failed: %s", rid, exc)

    db.session.delete(record)
    db.session.commit()
    _audit("engine_sginfo", "collect.delete",
           target=f"#{rid}",
           detail=f"archive removed: {target}")


# ── Worker ──────────────────────────────────────────────────────────────

def _run_collection(record_id: int, cfg_snapshot) -> None:
    """Worker body — runs in a background thread.

    Re-reads the record inside an app context (different SQLAlchemy
    session from the request thread), opens an SMC session, calls
    ``node.sginfo(filename=...)`` to stream the archive to disk,
    indexes the members, and flips the row to ``done`` (or ``failed``
    on any exception).
    """
    from webapp.app import app  # local import — avoids circulars at module load

    started = datetime.now(timezone.utc)

    with app.app_context():
        record = db.session.get(EngineSginfoCollection, record_id)
        if record is None:
            log.error("sginfo worker: record #%s vanished", record_id)
            return
        try:
            target_dir = archive_root_dir(record)
            target_dir.mkdir(parents=True, exist_ok=True)
            archive = target_dir / "sginfo.gz"

            from webapp.smc_tls_client import smc_session
            from smc.core.engine import Engine

            with smc_session(cfg_snapshot):
                engine = Engine(record.engine_name)
                nodes = list(getattr(engine, "nodes", []) or [])
                if record.node_index >= len(nodes):
                    raise ValueError(
                        f"Node index {record.node_index} out of range "
                        f"(engine has {len(nodes)} node(s))")
                node = nodes[record.node_index]
                # The SDK writes the archive to the path passed as
                # `filename` and also returns the bytes in `result.content`.
                # Passing an absolute path lets us avoid buffering 50–
                # 200 MB in worker memory.
                node.sginfo(
                    include_core_files=bool(record.include_core_files),
                    include_slapcat_output=bool(record.include_slapcat_output),
                    filename=str(archive),
                )

            if not archive.is_file():
                raise IOError(
                    f"sginfo SDK call returned, but archive is missing at "
                    f"{archive}")
            size = archive.stat().st_size
            if size <= 0:
                raise IOError(
                    f"sginfo archive is empty at {archive}")

            members = _scan_archive_members(archive)
            duration_ms = int(
                (datetime.now(timezone.utc) - started).total_seconds() * 1000)

            record.archive_path = str(archive)
            record.archive_bytes = size
            record.member_index_json = json.dumps(members)
            record.member_count = len(members)
            record.duration_ms = duration_ms
            record.finished_at = datetime.now(timezone.utc)
            record.status = "done"
            db.session.commit()

            _audit("engine_sginfo", "collect.done",
                   target=f"{record.engine_name}/node{record.node_index}",
                   detail=(f"record_id={record.id} bytes={size} "
                           f"members={len(members)} "
                           f"duration_ms={duration_ms}"),
                   domain_id=record.domain_id,
                   source_correlation_id=f"sginfo:{record.id}")

        except Exception as exc:
            log.exception("sginfo worker #%s failed", record_id)
            try:
                db.session.rollback()
            except Exception:
                pass
            try:
                record = db.session.get(EngineSginfoCollection, record_id)
                if record is not None:
                    record.status = "failed"
                    record.error = (str(exc) or type(exc).__name__)[:4000]
                    record.finished_at = datetime.now(timezone.utc)
                    record.duration_ms = int(
                        (datetime.now(timezone.utc) - started).total_seconds()
                        * 1000)
                    db.session.commit()
                    _audit("engine_sginfo", "collect.failed",
                           target=(f"{record.engine_name}/"
                                   f"node{record.node_index}"),
                           detail=f"record_id={record.id} error={exc!s}",
                           status="failed",
                           domain_id=record.domain_id,
                           source_correlation_id=f"sginfo:{record.id}")
            except Exception:
                log.exception(
                    "sginfo worker #%s: status flip to failed also failed",
                    record_id)


# ── Helpers ─────────────────────────────────────────────────────────────

def _scan_archive_members(path: Path) -> list:
    """Walk every regular-file member in the tarball; return sorted list."""
    out = []
    with tarfile.open(path, "r:gz") as tf:
        for ti in tf:
            if not ti.isfile():
                continue
            name = ti.name
            suffix = ""
            i = name.rfind(".")
            j = name.rfind("/")
            if i > j:
                suffix = name[i:].lower()
            out.append({
                "path": name,
                "size": int(ti.size or 0),
                "is_text": suffix in _TEXT_SUFFIXES,
            })
    out.sort(key=lambda m: m["path"].lower())
    return out


def _smc_cfg_for_domain(domain):
    """Build the same dataclass `smc_session` accepts, from a Domain row.

    Mirrors `webapp.dhcp_manager._smc_cfg(domain)` without the import
    cycle. Domain.api_key carries every server-level field after the
    Multi-Domain Revamp (B.3).
    """
    from webapp.smc_dhcp_client import SMCConfig
    ak = domain.api_key
    return SMCConfig(
        url=ak.smc_url,
        api_key=ak.decrypted_key,
        verify_ssl=bool(ak.verify_ssl),
        timeout=int(ak.timeout or 60),
        domain=domain.smc_domain_name or "",
        api_version=ak.api_version or "",
    )


def _audit(feature: str, action: str, *, target: str = "",
           detail: str = "", status: str = "ok",
           domain_id: Optional[int] = None,
           source_correlation_id: str = "") -> None:
    try:
        from shared.logging import audit
        audit(feature=feature, action=action, target=target,
              detail=detail, status=status,
              domain_id=domain_id,
              source_correlation_id=source_correlation_id)
    except Exception as exc:
        log.warning("sginfo audit emit failed (%s/%s): %s",
                    feature, action, exc)
