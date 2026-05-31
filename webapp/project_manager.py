"""
Migration Project Manager
==========================
CRUD operations for migration projects.
Projects are persisted as JSON files in the resolved ``PROJECTS_DIR``.

Resolution order (audit V1, 2026-05-29):
  1. ``$FLEXEDGE_PROJECTS_DIR`` env var, if set.
  2. ``/app/data/projects/`` when ``/app/data/`` exists — this is the
     Docker bind-mount target (see docker-compose.yml). Production
     storage; survives container recreate.
  3. ``webapp/projects/`` next to this file — dev/standalone fallback.
     Gitignored, lives inside the source tree for hands-on debugging.

The pre-V1 default (``webapp/projects/`` only) wrote manifests inside
the container's writable overlay layer in Docker deployments; every
``make update`` / image rebuild silently destroyed in-flight migrations
because the bind-mounted ``/app/data/projects/`` was never read.

Each project directory contains:
  - project.json         — Project manifest (metadata, target config, status)
  - source.conf          — Copy of the uploaded FortiGate config file
  - parsed_objects.json  — Output of fgt_parser
  - dedup_results.json   — Deduplication analysis results
  - converted_rules.json — Rules converted to Forcepoint format
  - import_log.json      — Import execution log
"""

import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_LEGACY_PROJECTS_DIR = Path(__file__).parent / "projects"
_DOCKER_DATA_DIR = Path("/app/data/projects")


def _resolve_projects_dir() -> Path:
    """Pick the live PROJECTS_DIR per the resolution order in the module
    docstring. Called at import time and cached in ``PROJECTS_DIR``."""
    override = os.environ.get("FLEXEDGE_PROJECTS_DIR", "").strip()
    if override:
        return Path(override)
    # Detect Docker by the existence of /app/data (the Dockerfile creates
    # it explicitly). On non-Docker hosts /app rarely exists, so this
    # check stays cheap and unambiguous.
    if _DOCKER_DATA_DIR.parent.exists():
        return _DOCKER_DATA_DIR
    return _LEGACY_PROJECTS_DIR


PROJECTS_DIR = _resolve_projects_dir()


def _migrate_legacy_projects_dir() -> int:
    """Move any pre-V1 projects from ``webapp/projects/`` into the
    resolved ``PROJECTS_DIR``. One-shot, idempotent.

    Triggers only when:
      * The resolved dir is NOT the legacy dir (otherwise a no-op).
      * The legacy dir actually exists AND has at least one project
        subdirectory (a ``.gitignore`` alone doesn't count).
      * The resolved dir is empty of project subdirs (don't blindly
        overwrite a populated production volume).

    Returns the number of project directories moved.
    """
    if PROJECTS_DIR == _LEGACY_PROJECTS_DIR:
        return 0
    if not _LEGACY_PROJECTS_DIR.exists():
        return 0
    legacy_projects = [p for p in _LEGACY_PROJECTS_DIR.iterdir()
                       if p.is_dir() and not p.name.startswith(".")]
    if not legacy_projects:
        return 0
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    target_projects = [p for p in PROJECTS_DIR.iterdir()
                       if p.is_dir() and not p.name.startswith(".")]
    if target_projects:
        log.warning(
            "Migration projects dir %s already populated (%d projects); "
            "leaving legacy dir %s alone — operator should reconcile by hand.",
            PROJECTS_DIR, len(target_projects), _LEGACY_PROJECTS_DIR,
        )
        return 0
    moved = 0
    for src in legacy_projects:
        dst = PROJECTS_DIR / src.name
        try:
            shutil.move(str(src), str(dst))
            moved += 1
        except Exception as exc:
            log.error("Could not move legacy project %s → %s: %s",
                      src, dst, exc)
    if moved:
        log.info("V1 migration: moved %d project(s) from %s to %s",
                 moved, _LEGACY_PROJECTS_DIR, PROJECTS_DIR)
    return moved


def _ensure_projects_dir():
    """Create projects directory if it doesn't exist."""
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    gitignore = PROJECTS_DIR / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*\n!.gitignore\n", encoding="utf-8")


def _project_dir(project_id):
    return PROJECTS_DIR / project_id


def _read_json(filepath):
    if filepath.exists():
        return json.loads(filepath.read_text(encoding="utf-8"))
    return None


def _write_json(filepath, data):
    filepath.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


# ── Project CRUD ──────────────────────────────────────────────────────────

def list_projects(domain_id=None):
    """Return project manifests sorted newest-first.

    When ``domain_id`` is passed, returns only projects whose manifest's
    ``domain_id`` field matches it. Legacy manifests with no ``domain_id``
    (pre-C2 fix, 2026-05-20) are always included regardless — they need
    to remain visible so operators can claim or delete them. Pass
    ``domain_id=None`` to fetch every project on disk (used by callers
    that don't have a Domain context, e.g. CLI cleanup tooling).
    """
    _ensure_projects_dir()
    projects = []
    for d in PROJECTS_DIR.iterdir():
        if d.is_dir() and (d / "project.json").exists():
            proj = _read_json(d / "project.json")
            if not proj:
                continue
            if domain_id is not None:
                proj_did = proj.get("domain_id")
                # proj_did is None → legacy manifest, always visible.
                # proj_did matches → in-scope.
                # proj_did differs → hidden from this Domain's view.
                if proj_did is not None and proj_did != domain_id:
                    continue
            projects.append(proj)
    projects.sort(key=lambda p: p.get("created_at", ""), reverse=True)
    return projects


def get_project(project_id):
    """Load a project manifest. Returns None if not found."""
    manifest = _project_dir(project_id) / "project.json"
    return _read_json(manifest)


def create_project(name, config_file_path, config_filename, domain_id=None):
    """Create a new project from a FortiGate config file.

    Args:
        name: Human-readable project name.
        config_file_path: Path to the uploaded .conf file (temporary).
        config_filename: Original filename.
        domain_id: Active Domain's id (pinned into the manifest so future
            routes can enforce Domain isolation per audit C2). None is
            permitted for CLI-driven creates that have no Domain context —
            those projects show up as "legacy" until the first UI mutation
            claims them.
    """
    _ensure_projects_dir()
    project_id = str(uuid.uuid4())[:8]
    pdir = _project_dir(project_id)
    pdir.mkdir(parents=True, exist_ok=True)

    # Copy config file
    dest = pdir / "source.conf"
    shutil.copy2(config_file_path, dest)

    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "id": project_id,
        "name": name,
        "domain_id": domain_id,  # C2: per-Domain isolation
        "created_at": now,
        "updated_at": now,
        "status": "created",
        "source_file": config_filename,
        "source_hostname": "",
        # C1 (audit fix-up, 2026-05-09): plaintext SMC credentials are
        # NEVER persisted on the project file. The ``smc_url`` /
        # ``api_key`` / ``domain`` / ``verify_ssl`` are resolved at run-
        # time from the active Domain row (`g.api_key_obj`). The only
        # fields persisted here are project-specific operator choices.
        "target": {
            "policy_name": "",
            "object_prefix": "FGT-",
        },
        "stats": {},
    }
    _write_json(pdir / "project.json", manifest)
    return manifest


def update_project(project_id, updates):
    """Merge updates into project manifest."""
    manifest = get_project(project_id)
    if not manifest:
        raise ValueError(f"Project not found: {project_id}")

    manifest.update(updates)
    manifest["updated_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(_project_dir(project_id) / "project.json", manifest)
    return manifest


def delete_project(project_id):
    """Remove a project and all its data."""
    pdir = _project_dir(project_id)
    if pdir.exists():
        shutil.rmtree(pdir)


def get_source_path(project_id):
    """Return path to the source .conf file."""
    return _project_dir(project_id) / "source.conf"


# ── Parsed Objects ────────────────────────────────────────────────────────

def save_parsed_objects(project_id, data):
    _write_json(_project_dir(project_id) / "parsed_objects.json", data)


def get_parsed_objects(project_id):
    return _read_json(_project_dir(project_id) / "parsed_objects.json")


# ── Dedup Results ─────────────────────────────────────────────────────────

def save_dedup_results(project_id, data):
    _write_json(_project_dir(project_id) / "dedup_results.json", data)


def get_dedup_results(project_id):
    return _read_json(_project_dir(project_id) / "dedup_results.json")


# ── Converted Rules ──────────────────────────────────────────────────────

def save_converted_rules(project_id, data):
    _write_json(_project_dir(project_id) / "converted_rules.json", data)


def get_converted_rules(project_id):
    return _read_json(_project_dir(project_id) / "converted_rules.json")


# ── Import Log ───────────────────────────────────────────────────────────

def save_import_log(project_id, data):
    _write_json(_project_dir(project_id) / "import_log.json", data)


def get_import_log(project_id):
    return _read_json(_project_dir(project_id) / "import_log.json")


def append_import_log_entry(project_id, level, msg):
    """Append a single log entry to the import log."""
    log_path = _project_dir(project_id) / "import_log.json"
    log_data = _read_json(log_path) or {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "entries": [],
        "objects_created": 0,
        "objects_skipped": 0,
        "objects_errors": 0,
        "rules_created": 0,
        "rules_errors": 0,
    }
    log_data["entries"].append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "msg": msg,
    })
    _write_json(log_path, log_data)
    return log_data
