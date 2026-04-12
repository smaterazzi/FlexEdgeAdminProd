"""
Migration Project Manager
==========================
CRUD operations for migration projects.
Projects are persisted as JSON files in webapp/projects/<uuid>/.

Each project directory contains:
  - project.json         — Project manifest (metadata, target config, status)
  - source.conf          — Copy of the uploaded FortiGate config file
  - parsed_objects.json  — Output of fgt_parser
  - dedup_results.json   — Deduplication analysis results
  - converted_rules.json — Rules converted to Forcepoint format
  - import_log.json      — Import execution log
"""

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECTS_DIR = Path(__file__).parent / "projects"


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

def list_projects():
    """Return a list of all project manifests, sorted by creation date (newest first)."""
    _ensure_projects_dir()
    projects = []
    for d in PROJECTS_DIR.iterdir():
        if d.is_dir() and (d / "project.json").exists():
            proj = _read_json(d / "project.json")
            if proj:
                projects.append(proj)
    projects.sort(key=lambda p: p.get("created_at", ""), reverse=True)
    return projects


def get_project(project_id):
    """Load a project manifest. Returns None if not found."""
    manifest = _project_dir(project_id) / "project.json"
    return _read_json(manifest)


def create_project(name, config_file_path, config_filename):
    """Create a new project from a FortiGate config file.

    Args:
        name: Human-readable project name
        config_file_path: Path to the uploaded .conf file (temporary)
        config_filename: Original filename

    Returns:
        Project manifest dict
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
        "created_at": now,
        "updated_at": now,
        "status": "created",
        "source_file": config_filename,
        "source_hostname": "",
        "target": {
            "smc_url": "",
            "api_key": "",
            "domain": "",
            "verify_ssl": False,
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
