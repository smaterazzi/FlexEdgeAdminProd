"""
FlexEdgeAdmin — build version information.

Resolves the running build's version, commit SHA, and build date by
checking (in order):

  1. Environment variables injected at Docker build time
     (FLEXEDGE_VERSION, FLEXEDGE_COMMIT, FLEXEDGE_BUILD_DATE)
  2. Live `git` commands if a .git directory is present (dev mode)
  3. Safe fallbacks ("dev" / "unknown")

Used by:
  - Template context processor in webapp/app.py (sidebar footer)
  - `/version` JSON endpoint for external checks
"""
import os
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _git(args: list[str]) -> str | None:
    """Run a git command in the project root; return stdout or None."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


@lru_cache(maxsize=1)
def get_version() -> dict:
    """
    Return a dict describing the running build:
        {
          "version":     "2.1.0" | "dev",
          "commit":      "82d77bd" | "unknown",
          "commit_full": "82d77bd..." | "unknown",
          "build_date":  ISO-8601 UTC string | "unknown",
          "display":     "v2.1.0 (82d77bd) 2026-04-15",
        }
    Cached — resolved once per process.
    """
    # 1. Env vars first (Docker build-time injection)
    version = os.environ.get("FLEXEDGE_VERSION", "").strip()
    commit = os.environ.get("FLEXEDGE_COMMIT", "").strip()
    commit_full = os.environ.get("FLEXEDGE_COMMIT_FULL", "").strip() or commit
    build_date = os.environ.get("FLEXEDGE_BUILD_DATE", "").strip()

    # 2. Git fallback for dev mode (no env vars set)
    if not commit:
        commit = _git(["rev-parse", "--short", "HEAD"]) or "unknown"
    if not commit_full:
        commit_full = _git(["rev-parse", "HEAD"]) or commit
    if not build_date:
        # Last commit date if git available, otherwise current time
        git_date = _git(["log", "-1", "--format=%cI"])
        build_date = git_date or datetime.now(timezone.utc).isoformat()

    # 3. Version: env > CHANGELOG top entry > "dev"
    if not version:
        version = _read_version_from_changelog() or "dev"

    # Format a compact display string for the sidebar
    short_date = build_date[:10] if len(build_date) >= 10 else build_date
    display = f"v{version} ({commit}) {short_date}" if commit != "unknown" else f"v{version}"

    return {
        "version": version,
        "commit": commit,
        "commit_full": commit_full,
        "build_date": build_date,
        "display": display,
    }


def _read_version_from_changelog() -> str | None:
    """Parse the top version line from CHANGELOG.md (e.g. '## [2.1.0] - ...')."""
    changelog = PROJECT_ROOT / "CHANGELOG.md"
    if not changelog.exists():
        return None
    try:
        for line in changelog.read_text().splitlines():
            line = line.strip()
            if line.startswith("## [") and "]" in line:
                v = line.split("[", 1)[1].split("]", 1)[0]
                if v.lower() not in ("unreleased", ""):
                    return v
    except Exception:
        pass
    return None
