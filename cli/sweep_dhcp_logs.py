#!/usr/bin/env python3
"""
FlexEdgeAdmin CLI — DHCP log retention sweep.

Deletes ``dhcp_activity_logs`` and ``dhcp_deployments`` rows older than
the configured retention window. Phase 0 validation rows are preserved
regardless of age (they're the gate signal, not noise).

Designed to run from cron inside the running Docker container, e.g.::

    # Weekly sweep, 90-day retention, every Sunday at 03:30
    30 3 * * 0  /app/cli/sweep_dhcp_logs.py --retention 90

or from the host::

    docker compose exec flexedge-web python /app/cli/sweep_dhcp_logs.py

Equivalent to clicking the "Sweep old" button on the DHCP Manager
activity page, but doesn't require an HTTP session. Output is JSON to
stdout so cron emails / log aggregators can parse it; non-zero exit
status on failure.
"""

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path so `webapp` and `shared` are importable.
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--retention", "-r", type=int, default=90,
        help="Retention window in days (default: 90). Rows older than now() - retention "
             "are deleted. Phase 0 validation rows are always kept.",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress JSON output on success; only print on failure. "
             "Useful for cron entries that should stay silent on the happy path.",
    )
    parser.add_argument(
        "--domain", "-d", type=str, default=None,
        help="Sweep only the given Domain (by slug). If omitted, every "
             "active Domain is swept independently — each gets its own "
             "scoped delete pass + audit log entry. Use this when the "
             "cron-friendly default ('sweep all Domains') is what you "
             "want for shared retention; pass an explicit slug for "
             "targeted maintenance.",
    )
    args = parser.parse_args()

    if args.retention <= 0:
        print(json.dumps({"ok": False, "error": "retention must be ≥ 1"}),
              file=sys.stderr)
        return 2

    # Build the Flask app context lazily — full webapp boot is heavy but
    # gives us the same DB connection / encryption setup as the running
    # service, so the sweep operates on the live database.
    try:
        from webapp.app import app
        from webapp.dhcp_manager import sweep_old_logs
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"import: {type(exc).__name__}: {exc}"}),
              file=sys.stderr)
        return 3

    try:
        with app.app_context():
            from webapp.models import Domain
            if args.domain:
                # Targeted Domain sweep.
                d = Domain.query.filter_by(slug=args.domain).first()
                if d is None:
                    print(json.dumps({"ok": False,
                                      "error": f"unknown domain slug {args.domain!r}"}),
                          file=sys.stderr)
                    return 4
                summary = sweep_old_logs(args.retention, domain_id=d.id)
                summary["domain_slug"] = d.slug
                summaries = [summary]
            else:
                # Cross-Domain sweep — iterate every active Domain so each
                # gets its own scoped pass (this fires per-Domain audit
                # entries, instead of one global "wiped everything" row).
                summaries = []
                for d in Domain.query.filter_by(is_active=True).all():
                    s = sweep_old_logs(args.retention, domain_id=d.id)
                    s["domain_slug"] = d.slug
                    summaries.append(s)
    except Exception as exc:
        print(json.dumps({"ok": False,
                          "error": f"{type(exc).__name__}: {exc}"}),
              file=sys.stderr)
        return 1

    payload = {
        "ok": True,
        "retention_days": args.retention,
        "scope": ("single" if args.domain else "all_domains"),
        "domain_count": len(summaries),
        "totals": {
            "activity_deleted": sum(s.get("activity_deleted", 0) for s in summaries),
            "deployments_deleted": sum(s.get("deployments_deleted", 0) for s in summaries),
            "platform_log_deleted": sum(s.get("platform_log_deleted", 0) for s in summaries),
        },
        "per_domain": summaries,
    }
    if not args.quiet:
        print(json.dumps(payload, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
