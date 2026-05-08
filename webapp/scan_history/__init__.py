"""Engine Scan History — re-usable persistence + UI for engine scans.

Phase 1 (this module): persistence, history list, detail view, comments,
star, delete, retention sweep, audit. Compare / time-graph / scheduler
follow in later phases — see docs/Engines-ScanHistory.md.

Public API
----------
register_blueprint(app)
    Register the /engines/scans Blueprint. Call once at boot.

register_feature_logging()
    Register the "engine_scan_history" feature with shared.logging.
    Call once at boot, before any audit() / op() emit fires.

service.register_scan(domain, report, *, user_id=None, schedule_id=None,
                      source="manual", source_correlation="")
    Persist an EngineScanReport (from webapp.engine_scan) into the DB.
    Returns the new EngineScanRecord.

service.list_scans(domain, **filters)
    Return EngineScanRecord rows ordered by started_at DESC.

service.get_scan(domain, scan_id) -> EngineScanRecord
service.set_comment(domain, scan_id, comment, user_email)
service.set_starred(domain, scan_id, starred, user_email)
service.delete_scan(domain, scan_id, user_email)

retention.sweep_retention(domain) -> SweepReport
    Apply the configured retention rule and emit audit log.
"""

from webapp.scan_history import service, retention   # re-export
from webapp.scan_history.routes import scan_history_bp


def register_blueprint(app):
    """Register the /engines/scans blueprint. Idempotent."""
    if "scan_history" in app.blueprints:
        return
    app.register_blueprint(scan_history_bp)


def register_feature_logging():
    """Register this feature with shared.logging. Idempotent."""
    from shared.logging import register_feature
    register_feature("engine_scan_history", "Engine Scan History")


__all__ = [
    "register_blueprint",
    "register_feature_logging",
    "service",
    "retention",
    "scan_history_bp",
]
