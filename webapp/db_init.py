"""
FlexEdgeAdmin — Database initialization on first run.

Called during app startup:
  1. Generates the encryption key file if it doesn't exist
  2. Creates database tables if they don't exist
  3. Sets a flag indicating whether the setup wizard is needed
"""

import logging
import os

from shared.encryption import key_file_exists, generate_key_file, load_key, KEY_FILE

log = logging.getLogger(__name__)


def init_database(app):
    """Initialize encryption key and database tables.

    Call this after db.init_app(app) in the Flask app setup.
    Sets app.config["SETUP_REQUIRED"] = True if no users exist yet.
    """
    from shared.db import db

    key_path = os.environ.get("ENCRYPTION_KEY_FILE", KEY_FILE)

    # 1. Ensure encryption key exists
    if not key_file_exists(key_path):
        generate_key_file(key_path)
        log.info("Generated new encryption key at %s", key_path)
    else:
        load_key(key_path)  # Validate the key loads correctly
        log.debug("Encryption key loaded from %s", key_path)

    # 2. Create DB tables if they don't exist
    with app.app_context():
        # Import models so they are registered with SQLAlchemy
        import webapp.models  # noqa: F401
        _migrate_pre_create(db, app)
        db.create_all()
        _migrate_post_create(db, app)
        log.info("Database tables ensured at %s", app.config["SQLALCHEMY_DATABASE_URI"])

    # 3. Check if setup wizard is needed (no users in DB)
    with app.app_context():
        from webapp.models import User
        user_count = User.query.count()
        app.config["SETUP_REQUIRED"] = user_count == 0
        if app.config["SETUP_REQUIRED"]:
            log.warning("No users in database — setup wizard will be shown on first visit")


def is_setup_required(app) -> bool:
    """Check whether the setup wizard still needs to run."""
    return app.config.get("SETUP_REQUIRED", False)


# ── Lightweight migration helpers ────────────────────────────────────────
# Used in lieu of a formal migration framework — only handles the small set
# of additive / one-shot schema changes the project has accumulated.

def _sqlite_columns(db, table: str) -> list[str]:
    """Return the column names of a SQLite table; empty list if no table."""
    try:
        rows = db.session.execute(db.text(f"PRAGMA table_info({table})")).all()
        return [row[1] for row in rows]
    except Exception:
        return []


def _is_sqlite(app) -> bool:
    return "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", "")


def _migrate_pre_create(db, app):
    """Run BEFORE db.create_all() — handles destructive changes
    (drop-and-recreate) so create_all rebuilds the table fresh.
    """
    if not _is_sqlite(app):
        return  # Non-SQLite: assume a real DBA handles it.

    cols = _sqlite_columns(db, "dhcp_engine_credentials")
    if cols and ("private_key_pem" in cols or "public_key_openssh" in cols):
        log.warning(
            "Detected legacy key-based dhcp_engine_credentials schema; "
            "dropping table — credentials will need re-enrollment."
        )
        try:
            db.session.execute(db.text("DROP TABLE dhcp_engine_credentials"))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to drop legacy dhcp_engine_credentials: %s", exc)


def _migrate_post_create(db, app):
    """Run AFTER db.create_all() — handles additive changes that create_all
    won't apply to an EXISTING table (it only creates *missing* tables).
    """
    if not _is_sqlite(app):
        return

    # Add tenants.flexedge_source_ip if missing (existing tenants tables
    # predate this column).
    cols = _sqlite_columns(db, "tenants")
    if cols and "flexedge_source_ip" not in cols:
        log.info("Adding tenants.flexedge_source_ip column")
        try:
            db.session.execute(db.text(
                "ALTER TABLE tenants ADD COLUMN flexedge_source_ip "
                "VARCHAR(45) NOT NULL DEFAULT ''"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add tenants.flexedge_source_ip: %s", exc)
