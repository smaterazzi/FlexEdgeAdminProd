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
        db.create_all()
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
