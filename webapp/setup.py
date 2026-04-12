"""
FlexEdgeAdmin — One-time setup wizard.

Shown on first run when no users exist in the database.
Requires Azure AD login first (so we know the admin's real email).
Creates the first admin user, then becomes permanently inaccessible.
"""

import logging

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app,
)

from shared.db import db

log = logging.getLogger(__name__)

setup_bp = Blueprint("admin_setup", __name__)


@setup_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """One-time setup wizard to create the first admin user."""
    from webapp.models import User

    # If setup is no longer needed, 404
    if not current_app.config.get("SETUP_REQUIRED", False):
        flash("Setup has already been completed.", "info")
        return redirect(url_for("index"))

    # Must be logged in via Azure AD first
    user_info = session.get("user")
    if not user_info:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        email = user_info["email"].lower().strip()
        display_name = user_info.get("name", email)

        # Create the admin user
        admin = User(
            email=email,
            display_name=display_name,
            role="admin",
            is_active=True,
        )
        db.session.add(admin)
        db.session.commit()

        # Mark setup as complete
        current_app.config["SETUP_REQUIRED"] = False

        log.info("Setup complete — admin user created: %s", email)
        flash(f"Welcome, {display_name}! Your admin account has been created.", "success")
        return redirect(url_for("admin.dashboard"))

    return render_template("admin/setup.html", user=user_info)
