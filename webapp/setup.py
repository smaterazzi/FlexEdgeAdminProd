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
    """One-time setup wizard to create the first admin user.

    H10 (audit fix-up, 2026-05-09) — race + tid hardening:

      * AAD `tid` claim must match a concrete `AZURE_TENANT_ID` UUID.
        `auth.callback()` already enforces this; we re-check here as
        defence-in-depth so the wizard can't be reached on a multi-tenant
        configuration even if a future code change loosens the callback.

      * The "no users exist" check is racy under multiple workers: two
        Azure AD users hitting /setup simultaneously could both pass the
        check and both write a User row — leaving the deployment with two
        Super Admins, which is a security hole.

        Fix: claim a sentinel row in `platform_settings` (key
        `setup_completed`, primary key) BEFORE creating the user. The PK
        UNIQUE constraint gives us atomic single-winner semantics — the
        loser hits IntegrityError and rolls back. Also re-check `User.query.count()`
        inside the same transaction for the case where the sentinel is
        missing on a legacy install but users already exist.
    """
    from webapp.models import User, PlatformSetting
    from sqlalchemy.exc import IntegrityError
    from webapp.auth import verify_aad_tid, aad_tenant_is_single

    # If setup is no longer needed, redirect to index
    if not current_app.config.get("SETUP_REQUIRED", False):
        flash("Setup has already been completed.", "info")
        return redirect(url_for("index"))

    # Must be logged in via Azure AD first
    user_info = session.get("user")
    if not user_info:
        return redirect(url_for("auth.login"))

    # Defence-in-depth: refuse the wizard on a multi-tenant configuration.
    # `tid` is only present on the original token; we don't have it in the
    # session here, so we gate on AZURE_TENANT_ID shape alone. If the
    # operator deliberately set it to `common`/`organizations`, the wizard
    # is unsafe — surface it loudly.
    if not aad_tenant_is_single():
        log.error(
            "Setup wizard refused: AZURE_TENANT_ID is not a concrete UUID "
            "(got %r). Multi-tenant configurations let any Microsoft user "
            "claim Super Admin during setup.",
            current_app.config.get("AZURE_TENANT_ID"),
        )
        flash(
            "Setup is disabled: AZURE_TENANT_ID must be a single-tenant "
            "UUID. Edit your .env to set the actual Azure tenant ID and "
            "restart, then return to /setup.",
            "danger",
        )
        return render_template("auth/login.html"), 503

    if request.method == "POST":
        email = user_info["email"].lower().strip()
        display_name = user_info.get("name", email)

        # Atomic single-winner claim. Two concurrent workers each insert
        # the sentinel row; one wins and proceeds, the other hits the PK
        # uniqueness violation and rolls back.
        sentinel = PlatformSetting(
            key="setup_completed",
            value="1",
            updated_by_email=email,
        )
        try:
            db.session.add(sentinel)
            db.session.flush()  # forces INSERT; raises IntegrityError on conflict
        except IntegrityError:
            db.session.rollback()
            current_app.config["SETUP_REQUIRED"] = False
            log.warning(
                "Setup race: %s lost the claim — another administrator "
                "completed setup at the same moment.", email,
            )
            flash(
                "Setup was completed by another administrator at the same "
                "moment. Ask them to grant you access via the Admin Portal.",
                "info",
            )
            session.clear()
            return redirect(url_for("auth.login"))

        # Belt-and-suspenders: re-check user count inside the same
        # transaction. Catches legacy installs where the sentinel is
        # missing but users were created via JSON migration.
        if User.query.count() > 0:
            db.session.rollback()
            current_app.config["SETUP_REQUIRED"] = False
            log.warning(
                "Setup wizard refused for %s: users already exist in DB "
                "(legacy / migrated install).", email,
            )
            flash(
                "Setup has already been completed (users already exist). "
                "Sign in normally and ask an administrator for access.",
                "info",
            )
            session.clear()
            return redirect(url_for("auth.login"))

        # Create the bootstrap user.
        # is_super_admin=True flags this user as the platform's Super Admin
        # per the four-tier role model (Change Management Q10, refined
        # 2026-05-01) — they see every Domain (including ones added later)
        # and are the only role allowed cross-Domain infrastructure ops
        # (Tenant / API Key / Domain CRUD).
        # role='admin' kept for legacy compat with `user_manager.is_admin()`.
        admin = User(
            email=email,
            display_name=display_name,
            role="admin",
            is_super_admin=True,
            is_active=True,
        )
        db.session.add(admin)
        db.session.commit()

        # Mark setup as complete
        current_app.config["SETUP_REQUIRED"] = False

        log.info("Setup complete — Super Admin created: %s", email)
        flash(f"Welcome, {display_name}! Your Super Admin account has been created.", "success")
        return redirect(url_for("admin.dashboard"))

    return render_template("admin/setup.html", user=user_info)
