"""
FlexEdgeAdmin — Admin portal Blueprint.

CRUD for tenants, users, and API keys. Only accessible to admin-role users.
All API keys are stored encrypted; plaintext is shown only once at creation.
"""

import io
import logging
import zipfile
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app, send_file,
)

from sqlalchemy.exc import IntegrityError

from shared.db import db
from shared.encryption import KEY_FILE, hash_value
from webapp.models import Tenant, User, ApiKey, UserTenantAccess


def _friendly_db_error(exc: Exception, action: str) -> str:
    """Translate common SQLAlchemy errors to operator-friendly messages."""
    msg = str(exc)
    if isinstance(exc, IntegrityError):
        if "tenants.slug" in msg:
            return ("That tenant slug is already in use — pick a different one. "
                    "Slugs must be unique across all tenants.")
        if "users.email" in msg:
            return "A user with that email already exists."
        if "uq_user_tenant_key" in msg:
            return "That user is already linked to that tenant + API key."
        return f"Could not {action} — a unique constraint was violated."
    return f"Error trying to {action}: {exc}"

log = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ── Access control ──────────────────────────────────────────────────────

def admin_required(f):
    """Require authenticated user with admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user_info = session.get("user")
        if not user_info:
            return redirect(url_for("auth.login", next=request.url))
        import user_manager
        if not user_manager.is_admin(user_info.get("email", "")):
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ───────────────────────────────────────────────────────────

@admin_bp.route("/")
@admin_required
def dashboard():
    tenants = Tenant.query.filter_by(is_active=True).count()
    users = User.query.filter_by(is_active=True).count()
    api_keys = ApiKey.query.filter_by(is_active=True).count()
    return render_template("admin/dashboard.html",
                           tenant_count=tenants, user_count=users, key_count=api_keys)


# ── Tenants ─────────────────────────────────────────────────────────────

@admin_bp.route("/tenants")
@admin_required
def tenants():
    items = Tenant.query.order_by(Tenant.name).all()
    return render_template("admin/tenants.html", tenants=items)


@admin_bp.route("/tenants/new", methods=["GET", "POST"])
@admin_required
def tenant_new():
    if request.method == "POST":
        tenant = Tenant(
            slug=request.form["slug"].strip().lower(),
            name=request.form["name"].strip(),
            smc_url=request.form["smc_url"].strip(),
            verify_ssl="verify_ssl" in request.form,
            timeout=int(request.form.get("timeout", 120)),
            default_domain=request.form.get("default_domain", "").strip(),
            api_version=request.form.get("api_version", "").strip() or None,
        )
        db.session.add(tenant)
        try:
            db.session.commit()
            flash(f"Tenant '{tenant.name}' created.", "success")
            return redirect(url_for("admin.tenants"))
        except Exception as e:
            db.session.rollback()
            flash(_friendly_db_error(e, "create the tenant"), "danger")
    return render_template("admin/tenant_form.html", tenant=None)


@admin_bp.route("/tenants/<int:id>/edit", methods=["GET", "POST"])
@admin_required
def tenant_edit(id):
    tenant = Tenant.query.get_or_404(id)
    if request.method == "POST":
        tenant.slug = request.form["slug"].strip().lower()
        tenant.name = request.form["name"].strip()
        tenant.smc_url = request.form["smc_url"].strip()
        tenant.verify_ssl = "verify_ssl" in request.form
        tenant.timeout = int(request.form.get("timeout", 120))
        tenant.default_domain = request.form.get("default_domain", "").strip()
        tenant.api_version = request.form.get("api_version", "").strip() or None
        try:
            db.session.commit()
            flash(f"Tenant '{tenant.name}' updated.", "success")
            return redirect(url_for("admin.tenants"))
        except Exception as e:
            db.session.rollback()
            flash(_friendly_db_error(e, "update the tenant"), "danger")
    return render_template("admin/tenant_form.html", tenant=tenant)


@admin_bp.route("/tenants/<int:id>/delete", methods=["POST"])
@admin_required
def tenant_delete(id):
    tenant = Tenant.query.get_or_404(id)
    tenant.is_active = False
    db.session.commit()
    flash(f"Tenant '{tenant.name}' deactivated.", "warning")
    return redirect(url_for("admin.tenants"))


# ── Users ───────────────────────────────────────────────────────────────

@admin_bp.route("/users")
@admin_required
def users():
    items = User.query.order_by(User.email).all()
    return render_template("admin/users.html", users=items)


@admin_bp.route("/users/new", methods=["GET", "POST"])
@admin_required
def user_new():
    if request.method == "POST":
        user = User(
            email=request.form["email"].strip().lower(),
            display_name=request.form.get("display_name", "").strip(),
            role=request.form.get("role", "viewer"),
            is_active="is_active" in request.form,
        )
        db.session.add(user)
        try:
            db.session.commit()
            # Process tenant assignments
            _update_user_accesses(user, request.form)
            flash(f"User '{user.email}' created.", "success")
            return redirect(url_for("admin.users"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating user: {e}", "danger")

    all_tenants = Tenant.query.filter_by(is_active=True).order_by(Tenant.name).all()
    all_keys = ApiKey.query.filter_by(is_active=True).order_by(ApiKey.name).all()
    return render_template("admin/user_form.html", user=None,
                           tenants=all_tenants, api_keys=all_keys)


@admin_bp.route("/users/<int:id>/edit", methods=["GET", "POST"])
@admin_required
def user_edit(id):
    user = User.query.get_or_404(id)
    if request.method == "POST":
        user.email = request.form["email"].strip().lower()
        user.display_name = request.form.get("display_name", "").strip()
        user.role = request.form.get("role", "viewer")
        user.is_active = "is_active" in request.form
        try:
            _update_user_accesses(user, request.form)
            db.session.commit()
            flash(f"User '{user.email}' updated.", "success")
            return redirect(url_for("admin.users"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating user: {e}", "danger")

    all_tenants = Tenant.query.filter_by(is_active=True).order_by(Tenant.name).all()
    all_keys = ApiKey.query.filter_by(is_active=True).order_by(ApiKey.name).all()
    return render_template("admin/user_form.html", user=user,
                           tenants=all_tenants, api_keys=all_keys)


@admin_bp.route("/users/<int:id>/delete", methods=["POST"])
@admin_required
def user_delete(id):
    user = User.query.get_or_404(id)
    user.is_active = False
    db.session.commit()
    flash(f"User '{user.email}' deactivated.", "warning")
    return redirect(url_for("admin.users"))


def _update_user_accesses(user, form):
    """Update user_tenant_access rows from form data.

    Form fields expected: access_<tenant_id>=<api_key_id> for each assigned tenant.
    """
    # Clear existing accesses
    UserTenantAccess.query.filter_by(user_id=user.id).delete()

    # Add new accesses from form
    for key, value in form.items():
        if key.startswith("access_") and value:
            try:
                tenant_id = int(key.split("_")[1])
                api_key_id = int(value)
                access = UserTenantAccess(
                    user_id=user.id,
                    tenant_id=tenant_id,
                    api_key_id=api_key_id,
                )
                db.session.add(access)
            except (ValueError, IndexError):
                continue

    db.session.flush()


# ── API Keys ────────────────────────────────────────────────────────────

@admin_bp.route("/api-keys")
@admin_required
def api_keys():
    items = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return render_template("admin/api_keys.html", api_keys=items)


@admin_bp.route("/api-keys/new", methods=["GET", "POST"])
@admin_required
def api_key_new():
    if request.method == "POST":
        plaintext = request.form["api_key"].strip()
        tenant_id = int(request.form["tenant_id"])

        # Get current admin user
        admin_email = session["user"]["email"]
        admin_user = User.query.filter_by(email=admin_email).first()

        key = ApiKey(
            name=request.form["name"].strip(),
            tenant_id=tenant_id,
            created_by_id=admin_user.id if admin_user else None,
        )
        key.set_key(plaintext)

        db.session.add(key)
        try:
            db.session.commit()
            # Show the key ONE TIME on the confirmation page
            return render_template("admin/api_key_created.html",
                                   api_key=key, plaintext=plaintext)
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating API key: {e}", "danger")

    all_tenants = Tenant.query.filter_by(is_active=True).order_by(Tenant.name).all()
    return render_template("admin/api_key_form.html", tenants=all_tenants)


@admin_bp.route("/api-keys/<int:id>/revoke", methods=["POST"])
@admin_required
def api_key_revoke(id):
    key = ApiKey.query.get_or_404(id)
    key.is_active = False
    db.session.commit()
    flash(f"API key '{key.name}' revoked.", "warning")
    return redirect(url_for("admin.api_keys"))


@admin_bp.route("/api-keys/<int:id>/reactivate", methods=["POST"])
@admin_required
def api_key_reactivate(id):
    """Re-enable a previously revoked key.

    Useful when revocation was a mistake or a temporary safety pull. The
    plaintext key was already encrypted at creation and is unchanged in
    storage, so reactivation makes it usable again immediately. Sessions
    that still cache this key in active_profile will now succeed against
    SMC again — no re-selection needed.
    """
    key = ApiKey.query.get_or_404(id)
    key.is_active = True
    db.session.commit()
    flash(f"API key '{key.name}' reactivated.", "success")
    return redirect(url_for("admin.api_keys"))


# ── Backup ──────────────────────────────────────────────────────────────

@admin_bp.route("/backup")
@admin_required
def backup():
    """Download a ZIP containing the database and encryption key."""
    import os

    db_path = current_app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
    key_path = os.environ.get("ENCRYPTION_KEY_FILE", KEY_FILE)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.isfile(db_path):
            zf.write(db_path, "flexedge.db")
        if os.path.isfile(key_path):
            zf.write(key_path, "encryption.key")

    buf.seek(0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"flexedge-backup-{timestamp}.zip",
    )


# ── JSON Migration ──────────────────────────────────────────────────────

@admin_bp.route("/migrate-json", methods=["POST"])
@admin_required
def migrate_json():
    """One-time migration from JSON config files to database."""
    import json
    import os
    from pathlib import Path

    config_dir = Path(current_app.root_path).parent / "config"
    results = {"tenants": 0, "users": 0, "api_keys": 0, "accesses": 0}

    # Migrate tenants
    tenants_path = config_dir / "tenants.json"
    if tenants_path.is_file():
        with open(tenants_path) as f:
            raw_tenants = json.load(f)
        for slug, data in raw_tenants.items():
            if slug.startswith("_"):
                continue
            if not Tenant.query.filter_by(slug=slug).first():
                t = Tenant(
                    slug=slug,
                    name=data.get("name", slug),
                    smc_url=data["smc_url"],
                    verify_ssl=data.get("verify_ssl", False),
                    timeout=data.get("timeout", 120),
                    default_domain=data.get("domain", ""),
                    api_version=data.get("api_version"),
                )
                db.session.add(t)
                results["tenants"] += 1
        db.session.commit()

    # Migrate users
    users_path = config_dir / "users.json"
    if users_path.is_file():
        with open(users_path) as f:
            raw_users = json.load(f)
        for email, udata in raw_users.items():
            if email.startswith("_"):
                continue
            email = email.lower().strip()
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email, role=udata.get("role", "viewer"), is_active=True)
                db.session.add(user)
                db.session.flush()
                results["users"] += 1

            for profile in udata.get("profiles", []):
                tenant_slug = profile.get("tenant")
                api_key_plain = profile.get("api_key", "")
                if not tenant_slug or not api_key_plain:
                    continue

                tenant = Tenant.query.filter_by(slug=tenant_slug).first()
                if not tenant:
                    continue

                # Check if this key already exists (by hash)
                k_hash = hash_value(api_key_plain)
                existing_key = ApiKey.query.filter_by(
                    key_hash=k_hash, tenant_id=tenant.id
                ).first()

                if not existing_key:
                    existing_key = ApiKey(
                        name=f"{profile.get('name', tenant.name)} key",
                        tenant_id=tenant.id,
                        created_by_id=user.id,
                    )
                    existing_key.set_key(api_key_plain)
                    db.session.add(existing_key)
                    db.session.flush()
                    results["api_keys"] += 1

                # Create access
                if not UserTenantAccess.query.filter_by(
                    user_id=user.id, tenant_id=tenant.id, api_key_id=existing_key.id
                ).first():
                    access = UserTenantAccess(
                        user_id=user.id, tenant_id=tenant.id, api_key_id=existing_key.id
                    )
                    db.session.add(access)
                    results["accesses"] += 1

        db.session.commit()

    flash(
        f"Migration complete: {results['tenants']} tenants, {results['users']} users, "
        f"{results['api_keys']} API keys, {results['accesses']} access mappings imported.",
        "success",
    )
    return redirect(url_for("admin.dashboard"))
