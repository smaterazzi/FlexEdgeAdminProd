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
from webapp.auth_roles import super_admin_required
from webapp.models import Tenant, User, ApiKey, Domain, UserDomainAccess


def _friendly_db_error(exc: Exception, action: str) -> str:
    """Translate common SQLAlchemy errors to operator-friendly messages."""
    msg = str(exc)
    if isinstance(exc, IntegrityError):
        if "tenants.slug" in msg:
            return ("That tenant slug is already in use — pick a different one. "
                    "Slugs must be unique across all tenants.")
        if "domains.slug" in msg or "ix_domains_slug" in msg:
            return ("That domain slug is already in use — pick a different one. "
                    "Slugs must be unique across all domains.")
        if "uq_api_key_smc_domain" in msg:
            return ("A domain with that SMC domain name already exists for this "
                    "API key — pick a different SMC domain or use the existing one.")
        if "users.email" in msg:
            return "A user with that email already exists."
        if "uq_user_domain" in msg:
            return "That user already has access to this domain."
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
    domains = Domain.query.filter_by(is_active=True).count()
    return render_template("admin/dashboard.html",
                           tenant_count=tenants, user_count=users,
                           key_count=api_keys, domain_count=domains)


# ── Tenants ─────────────────────────────────────────────────────────────

@admin_bp.route("/tenants")
@super_admin_required
def tenants():
    items = Tenant.query.order_by(Tenant.name).all()
    return render_template("admin/tenants.html", tenants=items)


@admin_bp.route("/tenants/new", methods=["GET", "POST"])
@super_admin_required
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
@super_admin_required
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
@super_admin_required
def tenant_delete(id):
    tenant = Tenant.query.get_or_404(id)
    tenant.is_active = False
    db.session.commit()
    flash(f"Tenant '{tenant.name}' deactivated.", "warning")
    return redirect(url_for("admin.tenants"))


# ── Domains ─────────────────────────────────────────────────────────────
#
# Multi-Domain Revamp Phase B.2c. A Domain = (api_key, smc_domain_name)
# pair — the operator-facing scope unit. Tenants stay reachable as a
# legacy admin page during the transition; once Phase B.3 drops the
# tenants table, the only entry points will be API Keys + Domains + Users.

import re as _re_admin


def _slugify_domain(value: str, fallback: str = "domain") -> str:
    s = (value or "").strip().lower()
    s = _re_admin.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s or fallback


def _ensure_unique_slug(base_slug: str) -> str:
    """Append -2, -3, … until the slug is unique."""
    slug = base_slug
    n = 2
    while Domain.query.filter_by(slug=slug).first() is not None:
        slug = f"{base_slug}-{n}"
        n += 1
    return slug


@admin_bp.route("/domains")
@super_admin_required
def domains():
    items = (Domain.query
             .order_by(Domain.is_active.desc(), Domain.display_name)
             .all())
    return render_template("admin/domains.html", domains=items)


@admin_bp.route("/domains/new", methods=["GET", "POST"])
@super_admin_required
def domain_new():
    if request.method == "POST":
        api_key_id = int(request.form["api_key_id"])
        api_key = db.session.get(ApiKey, api_key_id)
        if not api_key:
            flash("API key not found.", "danger")
            return redirect(url_for("admin.domain_new"))
        smc_domain_name = (request.form.get("smc_domain_name") or "Shared Domain").strip() or "Shared Domain"
        display_name = (request.form.get("display_name") or "").strip()
        if not display_name:
            display_name = f"{api_key.name} · {smc_domain_name}"
        slug = (request.form.get("slug") or "").strip()
        if slug:
            slug = _slugify_domain(slug, fallback="domain")
        else:
            slug = _ensure_unique_slug(_slugify_domain(display_name, fallback="domain"))

        domain = Domain(
            api_key_id=api_key.id,
            smc_domain_name=smc_domain_name,
            display_name=display_name,
            slug=slug,
            is_active=True,
        )
        db.session.add(domain)
        try:
            db.session.commit()
            flash(f"Domain '{display_name}' created.", "success")
            return redirect(url_for("admin.domains"))
        except Exception as e:
            db.session.rollback()
            flash(_friendly_db_error(e, "create the domain"), "danger")

    api_keys_list = ApiKey.query.filter_by(is_active=True).order_by(ApiKey.name).all()
    return render_template("admin/domain_form.html",
                           domain=None, api_keys=api_keys_list)


@admin_bp.route("/domains/<int:id>/edit", methods=["GET", "POST"])
@super_admin_required
def domain_edit(id):
    domain = Domain.query.get_or_404(id)
    if request.method == "POST":
        new_smc_domain = (request.form.get("smc_domain_name") or "").strip() or domain.smc_domain_name
        new_display = (request.form.get("display_name") or "").strip() or domain.display_name
        new_slug = (request.form.get("slug") or "").strip()
        new_api_key_id = int(request.form.get("api_key_id") or domain.api_key_id)

        domain.api_key_id = new_api_key_id
        domain.smc_domain_name = new_smc_domain
        domain.display_name = new_display
        if new_slug and new_slug != domain.slug:
            domain.slug = _slugify_domain(new_slug, fallback="domain")
        try:
            db.session.commit()
            flash(f"Domain '{domain.display_name}' updated.", "success")
            return redirect(url_for("admin.domains"))
        except Exception as e:
            db.session.rollback()
            flash(_friendly_db_error(e, "update the domain"), "danger")

    api_keys_list = ApiKey.query.filter_by(is_active=True).order_by(ApiKey.name).all()
    return render_template("admin/domain_form.html",
                           domain=domain, api_keys=api_keys_list)


@admin_bp.route("/domains/<int:id>/delete", methods=["POST"])
@super_admin_required
def domain_delete(id):
    """Soft-delete (deactivate) — actual rows stay because feature data
    references domain_id with ON DELETE CASCADE. Hard-delete via DB only
    when you're certain no feature rows depend on it."""
    domain = Domain.query.get_or_404(id)
    domain.is_active = False
    db.session.commit()
    flash(f"Domain '{domain.display_name}' deactivated. "
          f"Feature data tied to it remains in the DB.", "warning")
    return redirect(url_for("admin.domains"))


@admin_bp.route("/domains/<int:id>/reactivate", methods=["POST"])
@super_admin_required
def domain_reactivate(id):
    domain = Domain.query.get_or_404(id)
    domain.is_active = True
    db.session.commit()
    flash(f"Domain '{domain.display_name}' reactivated.", "success")
    return redirect(url_for("admin.domains"))


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
            db.session.flush()  # need user.id for the access rows
            _update_user_domain_accesses(user, request.form)
            db.session.commit()
            flash(f"User '{user.email}' created.", "success")
            return redirect(url_for("admin.users"))
        except Exception as e:
            db.session.rollback()
            flash(_friendly_db_error(e, "create the user"), "danger")

    return render_template("admin/user_form.html", user=None,
                           domains=_active_domains_for_form())


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
            _update_user_domain_accesses(user, request.form)
            db.session.commit()
            flash(f"User '{user.email}' updated.", "success")
            return redirect(url_for("admin.users"))
        except Exception as e:
            db.session.rollback()
            flash(_friendly_db_error(e, "update the user"), "danger")

    return render_template("admin/user_form.html", user=user,
                           domains=_active_domains_for_form(),
                           bypass_panel=_bypass_panel_for_user(user))


def _bypass_panel_for_user(user):
    """Build the per-user bypass panel state for `user_form.html`.

    Returns a list of dicts, one per (Domain, Feature) pair the editor
    has visibility into. Each dict carries:
      * `domain`           — Domain row
      * `feature_key`      — bypass feature name
      * `feature_label`    — UI label
      * `enabled`          — current per-user toggle
      * `can_edit`         — editor can grant/revoke this combination
      * `capability_on`    — domain capability is ON (UI hint)
    """
    from shared.queue_settings import (
        list_bypass_features, list_user_bypasses, list_domain_capabilities,
        can_edit_user_bypass,
    )

    out = []
    domains = _active_domains_for_form()
    for d in domains:
        user_state = list_user_bypasses(d, user)
        cap_state = list_domain_capabilities(d)
        for fkey, flabel in list_bypass_features():
            out.append({
                "domain":         d,
                "feature_key":    fkey,
                "feature_label":  flabel,
                "enabled":        bool(user_state.get(fkey, False)),
                "capability_on":  bool(cap_state.get(fkey, False)),
                "can_edit":       can_edit_user_bypass(d, fkey),
            })
    return out


@admin_bp.route("/users/<int:id>/bypass", methods=["POST"])
@admin_required
def user_bypass(id):
    """Save per-user bypass settings for the named user.

    Form submits a flat set of `bypass_<domain_id>_<feature_key>=on` keys.
    For each (domain, feature) the editor is allowed to edit, we upsert
    the FeatureBypassSetting row with the form-checkbox value.
    Combinations not in the form (no checkbox) → False.

    Authority: `can_edit_user_bypass(domain, feature)` per pair (Super /
    Global always allowed; Domain Admin only when domain capability is
    ON for that feature).
    """
    target = User.query.get_or_404(id)

    from shared.queue_settings import (
        list_bypass_features, can_edit_user_bypass, set_user_bypass,
    )
    me_email = (session.get("user") or {}).get("email", "")

    domains = _active_domains_for_form()
    changed = 0
    skipped = 0
    for d in domains:
        for fkey, _ in list_bypass_features():
            if not can_edit_user_bypass(d, fkey):
                # Editor not allowed to touch this combination — skip
                # silently (the form may have rendered the toggle as
                # disabled, so the value is irrelevant).
                continue
            checkbox_name = f"bypass_{d.id}_{fkey}"
            new_val = request.form.get(checkbox_name) == "on"
            try:
                set_user_bypass(d, target, fkey, new_val, by_email=me_email)
                changed += 1
            except Exception as exc:
                skipped += 1
                flash(f"{d.slug}/{fkey}: {exc}", "danger")

    if changed:
        flash(f"Saved {changed} bypass setting(s) for {target.email}.",
              "success")
    if skipped:
        flash(f"{skipped} setting(s) failed — see errors above.", "warning")
    return redirect(url_for("admin.user_edit", id=target.id))


@admin_bp.route("/users/<int:id>/delete", methods=["POST"])
@admin_required
def user_delete(id):
    user = User.query.get_or_404(id)
    user.is_active = False
    db.session.commit()
    flash(f"User '{user.email}' deactivated.", "warning")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/invite-operator", methods=["GET", "POST"])
def invite_operator():
    """Invite a Domain Operator (Q13).

    Domain Admin (or higher) enters an Azure AD email + picks a Domain
    they have admin rights on. We look up or create the User row and
    grant `UserDomainAccess(role='operator')` on the chosen Domain.

    The user logs in normally via Azure AD afterwards — there is no
    email-magic-link flow today (parked as a TODO per Q13a). Display
    name is filled in on first login from the OIDC claims.
    """
    # Allowed: Super + Global + Domain Admin (Q13).
    from webapp.auth_roles import (
        is_domain_admin as _is_da, is_super_admin as _is_sa,
        is_global_admin as _is_ga,
    )
    user_info = session.get("user")
    if not user_info:
        return redirect(url_for("auth.login", next=request.url))
    if not _is_da():
        flash("Domain Admin access required.", "danger")
        return redirect(url_for("admin.users"))

    inviter_email = (user_info.get("email") or "").strip().lower()
    inviter = User.query.filter_by(email=inviter_email).first()

    invitable = _domains_inviter_can_manage(inviter, _is_sa(), _is_ga())
    if not invitable:
        flash("You don't admin any Domain — cannot invite operators.", "warning")
        return redirect(url_for("admin.users"))

    if request.method == "GET":
        return render_template("admin/invite_operator.html",
                               domains=invitable)

    email = (request.form.get("email") or "").strip().lower()
    domain_id_raw = (request.form.get("domain_id") or "").strip()
    if not email or "@" not in email:
        flash("Enter a valid Azure AD email address.", "danger")
        return render_template("admin/invite_operator.html",
                               domains=invitable, form_values=request.form)
    try:
        domain_id = int(domain_id_raw)
    except ValueError:
        flash("Pick a Domain from the list.", "danger")
        return render_template("admin/invite_operator.html",
                               domains=invitable, form_values=request.form)

    domain = next((d for d in invitable if d.id == domain_id), None)
    if domain is None:
        flash("You don't admin that Domain.", "danger")
        return render_template("admin/invite_operator.html",
                               domains=invitable, form_values=request.form)

    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(
            email=email,
            display_name="",      # filled in on first Azure AD login
            role="viewer",        # legacy role; per-Domain role on access row
            is_active=True,
        )
        db.session.add(user)
        db.session.flush()
        created_user = True
    else:
        if not user.is_active:
            user.is_active = True
        created_user = False

    existing = (UserDomainAccess.query
                .filter_by(user_id=user.id, domain_id=domain.id)
                .first())
    if existing is not None:
        flash(f"{email} already has access to {domain.display_name} "
              f"(role={existing.role}). Edit the user to change it.",
              "info")
        return redirect(url_for("admin.user_edit", id=user.id))

    access = UserDomainAccess(
        user_id=user.id, domain_id=domain.id, role="operator",
        is_default=False,
    )
    db.session.add(access)
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        flash(_friendly_db_error(exc, "invite operator"), "danger")
        return render_template("admin/invite_operator.html",
                               domains=invitable, form_values=request.form)

    try:
        from shared.logging import audit
        audit(
            feature="admin", action="user.invite_operator",
            target=email,
            detail=(f"created_user={created_user} "
                    f"domain={domain.slug!r} "
                    f"by={inviter_email}"),
        )
    except Exception:
        pass

    flash(f"Invited {email} as Operator on {domain.display_name}. "
          f"They can log in via Azure AD now.", "success")
    return redirect(url_for("admin.user_edit", id=user.id))


def _domains_inviter_can_manage(inviter, is_super, is_global) -> list[Domain]:
    """Return the Domains the inviter is allowed to invite operators into.

    Super and Global Admin can invite into any active Domain. A Domain
    Admin can only invite into Domains where they hold `role='admin'`
    (or higher) on `UserDomainAccess`.
    """
    if is_super or is_global:
        return _active_domains_for_form()
    if inviter is None:
        return []
    eligible_ids = {
        a.domain_id for a in inviter.domain_accesses
        if a.role in ("admin", "global_admin")
    }
    if not eligible_ids:
        return []
    return (Domain.query
            .filter(Domain.is_active.is_(True), Domain.id.in_(eligible_ids))
            .order_by(Domain.display_name).all())


def _active_domains_for_form() -> list[Domain]:
    """All active domains, ordered for stable form rendering."""
    return (Domain.query.filter_by(is_active=True)
                        .order_by(Domain.display_name).all())


def _update_user_domain_accesses(user, form):
    """Replace this user's UserDomainAccess rows from the form selection.

    Form fields expected:
      * `domain_<id>` checkbox — present if the user should have access.
      * `default_domain_id` radio — the id of the Domain to flag is_default.

    Only one domain can be flagged is_default per user (enforced here).
    """
    selected_ids: set[int] = set()
    for key in form.keys():
        if key.startswith("domain_") and form.get(key):
            try:
                selected_ids.add(int(key.split("_", 1)[1]))
            except (ValueError, IndexError):
                continue

    try:
        default_id = int(form.get("default_domain_id") or 0) or None
    except ValueError:
        default_id = None
    if default_id is not None and default_id not in selected_ids:
        # Operator marked something default that isn't checked — ignore the default.
        default_id = None

    existing = {a.domain_id: a for a in user.domain_accesses}

    # Add newly-checked
    for did in selected_ids - existing.keys():
        domain = db.session.get(Domain, did)
        if domain is None or not domain.is_active:
            continue
        access = UserDomainAccess(
            user_id=user.id,
            domain_id=did,
            is_default=(did == default_id),
        )
        db.session.add(access)

    # Remove unchecked
    for did in existing.keys() - selected_ids:
        db.session.delete(existing[did])

    # Update is_default on still-present rows
    for did in selected_ids & existing.keys():
        existing[did].is_default = (did == default_id)

    db.session.flush()


# ── API Keys ────────────────────────────────────────────────────────────

@admin_bp.route("/api-keys")
@super_admin_required
def api_keys():
    items = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return render_template("admin/api_keys.html", api_keys=items)


@admin_bp.route("/api-keys/new", methods=["GET", "POST"])
@super_admin_required
def api_key_new():
    """Create an ApiKey + auto-create the matching backing Tenant + Domain.

    Phase B.2c reshape: the form takes the SMC server config directly
    (URL, SSL, timeout, api_version) since those fields now live on
    api_keys (Phase A). The admin no longer picks a Tenant up-front —
    a Tenant is found-or-created behind the scenes for legacy compat,
    and a Domain is auto-created so the new key is immediately usable.
    """
    if request.method == "POST":
        name = request.form["name"].strip()
        plaintext = request.form["api_key"].strip()
        smc_url = request.form["smc_url"].strip()
        if not smc_url:
            flash("SMC URL is required.", "danger")
            return redirect(url_for("admin.api_key_new"))

        try:
            timeout = int(request.form.get("timeout", 120))
        except ValueError:
            timeout = 120
        verify_ssl = "verify_ssl" in request.form
        api_version = (request.form.get("api_version", "") or "").strip() or None
        flexedge_source_ip = (request.form.get("flexedge_source_ip", "") or "").strip()
        smc_domain_name = (request.form.get("smc_domain_name", "") or "").strip() or "Shared Domain"
        domain_slug_raw = (request.form.get("domain_slug", "") or "").strip()

        admin_email = session["user"]["email"]
        admin_user = User.query.filter_by(email=admin_email).first()

        # Find-or-create a Tenant for legacy compat. The Tenant entity is
        # going away in Phase B.3, but until then api_keys.tenant_id is
        # nullable but conventionally set; we keep the column populated so
        # any code still reading it (legacy tenant_id-based queries) works.
        tenant = (Tenant.query.filter_by(smc_url=smc_url, is_active=True)
                              .order_by(Tenant.id).first())
        if tenant is None:
            base_tslug = _slugify_domain(name, fallback="tenant")
            tslug = base_tslug
            n = 2
            while Tenant.query.filter_by(slug=tslug).first() is not None:
                tslug = f"{base_tslug}-{n}"
                n += 1
            tenant = Tenant(
                slug=tslug,
                name=name,
                smc_url=smc_url,
                verify_ssl=verify_ssl,
                timeout=timeout,
                default_domain=smc_domain_name,
                api_version=api_version,
                flexedge_source_ip=flexedge_source_ip,
                is_active=True,
            )
            db.session.add(tenant)
            db.session.flush()  # get tenant.id

        # Create the ApiKey with the absorbed server fields.
        key = ApiKey(
            name=name,
            tenant_id=tenant.id,
            created_by_id=admin_user.id if admin_user else None,
            smc_url=smc_url,
            verify_ssl=verify_ssl,
            timeout=timeout,
            api_version=api_version,
            flexedge_source_ip=flexedge_source_ip,
        )
        key.set_key(plaintext)
        db.session.add(key)
        db.session.flush()  # get key.id

        # Auto-create the Domain so the new key is immediately usable.
        if domain_slug_raw:
            domain_slug = _slugify_domain(domain_slug_raw, fallback="domain")
        else:
            domain_slug = _ensure_unique_slug(_slugify_domain(name, fallback="domain"))
        domain = Domain(
            api_key_id=key.id,
            smc_domain_name=smc_domain_name,
            display_name=f"{name} · {smc_domain_name}",
            slug=domain_slug,
            is_active=True,
        )
        db.session.add(domain)

        try:
            db.session.commit()
            return render_template("admin/api_key_created.html",
                                   api_key=key, plaintext=plaintext,
                                   created_domain=domain)
        except Exception as e:
            db.session.rollback()
            flash(_friendly_db_error(e, "create the API key"), "danger")

    existing_tenants = (Tenant.query.filter_by(is_active=True)
                                    .order_by(Tenant.name).all())
    return render_template("admin/api_key_form.html",
                           existing_tenants=existing_tenants)


@admin_bp.route("/api-keys/<int:id>/rotate", methods=["POST"])
@super_admin_required
def api_key_rotate(id):
    """Replace the encrypted API key plaintext on an existing record.

    All Domains, feature rows, and server config stay intact — only the
    encrypted key blob and its hash are overwritten.
    """
    key = ApiKey.query.get_or_404(id)
    new_plaintext = (request.form.get("new_api_key") or "").strip()
    if not new_plaintext:
        flash("New API key value is required.", "danger")
        return redirect(url_for("admin.api_keys"))

    key.set_key(new_plaintext)
    db.session.commit()
    flash(f"API key '{key.name}' rotated successfully.", "success")
    return redirect(url_for("admin.api_keys"))


@admin_bp.route("/api-keys/<int:id>/revoke", methods=["POST"])
@super_admin_required
def api_key_revoke(id):
    key = ApiKey.query.get_or_404(id)
    key.is_active = False
    db.session.commit()
    flash(f"API key '{key.name}' revoked.", "warning")
    return redirect(url_for("admin.api_keys"))


@admin_bp.route("/api-keys/<int:id>/reactivate", methods=["POST"])
@super_admin_required
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


@admin_bp.route("/api-keys/<int:id>/delete", methods=["POST"])
@super_admin_required
def api_key_delete(id):
    """Hard-delete an API key — destructive.

    By default refuses if any Domain still points at this key (because
    `Domain.api_key_id` has ON DELETE CASCADE — deleting the key would
    silently take every Domain + every feature row keyed to those
    Domains down with it, which is rarely what the operator wants).

    Two paths:
      * Default: refuse with a list of dependent Domains. Operator
        deletes those first via /admin/domains, then retries.
      * Force (`force=1` form field): cascade-delete everything tied
        to this key. The confirm dialog spells out exactly what goes.
    """
    key = ApiKey.query.get_or_404(id)
    name = key.name
    force = request.form.get("force") == "1"

    dependent_domains = Domain.query.filter_by(api_key_id=key.id).all()
    if dependent_domains and not force:
        names = ", ".join(d.display_name for d in dependent_domains[:5])
        more = "" if len(dependent_domains) <= 5 else f" + {len(dependent_domains) - 5} more"
        flash(
            f"Cannot delete API key '{name}': {len(dependent_domains)} Domain(s) "
            f"still reference it ({names}{more}). Deactivate or delete those Domains "
            f"first in /admin/domains, or re-submit with the 'force cascade delete' "
            f"checkbox to wipe everything tied to this key.",
            "danger",
        )
        return redirect(url_for("admin.api_keys"))

    try:
        # CASCADE handles the rest: domains → feature rows.
        db.session.delete(key)
        db.session.commit()
        if dependent_domains:
            flash(
                f"API key '{name}' deleted along with {len(dependent_domains)} "
                f"Domain(s) and any feature data they owned (cascade).",
                "warning",
            )
        else:
            flash(f"API key '{name}' deleted.", "success")
    except Exception as exc:
        db.session.rollback()
        flash(_friendly_db_error(exc, "delete the API key"), "danger")
    return redirect(url_for("admin.api_keys"))


# ── Backup ──────────────────────────────────────────────────────────────

@admin_bp.route("/backup")
@super_admin_required
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


# ── Factory reset (Super Admin only) ────────────────────────────────────

@admin_bp.route("/factory-reset", methods=["GET"])
def factory_reset_form():
    """Danger page — typed-confirmation form for full environment wipe.

    Gated by Super Admin (not just admin) so a Domain Admin can't
    detonate the whole deployment.
    """
    from webapp.auth_roles import is_super_admin
    if not is_super_admin():
        flash("Factory reset requires Super Admin privileges.", "danger")
        return redirect(url_for("admin.dashboard"))

    from webapp.factory_reset import CONFIRM_PHRASE
    user_email = (session.get("user") or {}).get("email", "")
    return render_template(
        "admin/factory_reset.html",
        confirm_phrase=CONFIRM_PHRASE,
        super_admin_email=user_email,
    )


@admin_bp.route("/factory-reset", methods=["POST"])
def factory_reset_execute():
    """Stream the pre-reset backup ZIP, perform the reset, redirect to
    dashboard with a flash summary.

    Two-step within one request:
      1. Validate the typed confirmation phrase. Bail with a flash on
         mismatch.
      2. Build the backup ZIP in memory (DB file + encryption key).
      3. Execute the reset (DB wipe + filesystem clean + cache flush).
      4. Stream the backup as a file download — the operator's browser
         saves it BEFORE seeing the post-reset dashboard.

    Note: the file download happens AFTER the wipe, but the ZIP was
    built BEFORE — so it captures pre-reset state. The operator can
    open it to recover any tenant/key/domain config they didn't mean
    to lose.
    """
    from webapp.auth_roles import is_super_admin
    if not is_super_admin():
        flash("Factory reset requires Super Admin privileges.", "danger")
        return redirect(url_for("admin.dashboard"))

    from webapp.factory_reset import (
        CONFIRM_PHRASE, is_confirmed, build_backup_zip, perform_reset,
    )

    typed = request.form.get("confirm_phrase", "")
    if not is_confirmed(typed):
        flash(
            f"Confirmation phrase mismatch — type exactly '{CONFIRM_PHRASE}' "
            f"to authorise the reset. Nothing was changed.",
            "warning",
        )
        return redirect(url_for("admin.factory_reset_form"))

    # Resolve the invoking user from the session BEFORE the wipe so we
    # still have their User.id after non-super-admin users are gone.
    import user_manager
    user_email = (session.get("user") or {}).get("email", "")
    user_row = User.query.filter_by(email=user_email).first()
    if user_row is None:
        flash("Could not resolve your User record — refusing reset to "
              "avoid lockout. Contact support.", "danger")
        return redirect(url_for("admin.dashboard"))

    # 1. Build the backup BEFORE we wipe.
    try:
        backup_bytes, backup_filename = build_backup_zip()
    except Exception as exc:
        log.exception("factory_reset: backup build failed")
        flash(f"Could not build pre-reset backup — aborting reset. {exc}",
              "danger")
        return redirect(url_for("admin.factory_reset_form"))

    # 2. Wipe.
    try:
        report = perform_reset(invoking_user_id=user_row.id)
    except Exception as exc:
        log.exception("factory_reset: perform_reset raised")
        flash(f"Reset FAILED partway through — system may be in an "
              f"inconsistent state. Error: {exc}. Restore from the "
              f"backup ZIP if needed.", "danger")
        return send_file(
            io.BytesIO(backup_bytes),
            mimetype="application/zip",
            as_attachment=True,
            download_name=backup_filename,
        )

    # 3. Stash a summary into the flash queue. The operator lands back
    #    on the dashboard with a green banner explaining what happened.
    summary = (
        f"Factory reset complete. "
        f"{report.total_rows_deleted} rows deleted across "
        f"{len(report.rows_deleted)} tables, "
        f"{len(report.files_deleted)} on-disk artifacts removed, "
        f"{report.cache_sections_cleared} cache section(s) cleared. "
        f"Your Super Admin account ({report.super_admin_email}) survived "
        f"the reset. Pre-reset backup downloading now — store it safely."
    )
    flash(summary, "success")

    # 4. Stream the backup as the response body. The dashboard URL
    #    redirect can't carry the file download, so the response itself
    #    IS the ZIP — the operator gets the file, then can navigate
    #    back manually. (Browsers handle file-download responses without
    #    leaving the current page if the headers are right.)
    return send_file(
        io.BytesIO(backup_bytes),
        mimetype="application/zip",
        as_attachment=True,
        download_name=backup_filename,
    )


# ── JSON Migration ──────────────────────────────────────────────────────

@admin_bp.route("/migrate-json", methods=["POST"])
@super_admin_required
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

                # Create access via UserDomainAccess (the canonical
                # scope-grant table). Find/auto-create a Domain for this
                # ApiKey if one doesn't exist yet so the import lands
                # somewhere usable.
                domain = Domain.query.filter_by(api_key_id=existing_key.id).first()
                if domain is None:
                    domain = Domain(
                        api_key_id=existing_key.id,
                        smc_domain_name=tenant.default_domain or "Shared Domain",
                        display_name=f"{tenant.name} · {tenant.default_domain or 'Shared Domain'}",
                        slug=f"json-import-{existing_key.id}",
                        is_active=True,
                    )
                    db.session.add(domain)
                    db.session.flush()
                if not UserDomainAccess.query.filter_by(
                    user_id=user.id, domain_id=domain.id
                ).first():
                    access = UserDomainAccess(
                        user_id=user.id, domain_id=domain.id,
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


# ── Platform log settings ──────────────────────────────────────────────
#
# Configures the unified platform log subsystem (see shared/logging.py):
# log mode (Normal/Verbose), per-feature on/off toggles, retention days,
# manual sweep trigger.

@admin_bp.route("/log-settings", methods=["GET", "POST"])
@super_admin_required
def log_settings():
    """Display + update the platform log configuration AND the per-Domain
    bypass-queue capability matrix (Phase E.2).
    """
    from shared.logging import (
        list_features, current_log_mode, current_retention_days,
        is_feature_enabled, set_feature_enabled, set_setting,
        sweep_old_logs,
    )
    from shared.queue_settings import (
        list_bypass_features, list_domain_capabilities,
        set_capability, can_edit_capability, is_known_bypass_feature,
    )
    from webapp.models import PlatformLog
    from sqlalchemy import func
    from flask import g

    me_email = (session.get("user") or {}).get("email", "")
    active_domain = getattr(g, "domain", None)

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip()

        if action == "save":
            mode = (request.form.get("log_mode") or "normal").strip().lower()
            mode = "verbose" if mode == "verbose" else "normal"
            set_setting("log_mode", mode, by_email=me_email)

            try:
                days = max(1, min(3650, int(request.form.get("retention_days", "90"))))
            except ValueError:
                days = 90
            set_setting("log_retention_days", str(days), by_email=me_email)

            for feature in list_features():
                key = f"feature_log_{feature['name']}"
                set_feature_enabled(
                    feature["name"],
                    request.form.get(key) == "on",
                    by_email=me_email,
                )
            flash("Log settings saved.", "success")

        elif action == "sweep":
            result = sweep_old_logs()
            if "error" in result:
                flash(f"Sweep failed: {result['error']}", "danger")
            else:
                flash(f"Sweep complete — deleted {result['deleted']} rows older "
                      f"than {result['cutoff']}.", "success")

        elif action == "bypass_capability":
            # Phase E.2 — toggle the domain capability flag per feature.
            # Authority: Domain Admin (in active Domain), Global, Super.
            if active_domain is None:
                flash("No active Domain — switch via the topbar first.",
                      "warning")
            else:
                changed = 0
                for fkey, _ in list_bypass_features():
                    if not can_edit_capability(active_domain, fkey):
                        continue
                    enabled = request.form.get(f"capability_{fkey}") == "on"
                    try:
                        set_capability(active_domain, fkey, enabled,
                                       by_email=me_email)
                        changed += 1
                    except Exception as exc:
                        flash(f"Could not save capability for {fkey}: {exc}",
                              "danger")
                if changed:
                    flash(f"Saved {changed} bypass-capability change(s) for "
                          f"Domain '{active_domain.display_name}'.", "success")

        return redirect(url_for("admin.log_settings"))

    # GET — render with current state
    counts_by_feature = dict(
        db.session.query(PlatformLog.feature, func.count(PlatformLog.id))
        .group_by(PlatformLog.feature).all()
    )
    total_rows = db.session.query(func.count(PlatformLog.id)).scalar() or 0

    features = list_features()
    feature_state = []
    for f in features:
        feature_state.append({
            "name":  f["name"],
            "label": f["label"],
            "enabled": is_feature_enabled(f["name"]),
            "row_count": counts_by_feature.get(f["name"], 0),
        })

    # Phase E.2 — bypass capability matrix for the active Domain.
    bypass_caps = list_domain_capabilities(active_domain) if active_domain else {}
    bypass_state = []
    for fkey, flabel in list_bypass_features():
        bypass_state.append({
            "key":     fkey,
            "label":   flabel,
            "enabled": bool(bypass_caps.get(fkey, False)),
            "can_edit": (active_domain is not None
                        and can_edit_capability(active_domain, fkey)),
        })

    return render_template(
        "admin/log_settings.html",
        log_mode=current_log_mode(),
        retention_days=current_retention_days(),
        features=feature_state,
        total_rows=total_rows,
        bypass_features=bypass_state,
        active_domain=active_domain,
    )


# ── Cache settings (Loose / Quick refresh levels) ──────────────────────
#
# Two named TTL levels that the codebase passes to `cache_get_or_fetch`:
#   * Loose refresh — for inventory data FlexEdge doesn't write
#                     (engine list, cluster detail, policy list, ...).
#   * Quick refresh — for data FlexEdge writes via the queue
#                     (hosts/networks/services, policy rules, ...).
#
# Defaults: Loose=24h, Quick=1h. Operator overrides are stored in
# `platform_settings` keys `cache_ttl_loose_seconds` /
# `cache_ttl_quick_seconds`. Reload is in-process via
# `smc_cache.reload_ttl_settings()`.

@admin_bp.route("/cache-settings", methods=["GET", "POST"])
@super_admin_required
def cache_settings():
    from shared.logging import set_setting
    from shared.smc_cache import (
        LOOSE_REFRESH_TTL, QUICK_REFRESH_TTL, MAX_TTL,
        get_loose_ttl, get_quick_ttl, reload_ttl_settings,
        stats as cache_stats,
    )

    me_email = (session.get("user") or {}).get("email", "")

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip()

        if action == "reset":
            # Wipe both overrides — defaults take effect again.
            set_setting("cache_ttl_loose_seconds", "", by_email=me_email)
            set_setting("cache_ttl_quick_seconds", "", by_email=me_email)
            reload_ttl_settings()
            flash("Cache TTLs reset to defaults "
                  f"(Loose {LOOSE_REFRESH_TTL // 3600} h, "
                  f"Quick {QUICK_REFRESH_TTL // 3600} h).", "success")
            return redirect(url_for("admin.cache_settings"))

        # action == 'save'
        try:
            loose_h = float(request.form.get("loose_hours", "").strip() or "24")
        except ValueError:
            loose_h = 24
        try:
            quick_h = float(request.form.get("quick_hours", "").strip() or "1")
        except ValueError:
            quick_h = 1

        # Clamp into [1 min, 24 h] — same range smc_cache enforces.
        loose_s = max(60, min(int(loose_h * 3600), MAX_TTL))
        quick_s = max(60, min(int(quick_h * 3600), MAX_TTL))

        set_setting("cache_ttl_loose_seconds", str(loose_s), by_email=me_email)
        set_setting("cache_ttl_quick_seconds", str(quick_s), by_email=me_email)
        reload_ttl_settings()

        flash(
            f"Saved. Loose refresh = {loose_s // 60} min "
            f"({loose_s / 3600:.2f} h); "
            f"Quick refresh = {quick_s // 60} min "
            f"({quick_s / 3600:.2f} h). "
            f"New values apply to NEWLY-created cache sections; restart "
            f"the app for full effect on already-active sections.",
            "success",
        )
        return redirect(url_for("admin.cache_settings"))

    return render_template(
        "admin/cache_settings.html",
        loose_ttl=get_loose_ttl(),
        quick_ttl=get_quick_ttl(),
        loose_default=LOOSE_REFRESH_TTL,
        quick_default=QUICK_REFRESH_TTL,
        max_ttl=MAX_TTL,
        stats=cache_stats(),
    )
