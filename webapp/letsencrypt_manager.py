"""Let's Encrypt CRUD blueprint — Roadmap item 5 / Phases LE.1 + LE.2 (2026-05-11).

Routes:

  GET  /tls/letsencrypt              List + status
  GET  /tls/letsencrypt/new          Request form
  POST /tls/letsencrypt              Submit request → enqueue + maybe auto-push
  GET  /tls/letsencrypt/<id>         Detail view
  POST /tls/letsencrypt/<id>/renew   Force-renew (Phase LE.2 stub-callable; full
                                     scheduler ships in LE.3)
  POST /tls/letsencrypt/<id>/delete  Stop tracking (Phase LE.5 wires revoke)
  GET  /tls/letsencrypt/<id>/status  JSON poll target for the watcher card
  GET  /tls/letsencrypt/account      Account info + TOS-accepted state
  POST /tls/letsencrypt/account      First-time setup wizard (email + accept TOS)

All routes require Domain Admin or higher per Q6. The allowlist check
runs at submit time AND defensively inside the queue handler.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from flask import (
    Blueprint, flash, g, jsonify, redirect, render_template,
    request, session, url_for,
)

from shared.db import db
from webapp.auth_roles import domain_admin_required, is_domain_admin
from webapp.models import (
    AcmeAccount, DomainCertPattern, ManagedCertificate, PendingChange,
)
from webapp.letsencrypt_allowlist import (
    is_fqdn_allowed_for_domain, normalize_fqdn,
)

log = logging.getLogger(__name__)

letsencrypt_bp = Blueprint("letsencrypt", __name__,
                           url_prefix="/tls/letsencrypt")

# Public ACME HTTP-01 challenge file server. Mounted at the app root
# (no url_prefix) so it lives at `/.well-known/acme-challenge/<token>`
# where Let's Encrypt's validation servers expect it.
#
# nginx/Traefik in front MUST forward `/.well-known/acme-challenge/*`
# to FEA's gunicorn (it's a one-line proxy rule). The endpoint serves
# files from the webroot directory certbot writes to (configurable via
# `CERTBOT_WEBROOT` env var; default `/var/www/certbot`).
#
# This route is intentionally NOT decorated with `@profile_required`
# or `@admin_required` — LE's validation server hits it without any
# session/credentials. CSRF is exempted on registration in app.py
# (read-only GET; no state-change).
acme_challenge_bp = Blueprint("acme_challenge", __name__)


def _operator_email() -> str:
    return ((session.get("user") or {}).get("email") or "").strip().lower()


def _current_user_id():
    from webapp.models import User
    email = _operator_email()
    if not email:
        return None
    u = User.query.filter_by(email=email).first()
    return u.id if u else None


def _active_domain():
    return getattr(g, "domain", None)


# ── Setup wizard (one-shot, first visit) ─────────────────────────────────

@letsencrypt_bp.route("/account", methods=["GET", "POST"])
@domain_admin_required
def account_view():
    """Show or create the singleton AcmeAccount.

    Q3 + Q9 locked: one account per deployment, with a one-shot setup
    wizard. The POST handler refuses to create a second account if one
    already exists — operators edit the email/staging in place from this
    same view.
    """
    account = AcmeAccount.query.first()
    # LE hygiene (2026-05-29): AcmeAccount is a singleton (Q3=A) and
    # `is_staging` is global — flipping it changes which LE endpoint
    # EVERY Domain's cert ops hit. Gate writes to that flag behind
    # Super Admin so a Domain Admin can't accidentally take everyone
    # else's prod cert ops into staging (or vice versa). Email and
    # ToS-acceptance edits stay Domain-Admin-mutable.
    try:
        from webapp.auth_roles import is_super_admin
        _is_super = is_super_admin()
    except Exception:
        _is_super = False

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        is_staging_form = (request.form.get("is_staging") == "1")
        # If non-Super-Admin posts a different is_staging value, ignore
        # it and keep the existing flag. New-account flow (account is
        # None) still respects the operator's pick because somebody has
        # to set the initial value — and only Domain Admins can hit
        # this route in the first place.
        if account is not None and not _is_super and is_staging_form != account.is_staging:
            flash("Only a Super Admin can change the staging/production "
                  "endpoint on the singleton Let's Encrypt account — it "
                  "affects every Domain. Keeping the existing value.",
                  "warning")
            is_staging = account.is_staging
        else:
            is_staging = is_staging_form
        agreed = (request.form.get("agree_tos") == "1")

        if not email or "@" not in email:
            flash("A valid email address is required.", "danger")
            return render_template(
                "tls/letsencrypt/account.html",
                account=account, form_email=email,
                form_is_staging=is_staging,
                can_change_staging=(_is_super or account is None),
            )
        if account is None and not agreed:
            flash("You must accept the Let's Encrypt Terms of Service "
                  "to create the account.", "danger")
            return render_template(
                "tls/letsencrypt/account.html",
                account=account, form_email=email,
                form_is_staging=is_staging,
                can_change_staging=(_is_super or account is None),
            )

        # Register the account at LE if it's new; otherwise just update
        # the in-FEA metadata.
        if account is None:
            # LE hygiene (2026-05-29): certbot register is synchronous
            # and can block up to DEFAULT_TIMEOUT_S=300s — the request
            # thread holds the gunicorn worker for that long. Default
            # Dockerfile gunicorn timeout is 120s, so a slow LE round-
            # trip would 504 before certbot returns. Log at the moment
            # the operator triggers the slow path so the warning shows
            # in `make logs` exactly when it matters; the route doc on
            # docs/deployment-guide.md spells out the bump.
            log.warning(
                "LE: registering ACME account at LE — this can block up "
                "to 300s. If gunicorn 504s before completion, bump "
                "--timeout in docker/Dockerfile CMD (current default is "
                "120s) and retry. Tracking ticket: LE hygiene 2026-05-29."
            )
            from webapp.letsencrypt_certbot import register_account
            result = register_account(email=email, is_staging=is_staging)
            if not result.success:
                log.warning("ACME register failed: %s", result.error)
                flash(f"Let's Encrypt registration failed: {result.error}",
                      "danger")
                return render_template(
                    "tls/letsencrypt/account.html",
                    account=None, form_email=email,
                    form_is_staging=is_staging,
                    can_change_staging=True,  # new account flow
                )
            from webapp.letsencrypt_certbot import CERTBOT_CONFIG_DIR
            account = AcmeAccount(
                email=email,
                is_staging=is_staging,
                tos_accepted_at=datetime.now(timezone.utc),
                tos_accepted_by_email=_operator_email() or email,
                key_file_path=f"{CERTBOT_CONFIG_DIR}/accounts/",
            )
            db.session.add(account)
            db.session.commit()
            try:
                from shared.logging import audit
                audit(
                    feature="letsencrypt",
                    action="account.create",
                    target=email,
                    detail=(f"is_staging={is_staging} "
                            f"tos_accepted_by={_operator_email()}"),
                )
            except Exception:
                pass
            flash(f"Let's Encrypt account created for {email} "
                  f"({'staging' if is_staging else 'production'}).",
                  "success")
            return redirect(url_for("letsencrypt.list_certs"))
        else:
            # Edit existing — only email + is_staging are mutable.
            old_email = account.email
            old_staging = account.is_staging
            account.email = email
            account.is_staging = is_staging
            db.session.commit()
            try:
                from shared.logging import audit
                audit(
                    feature="letsencrypt",
                    action="account.update",
                    target=email,
                    detail=(f"email: {old_email!r} → {email!r}; "
                            f"is_staging: {old_staging} → {is_staging}"),
                )
            except Exception:
                pass
            flash("Account updated.", "success")
            return redirect(url_for("letsencrypt.account_view"))

    return render_template("tls/letsencrypt/account.html",
                           account=account,
                           form_email=(account.email if account else ""),
                           form_is_staging=(account.is_staging
                                            if account else True),
                           can_change_staging=(_is_super or account is None))


# ── List + new request + detail ──────────────────────────────────────────

@letsencrypt_bp.route("/")
@domain_admin_required
def list_certs():
    """Cert list scoped to the active FEA Domain (Super sees all).

    LE.3 (2026-05-29): every visit triggers
    ``ensure_lazy_renewal_sweep()`` if the last sweep was more than
    ``SWEEP_INTERVAL`` ago. Cross-Domain by design — single sweep
    walks every Domain's active certs (operator answer LE-Q1=A).
    Best-effort: failures log + swallow so the cert list still
    renders even if SMC or the scheduler are unhealthy.
    """
    # Trigger the lazy sweep — runs in a background thread since audit
    # P4 (2026-06-11) so the cert list never stalls behind certbot /
    # queue pushes. Enqueued renewals surface on /tls/letsencrypt/requests
    # and in the per-cert status on the next page load.
    try:
        from webapp.letsencrypt_scheduler import ensure_lazy_renewal_sweep
        if ensure_lazy_renewal_sweep(triggered_by_user_email=_operator_email()):
            flash("LE renewal sweep started in the background — any due "
                  "certs get enqueued for renewal. See "
                  "/tls/letsencrypt/requests for per-cert status.", "info")
    except Exception as exc:
        log.warning("LE renewal lazy-sweep skipped: %s", exc)

    domain = _active_domain()
    account = AcmeAccount.query.first()
    if account is None:
        # First-time visit — bounce to the setup wizard.
        flash("Let's Encrypt account not configured yet — set it up first.",
              "info")
        return redirect(url_for("letsencrypt.account_view"))

    qry = ManagedCertificate.query
    if not _is_super():
        if domain is None:
            certs = []
        else:
            qry = qry.filter_by(domain_id=domain.id)
            certs = qry.order_by(ManagedCertificate.created_at.desc()).all()
    else:
        certs = qry.order_by(ManagedCertificate.created_at.desc()).all()

    # Pattern-count signal for the empty-state CTA. Counts patterns on
    # the active Domain regardless of role — Super with an active
    # Domain still sees their Domain's count (previously the gate was
    # gated on `not _is_super()`, which incorrectly forced 0 for Super
    # and made the "Configure allowlist" CTA appear even when the
    # Domain already had patterns).
    #
    # `patterns_count` stays None when there is no active Domain — the
    # template renders a different, traversable CTA in that case ("Pick
    # a Domain in the topbar first").
    patterns_count: Optional[int] = None
    if domain is not None:
        patterns_count = (DomainCertPattern.query
                          .filter_by(domain_id=domain.id).count())

    return render_template(
        "tls/letsencrypt/list.html",
        certs=certs, account=account,
        patterns_count=patterns_count,
        has_active_domain=(domain is not None),
        active_domain=domain,
    )


@letsencrypt_bp.route("/new", methods=["GET", "POST"])
@domain_admin_required
def cert_new():
    """Request a new cert. Q6 allowlist enforced at submit time."""
    domain = _active_domain()
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))

    account = AcmeAccount.query.first()
    if account is None:
        flash("Let's Encrypt account not configured yet — set it up first.",
              "info")
        return redirect(url_for("letsencrypt.account_view"))

    patterns = (DomainCertPattern.query
                .filter_by(domain_id=domain.id)
                .order_by(DomainCertPattern.pattern.asc())
                .all())

    if request.method == "POST":
        fqdn = normalize_fqdn(request.form.get("fqdn", ""))
        is_staging = (request.form.get("is_staging") == "1")
        # LE.4 — challenge_type picker. Wildcards (*.) are only
        # supportable via DNS-01.
        challenge_type = (request.form.get("challenge_type") or "http01").strip()
        if challenge_type not in ("http01", "dns01_manual"):
            flash(f"Unknown challenge type: {challenge_type!r}", "danger")
            return render_template(
                "tls/letsencrypt/new.html",
                patterns=patterns, form_fqdn=fqdn,
                form_is_staging=is_staging,
                form_challenge_type=challenge_type, account=account,
            )

        def _rerender():
            return render_template(
                "tls/letsencrypt/new.html",
                patterns=patterns, form_fqdn=fqdn,
                form_is_staging=is_staging,
                form_challenge_type=challenge_type, account=account,
            )

        if not fqdn:
            flash("A fully-qualified domain name is required.", "danger")
            return _rerender()

        is_wildcard = fqdn.startswith("*.")
        if is_wildcard and challenge_type != "dns01_manual":
            flash("Wildcard certs (*.example.com) require DNS-01 — "
                  "switch the challenge type.", "danger")
            return _rerender()
        if not is_wildcard:
            # FQDN validator for non-wildcard: lowercase ASCII / digits
            # / dots / hyphens only. (HTML5 pattern is operator
            # affordance only; server-side is the source of truth.)
            import re as _re
            if not _re.fullmatch(r"[a-z0-9.\-]+", fqdn):
                flash("Invalid FQDN — lowercase ASCII / digits / dots / "
                      "hyphens only. For wildcards, prefix with *.",
                      "danger")
                return _rerender()

        # Q6 allowlist check (also re-checked in the queue handler).
        allowed, reason = is_fqdn_allowed_for_domain(fqdn, domain.id)
        if not allowed:
            flash(f"Cert request refused: {fqdn!r} {reason}.", "danger")
            return _rerender()

        # Duplicate check.
        existing = (ManagedCertificate.query
                    .filter_by(domain=fqdn).first())
        if existing is not None:
            flash(f"A certificate for {fqdn!r} already exists "
                  f"(id #{existing.id}, status {existing.status}).",
                  "warning")
            return redirect(url_for("letsencrypt.cert_detail",
                                    cert_id=existing.id))

        # Enqueue + maybe auto-push.
        from webapp.letsencrypt_queue import (
            enqueue_cert_request, try_auto_push_for_admins,
        )
        from sqlalchemy.exc import IntegrityError
        try:
            cert, change = enqueue_cert_request(
                fqdn=fqdn, domain=domain, is_staging=is_staging,
                requested_by_user_id=_current_user_id(),
                account=account, challenge_type=challenge_type,
            )
        except IntegrityError:
            # Race condition: another request created the cert between
            # our duplicate check and commit.
            db.session.rollback()
            existing = ManagedCertificate.query.filter_by(domain=fqdn).first()
            if existing:
                flash(f"A certificate for {fqdn!r} was just created by another "
                      f"request (id #{existing.id}).", "warning")
                return redirect(url_for("letsencrypt.cert_detail",
                                        cert_id=existing.id))
            flash(f"Database constraint error for {fqdn!r}. Please retry.", "danger")
            return _rerender()
        try:
            from shared.logging import audit
            audit(
                feature="letsencrypt",
                action="cert_request.enqueue",
                target=fqdn,
                detail=(f"cert_id={cert.id} change_id={change.id} "
                        f"is_staging={cert.is_staging}"),
                source_correlation_id=change.source_correlation_id,
                domain_id=domain.id,
            )
        except Exception:
            pass

        spawned, scan_id = try_auto_push_for_admins(
            change=change, cert=cert, user_email=_operator_email(),
        )
        if spawned and scan_id:
            return redirect(url_for("letsencrypt.cert_detail",
                                    cert_id=cert.id, le_scan_id=scan_id))
        flash(f"Cert request for {fqdn!r} queued for review "
              f"(change #{change.id}).", "info")
        return redirect(url_for("changes.index",
                                source=f"letsencrypt_cert:{cert.id}"))

    return render_template(
        "tls/letsencrypt/new.html",
        patterns=patterns, form_fqdn="", form_is_staging=False,
        form_challenge_type="http01", account=account,
    )


@letsencrypt_bp.route("/<int:cert_id>")
@domain_admin_required
def cert_detail(cert_id):
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None:
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))
    if not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))

    # Resolve the linked PendingChange (if any) so the template can show
    # the current queue state inline with action buttons. The cert's
    # `pending_change_id` is cleared on bypass-cleanup but the queue row
    # itself may still exist in `queued` / `push_failed`.
    linked_change = None
    if cert.pending_change_id is not None:
        linked_change = db.session.get(PendingChange, cert.pending_change_id)
    if linked_change is None:
        # Fall back: latest LE change for this cert by source_correlation_id.
        linked_change = (PendingChange.query
                         .filter_by(
                             feature_source="letsencrypt",
                             source_correlation_id=f"letsencrypt_cert:{cert.id}",
                         )
                         .order_by(PendingChange.created_at.desc())
                         .first())

    # Watcher / consume — `?le_scan_id=X` arrives after a bypass auto-push.
    scan_running = None
    le_scan_id = (request.args.get("le_scan_id") or "").strip()
    if le_scan_id:
        from webapp import letsencrypt_jobs
        user_email = _operator_email()
        status = letsencrypt_jobs.get_status(le_scan_id, user_email=user_email)
        if status is None:
            pass  # silently — operator's watcher may have already consumed it
        elif status["state"] == "running":
            scan_running = status
        elif status["state"] == "failed":
            flash(f"Cert op worker failed: "
                  f"{status.get('error') or 'unknown error'}", "danger")
            letsencrypt_jobs.discard(le_scan_id, user_email=user_email)
        else:  # done
            push_result = letsencrypt_jobs.consume_report(
                le_scan_id, user_email=user_email,
            )
            db.session.refresh(cert)
            if push_result is not None and getattr(push_result, "success", False):
                flash(f"Cert op succeeded for {cert.domain}.", "success")
            else:
                err = (getattr(push_result, "error", "")
                       or cert.last_error or "Unknown")
                # Show the first line only — full error already on
                # cert.last_error, surfaced in the detail card.
                first_line = err.splitlines()[0] if err else ""
                flash(f"Cert op failed: {first_line}", "danger")

    return render_template(
        "tls/letsencrypt/detail.html",
        cert=cert, scan_running=scan_running,
        linked_change=linked_change,
        actionable_states=_ACTIONABLE_STATES,
    )


@letsencrypt_bp.route("/<int:cert_id>/status")
@domain_admin_required
def cert_status(cert_id):
    """JSON poll target for the watcher card on cert_detail."""
    from webapp import letsencrypt_jobs
    scan_id = (request.args.get("id") or "").strip()
    user_email = _operator_email()
    status = letsencrypt_jobs.get_status(scan_id, user_email=user_email)
    if status is None:
        return jsonify({"state": "missing"}), 404
    return jsonify(status)


@letsencrypt_bp.route("/<int:cert_id>/renew", methods=["POST"])
@domain_admin_required
def cert_renew(cert_id):
    """Force-renew a cert. Operator-triggered button.

    LE.3 scheduler enqueues these automatically for HTTP-01 certs.
    For DNS-01 certs, "renewal" is structurally a re-issuance —
    operator publishes a fresh TXT record. We route those through
    ``cert_request`` again instead of ``cert_renew``, so the DNS-01
    flow re-opens an ACME order and surfaces the new TXT details.
    """
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None or not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))
    if not cert.certbot_lineage:
        flash("This cert has no lineage on disk yet — renewal needs an "
              "already-issued cert. Run the request first.", "warning")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))

    from webapp.letsencrypt_queue import (
        enqueue_cert_renew, enqueue_cert_request, try_auto_push_for_admins,
    )

    # LE.4 — DNS-01 renewal is structurally a re-issuance. Re-open the
    # DNS-01 order via cert_request so the operator gets a fresh TXT
    # record they can publish.
    if cert.challenge_type == "dns01_manual":
        # Wipe the prior stash so cert_request's DNS-01 branch
        # initialises a clean order. Status goes back to pending.
        cert.status = "pending"
        cert.dns_challenge_state = ""
        cert.dns_challenge_record_name = ""
        cert.dns_challenge_record_value = ""
        cert.last_error = ""
        db.session.commit()
        # Use enqueue_cert_request to drive the dns01 branch in the
        # handler. The existing cert row is reused (challenge_type
        # already set); we just need a fresh PendingChange.
        import json as _json
        from webapp.models import PendingChange
        payload = {"certificate_id": cert.id}
        change = PendingChange(
            domain_id=cert.domain_id,
            user_id=_current_user_id(),
            smc_object_id=None,
            scope="main",
            operation="cert_request",
            payload_json=_json.dumps(payload),
            feature_source="letsencrypt",
            source_correlation_id=f"letsencrypt_cert:{cert.id}",
            state="queued",
        )
        db.session.add(change)
        db.session.flush()
        cert.pending_change_id = change.id
        db.session.commit()
        try:
            from shared.logging import audit
            audit(
                feature="letsencrypt",
                action="cert_request.enqueue",
                target=cert.domain,
                detail=(f"DNS-01 renewal — cert_id={cert.id} "
                        f"change_id={change.id} (re-issuance)"),
                source_correlation_id=change.source_correlation_id,
                domain_id=cert.domain_id,
            )
        except Exception:
            pass
        spawned, scan_id = try_auto_push_for_admins(
            change=change, cert=cert, user_email=_operator_email(),
        )
        if spawned and scan_id:
            return redirect(url_for("letsencrypt.cert_detail",
                                    cert_id=cert.id, le_scan_id=scan_id))
        flash(f"DNS-01 re-issuance queued for {cert.domain}. Once the "
              f"order opens you'll see a fresh TXT record to publish.",
              "info")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))

    change = enqueue_cert_renew(
        cert=cert, requested_by_user_id=_current_user_id(),
    )
    try:
        from shared.logging import audit
        audit(
            feature="letsencrypt",
            action="cert_renew.enqueue",
            target=cert.domain,
            detail=f"cert_id={cert.id} change_id={change.id}",
            source_correlation_id=change.source_correlation_id,
            domain_id=cert.domain_id,
        )
    except Exception:
        pass

    spawned, scan_id = try_auto_push_for_admins(
        change=change, cert=cert, user_email=_operator_email(),
    )
    if spawned and scan_id:
        return redirect(url_for("letsencrypt.cert_detail",
                                cert_id=cert.id, le_scan_id=scan_id))
    flash(f"Renewal queued for {cert.domain} (change #{change.id}).",
          "info")
    return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))


@letsencrypt_bp.route("/<int:cert_id>/dns-verify", methods=["POST"])
@domain_admin_required
def cert_dns_verify(cert_id):
    """LE.4 — operator clicked "I've published the TXT record".

    Only meaningful for DNS-01 certs in awaiting_dns state. Enqueues
    a ``cert_dns_verify`` queue op which the handler runs to resume
    the ACME order (answer challenge → poll → finalize → save files).
    """
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None or not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))
    if cert.challenge_type != "dns01_manual":
        flash("Only DNS-01 certs need this step.", "warning")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))
    if cert.status != "pending" or not cert.dns_challenge_state:
        flash(f"Cert is in state '{cert.status}' — verify is only valid "
              "for pending DNS-01 certs with an open order.", "warning")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))

    from webapp.letsencrypt_queue import (
        enqueue_cert_dns_verify, try_auto_push_for_admins,
    )
    change = enqueue_cert_dns_verify(
        cert=cert, requested_by_user_id=_current_user_id(),
    )
    try:
        from shared.logging import audit
        audit(
            feature="letsencrypt",
            action="cert_dns_verify.enqueue",
            target=cert.domain,
            detail=(f"cert_id={cert.id} change_id={change.id} "
                    f"record={cert.dns_challenge_record_name}"),
            source_correlation_id=change.source_correlation_id,
            domain_id=cert.domain_id,
        )
    except Exception:
        pass

    spawned, scan_id = try_auto_push_for_admins(
        change=change, cert=cert, user_email=_operator_email(),
    )
    if spawned and scan_id:
        return redirect(url_for("letsencrypt.cert_detail",
                                cert_id=cert.id, le_scan_id=scan_id))
    flash(f"DNS-01 verify queued for {cert.domain} (change #{change.id}).",
          "info")
    return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))


@letsencrypt_bp.route("/<int:cert_id>/dns-precheck", methods=["POST"])
@domain_admin_required
def cert_dns_precheck(cert_id):
    """Operator-facing pre-check — queries the configured TXT record
    via dnspython and compares the value. Diagnostic only; doesn't
    talk to LE.
    """
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None or not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))
    if not (cert.dns_challenge_record_name and cert.dns_challenge_record_value):
        flash("No DNS-01 challenge details on this cert yet.", "warning")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))

    try:
        from webapp.letsencrypt_acme import precheck_dns_txt
        found, detail = precheck_dns_txt(
            record_name=cert.dns_challenge_record_name,
            expected_value=cert.dns_challenge_record_value,
        )
    except Exception as exc:
        flash(f"DNS pre-check failed to run: {exc}", "danger")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))

    if found:
        flash(f"DNS pre-check OK — {detail}", "success")
    else:
        flash(f"DNS pre-check did NOT find the expected TXT record. "
              f"{detail} Try again after the record propagates "
              "(usually <5 min, sometimes longer).", "warning")
    try:
        from shared.logging import audit
        audit(
            feature="letsencrypt",
            action="cert_dns_precheck",
            target=cert.domain,
            detail=detail[:500], status=("ok" if found else "error"),
            domain_id=cert.domain_id,
        )
    except Exception:
        pass
    return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))


# RFC 5280 revocation reason codes accepted by certbot. Subset chosen
# to match realistic operator scenarios — the full list (`cACompromise`,
# `certificateHold`, etc.) is rarely meaningful for an end-entity cert.
_REVOKE_REASONS = (
    "unspecified",
    "keyCompromise",
    "superseded",
    "cessationOfOperation",
    "affiliationChanged",
)


@letsencrypt_bp.route("/<int:cert_id>/revoke", methods=["POST"])
@domain_admin_required
def cert_revoke(cert_id):
    """Revoke a cert at Let's Encrypt (LE.5.b — operator answer LE-Q3=B).

    Distinct from `cert_delete` ("Stop tracking"):
      * revoke = "burn this cert at LE so it can no longer be served"
        (the issued certificate is added to LE's CRL/OCSP).
      * stop tracking = "drop FEA's record of the cert" (cert at LE
        stays valid until natural expiry).

    The optional ``also_stop_tracking=1`` form field chains both
    actions into one click. The chain runs INSIDE the queue handler
    after the revoke succeeds — doing it from the request thread
    would race the async handler (which reads the cert mid-flight).
    """
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None or not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))
    if cert.status != "active":
        flash(f"Only active certs can be revoked at LE — this one is "
              f"in state '{cert.status}'. Use Stop tracking instead.",
              "warning")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))
    if not cert.certbot_lineage:
        flash("This cert has no lineage on disk — nothing to revoke.",
              "warning")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))

    reason = (request.form.get("reason") or "unspecified").strip()
    if reason not in _REVOKE_REASONS:
        flash(f"Invalid revoke reason: {reason}", "danger")
        return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))
    also_stop_tracking = (request.form.get("also_stop_tracking") == "1")

    from webapp.letsencrypt_queue import (
        enqueue_cert_revoke, try_auto_push_for_admins,
    )
    change = enqueue_cert_revoke(
        cert=cert, reason=reason,
        also_stop_tracking=also_stop_tracking,
        requested_by_user_id=_current_user_id(),
    )
    try:
        from shared.logging import audit
        audit(
            feature="letsencrypt",
            action="cert_revoke.enqueue",
            target=cert.domain,
            detail=(f"cert_id={cert.id} change_id={change.id} "
                    f"reason={reason} chain_stop_tracking={also_stop_tracking}"),
            source_correlation_id=change.source_correlation_id,
            domain_id=cert.domain_id,
        )
    except Exception:
        pass

    spawned, scan_id = try_auto_push_for_admins(
        change=change, cert=cert, user_email=_operator_email(),
    )
    if spawned and scan_id:
        return redirect(url_for("letsencrypt.cert_detail",
                                cert_id=cert.id, le_scan_id=scan_id))
    chain_msg = " (will also stop tracking)" if also_stop_tracking else ""
    flash(f"Revoke queued for {cert.domain}{chain_msg} "
          f"(change #{change.id}).", "info")
    return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))


@letsencrypt_bp.route("/<int:cert_id>/delete", methods=["POST"])
@domain_admin_required
def cert_delete(cert_id):
    """Stop tracking the cert in FEA, optionally purging disk state.

    By default the FEA row is removed and the certbot lineage files
    on disk are left alone (operator can run `certbot delete --cert-name
    <fqdn>` manually if they want). Set ``purge_lineage=1`` on the form
    to ALSO wipe certbot's per-FQDN state via
    `reset_lineage_for_fqdn(fqdn)` — the same path-traversal-guarded
    cleanup the **Reset state** button uses. The ACME account key and
    other FQDNs' state are always preserved.

    Does NOT revoke at LE — that's the dedicated revoke flow (Phase
    LE.5.b).

    LE hygiene (2026-05-29): the linked PendingChange (if any) is
    auto-aborted before the cert is deleted, so we don't leave the
    queue row in `queued` state with a dangling `certificate_id` the
    handler would later resolve to "not found". push_failed / applied
    rows are terminal-ish (no race) and rely on the FK's
    ondelete=SET NULL cascade.
    """
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None or not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))
    fqdn = cert.domain
    purge_lineage = (request.form.get("purge_lineage") == "1")

    purge_summary: dict = {}
    if purge_lineage:
        from webapp.letsencrypt_certbot import reset_lineage_for_fqdn
        purge_summary = reset_lineage_for_fqdn(fqdn)

    # LE hygiene: auto-abort the linked queue row if it's still actively
    # queued / conflicted. abort_one() handles atomic claim — returns
    # False if the row is in a non-abortable state (already applied /
    # push_failed / aborted), in which case the FK's ondelete=SET NULL
    # takes care of dropping the certificate_id reference.
    linked_change_id = cert.pending_change_id
    if linked_change_id is not None:
        try:
            from shared.queue_runner import abort_one
            if abort_one(linked_change_id,
                         reason=f"cert deleted by operator "
                                f"({_operator_email() or 'unknown'})"):
                log.info(
                    "LE: aborted PendingChange %d before deleting cert %d (%s)",
                    linked_change_id, cert.id, fqdn,
                )
        except Exception as exc:
            log.warning(
                "LE: could not auto-abort PendingChange %d for cert %d: %s",
                linked_change_id, cert.id, exc,
            )

    db.session.delete(cert)
    db.session.commit()
    try:
        from shared.logging import audit
        if purge_lineage:
            removed_n = len(purge_summary.get("removed") or [])
            error_n = len(purge_summary.get("error") or [])
            audit(
                feature="letsencrypt",
                action="cert.delete_with_purge",
                target=fqdn,
                status=("ok" if error_n == 0 else "partial"),
                detail=(f"cert_id={cert_id} removed from FEA tracking; "
                        f"lineage purge removed={removed_n} "
                        f"errors={error_n} paths={purge_summary}"),
            )
        else:
            audit(
                feature="letsencrypt",
                action="cert.untrack",
                target=fqdn,
                detail=(f"cert_id={cert_id} removed from FEA tracking; "
                        f"lineage files on disk untouched"),
            )
    except Exception:
        pass

    if purge_lineage:
        removed_n = len(purge_summary.get("removed") or [])
        error_n = len(purge_summary.get("error") or [])
        if error_n:
            flash(f"Stopped tracking <code>{fqdn}</code> and partially "
                  f"purged disk state ({removed_n} paths removed, "
                  f"{error_n} errors — see /tls/letsencrypt/log).",
                  "warning")
        elif removed_n:
            flash(f"Stopped tracking <code>{fqdn}</code> and purged "
                  f"{removed_n} lineage paths on disk.", "success")
        else:
            flash(f"Stopped tracking <code>{fqdn}</code>. Nothing to "
                  f"purge on disk (no lineage existed).", "info")
    else:
        flash(f"Stopped tracking <code>{fqdn}</code>. Lineage files on "
              f"disk are untouched — tick "
              f"<em>Also delete files on disk</em> next time, or run "
              f"<code>certbot delete --cert-name {fqdn}</code> manually.",
              "info")
    return redirect(url_for("letsencrypt.list_certs"))


# ── Request-level CRUD (PendingChange management, 2026-05-12) ───────────
#
# Every cert op enqueues a PendingChange (operation = cert_request /
# cert_renew / cert_revoke). The /changes/ page lists ALL pending
# changes across every feature; this view is the LE-specific lens —
# only feature_source='letsencrypt' rows, scoped to the active Domain,
# with cert-context columns (fqdn, status, last_error) joined in.
#
# Operators get inline Push / Retry / Abort buttons + a bulk-action
# checkbox column so they can clear out stuck pending rows without
# leaving the LE feature.


_LE_OPS = ("cert_request", "cert_renew", "cert_revoke", "cert_dns_verify")
_ACTIONABLE_STATES = ("queued", "push_failed")


def _can_act_on_le_change(change: PendingChange) -> bool:
    """Domain-scoped visibility + admin role check for inline actions."""
    if change is None:
        return False
    if change.feature_source != "letsencrypt":
        return False
    if not is_domain_admin():
        return False
    if _is_super():
        return True
    active = _active_domain()
    return active is not None and change.domain_id == active.id


@letsencrypt_bp.route("/requests")
@domain_admin_required
def requests_index():
    """List LE PendingChange rows scoped to the active Domain.

    Filters:
      * ``state`` — comma-separated list (default: queued,push_failed,conflict)
      * ``op``    — cert_request | cert_renew | cert_revoke (default all)
      * ``fqdn``  — substring match on the linked cert's FQDN

    The list is grouped by ManagedCertificate so the operator sees the
    request next to its cert context. Each row carries inline action
    buttons (Push / Retry / Abort) gated on the change's state.
    """
    domain = _active_domain()
    state_filter = (request.args.get("state") or
                    "queued,push_failed,conflict").strip()
    op_filter = (request.args.get("op") or "").strip()
    fqdn_filter = (request.args.get("fqdn") or "").strip().lower()

    state_list = [s.strip() for s in state_filter.split(",") if s.strip()]
    if not state_list:
        # Empty list = "all states" — useful for the audit view.
        state_list = ["queued", "pushing", "conflict", "push_failed",
                      "pushed", "applied", "aborted"]

    qry = (PendingChange.query
           .filter(PendingChange.feature_source == "letsencrypt",
                   PendingChange.state.in_(state_list))
           .order_by(PendingChange.created_at.desc()))
    if op_filter and op_filter in _LE_OPS:
        qry = qry.filter(PendingChange.operation == op_filter)
    if not _is_super():
        if domain is None:
            qry = qry.filter(PendingChange.domain_id == -1)  # match nothing
        else:
            qry = qry.filter(PendingChange.domain_id == domain.id)

    changes = qry.limit(500).all()

    # Look up the linked ManagedCertificate for every row in one batch
    # — payload_json carries certificate_id; source_correlation_id is the
    # canonical pointer (`letsencrypt_cert:<id>`).
    cert_ids: set[int] = set()
    parsed_payloads: dict[int, dict] = {}
    import json
    for ch in changes:
        try:
            p = json.loads(ch.payload_json or "{}")
        except Exception:
            p = {}
        parsed_payloads[ch.id] = p
        cid = p.get("certificate_id")
        if isinstance(cid, int):
            cert_ids.add(cid)

    cert_by_id: dict[int, ManagedCertificate] = {}
    if cert_ids:
        rows = (ManagedCertificate.query
                .filter(ManagedCertificate.id.in_(cert_ids)).all())
        cert_by_id = {c.id: c for c in rows}

    # Optional FQDN substring filter — applied post-join so we keep the
    # PendingChange row count bounded.
    decorated = []
    for ch in changes:
        payload = parsed_payloads.get(ch.id, {})
        cert = cert_by_id.get(payload.get("certificate_id"))
        fqdn = (cert.domain if cert else
                (payload.get("fqdn") or ""))
        if fqdn_filter and fqdn_filter not in (fqdn or "").lower():
            continue
        decorated.append({
            "change": ch,
            "cert": cert,
            "fqdn": fqdn,
            "is_actionable": (ch.state in _ACTIONABLE_STATES),
        })

    account = AcmeAccount.query.first()
    return render_template(
        "tls/letsencrypt/requests.html",
        rows=decorated, account=account,
        state_filter=state_filter, op_filter=op_filter,
        fqdn_filter=fqdn_filter,
        actionable_states=_ACTIONABLE_STATES,
        le_ops=_LE_OPS,
    )


def _spawn_or_sync_push(change: PendingChange,
                        cert: Optional[ManagedCertificate]):
    """Bypass-aware push helper.

    If the operator has bypass + admin role, spawn the async scan_jobs
    worker so the request returns immediately and the UI polls a
    watcher card. Otherwise fall back to a synchronous push_one — the
    request blocks for the certbot duration but the operator gets the
    final outcome inline.

    Returns ``(scan_id_or_none, push_result_or_none)``.
    """
    from shared.queue_settings import should_bypass_queue
    is_bypass = False
    try:
        is_bypass = should_bypass_queue("letsencrypt")
    except Exception:
        pass

    if is_bypass and cert is not None:
        from webapp.letsencrypt_jobs import start_cert_op
        try:
            scan_id = start_cert_op(
                change_id=change.id,
                certificate_id=cert.id,
                fqdn=cert.domain,
                action=change.operation,
                user_email=_operator_email(),
                is_bypass=True,
            )
            return scan_id, None
        except Exception:
            log.exception("requests: start_cert_op spawn failed")

    # Synchronous fallback — blocks the request for ~30s on cert_request.
    from shared import queue_runner
    result = queue_runner.push_one(change.id)
    return None, result


def _flash_push_result(result) -> None:
    if result is None:
        return
    if getattr(result, "success", False):
        flash(f"Change #{result.change_id} pushed successfully.", "success")
    elif getattr(result, "skipped", False):
        flash(f"Change #{result.change_id} skipped: {result.error}", "info")
    else:
        err = (result.error or "unknown").splitlines()[0]
        flash(f"Change #{result.change_id} push failed: {err}", "danger")


@letsencrypt_bp.route("/requests/<int:change_id>/push", methods=["POST"])
@domain_admin_required
def request_push(change_id):
    """Push a queued change immediately. Bypass-aware (async with watcher)."""
    change = db.session.get(PendingChange, change_id)
    if not _can_act_on_le_change(change):
        flash("Request not found or not actionable on the active Domain.",
              "warning")
        return redirect(url_for("letsencrypt.requests_index"))
    if change.state != "queued":
        flash(f"Change #{change_id} is in state {change.state!r}, not "
              f"'queued'. Use Retry for failed pushes.", "info")
        return redirect(url_for("letsencrypt.requests_index"))

    # Resolve the linked cert for watcher redirect.
    import json
    payload = {}
    try:
        payload = json.loads(change.payload_json or "{}")
    except Exception:
        pass
    cert = (db.session.get(ManagedCertificate, payload.get("certificate_id"))
            if isinstance(payload.get("certificate_id"), int) else None)

    scan_id, result = _spawn_or_sync_push(change, cert)
    if scan_id and cert is not None:
        return redirect(url_for("letsencrypt.cert_detail",
                                cert_id=cert.id, le_scan_id=scan_id))
    _flash_push_result(result)
    return redirect(request.referrer or
                    url_for("letsencrypt.requests_index"))


@letsencrypt_bp.route("/requests/<int:change_id>/retry", methods=["POST"])
@domain_admin_required
def request_retry(change_id):
    """Retry a push_failed change. Transitions push_failed → queued, then pushes."""
    change = db.session.get(PendingChange, change_id)
    if not _can_act_on_le_change(change):
        flash("Request not found or not actionable on the active Domain.",
              "warning")
        return redirect(url_for("letsencrypt.requests_index"))
    if change.state not in ("push_failed", "conflict"):
        flash(f"Change #{change_id} is in state {change.state!r} — Retry "
              f"only applies to push_failed/conflict rows.", "info")
        return redirect(url_for("letsencrypt.requests_index"))

    # Atomic transition back to queued. Same pattern as
    # changes.row_resolve_conflict — bare ORM update + commit, then push.
    change.state = "queued"
    change.conflict_with_id = None
    change.push_error_text = ""
    change.push_error_at = None
    db.session.commit()
    try:
        from shared.logging import audit
        audit(
            feature="letsencrypt",
            action=f"{change.operation}.retry",
            target=change.source_correlation_id or f"change:{change.id}",
            detail=(f"operator-triggered retry; transitioned push_failed → "
                    f"queued; will push now"),
            source_correlation_id=change.source_correlation_id,
            domain_id=change.domain_id,
        )
    except Exception:
        pass

    # Also clear cert.status='failed' → 'pending' so the watcher shows
    # the in-flight state honestly.
    import json
    payload = {}
    try:
        payload = json.loads(change.payload_json or "{}")
    except Exception:
        pass
    cert = (db.session.get(ManagedCertificate, payload.get("certificate_id"))
            if isinstance(payload.get("certificate_id"), int) else None)
    if cert is not None and cert.status in ("failed",):
        cert.status = "pending"
        cert.last_error = ""
        db.session.commit()

    scan_id, result = _spawn_or_sync_push(change, cert)
    if scan_id and cert is not None:
        return redirect(url_for("letsencrypt.cert_detail",
                                cert_id=cert.id, le_scan_id=scan_id))
    _flash_push_result(result)
    return redirect(request.referrer or
                    url_for("letsencrypt.requests_index"))


@letsencrypt_bp.route("/requests/<int:change_id>/abort", methods=["POST"])
@domain_admin_required
def request_abort(change_id):
    """Abort a queued/push_failed change. Updates linked cert if still pending."""
    change = db.session.get(PendingChange, change_id)
    if not _can_act_on_le_change(change):
        flash("Request not found or not actionable on the active Domain.",
              "warning")
        return redirect(url_for("letsencrypt.requests_index"))
    if change.state not in _ACTIONABLE_STATES and change.state != "conflict":
        flash(f"Change #{change_id} is in state {change.state!r} — "
              f"already in a terminal state.", "info")
        return redirect(url_for("letsencrypt.requests_index"))

    # Resolve linked cert before the abort so we can update cert.status
    # after the queue transition succeeds.
    import json
    payload = {}
    try:
        payload = json.loads(change.payload_json or "{}")
    except Exception:
        pass
    cert = (db.session.get(ManagedCertificate, payload.get("certificate_id"))
            if isinstance(payload.get("certificate_id"), int) else None)

    reason = (request.form.get("reason") or "").strip() or "operator abort"
    from shared import queue_runner
    if not queue_runner.abort_one(change_id, reason=reason):
        flash(f"Change #{change_id} could not be aborted (state may have "
              f"changed concurrently).", "info")
        return redirect(request.referrer or
                        url_for("letsencrypt.requests_index"))

    # Update the cert too — a stuck 'pending' cert with an aborted
    # request should reflect that reality so operators can resubmit
    # cleanly (the unique-domain check at /new still blocks dupes; they
    # delete first then re-request).
    if cert is not None and cert.status in ("pending",):
        cert.status = "failed"
        cert.last_error = f"Request aborted by operator: {reason}"
        if cert.pending_change_id == change_id:
            cert.pending_change_id = None
        db.session.commit()

    flash(f"Change #{change_id} aborted. The cert is marked failed; click "
          f"<strong>Delete request</strong> on its detail page if you want "
          f"to fully untrack it before resubmitting.", "warning")
    return redirect(request.referrer or
                    url_for("letsencrypt.requests_index"))


@letsencrypt_bp.route("/requests/bulk", methods=["POST"])
@domain_admin_required
def requests_bulk():
    """Bulk Push or Abort. Halt-on-failure on push; best-effort on abort."""
    action = (request.form.get("action") or "").strip()
    raw_ids = request.form.getlist("change_ids")
    try:
        ids = [int(x) for x in raw_ids if str(x).strip().isdigit()]
    except ValueError:
        ids = []
    if not ids:
        flash("No requests selected.", "warning")
        return redirect(url_for("letsencrypt.requests_index"))

    # Pre-filter against visibility — bulk shouldn't act on rows the
    # operator can't see in their list view.
    visible_changes = (PendingChange.query
                       .filter(PendingChange.id.in_(ids),
                               PendingChange.feature_source == "letsencrypt")
                       .all())
    if not _is_super():
        active = _active_domain()
        visible_changes = [c for c in visible_changes
                           if active and c.domain_id == active.id]
    visible_ids = {c.id for c in visible_changes}

    if action == "push":
        # Re-queue any push_failed first so push_batch picks them up.
        for c in visible_changes:
            if c.state == "push_failed":
                c.state = "queued"
                c.conflict_with_id = None
                c.push_error_text = ""
                c.push_error_at = None
        db.session.commit()

        from shared import queue_runner
        result = queue_runner.push_batch(list(visible_ids))
        flash(f"Bulk push: {result.pushed + result.applied} succeeded, "
              f"{result.failed} failed, {result.skipped} skipped"
              + (f", halted at change #{result.halted_at}"
                 if result.halted_at else "") + ".",
              "success" if result.failed == 0 else "warning")
        return redirect(url_for("letsencrypt.requests_index"))

    elif action == "abort":
        from shared import queue_runner
        aborted = 0
        for cid in visible_ids:
            if queue_runner.abort_one(cid, reason="bulk abort by admin"):
                aborted += 1
                # Also reset cert.status if pending.
                ch = db.session.get(PendingChange, cid)
                if ch is None:
                    continue
                import json
                try:
                    pl = json.loads(ch.payload_json or "{}")
                except Exception:
                    pl = {}
                cert = (db.session.get(ManagedCertificate,
                                       pl.get("certificate_id"))
                        if isinstance(pl.get("certificate_id"), int) else None)
                if cert is not None and cert.status == "pending":
                    cert.status = "failed"
                    cert.last_error = "Request aborted by operator (bulk)"
                    if cert.pending_change_id == cid:
                        cert.pending_change_id = None
        db.session.commit()
        flash(f"Bulk abort: {aborted} of {len(visible_ids)} aborted "
              f"(the rest may have transitioned concurrently).",
              "warning" if aborted else "info")
        return redirect(url_for("letsencrypt.requests_index"))

    else:
        flash("Unknown bulk action.", "warning")
        return redirect(url_for("letsencrypt.requests_index"))


# ── Diagnostics: certbot log tail, reachability test, state reset ───────
#
# Added 2026-05-12 after operators hit two real-world LE failures:
#
#   1. "No such authorization" — caused by an HTTP-01 round-trip that
#      LE's validator couldn't complete (DNS / firewall / reverse-proxy
#      misconfiguration). Diagnosing required pulling
#      `/config/letsencrypt-logs/letsencrypt.log` via `docker exec`
#      because the captured stderr only showed the top-level error.
#
#   2. Stale lineage state preventing a fresh re-request after a
#      previous failed run.
#
# The three routes below let the operator self-diagnose + recover
# without leaving the FEA UI.


@letsencrypt_bp.route("/log")
@domain_admin_required
def log_tail_view():
    """Return the tail of the certbot debug log.

    Read-only; admin-only. Path is fixed in `letsencrypt_certbot.py`
    (`<CERTBOT_LOGS_DIR>/letsencrypt.log`) — caller doesn't pass any
    path, so there's no traversal vector. Renders as a styled
    full-page view with refresh, or returns text/plain when `?raw=1`.
    """
    from webapp.letsencrypt_certbot import (
        read_log_tail, log_file_path, CERTBOT_LOGS_DIR,
    )
    raw = (request.args.get("raw") or "").strip()
    text = read_log_tail(max_lines=600)
    if raw == "1":
        from flask import Response
        return Response(text or "(log file is empty or not yet created)\n",
                        mimetype="text/plain")
    return render_template(
        "tls/letsencrypt/log_view.html",
        log_text=text, log_path=log_file_path(),
        logs_dir=CERTBOT_LOGS_DIR,
    )


@letsencrypt_bp.route("/<int:cert_id>/reach-test", methods=["POST"])
@domain_admin_required
def cert_reach_test(cert_id):
    """Run an HTTP-01 reachability probe against the cert's FQDN.

    Writes a random token to FEA's webroot, GETs
    ``http://<fqdn>/.well-known/acme-challenge/<token>``, compares the
    response body. Result flashed inline + audit-logged. Useful before
    submitting a cert request to verify the reverse proxy is wired up.
    """
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None or not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))

    from webapp.letsencrypt_certbot import test_http01_reachability
    result = test_http01_reachability(fqdn=cert.domain)
    try:
        from shared.logging import audit
        audit(
            feature="letsencrypt",
            action="reach_test",
            target=cert.domain,
            status=("ok" if result.success else "failed"),
            detail=(f"http_status={result.http_status} "
                    f"duration_ms={result.duration_ms} "
                    f"err={result.error[:200] if result.error else ''}"),
            domain_id=cert.domain_id,
        )
    except Exception:
        pass

    if result.success:
        flash(f"HTTP-01 reachability test passed for "
              f"<code>{cert.domain}</code> "
              f"(HTTP {result.http_status}, {result.duration_ms}ms). "
              f"A real cert request will pass validation.",
              "success")
    else:
        suffix = (f" (HTTP {result.http_status})"
                  if result.http_status else "")
        flash(f"HTTP-01 reachability test FAILED for "
              f"<code>{cert.domain}</code>{suffix}: {result.error}",
              "danger")

    return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))


@letsencrypt_bp.route("/<int:cert_id>/reset-state", methods=["POST"])
@domain_admin_required
def cert_reset_state(cert_id):
    """Delete certbot's per-FQDN state so the next request starts fresh.

    Wipes ``renewal/<fqdn>.conf``, ``live/<fqdn>/``, ``archive/<fqdn>/``
    under ``CERTBOT_CONFIG_DIR``. Account key is preserved. Clears the
    cert's `certbot_lineage` column. The ManagedCertificate row is NOT
    deleted — that's what "Delete request" / "Stop tracking" is for.
    """
    cert = db.session.get(ManagedCertificate, cert_id)
    if cert is None or not _can_see(cert):
        flash("Certificate not found.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))

    from webapp.letsencrypt_certbot import reset_lineage_for_fqdn
    summary = reset_lineage_for_fqdn(cert.domain)
    removed_count = len(summary.get("removed") or [])
    error_count = len(summary.get("error") or [])

    if cert.certbot_lineage:
        cert.certbot_lineage = ""
    if cert.status == "active" and removed_count > 0:
        # The lineage is gone — reflect that honestly. Operator can
        # click Force renew (which now does a fresh request) or Delete
        # request and resubmit.
        cert.status = "failed"
        cert.last_error = "certbot state reset by operator"
    db.session.commit()

    try:
        from shared.logging import audit
        audit(
            feature="letsencrypt",
            action="state_reset",
            target=cert.domain,
            status=("ok" if error_count == 0 else "partial"),
            detail=(f"removed={removed_count} "
                    f"missing={len(summary.get('missing') or [])} "
                    f"errors={error_count}; paths={summary}"),
            domain_id=cert.domain_id,
        )
    except Exception:
        pass

    if error_count:
        flash(f"Certbot state for <code>{cert.domain}</code> partially "
              f"reset — {removed_count} paths removed, {error_count} "
              f"errors. Check /tls/letsencrypt/log.", "warning")
    elif removed_count:
        flash(f"Certbot state for <code>{cert.domain}</code> reset "
              f"({removed_count} paths removed). The next request will "
              f"start a fresh ACME order.", "success")
    else:
        flash(f"No certbot state on disk for <code>{cert.domain}</code> "
              f"— nothing to reset.", "info")
    return redirect(url_for("letsencrypt.cert_detail", cert_id=cert.id))


# ── Per-Domain allowlist management (Q6b — Domain Admin self-service) ───

@letsencrypt_bp.route("/patterns", methods=["GET", "POST"])
@domain_admin_required
def patterns_view():
    """Manage the cert-pattern allowlist for the operator's active Domain.

    Q6b locked: Domain Admin can edit their Domain's allowlist
    self-service. Add and remove patterns; matching is via fnmatch on
    the FQDN at cert-request time. The "no patterns = nothing allowed"
    safe default is enforced by the allowlist matcher (see
    `webapp/letsencrypt_allowlist.is_fqdn_allowed_for_domain`).
    """
    domain = _active_domain()
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("letsencrypt.list_certs"))

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if action == "add":
            raw = (request.form.get("pattern") or "").strip().lower()
            from webapp.letsencrypt_allowlist import is_valid_pattern
            ok, reason = is_valid_pattern(raw)
            if not ok:
                flash(f"Pattern refused: {reason}.", "danger")
            else:
                # Idempotent — UNIQUE(domain_id, pattern) catches dupes.
                existing = (DomainCertPattern.query
                            .filter_by(domain_id=domain.id, pattern=raw)
                            .first())
                if existing is not None:
                    flash(f"Pattern {raw!r} is already on the list.", "info")
                else:
                    db.session.add(DomainCertPattern(
                        domain_id=domain.id,
                        pattern=raw,
                        created_by_user_id=_current_user_id(),
                    ))
                    db.session.commit()
                    try:
                        from shared.logging import audit
                        audit(
                            feature="letsencrypt",
                            action="pattern.add",
                            target=raw,
                            detail=f"domain_id={domain.id}",
                            domain_id=domain.id,
                        )
                    except Exception:
                        pass
                    flash(f"Pattern {raw!r} added.", "success")
        elif action == "add_and_continue":
            # Inline pattern-add from the /new page: same as `add` but
            # redirects back to `/new` (or wherever `next` points) so the
            # operator can keep filling out the cert request form.
            raw = (request.form.get("pattern") or "").strip().lower()
            next_url = (request.form.get("next") or "").strip()
            from webapp.letsencrypt_allowlist import is_valid_pattern
            ok, reason = is_valid_pattern(raw)
            if not ok:
                flash(f"Pattern refused: {reason}.", "danger")
            else:
                existing = (DomainCertPattern.query
                            .filter_by(domain_id=domain.id, pattern=raw)
                            .first())
                if existing is not None:
                    flash(f"Pattern {raw!r} is already on the list.", "info")
                else:
                    db.session.add(DomainCertPattern(
                        domain_id=domain.id, pattern=raw,
                        created_by_user_id=_current_user_id(),
                    ))
                    db.session.commit()
                    try:
                        from shared.logging import audit
                        audit(
                            feature="letsencrypt",
                            action="pattern.add",
                            target=raw,
                            detail=(f"domain_id={domain.id} "
                                    f"(inline from /new)"),
                            domain_id=domain.id,
                        )
                    except Exception:
                        pass
                    flash(f"Pattern {raw!r} added — you can now request "
                          f"a matching certificate.", "success")
            # Same-origin redirect guard — only accept paths under
            # /tls/letsencrypt/, never absolute or external URLs.
            if (next_url and next_url.startswith("/tls/letsencrypt/")
                    and "//" not in next_url[1:]):
                return redirect(next_url)
            return redirect(url_for("letsencrypt.cert_new"))
        elif action == "remove":
            try:
                pid = int(request.form.get("pattern_id") or "0")
            except ValueError:
                pid = 0
            row = (DomainCertPattern.query
                   .filter_by(id=pid, domain_id=domain.id)
                   .first())
            if row is None:
                flash("Pattern not found on this Domain.", "warning")
            else:
                pat = row.pattern
                db.session.delete(row)
                db.session.commit()
                try:
                    from shared.logging import audit
                    audit(
                        feature="letsencrypt",
                        action="pattern.remove",
                        target=pat,
                        detail=f"domain_id={domain.id}",
                        domain_id=domain.id,
                    )
                except Exception:
                    pass
                flash(f"Pattern {pat!r} removed.", "warning")
        else:
            flash("Unknown action.", "warning")
        return redirect(url_for("letsencrypt.patterns_view"))

    patterns = (DomainCertPattern.query
                .filter_by(domain_id=domain.id)
                .order_by(DomainCertPattern.pattern.asc())
                .all())
    return render_template(
        "tls/letsencrypt/patterns.html",
        patterns=patterns, domain=domain,
    )


# ── Helpers ──────────────────────────────────────────────────────────────

def _is_super() -> bool:
    try:
        from webapp.auth_roles import is_super_admin
        return is_super_admin()
    except Exception:
        return False


def _can_see(cert: ManagedCertificate) -> bool:
    """Domain-scoped visibility. Super sees everything; Domain Admin
    sees only certs in their active Domain."""
    if _is_super():
        return True
    domain = _active_domain()
    if domain is None:
        return False
    return cert.domain_id == domain.id


# ── Public ACME HTTP-01 challenge endpoint ──────────────────────────────

@acme_challenge_bp.route("/.well-known/acme-challenge/<path:token>")
def acme_challenge(token: str):
    """Serve the ACME HTTP-01 challenge file LE's validator is fetching.

    certbot wrote `<token>` (a base64url-encoded blob) under
    `<webroot>/.well-known/acme-challenge/` during the cert request;
    this endpoint reads that file and returns it verbatim. No auth, no
    CSRF — LE's servers hit it from the internet.

    Safety: the `path:` converter accepts slashes which would allow a
    traversal attack (`../`). We sanitise by refusing any non-alphanumeric
    token (LE's token alphabet is base64url: A-Z, a-z, 0-9, `-`, `_`).
    """
    import re
    from pathlib import Path
    from flask import abort, send_file
    from webapp.letsencrypt_certbot import WEBROOT

    if not re.match(r"^[A-Za-z0-9_\-]+$", token):
        log.warning("acme_challenge: refused malformed token %r", token[:40])
        abort(404)

    challenge_path = Path(WEBROOT) / ".well-known" / "acme-challenge" / token
    # Resolve and double-check the file is INSIDE the webroot. Defence
    # in depth — the alphanumeric guard already rejects `..` but this
    # catches symlink shenanigans too.
    try:
        resolved = challenge_path.resolve()
        webroot_resolved = Path(WEBROOT).resolve()
    except Exception:
        abort(404)
    try:
        resolved.relative_to(webroot_resolved)
    except ValueError:
        log.warning("acme_challenge: refused out-of-webroot resolve %r",
                    str(resolved))
        abort(404)
    if not resolved.is_file():
        abort(404)
    return send_file(str(resolved), mimetype="text/plain")
