"""
FlexEdgeAdmin — DHCP Reservation Manager Blueprint.

Admin-only feature that manages MAC-to-IP reservations on Forcepoint NGFW
engines with the internal DHCP server enabled. The SMC API does not expose
DHCP reservations, so SMC Host elements are used as the source of truth
(MAC stored inside Host.comment via a `[flexedge:mac=...]` marker). The
actual push of `host { }` blocks into `/data/config/base/dhcp-server.conf`
on each cluster node is handled by Phase 4 (`dhcp_deployer.py`).

Routes mounted at /dhcp/*

Phase 3 scope (this file):
  - Dashboard + activity log
  - Scope discovery & enable/disable
  - Host CRUD (reservations)
  - AJAX cascade: tenant → api-key → engine → scopes
  - "Deploy" button is wired but hands off to a placeholder until Phase 4.
"""
import hmac
import logging
import re
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from ipaddress import ip_address, ip_network
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app, jsonify, g,
)

from shared.db import db
from webapp.models import (
    ApiKey, DhcpActivityLog, DhcpDeployment, DhcpEngineCredential,
    DhcpEngineSshAccess, DhcpReservation, DhcpScope, Tenant, Domain,
)
from webapp.smc_dhcp_client import (
    SMCConfig, smc_session,
    DhcpHostView, DhcpScopeInfo,
    list_scopes_for_engine, list_cluster_nodes, dump_engine_interfaces,
    is_node_initiated_contact,
    host_create, host_update, host_delete, host_get, host_list_by_scope,
    is_valid_mac, normalize_mac,
    find_ssh_access_rule, find_active_policy,
    update_source_host_address, add_source_host_to_rule,
    _derive_cidr_from_pool,
)
from webapp.smc_tls_client import list_engines, smc_error_detail
from webapp.dhcp_ssh import (
    SSHTarget, SSHCredential, FingerprintMismatch,
    tcp_probe, verify_credential, is_auth_failure,
    get_file as ssh_get_file,
)
from webapp.dhcp_bootstrap import (
    engine_bootstrap_lock,
    probe_public_ip, preflight, install_ssh_rule, upload_policy,
    remove_rule, enroll_node, force_reset_password,
    rule_name_for,
)
from webapp.dhcp_leases import parse_dhcpd_leases, merge_cluster_leases

log = logging.getLogger(__name__)

dhcp_bp = Blueprint("dhcp", __name__, url_prefix="/dhcp")


# ── Access control ──────────────────────────────────────────────────────

def admin_required(f):
    """Require authenticated user with admin role (mirrors TLS Manager)."""
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


def require_api_token(f):
    """Decorator for webhook endpoints: Bearer token auth.

    C6 + M15 (audit fix-up, 2026-05-09):
      * Use ``hmac.compare_digest`` to compare the presented token with
        the configured one — constant-time comparison prevents byte-by-byte
        timing-attack token recovery.
      * Refuse with HTTP 503 when the configured token is empty / None.
        Without this guard a misconfigured deploy (token-file write
        failed, env var unset) would coerce ``None`` into the comparison
        and reject everything as "Invalid token" — the failure mode is
        indistinguishable from "wrong token from caller". 503 makes the
        misconfiguration unambiguous in the logs.
    """
    import hmac
    @wraps(f)
    def decorated(*args, **kwargs):
        configured = current_app.config.get("DHCP_API_TOKEN") or ""
        if not configured:
            # Unconfigured webhook MUST refuse outright — see tls_manager
            # for the rationale (same guard pattern).
            return jsonify({"error": "Webhook token not configured on server"}), 503
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401
        presented = auth[7:]
        if not hmac.compare_digest(presented.encode("utf-8"),
                                   configured.encode("utf-8")):
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated


def _log_activity(category: str, action: str, status: str,
                  target: str = "", detail: str = ""):
    """Funnel a DHCP audit-log entry through the platform log writer.

    Replaces the old direct DhcpActivityLog write per the standing rule
    (memory: feedback_logging_standing_rule). The legacy `category +
    action` pair is composed into a single platform action string —
    e.g. `scope.create`, `reservation.delete`, `system.phase0_validated`.

    `system` rows route to feature='system' so the retention sweep can
    preserve gate signals (Phase 0 marker) regardless of feature toggles.
    """
    from shared.logging import audit
    feature = "system" if category == "system" else "dhcp"
    audit(feature=feature,
          action=f"{category}.{action}",
          target=target, detail=detail, status=status)


def _legacy_smc_domain_name(tenant, api_key) -> str:
    """Resolve the SMC admin-domain for a legacy ``(tenant, api_key)`` cfg.

    Root-cause fix (2026-05-31): an ApiKey can back MULTIPLE Domains (same
    SMC server, different SMC admin-domain — e.g. "Shared Domain" vs.
    "Milano"). The legacy cfg builders used ``tenant.default_domain``, a
    single fixed value, so switching the topbar Domain never changed which
    SMC admin-domain the DHCP cascade / scope discovery actually queried —
    every Domain backed by the same key resolved to the tenant default.
    Symptom: "the tenant list shows a cached one that doesn't switch to the
    selected Domain."

    Prefer the request's ACTIVE Domain when it's backed by this ApiKey —
    that's the operator's authoritative scope and carries the correct
    ``smc_domain_name``. Fall back to ``tenant.default_domain`` only when
    there's no matching active Domain (CLI / out-of-request callers).
    """
    active = getattr(g, "domain", None)
    if (api_key is not None and active is not None
            and getattr(active, "api_key_id", None) == api_key.id
            and active.smc_domain_name):
        return active.smc_domain_name
    return tenant.default_domain or ""


def _smc_cfg(tenant_or_domain, api_key: ApiKey | None = None) -> SMCConfig:
    """Build the SMC client config.

    Phase B.2 transition: accepts EITHER a Domain (preferred, single-arg)
    OR the legacy (Tenant, ApiKey) pair. New code should pass a Domain;
    server config now lives on ApiKey, SMC-domain name on Domain.
    """
    # New form: a Domain carries everything we need.
    if isinstance(tenant_or_domain, Domain):
        domain = tenant_or_domain
        ak = domain.api_key
        return SMCConfig(
            url=ak.smc_url,
            api_key=ak.decrypted_key,
            domain=domain.smc_domain_name or "",
            api_version=ak.api_version or "",
            verify_ssl=ak.verify_ssl,
            timeout=ak.timeout,
        )
    # Legacy form: (Tenant, ApiKey). Pull server fields from the ApiKey
    # (Phase A absorbed them onto api_keys); resolve the SMC admin-domain
    # from the ACTIVE Domain (see _legacy_smc_domain_name) so a multi-domain
    # ApiKey honors the operator's topbar selection instead of pinning to
    # the tenant default.
    tenant = tenant_or_domain
    return SMCConfig(
        url=api_key.smc_url or tenant.smc_url,
        api_key=api_key.decrypted_key,
        domain=_legacy_smc_domain_name(tenant, api_key),
        api_version=api_key.api_version or tenant.api_version or "",
        verify_ssl=api_key.verify_ssl if api_key.verify_ssl is not None else tenant.verify_ssl,
        timeout=api_key.timeout or tenant.timeout,
    )


def _smc_cfg_dict(tenant_or_domain, api_key: ApiKey | None = None) -> dict:
    """Dict-shaped SMC config — matches `app.get_user_cfg()` shape.

    Required by `engine_inquiry.list_clusters` and the rest of the
    `webapp.smc_client.smc_session(cfg)` callers (top-level
    `smc_client`, dict-keyed: `cfg["smc_url"]`, `cfg["api_key"]`, …).

    `_smc_cfg(...)` above returns the `SMCConfig` dataclass used by
    `webapp.smc_tls_client.smc_session(cfg)` (attribute-keyed:
    `cfg.url`, `cfg.api_key`). The two are not interchangeable — passing
    one where the other is expected raises
    ``TypeError: 'SMCConfig' object is not subscriptable``, which is
    what the user saw as "Error: 'SMCConfig' object" in the engines
    cascade.

    Returns the same dict shape every `domain_objects.*` cache fetcher
    consumes (engines / cluster / scopes / policy / element / dhcp_host).
    """
    if isinstance(tenant_or_domain, Domain):
        domain = tenant_or_domain
        ak = domain.api_key
        return {
            "smc_url":      ak.smc_url,
            "api_key":      ak.decrypted_key,
            "verify_ssl":   bool(ak.verify_ssl),
            "timeout":      ak.timeout or 120,
            "domain":       domain.smc_domain_name or "",
            "api_version":  ak.api_version or "",
            "retry_on_busy": True,
        }
    tenant = tenant_or_domain
    return {
        "smc_url":      (api_key.smc_url or tenant.smc_url),
        "api_key":      api_key.decrypted_key,
        "verify_ssl":   bool(api_key.verify_ssl
                             if api_key.verify_ssl is not None
                             else tenant.verify_ssl),
        "timeout":      api_key.timeout or tenant.timeout or 120,
        # Active-Domain-aware SMC admin-domain (see _legacy_smc_domain_name)
        # — a multi-domain ApiKey must query the Domain the operator picked,
        # not the tenant default.
        "domain":       _legacy_smc_domain_name(tenant, api_key),
        "api_version":  api_key.api_version or tenant.api_version or "",
        "retry_on_busy": True,
    }


def _wants_json_response() -> bool:
    """True for AJAX-style requests — same check used inline by every
    route that branches on response shape."""
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("Accept") or ""))


def _check_stale_form_or_response(*, redirect_to: str = "dhcp.credentials_list"):
    """Stale-form detector for routes that POST legacy ``tenant_id`` /
    ``api_key_id`` form fields.

    Background — the credentials/scopes templates predate the
    Multi-Domain Revamp. Their forms still carry ``tenant_id`` and
    sometimes ``api_key_id`` hidden fields populated at render time.
    The values are sometimes a real Tenant.id (when sourced from a
    ``<select>``), sometimes a Domain.id (when the template confused
    ``tid`` for ``c.domain_id``). Either is fine — for the *current*
    request — when those form values match the active Domain.

    What's NOT fine: the operator switches Domain in the topbar
    (``session["active_profile"]`` updates), but a still-mounted DOM
    in this tab (e.g. the wizard, a modal, or a stale browser history
    entry) submits an AJAX request whose form still references the
    OLD Domain's IDs. Pre-Revamp code resolved the form's tenant_id
    via a sloppy ``Domain.query.join(ApiKey).filter(ApiKey.tenant_id ==
    form_tid)`` fallback, which by coincidence often picked the *new*
    session Domain — producing the cryptic "no enrollment record for
    engine X on domain Y" downstream when the engine actually only
    exists in the OLD Domain's data.

    This helper detects the stale-form case authoritatively from
    ``g.domain`` and refuses with a clear "page is out of sync,
    reload" message. AJAX gets HTTP 409 + JSON; form POSTs get a flash
    + redirect.

    Returns:
        ``None`` when the form's IDs are consistent with the active
        Domain (or when no IDs were sent — route does its own
        validation). The route then proceeds.
        A Flask response when stale — caller does ``return resp``.
    """
    from flask import g
    domain = getattr(g, "domain", None)
    if domain is None or domain.api_key is None:
        # No active Domain at all — let the route's own no-domain
        # handling fire (each one has its own copy).
        return None

    expected_did = domain.id
    expected_tid = domain.api_key.tenant_id
    expected_kid = domain.api_key.id

    def _to_int(s):
        try:
            return int(s) if s else None
        except (TypeError, ValueError):
            return None

    form_tid = _to_int(request.form.get("tenant_id"))
    form_kid = _to_int(request.form.get("api_key_id"))

    # Templates send `tenant_id` for either Tenant.id OR Domain.id —
    # both are accepted here. Mismatch in BOTH dimensions = stale.
    tid_ok = (form_tid is None
              or form_tid == expected_tid
              or form_tid == expected_did)
    kid_ok = (form_kid is None or form_kid == expected_kid)
    if tid_ok and kid_ok:
        return None

    msg = ("This page was loaded for a different Domain than the one "
           "currently active in the topbar. Reload the page and try "
           "again — the form data references stale context.")
    if _wants_json_response():
        return jsonify(
            ok=False, error=msg, code="stale_form",
            form_tenant_id=form_tid,
            form_api_key_id=form_kid,
            active_domain_id=expected_did,
            active_tenant_id=expected_tid,
            active_api_key_id=expected_kid,
        ), 409
    flash(msg, "warning")
    return redirect(url_for(redirect_to))


def _scope_or_404(scope_id: int) -> DhcpScope:
    scope = db.session.get(DhcpScope, scope_id)
    if not scope:
        flash("Scope not found.", "danger")
        return None
    return scope


def _scope_with_creds_or_redirect(scope_id: int) -> DhcpScope:
    """Like ``_scope_or_404`` but also refuses if the scope's engine
    has no fully-verified SSH credentials in the active Domain.

    Returns ``None`` and flashes; callers redirect (typically to
    ``/dhcp/scopes`` or back-referrer). Used by every operation that
    needs SSH access to the engine — leases viewer, subnet scan,
    Phase 4 deploy, reservation CRUD. Pure-FlexEdge ops (delete /
    enable / disable / sync) skip this guard.

    TODO-item-1 (2026-05-08): hide unusable items entirely; admin can
    still reach them via /dhcp/scopes?show_all=1 for cleanup.
    """
    scope = _scope_or_404(scope_id)
    if scope is None:
        return None
    from webapp.engine_credentials import is_engine_credentials_valid
    if not is_engine_credentials_valid(scope.domain_id, scope.engine_name):
        flash(
            f"Engine {scope.engine_name!r} has no fully-verified SSH "
            f"credentials in this Domain. Every cluster node must be "
            f"enrolled and verified before this scope can be used. "
            f"Enroll in Credentials, then come back.",
            "warning",
        )
        return None
    return scope


def _lazy_backfill_subnet_cidr(scope: DhcpScope) -> bool:
    """Backfill ``scope.subnet_cidr`` from saved gateway/pool fields when
    discovery didn't manage to set it.

    Why: scopes discovered before the 2026-05-20 CIDR-derivation fallback
    landed (or scopes whose SMC payload has neither ``address`` nor
    ``network_value`` on the interface level — observed on some cluster
    VLAN sub-interfaces) ended up with ``subnet_cidr=""`` in the DB. That
    blocks the leases subnet-filter AND the Full-subnet scan, with the
    operator told to "Re-run scope discovery" — which doesn't help if
    SMC still won't give us the missing fields. But the scope row often
    *does* have ``gateway`` + ``dhcp_pool_start`` + ``dhcp_pool_end``
    persisted from that same discovery, which is enough to derive a
    usable CIDR locally.

    Returns True iff a value was derived and persisted. No-op when
    ``subnet_cidr`` already holds a parseable network, or when there
    isn't enough data on the row to produce at least a /30 (≥4 hosts).

    A non-empty but unparseable ``subnet_cidr`` (e.g. a garbage value
    persisted by an old discovery shape) is treated the same as empty
    and overwritten — otherwise the leases filter and Full-subnet scan
    stay broken forever.
    """
    from ipaddress import ip_network
    current = (scope.subnet_cidr or "").strip()
    if current:
        try:
            ip_network(current, strict=False)
            return False  # already parseable — leave alone
        except (ValueError, TypeError):
            log.info(
                "Scope %s has unparseable subnet_cidr=%r — will overwrite "
                "with derived value if possible.", scope.id, current,
            )
    derived_cidr, _ = _derive_cidr_from_pool(
        {"default_gateway": scope.gateway or ""},
        scope.dhcp_pool_start or "",
        scope.dhcp_pool_end or "",
    )
    if not derived_cidr:
        return False
    # Refuse trivially small derivations (/31 or /32). They happen when
    # only the gateway is known, or when pool_start == pool_end, and
    # would be useless for scanning or filtering anyway.
    try:
        net = ip_network(derived_cidr, strict=False)
        if net.prefixlen >= 31:
            return False
    except ValueError:
        return False
    scope.subnet_cidr = derived_cidr
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return False
    log.info(
        "Backfilled subnet_cidr=%s on scope %s (%s/%s) from saved "
        "gateway=%r pool=%r-%r",
        derived_cidr, scope.id, scope.engine_name, scope.interface_id,
        scope.gateway, scope.dhcp_pool_start, scope.dhcp_pool_end,
    )
    return True


def _domain_from_form(tenant_id: int, api_key_id: int) -> Domain | None:
    """Resolve the Domain from the (tenant_id, api_key_id) pair the
    cascading admin forms still POST today.

    Multi-domain fix (2026-05-31): an ApiKey can back several Domains, so a
    bare ``filter_by(api_key_id=…).first()`` silently pinned every action to
    whichever Domain row was created first — ignoring the operator's topbar
    selection (the reported "scopes don't switch Domain" bug). Prefer the
    request's ACTIVE Domain when it's backed by this ApiKey; only fall back
    to ``.first()`` for out-of-request callers or a mismatched form.

    Falls back gracefully — returns None if no Domain found, callers should
    treat that as "Phase A migration didn't run for this key" and bail out.
    """
    active = getattr(g, "domain", None)
    if active is not None and getattr(active, "api_key_id", None) == api_key_id:
        return active
    return Domain.query.filter_by(api_key_id=api_key_id).first()


def _domain_id_for_form(tenant_id: int, api_key_id: int) -> int | None:
    """Convenience wrapper for the common ``int | None`` you want to
    pass into a ``filter_by(domain_id=...)`` or a ``Model(domain_id=...)``
    constructor without having to hold the Domain object."""
    d = _domain_from_form(tenant_id, api_key_id)
    return d.id if d else None


def _active_domain_id() -> int | None:
    """Domain id for the request's active Domain, or None.

    Used by every read-side list view that must show only rows belonging
    to the currently-selected Domain. Returning None signals the view to
    bail out / show an empty list — never let a `domain_id IS NULL`
    accident leak rows from other Domains.
    """
    domain = getattr(g, "domain", None)
    return domain.id if domain is not None else None


def _assert_active_domain_match(tenant_id: int, key_id: int):
    """Reject URL-provided ``(tenant_id, api_key_id)`` pairs that don't
    belong to the active Domain.

    The legacy ``/dhcp/api/tenants/<tid>/api-keys/<kid>/...`` cascade
    endpoints take both IDs from the URL. They predate the Multi-Domain
    Revamp and used to assume the operator could span every Tenant.
    Today the operator's effective scope is exactly one Domain, so the
    only legitimate ``(tid, kid)`` pair is the one bound to
    ``g.domain``. Any other pair is either a stale dropdown value or
    URL crafting — refuse with 403.

    Returns ``None`` on success, a ``(flask.Response, 403)`` tuple the
    caller forwards to the client on mismatch.
    """
    domain = getattr(g, "domain", None)
    if domain is None:
        return jsonify({"error": "no active domain"}), 400
    bound_key = getattr(domain, "api_key", None)
    if (bound_key is None
            or bound_key.id != key_id
            or bound_key.tenant_id != tenant_id):
        return jsonify({
            "error": "cross-Domain access refused",
            "detail": ("The (tenant_id, api_key_id) in the URL does not "
                       "belong to the active Domain. Switch Domains in "
                       "the topbar or refresh the page to reload the "
                       "cascading dropdowns."),
        }), 403
    return None


def _domain_ids_for_tenant(tenant_id: int) -> list[int]:
    """All active Domain ids belonging to the tenant via its ApiKeys.

    Used by the few credentials-wizard routes that POST only `tenant_id`
    (no api_key_id) to filter feature tables that are now keyed by
    `domain_id`. After Phase B.3 drops feature-table tenant_id columns,
    this is the bridge between the legacy tenant-cascade form and the
    domain-scoped data model.
    """
    return [d.id for d in
            Domain.query.join(ApiKey, Domain.api_key_id == ApiKey.id)
                        .filter(ApiKey.tenant_id == tenant_id,
                                Domain.is_active.is_(True))
                        .all()]


# ── Phase 0 validation flag ────────────────────────────────────────────
#
# Phase 0 = operator-run lab test that confirms the SMC engine doesn't
# overwrite our edits to /data/config/base/dhcp-server.conf on policy
# refresh / upload / reboot. Until validated, the Deploy button is gated
# (preflight returns "blocked") and the dashboard shows a yellow banner.
#
# Stored as a single DhcpActivityLog row with the marker shape:
#   category="system", action="phase0_validated"
# Keeping it in the activity log gives free audit trail (operator, when,
# notes); revoking is a row delete. No new schema needed.

PHASE0_CATEGORY = "system"
PHASE0_ACTION = "phase0_validated"


def _read_dhcp_activity_for_dashboard(domain_id: int | None, limit: int = 50):
    """Return a list of legacy-shaped log rows for the DHCP dashboard.

    Reads from the unified PlatformLog and re-projects each row into a
    `SimpleNamespace` that exposes `created_at / category / action /
    status / target / detail / id` — the fields the existing dashboard
    template uses. Filters by feature ('dhcp' or 'system') and the
    active Domain (plus null-domain system rows).
    """
    from types import SimpleNamespace
    from webapp.models import PlatformLog

    q = PlatformLog.query.filter(PlatformLog.feature.in_(["dhcp", "system", "engines"]))
    if domain_id is not None:
        q = q.filter(
            (PlatformLog.domain_id == domain_id) |
            (PlatformLog.domain_id.is_(None))
        )
    rows = q.order_by(PlatformLog.timestamp.desc()).limit(limit).all()

    out = []
    for r in rows:
        if "." in (r.action or ""):
            cat, act = r.action.split(".", 1)
        else:
            cat, act = (r.feature or "?"), (r.action or "")
        out.append(SimpleNamespace(
            id=r.id,
            created_at=r.timestamp,
            category=cat,
            action=act,
            status=r.status,
            target=r.target,
            detail=r.detail,
        ))
    return out


_PHASE0_PLATFORM_ACTION = f"{PHASE0_CATEGORY}.{PHASE0_ACTION}"


def is_phase0_validated() -> bool:
    """True iff an operator has previously marked Phase 0 as validated.

    Looks in BOTH the unified `platform_logs` (where new writes land) AND
    the legacy `dhcp_activity_logs` (where pre-unification rows still
    live until the next retention sweep). Either match satisfies the gate.
    """
    from webapp.models import PlatformLog
    plog_hit = (PlatformLog.query
                .filter_by(feature="system", action=_PHASE0_PLATFORM_ACTION,
                           status="ok")
                .first()) is not None
    if plog_hit:
        return True
    return (DhcpActivityLog.query
            .filter_by(category=PHASE0_CATEGORY, action=PHASE0_ACTION,
                       status="ok")
            .first()) is not None


def get_phase0_validation():
    """Most recent Phase 0 validation row, or None.

    Returns whichever is newer between platform_logs and the legacy
    dhcp_activity_logs row. Both shapes expose `created_at` (legacy) or
    `timestamp` (platform); the dashboard template only needs a datetime
    via .created_at, so we adapt the platform row into a SimpleNamespace.
    """
    from types import SimpleNamespace
    from webapp.models import PlatformLog

    legacy = (DhcpActivityLog.query
              .filter_by(category=PHASE0_CATEGORY, action=PHASE0_ACTION,
                         status="ok")
              .order_by(DhcpActivityLog.created_at.desc())
              .first())
    plog = (PlatformLog.query
            .filter_by(feature="system", action=_PHASE0_PLATFORM_ACTION,
                       status="ok")
            .order_by(PlatformLog.timestamp.desc())
            .first())

    legacy_t = legacy.created_at if legacy else None
    plog_t = plog.timestamp if plog else None

    if plog_t and (legacy_t is None or plog_t >= legacy_t):
        return SimpleNamespace(
            id=plog.id, created_at=plog.timestamp,
            category=PHASE0_CATEGORY, action=PHASE0_ACTION,
            status=plog.status, target=plog.target, detail=plog.detail,
        )
    return legacy


# ── Initialization ──────────────────────────────────────────────────────

def init_dhcp_manager(app):
    """Ensure the Bearer token for webhook endpoints exists on disk.

    Matches the TLS Manager's `/config/.tls_api_token` convention, but with a
    separate token so DHCP and TLS scopes can be rotated independently.
    """
    token_file = Path(app.config.get("CONFIG_DIR", "/config")) / ".dhcp_api_token"
    if token_file.exists():
        app.config["DHCP_API_TOKEN"] = token_file.read_text().strip()
    else:
        token = secrets.token_urlsafe(32)
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token)
        try:
            token_file.chmod(0o600)
        except Exception:
            pass
        app.config["DHCP_API_TOKEN"] = token


# ── Dashboard ───────────────────────────────────────────────────────────

@dhcp_bp.route("/")
@admin_required
def dashboard():
    domain_id = _active_domain_id()
    if domain_id is None:
        scopes, creds, accesses = [], [], []
    else:
        scopes = (DhcpScope.query
                  .filter_by(domain_id=domain_id)
                  .order_by(DhcpScope.engine_name, DhcpScope.interface_id).all())
        creds = DhcpEngineCredential.query.filter_by(domain_id=domain_id).all()
        accesses = DhcpEngineSshAccess.query.filter_by(domain_id=domain_id).all()

    # Activity log: read from the unified PlatformLog (the per-feature
    # activity table is no longer written; existing rows were backfilled
    # at boot by `_phase_log_unification`). Rows are projected into a
    # legacy-shaped namespace so the dashboard template — which uses
    # log.created_at / log.category / log.action — keeps working unchanged.
    activity_logs = _read_dhcp_activity_for_dashboard(domain_id, limit=50)
    reservation_counts = {
        s.id: s.reservations.count() for s in scopes
    }
    out_of_sync = {
        s.id: s.reservations.filter(DhcpReservation.status != "synced").count()
        for s in scopes
    }

    # Credential / cluster summary stats — scoped to the active Domain.
    enrolled_engines = {(c.domain_id, c.engine_name) for c in creds}
    healthy_creds = sum(1 for c in creds if c.last_verify_status == "ok")
    unhealthy_creds = sum(1 for c in creds if c.last_verify_status == "failed")

    return render_template(
        "dhcp/dashboard.html",
        scopes=scopes,
        reservation_counts=reservation_counts,
        out_of_sync=out_of_sync,
        activity_logs=activity_logs,
        creds=creds,
        accesses=accesses,
        enrolled_engine_count=len(enrolled_engines),
        total_credential_count=len(creds),
        healthy_cred_count=healthy_creds,
        unhealthy_cred_count=unhealthy_creds,
        ssh_rule_count=len(accesses),
        phase0_validated=is_phase0_validated(),
        phase0_validation=get_phase0_validation(),
    )


@dhcp_bp.route("/system/phase0/validate", methods=["POST"])
@admin_required
def system_phase0_validate():
    """Operator confirms they've run the Phase 0 lab persistence test
    on a real cluster and observed that ``/data/config/base/dhcp-server.conf``
    survives policy refresh / upload / reboot.

    Until this is recorded, Phase 4 deploys are blocked at preflight to
    prevent the operator from learning the hard way that SMC was silently
    overwriting their reservations.
    """
    notes = (request.form.get("notes") or "").strip()
    op = _operator_email()
    detail = (f"Operator confirmed Phase 0 lab persistence test "
              f"({notes!r})" if notes else
              "Operator confirmed Phase 0 lab persistence test "
              "(no notes provided).")
    _log_activity(PHASE0_CATEGORY, PHASE0_ACTION, "ok",
                  target=op or "system", detail=detail)
    flash("Phase 0 validation recorded — Phase 4 deploy is now unlocked.",
          "success")
    return redirect(url_for("dhcp.dashboard"))


@dhcp_bp.route("/system/phase0/revoke", methods=["POST"])
@admin_required
def system_phase0_revoke():
    """Revoke a previous Phase 0 validation.

    Used when the lab cluster has been re-imaged, SMC was upgraded, or
    something else changed that invalidates the prior persistence test.
    Deletes the most recent validation row so the gate re-engages.
    """
    row = get_phase0_validation()
    if not row:
        flash("No Phase 0 validation on record to revoke.", "info")
        return redirect(url_for("dhcp.dashboard"))
    db.session.delete(row)
    db.session.commit()
    _log_activity(PHASE0_CATEGORY, "phase0_revoked", "ok",
                  target=_operator_email(),
                  detail=f"Revoked validation row id={row.id} "
                         f"originally recorded {row.created_at}.")
    flash("Phase 0 validation revoked. Phase 4 deploy is now blocked "
          "until re-validated.", "warning")
    return redirect(url_for("dhcp.dashboard"))


# ── Scopes ──────────────────────────────────────────────────────────────

@dhcp_bp.route("/scopes")
@admin_required
def scopes_list():
    domain_id = _active_domain_id()
    show_all = request.args.get("show_all") == "1"
    if domain_id is None:
        scopes = []
        hidden_count = 0
    else:
        all_scopes = (DhcpScope.query
                      .filter_by(domain_id=domain_id)
                      .order_by(DhcpScope.engine_name, DhcpScope.interface_id).all())
        # TODO-item-1 gate: hide scopes whose engine has no fully-verified
        # SSH credentials in this Domain. ?show_all=1 bypasses the filter
        # so an admin can clean up stale scopes (delete) without
        # re-enrolling credentials first.
        from webapp.engine_credentials import valid_engines_for_domain
        valid = valid_engines_for_domain(domain_id)
        if show_all:
            scopes = all_scopes
            hidden_count = 0
        else:
            scopes = [s for s in all_scopes if s.engine_name in valid]
            hidden_count = len(all_scopes) - len(scopes)
    # Domain-Scoping: only the active Domain's bound Tenant — never a
    # full Tenant list. The operator should never see another Domain's
    # infrastructure surfaced here.
    domain_obj = getattr(g, "domain", None)
    bound_tenant_id = (domain_obj.api_key.tenant_id
                       if domain_obj is not None and domain_obj.api_key is not None
                       else None)
    tenants = ([] if bound_tenant_id is None
               else Tenant.query
                          .filter_by(id=bound_tenant_id, is_active=True)
                          .all())
    return render_template("dhcp/scopes.html", scopes=scopes, tenants=tenants,
                           hidden_count=hidden_count, show_all=show_all)


@dhcp_bp.route("/scopes/discover", methods=["POST"])
@admin_required
def scopes_discover():
    """Enumerate DHCP-enabled interfaces on a given engine + upsert them."""
    stale = _check_stale_form_or_response(redirect_to="dhcp.scopes_list")
    if stale is not None:
        return stale
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        flash("Tenant or API key not found.", "danger")
        return redirect(url_for("dhcp.scopes_list"))

    cfg = _smc_cfg(tenant, api_key)
    # `domain_objects.scopes` ultimately calls `smc_client.smc_session(cfg)`
    # which expects a DICT-shaped cfg (not the SMCConfig dataclass).
    cfg_dict = _smc_cfg_dict(tenant, api_key)
    target = f"{tenant.name}/{api_key.name}/{engine_name}"
    domain_id = _domain_id_for_form(tenant_id, api_key_id)
    try:
        # Force a fresh walk + repopulate the shared ``scopes`` cache —
        # this is the operator's explicit "give me the truth from SMC"
        # action. Subsequent cascade previews on the same engine read
        # the warmed cache.
        domain_obj = getattr(g, "domain", None)
        from webapp import domain_objects
        scope_dicts, _cv = domain_objects.scopes(
            domain_obj, cfg_dict, engine_name, refresh=True)
        # Project dicts back to the dataclass shape the upsert loop expects
        from webapp.smc_dhcp_client import DhcpScopeInfo
        found = [DhcpScopeInfo(**{
            k: d.get(k) for k in d.keys()
            if k in DhcpScopeInfo.__dataclass_fields__
        }) for d in scope_dicts]

        added, updated = 0, 0
        now = datetime.now(timezone.utc)
        for info in found:
            # Check both new (domain_id) and legacy (tenant_id) uniqueness to
            # avoid hitting the vestigial UNIQUE(tenant_id, engine_name,
            # interface_id) constraint on a stale row from a previous Domain.
            # Same pattern as the credentials upsert.
            existing = DhcpScope.query.filter_by(
                domain_id=domain_id,
                engine_name=engine_name,
                interface_id=info.interface_id,
            ).first()
            if existing is None:
                existing = DhcpScope.query.filter_by(
                    tenant_id=tenant.id,
                    engine_name=engine_name,
                    interface_id=info.interface_id,
                ).first()
            if existing:
                existing.api_key_id = api_key.id
                existing.domain_id = domain_id  # backfill if it was NULL on legacy rows
                existing.interface_label = info.interface_label or existing.interface_label
                existing.subnet_cidr = info.subnet_cidr or existing.subnet_cidr
                existing.gateway = info.gateway or existing.gateway
                existing.dhcp_pool_start = info.dhcp_pool_start or existing.dhcp_pool_start
                existing.dhcp_pool_end = info.dhcp_pool_end or existing.dhcp_pool_end
                existing.last_synced_from_smc_at = now
                updated += 1
            else:
                db.session.add(DhcpScope(
                    domain_id=domain_id,
                    tenant_id=tenant.id,             # legacy — kept until B.3
                    api_key_id=api_key.id,           # legacy — kept until B.3
                    engine_name=engine_name,
                    interface_id=info.interface_id,
                    interface_label=info.interface_label,
                    subnet_cidr=info.subnet_cidr,
                    gateway=info.gateway,
                    dhcp_pool_start=info.dhcp_pool_start,
                    dhcp_pool_end=info.dhcp_pool_end,
                    enabled_in_flexedge=False,
                    last_synced_from_smc_at=now,
                ))
                added += 1
        db.session.commit()
        _log_activity("scope", "discover", "ok", target,
                      f"Found {len(found)} scope(s); added {added}, updated {updated}.")
        if found:
            flash(f"Discovered {len(found)} scope(s) on {engine_name} "
                  f"({added} new, {updated} updated).", "success")
        else:
            flash(f"No DHCP-enabled scopes found on {engine_name}. "
                  f"If you expected some, hit the diagnostic endpoint "
                  f"/dhcp/api/tenants/{tenant.id}/api-keys/{api_key.id}/"
                  f"engines/{engine_name}/interfaces/debug to inspect the "
                  f"raw SMC JSON and file an update to the parser.",
                  "warning")
    except Exception as exc:
        db.session.rollback()
        _log_activity("scope", "discover", "failed", target, smc_error_detail(exc))
        flash(f"Discovery failed: {exc}", "danger")
    return redirect(url_for("dhcp.scopes_list"))


@dhcp_bp.route("/scopes/<int:scope_id>/enable", methods=["POST"])
@admin_required
def scope_enable(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    scope.enabled_in_flexedge = True
    db.session.commit()
    _log_activity("scope", "enable", "ok",
                  f"{scope.engine_name}/{scope.interface_id}", scope.subnet_cidr)
    flash(f"Scope {scope.subnet_cidr} enabled.", "success")
    return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))


@dhcp_bp.route("/scopes/<int:scope_id>/disable", methods=["POST"])
@admin_required
def scope_disable(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    scope.enabled_in_flexedge = False
    db.session.commit()
    _log_activity("scope", "disable", "ok",
                  f"{scope.engine_name}/{scope.interface_id}", scope.subnet_cidr)
    flash(f"Scope {scope.subnet_cidr} disabled.", "info")
    return redirect(url_for("dhcp.scopes_list"))


@dhcp_bp.route("/scopes/<int:scope_id>/delete", methods=["POST"])
@admin_required
def scope_delete(scope_id):
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    target = f"{scope.engine_name}/{scope.interface_id}"
    cidr = scope.subnet_cidr
    db.session.delete(scope)
    db.session.commit()
    _log_activity("scope", "delete", "ok", target, cidr)
    flash(f"Scope {cidr} deleted from FlexEdge tracking (SMC is untouched).", "info")
    return redirect(url_for("dhcp.scopes_list"))


@dhcp_bp.route("/scopes/<int:scope_id>")
@admin_required
def scope_detail(scope_id):
    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    # H7 (audit fix-up, 2026-05-09): consume the post-deploy scan_jobs
    # report when the page is reloaded after the watcher polls "done".
    deploy_running = None
    deploy_scan_id = (request.args.get("deploy_scan_id") or "").strip()
    if deploy_scan_id:
        from webapp import dhcp_deploy_jobs
        user_email = (session.get("user") or {}).get("email", "")
        status = dhcp_deploy_jobs.get_status(deploy_scan_id, user_email=user_email)
        if status is None:
            flash("Deploy job not found or expired.", "info")
        elif status["state"] == "running":
            deploy_running = status
        elif status["state"] == "failed":
            flash(f"Deploy worker failed: "
                  f"{status.get('error') or 'unknown error'}", "danger")
            dhcp_deploy_jobs.discard(deploy_scan_id, user_email=user_email)
        else:  # done
            result = dhcp_deploy_jobs.consume_report(
                deploy_scan_id, user_email=user_email,
            )
            action = (status.get("action") or "push")
            target = f"{scope.engine_name}/{scope.interface_id}"
            if result is None:
                flash("Deploy results expired.", "warning")
            elif result.overall_status == "blocked":
                flash(f"Deployment blocked: {result.blocked_reason}", "warning")
                _log_activity("deploy", action, "blocked", target,
                              f"Blocked: {result.blocked_reason}")
            elif result.overall_status == "ok":
                flash(f"Deploy succeeded on all {result.successful_nodes} "
                      f"node(s). Pushed "
                      f"{result.nodes[0].reservations_count if result.nodes else 0}"
                      f" reservation(s).", "success")
                _log_activity("deploy", action, "ok", target,
                              f"OK on {result.successful_nodes}/"
                              f"{len(result.nodes)} nodes.")
            elif result.overall_status == "partial":
                failed = ", ".join(f"node {n.node_index}: {n.error}"
                                   for n in result.nodes if n.status != "ok")
                flash(f"Partial success: {result.successful_nodes}/"
                      f"{len(result.nodes)} nodes pushed. "
                      f"Failures: {failed}", "warning")
                _log_activity("deploy", action, "partial", target,
                              f"Partial: {result.successful_nodes}/"
                              f"{len(result.nodes)} OK. Failures: {failed}")
            else:
                failed = "; ".join(f"node {n.node_index}: {n.error}"
                                   for n in result.nodes) or "no nodes attempted"
                flash(f"Deploy failed on all nodes. {failed}", "danger")
                _log_activity("deploy", action, "failed", target,
                              f"Failed on all nodes: {failed}")
            for n in (result.nodes if result else []):
                if n.reload_warning:
                    flash(f"Node {n.node_index}: dhcpd reload warning — "
                          f"{n.reload_warning}", "warning")

    # M13 (audit fix-up, 2026-05-09): paginate the reservation list.
    # Big scopes can carry hundreds of reservations; the previous .all()
    # rendered every row and a single template iteration on a 1000-row
    # scope was a noticeable hang.
    try:
        page = max(1, int(request.args.get("page") or "1"))
    except ValueError:
        page = 1
    page_size = 50
    res_qry = (DhcpReservation.query
               .filter_by(scope_id=scope.id)
               .order_by(DhcpReservation.ip_address))
    total_reservations = res_qry.count()
    reservations = (res_qry
                    .limit(page_size)
                    .offset((page - 1) * page_size)
                    .all())
    total_pages = max(1, (total_reservations + page_size - 1) // page_size)
    recent_deploys = (DhcpDeployment.query
                      .filter_by(scope_id=scope.id)
                      .order_by(DhcpDeployment.created_at.desc()).limit(10).all())
    return render_template(
        "dhcp/scope_detail.html",
        scope=scope,
        reservations=reservations,
        recent_deploys=recent_deploys,
        deploy_running=deploy_running,
        pagination={
            "page": page,
            "page_size": page_size,
            "total_rows": total_reservations,
            "total_pages": total_pages,
        },
    )


@dhcp_bp.route("/scopes/<int:scope_id>/deploy/status")
@admin_required
def scope_deploy_status(scope_id):
    """JSON poll target for the deploy watcher card."""
    from webapp import dhcp_deploy_jobs
    scan_id = (request.args.get("id") or "").strip()
    user_email = (session.get("user") or {}).get("email", "")
    status = dhcp_deploy_jobs.get_status(scan_id, user_email=user_email)
    if status is None:
        return jsonify({"state": "missing"}), 404
    return jsonify(status)


@dhcp_bp.route("/scopes/<int:scope_id>/sync", methods=["POST"])
@admin_required
def scope_sync_hosts(scope_id):
    """Reconcile DhcpReservation rows with Host elements in SMC for this scope.

    Walks every Host whose address falls inside the scope CIDR, reads the
    MAC marker from the comment, and upserts a DhcpReservation row. Hosts
    without a marker are ignored (they're normal hosts, not reservations).
    Local rows whose Host disappeared are flagged status='error'.
    """
    scope = _scope_or_404(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    # Phase B.3: scope.domain → ApiKey directly (Domain.api_key has the
    # absorbed server fields; _smc_cfg accepts a Domain).
    domain = scope.domain
    if domain is None or domain.api_key is None:
        flash("Scope has no Domain or ApiKey on file. Re-enroll via Admin Portal.", "danger")
        return redirect(url_for("dhcp.scopes_list"))
    cfg = _smc_cfg(domain)
    target = f"{scope.engine_name}/{scope.interface_id} {scope.subnet_cidr}"

    try:
        with smc_session(cfg):
            hosts = host_list_by_scope(scope.subnet_cidr)
        known_names = set()
        added, updated = 0, 0
        for h in hosts:
            if not h.mac_address:
                continue  # not a reservation
            known_names.add(h.name)
            res = DhcpReservation.query.filter_by(
                scope_id=scope.id, smc_host_name=h.name,
            ).first()
            if res:
                changed = (res.ip_address != h.address
                           or res.mac_address != h.mac_address
                           or res.smc_host_href != h.href)
                res.ip_address = h.address
                res.mac_address = h.mac_address
                res.smc_host_href = h.href
                if changed:
                    res.status = "out_of_sync"
                updated += 1
            else:
                db.session.add(DhcpReservation(
                    scope_id=scope.id,
                    smc_host_name=h.name,
                    smc_host_href=h.href,
                    ip_address=h.address,
                    mac_address=h.mac_address,
                    status="out_of_sync",
                ))
                added += 1

        # Stale rows → Host disappeared from SMC
        for res in DhcpReservation.query.filter_by(scope_id=scope.id).all():
            if res.smc_host_name not in known_names:
                res.status = "error"
                res.last_error = "Host no longer present in SMC"

        db.session.commit()
        _log_activity("scope", "sync_hosts", "ok", target,
                      f"added={added}, updated={updated}")
        flash(f"Synced {added + updated} reservation(s) from SMC "
              f"({added} new, {updated} updated).", "success")
    except Exception as exc:
        db.session.rollback()
        _log_activity("scope", "sync_hosts", "failed", target, smc_error_detail(exc))
        flash(f"Sync failed: {exc}", "danger")
    return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))


# ── Reservations (Host CRUD) ─────────────────────────────────────────────

@dhcp_bp.route("/scopes/<int:scope_id>/reservations/new", methods=["GET", "POST"])
@admin_required
def reservation_new(scope_id):
    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    if request.method == "GET":
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=None, host_view=None)

    operator_name = request.form.get("name", "").strip()
    address = request.form["address"].strip()
    mac = request.form["mac_address"].strip()
    ipv6 = request.form.get("ipv6_address", "").strip()
    secondary_raw = request.form.get("secondary", "").strip()
    secondary = [s.strip() for s in secondary_raw.split(",") if s.strip()]
    comment = request.form.get("comment", "").strip()
    tools_profile_ref = request.form.get("tools_profile_ref", "").strip()

    # Q16 (Round 3) — derive the SMC Host name from scope context if the
    # operator left the field blank. Operator overrides honored.
    from webapp.dhcp_reservation_queue import (
        derive_smc_host_name, enqueue_reservation_create,
        try_auto_push_for_admins,
    )
    name = derive_smc_host_name(scope, address, operator_name)

    # Validation (same rules as before; uses the derived name).
    errors = _validate_reservation(scope, name, address, mac, ipv6, secondary,
                                   exclude_reservation_id=None)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template(
            "dhcp/reservation_form.html",
            scope=scope, reservation=None, host_view=None,
            form_values=request.form,
        )

    mac_norm = normalize_mac(mac)
    domain = scope.domain
    if domain is None or domain.api_key is None:
        flash("Scope has no Domain or ApiKey on file. Re-enroll via Admin Portal.", "danger")
        return redirect(url_for("dhcp.scopes_list"))
    target = f"{scope.engine_name}/{scope.interface_id}/{name}"

    # Phase E.2 — enqueue instead of immediate SMC write.
    # 1. Create DhcpReservation in 'queued' state (no SMC backing yet).
    # 2. Enqueue PendingChange(operation='create', smc_type='host').
    # 3. Auto-push if user is Domain Admin or higher (Q15/a).
    try:
        res = DhcpReservation(
            scope_id=scope.id,
            smc_host_name=name,
            smc_host_href="",        # filled in by the queue handler on push
            ip_address=address,
            mac_address=mac_norm,
            status="queued",
        )
        db.session.add(res)
        db.session.flush()           # need res.id for source_correlation_id

        change = enqueue_reservation_create(
            scope=scope, reservation=res,
            name=name, address=address, mac_address=mac_norm,
            ipv6_address=ipv6, secondary=secondary,
            tools_profile_ref=tools_profile_ref, comment=comment,
        )
    except Exception as exc:
        db.session.rollback()
        _log_activity("reservation", "create", "failed", target, smc_error_detail(exc))
        flash(f"Could not queue reservation: {exc}", "danger")
        return render_template(
            "dhcp/reservation_form.html",
            scope=scope, reservation=None, host_view=None,
            form_values=request.form,
        )

    # Try inline push for admins; Operators stay queued.
    outcome = try_auto_push_for_admins(change, res)

    if outcome == "pushed":
        _log_activity("reservation", "create", "ok", target,
                      f"MAC={mac_norm} IP={address} via_queue=True auto_pushed=True")
        flash(f"Reservation {name} created.", "success")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    if outcome == "push_failed":
        _log_activity("reservation", "create", "failed", target,
                      f"queued+pushed: {res.last_error}")
        flash(f"SMC rejected the create — {res.last_error}. "
              f"The reservation is on the scope page in 'push-failed' state; "
              f"click Retry there once you've addressed the cause.",
              "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    # outcome == 'queued' — Operator path
    _log_activity("reservation", "create.queued", "ok", target,
                  f"MAC={mac_norm} IP={address} change_id={change.id}")
    flash(f"Reservation {name} queued. Visit the Change Queue to push it.",
          "info")
    return redirect(url_for("changes.index",
                            source=f"dhcp_reservation:{res.id}"))


@dhcp_bp.route("/reservations/<int:reservation_id>/edit", methods=["GET", "POST"])
@admin_required
def reservation_edit(reservation_id):
    res = db.session.get(DhcpReservation, reservation_id)
    if not res:
        flash("Reservation not found.", "danger")
        return redirect(url_for("dhcp.scopes_list"))
    scope = _scope_with_creds_or_redirect(res.scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))
    domain = scope.domain
    if domain is None or domain.api_key is None:
        flash("Scope has no Domain or ApiKey on file. Re-enroll via Admin Portal.", "danger")
        return redirect(url_for("dhcp.scopes_list"))
    cfg = _smc_cfg(domain)
    # `domain_objects.dhcp_host` needs the DICT-shaped cfg (smc_client backend).
    cfg_dict = _smc_cfg_dict(domain)

    # Read the live SMC Host (if it exists yet) so the form pre-fills with
    # current values. For 'queued' reservations the Host doesn't exist —
    # we synthesize a host_view from the cached payload of the queued
    # change so the form still pre-fills. Cache-backed via the shared
    # ``dhcp_host`` section (Quick 1h, queue-runner-invalidated on edit).
    host_view = None
    if res.smc_host_href:
        try:
            from webapp import domain_objects
            host_view, _cv = domain_objects.dhcp_host(
                domain, cfg_dict, res.smc_host_name)
        except Exception as exc:
            flash(f"Could not read Host from SMC: {exc}", "warning")

    if request.method == "GET":
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=res, host_view=host_view)

    address = request.form["address"].strip()
    mac = request.form["mac_address"].strip()
    ipv6 = request.form.get("ipv6_address", "").strip()
    secondary_raw = request.form.get("secondary", "").strip()
    secondary = [s.strip() for s in secondary_raw.split(",") if s.strip()]
    comment = request.form.get("comment", "").strip()
    tools_profile_ref = request.form.get("tools_profile_ref", "").strip()

    errors = _validate_reservation(scope, res.smc_host_name, address, mac,
                                   ipv6, secondary,
                                   exclude_reservation_id=res.id)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=res, host_view=host_view,
                               form_values=request.form)

    mac_norm = normalize_mac(mac)
    target = f"{scope.engine_name}/{scope.interface_id}/{res.smc_host_name}"
    previous_ip = res.ip_address

    # Phase E.2 — enqueue an `update` (or mutate the in-flight `create`
    # payload if the reservation hasn't pushed yet, per Q16/a).
    from webapp.dhcp_reservation_queue import (
        enqueue_reservation_update, try_auto_push_for_admins,
    )
    try:
        change = enqueue_reservation_update(
            reservation=res,
            address=address, mac_address=mac_norm,
            ipv6_address=ipv6, secondary=secondary,
            tools_profile_ref=tools_profile_ref, comment=comment,
            previous_address=previous_ip,
        )
        # Reflect new draft values in our cache while queued (so the
        # listing shows the operator's intent).
        res.ip_address = address
        res.mac_address = mac_norm
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        _log_activity("reservation", "update", "failed", target, smc_error_detail(exc))
        flash(f"Could not queue update: {exc}", "danger")
        return render_template("dhcp/reservation_form.html",
                               scope=scope, reservation=res, host_view=host_view,
                               form_values=request.form)

    outcome = try_auto_push_for_admins(change, res)

    if outcome == "pushed":
        # On successful push, mark as out-of-sync so the operator knows
        # to redeploy to engines (Phase 4 stays out-of-queue per Q18).
        res.status = "out_of_sync"
        db.session.commit()
        _log_activity("reservation", "update", "ok", target,
                      f"MAC={mac_norm} IP={address} via_queue=True auto_pushed=True")
        flash(f"Reservation {res.smc_host_name} updated.", "success")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    if outcome == "push_failed":
        _log_activity("reservation", "update", "failed", target,
                      f"queued+pushed: {res.last_error}")
        flash(f"SMC rejected the update — {res.last_error}. "
              f"Retry from the scope page once you've addressed the cause.",
              "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    # outcome == 'queued' — Operator path
    _log_activity("reservation", "update.queued", "ok", target,
                  f"MAC={mac_norm} IP={address} change_id={change.id}")
    flash(f"Update for {res.smc_host_name} queued. Visit the Change Queue to push it.",
          "info")
    return redirect(url_for("changes.index",
                            source=f"dhcp_reservation:{res.id}"))


@dhcp_bp.route("/scopes/<int:scope_id>/reservations/bulk-delete", methods=["POST"])
@admin_required
def reservations_bulk_delete(scope_id):
    """Delete multiple reservations from a scope in one shot.

    Form fields:
      * `reservation_id` — repeated checkbox, one per row to delete.
      * `delete_host` — present if the SMC Host element should also be
        removed. Applied to every selected reservation.

    Phase E.2 — SMC Host deletes go through the queue (one PendingChange
    row per reservation, all with the same `source_correlation_id` so
    the operator can see them grouped on `/changes/`). Domain Admin and
    above push the batch with halt-on-failure (`push_batch`); Operators
    submit `to_be_deleted` rows that wait for Global Admin Confirm.
    DB-only deletes (operator unticks "also delete SMC Host") still run
    immediately — no SMC mutation, no queue.
    """
    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    raw_ids = request.form.getlist("reservation_id")
    try:
        ids = sorted({int(x) for x in raw_ids if x})
    except ValueError:
        flash("Bad form: reservation_id must be integer.", "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))
    if not ids:
        flash("Pick at least one reservation to delete.", "warning")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    also_delete_hosts = bool(request.form.get("delete_host"))

    rows = (DhcpReservation.query
            .filter(DhcpReservation.id.in_(ids),
                    DhcpReservation.scope_id == scope_id)
            .all())
    if not rows:
        flash("None of the selected reservations exist on this scope.", "warning")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    # DB-only path — operator unticked "also delete SMC Host". No queue
    # involved; just drop our DB rows. SMC Hosts stay in place.
    if not also_delete_hosts:
        deleted = 0
        for r in rows:
            target = f"{scope.engine_name}/{scope.interface_id}/{r.smc_host_name}"
            # If a queued change is in flight, abort it too.
            if r.pending_change_id:
                try:
                    from shared.queue_runner import abort_one
                    abort_one(r.pending_change_id, "bulk DB-only delete")
                except Exception:
                    pass
            db.session.delete(r)
            deleted += 1
            _log_activity("reservation", "delete", "ok", target,
                          "host_deleted=False via_bulk=True db_only=True")
        db.session.commit()
        flash(f"Deleted {deleted} reservation(s). SMC Host elements left in place "
              f"(tick 'Also delete SMC Host' to remove them too).", "success")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    # Queue path — operator wants the SMC Hosts deleted too.
    domain = scope.domain
    if domain is None or domain.api_key is None:
        flash("Scope has no Domain on file — cannot enqueue Host deletes. "
              "Fix the Domain assignment in Admin Portal.", "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    from webapp.dhcp_reservation_queue import enqueue_reservation_delete
    try:
        from webapp.auth_roles import is_domain_admin
        is_admin = is_domain_admin()
    except Exception:
        is_admin = False
    operation = "delete" if is_admin else "to_be_deleted"

    # Pre-pass: classify rows into (queued-but-unpushed) and (live in SMC).
    # Queued-but-unpushed rows skip the SMC delete entirely — abort their
    # in-flight create + drop the DB row + queue row in one shot.
    queued_unpushed = [r for r in rows if not r.smc_host_href]
    live = [r for r in rows if r.smc_host_href]

    aborted_count = 0
    for r in queued_unpushed:
        if r.pending_change_id:
            try:
                from shared.queue_runner import abort_one
                abort_one(r.pending_change_id, "bulk delete before push")
            except Exception:
                pass
        db.session.delete(r)
        aborted_count += 1
    if aborted_count:
        db.session.commit()

    if not live:
        flash(f"Aborted {aborted_count} queued reservation(s) before push.",
              "info")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    # Enqueue one delete change per live reservation, all sharing a
    # batch correlation id so the operator sees them grouped on /changes/.
    import secrets
    batch_corr = f"dhcp_reservation_bulk:{scope.id}:{secrets.token_hex(4)}"
    change_ids = []
    enqueue_failures = 0
    for r in live:
        try:
            change = enqueue_reservation_delete(reservation=r, operation=operation)
            # Override the per-row correlation with the bulk batch id so
            # /changes/?source=<batch_corr> shows the whole group.
            change.source_correlation_id = batch_corr
            db.session.commit()
            change_ids.append(change.id)
        except Exception as exc:
            enqueue_failures += 1
            log.exception("Bulk delete: enqueue failed for reservation #%s: %s",
                          r.id, exc)

    if not change_ids:
        flash("Could not enqueue any delete — see logs.", "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    # Operator path — leave them queued for Global Admin to Confirm.
    if not is_admin:
        flash(f"Submitted {len(change_ids)} delete request(s). They show "
              f"struck-through in listings until a Global Admin Confirms each "
              f"from the Change Queue.", "info")
        return redirect(url_for("changes.index", source=batch_corr))

    # Admin path — push the whole batch with halt-on-failure (Q4).
    from shared.queue_runner import push_batch
    result = push_batch(change_ids)

    # Sweep DB rows for the changes that successfully pushed.
    pushed_change_ids = {r.change_id for r in result.results
                         if r.success and r.change_id is not None}
    db_deleted = 0
    for r in live:
        if r.pending_change_id is None:
            # push_one cleared it → success; remove the DB row.
            db.session.delete(r)
            db_deleted += 1
        elif r.pending_change_id in pushed_change_ids:
            # Belt-and-braces — success path normally clears the FK.
            db.session.delete(r)
            db_deleted += 1
    db.session.commit()

    target_summary = f"{scope.engine_name}/{scope.interface_id}"
    detail = (f"requested={len(live)} pushed={result.applied + result.pushed} "
              f"failed={result.failed} skipped={result.skipped} "
              f"halted_at={result.halted_at} db_deleted={db_deleted} "
              f"db_aborted_unpushed={aborted_count}")
    _log_activity("reservation", "delete.bulk", "ok" if result.failed == 0 else "partial",
                  target_summary, detail)

    if result.failed == 0 and aborted_count == 0:
        flash(f"Deleted {db_deleted} reservation(s) (Hosts removed from SMC, batch=`{batch_corr}`).",
              "success")
    elif result.failed == 0:
        flash(f"Deleted {db_deleted} live reservation(s) + aborted "
              f"{aborted_count} queued. Batch={batch_corr}.", "success")
    else:
        flash(f"Bulk delete halted at change #{result.halted_at}: "
              f"{result.aborted_after_halt} row(s) left QUEUED. "
              f"Pushed={db_deleted}, aborted-unpushed={aborted_count}. "
              f"Resume from /changes/?source={batch_corr}.", "warning")

    return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))


@dhcp_bp.route("/reservations/<int:reservation_id>/delete", methods=["POST"])
@admin_required
def reservation_delete(reservation_id):
    res = db.session.get(DhcpReservation, reservation_id)
    if not res:
        flash("Reservation not found.", "danger")
        return redirect(url_for("dhcp.scopes_list"))

    scope_id = res.scope_id
    scope = res.scope
    domain = scope.domain
    if domain is None or domain.api_key is None:
        flash("Scope has no Domain or ApiKey on file. Re-enroll via Admin Portal.", "danger")
        return redirect(url_for("dhcp.scopes_list"))

    also_delete_host = bool(request.form.get("delete_host"))
    target = f"{scope.engine_name}/{scope.interface_id}/{res.smc_host_name}"

    # If the operator unchecked "also delete SMC Host", we keep the SMC
    # element and only drop our DB row (DB-only cleanup — no queue needed).
    if not also_delete_host:
        db.session.delete(res)
        db.session.commit()
        _log_activity("reservation", "delete", "ok", target,
                      "host_deleted=False db_only=True")
        flash(f"Reservation removed from FlexEdgeAdmin. SMC Host "
              f"{res.smc_host_name} kept in place.", "info")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    # Operator wants the SMC Host deleted too — go through the queue.
    # Phase E.2 + Q12 + Q15: Operators submit `to_be_deleted` (awaits
    # Global Admin Confirm); Domain Admin+ submits `delete` and auto-pushes.
    from webapp.dhcp_reservation_queue import (
        enqueue_reservation_delete, try_auto_push_for_admins,
    )
    try:
        from webapp.auth_roles import is_domain_admin
        operation = "delete" if is_domain_admin() else "to_be_deleted"
    except Exception:
        operation = "to_be_deleted"

    # If the reservation was still queued (never pushed to SMC), an
    # SMC-side delete makes no sense — the Host doesn't exist there.
    # Just drop the queue row + DB row.
    if not res.smc_host_href:
        if res.pending_change_id:
            from webapp.models import PendingChange
            from shared.queue_runner import abort_one
            abort_one(res.pending_change_id, "reservation deleted before push")
        db.session.delete(res)
        db.session.commit()
        _log_activity("reservation", "delete", "ok", target,
                      "queued_unpushed=True db+queue_only")
        flash(f"Queued reservation {res.smc_host_name} aborted before push.",
              "info")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    try:
        change = enqueue_reservation_delete(reservation=res, operation=operation)
    except Exception as exc:
        db.session.rollback()
        _log_activity("reservation", "delete", "failed", target,
                      f"queue insert failed: {exc}")
        flash(f"Could not queue delete: {exc}", "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    outcome = try_auto_push_for_admins(change, res)

    if outcome == "pushed":
        # Admin path — Host is gone from SMC; remove the DB row too.
        db.session.delete(res)
        db.session.commit()
        _log_activity("reservation", "delete", "ok", target,
                      "host_deleted=True via_queue=True auto_pushed=True")
        flash(f"Reservation {res.smc_host_name} deleted (Host removed from SMC).",
              "success")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    if outcome == "push_failed":
        _log_activity("reservation", "delete", "failed", target,
                      f"queued+pushed: {res.last_error}")
        flash(f"SMC rejected the delete — {res.last_error}. "
              f"Retry from the scope page or the Change Queue.", "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope_id))

    if outcome == "pending_confirm":
        # Operator-submitted `to_be_deleted` — Global Admin must confirm.
        # The reservation row stays visible (with strikethrough via Q12)
        # until confirmed.
        _log_activity("reservation", "to_be_deleted", "ok", target,
                      f"change_id={change.id} awaiting_global_admin_confirm")
        flash(f"Delete of {res.smc_host_name} submitted. A Global Admin "
              f"needs to Confirm it from the Change Queue before the SMC "
              f"Host is removed. The reservation is shown struck-through "
              f"in listings until then.", "info")
        return redirect(url_for("changes.index",
                                source=f"dhcp_reservation:{res.id}"))

    # outcome == 'queued' — shouldn't happen for delete (Operator hits
    # `pending_confirm`, Admin auto-pushes). Defensive fallback.
    flash(f"Delete queued. Visit the Change Queue to push.", "info")
    return redirect(url_for("changes.index",
                            source=f"dhcp_reservation:{res.id}"))


@dhcp_bp.route("/reservations/<int:reservation_id>/retry-push", methods=["POST"])
@admin_required
def reservation_retry_push(reservation_id):
    """Retry a `push_failed` reservation's queued change (Q17/b).

    Re-invokes `push_one()` on the same `pending_changes` row. On
    success: reservation transitions queued → pending; pending_change_id
    cleared. On repeat failure: last_error refreshed.
    """
    res = db.session.get(DhcpReservation, reservation_id)
    if not res:
        flash("Reservation not found.", "danger")
        return redirect(url_for("dhcp.scopes_list"))
    if not res.pending_change_id:
        flash("Nothing to retry — this reservation has no pending change.",
              "warning")
        return redirect(url_for("dhcp.scope_detail", scope_id=res.scope_id))

    from webapp.models import PendingChange
    change = db.session.get(PendingChange, res.pending_change_id)
    if change is None:
        flash("Pending change is gone — clearing the link.", "warning")
        res.pending_change_id = None
        res.status = "error"
        db.session.commit()
        return redirect(url_for("dhcp.scope_detail", scope_id=res.scope_id))

    if change.state == "push_failed":
        # Reset to queued so push_one can pick it up again.
        change.state = "queued"
        change.push_error_text = ""
        change.push_error_at = None
        db.session.commit()

    from webapp.dhcp_reservation_queue import try_auto_push_for_admins
    target = f"{res.scope.engine_name}/{res.scope.interface_id}/{res.smc_host_name}"
    outcome = try_auto_push_for_admins(change, res)

    if outcome == "pushed":
        if change.operation == "delete":
            db.session.delete(res)
            db.session.commit()
            flash(f"Reservation {target} deleted on retry.", "success")
        else:
            if change.operation == "update":
                res.status = "out_of_sync"
                db.session.commit()
            flash(f"Reservation {res.smc_host_name} pushed on retry.",
                  "success")
        _log_activity("reservation", f"{change.operation}.retry", "ok",
                      target, f"change_id={change.id}")
    elif outcome == "push_failed":
        flash(f"Retry failed — {res.last_error}", "danger")
        _log_activity("reservation", f"{change.operation}.retry", "failed",
                      target, res.last_error)
    else:
        flash(f"Retry queued (no admin role; awaiting push from /changes/).",
              "info")

    return redirect(url_for("dhcp.scope_detail", scope_id=res.scope_id))


# ── Deploy / Preview ───────────────────────────────────────────────────

@dhcp_bp.route("/scopes/<int:scope_id>/deploy", methods=["POST"])
@admin_required
def scope_deploy(scope_id):
    return _run_push(scope_id, action="push")


@dhcp_bp.route("/scopes/<int:scope_id>/resync", methods=["POST"])
@admin_required
def scope_resync(scope_id):
    """Manual re-sync button.

    Per operator preference (Phase 3 plan question 3), the sync loop is
    operator-triggered via this button instead of a post-policy-upload
    webhook. Phase 4 — same path as deploy, just a different audit action.
    """
    return _run_push(scope_id, action="resync")


@dhcp_bp.route("/scopes/<int:scope_id>/preview", methods=["POST"])
@admin_required
def scope_preview(scope_id):
    """Dry-run a deploy: render + diff per node, but don't write.

    Renders the same per-node sha256 + unified diff as a real deploy
    would produce, persists DhcpDeployment audit rows with action="dry_run",
    and renders a preview page that the operator confirms BEFORE clicking
    the real Deploy button. Reservation row status is not mutated.

    Bypasses the Phase 0 gate (preview never writes the file). Still
    requires verified credentials and an installed SSH rule.
    """
    from webapp.dhcp_pusher import preview_scope

    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    target = f"{scope.engine_name}/{scope.interface_id}"
    operator = _operator_email()

    _log_activity("deploy", "dry_run", "info", target,
                  f"Preview starting for scope {scope.id}.")

    try:
        result = preview_scope(scope.id, operator)
    except Exception as exc:
        _log_activity("deploy", "dry_run", "failed", target, str(exc))
        flash(f"Preview failed: {exc}", "danger")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    if result.overall_status == "blocked":
        flash(f"Preview blocked: {result.blocked_reason}", "warning")
        _log_activity("deploy", "dry_run", "blocked", target,
                      f"Blocked: {result.blocked_reason}")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    _log_activity("deploy", "dry_run", "ok", target,
                  f"Preview ok on {result.successful_nodes}/{len(result.nodes)} nodes.")
    return render_template(
        "dhcp/scope_preview.html",
        scope=scope,
        result=result,
        phase0_validated=is_phase0_validated(),
    )


def _run_push(scope_id: int, action: str):
    """Shared deploy/resync handler — spawns a background scan_jobs runner.

    H7 (audit fix-up, 2026-05-09): the synchronous version blocked the
    request thread for 30-60s on a 5-node cluster, with worst-case
    2x-multiplied latency from the SMC global lock contention. Now
    spawns a daemon thread via `webapp.dhcp_deploy_jobs.start_deploy`
    and redirects to `scope_detail?deploy_scan_id=X`. The detail page
    renders a watcher card that polls /dhcp/scopes/<id>/deploy/status
    and reloads when the job is done.
    """
    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    target = f"{scope.engine_name}/{scope.interface_id}"
    operator = _operator_email()

    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=scope.domain_id,
                        engine_name=scope.engine_name)
             .all())
    if not creds:
        flash("No SSH credentials enrolled — cannot deploy.", "warning")
        _log_activity("deploy", action, "blocked", target,
                      "No credentials enrolled")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    _log_activity("deploy", action, "info", target,
                  f"{action.capitalize()} starting for scope {scope.id}.")

    from webapp.dhcp_deploy_jobs import start_deploy
    try:
        scan_id = start_deploy(
            scope_id=scope.id,
            engine_name=scope.engine_name,
            action=action,
            operator_email=operator,
            total_nodes=len(creds),
        )
    except Exception as exc:
        log.exception("scope_deploy: failed to spawn job")
        flash(f"Deploy failed to start: {exc}", "danger")
        _log_activity("deploy", action, "failed", target,
                      f"Spawn failed: {exc}")
        return redirect(url_for("dhcp.scope_detail", scope_id=scope.id))

    return redirect(url_for("dhcp.scope_detail",
                            scope_id=scope.id, deploy_scan_id=scan_id))


# ── SSH credentials (Phase 1c — auto-enrollment via SMC API) ────────────

def _cred_to_target(cred_row: DhcpEngineCredential) -> SSHTarget:
    # P1: delegate to the centralised helper so the connect_ip_override
    # is honored. `hostname` on the row stays the engine's real
    # interface IP — what the SMC rule's destination Host matches.
    from webapp.dhcp_ssh import target_from_credential
    return target_from_credential(cred_row)


def _cred_to_payload(cred_row: DhcpEngineCredential) -> SSHCredential:
    return SSHCredential(
        password=cred_row.encrypted_password,
        host_fingerprint=cred_row.host_fingerprint,
    )


def _operator_email() -> str:
    return (session.get("user") or {}).get("email", "")


def _audit_comment(action: str, engine_name: str = "") -> str:
    op = _operator_email() or "unknown"
    suffix = f" engine={engine_name}" if engine_name else ""
    return f"FlexEdgeAdmin {action} by {op}{suffix}"


def _validate_connect_ip_override(raw) -> str:
    """Return a clean IPv4 string, or "" if the input is missing/invalid.

    P1 (2026-05-12). The credentials wizard submits this from a
    dropdown of public contact addresses we ourselves discovered, but
    the form value is operator-controlled so we re-validate
    defensively before storing it. Empty / whitespace / bad shape →
    "" (= no override; today's behavior).

    IPv4 only for now. IPv6 NAT exit support can extend this later
    by widening `ip_address` to `ip_address(...)` and accepting any
    version, but the storage column is sized for IPv4.
    """
    if not raw:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    try:
        from ipaddress import IPv4Address
        return str(IPv4Address(s))
    except (ValueError, TypeError):
        log.warning("connect_ip_override refused: not a valid IPv4: %r", s)
        return ""


def _bump_access_refreshed(tenant_id: int, engine_name: str,
                           when=None, *, domain_id: int | None = None) -> None:
    """Convenience: stamp the access row's state_refreshed_at if present.

    Phase B.3: domain_id is canonical. The tenant_id positional kept
    for caller-signature stability but only used as a fallback to
    resolve a domain via the tenant's api_keys when domain_id is None
    (rare — every callsite now passes it explicitly).
    """
    when = when or datetime.now(timezone.utc)
    if domain_id is None:
        # Resolve from tenant — pick the first matching access row across
        # all the tenant's domains.
        candidate_dids = _domain_ids_for_tenant(tenant_id)
        if not candidate_dids:
            return
        q = (DhcpEngineSshAccess.query
             .filter(DhcpEngineSshAccess.domain_id.in_(candidate_dids),
                     DhcpEngineSshAccess.engine_name == engine_name))
    else:
        q = DhcpEngineSshAccess.query.filter_by(
            domain_id=domain_id, engine_name=engine_name,
        )
    a = q.first()
    if a:
        a.state_refreshed_at = when
        a.last_seen_in_policy_at = when


@dhcp_bp.route("/credentials", methods=["GET"])
@admin_required
def credentials_list():
    from webapp.engine_credentials import get_engine_freshness, CACHE_TTL_HOURS

    domain_id = _active_domain_id()
    if domain_id is None:
        creds, accesses = [], []
    else:
        # M7 (audit fix-up, 2026-05-09): eager-load Domain → ApiKey on
        # accesses. Without this, the source-IP drift loop below does
        # one lazy SELECT per access row for `access.domain.api_key` —
        # N+1 on a multi-engine Domain.
        from sqlalchemy.orm import joinedload
        creds = (DhcpEngineCredential.query
                 .filter_by(domain_id=domain_id)
                 .order_by(DhcpEngineCredential.engine_name,
                           DhcpEngineCredential.node_index).all())
        accesses = (DhcpEngineSshAccess.query
                    .options(joinedload(DhcpEngineSshAccess.domain)
                             .joinedload(Domain.api_key))
                    .filter_by(domain_id=domain_id)
                    .order_by(DhcpEngineSshAccess.engine_name).all())
    # Domain-Scoping fix: the credentials wizard only ever needs the ONE
    # Tenant bound to the active Domain's API key — the dropdown that
    # used to list every Tenant in the deployment was a leak of other
    # Domains' infrastructure into this view. Narrow to that one row;
    # the template's existing `{% for t in tenants %}` loops then
    # render exactly one option, the cascade auto-selects it, and
    # cross-Domain pivoting via this picker is impossible.
    domain_obj = getattr(g, "domain", None)
    bound_tenant_id = (domain_obj.api_key.tenant_id
                       if domain_obj is not None and domain_obj.api_key is not None
                       else None)
    if bound_tenant_id is None:
        tenants = []
    else:
        tenants = (Tenant.query
                   .filter_by(id=bound_tenant_id, is_active=True)
                   .all())
    tenants_by_id = {t.id: t for t in tenants}
    # Operator-facing label override — the dropdown / source-IP table
    # show the active *Domain* identity instead of the bound Tenant
    # name. Reason: when the admin form's "find-or-create on smc_url"
    # reuses an existing Tenant (i.e. when several Domains live on one
    # Forcepoint SMC instance), the dropdown otherwise renders the
    # reused Tenant's name and operators mistake it for the wrong
    # Domain — they expect the value to match the topbar selector.
    # The form's hidden tenant_id value stays unchanged, so the AJAX
    # cascade keeps working.
    domain_label = ""
    domain_smc = ""
    if domain_obj is not None:
        domain_label = (domain_obj.display_name
                        or domain_obj.slug
                        or f"domain#{domain_obj.id}")
        domain_smc = domain_obj.smc_domain_name or ""
    # Phase B.3: group credentials by (domain_id, engine) — the canonical
    # scope FK on every feature row.
    creds_by_engine: dict[tuple[int, str], list] = {}
    for c in creds:
        creds_by_engine.setdefault((c.domain_id, c.engine_name), []).append(c)
    accesses_by_engine = {(a.domain_id, a.engine_name): a for a in accesses}
    # Cache-freshness per engine, indexed by the same key.
    freshness_by_engine = {
        key: get_engine_freshness(key[0], key[1])
        for key in creds_by_engine.keys()
    }
    # Source-IP drift detection — flag any engine whose installed rule
    # was created against a source IP that no longer matches the tenant's
    # current `flexedge_source_ip`. Renders a per-engine warning so the
    # operator can re-install the rule (which will now create a NEW rule
    # for the new source instead of mutating the old one).
    source_drift_by_engine = {}
    for key, access in accesses_by_engine.items():
        # Phase B.3: flexedge_source_ip lives on the ApiKey now (Phase A
        # absorbed it from Tenant). Read via the Domain → ApiKey path.
        ak = access.domain.api_key if access.domain else None
        if ak is None:
            continue
        current = (ak.flexedge_source_ip or "").strip()
        installed = (access.fea_source_ip or "").strip()
        if current and installed and current != installed:
            source_drift_by_engine[key] = {
                "rule_source": installed,
                "tenant_source": current,
            }
    return render_template(
        "dhcp/credentials.html",
        credentials=creds,
        creds_by_engine=creds_by_engine,
        accesses_by_engine=accesses_by_engine,
        freshness_by_engine=freshness_by_engine,
        source_drift_by_engine=source_drift_by_engine,
        cache_ttl_hours=CACHE_TTL_HOURS,
        tenants=tenants,
        domain_label=domain_label,
        domain_smc=domain_smc,
    )


@dhcp_bp.route("/credentials/refresh", methods=["POST"])
@admin_required
def credentials_refresh():
    """Run the live state probe (SMC rule + SSH per node) for one engine.

    Two response shapes:

      * **AJAX** (``Accept: application/json`` or ``X-Requested-With:
        XMLHttpRequest``): JSON report. The browser updates the badge
        and renders the per-node + rule findings inline, **without
        reloading the page** — so any wizard state in Card 2 stays put.
      * **Form POST** (no JS / fallback): old redirect-with-flash path.

    Updates ``state_refreshed_at`` on every component that verified ok;
    leaves it stale on those that didn't, so the UI keeps the operator
    pointed at unfixed problems.
    """
    from webapp.engine_credentials import (
        refresh_engine_state, get_engine_freshness, CACHE_TTL_HOURS,
    )

    wants_json = _wants_json_response()

    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale

    try:
        tenant_id = int(request.form["tenant_id"])
    except (KeyError, ValueError):
        if wants_json:
            return jsonify(ok=False, error="tenant_id missing or invalid"), 400
        flash("Bad form: tenant_id missing or invalid.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    engine_name = (request.form.get("engine_name") or "").strip()
    if not engine_name:
        if wants_json:
            return jsonify(ok=False, error="engine_name missing"), 400
        flash("Bad form: engine_name missing.", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    # Phase B.3-prep: helpers take domain_id. Resolve from the form's
    # tenant_id+api_key_id pair (form still posts the cascade, refactored
    # along with the form during B.3 final cleanup).
    api_key_id_form = request.form.get("api_key_id")
    if api_key_id_form:
        domain_id = _domain_id_for_form(tenant_id, int(api_key_id_form))
    else:
        # Fallback: pick any Domain whose api_key belongs to this tenant.
        d = (Domain.query.join(ApiKey)
                         .filter(ApiKey.tenant_id == tenant_id)
                         .order_by(Domain.id).first())
        domain_id = d.id if d else None
    if domain_id is None:
        msg = (f"No Domain resolved for tenant {tenant_id}. "
               f"Run the multi-domain migration or assign a Domain to this tenant.")
        if wants_json:
            return jsonify(ok=False, error=msg), 400
        flash(msg, "danger")
        return redirect(url_for("dhcp.credentials_list"))

    target_label = engine_name
    try:
        report = refresh_engine_state(domain_id, engine_name)
    except Exception as exc:
        _log_activity("ssh", "refresh_state", "failed", target_label, str(exc))
        msg = f"State refresh failed: {type(exc).__name__}: {exc}"
        if wants_json:
            return jsonify(ok=False, error=msg), 500
        flash(msg, "danger")
        return redirect(url_for("dhcp.credentials_list"))

    if report.fatal_error:
        _log_activity("ssh", "refresh_state", "failed", target_label,
                      report.fatal_error)
        if wants_json:
            return jsonify(ok=False, error=report.fatal_error), 400
        flash(f"State refresh aborted: {report.fatal_error}", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    ok_nodes = sum(1 for n in report.nodes if n.tcp_ok and n.auth_ok)
    rule_ok = bool(report.rule and report.rule.rule_present_in_smc
                   and not report.rule_drift_messages)
    log_status = ("ok" if report.all_ok
                  else ("partial" if (ok_nodes or rule_ok) else "failed"))
    _log_activity("ssh", "refresh_state", log_status, target_label,
                  f"rule_ok={int(rule_ok)} nodes_ok={ok_nodes}/{len(report.nodes)}")

    if wants_json:
        # Recompute freshness so the client gets the post-refresh badge state
        # without needing its own clock skew assumptions.
        fresh = get_engine_freshness(domain_id, engine_name)
        return jsonify(
            ok=True,
            tenant_id=tenant_id,
            engine_name=engine_name,
            all_ok=report.all_ok,
            cache_ttl_hours=CACHE_TTL_HOURS,
            rule={
                "rule_name": report.rule.rule_name if report.rule else "",
                "rule_present_in_smc": (report.rule.rule_present_in_smc
                                        if report.rule else False),
                "expected_destinations": (report.rule.expected_destinations
                                          if report.rule else []),
                "actual_destinations": (report.rule.actual_destinations
                                        if report.rule else []),
                "error": report.rule.error if report.rule else "",
            },
            nodes=[{
                "node_index": n.node_index,
                "hostname": n.hostname,
                "tcp_ok": n.tcp_ok,
                "auth_ok": n.auth_ok,
                "error": n.error,
                "fingerprint_match": n.fingerprint_match,
            } for n in report.nodes],
            rule_drift_messages=report.rule_drift_messages,
            node_drift_messages=report.node_drift_messages,
            freshness={
                "age_hours": (None if fresh.age_hours is None
                              else round(fresh.age_hours, 2)),
                "is_fresh": fresh.is_fresh,
                "is_amber": fresh.is_amber,
                "is_stale_24h": fresh.is_stale_24h,
                "is_never": fresh.age_hours is None,
            },
        )

    # Non-AJAX fallback: redirect with flashes, exactly the old path.
    for msg in report.rule_drift_messages:
        flash(msg, "warning")
    for msg in report.node_drift_messages:
        flash(msg, "warning")
    if report.all_ok:
        flash(f"State refresh ok — rule + all {len(report.nodes)} node(s) "
              f"verified for {engine_name}.", "success")
    return redirect(url_for("dhcp.credentials_list"))


# ── Source-IP detection ────────────────────────────────────────────────

@dhcp_bp.route("/credentials/source-ip/probe", methods=["POST"])
@admin_required
def credentials_probe_source_ip():
    """AJAX: try public-IP echo services and return the suggestion +
    attempt log so the operator can see what we tried."""
    detected, log_lines = probe_public_ip()
    return jsonify({"detected": detected or "", "attempts": log_lines})


@dhcp_bp.route("/tenants/<int:tenant_id>/source-ip", methods=["POST"])
@admin_required
def tenant_save_source_ip(tenant_id):
    tenant = db.session.get(Tenant, tenant_id)
    if not tenant:
        flash("Tenant not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    new_ip = request.form.get("source_ip", "").strip()
    if new_ip:
        # Validate
        from ipaddress import ip_address
        try:
            ip_address(new_ip)
        except ValueError:
            flash(f"Invalid IP {new_ip!r}.", "danger")
            return redirect(url_for("dhcp.credentials_list"))
    tenant.flexedge_source_ip = new_ip
    db.session.commit()
    _log_activity("system", "set_source_ip", "ok", tenant.name,
                  f"flexedge_source_ip={new_ip!r}")
    flash(f"Saved FEA source IP for {tenant.name}: {new_ip or '(empty)'}", "success")
    return redirect(url_for("dhcp.credentials_list"))


# ── Discover nodes (cascade to populate the wizard) ────────────────────

@dhcp_bp.route("/credentials/discover-nodes", methods=["POST"])
@admin_required
def credentials_discover_nodes():
    """AJAX: given tenant+key+engine, return cluster node list + interface
    IPs + current SSH-rule state so the operator can pick a destination IP
    and decide whether to install a rule.
    """
    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    # Per-engine source-IP override (2026-05-31): a blank domain default no
    # longer hard-blocks discovery. The operator can type a per-engine FEA
    # source IP at the rule-install step instead. The rule block surfaces a
    # hint when the domain default is empty so it's clear an IP is needed
    # before installing. Drift computation below tolerates an empty
    # tenant_src gracefully.
    domain_id = _domain_id_for_form(tenant_id, api_key_id)
    cfg = _smc_cfg(tenant, api_key)
    try:
        with smc_session(cfg):
            nodes = list_cluster_nodes(engine_name)
            node_initiated = is_node_initiated_contact(engine_name)
            # P1 pre-flight — SMC-side SSH state per node, queried in
            # the same session so it's free. Wizard renders it as a
            # badge BEFORE the operator clicks Auto-enroll.
            from webapp.smc_dhcp_client import get_node_ssh_state
            ssh_state_by_index: dict[int, dict] = {}
            for n in nodes:
                try:
                    ssh_state_by_index[n.node_index] = get_node_ssh_state(
                        engine_name, n.node_index,
                    )
                except Exception as exc:
                    ssh_state_by_index[n.node_index] = {
                        "state": "unknown", "source": "",
                        "raw_signals": {},
                        "error": f"{type(exc).__name__}: {exc}",
                    }
            # Auth-method probe per node — tells the operator whether
            # the engine accepts password auth BEFORE they click
            # Auto-enroll. Dial host honors the NAT override; falls
            # back to primary mgt IP otherwise. Probe is opportunistic
            # (3s timeout) so a slow/offline node doesn't hang Discover.
            from webapp.dhcp_ssh import (
                SSHTarget as _SSHTarget, probe_ssh_auth_methods,
            )
            auth_methods_by_index: dict[int, dict] = {}
            for n in nodes:
                # Pick the most likely-reachable IP for the probe.
                probe_ip = ""
                for a in n.addresses:
                    publics = [c["address"] for c in a.contact_addresses
                               if c.get("is_public") and c.get("address")]
                    if publics and a.is_primary_mgt:
                        probe_ip = publics[0]
                        break
                if not probe_ip:
                    probe_ip = n.primary_address or ""
                if not probe_ip:
                    auth_methods_by_index[n.node_index] = {
                        "methods": [], "error": "no candidate IP",
                        "probe_host": "",
                    }
                    continue
                try:
                    methods, err = probe_ssh_auth_methods(
                        _SSHTarget(hostname=probe_ip, port=22,
                                   username="root"),
                        timeout=3,
                    )
                    auth_methods_by_index[n.node_index] = {
                        "methods": methods, "error": err,
                        "probe_host": probe_ip,
                    }
                except Exception as exc:
                    auth_methods_by_index[n.node_index] = {
                        "methods": [], "error": f"{type(exc).__name__}: {exc}",
                        "probe_host": probe_ip,
                    }
            try:
                policy_name = find_active_policy(engine_name)
            except Exception as exc:
                policy_name = ""
                policy_error = str(exc)
            else:
                policy_error = ""
            # Live rule lookup — also pulls each source Host's actual IP
            # so the wizard can compare against the tenant's current
            # FEA source IP and ask Add/Overwrite if they drift.
            rule_present = False
            rule_sources_live: list[dict] = []
            if policy_name:
                live_rule = find_ssh_access_rule(
                    policy_name, rule_name_for(engine_name))
                if live_rule is not None:
                    rule_present = True
                    rule_sources_live = live_rule.get("sources", []) or []
        existing_creds = {
            c.node_id: c
            for c in DhcpEngineCredential.query
                .filter_by(domain_id=domain_id, engine_name=engine_name).all()
        }
        access_row = DhcpEngineSshAccess.query.filter_by(
            domain_id=domain_id, engine_name=engine_name,
        ).first()

        # Per the operator spec, the wizard tests existing credentials
        # at discover time so the operator sees ahead of time whether
        # they need to rotate (broken) or just commit metadata changes
        # (working). The test runs OUTSIDE the smc_session block —
        # it's pure SSH (TCP probe + auth verify), no SMC.
        from webapp.dhcp_ssh import tcp_probe, verify_credential

        out_nodes = []
        for n in nodes:
            enrolled = existing_creds.get(n.node_id)
            # Per the operator spec:
            #   - node-initiated cluster → operator MUST pick from the
            #     candidate list (we don't auto-pick because primary_mgt
            #     may not be reachable from FEA).
            #   - SMC-initiated cluster → primary_mgt IP is the natural
            #     target (SMC reaches it, so FEA likely can too).
            candidates = [
                {
                    "address": a.address,
                    "interface_id": a.interface_id,
                    "network_value": a.network_value,
                    "is_primary_mgt": a.is_primary_mgt,
                    "is_outgoing": a.is_outgoing,
                    # P1 — surface per-interface contact addresses so the
                    # UI can offer a connect-IP override when 1:1 NAT
                    # exposes a public exit address on this NDI.
                    "reverse_connection": a.reverse_connection,
                    "contact_addresses": a.contact_addresses,
                } for a in n.addresses if a.address
            ]
            suggested = "" if node_initiated else n.primary_address

            # P1 — compute the suggested *connect IP override* per the
            # A+C rule the operator picked (2026-05-12):
            #   A) If the primary-mgt interface has a public contact
            #      address, default to that public address.
            #   C) Otherwise no auto-pick — the UI shows the picker and
            #      the operator chooses, OR leaves it blank (= today's
            #      behavior, dial the real interface IP).
            #
            # `reachable_via_nat` is the node-level summary: True iff at
            # least one NDI has at least one public contact address.
            # Drives the per-node banner regardless of cluster contact
            # mode.
            suggested_connect_ip = ""
            reachable_via_nat = False
            primary_public_contact = ""
            for a in n.addresses:
                publics = [c for c in a.contact_addresses if c.get("is_public")]
                if publics:
                    reachable_via_nat = True
                    if a.is_primary_mgt and not primary_public_contact:
                        primary_public_contact = publics[0]["address"]
            # Rule A: only auto-pick when it's the primary-mgt interface's
            # public contact address — that's what SMC itself dials.
            if primary_public_contact:
                suggested_connect_ip = primary_public_contact

            # Live cred test — drives the per-node UI in the wizard.
            # Status one of:
            #   not_enrolled — no DB record. UI shows "Auto-enroll" (rotates).
            #   working      — DB record + live SSH probe ok. UI shows
            #                  green badge + "Apply" (DB-only update, no
            #                  rotation).
            #   broken       — DB record but probe failed. UI shows red
            #                  badge + "Overwrite credential" (rotates).
            if enrolled is None:
                cred_status = "not_enrolled"
                cred_status_reason = ""
            else:
                target = _cred_to_target(enrolled)
                payload = SSHCredential(
                    password=enrolled.encrypted_password,
                    host_fingerprint=enrolled.host_fingerprint,
                )
                tcp_ok, tcp_reason = tcp_probe(target, timeout=5)
                if not tcp_ok:
                    cred_status = "broken"
                    cred_status_reason = f"TCP probe: {tcp_reason}"
                else:
                    auth_ok, auth_reason = verify_credential(target, payload)
                    if auth_ok:
                        cred_status = "working"
                        cred_status_reason = ""
                    else:
                        cred_status = "broken"
                        cred_status_reason = auth_reason or "auth failed"

            out_nodes.append({
                "node_index": n.node_index,
                "node_id": n.node_id,
                "name": n.name,
                "smc_nodeid": n.nodeid,
                "primary_mgt_address": n.primary_address,
                "candidates": candidates,
                "suggested_address": suggested,
                "already_enrolled": enrolled is not None,
                "enrolled_hostname": enrolled.hostname if enrolled else "",
                "current_port": enrolled.ssh_port if enrolled else 22,
                "current_username": (enrolled.ssh_username
                                     if enrolled else "root"),
                "last_verify_status": (enrolled.last_verify_status
                                       if enrolled else ""),
                # Status-aware fields used by the new wizard:
                "cred_status": cred_status,
                "cred_status_reason": cred_status_reason,
                # P1 — connect-IP override (NAT-aware).
                "reachable_via_nat": reachable_via_nat,
                "primary_public_contact": primary_public_contact,
                "suggested_connect_ip": suggested_connect_ip,
                # P1 — SMC-side SSH state (pre-flight). Wizard renders
                # a badge so the operator can spot a disabled daemon
                # BEFORE clicking Auto-enroll.
                "ssh_state": ssh_state_by_index.get(n.node_index, {}).get("state", "unknown"),
                "ssh_state_source": ssh_state_by_index.get(n.node_index, {}).get("source", ""),
                "ssh_state_error": ssh_state_by_index.get(n.node_index, {}).get("error", ""),
                # 2026-05-13 — auth-method probe. Catches engines
                # hardened to publickey-only BEFORE we burn a password
                # rotation. Empty list + non-empty error = probe couldn't
                # talk to the daemon (TCP / banner failure).
                "ssh_auth_methods": auth_methods_by_index.get(n.node_index, {}).get("methods", []),
                "ssh_auth_methods_error": auth_methods_by_index.get(n.node_index, {}).get("error", ""),
                "ssh_auth_methods_probe_host": auth_methods_by_index.get(n.node_index, {}).get("probe_host", ""),
                # Echo the persisted override, if any. Phase 5 fills this
                # when the operator confirms during enrollment; this read
                # path lets the UI show the current override on a node
                # the operator is re-visiting.
                "connect_ip_override": (
                    getattr(enrolled, "connect_ip_override", "") or ""
                    if enrolled else ""
                ),
            })

        # Aggregate destination-IP picker for the rule install:
        # node-initiated → all candidate IPs across the cluster
        # SMC-initiated  → just the primary_mgt IP per node
        rule_destinations = []
        seen = set()
        for n in nodes:
            if node_initiated:
                for a in n.addresses:
                    if a.address and a.address not in seen:
                        rule_destinations.append({
                            "address": a.address,
                            "label": f"node {n.node_index} ({n.name}) — {a.interface_id} — {a.address}"
                                     + (" [primary mgt]" if a.is_primary_mgt else ""),
                        })
                        seen.add(a.address)
            else:
                if n.primary_address and n.primary_address not in seen:
                    rule_destinations.append({
                        "address": n.primary_address,
                        "label": f"node {n.node_index} ({n.name}) — {n.primary_address} [primary mgt]",
                    })
                    seen.add(n.primary_address)

        # ── Live source-IP drift detection (per operator spec) ──────────
        # Compare every source Host's *actual* IP in SMC against the
        # tenant's current flexedge_source_ip. Drift if the user's IP
        # is NOT in the live source list. Surfaces three clear states
        # to the wizard:
        #   no_rule         — rule doesn't exist; install path will
        #                    create it as planned, no drift question.
        #   sources_match   — rule's source(s) include the tenant IP.
        #   sources_drift   — rule's source(s) don't include the
        #                    tenant IP. UI prompts Add or Overwrite
        #                    BEFORE letting Discover proceed to nodes.
        live_source_ips = [
            (s.get("address") or "").strip()
            for s in rule_sources_live
            if (s.get("address") or "").strip()
        ]
        tenant_src = (tenant.flexedge_source_ip or "").strip()
        if not rule_present:
            source_drift_state = "no_rule"
        elif tenant_src and tenant_src in live_source_ips:
            source_drift_state = "sources_match"
        else:
            source_drift_state = "sources_drift"

        # P1 cluster-level summary: True iff ANY node has a public
        # contact address. Drives the cluster banner ("Node-initiated
        # but reachable via NAT for the nodes below").
        cluster_reachable_via_nat = any(n.get("reachable_via_nat")
                                        for n in out_nodes)

        return jsonify({
            "nodes": out_nodes,
            "node_initiated_contact": node_initiated,
            "cluster_reachable_via_nat": cluster_reachable_via_nat,
            "rule_destinations": rule_destinations,
            "policy_name": policy_name,
            "policy_error": policy_error,
            "rule_name": rule_name_for(engine_name),
            "rule_present_in_policy": rule_present,
            # Live source info — drives the Add/Overwrite prompt in the
            # wizard. Each entry is {name, address}; address may be ""
            # if the SDK couldn't resolve it (logged warning).
            "rule_sources_live": rule_sources_live,
            "rule_source_drift_state": source_drift_state,
            "rule_db_record": {
                "destination_ip": access_row.destination_ip if access_row else "",
                "fea_source_ip": access_row.fea_source_ip if access_row else "",
                "created_by": access_row.created_by_email if access_row else "",
                "created_at": access_row.created_at.strftime("%Y-%m-%d %H:%M") if access_row else "",
            } if access_row else None,
            "rule_externally_removed": (
                access_row is not None and policy_name and not rule_present
            ),
            "tenant_source_ip": tenant.flexedge_source_ip,
        })
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


# ── SSH rule lifecycle (per engine) ────────────────────────────────────

def _wants_json_response():
    """Detect AJAX caller — JSON when X-Requested-With or Accept header
    asks for it, otherwise the legacy redirect-with-flash path. Used by
    every rule-mutation route so the wizard can stay put on success."""
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in (request.headers.get("Accept") or "")
    )


def _rule_action_response(ok: bool, msg: str, *,
                          level: str | None = None,
                          http: int = 200,
                          extra: dict | None = None):
    """Return JSON for AJAX callers, otherwise flash + redirect.

    Used by every credentials/rule-mutation route (install, push,
    overwrite source, add source, remove). Lets the wizard call them
    without losing wizard state — JS picks up the JSON, refreshes
    the wizard inline, and the page never reloads.
    """
    if _wants_json_response():
        payload = {"ok": ok, "message": msg}
        if extra:
            payload.update(extra)
        if not ok:
            payload["error"] = msg
        return jsonify(payload), (http if not ok or http != 200 else 200)
    flash(msg, level or ("success" if ok else "danger"))
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/rule/install", methods=["POST"])
@admin_required
def credentials_rule_install():
    """Install (or detect existing) the SSH allow rule + push policy.

    Accepts multiple destination IPs (one per cluster node) via either a
    repeated `destination_ip` form field or a single comma-separated
    `destination_ips`. The rule covers all of them so cluster nodes can be
    enrolled in one batch.
    """
    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()

    # Multi-IP collection: prefer multi-valued `destination_ip` (browsers
    # send each checked checkbox), fall back to comma-separated CSV.
    raw_list = request.form.getlist("destination_ip")
    if not raw_list:
        csv = request.form.get("destination_ips", "")
        raw_list = [x.strip() for x in csv.split(",") if x.strip()]
    destination_ips = [ip.strip() for ip in raw_list if ip and ip.strip()]
    # Deduplicate while preserving order
    seen, dedup = set(), []
    for ip in destination_ips:
        if ip not in seen:
            seen.add(ip); dedup.append(ip)
    destination_ips = dedup
    if not destination_ips:
        return _rule_action_response(
            False, "Pick at least one destination IP for the SSH rule.",
            level="danger", http=400,
        )

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        return _rule_action_response(
            False, "Tenant or API key not found.", level="danger", http=404,
        )
    # Per-engine FEA source-IP override (2026-05-31). The operator can
    # type a source IP in the rule block — used as the rule's source
    # for THIS engine only, independent of the tenant/domain-wide
    # default. Falls back to the tenant value when the field is blank.
    # Use case: node-initiated clusters behind 1:1 NAT where FEA's
    # egress IP as seen by THIS engine differs from the domain default.
    override_ip = (request.form.get("fea_source_ip") or "").strip()
    if override_ip:
        from ipaddress import ip_address
        try:
            ip_address(override_ip)
        except ValueError:
            return _rule_action_response(
                False, f"Invalid FEA source IP {override_ip!r}.",
                level="danger", http=400,
            )
        source_ip = override_ip
    else:
        source_ip = (tenant.flexedge_source_ip or "").strip()
    if not source_ip:
        return _rule_action_response(
            False, ("No FEA source IP available. Type one in the "
                    "'FEA source IP' field, or set the domain default "
                    "in the Source IP card at the top of the page."),
            level="danger", http=400,
        )
    domain_id = _domain_id_for_form(tenant_id, api_key_id)

    # NOTE (2026-05-31): the old source-IP "drift refusal" that lived here
    # was REMOVED. It refused the install whenever the DB-recorded source
    # differed from the requested source and told the operator to use
    # Add/Overwrite — but that fired spuriously on a plain "Re-push policy"
    # (which now routes to /credentials/policy-install, a pure upload that
    # never touches the rule). Source changes on an EXISTING rule go
    # through the always-visible "Change rule source IP" card
    # (Overwrite / Add → update_source_host_address / add_source_host_to_rule).
    # This route now only legitimately runs for a FRESH install (no rule in
    # the policy) or a recreate (rule externally removed): `add_ssh_access_rule`
    # creates the rule with the requested source when it's absent, and
    # no-ops on the source when the rule is already present — so there is no
    # silent-mutation hazard to guard against here anymore.
    existing_access = (DhcpEngineSshAccess.query
                       .filter_by(domain_id=domain_id, engine_name=engine_name)
                       .first())
    # Preserve the existing rule_name when present (keeps any legacy
    # versioned name from before the canonical-naming redesign); otherwise
    # let install_ssh_rule pick the canonical name.
    rule_name_to_use = (existing_access.rule_name
                       if existing_access and existing_access.rule_name
                       else None)

    target_label = f"{engine_name} ({len(destination_ips)} dest IP(s))"

    # Phase E.2 — enqueue + auto-push for admins (Q15/a).
    from webapp.dhcp_credentials_queue import (
        enqueue_install_ssh_rule, try_auto_push,
    )
    domain = db.session.get(Domain, domain_id)
    if domain is None:
        return _rule_action_response(
            False, "Domain not found for this tenant/api-key pair.",
            level="danger", http=400,
        )

    try:
        change = enqueue_install_ssh_rule(
            domain=domain,
            engine_name=engine_name,
            source_ip=source_ip,
            destination_ips=destination_ips,
            rule_name=rule_name_to_use,
            fea_hostname=request.host or "",
        )
    except Exception as exc:
        _log_activity("ssh", "install_rule", "failed", target_label,
                      f"enqueue failed: {exc}")
        return _rule_action_response(
            False, f"Could not queue rule install: {exc}",
            level="danger", http=500,
        )

    # Capture id up-front: when bypass_queue is enabled, try_auto_push
    # deletes the change row on success and `change` becomes detached.
    change_id = change.id

    outcome = try_auto_push(change)

    if outcome == "pushed":
        access = (DhcpEngineSshAccess.query
                  .filter_by(domain_id=domain_id, engine_name=engine_name)
                  .first())
        rule_name = access.rule_name if access else "(unknown)"
        policy_name = access.policy_name if access else "(unknown)"
        _log_activity(
            "ssh", "install_rule", "ok", target_label,
            f"via_queue=True rule={rule_name} policy={policy_name} "
            f"source_ip={source_ip!r}",
        )
        return _rule_action_response(
            True,
            f"Installed rule {rule_name} in policy {policy_name} "
            f"and uploaded to engine (queue change #{change_id}).",
        )

    if outcome == "push_failed":
        # Safe to refresh: bypass cleanup only fires on success.
        db.session.refresh(change)
        err = change.push_error_text or "Unknown error"
        _log_activity("ssh", "install_rule", "failed", target_label, err)
        return _rule_action_response(
            False, f"Install rule failed (queue change #{change_id}): {err}",
            level="danger", http=500,
        )

    # outcome == 'queued' — non-admin path.
    _log_activity("ssh", "install_rule.queued", "ok", target_label,
                  f"change_id={change_id} awaiting admin push")
    return _rule_action_response(
        True,
        f"Rule install queued (change #{change_id}). A Domain Admin "
        f"or higher must push it from the Change Queue.",
    )


@dhcp_bp.route("/credentials/policy-install", methods=["POST"])
@admin_required
def credentials_policy_install():
    """Force a policy upload to the engine without changing the rule.

    Operator-triggered, idempotent. Useful when:
      * the engine is running a stale policy (e.g. reverted by an admin
        in SMC GUI, or rolled back after a failed deploy)
      * the rule's destination set was just updated and the previous
        upload didn't catch (shouldn't happen since rule install always
        uploads now, but kept as a safety net)
      * Refresh-state probe reported the rule as "MISSING in SMC" and
        the operator just re-installed it manually in SMC GUI
    """
    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale
    try:
        tenant_id = int(request.form["tenant_id"])
    except (KeyError, ValueError):
        return _rule_action_response(
            False, "Bad form: tenant_id missing or invalid.",
            level="danger", http=400,
        )
    engine_name = (request.form.get("engine_name") or "").strip()
    if not engine_name:
        return _rule_action_response(
            False, "Bad form: engine_name missing.", level="danger", http=400,
        )

    # Phase B.3: tenant_id column being dropped from feature tables.
    # Look up access via Domains belonging to this tenant.
    _dids = _domain_ids_for_tenant(tenant_id)
    access = (DhcpEngineSshAccess.query
              .filter(DhcpEngineSshAccess.domain_id.in_(_dids),
                      DhcpEngineSshAccess.engine_name == engine_name)
              .first())
    if not access:
        return _rule_action_response(
            False,
            f"No managed SSH rule on record for {engine_name}. Install the rule first.",
            level="warning", http=404,
        )

    # Phase B.3: access.domain holds ApiKey + smc_domain_name.
    domain = access.domain
    if domain is None or domain.api_key is None:
        return _rule_action_response(
            False, "Domain or ApiKey gone for this access row.",
            level="danger", http=404,
        )

    target_label = f"{engine_name} (policy={access.policy_name})"

    # Phase E.2 — enqueue + auto-push for admins (Q15/a). Reuses the
    # existing `upload_policy` queue handler (Phase C).
    from webapp.dhcp_credentials_queue import (
        enqueue_policy_upload, try_auto_push,
    )
    try:
        change = enqueue_policy_upload(
            domain=domain, engine_name=engine_name,
            policy_name=access.policy_name,
        )
    except Exception as exc:
        _log_activity("ssh", "policy_install", "failed", target_label,
                      f"enqueue failed: {exc}")
        return _rule_action_response(
            False, f"Could not queue policy install: {exc}",
            level="danger", http=500,
        )

    # Capture id up-front: when bypass_queue is enabled, try_auto_push
    # deletes the change row on success and `change` becomes detached.
    change_id = change.id

    outcome = try_auto_push(change)

    if outcome == "pushed":
        _bump_access_refreshed(tenant_id, engine_name, domain_id=access.domain_id)
        db.session.commit()
        _log_activity("ssh", "policy_install", "ok", target_label,
                      f"via_queue=True change_id={change_id}")
        return _rule_action_response(
            True,
            f"Policy {access.policy_name} pushed to engine {engine_name} "
            f"(queue change #{change_id}). Rules on the engine now match SMC.",
        )

    if outcome == "push_failed":
        # Safe to refresh: bypass cleanup only fires on success.
        db.session.refresh(change)
        err = change.push_error_text or "Unknown error"
        _log_activity("ssh", "policy_install", "failed", target_label, err)
        return _rule_action_response(
            False,
            f"Policy install failed (queue change #{change_id}): {err}. "
            f"The engine is still running its previous policy.",
            level="danger", http=500,
        )

    # Defensive — admin-only route normally, so 'queued' is unexpected.
    _log_activity("ssh", "policy_install.queued", "ok", target_label,
                  f"change_id={change_id} awaiting admin push")
    return _rule_action_response(
        True,
        f"Policy install queued (change #{change_id}). "
        f"Push from the Change Queue.",
    )


def _resolve_drift_context(request_form):
    """Common preamble for the source-drift handlers.

    Returns ``(access_row, tenant, cfg, target_label, error_msg)``.

    On success, ``error_msg`` is empty. On failure all positional
    values are ``None`` and ``error_msg`` carries an operator-facing
    explanation — caller renders it via ``_rule_action_response`` so
    the AJAX wizard sees the actual reason rather than a silent
    redirect.
    """
    try:
        tenant_id = int(request_form["tenant_id"])
    except (KeyError, ValueError):
        return None, None, None, None, "Bad form: tenant_id missing or invalid."
    engine_name = (request_form.get("engine_name") or "").strip()
    if not engine_name:
        return None, None, None, None, "Bad form: engine_name missing."

    # Phase B.3: tenant_id column being dropped from feature tables.
    # Look up access via Domains belonging to this tenant.
    _dids = _domain_ids_for_tenant(tenant_id)
    access = (DhcpEngineSshAccess.query
              .filter(DhcpEngineSshAccess.domain_id.in_(_dids),
                      DhcpEngineSshAccess.engine_name == engine_name)
              .first())
    if not access:
        return None, None, None, None, "No managed SSH rule on record for this engine."

    # Phase B.3: server config + flexedge_source_ip live on the ApiKey
    # (via Domain). Tenant is no longer the source of truth for these.
    domain = access.domain
    api_key = domain.api_key if domain else None
    if not domain or not api_key:
        return None, None, None, None, "Domain or ApiKey gone for this access row."

    new_source_ip = (api_key.flexedge_source_ip or "").strip()
    if not new_source_ip:
        return None, None, None, None, (
            f"API key {api_key.name!r} has no FlexEdge source IP configured. "
            f"Set it first in Card 1."
        )

    cfg = _smc_cfg(domain)
    target_label = f"{engine_name} (rule={access.rule_name})"
    # Return `domain` in place of `tenant` — callers consume it as
    # the carrier of api_key + flexedge_source_ip + name.
    return access, domain, cfg, target_label, ""


def _resolve_override_source_ip(form, domain):
    """Resolve the FEA source IP for a drift-resolution action.

    Per-engine override (2026-05-31): if the form carries a non-empty
    ``new_source_ip`` (the operator typed one in the rule block), validate
    and use it. Otherwise fall back to the domain default
    (``domain.api_key.flexedge_source_ip``).

    Returns:
      * the resolved IP string (may be "" if neither is set), or
      * ``None`` when an explicit override was supplied but is invalid.
    """
    override = (form.get("new_source_ip") or "").strip()
    if override:
        from ipaddress import ip_address
        try:
            ip_address(override)
        except ValueError:
            return None
        return override
    return (domain.api_key.flexedge_source_ip or "").strip()


@dhcp_bp.route("/credentials/rule/source/overwrite", methods=["POST"])
@admin_required
def credentials_rule_source_overwrite():
    """OVERWRITE the existing source Host's IP address — single source
    rule semantics. The rule itself is unchanged; the operator's
    current ``flexedge_source_ip`` replaces the previous one.

    Use case: FEA's egress IP changed (NAT rotation, network move) and
    the operator wants the rule to allow only the new IP. Old IP is
    no longer accepted on the engine.
    """
    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale
    access, domain, cfg, target_label, err = _resolve_drift_context(request.form)
    if access is None:
        return _rule_action_response(False, err, level="warning", http=400)
    # Per-engine override (2026-05-31): the operator may overwrite to a
    # manually-typed source IP rather than the domain default.
    new_source_ip = _resolve_override_source_ip(request.form, domain)
    if new_source_ip is None:
        return _rule_action_response(
            False, "Invalid FEA source IP for overwrite.",
            level="danger", http=400,
        )
    if not new_source_ip:
        return _rule_action_response(
            False, ("No FEA source IP available to overwrite to — type "
                    "one in the rule block or set the domain default."),
            level="danger", http=400,
        )
    old_source_ip = access.fea_source_ip
    try:
        with engine_bootstrap_lock(access.engine_name):
            with smc_session(cfg):
                host_name = update_source_host_address(
                    access.rule_name, new_source_ip)
                upload_ok, upload_msg = upload_policy(
                    access.engine_name, access.policy_name)
        if not upload_ok:
            _log_activity("ssh", "rule_source_overwrite", "failed",
                          target_label,
                          f"Host updated but upload failed: {upload_msg}")
            return _rule_action_response(
                False,
                (f"Updated Host {host_name} to {new_source_ip} but the "
                 f"policy upload FAILED: {upload_msg}. Engine may still "
                 f"be running the old policy with the old IP. Click "
                 f"Push policy to retry."),
                level="danger", http=500,
            )
        access.fea_source_ip = new_source_ip
        _bump_access_refreshed(0, access.engine_name, domain_id=access.domain_id)
        db.session.commit()
        _log_activity(
            "ssh", "rule_source_overwrite", "ok", target_label,
            (f"Host={host_name} {old_source_ip!r} → {new_source_ip!r} "
             f"upload={upload_msg}"),
        )
        return _rule_action_response(
            True,
            (f"Source Host {host_name} updated: {old_source_ip} → "
             f"{new_source_ip}. Policy uploaded; engine now allows SSH "
             f"from the new IP only."),
        )
    except Exception as exc:
        _log_activity("ssh", "rule_source_overwrite", "failed",
                      target_label, str(exc))
        return _rule_action_response(
            False, f"Source overwrite failed: {exc}",
            level="danger", http=500,
        )


@dhcp_bp.route("/credentials/rule/source/add", methods=["POST"])
@admin_required
def credentials_rule_source_add():
    """ADD a new source Host to the existing rule's sources list.

    The rule keeps its existing source(s) AND gets the new one. Both
    old and new FEA IPs are now allowed on the engine. Useful during
    a transition (e.g. NAT cutover) when both addresses must work
    simultaneously. Operator should later return and run Overwrite to
    drop the obsolete source once the cutover is confirmed.
    """
    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale
    access, domain, cfg, target_label, err = _resolve_drift_context(request.form)
    if access is None:
        return _rule_action_response(False, err, level="warning", http=400)
    # Per-engine override (2026-05-31): operator may add a manually-typed
    # source IP rather than the domain default.
    new_source_ip = _resolve_override_source_ip(request.form, domain)
    if new_source_ip is None:
        return _rule_action_response(
            False, "Invalid FEA source IP to add.",
            level="danger", http=400,
        )
    if not new_source_ip:
        return _rule_action_response(
            False, ("No FEA source IP available to add — type one in the "
                    "rule block or set the domain default."),
            level="danger", http=400,
        )
    try:
        with engine_bootstrap_lock(access.engine_name):
            with smc_session(cfg):
                new_host_name = add_source_host_to_rule(
                    access.policy_name, access.rule_name, new_source_ip)
                upload_ok, upload_msg = upload_policy(
                    access.engine_name, access.policy_name)
        if not upload_ok:
            _log_activity("ssh", "rule_source_add", "failed",
                          target_label,
                          f"Host added but upload failed: {upload_msg}")
            return _rule_action_response(
                False,
                (f"Added Host {new_host_name} ({new_source_ip}) to rule "
                 f"{access.rule_name} but the policy upload FAILED: "
                 f"{upload_msg}. Engine may not yet honor the new source. "
                 f"Click Push policy to retry."),
                level="danger", http=500,
            )
        # The DB row's fea_source_ip is the canonical "current" source
        # for drift comparison — update it to the new IP. Old IPs are
        # tracked on SMC as additional source Hosts.
        access.fea_source_ip = new_source_ip
        _bump_access_refreshed(0, access.engine_name, domain_id=access.domain_id)
        db.session.commit()
        _log_activity(
            "ssh", "rule_source_add", "ok", target_label,
            (f"new_host={new_host_name} new_ip={new_source_ip} "
             f"upload={upload_msg}"),
        )
        return _rule_action_response(
            True,
            (f"Added Host {new_host_name} ({new_source_ip}) as an "
             f"additional source on rule {access.rule_name}. Both old "
             f"and new IPs are now allowed. Policy uploaded."),
        )
    except Exception as exc:
        _log_activity("ssh", "rule_source_add", "failed",
                      target_label, str(exc))
        return _rule_action_response(
            False, f"Source add failed: {exc}",
            level="danger", http=500,
        )


@dhcp_bp.route("/credentials/rule/remove", methods=["POST"])
@admin_required
def credentials_rule_remove():
    """Manual rule removal — operator-triggered.

    Refuses if any credentials still reference this engine. The auto-cleanup
    on last-credential-deletion path is in `credentials_delete`.
    """
    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale
    tenant_id = int(request.form["tenant_id"])
    engine_name = request.form["engine_name"].strip()
    # Phase B.3: feature tables are domain-scoped; resolve via tenant's domains.
    _dids = _domain_ids_for_tenant(tenant_id)
    access = (DhcpEngineSshAccess.query
              .filter(DhcpEngineSshAccess.domain_id.in_(_dids),
                      DhcpEngineSshAccess.engine_name == engine_name)
              .first())
    if not access:
        flash("No managed SSH rule on record for this engine.", "info")
        return redirect(url_for("dhcp.credentials_list"))

    creds_remaining = (DhcpEngineCredential.query
                       .filter(DhcpEngineCredential.domain_id.in_(_dids),
                               DhcpEngineCredential.engine_name == engine_name)
                       .count())
    if creds_remaining > 0:
        flash(f"Refusing to remove SSH rule: {creds_remaining} credential(s) "
              f"still depend on it. Delete them first.", "warning")
        return redirect(url_for("dhcp.credentials_list"))

    _do_rule_teardown(access)
    return redirect(url_for("dhcp.credentials_list"))


def _do_rule_teardown(access: DhcpEngineSshAccess) -> None:
    """Internal: remove our rule from policy, push policy, delete DB row.
    Used by manual removal AND last-credential-deletion auto cleanup.

    Phase E.2 — goes through the queue. Domain Admin+ auto-pushes
    inline; non-admin (shouldn't happen — this path is admin-only)
    leaves the row queued.
    """
    domain = access.domain
    if domain is None or domain.api_key is None:
        flash("Domain or ApiKey gone — cannot remove rule from SMC; "
              "removing local record only.", "warning")
        db.session.delete(access)
        db.session.commit()
        return

    target = f"{access.engine_name} rule={access.rule_name}"
    from webapp.dhcp_credentials_queue import (
        enqueue_remove_ssh_rule, try_auto_push,
    )
    try:
        change = enqueue_remove_ssh_rule(
            domain=domain,
            engine_name=access.engine_name,
            policy_name=access.policy_name or "",
            rule_name=access.rule_name or "",
        )
    except Exception as exc:
        _log_activity("ssh", "remove_rule", "failed", target,
                      f"enqueue failed: {exc}")
        flash(f"Could not queue rule removal: {exc}", "danger")
        return

    # Capture id + rule_name up-front: when bypass_queue is enabled,
    # try_auto_push deletes the change row on success and `change`
    # becomes detached; deleting `access` below also detaches it.
    change_id = change.id
    rule_name_for_msg = access.rule_name

    outcome = try_auto_push(change)

    if outcome == "pushed":
        # Push succeeded — clean up the local access row.
        db.session.delete(access)
        db.session.commit()
        _log_activity("ssh", "remove_rule", "ok", target,
                      f"via_queue=True change_id={change_id}")
        flash(f"Removed rule {rule_name_for_msg} and uploaded policy "
              f"(queue change #{change_id}).", "success")
        return

    if outcome == "push_failed":
        # Safe to refresh: bypass cleanup only fires on success.
        db.session.refresh(change)
        err = change.push_error_text or "Unknown error"
        _log_activity("ssh", "remove_rule", "failed", target, err)
        flash(f"Rule removal failed (queue change #{change_id}): {err}. "
              f"The local SSH-access record is kept so retry can re-attempt.",
              "danger")
        return

    # outcome == 'queued' — defensive (this path is admin-only normally).
    _log_activity("ssh", "remove_rule.queued", "ok", target,
                  f"change_id={change_id} awaiting admin push")
    flash(f"Rule removal queued (change #{change_id}). "
          f"Push from the Change Queue to complete.", "info")


# ── Per-node bootstrap (auto via SMC change_ssh_pwd) ───────────────────

@dhcp_bp.route("/credentials/bootstrap", methods=["POST"])
@admin_required
def credentials_bootstrap():
    """Enroll one node:
       1. TCP probe to verify path is open
       2. SMC: enable SSH on the node
       3. SMC: change_ssh_pwd to a fresh 64-char random
       4. SSH-connect with TOFU fingerprint capture
       5. Verify with the captured fingerprint pinned
       6. Persist the credential (password Fernet-encrypted)
    """
    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale
    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()
    node_index = int(request.form["node_index"])
    node_id = request.form["node_id"].strip()
    node_name = request.form.get("node_name", "").strip()
    hostname = request.form["hostname"].strip()
    ssh_port = int(request.form.get("ssh_port", "22"))
    ssh_username = request.form.get("ssh_username", "root").strip() or "root"
    # P1: optional NAT-exit IP the wizard offers when the node is
    # node-initiated but has a public contact address. Validated by
    # `_validate_connect_ip_override` so the form can't smuggle in a
    # bogus value.
    connect_ip_override = _validate_connect_ip_override(
        request.form.get("connect_ip_override", ""))

    wants_json = (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in (request.headers.get("Accept") or "")
    )

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        if wants_json:
            return jsonify(ok=False, error="Tenant or API key not found."), 404
        flash("Tenant or API key not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    # P1: SSH dial uses the override when set; the SMC SSH-allow rule
    # destination keeps using `hostname` (engine's real interface IP).
    dial_host = connect_ip_override or hostname
    target = SSHTarget(hostname=dial_host, port=ssh_port, username=ssh_username)
    cfg = _smc_cfg(tenant, api_key)
    target_label = f"{engine_name}/node{node_index}@{dial_host}"
    if connect_ip_override:
        target_label += f" (real={hostname})"
    audit = _audit_comment("auto-enrollment", engine_name)
    domain_id = _domain_id_for_form(tenant_id, api_key_id)

    try:
        with engine_bootstrap_lock(engine_name):
            with smc_session(cfg):
                result = enroll_node(
                    engine_name=engine_name, node_index=node_index,
                    target=target, audit_comment=audit,
                )
        if not result.ok:
            _log_activity("ssh", f"bootstrap_{result.failed_at_stage}",
                          "failed", target_label, result.error)
            if wants_json:
                return jsonify(
                    ok=False,
                    stage=result.failed_at_stage,
                    error=result.error,
                    node_index=node_index,
                    hostname=hostname,
                ), 200    # 200 so client can render the per-node failure
            flash(f"Bootstrap failed at stage '{result.failed_at_stage}': "
                  f"{result.error}", "danger")
            return redirect(url_for("dhcp.credentials_list"))

        # Persist credential — check both new (domain_id) and legacy (tenant_id)
        # uniqueness to avoid hitting the vestigial UNIQUE constraint.
        existing = DhcpEngineCredential.query.filter_by(
            domain_id=domain_id, engine_name=engine_name, node_id=node_id,
        ).first()
        if existing is None:
            existing = DhcpEngineCredential.query.filter_by(
                tenant_id=tenant_id, engine_name=engine_name, node_id=node_id,
            ).first()
        now = datetime.now(timezone.utc)
        if existing:
            existing.api_key_id = api_key_id
            existing.domain_id = domain_id  # backfill if NULL
            existing.node_index = node_index
            existing.node_name = node_name or existing.node_name
            existing.hostname = hostname
            existing.ssh_port = ssh_port
            existing.ssh_username = ssh_username
            existing.encrypted_password = result.new_password
            existing.host_fingerprint = result.host_fingerprint
            existing.last_verified_at = now
            existing.last_verify_status = "ok"
            existing.last_error = ""
            existing.state_refreshed_at = now
            existing.connect_ip_override = connect_ip_override
        else:
            db.session.add(DhcpEngineCredential(
                domain_id=domain_id,
                tenant_id=tenant_id, api_key_id=api_key_id,   # legacy — kept until B.3
                engine_name=engine_name, node_index=node_index,
                node_id=node_id, node_name=node_name,
                hostname=hostname, ssh_port=ssh_port, ssh_username=ssh_username,
                encrypted_password=result.new_password,
                host_fingerprint=result.host_fingerprint,
                last_verified_at=now, last_verify_status="ok",
                state_refreshed_at=now,
                connect_ip_override=connect_ip_override,
            ))
        # Enrollment proves both SSH (we connected to the node) and the
        # rule (it must have been in policy for the connect to work) —
        # bump the access row too.
        _bump_access_refreshed(tenant_id, engine_name, now, domain_id=domain_id)
        db.session.commit()
        _log_activity("ssh", "bootstrap", "ok", target_label,
                      f"fingerprint={result.host_fingerprint}")
        # P1: dedicated audit row when a NAT override is in effect so
        # operators can grep `/logs?feature=dhcp&action=credential.enrolled_via_nat`
        # to see which nodes are being reached via 1:1 NAT.
        if connect_ip_override:
            try:
                from shared.logging import audit
                audit(
                    feature="dhcp",
                    action="credential.enrolled_via_nat",
                    target=target_label,
                    detail=(f"real_ip={hostname} "
                            f"connect_ip={connect_ip_override} "
                            f"node_index={node_index}"),
                    domain_id=domain_id,
                )
            except Exception:
                pass
        if wants_json:
            return jsonify(
                ok=True,
                node_index=node_index,
                hostname=hostname,
                fingerprint=result.host_fingerprint,
                tenant_id=tenant_id,
                engine_name=engine_name,
            )
        flash(f"Enrolled {engine_name} node {node_index} ({hostname}). "
              f"Fingerprint: {result.host_fingerprint}", "success")
    except Exception as exc:
        _log_activity("ssh", "bootstrap", "failed", target_label, str(exc))
        if wants_json:
            return jsonify(ok=False, error=str(exc),
                           node_index=node_index, hostname=hostname), 500
        flash(f"Bootstrap failed: {exc}", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/apply", methods=["POST"])
@admin_required
def credentials_apply():
    """Commit IP / port / username changes for an EXISTING WORKING
    credential — DB-only, no SSH, no SMC, no password rotation.

    Use case: the operator picked a different NDI for a node whose
    existing credential is verified working (typically because the
    node has multiple IPs and the operator wants to manage it through
    a different one). The same root password works on the engine
    regardless of which NDI we connect to, so we just update the DB
    metadata and bump the freshness timestamp.

    For BROKEN credentials, this route refuses — the operator must
    explicitly choose 'Overwrite credential' (which rotates the
    password via SMC).
    """
    wants_json = _wants_json_response()

    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale

    def _err(msg, http=400):
        if wants_json:
            return jsonify(ok=False, error=msg), http
        flash(msg, "danger" if http >= 400 else "warning")
        return redirect(url_for("dhcp.credentials_list"))

    try:
        tenant_id = int(request.form["tenant_id"])
    except (KeyError, ValueError):
        return _err("Bad form: tenant_id missing or invalid.")
    engine_name = (request.form.get("engine_name") or "").strip()
    node_id = (request.form.get("node_id") or "").strip()
    if not engine_name or not node_id:
        return _err("Bad form: engine_name and node_id are required.")
    new_hostname = (request.form.get("hostname") or "").strip()
    if not new_hostname:
        return _err("Bad form: hostname is required.")
    try:
        new_port = int(request.form.get("ssh_port", "22"))
    except ValueError:
        new_port = 22
    new_username = (request.form.get("ssh_username") or "root").strip() or "root"
    # P1: pick up the override from the wizard; empty / invalid → ""
    # (= today's behavior, dial new_hostname).
    new_connect_ip_override = _validate_connect_ip_override(
        request.form.get("connect_ip_override", ""))

    # Phase B.3: tenant_id is going away on feature tables.
    _dids = _domain_ids_for_tenant(tenant_id)
    cred = (DhcpEngineCredential.query
            .filter(DhcpEngineCredential.domain_id.in_(_dids),
                    DhcpEngineCredential.engine_name == engine_name,
                    DhcpEngineCredential.node_id == node_id)
            .first())
    if cred is None:
        return _err(f"No credential on record for {engine_name}/node_id={node_id}. "
                    f"Use Auto-enroll instead.", http=404)

    # P1: SSH dial uses override; rule destination stays real IP.
    dial_host = new_connect_ip_override or new_hostname
    target_label = f"{engine_name}/node{cred.node_index}@{dial_host}"
    if new_connect_ip_override:
        target_label += f" (real={new_hostname})"

    # Live verify against the new target before committing. Apply must
    # never silently break a previously-working credential — if the
    # operator points us at an IP that doesn't actually accept this
    # credential, refuse and tell them to use Overwrite.
    target = SSHTarget(hostname=dial_host, port=new_port,
                       username=new_username)
    payload = SSHCredential(password=cred.encrypted_password,
                            host_fingerprint=cred.host_fingerprint)
    tcp_ok, tcp_reason = tcp_probe(target, timeout=8)
    if not tcp_ok:
        msg = (f"Apply refused: {new_hostname}:{new_port} TCP unreachable "
               f"({tcp_reason}). Either the rule doesn't cover this IP "
               f"or the engine isn't online — use Overwrite credential "
               f"if you want to rotate the password.")
        _log_activity("ssh", "apply", "failed", target_label, msg)
        return _err(msg, http=200)
    auth_ok, auth_reason = verify_credential(target, payload)
    if not auth_ok:
        msg = (f"Apply refused: SSH auth failed against "
               f"{new_hostname}:{new_port} ({auth_reason}). The stored "
               f"password doesn't match what's on this node — use "
               f"Overwrite credential to rotate via SMC.")
        _log_activity("ssh", "apply", "failed", target_label, msg)
        return _err(msg, http=200)

    # All good — commit metadata.
    now = datetime.now(timezone.utc)
    old_summary = (f"hostname={cred.hostname!r} port={cred.ssh_port} "
                   f"user={cred.ssh_username!r} "
                   f"override={cred.connect_ip_override!r}")
    cred.hostname = new_hostname
    cred.ssh_port = new_port
    cred.ssh_username = new_username
    cred.connect_ip_override = new_connect_ip_override
    cred.last_verified_at = now
    cred.last_verify_status = "ok"
    cred.last_error = ""
    cred.state_refreshed_at = now
    db.session.commit()

    _log_activity(
        "ssh", "apply", "ok", target_label,
        f"{old_summary} → hostname={new_hostname!r} port={new_port} "
        f"user={new_username!r} (no password rotation)",
    )

    if wants_json:
        return jsonify(
            ok=True,
            tenant_id=tenant_id,
            engine_name=engine_name,
            node_id=node_id,
            node_index=cred.node_index,
            hostname=new_hostname,
            cred_status="working",
            message=(f"Updated metadata for node {cred.node_index} — "
                     f"no password rotation. Credential verified."),
        )
    flash(f"Applied metadata changes to {target_label}. "
          f"Credential verified; password unchanged.", "success")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/bootstrap-batch", methods=["POST"])
@admin_required
def credentials_bootstrap_batch():
    """Enroll multiple cluster nodes for one engine in a single transaction.

    Form data shape (one engine, N nodes):
      tenant_id, api_key_id, engine_name
      node_count
      node_<i>_index, node_<i>_id, node_<i>_name, node_<i>_hostname,
      node_<i>_ssh_port, node_<i>_ssh_username

    Aggregates per-node results, persists each successful credential, and
    returns either:
      * **AJAX** (``Accept: application/json`` or ``X-Requested-With``):
        a JSON object with per-node outcomes. The browser renders the
        list inline so the wizard's discovered-nodes panel above stays put.
      * **Form fallback**: redirect-with-flash, exactly as before.

    The whole batch runs inside ONE smc_session and ONE per-engine lock
    acquisition — significantly faster than N sequential single-node calls.
    """
    wants_json = _wants_json_response()

    stale = _check_stale_form_or_response()
    if stale is not None:
        return stale

    def _err(msg: str, http: int = 400):
        if wants_json:
            return jsonify(ok=False, error=msg), http
        flash(msg, "danger" if http >= 400 else "warning")
        return redirect(url_for("dhcp.credentials_list"))

    tenant_id = int(request.form["tenant_id"])
    api_key_id = int(request.form["api_key_id"])
    engine_name = request.form["engine_name"].strip()
    try:
        node_count = int(request.form.get("node_count", "0"))
    except ValueError:
        node_count = 0
    if node_count <= 0:
        return _err("No nodes specified for batch enrollment.", http=400)

    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, api_key_id)
    if not tenant or not api_key:
        return _err("Tenant or API key not found.", http=404)
    cfg = _smc_cfg(tenant, api_key)
    audit = _audit_comment("auto-enrollment (batch)", engine_name)
    domain_id = _domain_id_for_form(tenant_id, api_key_id)

    # Pre-collect node specs from form (so we don't need form access inside the lock)
    specs: list[dict] = []
    for i in range(node_count):
        prefix = f"node_{i}_"
        host = request.form.get(prefix + "hostname", "").strip()
        if not host:
            continue
        try:
            specs.append({
                "node_index": int(request.form[prefix + "index"]),
                "node_id":    request.form.get(prefix + "id", "").strip(),
                "node_name":  request.form.get(prefix + "name", "").strip(),
                "hostname":   host,
                "port":       int(request.form.get(prefix + "ssh_port", "22")),
                "username":   request.form.get(prefix + "ssh_username", "root").strip() or "root",
                # P1: per-node override carried alongside the rest of
                # the spec.  Validated defensively here so a bad value
                # for one node doesn't poison the whole batch.
                "connect_ip_override": _validate_connect_ip_override(
                    request.form.get(prefix + "connect_ip_override", "")),
            })
        except (KeyError, ValueError) as exc:
            _log_activity("ssh", "bootstrap_batch", "failed",
                          f"{engine_name}/node{i}", f"bad form data: {exc}")

    if not specs:
        return _err("No valid node specs in batch.", http=400)

    # Per-node structured results — used for both audit log and JSON shape.
    node_results: list[dict] = []
    successes, failures = 0, 0

    try:
        with engine_bootstrap_lock(engine_name, timeout=180):
            with smc_session(cfg):
                for spec in specs:
                    # P1: dial via override; rule destination stays real IP.
                    dial_host = spec["connect_ip_override"] or spec["hostname"]
                    target_label = f"{engine_name}/node{spec['node_index']}@{dial_host}"
                    if spec["connect_ip_override"]:
                        target_label += f" (real={spec['hostname']})"
                    target = SSHTarget(hostname=dial_host, port=spec["port"],
                                       username=spec["username"])
                    res_entry: dict = {
                        "node_index": spec["node_index"],
                        "node_id":    spec["node_id"],
                        "node_name":  spec["node_name"],
                        "hostname":   spec["hostname"],
                        "connect_ip_override": spec["connect_ip_override"],
                    }
                    try:
                        result = enroll_node(
                            engine_name=engine_name,
                            node_index=spec["node_index"],
                            target=target, audit_comment=audit,
                        )
                    except Exception as exc:
                        failures += 1
                        res_entry.update(ok=False, stage="exception", error=str(exc))
                        node_results.append(res_entry)
                        _log_activity("ssh", "bootstrap", "failed", target_label, str(exc))
                        continue

                    if not result.ok:
                        failures += 1
                        res_entry.update(
                            ok=False, stage=result.failed_at_stage,
                            error=result.error,
                        )
                        node_results.append(res_entry)
                        _log_activity("ssh", f"bootstrap_{result.failed_at_stage}",
                                      "failed", target_label, result.error)
                        continue

                    # Persist this credential — check both new (domain_id) and
                    # legacy (tenant_id) uniqueness to avoid the vestigial constraint.
                    existing = DhcpEngineCredential.query.filter_by(
                        domain_id=domain_id, engine_name=engine_name,
                        node_id=spec["node_id"],
                    ).first()
                    if existing is None:
                        existing = DhcpEngineCredential.query.filter_by(
                            tenant_id=tenant_id, engine_name=engine_name,
                            node_id=spec["node_id"],
                        ).first()
                    now = datetime.now(timezone.utc)
                    if existing:
                        existing.api_key_id = api_key_id
                        existing.domain_id = domain_id  # backfill if NULL
                        existing.node_index = spec["node_index"]
                        existing.node_name = spec["node_name"] or existing.node_name
                        existing.hostname = spec["hostname"]
                        existing.ssh_port = spec["port"]
                        existing.ssh_username = spec["username"]
                        existing.encrypted_password = result.new_password
                        existing.host_fingerprint = result.host_fingerprint
                        existing.last_verified_at = now
                        existing.last_verify_status = "ok"
                        existing.last_error = ""
                        existing.state_refreshed_at = now
                        existing.connect_ip_override = spec["connect_ip_override"]
                    else:
                        db.session.add(DhcpEngineCredential(
                            domain_id=domain_id,
                            tenant_id=tenant_id, api_key_id=api_key_id,   # legacy — kept until B.3
                            engine_name=engine_name,
                            node_index=spec["node_index"],
                            node_id=spec["node_id"], node_name=spec["node_name"],
                            hostname=spec["hostname"], ssh_port=spec["port"],
                            ssh_username=spec["username"],
                            encrypted_password=result.new_password,
                            host_fingerprint=result.host_fingerprint,
                            last_verified_at=now, last_verify_status="ok",
                            state_refreshed_at=now,
                            connect_ip_override=spec["connect_ip_override"],
                        ))
                    db.session.commit()
                    successes += 1
                    res_entry.update(
                        ok=True, stage="done",
                        fingerprint=result.host_fingerprint,
                    )
                    node_results.append(res_entry)
                    _log_activity("ssh", "bootstrap", "ok", target_label,
                                  f"fingerprint={result.host_fingerprint}")
                # Batch enroll proves the rule was in policy too — bump
                # access freshness once at the end (cheaper than per-node).
                if successes:
                    _bump_access_refreshed(tenant_id, engine_name, domain_id=domain_id)
                    db.session.commit()
    except Exception as exc:
        _log_activity("ssh", "bootstrap_batch", "failed", engine_name, str(exc))
        if wants_json:
            return jsonify(ok=False, error=f"Batch enrollment aborted: {exc}",
                           nodes=node_results, successes=successes,
                           failures=failures), 500
        flash(f"Batch enrollment aborted: {exc}", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    detail_lines = [
        ("node{i}: ok ({fp})".format(i=r["node_index"], fp=r.get("fingerprint", ""))
         if r.get("ok")
         else "node{i}: failed at {st} — {er}".format(
             i=r["node_index"], st=r.get("stage", "?"), er=r.get("error", "")))
        for r in node_results
    ]
    _log_activity("ssh", "bootstrap_batch",
                  "ok" if failures == 0 else ("partial" if successes else "failed"),
                  engine_name,
                  f"successes={successes} failures={failures}\n" + "\n".join(detail_lines))

    if wants_json:
        return jsonify(
            ok=True,
            tenant_id=tenant_id,
            engine_name=engine_name,
            successes=successes,
            failures=failures,
            total=len(node_results),
            nodes=node_results,
        )

    if successes and not failures:
        flash(f"Batch enrolled {successes} node(s) on {engine_name}.", "success")
    elif successes and failures:
        flash(f"Partial: {successes} succeeded, {failures} failed on {engine_name}. "
              f"See activity log for per-node detail.", "warning")
    else:
        flash(f"Batch enrollment failed for all {failures} node(s) on {engine_name}. "
              f"See activity log.", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/<int:cred_id>/verify", methods=["POST"])
@admin_required
def credentials_verify(cred_id):
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if not cred:
        flash("Credential not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    ok, err = verify_credential(_cred_to_target(cred), _cred_to_payload(cred))
    now = datetime.now(timezone.utc)
    cred.last_verified_at = now
    cred.last_verify_status = "ok" if ok else "failed"
    cred.last_error = "" if ok else err
    if ok:
        # Successful verify proves cred + reachability through the rule.
        cred.state_refreshed_at = now
        _bump_access_refreshed(0, cred.engine_name, now, domain_id=cred.domain_id)
    db.session.commit()
    target_label = f"{cred.engine_name}/node{cred.node_index}@{cred.hostname}"
    _log_activity("ssh", "verify", "ok" if ok else "failed", target_label, err)
    if ok:
        flash(f"{cred.engine_name} node {cred.node_index} reachable.", "success")
    elif is_auth_failure(err):
        flash(f"Authentication failed for {target_label} — the password "
              f"may have been changed externally. Click 'Force re-bootstrap' "
              f"to issue a new password via SMC.", "danger")
    else:
        flash(f"Verification failed: {err}", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/<int:cred_id>/force-reset", methods=["POST"])
@admin_required
def credentials_force_reset(cred_id):
    """A3 recovery: rotate the password via SMC, re-verify, store the new one.

    Used when verify fails with auth-failure (someone changed root pw out
    of band). Operator-confirmed: a button on the credential row is the
    only trigger.
    """
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if not cred:
        flash("Credential not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    domain = cred.domain
    if domain is None or domain.api_key is None:
        flash("Domain or ApiKey gone for this credential.", "danger")
        return redirect(url_for("dhcp.credentials_list"))

    cfg = _smc_cfg(domain)
    target = _cred_to_target(cred)
    target_label = f"{cred.engine_name}/node{cred.node_index}@{cred.hostname}"

    try:
        with engine_bootstrap_lock(cred.engine_name):
            with smc_session(cfg):
                result = force_reset_password(
                    engine_name=cred.engine_name,
                    node_index=cred.node_index,
                    target=target,
                    existing_fingerprint=cred.host_fingerprint,
                    audit_comment=_audit_comment("force-reset", cred.engine_name),
                )
        if not result.ok:
            _log_activity("ssh", "force_reset", "failed", target_label, result.error)
            flash(f"Force re-bootstrap failed at '{result.failed_at_stage}': "
                  f"{result.error}", "danger")
            return redirect(url_for("dhcp.credentials_list"))

        # Capture the prior fingerprint BEFORE we overwrite it, so the
        # audit log records the actual change (not the new value twice).
        prior_fp = cred.host_fingerprint or result.previous_fingerprint
        now = datetime.now(timezone.utc)
        cred.encrypted_password = result.new_password
        if result.host_fingerprint:
            cred.host_fingerprint = result.host_fingerprint
        cred.last_verified_at = now
        cred.last_verify_status = "ok"
        cred.last_error = ""
        cred.state_refreshed_at = now
        _bump_access_refreshed(0, cred.engine_name, now, domain_id=cred.domain_id)
        db.session.commit()

        if result.fingerprint_changed:
            # Loud audit: a fingerprint change papers over both engine
            # re-image (legit) and a hypothetical MITM (not legit). The
            # only way a defender notices is if we record both values.
            _log_activity(
                "ssh", "fingerprint_changed", "warning", target_label,
                detail=(f"Host key fingerprint changed during force-reset. "
                        f"OLD: {prior_fp or '(none)'}  →  "
                        f"NEW: {cred.host_fingerprint}. "
                        f"Operator must verify out-of-band that the engine "
                        f"was legitimately re-imaged."),
            )
            flash(
                "Password rotated, BUT the host key fingerprint changed "
                f"({prior_fp[:24]}… → {cred.host_fingerprint[:24]}…). "
                "If you did not re-image this engine, treat as a security "
                "incident and investigate before relying on this credential.",
                "warning",
            )
        else:
            flash(f"Password rotated and verified on {target_label}.", "success")
        _log_activity("ssh", "force_reset", "ok", target_label,
                      f"fingerprint={cred.host_fingerprint}"
                      + (" (CHANGED)" if result.fingerprint_changed else ""))
    except Exception as exc:
        _log_activity("ssh", "force_reset", "failed", target_label, str(exc))
        flash(f"Force re-bootstrap failed: {exc}", "danger")
    return redirect(url_for("dhcp.credentials_list"))


@dhcp_bp.route("/credentials/<int:cred_id>/delete", methods=["POST"])
@admin_required
def credentials_delete(cred_id):
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if not cred:
        flash("Credential not found.", "danger")
        return redirect(url_for("dhcp.credentials_list"))
    target_label = f"{cred.engine_name}/node{cred.node_index}@{cred.hostname}"
    # Phase B.3: domain_id is the canonical scope FK.
    domain_id = cred.domain_id
    engine_name = cred.engine_name
    db.session.delete(cred)
    db.session.commit()
    _log_activity("ssh", "delete", "ok", target_label,
                  "Local credential removed. Note: the rotated password is still "
                  "set on the node — re-bootstrap to rotate again.")
    flash(f"Credential removed for {target_label}.", "info")

    # Auto-cleanup: if no credentials remain for this engine, tear down the SSH rule
    remaining = DhcpEngineCredential.query.filter_by(
        domain_id=domain_id, engine_name=engine_name,
    ).count()
    if remaining == 0:
        access = DhcpEngineSshAccess.query.filter_by(
            domain_id=domain_id, engine_name=engine_name,
        ).first()
        if access:
            flash(f"Last credential for {engine_name} removed — tearing down "
                  f"the SSH allow rule {access.rule_name}.", "info")
            _do_rule_teardown(access)
    return redirect(url_for("dhcp.credentials_list"))


# ── Leases viewer (Phase 1b) ─────────────────────────────────────────────

LEASE_FILE = "/spool/dhcp-server/dhcpd.leases"


def _other_domains_with_creds(engine_name: str,
                              *, exclude_domain_id: int) -> list:
    """Find other Domains (the current user can access) that have
    SSH credentials for ``engine_name``.

    Returns a list of dicts ``{slug, display_name, node_count}``,
    sorted by display_name. Empty list when no match or session has
    no user. Restricted to Domains the operator actually has access
    to via `get_user_profiles` so we don't leak info about Domains
    they can't switch to anyway.
    """
    try:
        email = (session.get("user") or {}).get("email") or ""
        if not email:
            return []
        import user_manager
        profiles = user_manager.get_user_profiles(email) or []
        accessible_slugs = {(p.get("tenant") or "").strip()
                            for p in profiles
                            if p.get("tenant")}
        if not accessible_slugs:
            return []

        rows = (
            db.session.query(
                Domain.id, Domain.slug, Domain.display_name,
                db.func.count(DhcpEngineCredential.id),
            )
            .join(DhcpEngineCredential,
                  DhcpEngineCredential.domain_id == Domain.id)
            .filter(
                DhcpEngineCredential.engine_name == engine_name,
                Domain.id != exclude_domain_id,
                Domain.slug.in_(accessible_slugs),
                Domain.is_active.is_(True),
            )
            .group_by(Domain.id, Domain.slug, Domain.display_name)
            .order_by(Domain.display_name.asc())
            .all()
        )
        return [
            {"id": r[0], "slug": r[1],
             "display_name": r[2], "node_count": int(r[3] or 0)}
            for r in rows
        ]
    except Exception as exc:
        log.warning("other_domains_with_creds(%s): lookup failed: %s",
                    engine_name, exc)
        return []


@dhcp_bp.route("/scopes/<int:scope_id>/leases")
@admin_required
def scope_leases(scope_id):
    """Read dhcpd.leases from every enrolled node for this scope's engine,
    parse, merge, and display the consolidated view.

    One row per (MAC, IP) pair, with which nodes saw the lease. Cross-checks
    against reservations so the UI can flag a lease that deviates from its
    tracked reservation.

    When called with `?scan_id=X` and the scan is still running, the page
    renders an in-progress watcher (progress bar + 10-line log) that polls
    /scan/status. When the scan is `done`, the route consumes the report
    and renders the enriched view (Discovery column + untracked card).
    Failures flash and fall through to the plain leases view.
    """
    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    # Auto-recover scopes whose ``subnet_cidr`` was left empty by an old
    # discovery run (pre-2026-05-20 fallback) but whose gateway/pool
    # fields are intact in the DB. Avoids forcing the operator to
    # re-discover when SMC still won't yield ``address``/``network_value``.
    _lazy_backfill_subnet_cidr(scope)

    # Subnet-scan UX — handle ?scan_id=X. Either render the watcher
    # (state=running), consume + enrich (state=done), or fall through
    # cleanly with a flash on failure / expiry.
    scan_id = (request.args.get("scan_id") or "").strip()
    scan_report = None
    scan_running = None
    if scan_id:
        from webapp.dhcp_scan_jobs import get_status, consume_report, discard
        user_email = (session.get("user") or {}).get("email", "")
        status = get_status(scan_id, user_email=user_email)
        if status is None:
            flash("Scan job not found or expired — start a new one.", "info")
        elif status["state"] == "running":
            scan_running = status
        elif status["state"] == "failed":
            flash(f"Subnet scan failed: {status.get('error') or 'unknown error'}",
                  "danger")
            discard(scan_id, user_email=user_email)
        else:  # done
            scan_report = consume_report(scan_id, user_email=user_email)
            if scan_report is None:
                flash("Scan results expired before they could be loaded.",
                      "warning")
            else:
                _log_activity(
                    "scan", "subnet_sweep", "ok",
                    f"{scope.engine_name}/{scan_report.subnet_cidr}",
                    f"targets={scan_report.targets} "
                    f"icmp={scan_report.icmp_replies} "
                    f"arp={scan_report.arp_replies} "
                    f"duration={scan_report.duration_ms}ms "
                    f"via node{scan_report.source_node_index}",
                )

    # Phase B.2: scope.domain_id (populated by Phase B.1 backfill) is
    # the canonical scope FK. tenant_id stays populated until B.3.
    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=scope.domain_id,
                        engine_name=scope.engine_name)
             .order_by(DhcpEngineCredential.node_index).all())
    creds_missing = not creds
    # Don't teleport the operator away when no credentials are enrolled
    # yet — render the leases page with an empty state + a clear CTA so
    # they keep the scope context (breadcrumb, scope metadata, refresh
    # button). The template's `creds_missing` block surfaces an inline
    # alert with a "Enroll credentials" button.
    #
    # Cross-Domain diagnostic: same engine name can be reachable under
    # multiple Domains (multiple API keys hitting the same SMC). Tell
    # the operator exactly which OTHER Domain has credentials for this
    # engine and offer a one-click switch — restricted to Domains the
    # operator actually has access to so we don't leak info.
    other_domain_creds = []
    if creds_missing:
        other_domain_creds = _other_domains_with_creds(
            scope.engine_name, exclude_domain_id=scope.domain_id,
        )

    reservations = (DhcpReservation.query.filter_by(scope_id=scope.id).all())
    res_by_mac = {r.mac_address: r for r in reservations}
    res_by_ip = {r.ip_address: r for r in reservations}

    # When the watcher is rendering, skip the (slow) lease read + render
    # the page in "scanning" mode. The polling JS reloads the page on
    # completion, at which point the full lease read happens.
    if scan_running is not None:
        now = datetime.now(timezone.utc)
        subnet_size_running = 0
        if scope.subnet_cidr:
            try:
                import ipaddress as _ipa
                subnet_size_running = max(
                    0,
                    _ipa.ip_network(scope.subnet_cidr,
                                    strict=False).num_addresses - 2,
                )
            except Exception:
                subnet_size_running = 0
        return render_template(
            "dhcp/leases.html",
            scope=scope, leases=[], nodes=creds, fetch_errors={},
            now=now, lease_file_path=LEASE_FILE,
            leases_other_subnets=0, subnet_filter_cidr="",
            scan_report=None, scan_running=scan_running,
            untracked_rows=[],
            subnet_size=subnet_size_running,
            creds_missing=creds_missing,
            other_domain_creds=other_domain_creds,
            leases_cache_meta=None,
        )

    # H4 (audit fix-up, 2026-05-09): parallel + cached per-node fetch.
    # Was: sequential SSH read per node × 2-4s = 10-15s on a 4-node cluster
    # blocking the request thread. Now: fan out via ThreadPoolExecutor;
    # each node's parsed leases cache for 120s in section `dhcp.leases`,
    # key (domain_id, engine_name, node_index). Concurrent page loads
    # across operators share the cache. ?refresh=1 forces re-fetch.
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from shared.smc_cache import cache_get_or_fetch

    refresh = (request.args.get("refresh") == "1")

    def _fetch_node_leases_cached(cred):
        """Fetch + parse one node's lease file, cached for 120s.

        Cache TTL is intentionally tighter than the platform Quick (1h)
        / Loose (24h) tiers — leases rotate as DHCP clients renew, and
        operators visit this page WHILE diagnosing live network state.
        Two minutes is enough to make rapid scope-pivot navigation feel
        instant without serving genuinely stale data.
        """
        def _fetcher():
            target = _cred_to_target(cred)
            payload = _cred_to_payload(cred)
            raw = ssh_get_file(target, payload, LEASE_FILE)
            return parse_dhcpd_leases(raw.decode(errors="replace"))
        return cache_get_or_fetch(
            section="dhcp.leases",
            key_parts=(cred.domain_id, cred.engine_name, cred.node_index),
            fetcher=_fetcher,
            ttl=120,
            refresh=refresh,
        )

    per_node_results: dict[int, list] = {}
    fetch_errors: dict[int, str] = {}
    node_cache_meta: list = []  # CachedValue per successful node

    if creds:
        # max_workers=8 covers the largest cluster we've seen; on small
        # clusters Python clamps to len(creds) automatically anyway.
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(creds))),
                                thread_name_prefix="dhcp-leases") as pool:
            futures = {pool.submit(_fetch_node_leases_cached, c): c
                       for c in creds}
            for fut in as_completed(futures):
                cred = futures[fut]
                try:
                    cached = fut.result()
                    per_node_results[cred.node_index] = cached.data
                    node_cache_meta.append(cached)
                    if not cached.served_from_cache:
                        _log_activity(
                            "ssh", "read_leases", "ok",
                            f"{cred.engine_name}/node{cred.node_index}",
                            f"{len(cached.data)} lease blocks"
                            f"{' (refreshed)' if refresh else ''}",
                        )
                except Exception as exc:
                    fetch_errors[cred.node_index] = str(exc)
                    _log_activity(
                        "ssh", "read_leases", "failed",
                        f"{cred.engine_name}/node{cred.node_index}", str(exc),
                    )

    # Aggregate freshness for the badge — page is "fresh" only when EVERY
    # node was just re-fetched; otherwise show the oldest cached_at so the
    # operator sees the worst-case staleness.
    if node_cache_meta:
        oldest = min(node_cache_meta, key=lambda c: c.cached_at)
        leases_cache_meta = {
            "served_from_cache": all(m.served_from_cache for m in node_cache_meta),
            "age_seconds": int(oldest.age_seconds),
            "cached_at": oldest.cached_at,
        }
    else:
        leases_cache_meta = None

    merged = merge_cluster_leases(per_node_results) if per_node_results else []

    # Filter to the leases that belong to THIS scope's subnet.
    # ``dhcpd.leases`` is a single file shared by every scope on the engine,
    # so without filtering the operator sees leases from other VLANs too.
    import ipaddress
    leases_other_subnets = 0
    network = None
    if scope.subnet_cidr:
        try:
            network = ipaddress.ip_network(scope.subnet_cidr, strict=False)
        except (ValueError, TypeError):
            log.warning("Scope %s has unparseable subnet_cidr %r — showing all leases",
                        scope.id, scope.subnet_cidr)
            network = None

    if network is not None:
        in_scope = []
        for row in merged:
            try:
                if ipaddress.ip_address(row["ip"]) in network:
                    in_scope.append(row)
                else:
                    leases_other_subnets += 1
            except (ValueError, KeyError):
                leases_other_subnets += 1
        merged = in_scope

    # Annotate each merged row with reservation cross-check
    for row in merged:
        match = res_by_mac.get(row["mac"])
        if match:
            row["reservation_id"] = match.id
            row["reservation_host"] = match.smc_host_name
            row["reservation_ip"] = match.ip_address
            row["reservation_matches"] = (match.ip_address == row["ip"])
        else:
            row["reservation_id"] = None
            row["reservation_host"] = ""
            row["reservation_ip"] = ""
            row["reservation_matches"] = None
        row["from_scan"] = False  # came from dhcpd.leases
        row["smc_host_status"] = ""    # populated below from SMC index
        row["smc_host_name"] = ""
        row["smc_host_ip"] = ""

    # If we just consumed a scan report, fold the L3/L2 results into
    # every lease row, AND promote in-pool scan responders without a
    # lease into the main table (so the operator can pick them for
    # reservation alongside leases). Out-of-pool responders stay in the
    # secondary "Discovered hosts" card below.
    untracked_rows = []
    if scan_report is not None:
        from webapp.dhcp_subnet_scan import classify

        # Pool bounds for "in-scope" decision — defaults to the full
        # subnet when no pool is configured.
        pool_lo = pool_hi = None
        try:
            if scope.dhcp_pool_start and scope.dhcp_pool_end:
                pool_lo = int(ipaddress.ip_address(scope.dhcp_pool_start))
                pool_hi = int(ipaddress.ip_address(scope.dhcp_pool_end))
        except (ValueError, TypeError):
            pool_lo = pool_hi = None

        def _in_pool(ip_str: str) -> bool:
            if pool_lo is None or pool_hi is None:
                return network is not None and ipaddress.ip_address(ip_str) in network
            try:
                v = int(ipaddress.ip_address(ip_str))
                return pool_lo <= v <= pool_hi
            except (ValueError, TypeError):
                return False

        leased_ips: set[str] = set()
        for row in merged:
            ip = row.get("ip", "")
            leased_ips.add(ip)
            hit = scan_report.results.get(ip)
            row["scan_state"] = classify(
                has_lease=True,
                lease_active=(row.get("binding_state") == "active"),
                icmp_reply=bool(hit and hit.icmp_reply),
                arp_reply=bool(hit and hit.arp_reply),
            )
            row["scan_icmp"] = bool(hit and hit.icmp_reply)
            row["scan_arp"] = bool(hit and hit.arp_reply)

        for ip, hit in scan_report.results.items():
            if ip in leased_ips:
                continue
            if not (hit.icmp_reply or hit.arp_reply):
                continue
            res = res_by_ip.get(ip)
            scan_state = classify(
                has_lease=False, lease_active=False,
                icmp_reply=hit.icmp_reply, arp_reply=hit.arp_reply,
            )

            if _in_pool(ip):
                # Promote into the main lease table — the operator can
                # tick the row and add it to reservations like any
                # ordinary lease. Shaped like a lease dict so the same
                # template loop renders it; from_scan=True flips a few
                # column hints.
                merged.append({
                    "ip": ip,
                    "mac": hit.mac,
                    "client_hostname": "",
                    "binding_state": "no-lease",
                    "next_binding_state": "",
                    "starts": None, "ends": None,
                    "seen_on_nodes": [],
                    "reservation_id": res.id if res else None,
                    "reservation_host": res.smc_host_name if res else "",
                    "reservation_ip": res.ip_address if res else "",
                    "reservation_matches": (
                        res is not None and res.ip_address == ip),
                    "scan_icmp": hit.icmp_reply,
                    "scan_arp": hit.arp_reply,
                    "scan_state": scan_state,
                    "from_scan": True,
                })
            else:
                untracked_rows.append({
                    "ip": ip,
                    "mac": hit.mac,
                    "scan_icmp": hit.icmp_reply,
                    "scan_arp": hit.arp_reply,
                    "scan_state": scan_state,
                    "reservation_id": res.id if res else None,
                    "reservation_host": res.smc_host_name if res else "",
                })

        try:
            untracked_rows.sort(
                key=lambda r: tuple(int(p) for p in r["ip"].split(".")))
        except Exception:
            pass

    # ── SMC-Host pre-check for untracked rows ────────────────────────
    #
    # For every lease row that isn't already tracked as a DhcpReservation,
    # compute the planned SMC Host name and look it up in SMC. If SMC
    # already has a Host with that name (left over from a prior
    # deployment), the bulk-reserve action will either ADOPT (same IP)
    # or REFUSE (IP mismatch) — surface that intent here so the operator
    # can see it before ticking the box.
    #
    # One SMC roundtrip per page render (cached via dhcp.hosts.<subnet>
    # for 60s); pulls every Host whose IP is in the scope's subnet and
    # builds a name→view dict for O(1) lookups across N untracked rows.
    untracked_to_check = [r for r in merged
                          if not r.get("reservation_id")
                          and r.get("mac")
                          and r.get("ip")]
    if untracked_to_check and scope.subnet_cidr:
        try:
            smc_host_index = _fetch_smc_host_index_for_scope(scope)
            taken_check: set[str] = set()
            for row in untracked_to_check:
                planned_name = _smc_name_from_lease(
                    row.get("client_hostname", ""),
                    row["mac"],
                    taken_check,
                )
                # NOTE: do NOT add planned_name to taken_check — each row
                # is evaluated independently; the reserve action's
                # disambiguation (-2, -3) only applies within a single
                # POST batch.
                existing = smc_host_index.get(planned_name)
                if existing is None:
                    continue
                row["smc_host_name"] = planned_name
                row["smc_host_ip"] = (existing.address or "").strip()
                if row["smc_host_ip"] == row["ip"]:
                    row["smc_host_status"] = "will_adopt"
                else:
                    row["smc_host_status"] = "name_collision"
        except Exception as exc:
            # Don't fail the leases page if SMC is briefly unreachable —
            # the operator still sees lease state. The bulk-reserve action
            # will surface the real error if they tick a colliding row.
            log.warning("scope_leases: SMC host pre-check failed for "
                        "scope %s: %s", scope.id, exc)

    # Final stable sort by IP (numeric octet tuple) — fixes the
    # lexicographic ordering bug where 192.168.1.6 sorted after
    # 192.168.1.69, and ensures promoted from-scan rows interleave
    # naturally with lease rows.
    try:
        merged.sort(key=lambda r: tuple(
            int(p) for p in (r.get("ip") or "0.0.0.0").split(".")))
    except Exception:
        pass

    # Subnet size — passed to the template so both the modal AND the
    # extra_js polling block can read it without each block re-deriving
    # (Jinja {% set %} is block-scoped; inheritance does not bridge it).
    subnet_size = 0
    if network is not None:
        try:
            subnet_size = max(0, network.num_addresses - 2)
        except Exception:
            subnet_size = 0

    now = datetime.now(timezone.utc)
    return render_template(
        "dhcp/leases.html",
        scope=scope, leases=merged,
        nodes=creds, fetch_errors=fetch_errors,
        now=now, lease_file_path=LEASE_FILE,
        leases_other_subnets=leases_other_subnets,
        subnet_filter_cidr=str(network) if network is not None else "",
        scan_report=scan_report, scan_running=None,
        untracked_rows=untracked_rows,
        subnet_size=subnet_size,
        creds_missing=creds_missing,
        other_domain_creds=other_domain_creds,
        leases_cache_meta=leases_cache_meta,
    )


@dhcp_bp.route("/scopes/<int:scope_id>/scan", methods=["POST"])
@admin_required
def scope_scan(scope_id):
    """Start a background subnet scan from the cluster's primary node.

    Form fields:
      range_mode      one of {scope, subnet, custom}. Default: subnet for
                      <=/24, scope for >/24.
      custom_start    IPv4 (only when range_mode=custom)
      custom_end      IPv4 (only when range_mode=custom)
      accept_warning  '1' acknowledges that >256 hosts will be scanned

    On success, redirects to /leases?scan_id=X. The leases page polls
    /scan/status and switches to the enriched view on completion.
    """
    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    # Match what scope_leases does — derive subnet_cidr from saved
    # gateway/pool when discovery left it empty. Without this, the
    # Full-subnet mode would refuse even though we have enough info.
    _lazy_backfill_subnet_cidr(scope)

    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=scope.domain_id,
                        engine_name=scope.engine_name)
             .order_by(DhcpEngineCredential.node_index).all())
    # Defence in depth — `_scope_with_creds_or_redirect` already filtered
    # the case where no enrolled creds exist, but credentials could have
    # been deleted between the gate-check and this point.
    if not creds:
        flash(f"No SSH credentials enrolled for {scope.engine_name}. "
              f"Enroll each cluster node in Credentials first.", "warning")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))

    primary = next(
        (c for c in creds
         if (c.last_verify_status or "").lower() == "ok"),
        creds[0],
    )

    range_mode = (request.form.get("range_mode") or "subnet").strip().lower()
    custom_start = (request.form.get("custom_start") or "").strip()
    custom_end = (request.form.get("custom_end") or "").strip()
    accept_warning = request.form.get("accept_warning") == "1"

    from webapp.dhcp_subnet_scan import (
        enumerate_subnet_targets, enumerate_range_targets,
        MAX_HOSTS, WARN_THRESHOLD_HOSTS,
    )

    try:
        if range_mode == "scope":
            if not (scope.dhcp_pool_start and scope.dhcp_pool_end):
                flash("Scope has no pool range defined — pick "
                      "Full subnet or Custom range instead.", "warning")
                return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))
            ip_list = enumerate_range_targets(
                scope.dhcp_pool_start, scope.dhcp_pool_end,
                gateway=scope.gateway or "",
                subnet_cidr=scope.subnet_cidr or "",
            )
        elif range_mode == "custom":
            if not (custom_start and custom_end):
                flash("Custom range requires both start and end IPs.",
                      "warning")
                return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))
            ip_list = enumerate_range_targets(
                custom_start, custom_end,
                gateway=scope.gateway or "",
                subnet_cidr=scope.subnet_cidr or "",
            )
        else:  # subnet
            if not scope.subnet_cidr:
                flash("Scope has no subnet CIDR — pick a Custom range.",
                      "warning")
                return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))
            ip_list = enumerate_subnet_targets(
                scope.subnet_cidr, gateway=scope.gateway or "")
    except ValueError as exc:
        flash(f"Invalid scan range: {exc}", "danger")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))

    if not ip_list:
        flash("Resolved range is empty — nothing to scan.", "warning")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))
    if len(ip_list) > MAX_HOSTS:
        flash(f"Range too large ({len(ip_list)} hosts > {MAX_HOSTS} cap). "
              f"Narrow the range and try again.", "danger")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))
    if len(ip_list) > WARN_THRESHOLD_HOSTS and not accept_warning:
        flash(f"Selected range has {len(ip_list)} hosts (> {WARN_THRESHOLD_HOSTS}). "
              f"Tick the confirm box and re-submit.", "warning")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))

    from webapp.dhcp_scan_jobs import start_scan
    user_email = (session.get("user") or {}).get("email", "")
    scan_id = start_scan(
        target=_cred_to_target(primary),
        cred=_cred_to_payload(primary),
        ip_list=ip_list,
        subnet_cidr=scope.subnet_cidr or "",
        scope_id=scope.id,
        user_email=user_email,
        source_node_index=primary.node_index,
        source_node_hostname=primary.hostname,
    )
    _log_activity(
        "scan", "subnet_sweep_started", "ok",
        f"{scope.engine_name}/{scope.subnet_cidr}",
        f"mode={range_mode} targets={len(ip_list)} "
        f"via node{primary.node_index} scan_id={scan_id[:8]}",
    )
    return redirect(url_for("dhcp.scope_leases",
                            scope_id=scope.id, scan_id=scan_id))


@dhcp_bp.route("/scopes/<int:scope_id>/scan/status")
@admin_required
def scope_scan_status(scope_id):
    """JSON poll target. Polled every ~800ms by the leases watcher.

    Returns 404 when the scan_id is unknown / expired / owned by a
    different user. Returns the full status dict otherwise (state,
    progress, total, log_tail, etc. — see dhcp_scan_jobs.get_status).
    """
    scan_id = (request.args.get("id") or "").strip()
    if not scan_id:
        return jsonify({"error": "missing id"}), 400
    from webapp.dhcp_scan_jobs import get_status
    user_email = (session.get("user") or {}).get("email", "")
    status = get_status(scan_id, user_email=user_email)
    if status is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(status)


_SMC_NAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _fetch_smc_host_index_for_scope(scope) -> dict:
    """Return ``{host.name: DhcpHostView}`` for every SMC Host element
    whose IP is inside the scope's subnet.

    Cached via ``smc_cache`` section ``dhcp.hosts.<subnet>`` with the
    Quick TTL (1h by default) — fast enough that operators viewing the
    same scope's leases repeatedly don't pay the SMC roundtrip again.
    The cache is best-effort: cache failure or SMC unavailability bubble
    up as exceptions for the caller to swallow.

    Used by ``scope_leases`` to pre-flag rows whose planned SMC Host
    name already exists (so the operator sees adopt-vs-collide intent
    before clicking "Reserve").
    """
    if not (scope and scope.subnet_cidr):
        return {}
    domain = scope.domain
    if domain is None or domain.api_key is None:
        return {}

    from shared.smc_cache import cache_get_or_fetch, get_quick_ttl

    def _fetch() -> list[dict]:
        cfg = _smc_cfg(domain)
        with smc_session(cfg):
            views = host_list_by_scope(scope.subnet_cidr)
        # Persist as JSON-safe dicts so future Redis swap is mechanical.
        return [
            {"name": v.name, "href": v.href, "address": v.address,
             "mac_address": v.mac_address, "comment": v.comment}
            for v in views
        ]

    cv = cache_get_or_fetch(
        section="dhcp.hosts",
        key_parts=(domain.id, scope.subnet_cidr),
        fetcher=_fetch,
        ttl=get_quick_ttl(),
    )
    # Re-hydrate to lightweight objects that expose the attributes the
    # caller actually reads (.name, .address). Using SimpleNamespace
    # avoids importing the full DhcpHostView dataclass here.
    from types import SimpleNamespace
    return {d["name"]: SimpleNamespace(**d) for d in (cv.data or [])}


def _smc_name_from_lease(hostname: str, mac_norm: str,
                         taken: set[str]) -> str:
    """Build a unique, SMC-safe Host name from a lease's client-hostname + MAC.

    Falls back to ``lease-<mac-stripped>`` when no usable hostname is reported
    by the client. Appends ``-2``, ``-3``, … if the candidate collides with
    another name we've already minted in this batch (``taken``).
    """
    base = (hostname or "").strip()
    if base:
        base = _SMC_NAME_SAFE.sub("-", base).strip("-._")
    if not base:
        base = f"lease-{mac_norm.replace(':', '')}"
    candidate = base
    n = 2
    while candidate in taken:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


@dhcp_bp.route("/scopes/<int:scope_id>/leases/reserve", methods=["POST"])
@admin_required
def scope_leases_reserve(scope_id):
    """Bulk-create reservations from selected lease rows.

    Form payload: repeated ``lease_idx`` values (one per checkbox), and for
    each ``<idx>`` three hidden fields ``lease_<idx>_mac/_ip/_host``. All
    selected entries are validated and created in a single SMC session;
    per-lease failures are collected and surfaced via flash messages without
    aborting the batch.
    """
    scope = _scope_with_creds_or_redirect(scope_id)
    if not scope:
        return redirect(url_for("dhcp.scopes_list"))

    indices = request.form.getlist("lease_idx")
    if not indices:
        flash("No leases selected.", "warning")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))

    # Opt-in: when ticked, name-collision rows (SMC has a Host with the
    # planned name but a DIFFERENT IP) get the existing Host's address
    # updated to match the lease, then adopted as a DhcpReservation.
    # Off by default — refusing-on-collision is the safer behaviour
    # because it doesn't silently overwrite an SMC element's IP.
    fix_collisions = request.form.get("fix_collisions") == "1"

    candidates: list[dict] = []
    seen_mac: set[str] = set()
    seen_ip: set[str] = set()
    skipped: list[str] = []
    for idx in indices:
        mac = request.form.get(f"lease_{idx}_mac", "").strip()
        ip = request.form.get(f"lease_{idx}_ip", "").strip()
        host = request.form.get(f"lease_{idx}_host", "").strip()
        if not mac or not ip:
            skipped.append(f"#{idx}: missing MAC or IP in form payload")
            continue
        if not is_valid_mac(mac):
            skipped.append(f"{mac}: invalid MAC format")
            continue
        try:
            mac_norm = normalize_mac(mac)
        except ValueError:
            skipped.append(f"{mac}: cannot normalize MAC")
            continue
        if mac_norm in seen_mac:
            skipped.append(f"{mac_norm}: duplicate selection in this batch")
            continue
        if ip in seen_ip:
            skipped.append(f"{ip}: duplicate selection in this batch")
            continue
        seen_mac.add(mac_norm)
        seen_ip.add(ip)
        candidates.append({"mac": mac_norm, "ip": ip, "host": host})

    # DB-level conflicts (MAC or IP already reserved on this scope) and
    # subnet-bounds checks happen before opening the SMC session so we can
    # short-circuit empty batches cheaply.
    existing = DhcpReservation.query.filter_by(scope_id=scope.id).all()
    existing_macs = {r.mac_address for r in existing}
    existing_ips = {r.ip_address for r in existing}
    network = None
    if scope.subnet_cidr:
        try:
            network = ip_network(scope.subnet_cidr, strict=False)
        except ValueError:
            network = None

    valid: list[dict] = []
    for c in candidates:
        if c["mac"] in existing_macs:
            skipped.append(f"{c['mac']}: already reserved on this scope")
            continue
        if c["ip"] in existing_ips:
            skipped.append(f"{c['ip']}: already reserved on this scope")
            continue
        if network is not None:
            try:
                if ip_address(c["ip"]) not in network:
                    skipped.append(f"{c['ip']}: outside scope CIDR {scope.subnet_cidr}")
                    continue
            except ValueError:
                skipped.append(f"{c['ip']}: invalid IP")
                continue
        valid.append(c)

    if not valid:
        for s in skipped:
            flash(s, "warning")
        flash("Nothing to add — all selected leases were skipped.", "danger")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))

    # Mint unique SMC Host names up-front so a hostname collision in the
    # same batch is resolved deterministically (-2, -3, ...).
    taken_names: set[str] = set()
    for c in valid:
        c["name"] = _smc_name_from_lease(c["host"], c["mac"], taken_names)
        taken_names.add(c["name"])

    # Phase B.3: scope.domain → ApiKey directly (Domain.api_key has the
    # absorbed server fields; _smc_cfg accepts a Domain).
    domain = scope.domain
    if domain is None or domain.api_key is None:
        flash("Scope has no Domain or ApiKey on file. Re-enroll via Admin Portal.", "danger")
        return redirect(url_for("dhcp.scopes_list"))
    cfg = _smc_cfg(domain)

    created: list[str] = []
    adopted: list[str] = []
    repaired: list[str] = []
    errors: list[str] = []
    try:
        with smc_session(cfg):
            for c in valid:
                target = f"{scope.engine_name}/{scope.interface_id}/{c['name']}"
                try:
                    # Look up the planned name in SMC first. A previous
                    # deployment may have left a Host element with the
                    # same name — re-creating would trip SMC's "element
                    # name must be unique" error. Three outcomes:
                    #   * existing.address == c["ip"]  → adopt it,
                    #     record a DhcpReservation pointing at the
                    #     existing href with status='synced' (SMC
                    #     already has the canonical row).
                    #   * existing.address != c["ip"] AND
                    #     fix_collisions is OFF → refuse cleanly.
                    #   * existing.address != c["ip"] AND
                    #     fix_collisions is ON → update the SMC
                    #     Host's address to the lease IP, then adopt.
                    existing = host_get(c["name"])
                    if existing is not None:
                        existing_ip = (existing.address or "").strip()
                        if existing_ip == c["ip"]:
                            res = DhcpReservation(
                                scope_id=scope.id,
                                smc_host_name=existing.name,
                                smc_host_href=existing.href,
                                ip_address=existing.address,
                                mac_address=c["mac"],
                                status="synced",
                                source="lease",
                            )
                            db.session.add(res)
                            db.session.commit()
                            adopted.append(c["name"])
                            _log_activity(
                                "reservation", "adopt_from_lease", "ok",
                                target,
                                f"existing SMC Host adopted "
                                f"(MAC={c['mac']} IP={c['ip']})",
                            )
                            continue

                        if fix_collisions:
                            # Update the SMC Host's primary address to
                            # the lease IP, then adopt. The name, MAC
                            # marker (in comment), and other fields stay
                            # intact — only the address changes.
                            updated_view = host_update(
                                c["name"], address=c["ip"])
                            res = DhcpReservation(
                                scope_id=scope.id,
                                smc_host_name=updated_view.name,
                                smc_host_href=updated_view.href,
                                ip_address=updated_view.address,
                                mac_address=c["mac"],
                                status="synced",
                                source="lease",
                            )
                            db.session.add(res)
                            db.session.commit()
                            repaired.append(
                                f"{c['name']} ({existing_ip} → {c['ip']})")
                            _log_activity(
                                "reservation",
                                "adopt_with_ip_update", "ok",
                                target,
                                f"SMC Host IP repaired "
                                f"({existing_ip} → {c['ip']}); "
                                f"MAC={c['mac']}",
                            )
                            continue

                        # IP mismatch and the operator didn't tick the
                        # fix-collisions box — refuse rather than
                        # silently overwriting someone else's Host.
                        msg = (
                            f"SMC already has a Host '{c['name']}' "
                            f"with IP {existing_ip or '(blank)'}, "
                            f"but this lease has IP {c['ip']}. "
                            f"Tick 'Fix IP collisions' above to update "
                            f"the existing Host's IP to {c['ip']} and "
                            f"adopt it, OR rename / delete it in SMC "
                            f"Management Client."
                        )
                        errors.append(f"{c['name']} ({c['mac']} → {c['ip']}): {msg}")
                        _log_activity(
                            "reservation", "create_from_lease",
                            "failed", target, msg,
                        )
                        continue

                    view = host_create(
                        name=c["name"],
                        address=c["ip"],
                        mac_address=c["mac"],
                        comment=f"Imported from lease ({c['host'] or 'no hostname'})",
                    )
                    res = DhcpReservation(
                        scope_id=scope.id,
                        smc_host_name=view.name,
                        smc_host_href=view.href,
                        ip_address=view.address,
                        mac_address=c["mac"],
                        status="pending",
                        source="lease",
                    )
                    db.session.add(res)
                    db.session.commit()
                    created.append(c["name"])
                    _log_activity("reservation", "create_from_lease", "ok",
                                  target, f"MAC={c['mac']} IP={c['ip']}")
                except Exception as exc:
                    db.session.rollback()
                    detail = smc_error_detail(exc)
                    errors.append(f"{c['name']} ({c['mac']} → {c['ip']}): {detail}")
                    _log_activity("reservation", "create_from_lease", "failed",
                                  target, detail)
    except Exception as exc:
        flash(f"SMC session failed: {exc}", "danger")
        return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))

    if created:
        flash(f"Created {len(created)} reservation(s) from leases: "
              f"{', '.join(created)}.", "success")
    if adopted:
        flash(
            f"Adopted {len(adopted)} existing SMC Host element(s) from a "
            f"previous deployment (same name + same IP): "
            f"{', '.join(adopted)}. These were re-linked to FlexEdge "
            f"with status 'synced' — no new SMC element was created.",
            "info",
        )
    if repaired:
        flash(
            f"Updated IP on {len(repaired)} existing SMC Host element(s) "
            f"to match the current lease, then adopted: "
            f"{', '.join(repaired)}. The Host name + MAC marker were "
            f"preserved; only the address field changed.",
            "info",
        )
    for s in skipped:
        flash(s, "warning")
    for e in errors:
        flash(e, "danger")
    # If we updated SMC Host addresses, invalidate the cached
    # dhcp.hosts.<subnet> index so the next leases page render reflects
    # the new state (instead of serving stale name_collision badges).
    if repaired:
        try:
            from shared.smc_cache import invalidate
            invalidate("dhcp.hosts", (scope.domain_id, scope.subnet_cidr))
        except Exception:
            pass
    return redirect(url_for("dhcp.scope_leases", scope_id=scope.id))


# ── History + activity ───────────────────────────────────────────────────

@dhcp_bp.route("/history")
@admin_required
def history():
    domain_id = _active_domain_id()
    if domain_id is None:
        deployments = []
    else:
        # DhcpDeployment is keyed via DhcpScope.domain_id. Join through it.
        deployments = (DhcpDeployment.query
                       .join(DhcpScope, DhcpDeployment.scope_id == DhcpScope.id)
                       .filter(DhcpScope.domain_id == domain_id)
                       .order_by(DhcpDeployment.created_at.desc()).limit(200).all())
    return render_template("dhcp/history.html", deployments=deployments)


@dhcp_bp.route("/activity")
@admin_required
def activity():
    """Legacy URL — redirect to the unified /logs page.

    The per-feature activity table is no longer written (everything
    funnels through `shared.logging.audit()` into `platform_logs`).
    Bookmarks land on the new viewer pre-filtered to feature='dhcp'.
    """
    return redirect(url_for("logs_index", feature="dhcp", active_only="1"))


# ── Log retention sweep ─────────────────────────────────────────────────
#
# Activity rows now live in `platform_logs`; the dedicated retention
# sweep on the platform side (`shared.logging.sweep_old_logs`) handles
# them. This local sweep continues to manage `dhcp_deployments` rows
# (per-node push records with sha256 + diff — too rich for platform_logs)
# and the legacy `dhcp_activity_logs` rows that pre-date the unification.
# Phase 0 validation rows are preserved by both paths.
#
# Default retention falls back to the platform setting
# (`platform_settings.log_retention_days`, default 90). Operators can
# still override per-call by passing `retention_days` to the endpoint.

def _platform_retention_days() -> int:
    """Read retention from platform_settings, fallback 90 days."""
    try:
        from shared.logging import current_retention_days
        return current_retention_days()
    except Exception:
        return 90


def sweep_old_logs(retention_days: int | None = None,
                   domain_id: int | None = None) -> dict:
    """Delete deployment + legacy-activity rows older than ``retention_days``.

    When ``domain_id`` is provided, the sweep is scoped to that Domain:

      * `dhcp_deployments` rows are filtered through their parent
        `DhcpScope` (which carries `domain_id`).
      * `platform_logs` rows are filtered by `domain_id` directly via
        `shared.logging.sweep_old_logs`.
      * `dhcp_activity_logs` is the legacy pre-multi-domain table with
        no `domain_id` column. When ``domain_id`` is set, those rows
        are LEFT ALONE (a Domain-scoped sweep must never touch other
        Domains' rows; the legacy table predates the boundary). When
        ``domain_id`` is None (CLI cross-Domain sweep), the legacy
        rows are purged as before.

    Returns a summary dict of how many rows were removed per table.
    """
    if retention_days is None:
        retention_days = _platform_retention_days()
    if retention_days <= 0:
        raise ValueError("retention_days must be positive")
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    if domain_id is None:
        activity_deleted = (
            DhcpActivityLog.query
            .filter(DhcpActivityLog.created_at < cutoff)
            .filter(~((DhcpActivityLog.category == PHASE0_CATEGORY) &
                      (DhcpActivityLog.action == PHASE0_ACTION)))
            .delete(synchronize_session=False)
        )
    else:
        # Legacy table has no domain_id — skip when scoped.
        activity_deleted = 0

    deployments_q = DhcpDeployment.query.filter(
        DhcpDeployment.created_at < cutoff)
    if domain_id is not None:
        deployments_q = (deployments_q
                         .join(DhcpScope, DhcpScope.id == DhcpDeployment.scope_id)
                         .filter(DhcpScope.domain_id == domain_id))
    deployments_deleted = deployments_q.delete(synchronize_session=False)
    db.session.commit()

    # Also sweep the platform-wide log table — same Domain scope.
    from shared.logging import sweep_old_logs as platform_sweep
    plog_result = platform_sweep(retention_days, domain_id=domain_id)
    platform_deleted = plog_result.get("deleted", 0)

    summary = {
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
        "domain_id": domain_id,
        "activity_deleted": activity_deleted,
        "deployments_deleted": deployments_deleted,
        "platform_log_deleted": platform_deleted,
    }
    scope_note = (f"domain_id={domain_id}" if domain_id is not None
                  else "all Domains")
    _log_activity("system", "log_retention_sweep", "ok",
                  target=f"retention={retention_days}d",
                  detail=(f"Deleted {activity_deleted} legacy activity row(s), "
                          f"{deployments_deleted} deployment row(s), "
                          f"{platform_deleted} platform_logs row(s) older "
                          f"than {cutoff.isoformat()} ({scope_note}). "
                          f"Phase 0 validation rows preserved."))
    return summary


@dhcp_bp.route("/system/sweep-logs", methods=["POST"])
@admin_required
def system_sweep_logs():
    """Operator-triggered log retention sweep. Defaults to 90-day retention.

    Override via form field ``retention_days`` (positive integer). Useful
    targets: ad-hoc cleanup, or a scheduled agent calling this endpoint.
    """
    default_retention = _platform_retention_days()
    try:
        retention = int(request.form.get("retention_days", default_retention))
    except (TypeError, ValueError):
        flash("Invalid retention_days — must be a positive integer.", "danger")
        return redirect(url_for("dhcp.activity"))
    if retention <= 0:
        flash("retention_days must be ≥ 1.", "danger")
        return redirect(url_for("dhcp.activity"))

    # Domain-scoped sweep: the operator's button only ever wipes the
    # active Domain's rows. Cross-Domain sweeps run via the CLI helper.
    domain_id = _active_domain_id()
    if domain_id is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("dhcp.activity"))
    try:
        summary = sweep_old_logs(retention, domain_id=domain_id)
    except Exception as exc:
        _log_activity("system", "log_retention_sweep", "failed",
                      target=f"retention={retention}d", detail=str(exc))
        flash(f"Sweep failed: {exc}", "danger")
        return redirect(url_for("dhcp.activity"))

    flash(
        f"Retention sweep ok — removed {summary['activity_deleted']} "
        f"activity row(s) and {summary['deployments_deleted']} deployment "
        f"row(s) older than {retention} days.",
        "success",
    )
    return redirect(url_for("dhcp.activity"))


# ── AJAX helpers ─────────────────────────────────────────────────────────

@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys")
@admin_required
def api_tenant_keys(tenant_id):
    # Domain-scope guard: the active Domain's API key must belong to the
    # tenant in the URL. Otherwise an admin in Domain A could enumerate
    # Domain B's API keys via URL crafting.
    domain = getattr(g, "domain", None)
    if (domain is None
            or getattr(domain, "api_key", None) is None
            or domain.api_key.tenant_id != tenant_id):
        return jsonify({"error": "cross-Domain access refused"}), 403
    # Narrow further to the active Domain's bound key — every legitimate
    # cascade only ever needs that one row.
    keys = (ApiKey.query
            .filter_by(tenant_id=tenant_id, is_active=True)
            .filter(ApiKey.id == domain.api_key_id)
            .all())
    return jsonify([{"id": k.id, "name": k.name} for k in keys])


@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines")
@admin_required
def api_tenant_engines(tenant_id, key_id):
    guard = _assert_active_domain_match(tenant_id, key_id)
    if guard is not None:
        return guard
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    # `domain_objects.engines` calls `smc_client.smc_session(cfg)` which
    # expects a DICT-shaped cfg, not the SMCConfig dataclass.
    cfg = _smc_cfg_dict(tenant, api_key)
    try:
        # Phase 0 cross-feature reuse: hit the same ``engines`` cache
        # section that /engines/clusters populates. Visiting Clusters
        # first → instant cascade load here, no second SMC roundtrip.
        from webapp import domain_objects
        domain = getattr(g, "domain", None)
        engines_list, _cv = domain_objects.engines(domain, cfg)
        # Keep the legacy cascade payload shape the JS consumer expects
        # (name/type/href + a sources marker so debug paths stay happy).
        engines_payload = [
            {"name": e.name, "type": e.typeof, "href": e.href,
             "sources": ["cache"]}
            for e in engines_list
        ]
        return jsonify(engines_payload)
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/<engine_name>/interfaces/debug")
@admin_required
def api_engine_interfaces_debug(tenant_id, key_id, engine_name):
    """Return the raw physical_interface JSON plus what the parser extracted.

    Use this when scope discovery returns 0 to inspect the actual shape of
    the SMC API payload (it varies slightly between engine types / versions).
    """
    guard = _assert_active_domain_match(tenant_id, key_id)
    if guard is not None:
        return guard
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg(tenant, api_key)
    try:
        with smc_session(cfg):
            payload = dump_engine_interfaces(engine_name)
        return jsonify(payload)
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/<engine_name>/contact-addresses/debug")
@admin_required
def api_engine_contact_addresses_debug(tenant_id, key_id, engine_name):
    """P1 diagnostic — dump every contact address FEA sees for this engine.

    Surfaces all three sources so the operator can pinpoint which one
    SMC actually carries the public IP on:

      * ``engine_level`` — what ``engine.contact_addresses`` returns,
        keyed by ``(interface_id, interface_ip)``.
      * ``inline_per_interface`` — what we extract from each
        IPv4 / IPv6 interface's own ``contact_addresses`` block inside
        the physical_interface payload.
      * ``joined_nodes`` — the final per-node view after `list_cluster_nodes`
        merges the two sources. This is what the credentials wizard
        consumes.

    Hit URL (substitute IDs):
      ``/dhcp/api/tenants/<tid>/api-keys/<kid>/engines/<engine>/contact-addresses/debug``

    Returns JSON only — paste it back so we can confirm SMC's payload
    shape matches the parser without touching prod data.
    """
    guard = _assert_active_domain_match(tenant_id, key_id)
    if guard is not None:
        return guard
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    cfg = _smc_cfg(tenant, api_key)
    try:
        from smc.core.engine import Engine
        from webapp.smc_dhcp_client import (
            _build_contact_address_map, _parse_inline_contact_addresses,
            list_cluster_nodes,
        )
        with smc_session(cfg):
            engine = Engine(engine_name)

            # 1) Engine-level map (the SDK's `engine.contact_addresses`).
            # Capture EVERY attribute on each ContactAddressNode so we can
            # see what SMC actually serializes regardless of SDK version.
            try:
                engine_level_raw = []
                for ca in engine.contact_addresses:
                    entry = {}
                    # All public-ish attributes we recognize:
                    for key in ("interface_id", "interface_ip", "location",
                                "location_ref", "location_name", "dynamic",
                                "addresses", "address"):
                        try:
                            v = getattr(ca, key, None)
                            if v is None:
                                continue
                            if isinstance(v, (list, tuple, set)):
                                entry[key] = [str(x) for x in v]
                            else:
                                entry[key] = str(v)
                        except Exception as exc:
                            entry[f"{key}__error"] = str(exc)
                    # Materialise ca.data (the ElementCache) into a
                    # real dict so the diagnostic shows the on-wire
                    # JSON, not just `<ElementCache at 0x...>`.
                    # Accessing ca.data triggers the lazy fetch the
                    # first time round.
                    try:
                        raw = getattr(ca, "data", None)
                        if raw is not None:
                            if hasattr(raw, "data") and isinstance(raw.data, dict):
                                entry["__raw_data"] = dict(raw.data)
                            else:
                                try:
                                    entry["__raw_data"] = dict(raw)
                                except (TypeError, ValueError):
                                    entry["__raw_data_repr"] = str(raw)
                    except Exception as exc:
                        entry["__raw_data_error"] = (
                            f"{type(exc).__name__}: {exc}"
                        )
                    entry["__class__"] = type(ca).__name__
                    # Also surface the wrapper's public attributes so
                    # we can see whether `addresses` etc. exist.
                    try:
                        entry["__public_attrs"] = sorted(
                            a for a in dir(ca)
                            if not a.startswith("_")
                            and not callable(getattr(ca, a, None))
                        )
                    except Exception:
                        pass
                    engine_level_raw.append(entry)
            except Exception as exc:
                engine_level_raw = [{"error": str(exc),
                                     "exc_type": type(exc).__name__}]
            engine_level_parsed = _build_contact_address_map(engine)

            # 1a) Raw engine payload — slice down to anything that might
            # carry contact addresses, so we don't blast the operator
            # with a 50 KB dump but still get a clear picture.
            raw_engine_subset = {}
            try:
                eng_data = (engine.data.data if hasattr(engine.data, "data")
                            else dict(engine.data))
                # Look for any top-level key containing "contact" — that
                # surfaces whatever SMC serialized regardless of how the
                # SDK chose to expose it.
                raw_engine_subset = {
                    k: v for k, v in eng_data.items()
                    if "contact" in k.lower()
                }
                # Also dump the link relations so we can see if there's
                # a `contact_addresses` sub-resource the SDK should be
                # fetching (and tell whether we're hitting it).
                links = []
                for ln in (eng_data.get("link") or []):
                    rel = ln.get("rel") or ""
                    if "contact" in rel.lower():
                        links.append(ln)
                if links:
                    raw_engine_subset["__contact_links"] = links
            except Exception as exc:
                raw_engine_subset = {"error": str(exc),
                                     "exc_type": type(exc).__name__}

            # 2) Inline-per-interface — walk each physical_interface
            # payload looking for inline `contact_addresses` blocks.
            inline_per_interface = []
            for phys in engine.physical_interface:
                try:
                    data = (phys.data.data if hasattr(phys.data, "data")
                            else dict(phys.data))
                except Exception:
                    continue
                _collect_inline_contacts(data, "", inline_per_interface,
                                        _parse_inline_contact_addresses)

            # 3) Joined view — what the wizard ends up seeing. Also
            # includes the per-node SSH-daemon state probe with
            # verbose=True so EVERY field SMC returns (not just those
            # whose name contains "ssh") shows up in raw_signals. We
            # need this dump to figure out which field SMC 7.1
            # actually carries the daemon state in.
            from webapp.smc_dhcp_client import get_node_ssh_state
            joined_nodes = []
            for n in list_cluster_nodes(engine_name):
                joined_nodes.append({
                    "node_index": n.node_index,
                    "node_id": n.node_id,
                    "name": n.name,
                    "ssh_state": get_node_ssh_state(
                        engine_name, n.node_index, verbose=True,
                    ),
                    "addresses": [
                        {
                            "interface_id": a.interface_id,
                            "address": a.address,
                            "is_primary_mgt": a.is_primary_mgt,
                            "reverse_connection": a.reverse_connection,
                            "contact_addresses": a.contact_addresses,
                        }
                        for a in n.addresses
                    ],
                })

        return jsonify({
            "engine_name": engine_name,
            "engine_level": {
                "raw_from_sdk": engine_level_raw,
                "parsed_map": {
                    f"{k[0]}@{k[1]}": v
                    for k, v in engine_level_parsed.items()
                },
            },
            "raw_engine_payload_contact_keys": raw_engine_subset,
            "inline_per_interface": inline_per_interface,
            "joined_nodes": joined_nodes,
        })
    except Exception as exc:
        log.exception("contact-addresses debug failed")
        return jsonify({"error": smc_error_detail(exc)}), 500


def _collect_inline_contacts(level_payload: dict, parent_iface_id: str,
                             out_list: list, parser) -> None:
    """Recurse the physical_interface payload, append every inline-
    contact-address occurrence with its interface_id path so the
    diagnostic JSON shows exactly where SMC keeps the public IP.
    """
    iface_id = (parent_iface_id
                or str(level_payload.get("interface_id") or ""))
    for entry in level_payload.get("interfaces", []) or []:
        for inner_kind, inner in entry.items():
            if inner_kind not in ("single_node_interface", "node_interface"):
                continue
            if not isinstance(inner, dict):
                continue
            parsed = parser(inner)
            if not parsed:
                continue
            out_list.append({
                "interface_id": iface_id,
                "inner_kind": inner_kind,
                "real_ip": inner.get("address") or "",
                "nodeid": inner.get("nodeid"),
                "raw_inline": inner.get("contact_addresses")
                              or inner.get("contact_address"),
                "parsed": parsed,
            })
    vlans = (level_payload.get("vlanInterfaces")
             or level_payload.get("vlan_interfaces") or [])
    for vlan_wrap in vlans:
        vlan = vlan_wrap.get("physical_interface") or vlan_wrap
        vlan_raw_id = vlan.get("interface_id", "")
        combined = f"{iface_id}.{vlan_raw_id}" if vlan_raw_id else iface_id
        _collect_inline_contacts(vlan, combined, out_list, parser)


@dhcp_bp.route("/api/tenants/<int:tenant_id>/api-keys/<int:key_id>/engines/<engine_name>/scopes")
@admin_required
def api_engine_scopes(tenant_id, key_id, engine_name):
    """AJAX preview cascade for the discover form.

    Read-only SMC walk surfaced via the shared ``scopes`` cache section
    (Loose 24h TTL). The discover-and-save POST below invalidates this
    section so the next preview reflects what was just written.
    """
    guard = _assert_active_domain_match(tenant_id, key_id)
    if guard is not None:
        return guard
    tenant = db.session.get(Tenant, tenant_id)
    api_key = db.session.get(ApiKey, key_id)
    if not tenant or not api_key:
        return jsonify({"error": "Not found"}), 404
    # Two cfg shapes: domain_objects.* takes a DICT (smc_client backend);
    # smc_session below takes the SMCConfig DATACLASS (smc_tls_client backend).
    cfg = _smc_cfg(tenant, api_key)
    cfg_dict = _smc_cfg_dict(tenant, api_key)
    try:
        from webapp import domain_objects
        domain = getattr(g, "domain", None)
        scope_dicts, _cv = domain_objects.scopes(domain, cfg_dict, engine_name)
        # Cluster-node list isn't cache-shared yet (different shape than
        # cluster_detail's nodes — this one returns NDI primary addresses).
        # Keep live for now.
        with smc_session(cfg):
            nodes = list_cluster_nodes(engine_name)
        return jsonify({
            "scopes": [
                {
                    "interface_id": s.get("interface_id", ""),
                    "interface_label": s.get("interface_label", ""),
                    "subnet_cidr": s.get("subnet_cidr", ""),
                    "gateway": s.get("gateway", ""),
                    "dhcp_pool_start": s.get("dhcp_pool_start", ""),
                    "dhcp_pool_end": s.get("dhcp_pool_end", ""),
                    "default_lease_time": s.get("default_lease_time", ""),
                } for s in scope_dicts
            ],
            "nodes": [
                {
                    "node_index": n.node_index,
                    "node_id": n.node_id,
                    "name": n.name,
                    "primary_address": n.primary_address,
                } for n in nodes
            ],
        })
    except Exception as exc:
        return jsonify({"error": smc_error_detail(exc)}), 500


# ── Validation ───────────────────────────────────────────────────────────

def _validate_reservation(scope, name, address, mac, ipv6, secondary,
                          exclude_reservation_id):
    errors: list[str] = []
    if not name:
        errors.append("Name is required.")
    if not address:
        errors.append("Address is required.")
    if not mac or not is_valid_mac(mac):
        errors.append("MAC address is required in the form aa:bb:cc:dd:ee:ff.")

    # IP in scope CIDR?
    if scope.subnet_cidr:
        try:
            net = ip_network(scope.subnet_cidr, strict=False)
            if address and ip_address(address) not in net:
                errors.append(
                    f"IP {address} is outside the scope CIDR {scope.subnet_cidr}."
                )
        except ValueError:
            pass

    # Secondary addresses
    for s in secondary:
        try:
            ip_address(s)
        except ValueError:
            errors.append(f"Invalid secondary IP: {s!r}.")

    # IPv6 optional
    if ipv6:
        try:
            ip_address(ipv6)
        except ValueError:
            errors.append(f"Invalid IPv6 address: {ipv6!r}.")

    # DB-level uniqueness in scope
    if not errors and mac:
        try:
            mac_norm = normalize_mac(mac)
        except ValueError:
            mac_norm = mac
        q = DhcpReservation.query.filter_by(scope_id=scope.id, mac_address=mac_norm)
        if exclude_reservation_id is not None:
            q = q.filter(DhcpReservation.id != exclude_reservation_id)
        if q.first():
            errors.append(f"MAC {mac_norm} is already reserved in this scope.")

        q2 = DhcpReservation.query.filter_by(scope_id=scope.id, ip_address=address)
        if exclude_reservation_id is not None:
            q2 = q2.filter(DhcpReservation.id != exclude_reservation_id)
        if q2.first():
            errors.append(f"IP {address} is already reserved in this scope.")

    return errors
