"""
FlexEdgeAdmin — Engines Blueprint.

Top-level "Engines" section of the web UI:

    /engines/clusters             read-only list of all engines
    /engines/clusters/<name>      cluster detail (summary + nodes table)
    /engines/credentials          redirect to /dhcp/credentials
    /engines/tools                tools landing
    /engines/tools/scan           Scan tool (Phase C — placeholder for now)
    /engines/nodes/<cred_id>/terminal  in-browser SSH terminal (Phase B)

Phase A: Clusters / Nodes views (read-only). Terminal icon is rendered
but disabled until Phase B is enabled.

Phase B: WebSocket terminal route lives in webapp/engine_terminal.py
and is wired in via init_engines_manager() at app startup.
"""

from __future__ import annotations

import logging
from functools import wraps

from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, session, request, jsonify, Response, send_file, abort,
)

from shared.db import db
from webapp.models import (
    ApiKey, DhcpEngineCredential, EngineSginfoCollection, Tenant,
)
import engine_inquiry

log = logging.getLogger(__name__)

engines_bp = Blueprint("engines", __name__, url_prefix="/engines")


# ── Access control (mirrors DHCP/TLS pattern) ────────────────────────────

def admin_required(f):
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


def profile_required_admin(f):
    """Combine admin-role + active SMC profile/domain."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("auth.login", next=request.url))
        import user_manager
        if not user_manager.is_admin(session["user"].get("email", "")):
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        if "active_profile" not in session:
            flash("Select an SMC profile to continue.", "warning")
            return redirect(url_for("select_profile"))
        if "active_domain" not in session:
            flash("Select an SMC domain to continue.", "warning")
            return redirect(url_for("select_domain"))
        return f(*args, **kwargs)
    return decorated


# ── Helpers ──────────────────────────────────────────────────────────────

def _user_cfg() -> dict:
    """Build the dict-shaped SMC config from the current session.

    Mirrors ``app.get_user_cfg()`` — duplicated here to avoid importing
    from app.py (circular import on blueprint registration).
    """
    profile = session.get("active_profile") or {}
    if not profile:
        raise ValueError("No SMC profile selected.")
    return {
        "smc_url":      profile["smc_url"],
        "api_key":      profile["api_key"],
        "verify_ssl":   profile.get("verify_ssl", False),
        "timeout":      profile.get("timeout", 120),
        "domain":       session.get("active_domain"),
        "retry_on_busy": True,
    }


def _current_domain():
    """Phase B.2: return the active Domain for this request.

    `g.domain` is populated by the `_resolve_active_domain` before-request
    hook in app.py — the slug in `session["active_profile"]["tenant"]`
    resolves a Domain row directly (Phase A migrated each Tenant.slug onto
    the derived Domain.slug, preserving CLI back-compat).
    """
    from flask import g
    return getattr(g, "domain", None)


def list_tcp_services_for_picker(domain_id: int, cfg: dict) -> list[dict]:
    """Picker-ready TCP service list from cached SMC tcp_services.

    Returns ``[{"name": "HTTPS", "port_low": 443, "port_high": 443,
    "label": "443 · HTTPS", "search": "https 443"}, ...]`` sorted by
    name (case-insensitive). UDP services are intentionally excluded —
    the scan tool is TCP-only in v1. Catch-all ranges (>256 ports)
    are skipped because expanding "TCP All" (1-65535) into the
    operator's port list would never be what they meant.

    Uses the same ``smc.explorer.tcp_services`` cache section as
    ``resolve_port_services`` (key ``(domain_id, "", "")``) so a
    single cache miss serves both helpers. Empty list on any failure
    — picker degrades gracefully to typing-only input.
    """
    from shared.smc_cache import cache_get_or_fetch, get_quick_ttl
    from webapp import smc_client

    if not cfg:
        return []

    def _fetch():
        with smc_client.smc_session(cfg):
            return smc_client.list_elements("tcp_services")

    try:
        cv = cache_get_or_fetch(
            section="smc.explorer.tcp_services",
            key_parts=(domain_id, "", ""),
            fetcher=_fetch,
            ttl=get_quick_ttl(),
        )
        elements = cv.data or []
    except Exception as exc:
        log.warning("tcp_services picker fetch failed: %s", exc)
        return []

    out: list[dict] = []
    for elem in elements:
        name = (elem.get("name") or "").strip()
        if not name:
            continue
        try:
            lo = int(elem.get("min_dst_port") or 0)
            hi = int(elem.get("max_dst_port") or lo)
        except (TypeError, ValueError):
            continue
        if lo < 1 or hi < lo or hi > 65535:
            continue
        if (hi - lo) > 256:
            continue
        if hi == lo:
            label = f"{lo} · {name}"
        else:
            label = f"{lo}-{hi} · {name}"
        out.append({
            "name": name,
            "port_low": lo,
            "port_high": hi,
            "label": label,
            "search": f"{name} {lo} {hi}".lower(),
        })
    out.sort(key=lambda r: r["name"].lower())
    return out


def resolve_port_services(domain_id: int, cfg: dict) -> dict[int, str]:
    """Build a ``{port: service_name}`` map from cached SMC tcp/udp_services.

    Reuses the SMC Explorer cache sections (``smc.explorer.tcp_services``
    / ``smc.explorer.udp_services``, key ``(domain_id, "", "")``) so the
    lookup is free if the operator has already visited
    ``/browse/tcp_services`` in the last hour, and lives off the queue
    runner's auto-invalidation otherwise. Empty dict on failure — caller
    falls back to bare port numbers in the result table.

    Two passes: range services first, single-port services second so a
    specific name (``HTTPS`` = 443) overrides a range catch-all (``Web``
    = 80-89). Ranges wider than 256 ports are skipped entirely — those
    are usually "TCP All" / "all-ports" categories that would clobber
    every well-known port name and reduce signal.

    ``cfg`` is the dict-shaped SMC config the caller already builds for
    its own routes. Passing it in keeps this helper module-agnostic so
    callers in different blueprints (engines, scan_history) don't pull
    each other in.
    """
    from shared.smc_cache import cache_get_or_fetch, get_quick_ttl
    from webapp import smc_client

    if not cfg:
        return {}

    def _make_fetcher(tk: str):
        def _f():
            with smc_client.smc_session(cfg):
                return smc_client.list_elements(tk)
        return _f

    elements: list[dict] = []
    for type_key in ("tcp_services", "udp_services"):
        try:
            cv = cache_get_or_fetch(
                section=f"smc.explorer.{type_key}",
                key_parts=(domain_id, "", ""),
                fetcher=_make_fetcher(type_key),
                ttl=get_quick_ttl(),
            )
            elements.extend(cv.data or [])
        except Exception as exc:
            log.warning("port_services lookup (%s) failed: %s",
                        type_key, exc)

    out: dict[int, str] = {}
    for want_single in (False, True):
        for elem in elements:
            name = (elem.get("name") or "").strip()
            if not name:
                continue
            try:
                lo = int(elem.get("min_dst_port") or 0)
                hi = int(elem.get("max_dst_port") or lo)
            except (TypeError, ValueError):
                continue
            if lo < 1 or hi < lo or hi > 65535:
                continue
            is_single = (hi == lo)
            if is_single != want_single:
                continue
            if not is_single and (hi - lo) > 256:
                continue
            for port in range(lo, hi + 1):
                out[port] = name
    return out


def _credentials_for_engine(domain_id: int, engine_name: str) -> dict[int, DhcpEngineCredential]:
    """Map SMC's 1-based ``nodeid`` -> DhcpEngineCredential.

    The cluster_detail template looks up creds via
    ``creds_by_node.get(n.nodeid)``, where ``n.nodeid`` is
    ``engine_inquiry.NodeInfo.nodeid`` — an integer pulled from the SDK
    and 1-based by SMC convention (cluster member 1, member 2, ...).

    What we store on the credential row is different:

      * ``node_index`` — 0-based, the Python loop index from
        ``enumerate(engine.nodes)`` at enrollment.
      * ``node_id`` — opaque SMC href-tail / element key (e.g. "47780").
        Looks numeric but is **not** the cluster member nodeid.

    Mapping rule: ``node_index + 1`` IS the SMC 1-based nodeid. We used
    to also try ``int(node_id)`` as a fallback, but that misfired when
    SMC's href tails were numeric — they got mistaken for cluster
    member IDs and the Terminal button stayed grey forever.
    """
    rows = (DhcpEngineCredential.query
            .filter_by(domain_id=domain_id, engine_name=engine_name)
            .all())
    out: dict[int, DhcpEngineCredential] = {}
    for r in rows:
        key = int(getattr(r, "node_index", 0)) + 1
        out[key] = r
    return out


# ── Routes ───────────────────────────────────────────────────────────────

@engines_bp.route("/")
def index():
    """Default landing — bounce to clusters."""
    return redirect(url_for("engines.clusters"))


@engines_bp.route("/clusters")
@profile_required_admin
def clusters():
    """Read-through cached engines list.

    Cache key bundles tenant_id + domain + a short SHA256 of the API
    key (never the plaintext) so concurrent users on different
    tenants/domains never see each other's data. Cache is process-local;
    the operator forces a live SMC fetch via ``?refresh=1`` (wired to
    the "Refresh from SMC" button on the page).
    """
    import hashlib
    from shared.smc_cache import (
        cache_get_or_fetch, invalidate, get_loose_ttl,
    )
    from webapp.models import DhcpEngineSshAccess

    try:
        cfg = _user_cfg()
        domain_obj = _current_domain()
        domain_id = domain_obj.id if domain_obj else 0
        refresh_requested = (request.args.get("refresh") == "1")

        # Q5 family-wide refresh: refreshing the engines list also clears
        # every cached cluster_detail entry for THIS Domain. Operator's
        # mental model is "give me current data on the whole engines
        # feature" — narrow per-section refresh would force them to also
        # click Refresh on every cluster_detail page they later visit.
        if refresh_requested:
            invalidate("engines.detail")

        cv = cache_get_or_fetch(
            section="engines.list",
            # Phase B.2: domain_id alone identifies (server, smc-domain, key)
            # — replaces the legacy (tenant_id, domain_name, api_key_hash) tuple.
            key_parts=(domain_id,),
            fetcher=lambda: engine_inquiry.list_clusters(cfg),
            ttl=get_loose_ttl(),       # Loose refresh — read-only inventory
            refresh=refresh_requested,
        )
        # Surface which engines have FlexEdge state (creds and/or SSH
        # rule) so the template can show a "Forget" button only when
        # the operator has something to clean up.
        managed_engine_names: set[str] = set()
        if domain_id:
            for c in (DhcpEngineCredential.query
                      .filter_by(domain_id=domain_id).all()):
                managed_engine_names.add(c.engine_name)
            for a in (DhcpEngineSshAccess.query
                      .filter_by(domain_id=domain_id).all()):
                managed_engine_names.add(a.engine_name)
    except Exception as exc:
        log.error("clusters list failed: %s", exc)
        return render_template("error.html", message=str(exc))
    return render_template(
        "engines/clusters.html",
        engines=cv.data,
        cache_meta=cv,
        managed_engine_names=managed_engine_names,
        active_tenant=domain_obj,   # template renders .name — Domain has display_name; alias below
        active_domain=cfg.get("domain") or "",
    )


@engines_bp.route("/clusters/<path:engine_name>/forget", methods=["POST"])
@profile_required_admin
def cluster_forget(engine_name):
    """Forget an engine on the FlexEdgeAdmin side.

    Cleanup:
      1. Delete every ``DhcpEngineCredential`` row for this engine
         (DB-only; nothing to revoke on the engine itself — passwords
         stored here are encrypted secrets).
      2. If a ``DhcpEngineSshAccess`` row exists, remove the SMC rule
         it tracks + the helper Host elements + upload the policy, then
         delete the row.
      3. Invalidate the engines.list cache so the operator's next page
         load reflects the cleaned state.

    The engine itself is **not** affected — it remains in SMC,
    reachable through SMC Management Client, with its production
    policies intact. This is purely a FlexEdge-side cleanup.
    """
    from webapp.models import DhcpEngineSshAccess
    from webapp.smc_dhcp_client import (
        smc_session as smc_dhcp_session,
        remove_ssh_access_rule, policy_upload,
        SMCConfig as DhcpSMCConfig,
    )
    from shared.smc_cache import invalidate

    domain_obj = _current_domain()
    if domain_obj is None:
        flash("No active domain — pick one first.", "warning")
        return redirect(url_for("engines.clusters"))

    creds_to_delete = (DhcpEngineCredential.query
                       .filter_by(domain_id=domain_obj.id, engine_name=engine_name)
                       .all())
    access = (DhcpEngineSshAccess.query
              .filter_by(domain_id=domain_obj.id, engine_name=engine_name)
              .first())

    if not creds_to_delete and not access:
        flash(f"No FlexEdge state on record for engine '{engine_name}'.",
              "info")
        return redirect(url_for("engines.clusters"))

    cred_count = len(creds_to_delete)
    rule_summary = ""
    rule_remove_warning = ""

    # Step 1: SMC-side cleanup of the rule (if any). Done first so a
    # failure here doesn't leave us with orphan SMC state and no DB
    # record pointing at it.
    if access:
        # Need an ApiKey to log into SMC. Use the one tracked on the
        # access row — that's the key originally used to create the rule.
        api_key = db.session.get(ApiKey, access.api_key_id) if access.api_key_id else None
        if api_key is None:
            rule_remove_warning = (
                f"Tenant's API key for the rule is gone — cannot log "
                f"into SMC to remove rule {access.rule_name!r}. "
                f"DB-only cleanup proceeding; remove the rule manually "
                f"in SMC Management Client."
            )
        else:
            # Phase B.2: pull server config from the ApiKey directly
            # (Phase A absorbed those fields onto api_keys).
            cfg = DhcpSMCConfig(
                url=api_key.smc_url,
                api_key=api_key.decrypted_key,
                domain=domain_obj.smc_domain_name or "",
                api_version=api_key.api_version or "",
                verify_ssl=api_key.verify_ssl,
                timeout=api_key.timeout,
            )
            try:
                with smc_dhcp_session(cfg):
                    rule_existed, msg = remove_ssh_access_rule(
                        access.policy_name, access.rule_name)
                    upload_ok = True
                    upload_msg = ""
                    if rule_existed:
                        upload_msg_raw = policy_upload(
                            access.engine_name, access.policy_name)
                        upload_msg = str(upload_msg_raw)
                rule_summary = (
                    f"removed rule {access.rule_name!r}; "
                    f"upload={upload_msg!r}"
                    if rule_existed else
                    f"rule {access.rule_name!r} was already gone"
                )
            except Exception as exc:
                rule_remove_warning = (
                    f"SMC-side cleanup FAILED for rule "
                    f"{access.rule_name!r}: {exc}. DB cleanup will NOT "
                    f"proceed so you can retry. Remove the rule "
                    f"manually in SMC GUI if needed, then click Forget "
                    f"again to clear the DB."
                )
                _log_activity_engines(
                    "engines", "forget", "failed",
                    target=engine_name, detail=str(exc),
                )
                flash(rule_remove_warning, "danger")
                return redirect(url_for("engines.clusters"))

    # Step 2: DB cleanup — creds first, then access row.
    for c in creds_to_delete:
        db.session.delete(c)
    if access:
        db.session.delete(access)
    db.session.commit()

    # Step 3: cache invalidation so the next page load is fresh.
    # Drop both the engines list AND this engine's detail entry — the
    # Forget button is the canonical "I'm done with this engine" signal,
    # so any cached deeper view of it is stale.
    invalidate("engines.list")
    invalidate("engines.detail", (domain_obj.id, engine_name))

    detail = (f"creds_deleted={cred_count} "
              f"access_deleted={'yes' if access else 'no'} "
              f"{rule_summary}")
    _log_activity_engines("engines", "forget", "ok",
                          target=engine_name, detail=detail)

    msg_parts = [
        f"Forgot engine '{engine_name}' on the FlexEdge side.",
        f"Deleted {cred_count} credential row(s).",
    ]
    if access:
        msg_parts.append(rule_summary or "Removed SMC rule.")
    if rule_remove_warning:
        msg_parts.append(rule_remove_warning)
    flash(" ".join(msg_parts), "success" if not rule_remove_warning else "warning")
    return redirect(url_for("engines.clusters"))


def _log_activity_engines(category, action, status, target="", detail=""):
    """Engines audit-log entry — funnels through the platform log writer.

    Per the standing rule (memory: feedback_logging_standing_rule), every
    feature emits via `shared.logging.audit()`. Engines-namespace rows
    use `feature='engines'`; the legacy category+action pair is composed
    into the platform action string for backwards compatibility with
    existing readers that grep by action name.
    """
    from shared.logging import audit
    audit(feature="engines",
          action=f"{category}.{action}",
          target=target, detail=detail, status=status)


@engines_bp.route("/clusters/<path:engine_name>")
@profile_required_admin
def cluster_detail(engine_name):
    """Render a single cluster's full detail page.

    Cached read-through ([shared/smc_cache.py](shared/smc_cache.py),
    section ``engines.detail``, **Loose refresh** (24 h default) per
    the operator's TTL rule — this is read-only inventory FlexEdge
    doesn't mutate. The ``?refresh=1`` query param drives the in-page
    Refresh-from-SMC button. Cache key is ``(domain_id, engine_name)``
    so two Domains pointing at the same SMC don't share entries.

    All work — SMC fetch, DB credential lookup, template render — is wrapped
    in a single try/except. Any exception bubbles up to a friendly
    ``error.html`` page instead of Flask's bare 500 default, *and* gets
    logged with stack trace so we can diagnose without operator screenshots.
    """
    from shared.smc_cache import cache_get_or_fetch, get_loose_ttl

    try:
        cfg = _user_cfg()
        domain_obj = _current_domain()
        domain_id = domain_obj.id if domain_obj else 0

        cv = cache_get_or_fetch(
            section="engines.detail",
            key_parts=(domain_id, engine_name),
            fetcher=lambda: engine_inquiry.cluster_detail(cfg, engine_name),
            ttl=get_loose_ttl(),               # Loose refresh — read-only inventory
            refresh=(request.args.get("refresh") == "1"),
        )

        creds_by_node = {}
        if domain_obj:
            creds_by_node = _credentials_for_engine(domain_obj.id, engine_name)

        return render_template(
            "engines/cluster_detail.html",
            detail=cv.data,
            cache_meta=cv,
            creds_by_node=creds_by_node,
        )
    except Exception as exc:
        log.exception("cluster_detail(%s) failed", engine_name)
        return render_template(
            "error.html",
            message=f"Could not render cluster detail for {engine_name!r}: "
                    f"{type(exc).__name__}: {exc}",
        )


@engines_bp.route("/credentials")
@admin_required
def credentials_redirect():
    """Permanent redirect to the canonical DHCP-side credentials page."""
    return redirect(url_for("dhcp.credentials_list"), code=302)


@engines_bp.route("/tools")
@admin_required
def tools():
    return render_template("engines/tools.html")


@engines_bp.route("/tools/scan", methods=["GET"])
@profile_required_admin
def tools_scan():
    """Engines → Tools → Scan landing / watcher / results page.

    With no `?scan_id`, renders the picker form (cascading
    tenant/cluster/node/interface, target-mode radio, ports textarea
    pre-filled from the curated default).

    With `?scan_id=X`, queries the job runtime:
      * state=running → render the watcher (progress bar + 10-line log,
                        polled by JS via /tools/scan/status)
      * state=done    → consume the report and render the result table
                        + filter buttons + CSV-export link
      * state=failed  → flash error and fall back to the picker
    """
    scan_id = (request.args.get("scan_id") or "").strip()

    from webapp import engine_scan_jobs
    from webapp.engine_scan import DEFAULT_PORTS
    user_email = (session.get("user") or {}).get("email", "")

    scan_running = None
    scan_report = None

    if scan_id:
        status = engine_scan_jobs.get_status(scan_id, user_email=user_email)
        if status is None:
            flash("Scan job not found or expired — start a new one.", "info")
        elif status["state"] == "running":
            scan_running = status
        elif status["state"] == "failed":
            flash(f"Scan failed: {status.get('error') or 'unknown error'}",
                  "danger")
            engine_scan_jobs.discard(scan_id, user_email=user_email)
        else:  # done
            scan_report = engine_scan_jobs.consume_report(
                scan_id, user_email=user_email)
            if scan_report is None:
                flash("Scan results expired before they could be loaded.",
                      "warning")
            else:
                _log_activity_engines(
                    "scan", "scan_complete", "ok",
                    f"{scan_report.target_label}",
                    f"icmp={scan_report.icmp_replies} "
                    f"arp={scan_report.arp_replies} "
                    f"open_hosts={scan_report.hosts_with_open_ports} "
                    f"duration={scan_report.duration_ms}ms "
                    f"node={scan_report.source_node_index}",
                )
                # Persist to scan history (Phase 1 of Engines-ScanHistory).
                # Best-effort: in-memory results still render even on DB
                # failure. On success, redirect to the persistent detail
                # view so the operator lands on a URL that survives the
                # 15-min in-memory TTL.
                try:
                    from webapp.scan_history import service as _scan_history
                    domain_for_history = _current_domain()
                    user_obj = None
                    user_email_addr = (session.get("user") or {}).get("email", "")
                    if user_email_addr:
                        from webapp.models import User as _U
                        user_obj = _U.query.filter_by(email=user_email_addr).first()
                    record = _scan_history.register_scan(
                        domain_for_history, scan_report,
                        user_id=getattr(user_obj, "id", None),
                        source="manual",
                        source_correlation=scan_id[:64] if scan_id else "",
                    )
                    if record is not None:
                        return redirect(url_for(
                            "scan_history.detail", scan_id=record.id))
                except Exception as exc:
                    log.warning("scan_history persist failed: %s", exc)

    # Build the source picker payload — current cluster inventory so
    # the cascading dropdowns can render without a second round-trip.
    # Failures here are non-fatal: the page still loads, the operator
    # picks differently, the form POST validates again server-side.
    #
    # TODO-item-1 gate: filter the inventory to engines whose every node
    # has a verified=ok credential in the active Domain. The scan tool
    # runs `nc -z`/ICMP/arping FROM a cluster node, so it needs SSH —
    # un-credentialed engines are useless here.
    inventory = []
    inventory_error = None
    inventory_total = 0  # how many SMC clusters exist before the gate filtered
    inventory_cache_meta = None
    if not scan_running and not scan_report:
        try:
            from shared.smc_cache import (
                cache_get_or_fetch, invalidate, get_loose_ttl,
            )
            cfg = _user_cfg()
            domain = _current_domain()
            domain_id = domain.id if domain else 0

            # Q3 + Q5: share the `engines.list` cache section with
            # /engines/clusters (same data, same key shape) so fetches
            # are deduped. ?refresh=1 here also fans out per Q5 family-wide.
            refresh_requested = (request.args.get("refresh") == "1")
            if refresh_requested:
                invalidate("engines.detail")
            cv = cache_get_or_fetch(
                section="engines.list",
                key_parts=(domain_id,),
                fetcher=lambda: engine_inquiry.list_clusters(cfg),
                ttl=get_loose_ttl(),        # Loose refresh — read-only inventory
                refresh=refresh_requested,
            )
            clusters_summary = cv.data
            inventory_cache_meta = cv

            from webapp.engine_credentials import valid_engines_for_domain
            valid = valid_engines_for_domain(domain.id) if domain else set()
            inventory_total = len(clusters_summary)
            inventory = [
                {"name": c.name, "node_count": c.node_count, "typeof": c.typeof}
                for c in clusters_summary if c.name in valid
            ]
        except Exception as exc:
            inventory_error = str(exc)
            log.warning("tools_scan: cluster list failed: %s", exc)

    # Server-side numeric IP sort for the result table — same criterion
    # as the DHCP leases view (tuple-of-octet-ints). Jinja's default
    # `|sort` is lexicographic, which puts 192.168.1.69 before
    # 192.168.1.6.
    sorted_ips: list[str] = []
    port_services_map: dict[int, str] = {}
    if scan_report is not None:
        try:
            sorted_ips = sorted(
                scan_report.results.keys(),
                key=lambda ip: tuple(int(p) for p in ip.split(".")),
            )
        except Exception:
            sorted_ips = sorted(scan_report.results.keys())
        try:
            domain_obj = _current_domain()
            domain_id = domain_obj.id if domain_obj else 0
            port_services_map = resolve_port_services(domain_id, _user_cfg())
        except Exception as exc:
            log.warning("port_services_map build failed: %s", exc)

    # Picker mode: build the SMC-services payload that drives the
    # chips-with-autocomplete port input. Both lookups share the
    # ``smc.explorer.tcp_services`` cache section so a single fetch
    # serves both the chip-name resolver and the typeahead list.
    tcp_services_for_picker: list[dict] = []
    picker_port_services_map: dict[int, str] = {}
    if not scan_running and not scan_report:
        try:
            domain_obj = _current_domain()
            domain_id = domain_obj.id if domain_obj else 0
            cfg = _user_cfg()
            tcp_services_for_picker = list_tcp_services_for_picker(domain_id, cfg)
            picker_port_services_map = resolve_port_services(domain_id, cfg)
        except Exception as exc:
            log.warning("picker service lists failed: %s", exc)

    return render_template(
        "engines/tools_scan.html",
        scan_running=scan_running,
        scan_report=scan_report,
        sorted_ips=sorted_ips,
        port_services_map=port_services_map,
        inventory=inventory,
        inventory_error=inventory_error,
        inventory_total=inventory_total,
        inventory_hidden=max(0, inventory_total - len(inventory)),
        inventory_cache_meta=inventory_cache_meta,
        default_ports=",".join(str(p) for p in DEFAULT_PORTS),
        default_ports_list=list(DEFAULT_PORTS),
        tcp_services_for_picker=tcp_services_for_picker,
        picker_port_services_map=picker_port_services_map,
    )


@engines_bp.route("/tools/scan", methods=["POST"])
@profile_required_admin
def tools_scan_start():
    """Validate the picker form, build the IP list, kick off the
    background job, and redirect to the watcher.

    Form fields:
      engine_name      cluster name (string)
      node_index       1-based cluster nodeid (int)
      iface_id         interface id ("1.10" for VLAN 10 on iface 1)
      target_mode      'subnet' | 'single_ip' | 'custom_range'
      single_ip        when target_mode=single_ip
      custom_start     \\
      custom_end        \\ when target_mode=custom_range
      ports            comma/whitespace list (or "1-1024" range)
      skip_port_scan   '1' = ICMP/ARP only (Phase 3 skipped)
      accept_warning   '1' = operator confirmed >warn-threshold ops
    """
    from webapp.engine_scan import (
        parse_port_list, DEFAULT_PORTS,
        MAX_HOSTS, MAX_PORTS, WARN_OPS_THRESHOLD, HARD_OPS_CAP,
    )
    from webapp import engine_scan_jobs
    from webapp.dhcp_subnet_scan import (
        enumerate_subnet_targets, enumerate_range_targets,
    )

    engine_name = (request.form.get("engine_name") or "").strip()
    node_index_raw = (request.form.get("node_index") or "").strip()
    iface_id = (request.form.get("iface_id") or "").strip()
    vlan_id = (request.form.get("vlan_id") or "").strip()
    target_mode = (request.form.get("target_mode") or "subnet").strip().lower()
    single_ip = (request.form.get("single_ip") or "").strip()
    custom_start = (request.form.get("custom_start") or "").strip()
    custom_end = (request.form.get("custom_end") or "").strip()
    ports_raw = (request.form.get("ports") or "").strip()
    skip_port_scan = request.form.get("skip_port_scan") == "1"
    accept_warning = request.form.get("accept_warning") == "1"

    if not engine_name or not node_index_raw or not iface_id:
        flash("Pick a cluster, node, and interface first.", "warning")
        return redirect(url_for("engines.tools_scan"))

    try:
        node_index = int(node_index_raw)
    except ValueError:
        flash("Invalid node index.", "danger")
        return redirect(url_for("engines.tools_scan"))

    domain = _current_domain()
    if domain is None:
        flash("No active Domain — pick one first.", "warning")
        return redirect(url_for("engines.tools_scan"))

    # TODO-item-1 gate (defence in depth — UI hides un-credentialed
    # engines, but a direct curl would skip the GET filter).
    from webapp.engine_credentials import is_engine_credentials_valid
    if not is_engine_credentials_valid(domain.id, engine_name):
        flash(
            f"Engine {engine_name!r} has no fully-verified SSH credentials "
            f"in this Domain. Enroll every cluster node in Credentials "
            f"before launching a scan.",
            "warning",
        )
        return redirect(url_for("engines.tools_scan"))

    creds_by_node = _credentials_for_engine(domain.id, engine_name)
    cred_row = creds_by_node.get(node_index)
    if cred_row is None or (cred_row.last_verify_status or "").lower() != "ok":
        flash(f"No verified credential for node {node_index} of "
              f"{engine_name}. Visit the credentials page to fix.",
              "warning")
        return redirect(url_for("engines.tools_scan"))

    # Resolve interface metadata (subnet + OS-level interface name) by
    # asking the SMC inventory for the cluster's interface walk.
    iface_subnet_cidr = ""
    iface_label = iface_id + (f".{vlan_id}" if vlan_id else "")
    try:
        cfg = _user_cfg()
        with __import__("smc_client").smc_session(cfg):
            detail = engine_inquiry.cluster_detail(cfg, engine_name)
        for iface in detail.interfaces:
            if iface.interface_id == iface_id and (iface.vlan_id or "") == vlan_id:
                iface_label = (
                    f"{iface.interface_id}"
                    + (f".{iface.vlan_id}" if iface.vlan_id else "")
                )
                # Pick this node's address (NDI) on this interface.
                # Sub-interfaces all share the same network; the
                # network_value field carries the CIDR.
                for addr in iface.addresses:
                    if addr.network_value:
                        iface_subnet_cidr = addr.network_value
                        break
                break
    except Exception as exc:
        log.warning("tools_scan_start: interface walk failed: %s", exc)

    # Build target IP list.
    try:
        if target_mode == "single_ip":
            if not single_ip:
                flash("Single-IP mode needs an IP.", "warning")
                return redirect(url_for("engines.tools_scan"))
            ip_list = [single_ip]
            target_label = f"{engine_name}/{iface_label} → {single_ip}"
        elif target_mode == "custom_range":
            if not (custom_start and custom_end):
                flash("Custom range needs both start and end IPs.", "warning")
                return redirect(url_for("engines.tools_scan"))
            ip_list = enumerate_range_targets(
                custom_start, custom_end,
                subnet_cidr=iface_subnet_cidr,
            )
            target_label = (
                f"{engine_name}/{iface_label} → {custom_start}-{custom_end}"
            )
        else:  # subnet
            if not iface_subnet_cidr:
                flash("Could not resolve the interface's subnet — "
                      "use Custom range instead.", "warning")
                return redirect(url_for("engines.tools_scan"))
            ip_list = enumerate_subnet_targets(iface_subnet_cidr)
            target_label = f"{engine_name}/{iface_label} → {iface_subnet_cidr}"
    except ValueError as exc:
        flash(f"Invalid scan range: {exc}", "danger")
        return redirect(url_for("engines.tools_scan"))

    if not ip_list:
        flash("Resolved range is empty — nothing to scan.", "warning")
        return redirect(url_for("engines.tools_scan"))
    if len(ip_list) > MAX_HOSTS:
        flash(f"Range too large ({len(ip_list)} > {MAX_HOSTS} cap).",
              "danger")
        return redirect(url_for("engines.tools_scan"))

    # Parse ports.
    if skip_port_scan:
        ports: list[int] = []
    else:
        if not ports_raw:
            ports = list(DEFAULT_PORTS)
        else:
            try:
                ports = parse_port_list(ports_raw)
            except ValueError as exc:
                flash(f"Invalid port list: {exc}", "danger")
                return redirect(url_for("engines.tools_scan"))
        if len(ports) > MAX_PORTS:
            flash(f"Port list too large ({len(ports)} > {MAX_PORTS} cap).",
                  "danger")
            return redirect(url_for("engines.tools_scan"))

    total_ops = len(ip_list) + (len(ip_list) * len(ports) if ports else 0)
    if total_ops > HARD_OPS_CAP:
        flash(f"Scan would total {total_ops} operations (> {HARD_OPS_CAP} "
              f"hard cap). Narrow the range or shrink the port list.",
              "danger")
        return redirect(url_for("engines.tools_scan"))
    if total_ops > WARN_OPS_THRESHOLD and not accept_warning:
        flash(f"Scan would total {total_ops} operations "
              f"(> {WARN_OPS_THRESHOLD} threshold). Tick the confirm box "
              f"and re-submit.", "warning")
        return redirect(url_for("engines.tools_scan"))

    # Spawn the background job.
    user_email = (session.get("user") or {}).get("email", "")
    target = _cred_to_target_engines(cred_row)
    payload = _cred_to_payload_engines(cred_row)
    scan_id = engine_scan_jobs.start_scan(
        target=target, cred=payload,
        ip_list=ip_list, ports=ports,
        user_email=user_email,
        source_node_index=node_index,
        source_node_hostname=cred_row.hostname,
        source_iface_id=iface_id,
        source_iface_name=iface_label,
        target_label=target_label,
    )
    _log_activity_engines(
        "scan", "scan_started", "ok", target_label,
        f"mode={target_mode} ip_list_size={len(ip_list)} "
        f"ports={len(ports)} scan_id={scan_id[:8]}",
    )
    return redirect(url_for("engines.tools_scan", scan_id=scan_id))


@engines_bp.route("/tools/scan/status")
@profile_required_admin
def tools_scan_status():
    """JSON poll target for the watcher's polling loop. 404 on unknown."""
    scan_id = (request.args.get("id") or "").strip()
    if not scan_id:
        return jsonify({"error": "missing id"}), 400
    from webapp import engine_scan_jobs
    user_email = (session.get("user") or {}).get("email", "")
    status = engine_scan_jobs.get_status(scan_id, user_email=user_email)
    if status is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(status)


@engines_bp.route("/api/clusters/<path:engine_name>/interfaces")
@profile_required_admin
def api_cluster_interfaces(engine_name):
    """Cascading-picker JSON: nodes + interfaces for a cluster.

    Returns:
      {"nodes": [{"node_index": int, "hostname": str, "verified": bool}, ...],
       "interfaces": [{"id": str, "vlan_id": str, "subnet_cidr": str}, ...]}

    The OS-level interface name is auto-derived inside the engine-side
    script via `ip route get`, so we don't need to plumb it through the
    UI today; the picker just needs the SMC `interface_id` (stable
    identifier).
    """
    domain = _current_domain()
    if domain is None:
        return jsonify({"error": "no active domain"}), 400

    creds_by_node = _credentials_for_engine(domain.id, engine_name)

    try:
        cfg = _user_cfg()
        with __import__("smc_client").smc_session(cfg):
            detail = engine_inquiry.cluster_detail(cfg, engine_name)
    except Exception as exc:
        log.warning("api_cluster_interfaces(%s): %s", engine_name, exc)
        return jsonify({"error": str(exc)}), 502

    nodes = []
    for n in detail.nodes:
        cred = creds_by_node.get(n.nodeid)
        verified = bool(cred and (cred.last_verify_status or "").lower() == "ok")
        nodes.append({
            "node_index": n.nodeid, "hostname": cred.hostname if cred else "",
            "verified": verified, "version": n.engine_version,
            "status_state": n.status_state,
        })

    seen_iface_keys: set[tuple[str, str]] = set()
    interfaces = []
    for iface in detail.interfaces:
        key = (iface.interface_id or "", iface.vlan_id or "")
        if key in seen_iface_keys:
            continue
        seen_iface_keys.add(key)
        subnet_cidr = ""
        for addr in iface.addresses:
            if addr.network_value:
                subnet_cidr = addr.network_value
                break
        label = iface.interface_id
        if iface.vlan_id:
            label = f"{iface.interface_id}.{iface.vlan_id}"
        interfaces.append({
            "id": iface.interface_id,
            "vlan_id": iface.vlan_id or "",
            "label": label,
            "zone": iface.zone or "",
            "subnet_cidr": subnet_cidr,
        })

    # Stable order: physical iface first, then VLANs by numeric vlan_id.
    def _iface_sort_key(it):
        try:
            iid = int(it["id"])
        except (TypeError, ValueError):
            iid = 99999
        try:
            vid = int(it["vlan_id"]) if it["vlan_id"] else -1
        except (TypeError, ValueError):
            vid = 99999
        return (iid, vid)
    interfaces.sort(key=_iface_sort_key)

    return jsonify({"nodes": nodes, "interfaces": interfaces})


@engines_bp.route("/api/clusters/<path:engine_name>/interfaces/debug")
@profile_required_admin
def api_cluster_interfaces_debug(engine_name):
    """Diagnostic dump of every physical_interface payload as raw JSON.
    Use to verify what SMC actually returns when VLAN sub-interfaces
    don't show up on the picker. Hit:
      /engines/api/clusters/<engine>/interfaces/debug?pretty=1
    """
    from smc.core.engine import Engine
    from flask import Response
    import json

    cfg = _user_cfg()
    out: list[dict] = []
    try:
        with __import__("smc_client").smc_session(cfg):
            engine = Engine(engine_name)
            for pi in engine.physical_interface:
                # Try every shape we've seen for pi.data
                raw = getattr(pi, "data", None)
                snapshot: dict = {}
                if raw is None:
                    snapshot["_pi_data"] = None
                else:
                    snapshot["_repr_type"] = type(raw).__name__
                    try:
                        if hasattr(raw, "data") and isinstance(raw.data, dict):
                            snapshot["_via"] = ".data.data"
                            snapshot.update(dict(raw.data))
                        elif isinstance(raw, dict):
                            snapshot["_via"] = "isinstance(dict)"
                            snapshot.update(dict(raw))
                        else:
                            snapshot["_via"] = "dict(raw)"
                            snapshot.update(dict(raw))
                    except Exception as exc:
                        snapshot["_extract_error"] = str(exc)
                # Also try the SDK's vlan_interface iterator if present
                try:
                    vi_list = []
                    for vi in getattr(pi, "vlan_interface", []) or []:
                        vi_list.append({
                            "type": type(vi).__name__,
                            "data": getattr(vi, "data", None) if not hasattr(getattr(vi, "data", None), "data")
                                    else dict(vi.data.data),
                        })
                    snapshot["_pi_vlan_interface_iter"] = vi_list
                except Exception as exc:
                    snapshot["_pi_vlan_interface_iter_error"] = str(exc)
                out.append(snapshot)
    except Exception as exc:
        return jsonify({"error": str(exc), "engine": engine_name}), 502

    pretty = request.args.get("pretty") == "1"
    body = json.dumps(out, indent=2 if pretty else None, default=str)
    return Response(body, mimetype="application/json")


@engines_bp.route("/tools/scan/<scan_id>/csv")
@profile_required_admin
def tools_scan_csv(scan_id):
    """Export the consumed scan report as CSV. Operator-only stash —
    the report is removed from memory after export, mirroring
    consume_report semantics.
    """
    import csv
    from io import StringIO
    from flask import Response
    from webapp import engine_scan_jobs

    user_email = (session.get("user") or {}).get("email", "")
    report = engine_scan_jobs.consume_report(scan_id, user_email=user_email)
    if report is None:
        flash("Scan results expired or already consumed.", "warning")
        return redirect(url_for("engines.tools_scan"))

    buf = StringIO()
    w = csv.writer(buf)
    w.writerow([
        "ip", "icmp_reply", "arp_reply", "mac", "hostname",
        "open_ports", "closed_ports",
    ])
    rows = sorted(report.results.values(),
                  key=lambda r: tuple(int(p) for p in r.ip.split(".")
                                      if p.isdigit()))
    for r in rows:
        opens = ",".join(str(p) for p in r.open_ports)
        closes = ",".join(str(p) for p, s in sorted(r.ports.items())
                          if s == "closed")
        w.writerow([r.ip, int(r.icmp_reply), int(r.arp_reply),
                    r.mac, r.hostname, opens, closes])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f'attachment; filename="engine-scan-{scan_id[:8]}.csv"',
        },
    )


def _cred_to_target_engines(cred):
    """Build SSHTarget from a DhcpEngineCredential row. Mirrors
    `dhcp_manager._cred_to_target` to avoid the cross-blueprint import.
    """
    from webapp.dhcp_ssh import SSHTarget
    return SSHTarget(
        hostname=cred.hostname, port=cred.ssh_port,
        username=cred.ssh_username,
    )


def _cred_to_payload_engines(cred):
    """Build SSHCredential from a DhcpEngineCredential row.

    `encrypted_password` is an `EncryptedString` column — reading it
    returns plaintext (the type decorator handles Fernet round-trip).
    """
    from webapp.dhcp_ssh import SSHCredential
    return SSHCredential(
        password=cred.encrypted_password,
        host_fingerprint=cred.host_fingerprint or "",
    )


@engines_bp.route("/nodes/<int:cred_id>/terminal")
@admin_required
def node_terminal(cred_id):
    """Render the xterm.js terminal page. The WebSocket route lives on the
    Flask-Sock instance — see webapp/engine_terminal.py.
    """
    from webapp.models import DhcpEngineCredential
    cred = db.session.get(DhcpEngineCredential, cred_id)
    if cred is None:
        flash("Credential not found.", "danger")
        return redirect(url_for("engines.clusters"))
    if cred.last_verify_status != "ok":
        flash("This credential is not verified — re-enroll it before using the terminal.",
              "warning")
        return redirect(url_for("dhcp.credentials_list"))
    try:
        ws_path = url_for("engines.node_terminal_ws", cred_id=cred_id)
    except Exception:
        flash("Terminal WebSocket route is unavailable — flask-sock not installed.",
              "danger")
        return redirect(url_for("engines.clusters"))
    return render_template(
        "engines/terminal.html",
        cred=cred,
        ws_path=ws_path,
    )


# ── sgInfo (on-demand engine diagnostics) ───────────────────────────────
#
# Per-node "Collect sginfo" button on the cluster_detail page. Clicking
# kicks off a background SMC API call (`node.sginfo()` over the
# management channel — works for node-initiated-contact engines), saves
# the gzipped tar to /config/sginfo/<id>/, and renders a viewer that
# lets the operator browse the archive's members + view individual
# text files in-browser.

def _record_or_404(record_id: int) -> EngineSginfoCollection:
    rec = db.session.get(EngineSginfoCollection, record_id)
    if rec is None:
        abort(404)
    domain = _current_domain()
    if domain is None or rec.domain_id != domain.id:
        # Don't leak existence across Domains.
        abort(404)
    return rec


@engines_bp.route("/clusters/<path:engine_name>/sginfo", methods=["POST"])
@profile_required_admin
def sginfo_collect(engine_name):
    """Kick off a sginfo collection for one node of an engine.

    Form fields:
        node_index               (int, required)  — engine.nodes[i] index
        node_name                (str, optional)  — display label
        include_core_files       ('on' / missing) — pass-through to SMC
        include_slapcat_output   ('on' / missing) — pass-through to SMC

    Returns a redirect to the watcher view. The actual SMC call runs
    in a daemon thread so the request returns immediately.
    """
    domain = _current_domain()
    if domain is None:
        flash("Pick a Domain first.", "warning")
        return redirect(url_for("engines.cluster_detail",
                                engine_name=engine_name))

    try:
        node_index = int(request.form.get("node_index", "").strip())
    except ValueError:
        flash("Bad form: node_index must be an integer.", "danger")
        return redirect(url_for("engines.cluster_detail",
                                engine_name=engine_name))

    node_name = (request.form.get("node_name") or "").strip()
    include_core = request.form.get("include_core_files") == "on"
    include_slap = request.form.get("include_slapcat_output") == "on"

    user_id = None
    user_email = ""
    try:
        from webapp.models import User
        info = session.get("user") or {}
        user_email = (info.get("email") or "").strip().lower()
        if user_email:
            u = User.query.filter_by(email=user_email).first()
            user_id = u.id if u else None
    except Exception:
        pass

    from webapp import engine_sginfo
    try:
        result = engine_sginfo.start_collection(
            domain=domain,
            engine_name=engine_name,
            node_index=node_index,
            node_name=node_name,
            include_core_files=include_core,
            include_slapcat_output=include_slap,
            user_id=user_id,
            user_email=user_email,
        )
    except Exception as exc:
        log.exception("sginfo_collect: start failed for %s/node%s",
                      engine_name, node_index)
        flash(f"Could not start sginfo collection: {exc}", "danger")
        return redirect(url_for("engines.cluster_detail",
                                engine_name=engine_name))

    flash(f"sginfo collection started for {engine_name} node {node_index} "
          f"(record #{result.record_id}). Page will refresh when ready.",
          "info")
    return redirect(url_for("engines.sginfo_view",
                            record_id=result.record_id))


@engines_bp.route("/sginfo/<int:record_id>")
@profile_required_admin
def sginfo_view(record_id):
    """Watcher (when running) / file browser (when done) / error page."""
    rec = _record_or_404(record_id)
    members = []
    selected_path = (request.args.get("path") or "").strip()
    selected_text = ""
    selected_encoding = ""
    selected_truncated = False
    selected_is_text = False
    selected_size = 0
    text_error = ""

    if rec.status == "done":
        try:
            from webapp import engine_sginfo
            members = engine_sginfo.list_archive_members(rec)
        except Exception as exc:
            log.exception("sginfo_view: index failed for #%s", rec.id)
            text_error = f"Could not read archive index: {exc}"

    if selected_path and rec.status == "done" and not text_error:
        member = next((m for m in members if m["path"] == selected_path),
                      None)
        if member is None:
            text_error = f"Member not found in archive: {selected_path}"
        else:
            selected_size = member["size"]
            selected_is_text = member["is_text"]
            if selected_is_text and selected_size <= 8 * 1024 * 1024:
                try:
                    from webapp import engine_sginfo
                    (selected_text, selected_encoding, selected_truncated
                     ) = engine_sginfo.read_text_member(rec, selected_path)
                except Exception as exc:
                    text_error = f"Could not read {selected_path}: {exc}"

    return render_template(
        "engines/sginfo_view.html",
        record=rec,
        members=members,
        selected_path=selected_path,
        selected_text=selected_text,
        selected_encoding=selected_encoding,
        selected_truncated=selected_truncated,
        selected_is_text=selected_is_text,
        selected_size=selected_size,
        text_error=text_error,
    )


@engines_bp.route("/sginfo/<int:record_id>/status")
@profile_required_admin
def sginfo_status(record_id):
    """JSON poll target for the watcher."""
    rec = _record_or_404(record_id)
    return jsonify(
        id=rec.id,
        status=rec.status,
        error=rec.error,
        engine_name=rec.engine_name,
        node_index=rec.node_index,
        archive_bytes=int(rec.archive_bytes or 0),
        member_count=int(rec.member_count or 0),
        duration_ms=int(rec.duration_ms or 0),
        finished=(rec.status in ("done", "failed")),
    )


@engines_bp.route("/sginfo/<int:record_id>/file")
@profile_required_admin
def sginfo_file_download(record_id):
    """Download a single archive member as the original (binary) bytes."""
    rec = _record_or_404(record_id)
    if rec.status != "done":
        abort(409)
    member_path = (request.args.get("path") or "").strip()
    if not member_path:
        abort(400)

    from webapp import engine_sginfo
    try:
        data = engine_sginfo.stream_member_bytes(rec, member_path)
    except FileNotFoundError:
        abort(404)
    except Exception as exc:
        log.exception("sginfo_file_download: extract failed for #%s/%s",
                      rec.id, member_path)
        abort(500)

    # Inline-safe filename (sanitise path separators).
    fname = member_path.rsplit("/", 1)[-1] or "member.bin"
    return Response(
        data,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Content-Length": str(len(data)),
        },
    )


@engines_bp.route("/sginfo/<int:record_id>/download")
@profile_required_admin
def sginfo_archive_download(record_id):
    """Raw .gz archive download — for opening in Wireshark, sharing with
    Forcepoint Support, or local extraction."""
    rec = _record_or_404(record_id)
    if rec.status != "done":
        abort(409)
    from webapp import engine_sginfo
    path = engine_sginfo.archive_path(rec)
    if not path.is_file():
        abort(404)
    fname = (f"sginfo-{rec.engine_name}-node{rec.node_index}-"
             f"{rec.started_at:%Y%m%d-%H%M%S}.gz")
    return send_file(path, as_attachment=True, download_name=fname,
                     mimetype="application/gzip")


@engines_bp.route("/sginfo/<int:record_id>/delete", methods=["POST"])
@profile_required_admin
def sginfo_delete(record_id):
    rec = _record_or_404(record_id)
    engine_name = rec.engine_name
    from webapp import engine_sginfo
    try:
        engine_sginfo.delete_record(rec)
    except Exception as exc:
        log.exception("sginfo_delete: failed for #%s", record_id)
        flash(f"Could not delete sginfo record #{record_id}: {exc}",
              "danger")
        return redirect(url_for("engines.sginfo_history"))
    flash(f"sginfo record #{record_id} deleted.", "success")
    if request.form.get("return_to") == "engine":
        return redirect(url_for("engines.cluster_detail",
                                engine_name=engine_name))
    return redirect(url_for("engines.sginfo_history"))


@engines_bp.route("/sginfo")
@profile_required_admin
def sginfo_history():
    """List every sginfo collection in the active Domain (newest first)."""
    domain = _current_domain()
    if domain is None:
        flash("Pick a Domain first.", "warning")
        return redirect(url_for("index"))
    engine_filter = (request.args.get("engine") or "").strip()
    qry = (EngineSginfoCollection.query
           .filter_by(domain_id=domain.id)
           .order_by(EngineSginfoCollection.started_at.desc()))
    if engine_filter:
        qry = qry.filter(EngineSginfoCollection.engine_name == engine_filter)
    rows = qry.limit(500).all()
    return render_template(
        "engines/sginfo_history.html",
        rows=rows,
        engine_filter=engine_filter,
    )


# ── Initialization ──────────────────────────────────────────────────────

def init_engines_manager(app):
    """Register the WebSocket terminal route on the shared `Sock` instance.

    Called from app.py after the Flask-Sock instance is created. Phase B
    plumbing lives in webapp/engine_terminal.py.
    """
    try:
        from webapp import engine_terminal
        engine_terminal.register_routes(app)
    except Exception as exc:
        log.error("engine_terminal init failed (terminal will be unavailable): %s", exc)
