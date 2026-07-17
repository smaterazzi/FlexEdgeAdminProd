"""
FlexEdgeAdmin — Engine SSH Credential Manager.

Extracted from ``webapp/dhcp_manager.py`` on 2026-06-12 (TODO item
"CREDENTIAL MANAGER"): the credential feature — status-aware enrollment
wizard, per-Domain source-IP, node discovery, SSH-allow-rule lifecycle
(install / policy push / source overwrite-add / remove), per-node
bootstrap / apply / verify / force-reset / delete — is a feature in its
own right, consumed by Engines (Terminal, Tools → Scan) just as much as
by DHCP. It now lives in its own module so future work (key-based auth,
other engine-side features) has a clear home.

Compatibility contract
----------------------
This module registers its routes on **dhcp_manager's existing
``dhcp_bp``** rather than a new blueprint. That keeps:

* every URL unchanged (``/dhcp/credentials/...`` — operator bookmarks
  and the sidebar Engines → Credentials link keep working), and
* every endpoint name unchanged (``dhcp.credentials_*`` — no template
  ``url_for`` churn across the 6+ templates that link here).

A future focused commit can flip to a dedicated blueprint by updating
the endpoint references; this extraction deliberately changes structure
only, not behavior.

Import order matters: ``dhcp_manager`` imports this module at the
BOTTOM of its file (after ``dhcp_bp`` and the shared helpers below are
defined), and this module imports those names back from
``dhcp_manager``. That pairing is circular-safe precisely because the
bottom import runs last — do not move it to dhcp_manager's header.

Shared helpers intentionally left in ``dhcp_manager`` (used by its
leases viewer / subnet scan too): ``_cred_to_target``,
``_cred_to_payload``, ``_operator_email``, ``_smc_cfg``,
``_log_activity``, ``_check_stale_form_or_response`` and the
Domain-resolution helpers.

Flow diagram: docs/flows/dhcp-credential-enrollment.mmd
"""
import logging
from datetime import datetime, timezone

from flask import (
    render_template, request, redirect,
    url_for, flash, jsonify, g,
)

from shared.db import db
from webapp.models import (
    ApiKey, DhcpEngineCredential, DhcpEngineSshAccess, Tenant, Domain,
)
from webapp.smc_dhcp_client import (
    smc_session, list_cluster_nodes, is_node_initiated_contact,
    find_ssh_access_rule, find_active_policy,
    update_source_host_address, add_source_host_to_rule,
)
from webapp.smc_tls_client import smc_error_detail
from webapp.dhcp_ssh import (
    SSHTarget, SSHCredential,
    tcp_probe, verify_credential, is_auth_failure,
)
from webapp.dhcp_bootstrap import (
    engine_bootstrap_lock,
    probe_public_ip, upload_policy,
    enroll_node, force_reset_password,
    rule_name_for,
)

# Circular-safe: dhcp_manager imports THIS module at the bottom of its
# file, so every name below already exists when this import executes.
from webapp.dhcp_manager import (
    dhcp_bp, admin_required,
    _log_activity, _smc_cfg,
    _check_stale_form_or_response,
    _domain_id_for_form, _active_domain_id, _domain_ids_for_tenant,
    _cred_to_target, _cred_to_payload, _operator_email,
)

log = logging.getLogger(__name__)


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
        # Each entry carries `suggested`: the template pre-checks it (see
        # credentials.html). SMC-initiated → all real IPs suggested (rule
        # covers the whole cluster). Node-initiated → only the PUBLIC
        # contact (NAT-exit) IPs are suggested: when FEA is public it
        # reaches the nodes on those addresses, so they're the natural rule
        # destination. The nodes' real interface IPs stay available (un-
        # suggested) for topologies where 1:1 NAT rewrites the destination
        # to the private interface IP — the operator ticks those instead.
        rule_destinations = []
        seen = set()
        for n in nodes:
            if node_initiated:
                for a in n.addresses:
                    # Public contact address(es) — the NAT exit IP FEA dials.
                    # Suggested destination for node-initiated + public FEA.
                    for ca in a.contact_addresses:
                        pub = (ca.get("address") or "").strip()
                        if ca.get("is_public") and pub and pub not in seen:
                            rule_destinations.append({
                                "address": pub,
                                "label": f"node {n.node_index} ({n.name}) — {a.interface_id} — {pub} [public / NAT exit]",
                                "suggested": True,
                            })
                            seen.add(pub)
                    # Real interface IP — kept as a selectable (un-suggested)
                    # fallback for NAT topologies that rewrite the destination.
                    if a.address and a.address not in seen:
                        rule_destinations.append({
                            "address": a.address,
                            "label": f"node {n.node_index} ({n.name}) — {a.interface_id} — {a.address}"
                                     + (" [primary mgt]" if a.is_primary_mgt else ""),
                            "suggested": False,
                        })
                        seen.add(a.address)
            else:
                if n.primary_address and n.primary_address not in seen:
                    rule_destinations.append({
                        "address": n.primary_address,
                        "label": f"node {n.node_index} ({n.name}) — {n.primary_address} [primary mgt]",
                        "suggested": True,
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

    # Audit L15 (2026-06-11): take the same per-engine lock as
    # bootstrap / force-reset so an Apply racing a password rotation
    # can't verify against the OLD password and commit "ok" metadata
    # while the rotation invalidates it underneath.
    try:
        with engine_bootstrap_lock(engine_name):
            # Live verify against the new target before committing. Apply
            # must never silently break a previously-working credential —
            # if the operator points us at an IP that doesn't actually
            # accept this credential, refuse and tell them to use
            # Overwrite.
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
    except RuntimeError as exc:
        # engine_bootstrap_lock timeout — another op owns the engine.
        return _err(str(exc), http=409)

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

