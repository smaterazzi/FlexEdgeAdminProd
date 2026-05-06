"""
FlexEdgeAdmin — DHCP-ready helper.

Tells the FortiGate migration importer (and the DHCP Manager UI) which
target scopes are eligible to receive imported reservations.

A scope is "DHCP-ready" only when ALL of these hold (matching the
actual preconditions checked by ``dhcp_pusher._check_preconditions`` —
the migration UI must NOT advertise scopes whose deploy will block):

  1. The engine has ≥1 ``DhcpEngineCredential`` row.
  2. EVERY credential row is verified (``last_verify_status == 'ok'`` and
     ``last_verified_at`` is set).
  3. The engine has a ``DhcpEngineSshAccess`` rule recorded with at
     least one destination IP.
  4. The credential count covers the rule's destination IP list — i.e.
     every cluster node the operator ticked at rule install has been
     enrolled. (Partial-cluster setups would deploy onto enrolled nodes
     only, leaving siblings out of sync.)
  5. The scope's ``enabled_in_flexedge`` flag is True.

The migration target dict carries raw ``smc_url`` + ``api_key`` (not a
tenant FK), so we resolve the matching ``Tenant`` row by SMC URL +
API-key hash before listing scopes.
"""

import logging
from dataclasses import dataclass

from shared.db import db
from shared.encryption import hash_value
from webapp.models import (
    Tenant, ApiKey, DhcpScope, DhcpEngineCredential, DhcpEngineSshAccess,
)

log = logging.getLogger(__name__)


@dataclass
class ScopeOption:
    """Dropdown option representing one potential migration target."""
    scope_id: int
    engine_name: str
    interface_id: str
    interface_label: str
    subnet_cidr: str
    label: str                 # operator-readable display
    ready: bool
    missing: list[str]         # human-readable list of unmet requirements
    deep_link: str = ""        # /dhcp/... URL to fix what's missing


# ── Tenant resolver ─────────────────────────────────────────────────────

def find_tenant_for_target(target: dict) -> Tenant | None:
    """Match a migration project's ``target`` dict to a Tenant row.

    Migration projects store ``smc_url`` + ``api_key`` (raw plaintext)
    rather than a tenant_id, so we look up Tenant by smc_url and the
    API key by hash. This is the only safe way to bridge the migration
    layer to the DHCP Manager's tenant-scoped data without exposing
    plaintext keys.

    Returns None when no confident match is possible:
      - target is malformed (missing smc_url or api_key)
      - no active tenant matches the smc_url
      - multiple tenants share the smc_url AND none owns an active
        API key whose hash equals the target's

    In the multi-tenant ambiguity case we refuse to guess. The previous
    behaviour fell through to ``candidates[0]`` which silently bled the
    operator's selection across tenants — a real risk in deployments
    that share an SMC URL between domains. Caller must surface the
    None result with an actionable error ("add the matching API key
    to the right tenant in Admin Portal first").
    """
    smc_url = (target or {}).get("smc_url", "").strip()
    api_key_plain = (target or {}).get("api_key", "").strip()
    if not smc_url or not api_key_plain:
        return None

    candidates = Tenant.query.filter_by(smc_url=smc_url, is_active=True).all()
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    # Multiple tenants share this URL — disambiguate by API key hash.
    target_hash = hash_value(api_key_plain)
    for t in candidates:
        if ApiKey.query.filter_by(tenant_id=t.id, key_hash=target_hash,
                                  is_active=True).first():
            return t

    # No tenant claims this API key. Refuse to guess — silently picking
    # candidates[0] would bleed the migration into an unrelated tenant.
    log.warning(
        "find_tenant_for_target: %d tenants share smc_url=%r but none "
        "owns an active API key matching the target's hash. Refusing to "
        "guess; the migration will surface this as 'tenant not resolved'.",
        len(candidates), smc_url,
    )
    return None


# ── Readiness queries ──────────────────────────────────────────────────

def _split_destination_ips(csv: str) -> list[str]:
    return [ip.strip() for ip in (csv or "").split(",") if ip.strip()]


def _engine_credential_status(domain_id: int,
                              engine_name: str
                              ) -> tuple[bool, list[str]]:
    """Mirror of ``dhcp_pusher._check_preconditions`` for the credential side.

    Phase B.3-prep: takes ``domain_id`` (canonical scope FK).

    Returns (ok, missing_messages). Operator-facing strings.
    """
    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=domain_id, engine_name=engine_name)
             .all())
    if not creds:
        return False, ["no SSH credential enrolled for any node"]

    unverified = [c for c in creds
                  if not c.last_verified_at or c.last_verify_status != "ok"]
    if unverified:
        names = ", ".join(f"node {c.node_index}" for c in unverified)
        return False, [f"credential not verified: {names} — click Verify"]
    return True, []


def _engine_ssh_rule_status(domain_id: int,
                            engine_name: str,
                            ) -> tuple[bool, list[str], list[str]]:
    """Returns (ok, missing_messages, destination_ips)."""
    rule = (DhcpEngineSshAccess.query
            .filter_by(domain_id=domain_id, engine_name=engine_name)
            .first())
    if not rule:
        return False, ["FlexEdge SSH allow rule missing in SMC policy"], []

    dest_ips = _split_destination_ips(rule.destination_ip)
    if not dest_ips:
        return False, ["FlexEdge SSH allow rule has no destination IPs — "
                       "reinstall it from DHCP Manager → Credentials"], []
    return True, [], dest_ips


def _cluster_coverage_status(domain_id: int,
                             engine_name: str,
                             destination_ips: list[str]
                             ) -> tuple[bool, list[str]]:
    """Verify credential count ≥ rule destination count.

    Per-deploy semantics: the pusher iterates over enrolled credentials,
    so an unenrolled cluster node receives nothing — a silent split-brain.
    Block readiness when the rule advertises more node IPs than we have
    verified credentials for.
    """
    expected = len(destination_ips)
    cred_count = (DhcpEngineCredential.query
                  .filter_by(domain_id=domain_id, engine_name=engine_name,
                             last_verify_status="ok")
                  .count())
    if cred_count < expected:
        short = expected - cred_count
        return False, [f"{short} of {expected} cluster node(s) not yet "
                       f"enrolled — finish enrollment in DHCP Manager → "
                       f"Credentials before deploying"]
    return True, []


def list_scope_options(tenant: Tenant) -> list[ScopeOption]:
    """Return every DhcpScope row known for the tenant's Domain(s) as a
    ScopeOption, each tagged with ready=True/False and the list of unmet
    requirements so the UI can render greyed-out items with a tooltip.

    Scopes that haven't been opted into FlexEdge management are excluded
    entirely — they never appeared as candidates from the operator's
    point of view.

    Phase B.3-prep: still takes a Tenant object (callers in app.py +
    dedup_engine pass one). Internally we resolve the Domain via the
    scope's `domain_id` (Phase B.1 backfill made every DhcpScope
    domain-scoped).
    """
    if not tenant:
        return []

    # Phase B.3: every scope is keyed by domain_id. Resolve via the
    # tenant's ApiKeys → their Domains, then filter scopes by those
    # domain_ids. This works without the legacy DhcpScope.tenant_id
    # column once Phase B.3 drops it.
    from webapp.models import Domain, ApiKey
    domain_ids = [d.id for d in
                  Domain.query.join(ApiKey, Domain.api_key_id == ApiKey.id)
                              .filter(ApiKey.tenant_id == tenant.id)
                              .all()]
    if not domain_ids:
        return []
    scopes = (DhcpScope.query
              .filter(DhcpScope.domain_id.in_(domain_ids),
                      DhcpScope.enabled_in_flexedge.is_(True))
              .order_by(DhcpScope.engine_name, DhcpScope.interface_id)
              .all())

    options: list[ScopeOption] = []
    for s in scopes:
        missing: list[str] = []
        cred_ok, cred_missing = _engine_credential_status(s.domain_id, s.engine_name)
        rule_ok, rule_missing, dest_ips = _engine_ssh_rule_status(s.domain_id, s.engine_name)
        missing.extend(cred_missing)
        missing.extend(rule_missing)

        # Cluster-coverage check only meaningful when both creds & rule exist.
        if cred_ok and rule_ok:
            cov_ok, cov_missing = _cluster_coverage_status(
                s.domain_id, s.engine_name, dest_ips)
            missing.extend(cov_missing)

        # Build a useful label: "EDGE-CL01 / port 2.10 — 192.168.10.0/24"
        iface_label = (s.interface_label or s.interface_id).strip()
        label = (f"{s.engine_name} / port {iface_label} "
                 f"— {s.subnet_cidr}")
        if s.label:
            label += f"  ({s.label})"

        # Deep link points to whatever's most useful to fix the issue.
        if missing and any(
            kw in missing[0]
            for kw in ("credential", "enrolled", "Verify", "node")
        ):
            deep_link = f"/dhcp/credentials/{s.engine_name}"
        else:
            deep_link = f"/dhcp/scopes/{s.id}"

        options.append(ScopeOption(
            scope_id=s.id,
            engine_name=s.engine_name,
            interface_id=s.interface_id,
            interface_label=iface_label,
            subnet_cidr=s.subnet_cidr,
            label=label,
            ready=not missing,
            missing=missing,
            deep_link=deep_link,
        ))
    return options


def is_scope_ready(scope_id: int) -> tuple[bool, list[str]]:
    """Single-scope check used by importers / route guards.

    Returns ``(ready, missing)`` where ``missing`` is empty when ready=True.
    Tightened to mirror the deploy preflight, including cluster coverage.
    """
    scope: DhcpScope | None = db.session.get(DhcpScope, scope_id)
    if not scope:
        return False, ["scope not found"]
    if not scope.enabled_in_flexedge:
        return False, ["scope is not opted into FlexEdge management"]

    missing: list[str] = []
    cred_ok, cred_missing = _engine_credential_status(
        scope.domain_id, scope.engine_name)
    rule_ok, rule_missing, dest_ips = _engine_ssh_rule_status(
        scope.domain_id, scope.engine_name)
    missing.extend(cred_missing)
    missing.extend(rule_missing)
    if cred_ok and rule_ok:
        cov_ok, cov_missing = _cluster_coverage_status(
            scope.domain_id, scope.engine_name, dest_ips)
        missing.extend(cov_missing)
    return not missing, missing
