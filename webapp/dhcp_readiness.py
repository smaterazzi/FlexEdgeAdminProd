"""
FlexEdgeAdmin — DHCP-ready helper.

Tells the FortiGate migration importer (and the DHCP Manager UI) which
target scopes are eligible to receive imported reservations.

A scope is "DHCP-ready" only when ALL of these hold:

  1. Its parent engine has at least one ``DhcpEngineCredential`` row
     with ``last_verify_status == 'ok'``.
  2. The engine has a ``DhcpEngineSshAccess`` rule recorded.
  3. The scope's ``enabled_in_flexedge`` flag is True.

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

    Returns None if the target doesn't match any active tenant — the
    operator probably needs to add the tenant in the Admin Portal first.
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
    return candidates[0]   # last resort: first match (operator can correct)


# ── Readiness queries ──────────────────────────────────────────────────

def _engine_has_verified_credential(tenant_id: int,
                                    engine_name: str) -> bool:
    return (DhcpEngineCredential.query
            .filter_by(tenant_id=tenant_id,
                       engine_name=engine_name,
                       last_verify_status="ok")
            .first()) is not None


def _engine_has_ssh_rule(tenant_id: int, engine_name: str) -> bool:
    return (DhcpEngineSshAccess.query
            .filter_by(tenant_id=tenant_id, engine_name=engine_name)
            .first()) is not None


def list_scope_options(tenant: Tenant) -> list[ScopeOption]:
    """Return every DhcpScope row known for ``tenant`` as a ScopeOption,
    each tagged with ready=True/False and the list of unmet requirements
    so the UI can render greyed-out items with a tooltip.

    Scopes that haven't been opted into FlexEdge management are excluded
    entirely — they never appeared as candidates from the operator's
    point of view.
    """
    if not tenant:
        return []

    scopes = (DhcpScope.query
              .filter_by(tenant_id=tenant.id, enabled_in_flexedge=True)
              .order_by(DhcpScope.engine_name, DhcpScope.interface_id)
              .all())

    options: list[ScopeOption] = []
    for s in scopes:
        missing: list[str] = []
        if not _engine_has_verified_credential(tenant.id, s.engine_name):
            missing.append("no verified SSH credential for any node")
        if not _engine_has_ssh_rule(tenant.id, s.engine_name):
            missing.append("FlexEdge SSH allow rule missing in SMC policy")

        # Build a useful label: "EDGE-CL01 / port 2.10 — 192.168.10.0/24"
        iface_label = (s.interface_label or s.interface_id).strip()
        label = (f"{s.engine_name} / port {iface_label} "
                 f"— {s.subnet_cidr}")
        if s.label:
            label += f"  ({s.label})"

        # Deep link points to whatever's most useful to fix the issue.
        if missing and "credential" in missing[0]:
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
    """
    scope: DhcpScope = DhcpScope.query.get(scope_id)
    if not scope:
        return False, ["scope not found"]
    if not scope.enabled_in_flexedge:
        return False, ["scope is not opted into FlexEdge management"]

    missing: list[str] = []
    if not _engine_has_verified_credential(scope.tenant_id, scope.engine_name):
        missing.append("no verified SSH credential for any node")
    if not _engine_has_ssh_rule(scope.tenant_id, scope.engine_name):
        missing.append("FlexEdge SSH allow rule missing in SMC policy")
    return not missing, missing
