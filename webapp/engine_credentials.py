"""
FlexEdgeAdmin — engine SSH credentials, platform layer.

Per the architecture rule (memory: feedback_credentials_are_engines_level):
engine SSH credentials are platform-level resources owned by the Engines
feature, used by DHCP today and by terminal/scan/anything-future tomorrow.

This module hosts cache-freshness logic and the live-state probe for
those credentials. It deliberately imports model classes by their current
DHCP-namespaced names (``DhcpEngineCredential``, ``DhcpEngineSshAccess``)
so it can be moved to ``webapp/engines/credentials.py`` later as a
straight rename PR — nothing here depends on DHCP business logic.

Responsibilities
----------------
* ``is_engine_cache_fresh(domain_id, engine_name)`` — pure DB read; True
  if every cred + access row for the engine has ``state_refreshed_at``
  inside the freshness window.
* ``mark_engine_state_refreshed(...)`` — bumps the column on the rows
  the caller indicates were just verified (cred-only, access-only, or
  both). Called from every op that proves state.
* ``refresh_engine_state(domain_id, engine_name)`` — runs the live
  probe (SMC for the rule, TCP+SSH for each node) and returns a
  ``RefreshReport`` with structured drift details. Updates every row
  it successfully verified.

The cache window is 24 h per the operator's spec. Staleness is purely
informational — nothing blocks operations on a stale cache; it just
asks the operator to refresh.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from shared.db import db
from webapp.models import (
    Tenant, ApiKey, DhcpEngineCredential, DhcpEngineSshAccess,
)

logger = logging.getLogger(__name__)

# Per-operator spec: cached engine state is valid for 24 h, after which
# the UI prompts for a manual refresh. Constant for now; could become
# a Logs / Settings parameter later.
CACHE_TTL_HOURS = 24


# ── Freshness ────────────────────────────────────────────────────────────

@dataclass
class FreshnessSummary:
    """Cheap-to-compute view used by the credentials page renderer."""
    is_fresh: bool
    cred_refreshed_at: datetime | None
    access_refreshed_at: datetime | None
    earliest_refreshed_at: datetime | None    # min of the two; what UI shows
    age_hours: float | None                   # None when never refreshed

    @property
    def is_stale_24h(self) -> bool:
        return self.age_hours is not None and self.age_hours >= CACHE_TTL_HOURS

    @property
    def is_amber(self) -> bool:
        # Half-life: turn the badge yellow at 12 h, red at 24 h.
        return (self.age_hours is not None
                and self.age_hours >= CACHE_TTL_HOURS / 2
                and not self.is_stale_24h)


def get_engine_freshness(domain_id: int, engine_name: str) -> FreshnessSummary:
    """Inspect cred + access rows for an engine; return a freshness summary.

    Phase B.3-prep: takes ``domain_id`` (canonical scope FK).

    Behaviour:
      * If neither cred nor access has a ``state_refreshed_at``, returns
        ``is_fresh=False`` with ``age_hours=None`` (operator-readable
        as "never refreshed").
      * Otherwise picks the *oldest* of the two timestamps as the
        engine-level freshness — the cache is only as fresh as its
        oldest verified component.
    """
    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=domain_id, engine_name=engine_name)
             .all())
    access = (DhcpEngineSshAccess.query
              .filter_by(domain_id=domain_id, engine_name=engine_name)
              .first())

    cred_min: datetime | None = None
    if creds:
        cred_times = [c.state_refreshed_at for c in creds if c.state_refreshed_at]
        cred_min = min(cred_times) if cred_times else None
    access_t = access.state_refreshed_at if access else None

    candidates = [t for t in (cred_min, access_t) if t is not None]
    earliest = min(candidates) if candidates else None

    if earliest is None:
        return FreshnessSummary(
            is_fresh=False,
            cred_refreshed_at=cred_min,
            access_refreshed_at=access_t,
            earliest_refreshed_at=None,
            age_hours=None,
        )

    # Datetimes coming from SQLite via SQLAlchemy may be naive; treat as UTC.
    if earliest.tzinfo is None:
        earliest = earliest.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - earliest
    age_hours = age.total_seconds() / 3600.0

    return FreshnessSummary(
        is_fresh=age_hours < CACHE_TTL_HOURS,
        cred_refreshed_at=cred_min,
        access_refreshed_at=access_t,
        earliest_refreshed_at=earliest,
        age_hours=age_hours,
    )


def is_engine_cache_fresh(domain_id: int, engine_name: str) -> bool:
    """Pure boolean — convenience wrapper for routes that don't need the summary."""
    return get_engine_freshness(domain_id, engine_name).is_fresh


# ── Validity (operator-facing visibility gate) ───────────────────────────
#
# "Valid credentials" = at least one credential row exists for the engine
# in the active Domain AND every credential row has
# ``last_verify_status='ok'``. This is the rule used to decide whether
# the engine's DHCP scopes / scope operations / Tools-Scan picker entries
# should be visible to the operator (TODO item 1, 2026-05-08).
#
# The Terminal icon on cluster_detail is gated per-node, NOT per-engine
# — Terminal targets a specific node, so per-node validity is the right
# granularity there. Don't touch it.
#
# sgInfo collection is intentionally OUT of scope: it rides the SMC
# management channel and works without any SSH credential.

def is_engine_credentials_valid(domain_id: int, engine_name: str) -> bool:
    """True iff every enrolled credential for ``engine_name`` in
    ``domain_id`` is verified=ok and at least one row exists.

    Caveat: cannot detect partial enrollment (engine has 2 nodes, only
    node 0 enrolled) without an SMC fetch. Acceptable trade-off — the
    bulk-enroll workflow always covers every node, so partial
    enrollment is a transient state operators leave intentionally.
    """
    rows = (DhcpEngineCredential.query
            .filter_by(domain_id=domain_id, engine_name=engine_name)
            .all())
    if not rows:
        return False
    return all((r.last_verify_status or "").lower() == "ok" for r in rows)


def valid_engines_for_domain(domain_id: int) -> set[str]:
    """One-pass set of engine names whose credentials all verify=ok.

    Optimised for list-page rendering: a single grouped DB read instead
    of N round-trips. Empty set when ``domain_id`` is None.
    """
    if domain_id is None:
        return set()
    rows = (DhcpEngineCredential.query
            .filter_by(domain_id=domain_id)
            .with_entities(DhcpEngineCredential.engine_name,
                           DhcpEngineCredential.last_verify_status)
            .all())
    seen: dict[str, bool] = {}
    for engine_name, status in rows:
        ok = (status or "").lower() == "ok"
        if engine_name not in seen:
            seen[engine_name] = ok
        else:
            seen[engine_name] = seen[engine_name] and ok
    return {name for name, ok in seen.items() if ok}


# ── State-bump helpers (called from existing ops) ────────────────────────

def mark_credential_refreshed(cred: DhcpEngineCredential,
                              when: datetime | None = None) -> None:
    """Bump a single credential's state_refreshed_at. Caller must commit."""
    cred.state_refreshed_at = when or datetime.now(timezone.utc)


def mark_access_refreshed(access: DhcpEngineSshAccess,
                          when: datetime | None = None) -> None:
    """Bump a single access row's state_refreshed_at. Caller must commit."""
    access.state_refreshed_at = when or datetime.now(timezone.utc)


def mark_engine_state_refreshed(domain_id: int, engine_name: str, *,
                                creds: bool = True, access: bool = True,
                                when: datetime | None = None) -> None:
    """Bump every cred + access row for an engine (operator-typed convenience).

    Phase B.3-prep: takes ``domain_id``.

    Used by ops that probed both sides (e.g. successful Phase 4 deploy:
    rule preflight + per-node SSH). Caller must commit.
    """
    when = when or datetime.now(timezone.utc)
    if creds:
        for c in (DhcpEngineCredential.query
                  .filter_by(domain_id=domain_id, engine_name=engine_name)
                  .all()):
            c.state_refreshed_at = when
    if access:
        a = (DhcpEngineSshAccess.query
             .filter_by(domain_id=domain_id, engine_name=engine_name)
             .first())
        if a:
            a.state_refreshed_at = when


# ── Live probe (Refresh button) ──────────────────────────────────────────

@dataclass
class NodeProbeResult:
    node_index: int
    hostname: str
    tcp_ok: bool
    auth_ok: bool
    error: str = ""
    fingerprint_match: bool = True   # False only on host key mismatch


@dataclass
class RuleProbeResult:
    rule_name: str
    rule_present_in_smc: bool
    expected_destinations: list[str] = field(default_factory=list)
    actual_destinations: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def has_drift(self) -> bool:
        if not self.rule_present_in_smc:
            return True
        return set(self.expected_destinations) != set(self.actual_destinations)


@dataclass
class RefreshReport:
    domain_id: int
    engine_name: str
    rule: RuleProbeResult | None = None
    nodes: list[NodeProbeResult] = field(default_factory=list)
    rule_drift_messages: list[str] = field(default_factory=list)
    node_drift_messages: list[str] = field(default_factory=list)
    fatal_error: str = ""

    @property
    def has_any_drift(self) -> bool:
        return bool(self.rule_drift_messages or self.node_drift_messages)

    @property
    def all_ok(self) -> bool:
        return (not self.fatal_error
                and not self.has_any_drift
                and self.rule is not None
                and self.rule.rule_present_in_smc
                and all(n.tcp_ok and n.auth_ok for n in self.nodes))


def _split_csv_ips(csv: str) -> list[str]:
    return [ip.strip() for ip in (csv or "").split(",") if ip.strip()]


def refresh_engine_state(domain_id: int, engine_name: str) -> RefreshReport:
    """Run the live probe + bump state_refreshed_at on what passed.

    Phase B.3-prep: takes ``domain_id``. Server config + SMC domain name
    are pulled from the ApiKey-on-Domain (Phase A absorbed those fields).

    Steps:
      1. Open SMC session, look up the access rule by name.
         - If absent → drift_rule_missing.
         - If present → compare destinations to DB CSV; record drift list.
      2. Per credential: TCP probe + SSH verify.
         - TCP fail / auth fail / fingerprint mismatch all recorded as drift.
      3. For every component that succeeded, set state_refreshed_at = now.
      4. Returns a structured ``RefreshReport`` for the route to flash.

    Imported lazily so this module is testable without the SMC stack.
    """
    report = RefreshReport(domain_id=domain_id, engine_name=engine_name)

    # Imports are lazy: avoids a circular hop through dhcp_manager and lets
    # tests stub the SMC layer with monkeypatch on this module.
    from webapp.smc_dhcp_client import (
        SMCConfig, smc_session, find_active_policy, find_ssh_access_rule,
    )
    from webapp.dhcp_bootstrap import rule_name_for
    from webapp.dhcp_ssh import (
        SSHTarget, SSHCredential, tcp_probe, verify_credential,
    )
    from webapp.models import Domain

    domain = db.session.get(Domain, domain_id)
    if not domain:
        report.fatal_error = f"domain {domain_id} not found"
        return report

    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=domain_id, engine_name=engine_name)
             .order_by(DhcpEngineCredential.node_index)
             .all())
    access = (DhcpEngineSshAccess.query
              .filter_by(domain_id=domain_id, engine_name=engine_name)
              .first())

    if not creds and not access:
        report.fatal_error = (f"no enrollment record for engine "
                              f"{engine_name!r} on domain {domain.slug!r}")
        return report

    # 1. SMC-side probe — config now lives on the Domain's ApiKey.
    api_key = domain.api_key
    if api_key is None:
        report.fatal_error = ("no API key on file for this engine — re-run "
                              "enrollment from the Credentials page")
        return report

    smc_cfg = SMCConfig(
        url=api_key.smc_url,
        api_key=api_key.decrypted_key,
        domain=domain.smc_domain_name or "",
        api_version=api_key.api_version or "",
        verify_ssl=api_key.verify_ssl,
        timeout=api_key.timeout,
    )

    expected_dst = _split_csv_ips(access.destination_ip if access else "")
    rule_name = rule_name_for(engine_name)
    rule_probe = RuleProbeResult(rule_name=rule_name, rule_present_in_smc=False,
                                 expected_destinations=expected_dst)
    try:
        with smc_session(smc_cfg):
            policy_name = find_active_policy(engine_name)
            existing = find_ssh_access_rule(policy_name, rule_name)
            if existing:
                rule_probe.rule_present_in_smc = True
                rule_dst_names = existing.get("destination_names") or []
                # Destinations are Host element names like
                # "<rule_name>-dst-<i>"; we track the IPs on the access row,
                # not the names — so we compare counts and set membership
                # by *number of managed dst-* entries* vs expected.
                managed = [n for n in rule_dst_names
                           if n.startswith(f"{rule_name}-dst-")]
                rule_probe.actual_destinations = sorted(managed)
                expected_managed = sorted(
                    f"{rule_name}-dst-{i}" for i in range(len(expected_dst))
                )
                if expected_managed != rule_probe.actual_destinations:
                    report.rule_drift_messages.append(
                        f"SSH allow rule destination set drifted: "
                        f"expected {len(expected_managed)} entries, "
                        f"found {len(rule_probe.actual_destinations)} — "
                        f"reinstall the rule to align."
                    )
            else:
                report.rule_drift_messages.append(
                    f"SSH allow rule {rule_name!r} is MISSING from SMC "
                    f"policy {policy_name!r} — operator removed it out of "
                    f"band, or policy was rebuilt. Reinstall from the "
                    f"Credentials page."
                )
    except Exception as exc:
        rule_probe.error = str(exc)
        report.rule_drift_messages.append(
            f"Rule probe failed: {type(exc).__name__}: {exc}"
        )
    report.rule = rule_probe

    # 2. Per-node SSH probe (outside SMC session — pure paramiko + TCP)
    for c in creds:
        target = SSHTarget(hostname=c.hostname, port=c.ssh_port,
                           username=c.ssh_username)
        payload = SSHCredential(password=c.encrypted_password,
                                host_fingerprint=c.host_fingerprint)
        np = NodeProbeResult(node_index=c.node_index, hostname=c.hostname,
                             tcp_ok=False, auth_ok=False)

        ok, reason = tcp_probe(target, timeout=8)
        np.tcp_ok = ok
        if not ok:
            np.error = reason
            report.node_drift_messages.append(
                f"node {c.node_index} ({c.hostname}): TCP probe failed — "
                f"{reason}. Check that the SSH allow rule covers this IP "
                f"and the engine is online."
            )
            report.nodes.append(np)
            continue

        ok, reason = verify_credential(target, payload)
        np.auth_ok = ok
        if not ok:
            np.error = reason
            if "host key mismatch" in reason:
                np.fingerprint_match = False
                report.node_drift_messages.append(
                    f"node {c.node_index} ({c.hostname}): host key "
                    f"FINGERPRINT MISMATCH — engine was re-imaged or "
                    f"a MITM is in play. Use Force re-bootstrap to "
                    f"recapture the fingerprint after verifying the "
                    f"engine identity out-of-band."
                )
            elif "AUTH_FAIL" in reason:
                report.node_drift_messages.append(
                    f"node {c.node_index} ({c.hostname}): SSH password "
                    f"rejected — root password was changed externally. "
                    f"Use Force re-bootstrap to rotate via SMC API."
                )
            else:
                report.node_drift_messages.append(
                    f"node {c.node_index} ({c.hostname}): SSH verify "
                    f"failed — {reason}"
                )
        report.nodes.append(np)

    # 3. Bump state_refreshed_at on what verified successfully.
    now = datetime.now(timezone.utc)
    if rule_probe.rule_present_in_smc and access:
        # Rule probe doesn't tell us "destinations match" cleanly without
        # knowing operator intent — refresh the timestamp regardless of
        # destination drift. The drift message stays in the report so the
        # operator sees it; the fresh badge accurately reflects "we just
        # checked, here's what we found".
        access.state_refreshed_at = now
        access.last_seen_in_policy_at = now
    for c, np in zip(creds, report.nodes):
        if np.tcp_ok and np.auth_ok:
            c.state_refreshed_at = now
            c.last_verified_at = now
            c.last_verify_status = "ok"
            c.last_error = ""
        else:
            # Don't bump state_refreshed_at on failure — operator should
            # still see "stale" until they fix it. But DO record the
            # specific failure on the cred row so the badge reflects it.
            c.last_verify_status = "failed"
            c.last_error = np.error[:1000] if np.error else c.last_error

    db.session.commit()
    return report
