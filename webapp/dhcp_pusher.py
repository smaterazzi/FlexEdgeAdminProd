"""
FlexEdgeAdmin — DHCP Manager Phase 4: engine-side reservation push.

Writes the FlexEdge-managed reservations (and, in a follow-up phase,
scope-level options) to ``/data/config/base/dhcp-server.conf`` on each
cluster node, then reloads the dhcpd daemon.

Design (per docs/DHCP-ReservationStrategy.md):
  - Reservations are appended at the end of the file inside a delimited
    block so SMC's subnet { ... } block stays untouched. Re-runs replace
    the existing FlexEdge block in place.
  - host { ... } blocks at the top level are valid ISC syntax — ISC dhcpd
    matches them by IP into the surrounding subnet.
  - Per-node atomic write via ``put_file()`` (tmp + rename).
  - Per-deployment audit row in ``dhcp_deployments`` with sha256_before/after.
  - Best-effort SIGHUP via ``pkill -HUP``; if the reload fails we surface
    a warning but do not fail the deployment — the operator can refresh
    the policy from SMC to force a reload.

Scope-level options (``dhcp_scopes.options_json``) are NOT pushed in this
iteration — the column exists, the UI surfaces them, but they require
modifying SMC's subnet block and that's gated by Phase 0 lab validation.
A follow-up phase will inject them once the persistence test confirms
the engine doesn't overwrite our markers.
"""

import difflib
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import paramiko

from shared.db import db
from webapp.models import (
    DhcpScope, DhcpReservation, DhcpDeployment, DhcpEngineCredential,
    DhcpEngineSshAccess,
)
from webapp.dhcp_ssh import (
    SSHTarget, SSHCredential,
    tcp_probe, verify_credential, run, get_file, put_file,
)
from webapp.dhcp_bootstrap import engine_bootstrap_lock as engine_op_lock

log = logging.getLogger(__name__)

CONF_PATH = "/data/config/base/dhcp-server.conf"

# Delimiter markers. Each scope owns its own delimited block, anchored by
# `scope_id=N` on both BEGIN and END lines, so a deploy on one scope never
# touches another scope's reservations on the same engine.
RESERVATIONS_BEGIN = "# FLEXEDGE-RESERVATIONS-BEGIN"
RESERVATIONS_END = "# FLEXEDGE-RESERVATIONS-END"


def _scope_block_re(scope_id: int) -> re.Pattern:
    sid = re.escape(str(int(scope_id)))
    return re.compile(
        r"\n?" + re.escape(RESERVATIONS_BEGIN) + r" scope_id=" + sid
        + r"(?:\s[^\n]*)?\n.*?\n"
        + re.escape(RESERVATIONS_END) + r" scope_id=" + sid
        + r"(?:\s[^\n]*)?\n?",
        re.DOTALL,
    )


# ── Result types ─────────────────────────────────────────────────────────

@dataclass
class NodeResult:
    node_index: int
    node_hostname: str
    status: str               # "ok" | "failed" | "skipped"
    reservations_count: int = 0
    sha256_before: str = ""
    sha256_after: str = ""
    diff: str = ""
    duration_ms: int = 0
    error: str = ""
    reload_warning: str = ""


@dataclass
class PushResult:
    scope_id: int
    engine_name: str
    overall_status: str       # "ok" | "partial" | "failed" | "blocked"
    blocked_reason: str = ""
    nodes: list[NodeResult] = field(default_factory=list)

    @property
    def successful_nodes(self) -> int:
        return sum(1 for n in self.nodes if n.status == "ok")

    @property
    def failed_nodes(self) -> int:
        return sum(1 for n in self.nodes if n.status == "failed")


# ── Pre-flight validation ────────────────────────────────────────────────

def _check_preconditions(scope: DhcpScope, dry_run: bool = False
                         ) -> tuple[bool, str]:
    """Validate that a scope can be pushed.

    Returns (ok, reason). The reason is operator-facing.

    Phase 0 gate: if no operator has marked Phase 0 (lab persistence test)
    as validated, refuse to push — the engine may be silently overwriting
    /data/config/base/dhcp-server.conf on policy refresh, in which case
    every deploy looks ok but the reservations vanish on the next SMC
    save. Operator confirms by clicking "I validated Phase 0" on the
    DHCP Manager dashboard after running the lab procedure.

    Dry-run bypasses the Phase 0 gate (a preview never writes the file,
    so persistence concerns don't apply); the credential and SSH-rule
    checks still apply because we need an authenticated SSH read to
    fetch the current file.
    """
    if not dry_run:
        # Local import to avoid a circular dep — dhcp_manager imports dhcp_pusher.
        from webapp.dhcp_manager import is_phase0_validated
        if not is_phase0_validated():
            return False, (
                "Phase 0 lab persistence test has not been validated. Until "
                "an operator confirms that engine policy refresh / upload / "
                "reboot does NOT overwrite /data/config/base/dhcp-server.conf, "
                "deploys are blocked to prevent silent reservation loss. "
                "Run the procedure in docs/DHCP-Phase0-LabTest.md, then click "
                "'I validated Phase 0' on the DHCP Manager dashboard. "
                "(You can still use 'Preview' to see what a deploy would write.)"
            )

    if not scope.enabled_in_flexedge:
        return False, ("scope is not opted into FlexEdge management — "
                       "enable it before deploying")

    # Phase B.2: scope.domain_id is the canonical scope FK (Phase B.1
    # backfilled it from the legacy tenant_id).
    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=scope.domain_id,
                        engine_name=scope.engine_name)
             .all())
    if not creds:
        return False, ("no SSH credentials enrolled for this engine — "
                       "go to DHCP Manager → Credentials and enroll the "
                       "cluster nodes first")

    unverified = [c for c in creds
                  if not c.last_verified_at or c.last_verify_status != "ok"]
    if unverified:
        names = ", ".join(f"node {c.node_index}" for c in unverified)
        return False, (f"credentials need verification before deploy "
                       f"({names}) — open DHCP Manager → Credentials and "
                       f"click Verify on each affected row, then retry")

    rule = (DhcpEngineSshAccess.query
            .filter_by(domain_id=scope.domain_id,
                       engine_name=scope.engine_name).first())
    if not rule:
        return False, ("SSH allow rule is missing in SMC — go to DHCP "
                       "Manager → Credentials and reinstall the rule")

    return True, ""


# ── Content rendering ────────────────────────────────────────────────────

def _sanitize_host_name(s: str) -> str:
    """ISC dhcpd host names must be alphanumeric + dash/dot/underscore."""
    s = re.sub(r"[^A-Za-z0-9\-_.]", "-", s.strip())
    return s or "res"


def _normalize_mac(mac: str) -> str:
    """Lowercase colon form: aa:bb:cc:dd:ee:ff."""
    return mac.strip().lower().replace("-", ":")


def render_reservations_block(scope: DhcpScope,
                              reservations: list[DhcpReservation],
                              operator_email: str = "") -> str:
    """Build the delimited block to append to dhcp-server.conf.

    Returns "" if there are no reservations (caller decides whether to
    still write — e.g. to clear out a previous block).
    """
    if not reservations:
        body_lines = ["# (no FlexEdge reservations for this scope)"]
    else:
        body_lines = []
        for r in reservations:
            # Truncation-safe: ``flexedge-r<r.id>`` is always preserved at
            # the front because the slug suffix is what gets cut. Since
            # ``r.id`` is a globally unique primary key, two reservations
            # can never produce the same host name even if their slugs are
            # similar enough to be identical after truncation.
            prefix = f"flexedge-r{int(r.id)}"
            slug = _sanitize_host_name(r.smc_host_name)
            host_name = f"{prefix}-{slug}"[:63] if slug else prefix
            mac = _normalize_mac(r.mac_address)
            body_lines.append(
                f"host {host_name} {{ "
                f"hardware ethernet {mac}; "
                f"fixed-address {r.ip_address}; "
                f"}}  # smc-host={r.smc_host_name}"
            )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    op = operator_email or "system"
    metadata = (
        f"scope_id={scope.id} engine={scope.engine_name} "
        f"interface={scope.interface_id} "
        f"reservations={len(reservations)} "
        f"pushed_at={timestamp} pushed_by={op}"
    )

    parts = [
        f"{RESERVATIONS_BEGIN} {metadata}",
        "# DO NOT EDIT — managed by FlexEdgeAdmin",
        "# Edits here will be overwritten on the next deployment.",
        "",
    ]
    parts.extend(body_lines)
    parts.append(f"{RESERVATIONS_END} scope_id={scope.id}")
    return "\n".join(parts)


def merge_into_conf(existing: str, new_block: str, scope_id: int) -> str:
    """Append (or replace) THIS scope's FlexEdge reservations block.

    Only the block tagged with the matching ``scope_id`` is replaced —
    blocks belonging to other scopes on the same engine are preserved
    verbatim. Existing SMC-managed content is left exactly as-is.
    """
    pattern = _scope_block_re(scope_id)
    stripped = pattern.sub("\n", existing).rstrip("\n")

    if not new_block.strip():
        return stripped + "\n"

    # Always end with a single trailing newline.
    return stripped + "\n\n" + new_block + "\n"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _unified_diff(before: str, after: str, max_lines: int = 200) -> str:
    """Unified diff trimmed to ``max_lines`` for log brevity."""
    diff = difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        fromfile="dhcp-server.conf (before)",
        tofile="dhcp-server.conf (after)",
        lineterm="",
        n=2,
    )
    out = list(diff)
    if len(out) > max_lines:
        out = out[:max_lines] + [f"... ({len(out) - max_lines} more lines truncated)"]
    return "\n".join(out)


# ── dhcpd reload (best effort) ───────────────────────────────────────────

def _reload_dhcpd(target: SSHTarget, cred: SSHCredential) -> str:
    """Attempt a SIGHUP-style reload on the engine's DHCP daemon.

    Returns "" on success, or a warning string the caller can surface to
    the operator. We never fail the deployment over a failed reload — the
    operator can force a reload by refreshing the policy in SMC.

    Forcepoint engines run the daemon under a few possible names; we try
    them in order and stop at the first that signals at least one process.
    """
    # Exact-match (-x) on argv[0] so we never HUP an unrelated process
    # whose cmdline happens to contain the string (e.g. an editor session
    # on dhcp-server.conf, a tail -f, etc.).
    candidates = [
        # name, command (must exit 0 if signal was sent to ≥1 process)
        ("dhcp-server", "pkill -HUP -x dhcp-server"),
        ("dhcpd",       "pkill -HUP -x dhcpd"),
    ]
    for name, cmd in candidates:
        try:
            stdout, stderr, rc = run(target, cred, cmd, timeout=15)
        except Exception as exc:
            return f"reload skipped: SSH error during {name!r}: {exc}"
        if rc == 0:
            return ""    # ≥1 matching process signalled
        # rc=1 from pkill means "no process matched" — try the next name.
        if rc != 1:
            return (f"reload command {cmd!r} returned rc={rc} "
                    f"stdout={stdout!r} stderr={stderr!r}")

    return ("could not signal the DHCP daemon — neither dhcp-server nor "
            "dhcpd matched. Run a policy refresh in SMC to force a reload.")


# ── Per-node push ────────────────────────────────────────────────────────

def _push_to_node(scope: DhcpScope,
                  cred_row: DhcpEngineCredential,
                  reservations: list[DhcpReservation],
                  operator_email: str,
                  action: str,
                  dry_run: bool = False) -> NodeResult:
    """Push the rendered block to one node and record a DhcpDeployment row.

    Each per-node failure is captured but does NOT raise — the orchestrator
    decides aggregate status from all results.

    When ``dry_run`` is True: read the current file, render the new content,
    compute sha256 + unified diff, and return — but skip ``put_file``, the
    post-write verify, and the dhcpd reload. Use this to surface the diff
    in the UI before the operator commits.
    """
    started = time.monotonic()
    node = NodeResult(node_index=cred_row.node_index,
                      node_hostname=cred_row.hostname,
                      status="failed",
                      reservations_count=len(reservations))

    target = SSHTarget(hostname=cred_row.hostname,
                       port=cred_row.ssh_port,
                       username=cred_row.ssh_username)
    payload = SSHCredential(password=cred_row.encrypted_password,
                            host_fingerprint=cred_row.host_fingerprint)

    try:
        # 1. Pre-flight TCP probe — fail fast if SSH path is closed.
        ok, reason = tcp_probe(target, timeout=8)
        if not ok:
            raise RuntimeError(f"TCP probe failed: {reason}")

        # 2. Verify password (catch silent rotation early).
        ok, reason = verify_credential(target, payload)
        if not ok:
            raise RuntimeError(f"credential verify failed: {reason}")

        # 3. Read current file (or treat as empty if missing).
        try:
            existing = get_file(target, payload, CONF_PATH).decode("utf-8",
                                                                   errors="replace")
        except IOError:
            log.warning("Node %s: %s missing — will create",
                        cred_row.hostname, CONF_PATH)
            existing = ""
        node.sha256_before = _sha256_text(existing)

        # 4. Render new content.
        new_block = render_reservations_block(scope, reservations,
                                              operator_email)
        new_content = merge_into_conf(existing, new_block, scope.id)
        node.sha256_after = _sha256_text(new_content)

        if node.sha256_before == node.sha256_after:
            node.status = "ok"
            node.error = ""
            node.diff = "(no changes — file already in sync)"
            return node

        node.diff = _unified_diff(existing, new_content)

        # Dry-run stops here: we computed the diff but won't touch the
        # file or trigger a reload. The DhcpDeployment row written by
        # the orchestrator will carry action="dry_run" so it's clearly
        # distinguishable in the audit log.
        if dry_run:
            node.status = "ok"
            node.error = ""
            return node

        # 5. Atomic write (mode 0644 — dhcpd reads as root).
        put_file(target, payload, CONF_PATH,
                 new_content.encode("utf-8"), mode=0o644)

        # 6. Verify by re-reading.
        verify_text = get_file(target, payload, CONF_PATH).decode("utf-8",
                                                                  errors="replace")
        if _sha256_text(verify_text) != node.sha256_after:
            raise RuntimeError("post-write verification failed: "
                               "file hash on disk does not match what we wrote")

        # 7. Best-effort dhcpd reload.
        node.reload_warning = _reload_dhcpd(target, payload)

        node.status = "ok"
        node.error = ""
        return node

    except paramiko.AuthenticationException as exc:
        node.error = f"AUTH_FAIL: {exc}"
    except Exception as exc:
        node.error = f"{type(exc).__name__}: {exc}"
    finally:
        node.duration_ms = int((time.monotonic() - started) * 1000)

    return node


# ── Orchestrator ─────────────────────────────────────────────────────────

def push_scope_to_engine(scope_id: int,
                         operator_email: str,
                         action: str = "push",
                         dry_run: bool = False) -> PushResult:
    """Push a scope's FlexEdge-managed reservations to every node.

    Serialised per-engine via ``engine_op_lock`` (shared with bootstrap
    operations) so concurrent deploys on the same engine — or against
    sibling scopes that share the same ``dhcp-server.conf`` file — cannot
    race on the file. Returns a ``blocked`` result if another op holds
    the lock past the timeout.

    Args:
        scope_id: ``DhcpScope`` primary key.
        operator_email: For audit trail in the file marker and DB rows.
        action: ``push`` for an operator-triggered deploy, ``resync`` for
                a re-run that re-applies the same content, ``dry_run``
                for a preview-only call.
        dry_run: If True, runs the SSH read + render + diff path but
                 SKIPS the file write and reload. Reservation row status
                 is NOT mutated. Use to surface the diff in the UI for
                 operator confirmation before committing.

    Returns a ``PushResult`` summarizing per-node outcomes. Reservation
    rows are flipped to ``status=synced`` on full success or
    ``status=error`` on partial / total failure (with ``last_error``) —
    except in dry-run, which leaves them alone.
    All ``DhcpDeployment`` rows are committed before returning.
    """
    scope: DhcpScope = DhcpScope.query.get(scope_id)
    if not scope:
        return PushResult(scope_id=scope_id, engine_name="",
                          overall_status="blocked",
                          blocked_reason=f"scope {scope_id} not found")

    try:
        with engine_op_lock(scope.engine_name, timeout=300):
            return _push_scope_to_engine_locked(scope, operator_email,
                                                action, dry_run)
    except RuntimeError as exc:
        return PushResult(scope_id=scope.id, engine_name=scope.engine_name,
                          overall_status="blocked",
                          blocked_reason=(f"another deploy or enrollment is "
                                          f"in progress on this engine: {exc}"))


def _push_scope_to_engine_locked(scope: DhcpScope,
                                 operator_email: str,
                                 action: str,
                                 dry_run: bool) -> PushResult:
    """Locked body of ``push_scope_to_engine`` — caller holds engine_op_lock."""
    result = PushResult(scope_id=scope.id, engine_name=scope.engine_name,
                        overall_status="failed")

    # 1. Validate preconditions. Dry-run bypasses Phase 0 only.
    ok, reason = _check_preconditions(scope, dry_run=dry_run)
    if not ok:
        result.overall_status = "blocked"
        result.blocked_reason = reason
        return result

    # 2. Gather credentials + reservations.
    creds = (DhcpEngineCredential.query
             .filter_by(domain_id=scope.domain_id,
                        engine_name=scope.engine_name)
             .order_by(DhcpEngineCredential.node_index)
             .all())
    reservations = (DhcpReservation.query
                    .filter_by(scope_id=scope.id)
                    .order_by(DhcpReservation.ip_address)
                    .all())

    log.info("Phase 4 push: scope=%s engine=%s nodes=%d reservations=%d "
             "action=%s dry_run=%s by=%s",
             scope.id, scope.engine_name, len(creds), len(reservations),
             action, dry_run, operator_email)

    audit_action = "dry_run" if dry_run else action

    # 3. Per-node push.
    for cred in creds:
        node_result = _push_to_node(scope, cred, reservations,
                                    operator_email, action,
                                    dry_run=dry_run)
        result.nodes.append(node_result)

        # Persist a DhcpDeployment audit row. ``error`` and ``reload_warning``
        # are *separate* concerns: ``error`` means the file write failed,
        # ``reload_warning`` means the file was written but the dhcpd HUP
        # didn't reach an active process. Both can be empty (full success).
        deploy = DhcpDeployment(
            scope_id=scope.id,
            engine_name=scope.engine_name,
            node_index=node_result.node_index,
            node_hostname=node_result.node_hostname,
            action=audit_action,
            status="ok" if node_result.status == "ok" else "failed",
            reservations_count=node_result.reservations_count,
            file_sha256_before=node_result.sha256_before,
            file_sha256_after=node_result.sha256_after,
            diff=node_result.diff,
            duration_ms=node_result.duration_ms,
            error=node_result.error,
            reload_warning=node_result.reload_warning,
        )
        db.session.add(deploy)

    db.session.commit()

    # 4. Aggregate status.
    if result.successful_nodes == len(result.nodes):
        result.overall_status = "ok"
    elif result.successful_nodes > 0:
        result.overall_status = "partial"
    else:
        result.overall_status = "failed"

    # Per-node SSH success is fresh state evidence; bump the cred row's
    # state_refreshed_at on each cred whose node-result was ok. Skipped
    # in dry-run because we only read, not act, but reads still prove
    # connectivity so we DO bump there too.
    now = datetime.now(timezone.utc)
    cred_by_node_index = {c.node_index: c for c in creds}
    any_node_ok = False
    for node_result in result.nodes:
        if node_result.status == "ok":
            any_node_ok = True
            c = cred_by_node_index.get(node_result.node_index)
            if c is not None:
                c.state_refreshed_at = now
                c.last_verified_at = now
                c.last_verify_status = "ok"
                c.last_error = ""
    # If at least one node verified, the rule was in policy too
    # (preflight checked + the connect itself proved it).
    if any_node_ok:
        access = (DhcpEngineSshAccess.query
                  .filter_by(domain_id=scope.domain_id,
                             engine_name=scope.engine_name)
                  .first())
        if access:
            access.state_refreshed_at = now
            access.last_seen_in_policy_at = now

    # 5. Update reservation rows — only when we actually wrote.
    # Dry-run leaves reservation status alone so the operator can still
    # see what's pending after a preview.
    if not dry_run:
        now = datetime.now(timezone.utc)
        if result.overall_status == "ok":
            for r in reservations:
                r.status = "synced"
                r.last_synced_at = now
                r.last_error = ""
        else:
            # Leave already-synced rows alone; only flag this scope's pending ones.
            for r in reservations:
                if r.status == "pending":
                    r.status = "error"
                    r.last_error = (f"deploy {result.overall_status} — "
                                    f"{result.failed_nodes}/{len(result.nodes)} "
                                    f"nodes failed (see deployment log)")

    db.session.commit()
    return result


def resync_scope(scope_id: int, operator_email: str) -> PushResult:
    """Convenience wrapper: same as ``push`` but logged with action='resync'."""
    return push_scope_to_engine(scope_id, operator_email, action="resync")


def preview_scope(scope_id: int, operator_email: str) -> PushResult:
    """Dry-run: render + diff per node, but do not write or reload.

    Returns the same ``PushResult`` shape as a real push so the caller
    can render per-node diffs in the UI. Reservation rows are not
    mutated. ``DhcpDeployment`` rows are still written, with
    ``action="dry_run"`` for audit traceability.
    """
    return push_scope_to_engine(scope_id, operator_email,
                                action="push", dry_run=True)
