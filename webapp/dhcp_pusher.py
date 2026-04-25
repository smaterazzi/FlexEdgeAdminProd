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

log = logging.getLogger(__name__)

CONF_PATH = "/data/config/base/dhcp-server.conf"

# Delimiter markers — must round-trip through regex. Keep exactly one
# space-separated metadata key=value pair per token after the prefix so
# parsing stays predictable.
RESERVATIONS_BEGIN = "# FLEXEDGE-RESERVATIONS-BEGIN"
RESERVATIONS_END = "# FLEXEDGE-RESERVATIONS-END"

_RE_RESERVATIONS_BLOCK = re.compile(
    r"\n?" + re.escape(RESERVATIONS_BEGIN) + r"[^\n]*\n.*?\n"
    + re.escape(RESERVATIONS_END) + r"[^\n]*\n?",
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

def _check_preconditions(scope: DhcpScope) -> tuple[bool, str]:
    """Validate that a scope can be pushed.

    Returns (ok, reason). The reason is operator-facing.
    """
    if not scope.enabled_in_flexedge:
        return False, ("scope is not opted into FlexEdge management — "
                       "enable it before deploying")

    creds = (DhcpEngineCredential.query
             .filter_by(tenant_id=scope.tenant_id,
                        engine_name=scope.engine_name)
             .all())
    if not creds:
        return False, ("no SSH credentials enrolled for this engine — "
                       "go to DHCP Manager → Credentials and enroll the "
                       "cluster nodes first")

    unverified = [c for c in creds if not c.verified_at]
    if unverified:
        names = ", ".join(f"node {c.node_index}" for c in unverified)
        return False, f"unverified credentials: {names}"

    rule = (DhcpEngineSshAccess.query
            .filter_by(tenant_id=scope.tenant_id,
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
            host_name = _sanitize_host_name(
                f"flexedge-{scope.id}-{r.id}-{r.smc_host_name}"
            )[:63]   # ISC limits host names to 63 chars in practice
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


def merge_into_conf(existing: str, new_block: str) -> str:
    """Append (or replace) the FlexEdge reservations block in the file.

    If a previous FlexEdge block is present, replace it in place. Otherwise
    append to the end. Existing SMC-managed content is left exactly as-is.
    """
    # Strip an existing block if present (anywhere in the file).
    stripped = _RE_RESERVATIONS_BLOCK.sub("\n", existing).rstrip("\n")

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
    candidates = [
        # name, command (must exit 0 if signal was sent to ≥1 process)
        ("dhcp-server", "pkill -HUP -f dhcp-server"),
        ("dhcpd",       "pkill -HUP dhcpd"),
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
                  action: str) -> NodeResult:
    """Push the rendered block to one node and record a DhcpDeployment row.

    Each per-node failure is captured but does NOT raise — the orchestrator
    decides aggregate status from all results.
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
        new_content = merge_into_conf(existing, new_block)
        node.sha256_after = _sha256_text(new_content)

        if node.sha256_before == node.sha256_after:
            node.status = "ok"
            node.error = ""
            node.diff = "(no changes — file already in sync)"
            return node

        node.diff = _unified_diff(existing, new_content)

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
                         action: str = "push") -> PushResult:
    """Push a scope's FlexEdge-managed reservations to every node.

    Args:
        scope_id: ``DhcpScope`` primary key.
        operator_email: For audit trail in the file marker and DB rows.
        action: ``push`` for an operator-triggered deploy, ``resync`` for
                a re-run that re-applies the same content.

    Returns a ``PushResult`` summarizing per-node outcomes. Reservation
    rows are flipped to ``status=synced`` on full success or
    ``status=error`` on partial / total failure (with ``last_error``).
    All ``DhcpDeployment`` rows are committed before returning.
    """
    scope: DhcpScope = DhcpScope.query.get(scope_id)
    if not scope:
        return PushResult(scope_id=scope_id, engine_name="",
                          overall_status="blocked",
                          blocked_reason=f"scope {scope_id} not found")

    result = PushResult(scope_id=scope.id, engine_name=scope.engine_name,
                        overall_status="failed")

    # 1. Validate preconditions.
    ok, reason = _check_preconditions(scope)
    if not ok:
        result.overall_status = "blocked"
        result.blocked_reason = reason
        return result

    # 2. Gather credentials + reservations.
    creds = (DhcpEngineCredential.query
             .filter_by(tenant_id=scope.tenant_id,
                        engine_name=scope.engine_name)
             .order_by(DhcpEngineCredential.node_index)
             .all())
    reservations = (DhcpReservation.query
                    .filter_by(scope_id=scope.id)
                    .order_by(DhcpReservation.ip_address)
                    .all())

    log.info("Phase 4 push: scope=%s engine=%s nodes=%d reservations=%d "
             "action=%s by=%s",
             scope.id, scope.engine_name, len(creds), len(reservations),
             action, operator_email)

    # 3. Per-node push.
    for cred in creds:
        node_result = _push_to_node(scope, cred, reservations,
                                    operator_email, action)
        result.nodes.append(node_result)

        # Persist a DhcpDeployment audit row.
        deploy = DhcpDeployment(
            scope_id=scope.id,
            engine_name=scope.engine_name,
            node_index=node_result.node_index,
            node_hostname=node_result.node_hostname,
            action=action,
            status="ok" if node_result.status == "ok" else "failed",
            reservations_count=node_result.reservations_count,
            file_sha256_before=node_result.sha256_before,
            file_sha256_after=node_result.sha256_after,
            diff=node_result.diff,
            duration_ms=node_result.duration_ms,
            error=node_result.error or node_result.reload_warning,
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

    # 5. Update reservation rows.
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
