"""
FlexEdgeAdmin — DHCP Manager bootstrap orchestrator.

Stages a node-enrollment flow that's safe to run from the untrusted zone:

  Stage 1  Pre-flight (read-only, fully reversible)
  Stage 2  Network path: install SSH allow rule + push policy + TCP probe
           (each step is reversible until step 3 mutates the engine)
  Stage 3  Engine mutations: enable SSH daemon, set random root password
           via SMC, password-auth + capture host fingerprint
  Stage 4  Persist credential (password Fernet-encrypted)

Everything is split into small functions so the Blueprint can drive the
flow as multi-step interactive POSTs and surface intermediate state
(operator confirmation between rule push and password rotation).
"""
import logging
import re
import socket
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from webapp import smc_dhcp_client as smc
from webapp.dhcp_ssh import (
    SSHTarget, SSHCredential, FingerprintMismatch,
    first_contact, generate_password, tcp_probe, verify_credential,
)

logger = logging.getLogger(__name__)


# ── Per-engine concurrency lock ─────────────────────────────────────────

_engine_locks: dict[str, threading.Lock] = {}
_engine_locks_lock = threading.Lock()


def _get_engine_lock(engine_name: str) -> threading.Lock:
    with _engine_locks_lock:
        if engine_name not in _engine_locks:
            _engine_locks[engine_name] = threading.Lock()
        return _engine_locks[engine_name]


@contextmanager
def engine_bootstrap_lock(engine_name: str, timeout: int = 60):
    """Serialise bootstrap operations against the same engine.

    Two concurrent enrollments touching the same node would race on
    `change_ssh_pwd` and the loser's stored password becomes invalid.
    Per-engine lock keeps that off the table.
    """
    lock = _get_engine_lock(engine_name)
    acquired = lock.acquire(timeout=timeout)
    if not acquired:
        raise RuntimeError(
            f"Bootstrap on engine {engine_name!r} is already in progress; "
            f"refresh and retry in a minute."
        )
    try:
        yield
    finally:
        lock.release()


# ── Source-IP detection ─────────────────────────────────────────────────

_PUBLIC_IP_PROBES = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
]
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def probe_public_ip(timeout: int = 5) -> tuple[Optional[str], list[str]]:
    """Try a few public-IP echo services. Returns (chosen_ip, attempts_log).

    The result is offered to the operator as a *suggestion* — they can
    override before saving (some deployments want a specific NAT egress IP
    that differs from what these services report).
    """
    log: list[str] = []
    for url in _PUBLIC_IP_PROBES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "FlexEdgeAdmin"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode().strip()
                log.append(f"{url} → {body!r}")
                if _IP_RE.match(body):
                    return body, log
        except (urllib.error.URLError, socket.timeout, ValueError) as exc:
            log.append(f"{url} → error: {exc}")
        except Exception as exc:
            log.append(f"{url} → unexpected: {exc}")
    return None, log


# ── Stage 1 — Pre-flight ────────────────────────────────────────────────

@dataclass
class PreflightResult:
    ok: bool
    policy_name: str = ""
    error: str = ""


def preflight(engine_name: str) -> PreflightResult:
    """Read-only checks before we mutate anything.

    Caller should already be inside an `smc_session` context.
    """
    try:
        policy_name = smc.find_active_policy(engine_name)
    except Exception as exc:
        return PreflightResult(ok=False, error=str(exc))
    return PreflightResult(ok=True, policy_name=policy_name)


# ── Stage 2 — Network path ──────────────────────────────────────────────

@dataclass
class RuleInstallResult:
    ok: bool
    rule_href: str = ""
    rule_name: str = ""
    policy_name: str = ""
    already_present: bool = False
    error: str = ""


def rule_name_for(engine_name: str) -> str:
    """Stable tag used as the rule's name and lookup key."""
    slug = re.sub(r"[^A-Za-z0-9._-]", "-", engine_name)[:60]
    return f"flexedge-dhcp-mgmt-ssh-{slug}"


def install_ssh_rule(engine_name: str, source_ip: str, destination_ip: str,
                     created_by_email: str = "",
                     fea_hostname: str = "") -> RuleInstallResult:
    """Pre-flight + create rule + push policy. Idempotent.

    Caller MUST be inside an `smc_session` context.
    """
    pre = preflight(engine_name)
    if not pre.ok:
        return RuleInstallResult(ok=False, error=pre.error)

    name = rule_name_for(engine_name)
    existing = smc.find_ssh_access_rule(pre.policy_name, name)
    if existing:
        # Already in place — caller may still want to push policy if the
        # rule was added but never installed.
        return RuleInstallResult(
            ok=True, rule_href=existing["href"],
            rule_name=name, policy_name=pre.policy_name,
            already_present=True,
        )

    audit = (f"FlexEdgeAdmin auto-managed SSH allow rule. "
             f"Operator: {created_by_email or 'unknown'}. "
             f"FlexEdge host: {fea_hostname or 'unknown'}.")
    try:
        href = smc.add_ssh_access_rule(
            policy_name=pre.policy_name,
            rule_name=name,
            source_ip=source_ip,
            destination_ip=destination_ip,
            comment=audit,
        )
    except Exception as exc:
        return RuleInstallResult(ok=False, policy_name=pre.policy_name,
                                 rule_name=name,
                                 error=f"create rule failed: {exc}")
    return RuleInstallResult(ok=True, rule_href=href, rule_name=name,
                             policy_name=pre.policy_name,
                             already_present=False)


def upload_policy(engine_name: str, policy_name: str) -> tuple[bool, str]:
    """Trigger policy install. Returns (ok, message_or_error).

    Caller is inside `smc_session`.
    """
    try:
        result = smc.policy_upload(engine_name, policy_name)
        return True, str(result)
    except Exception as exc:
        return False, f"policy upload failed: {exc}"


def remove_rule(engine_name: str, policy_name: str
                ) -> tuple[bool, str]:
    """Tear down our managed rule + push policy. Idempotent.

    Caller is inside `smc_session`.
    """
    name = rule_name_for(engine_name)
    rule_existed, msg = smc.remove_ssh_access_rule(policy_name, name)
    if not rule_existed:
        return True, "rule already absent"
    if "ok" not in msg:
        return False, msg
    return True, "removed"


# ── Stage 3 — Engine mutations + first contact ──────────────────────────

@dataclass
class EnrollmentResult:
    ok: bool
    new_password: str = ""
    host_fingerprint: str = ""
    error: str = ""
    failed_at_stage: str = ""    # 'enable_ssh' | 'change_pwd' | 'connect' | 'verify'


def enroll_node(engine_name: str, node_index: int,
                target: SSHTarget, audit_comment: str = "",
                tcp_probe_timeout: int = 10) -> EnrollmentResult:
    """Enable SSH on the node, rotate root password to a random value via
    SMC API, then verify by SSH-connecting with that password (TOFU on host
    fingerprint).

    Caller is inside `smc_session`. The returned password should be
    persisted (Fernet-encrypted) by the Blueprint.
    """
    # Pre-stage: TCP probe so we fail fast if the rule push didn't open the path
    ok, err = tcp_probe(target, timeout=tcp_probe_timeout)
    if not ok:
        return EnrollmentResult(
            ok=False, failed_at_stage="connect",
            error=f"TCP probe failed before enrollment: {err}. "
                  f"Verify the SSH allow rule was installed and policy uploaded.",
        )

    # Stage 3a: enable SSH daemon
    try:
        smc.set_node_ssh_enabled(engine_name, node_index, True,
                                 comment=audit_comment)
    except Exception as exc:
        return EnrollmentResult(ok=False, failed_at_stage="enable_ssh",
                                error=f"enable SSH on node failed: {exc}")

    # Stage 3b: change password
    new_password = generate_password()
    try:
        smc.change_node_ssh_password(engine_name, node_index, new_password,
                                     comment=audit_comment)
    except Exception as exc:
        return EnrollmentResult(ok=False, failed_at_stage="change_pwd",
                                error=f"change_ssh_pwd failed: {exc}",
                                new_password=new_password)

    # Stage 3c: connect with the new password (TOFU on host fingerprint)
    try:
        fingerprint = first_contact(target, new_password)
    except Exception as exc:
        return EnrollmentResult(
            ok=False, failed_at_stage="connect",
            new_password=new_password,
            error=f"SSH connect with new password failed: {exc}. "
                  f"The new password IS set on the node — re-running this "
                  f"enrollment will rotate it again.",
        )

    # Stage 3d: round-trip verify with the captured fingerprint pinned
    cred = SSHCredential(password=new_password, host_fingerprint=fingerprint)
    ok, err = verify_credential(target, cred)
    if not ok:
        return EnrollmentResult(
            ok=False, failed_at_stage="verify",
            new_password=new_password, host_fingerprint=fingerprint,
            error=f"key-pinned verify failed: {err}",
        )

    return EnrollmentResult(
        ok=True, new_password=new_password, host_fingerprint=fingerprint,
    )


# ── Force re-bootstrap (A3 recovery path) ───────────────────────────────

def force_reset_password(engine_name: str, node_index: int,
                         target: SSHTarget,
                         existing_fingerprint: str = "",
                         audit_comment: str = "") -> EnrollmentResult:
    """Operator-triggered when an out-of-band password change has locked
    us out. Rotates the password and re-verifies. Reuses the stored host
    fingerprint if any — if it changes, it's a real MITM signal, not a
    routine rotation.
    """
    new_password = generate_password()
    try:
        smc.change_node_ssh_password(engine_name, node_index, new_password,
                                     comment=audit_comment)
    except Exception as exc:
        return EnrollmentResult(ok=False, failed_at_stage="change_pwd",
                                error=f"change_ssh_pwd failed: {exc}")

    if existing_fingerprint:
        cred = SSHCredential(password=new_password,
                             host_fingerprint=existing_fingerprint)
        ok, err = verify_credential(target, cred)
        if ok:
            return EnrollmentResult(ok=True, new_password=new_password,
                                    host_fingerprint=existing_fingerprint)
        # Fingerprint mismatch usually means engine was re-imaged. Recover
        # by capturing a fresh fingerprint via TOFU and re-verifying.
        if isinstance(err, str) and "host key mismatch" in err:
            try:
                new_fp = first_contact(target, new_password)
            except Exception as exc:
                return EnrollmentResult(ok=False, failed_at_stage="connect",
                                        new_password=new_password,
                                        error=f"re-fingerprint after rotation failed: {exc}")
            return EnrollmentResult(ok=True, new_password=new_password,
                                    host_fingerprint=new_fp)
        return EnrollmentResult(ok=False, failed_at_stage="verify",
                                new_password=new_password,
                                host_fingerprint=existing_fingerprint,
                                error=err)

    # No existing fingerprint — capture fresh
    try:
        fp = first_contact(target, new_password)
    except Exception as exc:
        return EnrollmentResult(ok=False, failed_at_stage="connect",
                                new_password=new_password,
                                error=f"first_contact failed: {exc}")
    return EnrollmentResult(ok=True, new_password=new_password,
                            host_fingerprint=fp)
