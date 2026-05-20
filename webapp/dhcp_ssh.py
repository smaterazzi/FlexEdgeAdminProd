"""
FlexEdgeAdmin — SSH primitives for DHCP Manager (password-only auth).

Auth model: root + Fernet-encrypted password (set by FlexEdge via SMC's
`change_ssh_pwd` API at enrollment) + pinned host fingerprint (TOFU on
first contact). The engine's `authorized_keys` is *not* touched.

Pure helpers — no Flask, no DB, no global state. The Blueprint orchestrates.
"""
import base64
import hashlib
import logging
import secrets
import socket
import string
from dataclasses import dataclass
from typing import Optional

import paramiko

logger = logging.getLogger(__name__)


@dataclass
class SSHTarget:
    hostname: str
    port: int = 22
    username: str = "root"
    timeout: int = 10


@dataclass
class SSHCredential:
    """Minimal credential payload — passed between the Blueprint and
    these helpers. Built from a DhcpEngineCredential row."""
    password: str
    host_fingerprint: str = ""     # "SHA256:xxxxx" form


class FingerprintMismatch(Exception):
    """Raised when the server's host key doesn't match the stored fingerprint.

    Treat as serious: either the engine was re-imaged or there's a MITM.
    The Blueprint logs this as status=failed.
    """


def _server_fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{b64}"


class _ExpectedKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Strict: accept the server iff its host key matches the stored fingerprint."""

    def __init__(self, expected_fingerprint: str):
        self.expected = expected_fingerprint

    def missing_host_key(self, client, hostname, key):
        got = _server_fingerprint(key)
        if got != self.expected:
            raise FingerprintMismatch(
                f"Host key fingerprint mismatch for {hostname}: "
                f"expected {self.expected}, got {got}"
            )


class _FirstContactPolicy(paramiko.MissingHostKeyPolicy):
    """Capture-and-accept the server's fingerprint on first contact."""

    def __init__(self):
        self.captured_fingerprint: Optional[str] = None

    def missing_host_key(self, client, hostname, key):
        self.captured_fingerprint = _server_fingerprint(key)


# ── Random password ────────────────────────────────────────────────────

# Avoid characters that need shell escaping or that some sshd
# configurations strip ($ ` " ' \ space).
_PWD_ALPHABET = string.ascii_letters + string.digits + "-_=+#%@!~"


def generate_password(length: int = 64) -> str:
    """Generate a strong random root password."""
    return "".join(secrets.choice(_PWD_ALPHABET) for _ in range(length))


# ── Connections ────────────────────────────────────────────────────────

def first_contact(target: SSHTarget, password: str) -> str:
    """Connect once with password auth, capture and return the host fingerprint.

    Used immediately after `change_ssh_pwd` during enrollment, before we
    have a stored fingerprint to pin against.

    Raises:
      paramiko.AuthenticationException — wrong password
      paramiko.SSHException             — connect/banner errors
      socket.error                       — network unreachable
    """
    policy = _FirstContactPolicy()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(policy)
    try:
        client.connect(
            hostname=target.hostname,
            port=target.port,
            username=target.username,
            password=password,
            timeout=target.timeout,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=target.timeout,
        )
        # Touch the connection to force the channel handshake to settle
        _exec_simple(client, "echo flexedge-first-contact")
    finally:
        client.close()
    if not policy.captured_fingerprint:
        raise RuntimeError("Did not observe a host fingerprint during first contact")
    return policy.captured_fingerprint


def ssh_connect(target: SSHTarget, cred: SSHCredential) -> paramiko.SSHClient:
    """Open an authenticated SSHClient using the stored password +
    pinned fingerprint. Caller is responsible for `.close()`.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_ExpectedKeyPolicy(cred.host_fingerprint))
    client.connect(
        hostname=target.hostname,
        port=target.port,
        username=target.username,
        password=cred.password,
        timeout=target.timeout,
        allow_agent=False,
        look_for_keys=False,
        banner_timeout=target.timeout,
    )
    return client


# ── Operations over an authenticated session ────────────────────────────

def _exec_simple(client: paramiko.SSHClient, cmd: str,
                 timeout: int = 15) -> tuple[str, str, int]:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


def run(target: SSHTarget, cred: SSHCredential, cmd: str,
        timeout: int = 30) -> tuple[str, str, int]:
    """Execute a command on the node. Return (stdout, stderr, exit_code)."""
    client = ssh_connect(target, cred)
    try:
        return _exec_simple(client, cmd, timeout=timeout)
    finally:
        client.close()


def get_file(target: SSHTarget, cred: SSHCredential,
             remote_path: str) -> bytes:
    """Read a remote file. Raises IOError if it doesn't exist."""
    client = ssh_connect(target, cred)
    try:
        with client.open_sftp() as sftp:
            with sftp.open(remote_path, "r") as f:
                return f.read()
    finally:
        client.close()


def put_file(target: SSHTarget, cred: SSHCredential,
             remote_path: str, content: bytes,
             mode: int = 0o600) -> None:
    """Atomic-write a file: tmp + chmod + rename."""
    import uuid
    tmp_path = f"{remote_path}.flexedge-tmp.{uuid.uuid4().hex}"
    client = ssh_connect(target, cred)
    try:
        with client.open_sftp() as sftp:
            with sftp.open(tmp_path, "w") as f:
                f.write(content)
            sftp.chmod(tmp_path, mode)
            try:
                sftp.posix_rename(tmp_path, remote_path)
            except (IOError, OSError):
                try:
                    sftp.remove(remote_path)
                except IOError:
                    pass
                sftp.rename(tmp_path, remote_path)
    except Exception:
        try:
            with client.open_sftp() as sftp:
                sftp.remove(tmp_path)
        except Exception:
            pass
        raise
    finally:
        client.close()


def verify_credential(target: SSHTarget, cred: SSHCredential
                      ) -> tuple[bool, str]:
    """Quick round-trip: connect with the stored password, run echo.

    Returns (True, "") on success, (False, error_message) on failure.

    Distinguishes auth failure from connect failure so the Blueprint can
    decide whether to offer the "Force re-bootstrap" recovery (only for
    auth failures — connect failures are usually network issues, not
    password rotation).
    """
    try:
        stdout, stderr, rc = run(target, cred, "echo flexedge-ok")
        if rc == 0 and "flexedge-ok" in stdout:
            return True, ""
        return False, f"unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}"
    except FingerprintMismatch as exc:
        return False, f"host key mismatch: {exc}"
    except paramiko.AuthenticationException:
        return False, "AUTH_FAIL: authentication failed (password may have been changed externally)"
    except (socket.error, paramiko.SSHException) as exc:
        return False, f"connection error: {exc}"
    except Exception as exc:      # pragma: no cover
        return False, f"unexpected error: {exc}"


def is_auth_failure(error_message: str) -> bool:
    """Helper: did `verify_credential` fail because of bad credentials?

    Used by the UI to show the "Force re-bootstrap" button only for the
    cases where rotating the password might fix it.
    """
    return "AUTH_FAIL" in (error_message or "")


def tcp_probe(target: SSHTarget, timeout: int = 10) -> tuple[bool, str]:
    """Reachability check before we touch SMC or password — opens a TCP
    socket to the SSH port and immediately closes it.

    Used by the bootstrap pre-flight to fail fast if the SSH allow rule
    push didn't actually open the path.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target.hostname, target.port))
        return True, ""
    except (socket.timeout, socket.error) as exc:
        return False, f"TCP {target.hostname}:{target.port} unreachable: {exc}"
    finally:
        try:
            s.close()
        except Exception:
            pass
