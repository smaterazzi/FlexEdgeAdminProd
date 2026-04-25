"""
FlexEdgeAdmin — Browser SSH terminal bridge.

Connects xterm.js in the browser to a paramiko interactive shell on the
target engine node, over a WebSocket served by flask-sock.

Constraints (from CLAUDE.md § Engines):

    * Exactly **one** opportunistic SSH session per user. Opening a new
      terminal kills any existing session for that user.
    * Connect/disconnect audit log only — no keystroke recording.
    * Inherits Entra ID admin-role auth via the Flask session.
    * Closing the browser tab terminates the SSH session.

Stack:

    * flask-sock (sync, works with gunicorn -k gthread)
    * paramiko `invoke_shell()` — interactive PTY over a single channel
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

import paramiko
from flask import session as flask_session
from flask import url_for, redirect, request, render_template, current_app

from shared.db import db
from webapp.models import (
    DhcpEngineCredential, EngineTerminalSession, User,
)

log = logging.getLogger(__name__)


# ── One-session-per-user registry ────────────────────────────────────────

_sessions_lock = threading.Lock()
_active_by_user: dict[str, "TerminalBridge"] = {}


def _utcnow():
    return datetime.now(timezone.utc)


# ── Bridge ───────────────────────────────────────────────────────────────

class TerminalBridge:
    """One paramiko interactive shell wired to one WebSocket."""

    def __init__(self, ws, cred: DhcpEngineCredential, user_email: str,
                 audit_row: EngineTerminalSession, source_ip: str):
        self.ws = ws
        self.cred = cred
        self.user_email = user_email
        self.audit_row = audit_row
        self.source_ip = source_ip
        self.client: paramiko.SSHClient | None = None
        self.channel: paramiko.Channel | None = None
        self._closed = False
        self._reader_thread: threading.Thread | None = None

    # paramiko side ──

    def open_ssh(self) -> None:
        client = paramiko.SSHClient()
        # Same fingerprint-pinning policy used by dhcp_ssh.ssh_connect
        from webapp.dhcp_ssh import _ExpectedKeyPolicy   # type: ignore
        client.set_missing_host_key_policy(
            _ExpectedKeyPolicy(self.cred.host_fingerprint)
        )
        client.connect(
            hostname=self.cred.hostname,
            port=self.cred.ssh_port or 22,
            username=self.cred.ssh_username or "root",
            password=self.cred.encrypted_password,  # EncryptedString returns plaintext on read
            timeout=20,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=20,
        )
        chan = client.invoke_shell(term="xterm-256color", width=120, height=32)
        chan.settimeout(0.0)  # non-blocking reads
        self.client = client
        self.channel = chan

    # bridge loop ──

    def _ssh_to_ws_loop(self):
        """Read SSH stdout/stderr, forward to WebSocket. Runs in a thread."""
        try:
            while not self._closed and self.channel and not self.channel.closed:
                if self.channel.recv_ready():
                    data = self.channel.recv(4096)
                    if not data:
                        break
                    try:
                        self.ws.send(data.decode("utf-8", errors="replace"))
                    except Exception:
                        break
                elif self.channel.recv_stderr_ready():
                    data = self.channel.recv_stderr(4096)
                    if data:
                        try:
                            self.ws.send(data.decode("utf-8", errors="replace"))
                        except Exception:
                            break
                else:
                    # No data; small sleep to avoid spinning the CPU
                    if self.channel.exit_status_ready():
                        break
                    threading_sleep(0.02)
        except Exception as exc:
            log.debug("ssh→ws loop ended: %s", exc)
        finally:
            self.close(reason="server_close")

    def run(self):
        """Main loop: pump WebSocket → SSH; reader thread handles SSH → WS."""
        self._reader_thread = threading.Thread(
            target=self._ssh_to_ws_loop, daemon=True,
            name=f"term-reader-{self.audit_row.id}",
        )
        self._reader_thread.start()

        try:
            while not self._closed:
                msg = self.ws.receive(timeout=1.0)
                if msg is None:
                    if self.channel is None or self.channel.closed:
                        break
                    continue
                if isinstance(msg, str):
                    # Frontend convention: control frames start with "\x00"
                    # followed by a JSON object; data frames are raw bytes.
                    if msg.startswith("\x00"):
                        self._handle_control(msg[1:])
                    else:
                        self.channel.send(msg)
                elif isinstance(msg, (bytes, bytearray)):
                    self.channel.send(msg)
        except Exception as exc:
            log.debug("ws→ssh loop ended: %s", exc)
        finally:
            self.close(reason="disconnect")

    def _handle_control(self, payload: str):
        """JSON control messages from the browser (e.g. resize)."""
        try:
            import json
            data = json.loads(payload or "{}")
        except Exception:
            return
        if data.get("type") == "resize":
            cols = int(data.get("cols", 120))
            rows = int(data.get("rows", 32))
            try:
                self.channel.resize_pty(width=cols, height=rows)
            except Exception:
                pass

    def close(self, reason: str = "disconnect"):
        if self._closed:
            return
        self._closed = True
        try:
            if self.channel:
                self.channel.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        try:
            self.ws.close()
        except Exception:
            pass
        # Audit close — separate session() since this may run on a worker thread
        try:
            with current_app.app_context():
                row = db.session.get(EngineTerminalSession, self.audit_row.id)
                if row is not None and row.closed_at is None:
                    row.closed_at = _utcnow()
                    row.close_reason = reason
                    db.session.commit()
        except Exception as exc:
            log.warning("Failed to write close audit for session %s: %s",
                        self.audit_row.id, exc)
        with _sessions_lock:
            cur = _active_by_user.get(self.user_email)
            if cur is self:
                _active_by_user.pop(self.user_email, None)


def threading_sleep(seconds: float):
    """Tiny sleep wrapper kept here so it's easy to mock in tests."""
    import time
    time.sleep(seconds)


# ── Helpers ──────────────────────────────────────────────────────────────

def _evict_existing_session(user_email: str):
    """If a session is already open for this user, close it first."""
    with _sessions_lock:
        existing = _active_by_user.get(user_email)
    if existing:
        log.info("Evicting existing terminal session for %s (replaced)", user_email)
        existing.close(reason="replaced")


def _is_admin(user_email: str) -> bool:
    import user_manager  # type: ignore
    return user_manager.is_admin(user_email or "")


def _user_row(email: str) -> User | None:
    if not email:
        return None
    return User.query.filter_by(email=email.lower().strip()).first()


# ── Route registration ───────────────────────────────────────────────────

def register_routes(app):
    """Wire the terminal page (HTTP) and the WebSocket route into the app.

    Idempotent — re-registration is a no-op (flask-sock checks).
    """
    try:
        from flask_sock import Sock
    except Exception as exc:  # pragma: no cover — module must exist in prod
        log.error("flask-sock not installed; terminal disabled: %s", exc)
        return

    sock = Sock(app)

    # --- WebSocket bridge ---

    @sock.route("/engines/nodes/<int:cred_id>/ws", endpoint="engines.node_terminal_ws")
    def node_terminal_ws(ws, cred_id: int):
        if "user" not in flask_session:
            ws.close(reason=4401, message="not authenticated")
            return
        email = (flask_session["user"].get("email") or "").lower()
        if not _is_admin(email):
            ws.close(reason=4403, message="admin role required")
            return

        cred = db.session.get(DhcpEngineCredential, cred_id)
        if cred is None:
            ws.close(reason=4404, message="credential not found")
            return
        if cred.last_verify_status != "ok":
            ws.close(reason=4424,
                     message="credential not verified — re-enroll in /dhcp/credentials")
            return

        # Enforce one session per user
        _evict_existing_session(email)

        # Audit row
        user_row = _user_row(email)
        source_ip = (request.headers.get("X-Forwarded-For", "")
                     or request.remote_addr or "").split(",")[0].strip()
        audit = EngineTerminalSession(
            user_id=user_row.id if user_row else None,
            credential_id=cred.id,
            engine_name=cred.engine_name,
            node_index=cred.node_id,
            source_ip=source_ip,
        )
        db.session.add(audit)
        db.session.commit()

        bridge = TerminalBridge(ws, cred, email, audit, source_ip)
        with _sessions_lock:
            _active_by_user[email] = bridge

        try:
            bridge.open_ssh()
        except Exception as exc:
            log.warning("SSH connect failed for %s/%s: %s",
                        cred.engine_name, cred.node_id, exc)
            try:
                ws.send(f"\r\n*** SSH connection failed: {exc} ***\r\n")
            except Exception:
                pass
            bridge.close(reason="error")
            return

        bridge.run()
