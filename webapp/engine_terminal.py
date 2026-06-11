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
    DhcpEngineCredential, EngineTerminalSession, User, Domain,
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
            # Audit L7 (2026-06-11): clamp client-supplied dimensions —
            # a hostile frame must not hand paramiko absurd PTY sizes.
            try:
                cols = max(1, min(1000, int(data.get("cols", 120))))
                rows = max(1, min(1000, int(data.get("rows", 32))))
            except (TypeError, ValueError):
                return
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


def _active_domain_id_for_ws() -> int | None:
    """Resolve the active Domain id from the Flask session.

    The WebSocket handshake doesn't always carry the same request-scope
    state as a normal HTTP route (Flask-Sock skips the app-level
    ``before_request`` hooks in some configurations), so we resolve
    ``Domain.slug`` from the session directly instead of relying on
    ``g.domain``. Returns None when no active profile is set — callers
    treat that as "no scope", which fails the Domain check unless the
    user is Super Admin.
    """
    profile = flask_session.get("active_profile") or {}
    slug = profile.get("tenant")
    if not slug:
        return None
    try:
        d = Domain.query.filter_by(slug=slug).first()
        return d.id if d is not None else None
    except Exception:
        return None


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
        log.info("[term-ws] entering handler cred_id=%s", cred_id)
        if "user" not in flask_session:
            log.warning("[term-ws] no user in session — closing 4401")
            ws.close(reason=4401, message="not authenticated")
            return
        email = (flask_session["user"].get("email") or "").lower()
        if not _is_admin(email):
            log.warning("[term-ws] %s not admin — closing 4403", email)
            ws.close(reason=4403, message="admin role required")
            return

        cred = db.session.get(DhcpEngineCredential, cred_id)
        if cred is None:
            log.warning("[term-ws] cred %s not found — closing 4404", cred_id)
            ws.close(reason=4404, message="credential not found")
            return

        # C4: Domain-Scoping — Domain Admin in Domain A must not SSH
        # into Domain B's engines via a cred_id from another Domain.
        # Super Admin is exempt (cross-Domain ops are their job). We
        # close with the same 4404 "not found" code so we don't leak
        # the existence of credentials in other Domains.
        #
        # WebSocket handshakes don't hit Flask's request lifecycle the
        # same way HTTP routes do — `g.domain` isn't always populated
        # by the time we land here. Resolve from the session profile
        # slug ourselves so the gate fires reliably on every connect.
        active_did = _active_domain_id_for_ws()
        user_for_check = _user_row(email)
        is_super = bool(user_for_check and user_for_check.is_super_admin)
        if (cred.domain_id is not None
                and cred.domain_id != active_did
                and not is_super):
            log.warning(
                "[term-ws] cross-Domain access blocked — user=%s "
                "active_domain=%s cred.domain_id=%s engine=%s — closing 4404",
                email, active_did, cred.domain_id, cred.engine_name,
            )
            ws.close(reason=4404, message="credential not found")
            return

        if cred.last_verify_status != "ok":
            log.warning("[term-ws] cred %s status=%s — closing 4424",
                        cred_id, cred.last_verify_status)
            ws.close(reason=4424,
                     message="credential not verified — re-enroll in /dhcp/credentials")
            return

        log.info("[term-ws] auth ok for %s → %s/node_id=%s host=%s:%s",
                 email, cred.engine_name, cred.node_id, cred.hostname, cred.ssh_port)

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
        log.info("[term-ws] audit row %s created", audit.id)

        bridge = TerminalBridge(ws, cred, email, audit, source_ip)
        with _sessions_lock:
            _active_by_user[email] = bridge

        try:
            log.info("[term-ws] calling open_ssh() → %s:%s", cred.hostname, cred.ssh_port or 22)
            bridge.open_ssh()
            log.info("[term-ws] open_ssh() returned — entering bridge loop")
        except Exception as exc:
            log.warning("[term-ws] SSH connect failed for %s/%s: %s",
                        cred.engine_name, cred.node_id, exc)
            try:
                ws.send(f"\r\n*** SSH connection failed: {exc} ***\r\n")
            except Exception:
                pass
            bridge.close(reason="error")
            return

        bridge.run()
        log.info("[term-ws] bridge loop ended for cred_id=%s", cred_id)
