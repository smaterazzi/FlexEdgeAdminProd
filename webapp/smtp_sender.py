"""SMTP delivery wrapper for cert-expiration alerts (2026-05-31).

Thin layer on top of :mod:`smtplib` + :mod:`email.message` that
encapsulates the three SMTP security modes we expose in the UI:

* ``starttls`` — open plaintext, upgrade with STARTTLS (port 587).
  This is the default and recommended mode.
* ``ssl``     — TLS from the first byte (port 465, SMTPS).
* ``plain``   — no TLS. Reserved for self-hosted relays inside the
  ops network; refused at form-validation time when ``port`` looks
  like a public submission port (25/465/587) AND the host doesn't
  resolve inside RFC1918 ranges. (The route applies that check.)

Dry-run / lab safety
--------------------
Setting ``FEA_SMTP_DRY_RUN=1`` in the environment shorts every send
to a log entry + a synthetic success result, with the rendered
``EmailMessage`` written to ``${FEA_SMTP_DRY_RUN_LOG_DIR:-/tmp/fea-smtp}``
as ``<timestamp>-<uuid>.eml`` so the operator can inspect what
*would* have been sent. The send routine NEVER opens a socket in
dry-run mode. This is the operator-facing equivalent of certbot's
``--staging`` flag — exercise the full pipeline without burning
real email deliverability.

Return shape is a small dataclass so callers can persist outcome
without parsing free-form strings.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from pathlib import Path

log = logging.getLogger("smtp_sender")


@dataclass
class SendResult:
    """Outcome of one SMTP send attempt."""
    ok: bool
    error: str = ""
    dry_run: bool = False
    accepted_recipients: int = 0
    refused_recipients: list[str] | None = None


@dataclass
class SmtpSettings:
    """Plain-bag for the SMTP fields that don't belong to a DB row.

    Decoupled from the ``SmtpConfig`` model so callers can build one
    from a transient form submission (operator types in the test
    button) without persisting a row first.
    """
    host: str
    port: int
    security: str           # starttls | ssl | plain
    username: str
    password: str           # plaintext at this layer
    from_address: str
    from_name: str = "FlexEdgeAdmin"
    timeout: float = 30.0


# Ports where an unencrypted login would transit the public internet
# in cleartext. 25 = MTA relay, 465 = SMTPS, 587 = submission.
_PUBLIC_SUBMISSION_PORTS = frozenset({25, 465, 587})


def plain_mode_refusal(host: str, port: int) -> str:
    """Enforce the documented ``plain`` restriction (audit S2, 2026-06-11).

    Returns a human-readable refusal reason, or ``""`` when the
    combination is acceptable. ``plain`` on a public submission port
    is only allowed when every resolved address for ``host`` is
    private/loopback (a self-hosted relay inside the ops network) —
    otherwise the SMTP password would cross the internet unencrypted.
    """
    import ipaddress
    import socket

    if port not in _PUBLIC_SUBMISSION_PORTS:
        return ""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        resolved = {info[4][0] for info in infos}
    except OSError as exc:
        return (f"could not resolve {host!r} to verify it is an internal "
                f"relay ({exc}) — plain (no TLS) mode is only allowed for "
                f"hosts inside the private network. Use STARTTLS or SSL.")
    public = sorted(
        a for a in resolved if ipaddress.ip_address(a).is_global
    )
    if public:
        return (f"{host} resolves to public address(es) "
                f"{', '.join(public)} — refusing plain (no TLS) mode on "
                f"port {port}: the SMTP password would cross the internet "
                f"unencrypted. Use STARTTLS or SSL instead.")
    return ""


def _dry_run_active() -> bool:
    return os.environ.get("FEA_SMTP_DRY_RUN", "").strip() in ("1", "true", "yes")


def _dry_run_log_dir() -> Path:
    return Path(os.environ.get("FEA_SMTP_DRY_RUN_LOG_DIR", "/tmp/fea-smtp"))


def _build_message(*, settings: SmtpSettings, to_addrs: list[str],
                   subject: str, body_text: str,
                   body_html: str | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((settings.from_name, settings.from_address))
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    # Domain-anchor the Message-ID at the sender address so receivers'
    # spam scanners aren't suspicious about the bare hostname.
    msg["Message-ID"] = make_msgid(domain=settings.from_address.split("@", 1)[-1])
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")
    return msg


def _write_dry_run(msg: EmailMessage) -> Path:
    """Persist the rendered message for operator inspection."""
    out_dir = _dry_run_log_dir()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        log.warning("dry-run: could not mkdir %s: %s", out_dir, exc)
        return Path()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"{stamp}-{uuid.uuid4().hex[:8]}.eml"
    path = out_dir / name
    try:
        path.write_bytes(bytes(msg))
    except Exception as exc:
        log.warning("dry-run: could not write %s: %s", path, exc)
        return Path()
    return path


def send_smtp(*, settings: SmtpSettings, to_addrs: list[str],
              subject: str, body_text: str,
              body_html: str | None = None) -> SendResult:
    """Send one email via the supplied SMTP settings.

    Returns ``SendResult(ok=False, error=…)`` on any failure; the
    caller persists the result. Never raises (except for genuinely
    catastrophic logic errors — empty recipient list).
    """
    if not to_addrs:
        return SendResult(ok=False, error="No recipients.")

    msg = _build_message(
        settings=settings, to_addrs=to_addrs,
        subject=subject, body_text=body_text, body_html=body_html,
    )

    if _dry_run_active():
        path = _write_dry_run(msg)
        log.info("FEA_SMTP_DRY_RUN active — wrote %s (would have sent to %s)",
                 path or "<inmem>", to_addrs)
        return SendResult(
            ok=True, dry_run=True,
            accepted_recipients=len(to_addrs),
            refused_recipients=[],
        )

    sec = (settings.security or "starttls").lower()
    try:
        if sec == "ssl":
            ctx = ssl.create_default_context()
            client = smtplib.SMTP_SSL(
                host=settings.host, port=settings.port,
                timeout=settings.timeout, context=ctx,
            )
        else:
            client = smtplib.SMTP(
                host=settings.host, port=settings.port,
                timeout=settings.timeout,
            )
            client.ehlo()
            if sec == "starttls":
                ctx = ssl.create_default_context()
                client.starttls(context=ctx)
                client.ehlo()
        try:
            if settings.username:
                client.login(settings.username, settings.password)
            refused = client.send_message(msg)
        finally:
            try:
                client.quit()
            except Exception:
                # quit() can fail when the server already closed the
                # connection — fine, the message was already accepted.
                try:
                    client.close()
                except Exception:
                    pass
    except smtplib.SMTPAuthenticationError as exc:
        return SendResult(
            ok=False,
            error=f"SMTP auth failed ({exc.smtp_code}): "
                  f"{exc.smtp_error.decode('utf-8', 'replace') if isinstance(exc.smtp_error, bytes) else exc.smtp_error}",
        )
    except smtplib.SMTPException as exc:
        return SendResult(ok=False, error=f"SMTP error: {exc}")
    except (OSError, ssl.SSLError) as exc:
        return SendResult(ok=False, error=f"Network error: {exc}")
    except Exception as exc:
        return SendResult(ok=False, error=f"Unexpected error: {exc}")

    refused_list = sorted(refused.keys()) if isinstance(refused, dict) else []
    accepted = max(0, len(to_addrs) - len(refused_list))
    return SendResult(
        ok=(accepted > 0),
        error=("Recipients refused: " + ", ".join(refused_list)) if refused_list and accepted == 0 else "",
        accepted_recipients=accepted,
        refused_recipients=refused_list,
    )
