"""Certbot subprocess wrappers — Roadmap item 5 / Phase LE.2 (2026-05-11).

Pure invocation helpers. No Flask context, no DB, no queue knowledge —
just `subprocess.run(["certbot", ...])` plus parsing.

The queue handler in `shared/queue_runner.py` and the scan_jobs runner
in `webapp/letsencrypt_jobs.py` both call into here so the actual
certbot invocation is one well-tested code path.

Q1 locked: certbot is bundled in the Docker image at `/usr/bin/certbot`.
Q2 locked: HTTP-01 only for this phase (DNS-01 manual via the `acme`
library is Phase LE.4 — different code path, lives in
`webapp/letsencrypt_acme.py` when shipped).
Q3 locked: one account per deployment.
Q4 locked: account key on disk at `/etc/letsencrypt/accounts/`.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# Where certbot is. Overridable for tests.
CERTBOT_BIN = os.environ.get("CERTBOT_BIN", "/usr/bin/certbot")

# Certbot config / work / logs directories.
#
# Default `/etc/letsencrypt` is owned by root inside the Docker image
# (where `apt-get install certbot` plants it), so the unprivileged
# gunicorn process cannot acquire `/etc/letsencrypt/.certbot.lock` and
# every invocation fails with "Read-only file system" (LE.2 first-run
# bug surfaced 2026-05-11 — operator hit this on the very first
# /tls/letsencrypt/account submit).
#
# Solution: redirect certbot to `/config/letsencrypt/`, which is the
# writable bind-mount used by every FEA deployment. `/config/` is also
# what `/admin/backup` includes, so the account key + cert lineage
# back up with the rest of the FEA state (Q12).
CERTBOT_CONFIG_DIR = os.environ.get("CERTBOT_CONFIG_DIR",
                                    "/config/letsencrypt")
CERTBOT_WORK_DIR = os.environ.get("CERTBOT_WORK_DIR",
                                  "/config/letsencrypt-work")
CERTBOT_LOGS_DIR = os.environ.get("CERTBOT_LOGS_DIR",
                                  "/config/letsencrypt-logs")

# Webroot. nginx/Traefik in front MUST serve
# `http://<host>/.well-known/acme-challenge/*` from this directory OR
# proxy that path back to FEA's gunicorn (the public `acme_challenge_bp`
# blueprint reads from this same path). The operator-facing
# deployment-guide.md spells out the one-line proxy rule under the LE
# section.
WEBROOT = os.environ.get("CERTBOT_WEBROOT",
                         "/config/letsencrypt-webroot")

# Default subprocess timeout — single-domain HTTP-01 normally completes
# in 20-60s. 5 minutes covers the worst case (LE backend slow / staging
# rate-limit retry).
DEFAULT_TIMEOUT_S = 300

# Let's Encrypt cert validity is 90 days; renewal window is 30 days
# before expiry per LE recommendation. We persist `next_renewal_after`
# at issuance time so the Phase LE.3 scheduler can pick rows up cheaply.
RENEWAL_WINDOW_DAYS = 60  # = 90 - 30


def _certbot_path_flags() -> list[str]:
    """Return the --config-dir/--work-dir/--logs-dir flags certbot needs
    to write under FEA's writable volume instead of /etc/letsencrypt."""
    return [
        "--config-dir", CERTBOT_CONFIG_DIR,
        "--work-dir", CERTBOT_WORK_DIR,
        "--logs-dir", CERTBOT_LOGS_DIR,
    ]


def _verbose_flag() -> list[str]:
    """Return `["-v"]` so certbot prints the full ACME exchange to
    stderr. Without this, errors like 'No such authorization' surface
    with the top-level message only and the actionable details (which
    auth, which challenge, what HTTP status LE returned) stay hidden
    in `${CERTBOT_LOGS_DIR}/letsencrypt.log`.

    Operator-controllable via `FEA_CERTBOT_VERBOSE=0` to disable —
    default is on because the diagnostic value far outweighs the
    extra stderr noise (we tail-truncate to 80 lines anyway).
    """
    if os.environ.get("FEA_CERTBOT_VERBOSE", "1") == "0":
        return []
    return ["-v"]


def log_file_path() -> str:
    """Return the certbot log file path.

    Public helper for the UI's "View log" endpoint. certbot writes
    every run to `letsencrypt.log` in `CERTBOT_LOGS_DIR`; previous
    runs rotate to `letsencrypt.log.N`.
    """
    return os.path.join(CERTBOT_LOGS_DIR, "letsencrypt.log")


def _live_dir() -> str:
    """Where issued certs land — `<CERTBOT_CONFIG_DIR>/live`."""
    return os.path.join(CERTBOT_CONFIG_DIR, "live")


def ensure_certbot_dirs() -> None:
    """Create the certbot config/work/logs dirs if they don't exist.

    Idempotent. Called lazily at the start of every certbot operation
    so a fresh container with an empty /config/ doesn't fail on first
    request with a "no such directory" error before certbot even runs.
    """
    for d in (CERTBOT_CONFIG_DIR, CERTBOT_WORK_DIR, CERTBOT_LOGS_DIR):
        Path(d).mkdir(parents=True, exist_ok=True)


@dataclass
class CertbotResult:
    """What a certbot run produced.

    `success` = certbot exited 0 AND the lineage directory now exists.
    `lineage` = `/etc/letsencrypt/live/<fqdn>` on success, "" otherwise.
    `stdout_tail` / `stderr_tail` = last ~80 lines each, for the
    operator-facing error display.
    """
    success: bool = False
    lineage: str = ""
    fullchain_path: str = ""
    privkey_path: str = ""
    next_renewal_after: Optional[datetime] = None
    error: str = ""
    stdout_tail: str = ""
    stderr_tail: str = ""
    duration_ms: int = 0
    exit_code: Optional[int] = None
    command: list[str] = field(default_factory=list)


def _tail(text: str, lines: int = 80) -> str:
    """Last N lines of a multiline string — for error surfacing without
    blowing out the audit log."""
    if not text:
        return ""
    parts = text.splitlines()
    if len(parts) <= lines:
        return text
    return "\n".join(parts[-lines:])


def ensure_webroot() -> None:
    """Make sure the webroot directory exists.

    certbot will create the `.well-known/acme-challenge/` subdirectory
    itself; we just need the parent to be writable. Called lazily before
    each cert request so a fresh container doesn't fail on first request.
    """
    Path(WEBROOT).mkdir(parents=True, exist_ok=True)


def register_account(*, email: str, is_staging: bool,
                     agree_tos: bool = True,
                     timeout_s: int = DEFAULT_TIMEOUT_S) -> CertbotResult:
    """Run `certbot register` to create the LE account.

    Q9 setup wizard calls this once. Idempotent at the certbot level:
    if the account already exists, certbot prints "There is an existing
    account" and exits non-zero — we treat that as success because the
    account is in fact registered.
    """
    if not agree_tos:
        return CertbotResult(success=False,
                             error="must agree to LE Terms of Service")
    if not email or "@" not in email:
        return CertbotResult(success=False, error="email is required")
    ensure_certbot_dirs()
    cmd = [
        CERTBOT_BIN, "register",
        *_certbot_path_flags(),
        *_verbose_flag(),
        "--non-interactive",
        "--agree-tos",
        "--email", email,
        "--no-eff-email",
    ]
    if is_staging:
        cmd.append("--staging")
    return _run(cmd, timeout_s=timeout_s, treat_existing_account_as_success=True)


def request_certificate(*, fqdn: str, email: str, is_staging: bool,
                        timeout_s: int = DEFAULT_TIMEOUT_S) -> CertbotResult:
    """Issue a new certificate for `fqdn` via HTTP-01.

    The caller is responsible for verifying:
      * the AcmeAccount exists (`register_account` was called)
      * the FQDN passes the per-Domain allowlist
      * the operator agreed to TOS

    On success, the cert is at `/etc/letsencrypt/live/<fqdn>/` and the
    `lineage` field of the result points there.
    """
    if not fqdn:
        return CertbotResult(success=False, error="fqdn is required")
    ensure_certbot_dirs()
    ensure_webroot()
    cmd = [
        CERTBOT_BIN, "certonly",
        *_certbot_path_flags(),
        *_verbose_flag(),
        "--non-interactive",
        "--agree-tos",
        "--email", email,
        "--webroot",
        "--webroot-path", WEBROOT,
        "-d", fqdn,
        "--cert-name", fqdn,
        "--no-eff-email",
        "--keep-until-expiring",   # avoids burning rate limit on retries
    ]
    if is_staging:
        cmd.append("--staging")
    result = _run(cmd, timeout_s=timeout_s)
    if result.success:
        lineage = os.path.join(_live_dir(), fqdn)
        if Path(lineage).is_dir():
            result.lineage = lineage
            result.fullchain_path = f"{lineage}/fullchain.pem"
            result.privkey_path = f"{lineage}/privkey.pem"
            result.next_renewal_after = (
                datetime.now(timezone.utc) + timedelta(days=RENEWAL_WINDOW_DAYS)
            )
        else:
            # certbot reported success but the lineage isn't on disk —
            # this should never happen but failing loud is better than
            # marking a cert active when it isn't.
            result.success = False
            result.error = (f"certbot exited 0 but lineage "
                            f"{lineage} does not exist on disk")
    return result


def renew_certificate(*, fqdn: str, is_staging: bool,
                      timeout_s: int = DEFAULT_TIMEOUT_S) -> CertbotResult:
    """Renew an existing certificate. Phase LE.3 calls this from the
    scheduler; Phase LE.2 exposes the "Force renew" button which lands
    here too.

    Uses `certbot renew --cert-name <fqdn>` so only the targeted cert
    is touched. `--force-renewal` is intentionally NOT set — operator
    can override via the dedicated re-issue flow if needed.
    """
    if not fqdn:
        return CertbotResult(success=False, error="fqdn is required")
    ensure_certbot_dirs()
    ensure_webroot()
    cmd = [
        CERTBOT_BIN, "renew",
        *_certbot_path_flags(),
        *_verbose_flag(),
        "--non-interactive",
        "--cert-name", fqdn,
        "--webroot",
        "--webroot-path", WEBROOT,
    ]
    if is_staging:
        cmd.append("--staging")
    result = _run(cmd, timeout_s=timeout_s)
    if result.success:
        lineage = os.path.join(_live_dir(), fqdn)
        result.lineage = lineage
        result.fullchain_path = f"{lineage}/fullchain.pem"
        result.privkey_path = f"{lineage}/privkey.pem"
        result.next_renewal_after = (
            datetime.now(timezone.utc) + timedelta(days=RENEWAL_WINDOW_DAYS)
        )
    return result


def revoke_certificate(*, fqdn: str, is_staging: bool,
                       reason: str = "unspecified",
                       timeout_s: int = DEFAULT_TIMEOUT_S) -> CertbotResult:
    """Revoke + delete the cert. Phase LE.5 implements the UI; the
    handler is here so LE.2 can pre-wire the queue op.
    """
    if not fqdn:
        return CertbotResult(success=False, error="fqdn is required")
    ensure_certbot_dirs()
    cmd = [
        CERTBOT_BIN, "revoke",
        *_certbot_path_flags(),
        *_verbose_flag(),
        "--non-interactive",
        "--cert-name", fqdn,
        "--reason", reason,
        "--delete-after-revoke",
    ]
    if is_staging:
        cmd.append("--staging")
    return _run(cmd, timeout_s=timeout_s)


def _run(cmd: list[str], *, timeout_s: int,
         treat_existing_account_as_success: bool = False) -> CertbotResult:
    """Run a certbot subprocess and parse the outcome.

    Never raises — every failure path is captured into the CertbotResult
    so callers can persist it for operator review.
    """
    result = CertbotResult(command=list(cmd))
    started = datetime.now(timezone.utc)
    log.info("certbot exec: %s",
             " ".join(shlex.quote(p) for p in cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError:
        result.error = (f"certbot binary not found at {CERTBOT_BIN}. "
                        "Is certbot installed in the container? "
                        "(`apt-get install certbot`)")
        return result
    except subprocess.TimeoutExpired as exc:
        result.error = f"certbot timed out after {timeout_s}s"
        result.stdout_tail = _tail(exc.stdout.decode() if exc.stdout else "")
        result.stderr_tail = _tail(exc.stderr.decode() if exc.stderr else "")
        return result

    result.exit_code = proc.returncode
    result.stdout_tail = _tail(proc.stdout)
    result.stderr_tail = _tail(proc.stderr)
    result.duration_ms = int(
        (datetime.now(timezone.utc) - started).total_seconds() * 1000
    )

    if proc.returncode == 0:
        result.success = True
        return result

    # Special case for register: "existing account" exits non-zero but
    # the account IS registered, so we accept it.
    if (treat_existing_account_as_success
            and "There is an existing account" in (proc.stdout or "")
                                                   + (proc.stderr or "")):
        result.success = True
        return result

    # Otherwise, surface a short error + the captured tails.
    short = (proc.stderr or proc.stdout or "").splitlines()[-3:]
    result.error = (f"certbot exit {proc.returncode}: "
                    + " | ".join(s.strip() for s in short if s.strip()))
    return result


# ── Operator-facing diagnostics (added 2026-05-12) ──────────────────────


@dataclass
class ReachabilityResult:
    """Outcome of a single HTTP-01 reachability probe.

    `success` = LE-equivalent fetch succeeded and the body matched the
    token we wrote. Anything else surfaces in `error` with the failing
    URL so the operator can paste it into curl.
    """
    success: bool = False
    fqdn: str = ""
    url: str = ""
    http_status: Optional[int] = None
    expected_body: str = ""
    received_body_tail: str = ""
    error: str = ""
    duration_ms: int = 0


def test_http01_reachability(*, fqdn: str,
                             timeout_s: int = 15) -> ReachabilityResult:
    """Verify that ``http://<fqdn>/.well-known/acme-challenge/<token>`` is
    served and returns the token body we just wrote into the webroot.

    The exact path LE's validator hits. If this round-trips, a real cert
    request will pass HTTP-01; if it doesn't, the cert request will
    burn an LE order on a doomed authorization.

    Steps:

    1. Generate a random token (alphanumeric+`-_`, len 24).
    2. Write the token to ``<WEBROOT>/.well-known/acme-challenge/<token>``
       with body = token (matches certbot's token-file format).
    3. HTTP GET ``http://<fqdn>/.well-known/acme-challenge/<token>``.
    4. Compare response body to the expected token.
    5. Delete the test file (always — best-effort).

    Always returns a ReachabilityResult; never raises. The operator
    sees one row per test in the audit log + an inline banner.
    """
    import ipaddress
    import secrets
    import socket
    import time
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError

    started = datetime.now(timezone.utc)
    out = ReachabilityResult(fqdn=fqdn)

    if not fqdn or "/" in fqdn:
        out.error = "fqdn is required and must not contain '/'"
        return out

    # SSRF guard (audit S1, 2026-06-11): the FQDN comes from a cert row
    # the Domain Admin controls (via their self-service allowlist), so
    # without this check the probe doubles as an internal port scanner
    # (127.0.0.1, 169.254.169.254, RFC1918). LE's validator can only
    # ever reach public addresses, so refusing non-global targets loses
    # nothing legitimate.
    try:
        ipaddress.ip_address(fqdn.strip("[]"))
        out.error = ("fqdn is an IP literal — reach-test only probes "
                     "public DNS names (Let's Encrypt would refuse an "
                     "IP-based order too)")
        return out
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(fqdn, 80, proto=socket.IPPROTO_TCP)
        resolved = {info[4][0] for info in infos}
    except OSError as exc:
        out.error = (f"DNS resolution failed for {fqdn}: {exc}. "
                     f"LE's validator would fail the same way.")
        return out
    non_global = sorted(
        a for a in resolved if not ipaddress.ip_address(a).is_global
    )
    if non_global:
        out.error = (f"{fqdn} resolves to non-public address(es) "
                     f"{', '.join(non_global)} — refusing the probe. "
                     f"LE's validator could never reach it, and probing "
                     f"private address space from FEA is not allowed.")
        return out

    ensure_webroot()
    challenge_dir = Path(WEBROOT) / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True, exist_ok=True)

    # certbot's tokens are base64url; we mimic that alphabet so the
    # acme_challenge_bp's `^[A-Za-z0-9_-]+$` regex accepts them too.
    token = f"fea-reachtest-{secrets.token_urlsafe(12)}"
    body = token  # certbot sets file body = token; same convention
    challenge_path = challenge_dir / token
    out.expected_body = body
    out.url = f"http://{fqdn}/.well-known/acme-challenge/{token}"

    try:
        challenge_path.write_text(body, encoding="ascii")
    except Exception as exc:
        out.error = (f"could not write test token to "
                     f"{challenge_path}: {exc}")
        return out

    try:
        req = Request(out.url, headers={
            "User-Agent": "FlexEdgeAdmin-reachability/1.0",
        })
        try:
            with urlopen(req, timeout=timeout_s) as resp:
                out.http_status = resp.status
                received = resp.read().decode(
                    "utf-8", errors="replace",
                )[:512]
        except HTTPError as exc:
            out.http_status = exc.code
            received = (exc.read().decode("utf-8", errors="replace")[:512]
                        if hasattr(exc, "read") else "")
            out.received_body_tail = received
            out.error = (f"HTTP {exc.code} from {out.url} — LE's "
                         f"validator would see the same. Check that your "
                         f"reverse proxy forwards `/.well-known/acme-challenge/*` "
                         f"to FEA's gunicorn (or serves directly from "
                         f"{WEBROOT}).")
            return out
        except URLError as exc:
            out.error = (f"could not reach {out.url} — {exc.reason}. "
                         f"Most common causes: (1) DNS for {fqdn} doesn't "
                         f"resolve to this server's public IP, "
                         f"(2) port 80 isn't open in the firewall, "
                         f"(3) nginx/Traefik isn't running.")
            return out

        out.received_body_tail = received[:256]
        if received.strip() == body:
            out.success = True
        else:
            out.error = (f"reachable but body mismatch — got "
                         f"{received[:80]!r}, expected {body!r}. The "
                         f"path is being served by a DIFFERENT server, "
                         f"or your reverse proxy isn't passing the "
                         f"path to FEA's gunicorn.")
    finally:
        # Best-effort cleanup — leaking a 64-byte file under
        # /config/letsencrypt-webroot/.well-known/acme-challenge/ isn't
        # a security hazard (the token is random + scoped to LE's
        # validation path), but tidy is better.
        try:
            challenge_path.unlink(missing_ok=True)
        except Exception:
            pass
        out.duration_ms = int(
            (datetime.now(timezone.utc) - started).total_seconds() * 1000
        )

    return out


def reset_lineage_for_fqdn(fqdn: str) -> dict:
    """Delete certbot's per-FQDN state so the next request starts fresh.

    Wipes (all best-effort, missing-ok):

    * ``<CERTBOT_CONFIG_DIR>/renewal/<fqdn>.conf``
    * ``<CERTBOT_CONFIG_DIR>/live/<fqdn>/`` (symlink directory)
    * ``<CERTBOT_CONFIG_DIR>/archive/<fqdn>/`` (historical certs)

    Does NOT touch:

    * the ACME account key (``<CERTBOT_CONFIG_DIR>/accounts/``) — those
      stay so the operator doesn't need to re-register.
    * any other FQDN's state.
    * the webroot challenge dir (already cleaned per-run).

    Returns a dict with `removed`/`missing`/`error` paths for the audit
    log and the UI flash. Path traversal is guarded by `_safe_fqdn_path`.
    """
    import shutil

    out: dict = {"removed": [], "missing": [], "error": []}
    if not _is_safe_fqdn(fqdn):
        out["error"].append(f"refusing unsafe fqdn={fqdn!r}")
        return out

    targets = [
        Path(CERTBOT_CONFIG_DIR) / "renewal" / f"{fqdn}.conf",
        Path(CERTBOT_CONFIG_DIR) / "live" / fqdn,
        Path(CERTBOT_CONFIG_DIR) / "archive" / fqdn,
    ]
    config_resolved = Path(CERTBOT_CONFIG_DIR).resolve()

    for path in targets:
        try:
            # Defence in depth — even though _is_safe_fqdn rejected `..`,
            # double-check the resolved path is inside CERTBOT_CONFIG_DIR.
            try:
                path_res = path.resolve(strict=False)
                path_res.relative_to(config_resolved)
            except ValueError:
                out["error"].append(f"refused out-of-config path {path}")
                continue

            if not path.exists():
                out["missing"].append(str(path))
                continue
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                # File or symlink — unlink covers both.
                path.unlink(missing_ok=True)
            out["removed"].append(str(path))
        except Exception as exc:
            out["error"].append(f"{path}: {exc}")

    return out


def _is_safe_fqdn(fqdn: str) -> bool:
    """Refuse anything that could traverse out of CERTBOT_CONFIG_DIR.

    Allows: lowercase alphanumeric + `.` + `-`. Refuses: empty, contains
    `/`, contains `..`, contains spaces, contains uppercase (LE FQDNs
    are normalized lowercase before reaching us anyway).
    """
    if not fqdn:
        return False
    if any(c.isspace() for c in fqdn):
        return False
    if "/" in fqdn or "\\" in fqdn or ".." in fqdn:
        return False
    if fqdn != fqdn.lower():
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    return all(c in allowed for c in fqdn)


def read_log_tail(*, max_lines: int = 400, max_bytes: int = 256_000) -> str:
    """Return the tail of the certbot debug log for the UI viewer.

    Reads at most `max_bytes` from the end of the file, then keeps the
    last `max_lines` lines. Returns "" if the file is missing or
    unreadable — the UI surfaces that as "no log yet" rather than an
    error to avoid leaking filesystem details.

    Path is fixed to `log_file_path()` (CERTBOT_LOGS_DIR/letsencrypt.log)
    — callers don't pass a path, so no traversal vector.
    """
    path = Path(log_file_path())
    if not path.exists():
        return ""
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(-max_bytes, 2)  # SEEK_END
                # Drop a (likely-partial) first line.
                fh.readline()
            data = fh.read()
        text = data.decode("utf-8", errors="replace")
    except Exception as exc:
        log.warning("read_log_tail failed: %s", exc)
        return ""
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(lines)
