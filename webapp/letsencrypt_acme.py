"""LE.4 — DNS-01 wildcard support via the ``acme`` Python library.

Why a separate orchestrator from certbot subprocess?
----------------------------------------------------
HTTP-01 fits the certbot-subprocess model nicely: invoke once, let
certbot handle everything. DNS-01 needs a **pause** between the
challenge-creation step and the verification step — operator has to
go publish a TXT record at their DNS provider before LE will accept
the challenge response. That async pause doesn't fit in one
subprocess call.

We use the ``acme`` Python library directly. The state machine is:

  NULL -> awaiting_dns -> verifying -> done   (success)
                                    -> failed (LE rejected)

Two public entry points:

  ``start_dns01_order(cert)``
      Creates an ACME order, fetches the dns-01 challenge, computes
      the TXT record name + value. Stashes order/challenge URIs in
      ``cert.dns_challenge_state`` (JSON blob) so the verify step
      can resume the order. Returns the record name + value for
      the operator UI.

  ``finalize_dns01_order(cert)``
      Operator has clicked "I've published the TXT record" — answer
      the challenge, poll the authorization until LE confirms, then
      finalize the order and save the cert files in the certbot
      layout that the existing TLS deploy pipeline expects.

Account key
-----------
Both functions need the ACME account's signing key. Certbot stores
it as a JWK at
``$CERTBOT_CONFIG_DIR/accounts/acme[-staging]-v02.api.letsencrypt.org/directory/<account_id>/private_key.json``.
We load it on demand. The account-setup wizard in
[webapp/letsencrypt_manager.account_view] creates the account; LE.4
just reuses the existing account key.

Renewal of DNS-01 certs
-----------------------
The LE.3 lazy-sweep scheduler EXPLICITLY SKIPS DNS-01 certs — auto-
renewal would require auto-publishing a new TXT record, which we
can't do without a per-Domain DNS API integration (out of scope).
Operator clicks Force renew on the cert detail page, which runs
``start_dns01_order`` again (new TXT name+value); they re-publish;
they click verify.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("letsencrypt.acme")


# ── Constants ────────────────────────────────────────────────────────────

ACME_PROD_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
ACME_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

# Polling — LE typically validates DNS-01 challenges within 30s of the
# answer call, but propagation can take longer. We poll the
# authorization in 5s ticks until either valid/invalid or timeout.
POLL_INTERVAL_S = 5
POLL_TIMEOUT_S = 180  # 3min; LE's own timeout for an answer is similar

# Order finalize deadline — gives LE time to issue + sign.
FINALIZE_TIMEOUT_S = 60


# ── Public dataclasses ───────────────────────────────────────────────────

@dataclass
class DnsChallengeDetails:
    """What the operator needs to publish at their DNS provider."""
    record_name: str        # e.g. "_acme-challenge.example.com"
    record_value: str       # the TXT record's content
    order_uri: str          # for resume
    challenge_uri: str      # for resume
    authz_uri: str          # for poll
    cert_key_pem: bytes     # private key for the eventual cert (stashed)


# ── Errors ───────────────────────────────────────────────────────────────

class AcmeError(Exception):
    """Anything went wrong inside the LE.4 ACME flow."""


# ── Helpers ──────────────────────────────────────────────────────────────

def _certbot_config_dir() -> str:
    return os.environ.get("CERTBOT_CONFIG_DIR", "/config/letsencrypt")


def _account_dir(is_staging: bool) -> Path:
    """Find the certbot-created account directory for the active server.

    Layout: ``$CERTBOT_CONFIG_DIR/accounts/<server>/directory/<account_id>/``.
    There's usually exactly one ``<account_id>`` subdir per server.
    Returns the deepest dir holding ``private_key.json`` and
    ``regr.json``.
    """
    base = Path(_certbot_config_dir()) / "accounts"
    if not base.is_dir():
        raise AcmeError(f"Certbot accounts dir not found: {base}. "
                        "Run /tls/letsencrypt/account first to register "
                        "the ACME account.")
    server = ("acme-staging-v02.api.letsencrypt.org" if is_staging
              else "acme-v02.api.letsencrypt.org")
    server_dir = base / server / "directory"
    if not server_dir.is_dir():
        raise AcmeError(f"No account dir for {server}. Did you register "
                        f"against this LE endpoint (staging={is_staging})?")
    candidates = [d for d in server_dir.iterdir() if d.is_dir()]
    if not candidates:
        raise AcmeError(f"No account_id subdirs in {server_dir}.")
    # Prefer the one that has both private_key.json AND regr.json.
    for d in candidates:
        if (d / "private_key.json").is_file() and (d / "regr.json").is_file():
            return d
    raise AcmeError(f"No complete account dir under {server_dir} — "
                    "expected private_key.json + regr.json.")


def _load_acme_client(*, is_staging: bool):
    """Build an ``acme.client.ClientV2`` using the certbot-stored
    account key and registration. Returns ``(client, account_key)``.
    """
    try:
        import josepy as jose
        from acme import client, messages
    except ImportError as exc:
        raise AcmeError(
            "ACME / josepy not installed. Run `pip install acme josepy` "
            "(included in requirements.txt since LE.4)."
        ) from exc

    acct_dir = _account_dir(is_staging)
    with open(acct_dir / "private_key.json") as f:
        account_key = jose.JWKRSA.json_loads(f.read())
    with open(acct_dir / "regr.json") as f:
        regr_dict = json.load(f)

    directory_url = ACME_STAGING_DIRECTORY if is_staging else ACME_PROD_DIRECTORY
    net = client.ClientNetwork(account_key, user_agent="flexedge-le.4")
    directory = client.ClientV2.get_directory(directory_url, net)
    acme_client = client.ClientV2(directory, net=net)

    # Make the registration known to the client so authenticated calls
    # land. acme >=2.0 stores this in client._regr.
    try:
        body = messages.Registration.from_json(regr_dict.get("body", {}))
        uri = regr_dict.get("uri", "")
        acme_client.net.account = messages.RegistrationResource(
            body=body, uri=uri,
        )
    except Exception as exc:
        log.warning("Could not hydrate ACME registration body: %s "
                    "(continuing — most calls will still work)", exc)

    return acme_client, account_key


def _generate_cert_key():
    """Fresh RSA-2048 private key for the cert. Returns the cryptography
    private key object."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_csr(fqdn: str, cert_key) -> bytes:
    """Build a single-SAN CSR for ``fqdn``. Returns PEM bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    # For wildcard FQDN, common-name strips the leading "*." per
    # convention (some clients render it cleaner that way; LE doesn't
    # care). The SAN carries the wildcard literally.
    cn = fqdn[2:] if fqdn.startswith("*.") else fqdn
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(fqdn)]),
            critical=False,
        )
        .sign(cert_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _dns_record_name(fqdn: str) -> str:
    """Compute the TXT record name LE expects for ``fqdn``.

    Wildcard certs validate against the BASE domain — for
    ``*.example.com`` the operator publishes ``_acme-challenge.example.com``
    (LE asks the wildcard's parent for proof of control).
    """
    base = fqdn[2:] if fqdn.startswith("*.") else fqdn
    return f"_acme-challenge.{base}"


# ── Save cert in certbot layout ──────────────────────────────────────────

def _save_cert_files(*, fqdn: str, cert_key, fullchain_pem: bytes,
                     lineage_dir_name: str = "") -> str:
    """Save cert + key in the layout the existing TLS deploy pipeline
    expects, mirroring certbot's structure:

      live/<lineage>/{cert.pem, chain.pem, fullchain.pem, privkey.pem}
      archive/<lineage>/{cert1.pem, chain1.pem, fullchain1.pem, privkey1.pem}

    Returns the lineage name (matches ``ManagedCertificate.certbot_lineage``).
    The TLS deploy pipeline reads from ``live/<lineage>/``.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509

    # certbot uses the FQDN as lineage name; wildcards become the base
    # domain (with the asterisk stripped) per certbot convention.
    lineage = lineage_dir_name or (fqdn[2:] if fqdn.startswith("*.") else fqdn)

    cfg = _certbot_config_dir()
    archive = Path(cfg) / "archive" / lineage
    live = Path(cfg) / "live" / lineage
    archive.mkdir(parents=True, exist_ok=True)
    live.mkdir(parents=True, exist_ok=True)

    # fullchain_pem is "cert + chain" — split for cert.pem / chain.pem.
    # The LE-issued PEM stream is cert THEN intermediates concatenated.
    pem_blocks = []
    current = b""
    for line in fullchain_pem.splitlines(keepends=True):
        current += line
        if line.startswith(b"-----END CERTIFICATE-----"):
            pem_blocks.append(current)
            current = b""
    if not pem_blocks:
        raise AcmeError("Empty cert PEM returned by LE — order may have "
                        "been finalized too early.")
    cert_pem = pem_blocks[0]
    chain_pem = b"".join(pem_blocks[1:]) if len(pem_blocks) > 1 else b""

    privkey_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Find the next version number (cert1.pem first, then cert2.pem...)
    n = 1
    while (archive / f"cert{n}.pem").exists():
        n += 1

    archive_files = {
        f"cert{n}.pem": cert_pem,
        f"chain{n}.pem": chain_pem,
        f"fullchain{n}.pem": fullchain_pem,
        f"privkey{n}.pem": privkey_pem,
    }
    for name, content in archive_files.items():
        path = archive / name
        path.write_bytes(content)
        os.chmod(path, 0o600 if "privkey" in name else 0o644)

    # Refresh live/ symlinks (or replace with files for portability —
    # certbot uses symlinks, but the TLS deploy reader just reads them).
    for live_name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
        link = live / live_name
        if link.exists() or link.is_symlink():
            link.unlink()
        # Use file copy rather than symlink so a backup-then-restore
        # cycle preserves the contents (LE.5.a's backup ZIP follows
        # files, not symlinks).
        archive_name = live_name.replace(".pem", f"{n}.pem")
        shutil.copy2(archive / archive_name, link)
        os.chmod(link, 0o600 if "privkey" in live_name else 0o644)

    # Also write a minimal renewal/<lineage>.conf so certbot's
    # discovery (certbot_reader.py) sees this lineage and we don't
    # confuse a future operator running `certbot certificates`.
    renewal = Path(cfg) / "renewal"
    renewal.mkdir(parents=True, exist_ok=True)
    conf_path = renewal / f"{lineage}.conf"
    if not conf_path.exists():
        conf_path.write_text(
            "# Renewal config written by FlexEdgeAdmin LE.4 (DNS-01).\n"
            "# Renewals are operator-driven — they cannot run via\n"
            "# `certbot renew` without the operator re-publishing the\n"
            "# TXT record. Use FEA's /tls/letsencrypt UI instead.\n"
            f"cert = {archive}/cert{n}.pem\n"
            f"privkey = {archive}/privkey{n}.pem\n"
            f"chain = {archive}/chain{n}.pem\n"
            f"fullchain = {archive}/fullchain{n}.pem\n\n"
            "[renewalparams]\n"
            "authenticator = manual\n"
            "manual_public_ip_logging_ok = True\n"
            f"server = {ACME_STAGING_DIRECTORY if 'staging' in str(archive) else ACME_PROD_DIRECTORY}\n",
            encoding="utf-8",
        )

    return lineage


# ── Public flow ──────────────────────────────────────────────────────────

def start_dns01_order(*, fqdn: str, is_staging: bool) -> DnsChallengeDetails:
    """Open an ACME order for ``fqdn`` using the DNS-01 challenge.

    Returns the TXT record details the operator must publish at their
    DNS provider PLUS the order/authz/challenge URIs the verify step
    needs to resume. The cert private key is generated here and
    returned so the caller can stash it in the cert row until verify
    succeeds.

    Wildcard FQDNs (``*.example.com``) work — LE validates against
    the base domain, so the operator publishes
    ``_acme-challenge.example.com``.
    """
    try:
        from acme import challenges as acme_challenges
    except ImportError as exc:
        raise AcmeError("ACME library not installed") from exc

    acme_client, account_key = _load_acme_client(is_staging=is_staging)
    cert_key = _generate_cert_key()
    csr_pem = _build_csr(fqdn, cert_key)

    try:
        order = acme_client.new_order(csr_pem)
    except Exception as exc:
        raise AcmeError(f"ACME new_order failed: {exc}") from exc

    if not order.authorizations:
        raise AcmeError("LE returned an order with no authorizations.")
    # Single-FQDN cert -> one authz.
    authz = order.authorizations[0]

    dns01_challenges = [
        c for c in authz.body.challenges
        if isinstance(c.chall, acme_challenges.DNS01)
    ]
    if not dns01_challenges:
        raise AcmeError(
            "LE did not offer a DNS-01 challenge for this authorization. "
            "Check that the FQDN is reachable for any-challenge type."
        )
    challenge = dns01_challenges[0]

    # The TXT record value LE expects.
    record_value = challenge.chall.validation(account_key)
    record_name = _dns_record_name(fqdn)

    from cryptography.hazmat.primitives import serialization
    cert_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    log.info("LE.4 start_dns01_order: fqdn=%s staging=%s record=%s",
             fqdn, is_staging, record_name)

    return DnsChallengeDetails(
        record_name=record_name,
        record_value=record_value,
        order_uri=str(getattr(order, "uri", "") or ""),
        challenge_uri=str(challenge.uri),
        authz_uri=str(authz.uri),
        cert_key_pem=cert_key_pem,
    )


def finalize_dns01_order(*, fqdn: str, is_staging: bool,
                         challenge_uri: str, authz_uri: str,
                         order_uri: str, cert_key_pem: bytes,
                         ) -> tuple[str, datetime]:
    """Resume the order: answer challenge, poll, finalize, save files.

    Returns ``(lineage_name, next_renewal_after)`` on success. Raises
    ``AcmeError`` on any failure — caller flips ``cert.status`` to
    ``failed`` and stamps the error.
    """
    try:
        from acme import client as acme_client_module, messages
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise AcmeError("ACME library not installed") from exc

    acme_client, account_key = _load_acme_client(is_staging=is_staging)

    # Reconstitute the challenge object from its URI. We need to
    # re-fetch the authorization to get the live challenge object that
    # acme.client expects for answer_challenge().
    try:
        authz_resp = acme_client._post_as_get(authz_uri)
        authz_body = messages.Authorization.from_json(authz_resp.json())
        authz_resource = messages.AuthorizationResource(
            body=authz_body, uri=authz_uri,
        )
    except Exception as exc:
        raise AcmeError(f"Could not refetch authorization: {exc}") from exc

    # Pick the right challenge body by matching the URI.
    challenge_body = None
    for cb in authz_body.challenges:
        if str(cb.uri) == challenge_uri:
            challenge_body = cb
            break
    if challenge_body is None:
        raise AcmeError("Stored challenge URI doesn't match any current "
                        "authorization challenge — order may have expired.")

    # Answer the challenge — tells LE we believe we've published the TXT.
    try:
        acme_client.answer_challenge(challenge_body, challenge_body.response(account_key))
    except Exception as exc:
        raise AcmeError(f"answer_challenge failed: {exc}") from exc

    # Poll the authorization until valid/invalid or timeout.
    deadline = time.monotonic() + POLL_TIMEOUT_S
    last_status = None
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_S)
        try:
            poll_resp = acme_client._post_as_get(authz_uri)
            poll_body = messages.Authorization.from_json(poll_resp.json())
            last_status = str(poll_body.status)
            log.info("LE.4 poll authz status=%s (%s)", last_status, fqdn)
            if last_status in ("valid", "invalid"):
                break
        except Exception as exc:
            log.warning("LE.4 poll error: %s", exc)
    else:
        raise AcmeError(f"Polling timed out after {POLL_TIMEOUT_S}s; "
                        f"last status: {last_status or 'unknown'}")

    if last_status == "invalid":
        # Try to pull a human-readable reason.
        reasons = []
        for cb in poll_body.challenges:
            if cb.error is not None:
                reasons.append(str(cb.error))
        reason = "; ".join(reasons) or "LE rejected the DNS-01 challenge"
        raise AcmeError(f"DNS-01 validation failed: {reason}")
    if last_status != "valid":
        raise AcmeError(f"Unexpected final authz status: {last_status}")

    # Finalize the order — POST CSR to the order's finalize URL and
    # poll until LE returns the cert chain.
    try:
        # Re-fetch the order so we have a fresh OrderResource.
        order_resp = acme_client._post_as_get(order_uri)
        order_body = messages.Order.from_json(order_resp.json())
        order_resource = messages.OrderResource(
            uri=order_uri, body=order_body,
            csr_pem=b"",  # CSR submitted at new_order; not needed here
        )
        finalize_deadline = datetime.now(timezone.utc) + timedelta(seconds=FINALIZE_TIMEOUT_S)
        finalized = acme_client.finalize_order(order_resource, finalize_deadline)
    except Exception as exc:
        raise AcmeError(f"finalize_order failed: {exc}") from exc

    fullchain_pem = (finalized.fullchain_pem or "").encode("ascii", errors="replace")
    if not fullchain_pem:
        raise AcmeError("LE returned an empty cert chain.")

    # Restore the cert key for serialization (we got the PEM in).
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    cert_key = load_pem_private_key(cert_key_pem, password=None)

    lineage = _save_cert_files(
        fqdn=fqdn, cert_key=cert_key, fullchain_pem=fullchain_pem,
    )

    next_renewal_after = datetime.now(timezone.utc) + timedelta(days=60)
    log.info("LE.4 finalize_dns01_order: fqdn=%s lineage=%s next_renew=%s",
             fqdn, lineage, next_renewal_after.isoformat())
    return lineage, next_renewal_after


def precheck_dns_txt(*, record_name: str, expected_value: str) -> tuple[bool, str]:
    """Operator-facing pre-check: query the TXT record at recursive
    resolvers and compare the value. Returns ``(found, detail)``.

    Independent of LE — purely diagnostic. Operators run this before
    clicking "I've published" to verify their DNS propagated.
    """
    try:
        import dns.resolver
    except ImportError:
        return False, "dnspython not installed"

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10.0
    try:
        answers = resolver.resolve(record_name, "TXT")
    except dns.resolver.NXDOMAIN:
        return False, f"NXDOMAIN — {record_name} has no TXT record yet."
    except dns.resolver.NoAnswer:
        return False, f"NoAnswer — {record_name} exists but has no TXT record."
    except Exception as exc:
        return False, f"DNS query failed: {exc}"

    seen = []
    for ans in answers:
        # TXT records are returned as ``RdataTXT`` with .strings (list of bytes).
        for s in ans.strings:
            val = s.decode("ascii", errors="replace")
            seen.append(val)
            if val == expected_value:
                return True, f"Found expected value at {record_name}."
    return False, (f"{record_name} has {len(seen)} TXT record(s) but "
                   f"none match the expected value. Got: {seen[:3]}")
