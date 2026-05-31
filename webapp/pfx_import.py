"""TLS Manager — .pfx import (Roadmap follow-up, 2026-05-31).

Operator-facing automation of the manual `openssl pkcs12` dance from
``docs/PFX2CER.md``. Parses a PKCS#12 bundle (cert + private key +
chain) submitted via the web UI, validates it, and writes the certbot-
layout PEM files into a managed directory so the existing TLS deploy
pipeline picks them up unchanged.

The deploy pipeline reads
``<ManagedCertificate.certbot_lineage>/fullchain.pem`` +
``.../privkey.pem`` from disk
(see :func:`webapp.tls_deployer.run_deployment`). PFX-imported certs
write those exact filenames into a dedicated parallel root —
``${FEA_PFX_DIR}`` (default ``/config/imported-certs``) — so they
coexist with Let's Encrypt lineages without cross-contaminating the
certbot config dir.

Differences from LE-issued certs
--------------------------------
* ``ManagedCertificate.challenge_type='pfx_import'`` — the LE.3 lazy-
  sweep renewal scheduler filters by ``challenge_type='http01'``, so
  PFX rows are naturally excluded from auto-renewal. Operator
  re-imports a new PFX when the cert is about to expire (or wires up
  the future expiration-dashboard alert system).
* ``ManagedCertificate.certbot_lineage`` points at the FEA-managed
  PFX dir, NOT at ``${CERTBOT_CONFIG_DIR}/live/...``. The TLS deploy
  pipeline doesn't care — it just reads ``fullchain.pem`` /
  ``privkey.pem`` from whatever path it's given.
* No ACME account / no certbot subprocess / no HTTP-01 challenge
  serving / no renewal queue ops. Pure file extraction.

Reimport semantics
------------------
Importing the SAME ``domain`` (CN) again REPLACES the on-disk files
in place and refreshes ``last_cert_hash`` + ``last_checked_at``. The
existing ``TLSDeployment`` rows keep pointing at the same
``certificate_id`` and trigger an SMC redeploy on next operator click
(no automatic redeploy — operator decides). Re-import is blocked if
the existing row was issued via Let's Encrypt (``challenge_type ∈
{'http01', 'dns01_manual'}``) — operator must untrack the LE cert
first to avoid clobbering the LE lineage from a parallel UI.

Backup
------
``${FEA_PFX_DIR}`` is included in ``/admin/backup`` ZIP via
:func:`webapp.factory_reset._walk_dir_into_zip`. Restore is reissue-
free: the PEM files come back with the DB row.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

log = logging.getLogger(__name__)


# Default location for PFX-imported certs. Override with the env var
# for tests or non-standard deployments. The parent `/config/` is the
# writable bind-mount the operator already has, and the backup ZIP
# (factory_reset.build_backup_zip) descends into it.
_DEFAULT_PFX_DIR = "/config/imported-certs"


def pfx_root() -> Path:
    """Resolve the PFX import root from the environment."""
    return Path(os.environ.get("FEA_PFX_DIR", _DEFAULT_PFX_DIR))


@dataclass
class ParsedPfx:
    """Materialised contents of a successfully parsed .pfx bundle.

    All three PEM strings are unencrypted and ready to write to disk.
    ``metadata`` carries the parsed X.509 fields the UI surfaces (CN,
    issuer, validity dates, SAN list, serial, fingerprint).
    """
    cert_pem: str
    privkey_pem: str
    chain_pem: str            # intermediates + root, may be ""
    fullchain_pem: str        # leaf + chain — what fullchain.pem contains
    metadata: dict = field(default_factory=dict)


class PfxImportError(Exception):
    """Raised on any failure parsing or sanity-checking the bundle."""
    pass


# Lifted from webapp/certbot_reader.py — same logic, but called twice
# (once from parse, once from save) and the caller wants both the
# metadata dict and the cryptography object, so keep it inline.
def _extract_cert_metadata(cert: x509.Certificate) -> dict:
    cn = ""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value
    except Exception:
        pass
    san_domains: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_domains = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    issuer_cn = ""
    try:
        issuer_attrs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if issuer_attrs:
            issuer_cn = issuer_attrs[0].value
    except Exception:
        pass
    return {
        "subject_cn": cn,
        "issuer": issuer_cn,
        "valid_from": cert.not_valid_before_utc,
        "valid_to": cert.not_valid_after_utc,
        "san_domains": san_domains,
        "serial": format(cert.serial_number, "x"),
        "fingerprint_sha256": cert.fingerprint(cert.signature_hash_algorithm).hex(),
    }


def parse_pfx(pfx_bytes: bytes, password: str | None) -> ParsedPfx:
    """Decode a PKCS#12 bundle into ready-to-write PEM strings.

    Raises :class:`PfxImportError` with an operator-friendly message
    on any failure: wrong password, missing private key, missing
    leaf cert, mismatched key+cert, expired cert.

    ``password`` may be empty / ``None`` for unprotected bundles —
    we pass the right shape through to ``pkcs12.load_pkcs12``.
    """
    if not pfx_bytes:
        raise PfxImportError("Uploaded PFX file is empty.")

    pw_bytes = password.encode("utf-8") if password else None
    try:
        bundle = pkcs12.load_pkcs12(pfx_bytes, pw_bytes)
    except ValueError as exc:
        # cryptography raises ValueError("Invalid password or PKCS12 data")
        # for both wrong password and corrupted bytes. Surface a clean
        # message either way.
        raise PfxImportError(
            "Could not decrypt PFX — wrong password, or the file is not "
            f"a valid PKCS#12 bundle ({exc})."
        ) from exc
    except Exception as exc:
        raise PfxImportError(f"Failed to parse PFX bundle: {exc}") from exc

    if bundle.key is None:
        raise PfxImportError(
            "PFX bundle contains no private key. Re-export the bundle "
            "with the private key included (openssl pkcs12 -export "
            "without -nokeys)."
        )
    if bundle.cert is None or bundle.cert.certificate is None:
        raise PfxImportError(
            "PFX bundle contains no end-entity certificate. Re-export "
            "with the leaf cert included."
        )

    leaf = bundle.cert.certificate
    intermediates = [c.certificate for c in (bundle.additional_certs or [])]

    # Validate key+cert match by comparing the public key bytes. The
    # cryptography library's pkcs12 loader already enforces this when
    # the PKCS#12 MAC verifies, but a hand-assembled bundle can mismatch
    # — surface it clearly here rather than failing at SMC import.
    try:
        cert_pub = leaf.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_pub = bundle.key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_pub != key_pub:
            raise PfxImportError(
                "Private key does not match the end-entity certificate "
                "in this PFX (public key mismatch). The bundle is "
                "inconsistent."
            )
    except PfxImportError:
        raise
    except Exception as exc:
        log.warning("PFX key/cert match check failed defensively: %s", exc)

    metadata = _extract_cert_metadata(leaf)
    now = datetime.now(timezone.utc)
    if metadata.get("valid_to") and metadata["valid_to"] < now:
        # Refuse to import an already-expired cert — it would deploy
        # and immediately break TLS on the engine. Operator gets a
        # clear refusal instead of an opaque SMC error later.
        raise PfxImportError(
            f"Certificate already expired on "
            f"{metadata['valid_to'].strftime('%Y-%m-%d')}. Re-issue "
            "the cert and re-export the PFX before importing."
        )

    # Serialise everything to PEM. Private key written unencrypted —
    # the deploy pipeline + SMC ingestion path both need it
    # unencrypted, and the file lives on the FEA host inside the
    # encrypted /config/ volume the operator manages anyway.
    privkey_pem = bundle.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    cert_pem = leaf.public_bytes(
        encoding=serialization.Encoding.PEM,
    ).decode("ascii")
    chain_pem_parts = [
        c.public_bytes(encoding=serialization.Encoding.PEM).decode("ascii")
        for c in intermediates
    ]
    chain_pem = "".join(chain_pem_parts)
    # fullchain.pem in certbot's layout is leaf + chain (concatenated).
    fullchain_pem = cert_pem + chain_pem

    return ParsedPfx(
        cert_pem=cert_pem,
        privkey_pem=privkey_pem,
        chain_pem=chain_pem,
        fullchain_pem=fullchain_pem,
        metadata=metadata,
    )


# Slug rule: PFX dirs go on a regular filesystem. ASCII-lowercase,
# digits, dot, hyphen only. Anything else gets replaced with `-` so
# wildcard CNs ("*.example.com") become "wildcard.example.com" — a
# safe filesystem name that's still recognisable.
_SLUG_RE = re.compile(r"[^a-z0-9.\-]+")


def slug_for_domain(domain: str) -> str:
    """Produce a safe directory name from a cert CN / hostname."""
    if not domain:
        return "unnamed"
    s = domain.strip().lower()
    s = s.replace("*", "wildcard")
    s = _SLUG_RE.sub("-", s)
    s = s.strip("-.") or "unnamed"
    return s[:200]  # filesystem-safe length


def lineage_dir_for(domain: str) -> Path:
    """Return the on-disk lineage path FEA uses for a given cert CN."""
    return pfx_root() / slug_for_domain(domain)


def save_parsed_pfx(parsed: ParsedPfx, domain: str) -> tuple[Path, str]:
    """Write the certbot-layout PEM files to ``lineage_dir_for(domain)``.

    Replaces existing files in place (re-import is idempotent on a
    per-CN basis). Sets restrictive permissions on the private key.
    Returns ``(lineage_path, fullchain_sha256)``.
    """
    out = lineage_dir_for(domain)
    out.mkdir(parents=True, exist_ok=True)

    # Match certbot's lineage layout: cert.pem / privkey.pem /
    # chain.pem / fullchain.pem. The TLS deployer reads fullchain.pem
    # + privkey.pem; the certbot_reader (used by the existing
    # /tls/certificates discovery) reads cert.pem + privkey.pem.
    (out / "cert.pem").write_text(parsed.cert_pem)
    (out / "chain.pem").write_text(parsed.chain_pem)
    (out / "fullchain.pem").write_text(parsed.fullchain_pem)

    pk_path = out / "privkey.pem"
    pk_path.write_text(parsed.privkey_pem)
    try:
        pk_path.chmod(0o600)
    except Exception as exc:
        # Some filesystems (NFS, certain Docker bind-mounts) refuse
        # chmod. Log and continue — the file is still inside the
        # FEA-private /config/ volume.
        log.info("PFX import: chmod 600 on privkey failed (%s); "
                 "filesystem may not support POSIX modes.", exc)

    fullchain_hash = hashlib.sha256(parsed.fullchain_pem.encode("utf-8")).hexdigest()
    return out, fullchain_hash
