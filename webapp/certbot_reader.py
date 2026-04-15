"""
FlexEdgeAdmin — Certbot certificate discovery and reading.
Reads /etc/letsencrypt/live/ and /etc/letsencrypt/renewal/ to enumerate
managed certificates, their domains, expiry, and file paths.
"""
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

logger = logging.getLogger(__name__)


@dataclass
class CertInfo:
    domain: str
    lineage_path: str
    cert_path: str
    key_path: str
    fullchain_path: str
    chain_path: str
    subject_cn: str = ""
    issuer: str = ""
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    san_domains: list = field(default_factory=list)
    serial: str = ""
    fingerprint_sha256: str = ""

    @property
    def is_expired(self) -> bool:
        return not self.valid_to or datetime.now(timezone.utc) > self.valid_to

    @property
    def days_until_expiry(self):
        if not self.valid_to:
            return None
        return (self.valid_to - datetime.now(timezone.utc)).days


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_certificate(cert_path: str) -> dict:
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    cn = ""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value
    except Exception:
        pass

    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_domains = san_ext.value.get_values_for_type(x509.DNSName)
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


def discover_certificates(live_dir: str) -> list:
    live = Path(live_dir)
    if not live.is_dir():
        logger.warning("Certbot live directory not found: %s", live_dir)
        return []

    certs = []
    for entry in sorted(live.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        cert_pem = entry / "cert.pem"
        key_pem = entry / "privkey.pem"
        if not cert_pem.exists() or not key_pem.exists():
            continue

        info = CertInfo(
            domain=entry.name,
            lineage_path=str(entry),
            cert_path=str(cert_pem),
            key_path=str(key_pem),
            fullchain_path=str(entry / "fullchain.pem") if (entry / "fullchain.pem").exists() else "",
            chain_path=str(entry / "chain.pem") if (entry / "chain.pem").exists() else "",
        )
        try:
            meta = parse_certificate(str(cert_pem))
            for k, v in meta.items():
                setattr(info, k, v)
        except Exception as e:
            logger.warning("Failed to parse cert for %s: %s", entry.name, e)
        certs.append(info)
    return certs


def read_renewal_config(renewal_dir: str, domain: str) -> dict:
    conf_path = Path(renewal_dir) / f"{domain}.conf"
    if not conf_path.exists():
        return {}
    config = {}
    section = None
    for line in conf_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[(\w+)\]$", line)
        if m:
            section = m.group(1)
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if section:
                k = f"{section}.{k}"
            config[k] = v
    return config
