"""
FlexEdgeAdmin — SMC API client for TLS credential operations.

Wraps smc-python to handle:
  - TLS credential import/update/delete
  - Engine TLS inspection assignment
  - Host object creation
  - Policy rule creation with deep inspection + decryption
  - Policy upload/refresh
  - Admin domain enumeration and validation
"""
import logging
from contextlib import contextmanager
from dataclasses import dataclass, field

from smc import session
from smc.administration.certificates.tls import TLSServerCredential
from smc.core.engine import Engine
from smc.elements.network import Host
from smc.elements.service import TCPService
from smc.policy.layer3 import FirewallPolicy
from smc.policy.rule_elements import Action, LogOptions

# ── Silence urllib3's InsecureRequestWarning ─────────────────────────────
# Every SMC call (with verify_ssl=False, the FlexEdge default) emits a
# warning. In tight loops like interface enumeration this floods the log.
# Tenants configured with verify_ssl=True are unaffected because urllib3
# only warns on unverified requests.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

logger = logging.getLogger(__name__)


@dataclass
class SMCConfig:
    url: str
    api_key: str
    domain: str = ""
    api_version: str = ""
    verify_ssl: bool = False
    timeout: int = 120


@dataclass
class DeployResult:
    success: bool = False
    tls_credential_name: str = ""
    host_public_name: str = ""
    host_private_name: str = ""
    policy_rule_name: str = ""
    policy_section_name: str = ""
    steps: list = field(default_factory=list)
    error: str = ""

    def add_step(self, name: str, status: str, detail: str = ""):
        self.steps.append({"name": name, "status": status, "detail": detail})


@contextmanager
def smc_session(cfg: SMCConfig):
    """Context manager for an authenticated SMC session."""
    login_kwargs = {
        "url": cfg.url,
        "api_key": cfg.api_key,
        "verify": cfg.verify_ssl,
        "timeout": cfg.timeout,
        "retry_on_busy": True,
    }
    if cfg.domain:
        login_kwargs["domain"] = cfg.domain
    if cfg.api_version:
        login_kwargs["api_version"] = cfg.api_version

    session.login(**login_kwargs)
    try:
        yield
    finally:
        try:
            session.logout()
        except Exception:
            pass


def smc_error_detail(exc: Exception) -> str:
    """Extract a human-readable error from an SMC exception."""
    parts = [str(exc)]
    for attr in ("smcresult", "msg", "message", "status_code", "json"):
        val = getattr(exc, attr, None)
        if val is None:
            continue
        if callable(val):
            try:
                val = val()
            except Exception:
                continue
        s = str(val)
        if s and s not in parts[0]:
            parts.append(s)
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Admin Domains
# ---------------------------------------------------------------------------

def _get_api_client_domain_info() -> dict:
    info = {
        "admin_domain_href": "",
        "admin_domain_id": "",
        "allowed_shared": True,
        "api_client_name": "",
        "visible_engines": [],
    }
    try:
        user = session.current_user
        data = user.data.data if hasattr(user.data, "data") else dict(user.data)
        info["api_client_name"] = data.get("name", "")
        info["admin_domain_href"] = data.get("admin_domain", "")
        info["allowed_shared"] = data.get("allowed_to_login_in_shared", True)
        if info["admin_domain_href"]:
            info["admin_domain_id"] = info["admin_domain_href"].rstrip("/").split("/")[-1]
    except Exception as e:
        logger.debug("Could not inspect ApiClient: %s", e)

    try:
        from smc.core.engine import Engine
        info["visible_engines"] = [e.name for e in Engine.objects.all()]
    except Exception:
        pass
    return info


def list_domains(url: str, api_key: str, api_version: str = "",
                 verify_ssl: bool = False, timeout: int = 60) -> dict:
    """
    Return {domains, domain_scoped, api_client_name, admin_domain_href,
            admin_domain_id, visible_engines}.
    """
    login_kwargs = {
        "url": url, "api_key": api_key, "verify": verify_ssl,
        "timeout": timeout, "retry_on_busy": True,
    }
    if api_version:
        login_kwargs["api_version"] = api_version

    try:
        session.login(**login_kwargs)
    except Exception as exc:
        raise RuntimeError(f"SMC login failed: {smc_error_detail(exc)}") from exc

    try:
        client_info = _get_api_client_domain_info()
        try:
            from smc.administration.access_rights import AdminDomain
        except ImportError:
            from smc.core.engine import AdminDomain  # type: ignore
        domains = [{"name": d.name, "href": getattr(d, "href", "")}
                   for d in AdminDomain.objects.all()]
        domain_scoped = len(domains) == 0 and not client_info["allowed_shared"]
        return {
            "domains": sorted(domains, key=lambda d: d["name"].lower()),
            "domain_scoped": domain_scoped,
            "api_client_name": client_info["api_client_name"],
            "admin_domain_href": client_info["admin_domain_href"],
            "admin_domain_id": client_info["admin_domain_id"],
            "visible_engines": client_info["visible_engines"],
        }
    except Exception as e:
        raise RuntimeError(f"Error listing domains: {smc_error_detail(e)}") from e
    finally:
        try:
            session.logout()
        except Exception:
            pass


def validate_domain(url: str, api_key: str, domain: str, api_version: str = "",
                    verify_ssl: bool = False, timeout: int = 60) -> dict:
    """Verify API key can log into a specific domain."""
    login_kwargs = {
        "url": url, "api_key": api_key, "domain": domain,
        "verify": verify_ssl, "timeout": timeout, "retry_on_busy": True,
    }
    if api_version:
        login_kwargs["api_version"] = api_version

    try:
        session.login(**login_kwargs)
    except Exception as exc:
        return {"valid": False, "detail": smc_error_detail(exc), "engines": 0}

    try:
        from smc.core.engine import Engine
        count = sum(1 for _ in Engine.objects.all())
        return {"valid": True, "detail": f"Logged in, {count} engine(s) visible", "engines": count}
    except Exception as e:
        return {"valid": True, "detail": f"Logged in but engine check failed: {e}", "engines": 0}
    finally:
        try:
            session.logout()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# TLS Credentials
# ---------------------------------------------------------------------------

def list_tls_credentials() -> list:
    results = []
    for cred in TLSServerCredential.objects.all():
        info = {"name": cred.name, "href": cred.href}
        try:
            info["valid_from"] = str(cred.valid_from) if cred.valid_from else ""
            info["valid_to"] = str(cred.valid_to) if cred.valid_to else ""
            info["certificate_state"] = getattr(cred, "certificate_state", "")
        except Exception:
            pass
        results.append(info)
    return results


def import_tls_credential(name: str, fullchain_path: str, privkey_path: str):
    """Import TLS credential, replacing any existing one with the same name."""
    try:
        existing = TLSServerCredential(name)
        existing.href  # noqa: trigger resolution
        existing.delete()
        logger.info("Deleted existing TLS credential: %s", name)
    except Exception:
        pass
    return TLSServerCredential.import_signed(
        name=name, certificate=fullchain_path, private_key=privkey_path,
    )


def delete_tls_credential(name: str) -> bool:
    try:
        TLSServerCredential(name).delete()
        return True
    except Exception as e:
        logger.error("Failed to delete TLS credential %s: %s", name, e)
        return False


# ---------------------------------------------------------------------------
# Engine TLS Inspection
# ---------------------------------------------------------------------------

def get_engine_tls_credentials(engine_name: str) -> list:
    engine = Engine(engine_name)
    return [{"name": c.name, "href": c.href}
            for c in engine.tls_inspection.server_credentials]


def assign_tls_to_engine(engine_name: str, credential_name: str) -> None:
    engine = Engine(engine_name)
    cred = TLSServerCredential(credential_name)
    existing = [c.name for c in engine.tls_inspection.server_credentials]
    if credential_name in existing:
        return
    engine.tls_inspection.add_tls_credential([cred])
    engine.update()


def remove_tls_from_engine(engine_name: str, credential_name: str) -> None:
    engine = Engine(engine_name)
    engine.tls_inspection.remove_tls_credential([TLSServerCredential(credential_name)])
    engine.update()


# ---------------------------------------------------------------------------
# Hosts and Policy Rules
# ---------------------------------------------------------------------------

def ensure_host(name: str, address: str) -> Host:
    try:
        host = Host(name)
        host.href
        return host
    except Exception:
        pass
    Host.create(name=name, address=address)
    return Host(name)


def get_engine_active_policy(engine_name: str):
    engine = Engine(engine_name)
    try:
        for status in engine.nodes:
            if hasattr(status, "installed_policy"):
                p = status.installed_policy
                if p:
                    return p
    except Exception:
        pass
    try:
        if hasattr(engine, "installed_policy"):
            return engine.installed_policy
    except Exception:
        pass
    return None


def find_tls_rule(policy_name: str, destination_name: str, section_name: str):
    policy = FirewallPolicy(policy_name)
    for rule in policy.fw_ipv4_access_rules.all():
        if rule.name and section_name.lower() in rule.name.lower():
            return {"name": rule.name, "href": rule.href, "is_disabled": rule.is_disabled}
        try:
            for dest in rule.destinations.all():
                if hasattr(dest, "name") and dest.name == destination_name:
                    return {"name": rule.name, "href": rule.href, "is_disabled": rule.is_disabled}
        except Exception:
            continue
    return None


def create_tls_inspection_rule(policy_name: str, service_name: str,
                               host_public_name: str, host_private_name: str,
                               section_name: str) -> str:
    policy = FirewallPolicy(policy_name)
    rule_name = f"{section_name} - HTTPS Inspection"
    dest_host = Host(host_private_name)
    https_service = TCPService("HTTPS")

    action = Action()
    action.deep_inspection = True
    action.file_filtering = True
    action.decrypting = True

    log_opts = LogOptions()
    log_opts.log_accounting_info_mode = True
    log_opts.log_level = "stored"

    policy.fw_ipv4_access_rules.create(
        name=rule_name, sources="any", destinations=[dest_host],
        services=[https_service], action=action, log_options=log_opts,
        add_pos=1, comment=f"Auto-managed TLS inspection for {service_name}",
    )
    return rule_name


# ---------------------------------------------------------------------------
# Policy Upload / Refresh
# ---------------------------------------------------------------------------

def policy_refresh(engine_name: str) -> str:
    return str(Engine(engine_name).refresh())


def policy_upload(engine_name: str, policy_name: str = None) -> str:
    engine = Engine(engine_name)
    if policy_name:
        return str(engine.upload(policy=policy_name))
    return str(engine.upload())


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def list_engines(debug: bool = False) -> list:
    """
    Enumerate every engine visible to the current session, regardless of type
    (Layer3/Layer2 firewalls, clusters, master engines, virtual engines, IPS, etc.).

    Three-stage discovery:
      1. Generic Engine.objects.all() — smc-python's native cross-type query
      2. Per-subclass enumeration — belt-and-suspenders for older smc-python
      3. Raw REST /elements/engine_clusters — catches anything the library
         abstraction misses. engine_clusters is the SMC API's native
         entry point that returns ALL engine types in one response.

    Each engine gets a 'sources' field listing which stages saw it, useful
    for debugging discovery gaps.
    """
    engines_by_href: dict[str, dict] = {}

    def _add(href: str, name: str, typeof: str, source: str):
        if href not in engines_by_href:
            engines_by_href[href] = {
                "name": name, "type": typeof, "href": href, "sources": [],
            }
        if source not in engines_by_href[href]["sources"]:
            engines_by_href[href]["sources"].append(source)

    # Stage 1: Engine.objects.all()
    try:
        from smc.core.engine import Engine
        for eng in Engine.objects.all():
            _add(eng.href, eng.name, eng.typeof, "generic")
    except Exception as e:
        logger.warning("Engine.objects.all() failed: %s", e)

    # Stage 2: per-subclass enumeration
    from smc.core import engines as engines_mod
    for cls_name in ("Layer3Firewall", "Layer2Firewall", "FirewallCluster",
                     "Layer2Cluster", "Layer3VirtualEngine",
                     "MasterEngine", "MasterEngineCluster",
                     "IPS", "VirtualIPS", "VirtualLayer2", "CloudSGSingleFW"):
        cls = getattr(engines_mod, cls_name, None)
        if cls is None:
            continue
        try:
            for eng in cls.objects.all():
                _add(eng.href, eng.name, eng.typeof, cls_name)
        except Exception as e:
            logger.debug("%s.objects.all() failed: %s", cls_name, e)

    # Stage 3: raw REST /elements/engine_clusters — catches anything the
    # library abstractions might miss. This endpoint is a "super-set" in SMC.
    try:
        s = session.session
        base = f"{session.url}/{session.api_version}"
        for ep in ("engine_clusters", "single_fw", "fw_cluster",
                   "virtual_fw", "master_engine", "single_layer2",
                   "layer2_cluster", "single_ips", "virtual_ips",
                   "virtual_firewall_layer2", "cloud_single_fw"):
            try:
                r = s.get(f"{base}/elements/{ep}", verify=False, timeout=30)
                if r.status_code == 200:
                    for item in r.json().get("result", []):
                        href = item.get("href", "")
                        name = item.get("name", "")
                        typeof = item.get("type", "")
                        if href and name:
                            _add(href, name, typeof, f"rest:{ep}")
            except Exception as e:
                logger.debug("REST /%s failed: %s", ep, e)
    except Exception as e:
        logger.warning("Raw REST engine enumeration failed: %s", e)

    result = sorted(engines_by_href.values(), key=lambda e: e["name"].lower())
    if not debug:
        # Strip the "sources" field for the public API unless debug was requested
        return [{k: v for k, v in e.items() if k != "sources"} for e in result]
    return result


def list_policies() -> list:
    return [{"name": p.name, "href": p.href} for p in FirewallPolicy.objects.all()]
