"""
FlexEdgeAdmin — TLS Deployment orchestrator.

Executes the full pipeline for a single TLSDeployment:
  1. Import TLSServerCredential into SMC
  2. Create host objects (public + private)
  3. Assign credential to engine TLS inspection
  4. Create/verify policy rule with deep inspection + decryption
  5. Upload/refresh policy on the engine
"""
import logging
from datetime import datetime, timezone

from shared.db import db
from webapp.models import (
    ManagedCertificate, TLSDeployment, TLSDeploymentLog, ApiKey, Tenant,
)
from webapp.smc_tls_client import (
    DeployResult, SMCConfig, smc_session,
    import_tls_credential, ensure_host, assign_tls_to_engine,
    get_engine_tls_credentials, get_engine_active_policy,
    find_tls_rule, create_tls_inspection_rule, policy_upload,
)

logger = logging.getLogger(__name__)


def _smc_cfg_for_deployment(dep: TLSDeployment) -> SMCConfig:
    """Build an SMCConfig from the deployment's linked Tenant + ApiKey."""
    tenant = dep.tenant
    api_key = dep.api_key
    return SMCConfig(
        url=tenant.smc_url,
        api_key=api_key.decrypted_key,
        domain=tenant.default_domain or "",
        api_version=tenant.api_version or "",
        verify_ssl=tenant.verify_ssl,
        timeout=tenant.timeout,
    )


def execute_deployment(dep: TLSDeployment, smc_cfg: SMCConfig,
                       cert_fullchain: str, cert_privkey: str) -> DeployResult:
    result = DeployResult()
    tls_cred_name = f"LE-{dep.service_name}"
    section_name = f"Service {dep.service_name} - TLS Protection"

    try:
        with smc_session(smc_cfg):
            # Step 1: Import TLS credential
            try:
                import_tls_credential(tls_cred_name, cert_fullchain, cert_privkey)
                result.tls_credential_name = tls_cred_name
                result.add_step("import_tls_credential", "ok", tls_cred_name)
            except Exception as e:
                result.add_step("import_tls_credential", "failed", str(e))
                result.error = f"TLS credential import failed: {e}"
                return result

            # Step 2: Create host objects
            pub_host_name = f"{dep.service_name}-PublicIPv4"
            priv_host_name = f"{dep.service_name}-PrivateIPv4"
            try:
                ensure_host(pub_host_name, dep.public_ipv4)
                result.host_public_name = pub_host_name
                result.add_step("create_host_public", "ok", f"{pub_host_name} ({dep.public_ipv4})")
            except Exception as e:
                result.add_step("create_host_public", "failed", str(e))
                result.error = f"Public host creation failed: {e}"
                return result

            try:
                ensure_host(priv_host_name, dep.private_ipv4)
                result.host_private_name = priv_host_name
                result.add_step("create_host_private", "ok", f"{priv_host_name} ({dep.private_ipv4})")
            except Exception as e:
                result.add_step("create_host_private", "failed", str(e))
                result.error = f"Private host creation failed: {e}"
                return result

            # Step 3: Assign TLS credential to engine
            try:
                current = [c["name"] for c in get_engine_tls_credentials(dep.engine_name)]
                result.add_step("check_engine_tls", "ok", f"Current: {current}")
                assign_tls_to_engine(dep.engine_name, tls_cred_name)
                result.add_step("assign_tls_to_engine", "ok", tls_cred_name)
            except Exception as e:
                result.add_step("assign_tls_to_engine", "failed", str(e))
                result.error = f"Engine TLS assignment failed: {e}"
                return result

            # Step 4: Policy rule
            try:
                policy_name = get_engine_active_policy(dep.engine_name)
                if not policy_name:
                    result.add_step("get_active_policy", "warning", "Could not determine active policy")
                else:
                    result.add_step("get_active_policy", "ok", policy_name)
                    existing = find_tls_rule(policy_name, priv_host_name, section_name)
                    if existing:
                        result.policy_rule_name = existing["name"]
                        result.add_step("check_tls_rule", "ok", f"Exists: {existing['name']}")
                    else:
                        rule_name = create_tls_inspection_rule(
                            policy_name, dep.service_name, pub_host_name,
                            priv_host_name, section_name,
                        )
                        result.policy_rule_name = rule_name
                        result.add_step("create_tls_rule", "ok", rule_name)
                    result.policy_section_name = section_name
            except Exception as e:
                result.add_step("policy_rule", "failed", str(e))
                logger.warning("Policy rule step failed: %s", e)

            # Step 5: Policy upload
            try:
                upload_result = policy_upload(dep.engine_name)
                result.add_step("policy_upload", "ok", upload_result)
            except Exception as e:
                result.add_step("policy_upload", "failed", str(e))
                logger.warning("Policy upload failed: %s", e)

            result.success = True
    except Exception as e:
        result.error = f"SMC session error: {e}"
        result.add_step("smc_session", "failed", str(e))

    return result


def run_deployment(deployment_id: int, action: str = "deploy") -> DeployResult:
    """Execute a deployment by ID; persist the result."""
    dep = db.session.get(TLSDeployment, deployment_id)
    if not dep:
        return DeployResult(error="Deployment not found")
    cert = db.session.get(ManagedCertificate, dep.certificate_id)
    if not cert:
        return DeployResult(error="Certificate not found")

    smc_cfg = _smc_cfg_for_deployment(dep)
    fullchain = f"{cert.certbot_lineage}/fullchain.pem"
    privkey = f"{cert.certbot_lineage}/privkey.pem"

    result = execute_deployment(dep, smc_cfg, fullchain, privkey)

    dep.last_deployed_at = datetime.now(timezone.utc)
    dep.last_status = "deployed" if result.success else "failed"
    dep.last_error = result.error
    dep.tls_credential_name = result.tls_credential_name
    dep.host_public_name = result.host_public_name
    dep.host_private_name = result.host_private_name
    dep.policy_rule_name = result.policy_rule_name
    dep.policy_section_name = result.policy_section_name

    db.session.add(TLSDeploymentLog(
        deployment_id=dep.id, action=action,
        status="success" if result.success else "failed",
        details=str(result.steps),
    ))
    db.session.commit()
    return result
