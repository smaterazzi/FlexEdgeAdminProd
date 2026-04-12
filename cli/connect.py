"""
FlexEdgeAdmin CLI — SMC Connection Module.

Handles authentication and session management for Forcepoint NGFW SMC.
Supports two config modes:
  1. Shared tenant config (tenants.json + SMC_API_KEY env var or --api-key)
  2. Legacy config.ini fallback for backward compatibility
"""

import argparse
import configparser
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path so `shared` is importable
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from smc import session


def load_config_from_tenant(tenant_id: str, api_key: str) -> dict:
    """Load SMC config from shared tenants.json.

    Args:
        tenant_id: Tenant ID from tenants.json (e.g. "prod").
        api_key: SMC API key (from env or CLI flag).

    Returns:
        Dictionary with CLI connection parameters.
    """
    from shared.tenant_config import get_tenant

    tenant = get_tenant(tenant_id)
    return tenant.to_cli_kwargs(api_key)


def load_config_from_ini(config_path: str = None) -> dict:
    """Load SMC configuration from legacy config.ini file.

    Args:
        config_path: Path to config.ini. Defaults to config.ini next to this script.

    Returns:
        Dictionary with SMC connection parameters.
    """
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "config.ini")

    config = configparser.ConfigParser()
    config.read(config_path)

    smc_config = {
        "address": config.get("smc", "smc_address"),
        "port": config.getint("smc", "smc_port"),
        "api_key": config.get("smc", "smc_apikey"),
        "ssl": config.getboolean("smc", "smc_ssl", fallback=False),
        "verify_ssl": config.getboolean("smc", "verify_ssl", fallback=False),
    }

    if config.has_option("smc", "ssl_cert_file"):
        cert_file = config.get("smc", "ssl_cert_file")
        if cert_file:
            smc_config["ssl_cert_file"] = cert_file

    if config.has_option("smc", "api_version"):
        api_version = config.get("smc", "api_version")
        if api_version:
            smc_config["api_version"] = api_version

    if config.has_option("smc", "domain"):
        domain = config.get("smc", "domain")
        if domain:
            smc_config["domain"] = domain

    return smc_config


def load_config(tenant_id: str = None, api_key: str = None, config_path: str = None) -> dict:
    """Load SMC config, preferring tenant mode, falling back to legacy INI.

    Resolution order:
      1. If tenant_id is given (or DEFAULT_TENANT env var), use tenants.json
      2. Else if config.ini exists, use legacy INI format
      3. Else raise an error with setup instructions
    """
    tid = tenant_id or os.environ.get("DEFAULT_TENANT")
    key = api_key or os.environ.get("SMC_API_KEY")

    if tid and key:
        return load_config_from_tenant(tid, key)

    if tid and not key:
        raise ValueError(
            f"Tenant '{tid}' specified but no API key provided.\n"
            f"Set SMC_API_KEY environment variable or pass --api-key."
        )

    # Fallback: legacy config.ini
    ini_path = config_path or os.path.join(os.path.dirname(__file__), "config.ini")
    if os.path.isfile(ini_path):
        return load_config_from_ini(ini_path)

    raise FileNotFoundError(
        "No configuration found. Either:\n"
        "  1. Set DEFAULT_TENANT + SMC_API_KEY environment variables, or\n"
        "  2. Create config/tenants.json from config/tenants.json.example, or\n"
        "  3. Create cli/config.ini from config/config.ini.example"
    )


def connect(tenant_id: str = None, api_key: str = None, config_path: str = None) -> bool:
    """Connect to SMC.

    Args:
        tenant_id: Optional tenant ID from tenants.json.
        api_key: Optional API key (or set SMC_API_KEY env var).
        config_path: Optional path to legacy config.ini.

    Returns:
        True if connection successful.
    """
    cfg = load_config(tenant_id=tenant_id, api_key=api_key, config_path=config_path)

    protocol = "https" if cfg.get("ssl", True) else "http"
    url = f"{protocol}://{cfg['address']}:{cfg['port']}"

    login_params = {
        "url": url,
        "api_key": cfg["api_key"],
    }

    if cfg.get("ssl", True):
        if cfg.get("verify_ssl") and "ssl_cert_file" in cfg:
            login_params["verify"] = cfg["ssl_cert_file"]
        else:
            login_params["verify"] = cfg.get("verify_ssl", False)

    if cfg.get("api_version"):
        login_params["api_version"] = cfg["api_version"]

    if cfg.get("domain"):
        login_params["domain"] = cfg["domain"]

    if cfg.get("timeout"):
        login_params["timeout"] = cfg["timeout"]

    session.login(**login_params)
    print(f"Connected to SMC at {url}")
    print(f"API Version: {session.api_version}")
    print(f"Session ID: {session.session_id}")

    return True


def disconnect():
    """Disconnect from SMC."""
    session.logout()
    print("Disconnected from SMC")


def main():
    parser = argparse.ArgumentParser(description="Test SMC connection")
    parser.add_argument("--tenant", "-t", help="Tenant ID from tenants.json")
    parser.add_argument("--api-key", "-k", help="SMC API key (or set SMC_API_KEY env var)")
    parser.add_argument("--config", "-c", help="Path to legacy config.ini")
    args = parser.parse_args()

    try:
        connect(tenant_id=args.tenant, api_key=args.api_key, config_path=args.config)
        print("\nConnection successful!")
        disconnect()
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
