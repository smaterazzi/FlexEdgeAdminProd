"""FortiGate migration VPN enqueue glue (Phase E.2 — last tier).

Mirrors the Q19/b internal-orchestrator pattern used by TLS deploy:
ONE queue row per VPN config, the handler runs the full pipeline
(VPNProfile → ExternalGateway → Endpoint → VPNSite → Networks →
PolicyVPN → topology) inside the queue runner's SMC session.

The expanded detail panel on `/changes/` shows every sub-step status
via `payload.steps[]` (rendered by the existing `from_json` filter).

Why a bundle handler instead of N small rows: the VPN topology open /
save / close transaction can't be split across queue rows without
partial commits leaking into SMC. Same reasoning as TLS Q19/b.
"""

import json
import logging
from typing import Optional

from shared.db import db
from webapp.models import PendingChange, User

log = logging.getLogger(__name__)


# ── Pipeline body (used by both the queue handler and any out-of-queue
#                     direct-write callers that pre-date the conversion).

class VpnPipelineResult:
    """Lightweight result carrier with the per-step trace.

    Mirrors `webapp.smc_tls_client.DeployResult` shape so the queue
    UI's expanded detail panel renders the same per-step badges.
    """

    def __init__(self):
        self.success: bool = False
        self.error: str = ""
        self.profile_name: str = ""
        self.gateway_name: str = ""
        self.policy_name: str = ""
        self.steps: list[dict] = []

    def add_step(self, name: str, status: str, detail: str = ""):
        self.steps.append({"name": name, "status": status, "detail": detail})


def execute_vpn_pipeline_inside_session(config: dict,
                                        engine_name: Optional[str] = None
                                        ) -> VpnPipelineResult:
    """Run the 6-step VPN pipeline assuming an SMC session is already open.

    Used by:
      * the queue handler (`shared/queue_runner.py:_handle_deploy_vpn`)
        — the runner opens the session.
      * any standalone caller that owns a session and wants the body.

    Steps:
      1. VPN profile (find-or-create with crypto capabilities)
      2. External gateway (find-or-create)
      3. External endpoint (remote peer IP)
      4. VPN site + member networks
      5. PolicyVPN container
      6. Topology (open + add satellite + add central + save + close)

    Returns a populated `VpnPipelineResult` with steps[] for the queue
    UI's Q19/b expanded-detail rendering.
    """
    from smc.vpn.policy import PolicyVPN
    from smc.vpn.elements import VPNProfile, ExternalGateway
    from smc.elements.network import Host, Network

    result = VpnPipelineResult()
    tunnel_name = config.get("name", "?")

    # ── Step 1: VPN profile ──────────────────────────────────────────
    profile_name = config.get("vpn_profile") or ""
    profile_action = (config.get("profile_action") or "create").strip()
    profile_obj = None

    if profile_action == "reuse":
        try:
            profile_obj = VPNProfile(profile_name)
            _ = profile_obj.href
            result.add_step("vpn_profile", "ok",
                            f"reused: {profile_name}")
        except Exception:
            result.add_step("vpn_profile", "warning",
                            f"could not find {profile_name!r} for reuse "
                            f"— falling back to create")
            profile_action = "create"

    if profile_action == "create":
        try:
            caps = config.get("profile_capabilities") or {}
            VPNProfile.create(
                name=profile_name,
                capabilities=caps,
                sa_life_time=config.get("p1_keylife", 86400),
                tunnel_life_time_seconds=config.get("p2_keylife", 28800),
            )
            profile_obj = VPNProfile(profile_name)
            result.add_step("vpn_profile", "ok",
                            f"created: {profile_name}")
        except Exception as e:
            err = str(e).lower()
            if ("already exists" in err or "must be unique" in err
                    or "duplicate" in err):
                try:
                    profile_obj = VPNProfile(profile_name)
                    result.add_step("vpn_profile", "ok",
                                    f"already exists: {profile_name}")
                except Exception as e2:
                    result.add_step("vpn_profile", "failed",
                                    f"already exists but cannot reload: {e2}")
                    result.error = f"VPN profile load failed: {e2}"
                    return result
            else:
                result.add_step("vpn_profile", "failed", str(e))
                result.error = f"VPN profile create failed: {e}"
                return result
    result.profile_name = profile_name

    # ── Step 2: External gateway ─────────────────────────────────────
    gw_name = config.get("gateway_name") or ""
    try:
        ExternalGateway.create(name=gw_name, trust_all_cas=True)
        result.add_step("external_gateway", "ok", f"created: {gw_name}")
    except Exception as e:
        err = str(e).lower()
        if ("already exists" in err or "must be unique" in err
                or "duplicate" in err):
            result.add_step("external_gateway", "ok",
                            f"already exists: {gw_name}")
        else:
            result.add_step("external_gateway", "failed", str(e))
            result.error = f"External gateway create failed: {e}"
            return result
    result.gateway_name = gw_name

    # ── Step 3: External endpoint ────────────────────────────────────
    endpoint_ip = config.get("endpoint_ip") or ""
    try:
        gw = ExternalGateway(gw_name)
        gw.external_endpoint.create(
            name=f"{gw_name}-EP",
            address=endpoint_ip,
        )
        result.add_step("external_endpoint", "ok",
                        f"{endpoint_ip} on {gw_name}")
    except Exception as e:
        err = str(e).lower()
        if ("already exists" in err or "must be unique" in err
                or "duplicate" in err):
            result.add_step("external_endpoint", "ok",
                            f"already exists on {gw_name}")
        else:
            # Endpoint failure is not fatal — log + continue. The
            # legacy direct path treated this as a warning too.
            result.add_step("external_endpoint", "warning", str(e))

    # ── Step 4: VPN site with member networks ────────────────────────
    site_elements = []
    skipped_subnets = []
    for subnet_cidr in (config.get("remote_subnets") or []):
        if not subnet_cidr:
            continue
        # Try to resolve as an existing element (Network or Host) first.
        resolved = None
        for cls in (Network, Host):
            try:
                for elem in cls.objects.filter(subnet_cidr):
                    resolved = elem
                    break
                if resolved is not None:
                    break
            except Exception:
                continue
        if resolved is not None:
            site_elements.append(resolved)
            continue

        # Create a temporary VPN-site Network for unresolved subnets.
        net_name = f"FGT-VPN-{tunnel_name}-{subnet_cidr.replace('/', '_')}"
        try:
            Network.create(
                name=net_name,
                ipv4_network=subnet_cidr,
                comment=f"VPN site network for {tunnel_name}",
            )
            site_elements.append(Network(net_name))
        except Exception as e:
            err = str(e).lower()
            if ("already exists" in err or "must be unique" in err
                    or "duplicate" in err):
                try:
                    site_elements.append(Network(net_name))
                except Exception:
                    skipped_subnets.append(subnet_cidr)
            else:
                skipped_subnets.append(f"{subnet_cidr} ({e})")

    if site_elements:
        try:
            gw = ExternalGateway(gw_name)
            gw.vpn_site.create(
                name=f"{gw_name}-Site",
                site_element=site_elements,
            )
            site_msg = (f"{len(site_elements)} network(s) on {gw_name}"
                        + (f"; skipped: {skipped_subnets}"
                           if skipped_subnets else ""))
            result.add_step("vpn_site", "ok", site_msg)
        except Exception as e:
            err = str(e).lower()
            if ("already exists" in err or "must be unique" in err
                    or "duplicate" in err):
                result.add_step("vpn_site", "ok",
                                f"already exists on {gw_name}")
            else:
                result.add_step("vpn_site", "warning", str(e))
    else:
        result.add_step("vpn_site", "warning",
                        f"no resolvable subnets — skipping site"
                        + (f" (skipped: {skipped_subnets})"
                           if skipped_subnets else ""))

    # ── Step 5: PolicyVPN container ──────────────────────────────────
    vpn_policy_name = f"FGT-VPN-{tunnel_name}"
    policy_existed = False
    try:
        vpn_kwargs = {"name": vpn_policy_name, "nat": True}
        if profile_obj is not None:
            vpn_kwargs["vpn_profile"] = profile_obj
        PolicyVPN.create(**vpn_kwargs)
        result.add_step("policy_vpn", "ok", f"created: {vpn_policy_name}")
    except Exception as e:
        err = str(e).lower()
        if ("already exists" in err or "must be unique" in err
                or "duplicate" in err):
            policy_existed = True
            result.add_step("policy_vpn", "ok",
                            f"already exists: {vpn_policy_name}")
        else:
            result.add_step("policy_vpn", "failed", str(e))
            result.error = f"PolicyVPN create failed: {e}"
            return result
    result.policy_name = vpn_policy_name

    # ── Step 6: Topology — open + add satellite + add central + save ─
    if not policy_existed:
        # Only configure topology on a freshly-created PolicyVPN.
        # Re-running on an existing policy could append duplicate
        # gateway entries; the operator can adjust topology in SMC GUI
        # if they need to.
        vpn = None
        try:
            vpn = PolicyVPN(vpn_policy_name)
            vpn.open()
            vpn.add_satellite_gateway(ExternalGateway(gw_name))
            result.add_step("topology_satellite", "ok", gw_name)

            if engine_name:
                try:
                    from smc.core.engines import Layer3Firewall
                    engine = Layer3Firewall(engine_name)
                    vpn.add_central_gateway(engine)
                    result.add_step("topology_central", "ok", engine_name)
                except Exception as eng_err:
                    result.add_step("topology_central", "warning",
                                    f"cannot add {engine_name!r}: {eng_err}")

            vpn.save()
            vpn.close()
            vpn = None
            result.add_step("topology_save", "ok", vpn_policy_name)
        except Exception as topo_err:
            result.add_step("topology_save", "warning", str(topo_err))
            try:
                if vpn is not None:
                    vpn.close()
            except Exception:
                pass
    else:
        result.add_step("topology_skip", "warning",
                        "PolicyVPN existed — left topology untouched")

    result.success = True
    return result


# ── Enqueue helper ───────────────────────────────────────────────────

def _current_user_id() -> Optional[int]:
    try:
        from flask import session, has_request_context
        if not has_request_context():
            return None
        info = session.get("user") or {}
        email = (info.get("email") or "").strip().lower()
        if not email:
            return None
        u = User.query.filter_by(email=email).first()
        return u.id if u else None
    except Exception:
        return None


def enqueue_vpn_imports(vpn_converted: dict, domain, project_id: int,
                        engine_name: Optional[str] = None) -> dict:
    """Stage VPN configs from a converted import as queue rows.

    ONE row per selected VPN config. Each row carries the full config
    dict + the engine name for topology assignment. The queue handler
    drives the 6-step pipeline internally and reports per-step status
    via `payload.steps[]` (visible in the queue UI's expanded detail).

    Returns a dict mirroring `smc_writer.create_vpn_infrastructure`::

        {
          "entries":          [...log lines...],
          "vpn_profiles":     int,    # *enqueued* — we don't know yet
                                       which will be "created" vs
                                       "reused" until push runs
          "gateways":         int,
          "vpn_policies":     int,    # = changes_enqueued
          "vpn_errors":       int,
          "changes_enqueued": int,
          "correlation_id":   str,
        }
    """
    correlation_id = f"migration:{project_id}"
    out = {
        "entries": [],
        "vpn_profiles": 0,
        "gateways": 0,
        "vpn_policies": 0,
        "vpn_errors": 0,
        "changes_enqueued": 0,
        "correlation_id": correlation_id,
    }

    if domain is None:
        out["entries"].append({"level": "error", "msg": (
            "VPN enqueue: no active Domain — cannot stage. Switch Domain "
            "via topbar and retry.")})
        return out

    vpn_configs = vpn_converted.get("vpn_configs") or []
    if not vpn_configs:
        out["entries"].append({"level": "info",
                               "msg": "No VPN configurations to import."})
        return out

    domain_id = domain.id

    try:
        for config in vpn_configs:
            if not config.get("selected", False):
                out["entries"].append({"level": "info", "msg": (
                    f"  − Skipped (not selected): {config.get('name', '?')}")})
                continue
            tunnel_name = (config.get("name") or "").strip()
            if not tunnel_name:
                continue
            try:
                payload = {
                    "smc_type":   "vpn",
                    "config":     config,
                    "engine_name": engine_name or "",
                }
                change = PendingChange(
                    domain_id=domain_id,
                    user_id=_current_user_id(),
                    smc_object_id=None,
                    scope="main",
                    operation="deploy_vpn",
                    payload_json=json.dumps(payload),
                    feature_source="migration",
                    source_correlation_id=correlation_id,
                    state="queued",
                )
                db.session.add(change)
                db.session.flush()

                out["vpn_profiles"] += 1
                out["gateways"] += 1
                out["vpn_policies"] += 1
                out["changes_enqueued"] += 1
                out["entries"].append({"level": "info", "msg": (
                    f"  ✓ Queued VPN: {tunnel_name} (change #{change.id})")})
            except Exception as exc:
                out["vpn_errors"] += 1
                out["entries"].append({"level": "error", "msg": (
                    f"  ✗ VPN {tunnel_name}: enqueue failed — "
                    f"{type(exc).__name__}: {exc}")})

        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        out["entries"].append({"level": "error", "msg": (
            f"VPN enqueue aborted at top level: {exc}")})

    out["entries"].append({"level": "info", "msg": (
        f"VPN migration staged — enqueued={out['changes_enqueued']} "
        f"errors={out['vpn_errors']}. "
        f"Visit /changes/?source={correlation_id} to review + push.")})
    return out
