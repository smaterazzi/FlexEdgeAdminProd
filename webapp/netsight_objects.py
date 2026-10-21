"""
FlexEdgeAdmin — single read entry point for NetSight (Extreme Site Engine)
data (RA-C, docs/RemoteAgents.md § Phase C).

Mirrors `webapp/domain_objects.py`: one cached accessor per object type,
Domain-scoped sections keyed `(domain.id, …)`, `(data, CachedValue)` return
shape so routes can render the standard freshness badge + `?refresh=1`.

Every read funnels through `run_query()`, which asks the reachable-networks
router where the Site Engine is reachable from:

  * "local"  — `NetSightClient` runs here, in the request thread;
  * "agent"  — the task is enqueued on that agent with a ONE-SHOT
               `secret_ref` (shared/agent_secrets.py) — the client secret
               itself never enters a task payload — and we block on
               `pool.wait_result`;
  * "refused" — `NetSightUnavailable(kind="refused")` with the router's
               operator-worded reason.

Failures are never cached: a fetcher that raises leaves the section empty
(`smc_cache.cache_get_or_fetch` re-raises and stores nothing).

Module-level names `_load_connection`, `_resolve`, `pick_executor`,
`NetSightClient`, `get_pool`, `issue_ref`, `audit` are the seams
tests/agents/test_netsight_objects.py monkeypatches — keep them as names.
"""

import ipaddress
import json
import logging
import socket
import time
from typing import Any, Optional, Tuple

from shared.agent_router import RouteDecision, pick_executor  # noqa: F401 (seam)
from shared.agent_secrets import issue_ref  # noqa: F401 (seam)
from shared.logging import audit  # noqa: F401 (seam)
from shared.netsight_client import NetSightClient, NetSightError  # noqa: F401 (seam)
from shared.smc_cache import (
    cache_get_or_fetch, get_loose_ttl, get_quick_ttl, invalidate,
)

log = logging.getLogger(__name__)

CAPABILITY = "netsight-query"
QUERIES = ("connect", "devices", "device", "ports", "vlans")
SECTIONS = ("netsight.devices", "netsight.device", "netsight.ports", "netsight.vlans")


class NetSightUnavailable(Exception):
    """NetSight data could not be produced. `kind` ∈ "no_connection" |
    "refused" | "failed" | "timeout"; `reason` is operator-facing."""

    def __init__(self, kind: str, reason: str):
        super().__init__(reason)
        self.kind = kind
        self.reason = reason
        self.task_id = None   # set on the agent path once a task was enqueued


# ── Seams ────────────────────────────────────────────────────────────────

def _load_connection(domain):
    from webapp.models import NetSightConnection
    return NetSightConnection.query.filter_by(domain_id=domain.id).first()


def _resolve(host: str) -> str:
    return socket.gethostbyname(host)


def get_pool():
    from webapp.agents_manager import get_pool as _gp
    return _gp()


# ── Core ─────────────────────────────────────────────────────────────────

def _check_args(query: str, args: dict) -> dict:
    if query not in QUERIES:
        raise NetSightUnavailable("failed", f"query not allowed: {query!r}")
    args = dict(args or {})
    if query in ("device", "ports", "vlans"):
        ip = str(args.get("ip") or "").strip()
        try:
            args["ip"] = str(ipaddress.ip_address(ip))
        except ValueError:
            raise NetSightUnavailable("failed", f"invalid device IP {ip!r}")
    else:
        args.pop("ip", None)
    return args


def _run_local(conn, query: str, args: dict, timeout_s: int):
    client = NetSightClient(conn.host, conn.client_id, conn.client_secret, port=conn.port,
                            cert_sha256=conn.cert_sha256, timeout=min(int(timeout_s), 30))
    if query == "connect":
        return client.connect_check()
    if query == "devices":
        return client.devices()
    if query == "device":
        return client.device(args["ip"])
    if query == "ports":
        sys_name, ports = client.ports(args["ip"])
        return {"sysName": sys_name, "ports": ports}
    return client.vlans(args["ip"])


def _build_task(conn, agent_name: str, query: str, args: dict, timeout_s: int) -> dict:
    """The task payload — carries a one-shot `secret_ref`, NEVER the secret.
    The pool's validate_task hook (agent_secrets.validate_task_payload)
    refuses anything else at enqueue."""
    ref = issue_ref(conn.client_secret, agent_name=agent_name)
    return {
        "type": CAPABILITY,
        "host": conn.host,
        "port": int(conn.port or 8443),
        "cert_sha256": conn.cert_sha256,
        "client_id": conn.client_id,
        "secret_ref": ref,
        "query": query,
        "args": args,
        "timeout": int(timeout_s),
        "ttl": int(timeout_s) + 30,
    }


def _unavailable(kind, reason, task_id=None) -> NetSightUnavailable:
    exc = NetSightUnavailable(kind, reason)
    exc.task_id = task_id
    return exc


def _run_agent(conn, decision: RouteDecision, query: str, args: dict, timeout_s: int):
    pool = get_pool()
    task = _build_task(conn, decision.agent_name, query, args, timeout_s)
    try:
        task_id = pool.enqueue(decision.agent_name, task)
    except (KeyError, ValueError) as exc:
        raise _unavailable("failed", f"could not enqueue on agent "
                                     f"{decision.agent_name}: {exc}")
    res = pool.wait_result(task_id, int(timeout_s) + 10)
    if res is None:
        raise _unavailable("timeout", f"agent {decision.agent_name} did not answer within "
                                      f"{int(timeout_s) + 10}s (task {task_id})", task_id)
    if not res.get("ok"):
        raise _unavailable("failed", f"agent {decision.agent_name}: "
                                     f"{res.get('error') or 'unknown error'}", task_id)
    try:
        return json.loads(res.get("content") or "null"), task_id
    except ValueError as exc:
        raise _unavailable("failed", f"agent {decision.agent_name} returned "
                                     f"unparsable content: {exc}", task_id)


def run_query_detailed(domain, query: str, args: Optional[dict] = None, *,
                       timeout_s: int = 60) -> Tuple[Any, RouteDecision]:
    """Run one allow-listed NetSight query for `domain`; returns
    `(data, decision)` so callers can tell the operator where it ran.
    Raises NetSightUnavailable."""
    args = _check_args(query, args)
    conn = _load_connection(domain)
    if conn is None:
        raise NetSightUnavailable(
            "no_connection", "no NetSight connection configured for this Domain")
    try:
        ip = _resolve(conn.host)
    except OSError as exc:
        raise NetSightUnavailable("failed", f"cannot resolve {conn.host}: {exc}")

    decision = pick_executor(domain, [ip], CAPABILITY)
    target = f"{query} {args}" if args else query
    started = time.monotonic()
    task_id = None
    try:
        if decision.kind == "refused":
            raise NetSightUnavailable("refused", decision.reason)
        if decision.kind == "agent":
            try:
                data, task_id = _run_agent(conn, decision, query, args, timeout_s)
            except NetSightUnavailable as exc:
                task_id = getattr(exc, "task_id", None)
                raise
        else:
            try:
                data = _run_local(conn, query, args, timeout_s)
            except NetSightError as exc:
                raise NetSightUnavailable("failed", str(exc)[:500])
    except NetSightUnavailable as exc:
        _audit_query(target, decision, started, "error", exc.reason, task_id, domain)
        if query == "connect":
            _note_connect(conn, ok=False, error=exc.reason)
        raise
    _audit_query(target, decision, started, "ok", "", task_id, domain)
    if query == "connect":
        ok = bool(isinstance(data, dict) and data.get("ok"))
        _note_connect(conn, ok=ok, error="" if ok else str((data or {}).get("error") or ""))
    return data, decision


def run_query(domain, query: str, args: Optional[dict] = None, *, timeout_s: int = 60):
    data, _ = run_query_detailed(domain, query, args, timeout_s=timeout_s)
    return data


def _where(decision: RouteDecision) -> str:
    return f"agent:{decision.agent_name}" if decision.kind == "agent" else decision.kind


def _audit_query(target, decision, started, status, err, task_id, domain):
    elapsed = int((time.monotonic() - started) * 1000)
    detail = f"{_where(decision)} {elapsed}ms"
    if err:
        detail += f" — {err}"
    try:
        audit("netsight", "query", target=target, detail=detail[:480], status=status,
              source_correlation_id=task_id, domain_id=getattr(domain, "id", None))
    except Exception:  # noqa: BLE001 — logging never breaks a read
        pass


def _note_connect(conn, *, ok: bool, error: str):
    """Best-effort last_ok_at / last_error on the connection row (connect
    probes only — not on every cached read)."""
    try:
        from datetime import datetime, timezone
        from shared.db import db
        if ok:
            conn.last_ok_at = datetime.now(timezone.utc).replace(tzinfo=None)
            conn.last_error = ""
        else:
            conn.last_error = (error or "")[:2000]
        db.session.commit()
    except Exception:  # noqa: BLE001
        try:
            from shared.db import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass


# ── Cached accessors ─────────────────────────────────────────────────────

def netsight_devices(domain, *, refresh: bool = False):
    """All switches managed by the Domain's Site Engine. Section
    ``netsight.devices``, key ``(domain.id,)``, **Loose TTL** (inventory)."""
    cv = cache_get_or_fetch(
        section="netsight.devices", key_parts=(domain.id,),
        fetcher=lambda: run_query(domain, "devices"),
        ttl=get_loose_ttl(), refresh=refresh)
    return cv.data or [], cv


def netsight_device(domain, ip: str, *, refresh: bool = False):
    """One switch with `deviceData`. Section ``netsight.device``,
    key ``(domain.id, ip)``, Loose TTL."""
    cv = cache_get_or_fetch(
        section="netsight.device", key_parts=(domain.id, ip),
        fetcher=lambda: run_query(domain, "device", {"ip": ip}),
        ttl=get_loose_ttl(), refresh=refresh)
    return cv.data, cv


def netsight_ports(domain, ip: str, *, refresh: bool = False):
    """``{"sysName", "ports": [...]}`` for one switch (VLANs + LLDP
    neighbours). Section ``netsight.ports``, key ``(domain.id, ip)``,
    **Quick TTL** — port state changes under our feet."""
    cv = cache_get_or_fetch(
        section="netsight.ports", key_parts=(domain.id, ip),
        fetcher=lambda: run_query(domain, "ports", {"ip": ip}),
        ttl=get_quick_ttl(), refresh=refresh)
    return cv.data or {"sysName": "", "ports": []}, cv


def netsight_vlans(domain, ip: str, *, refresh: bool = False):
    """VLANs on one switch (raw Q-BRIDGE port masks — decode with
    ``shared.netsight_client.portlist_from_hex``). Section
    ``netsight.vlans``, key ``(domain.id, ip)``, Quick TTL."""
    cv = cache_get_or_fetch(
        section="netsight.vlans", key_parts=(domain.id, ip),
        fetcher=lambda: run_query(domain, "vlans", {"ip": ip}),
        ttl=get_quick_ttl(), refresh=refresh)
    return cv.data or [], cv


def invalidate_netsight(domain=None) -> int:
    """Drop every NetSight section (all Domains — the sections are small and
    per-key invalidation would need every ip seen). Call after the
    connection row changes or on `?refresh=1` of the Switches list."""
    n = 0
    for section in SECTIONS:
        n += invalidate(section)
    return n
