"""FortiGate migration object enqueue glue (Phase E.2).

Replaces the SMC-direct path in `smc_writer.create_objects` for object
creation (host / network / address_range / fqdn / tcp_service /
udp_service / group / service_group / NAT host).

Each selected object becomes one `pending_changes` row, all sharing
``source_correlation_id="migration:<project_id>"`` so the operator
sees the whole batch grouped on `/changes/?source=migration:<id>`.

Enqueue order matters because the queue runner pushes in
`(scheduled_after, created_at)` order and group creation needs its
member SMC elements to already exist:

  1. Addresses (host / network / address_range / fqdn)
  2. Services (tcp / udp)
  3. Address groups
  4. Service groups
  5. NAT hosts

Within each tier the order doesn't matter — there are no cross-row
dependencies inside a tier. ``halt-on-failure`` in `push_batch` stops
the cascade if a member create fails so groups don't try to push with
unresolvable members.

Rules and NAT rules are NOT yet enqueued — they need the policy +
section + position model (Q9). Deferred to a focused follow-up.
"""

import json
import logging
from typing import Optional

from shared.db import db
from webapp.models import PendingChange, User

log = logging.getLogger(__name__)


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


def _enqueue(domain_id: int, smc_type: str, payload: dict,
             correlation_id: str) -> PendingChange:
    payload_with_type = dict(payload)
    payload_with_type["smc_type"] = smc_type
    change = PendingChange(
        domain_id=domain_id,
        user_id=_current_user_id(),
        smc_object_id=None,
        scope="main",
        operation="create",
        payload_json=json.dumps(payload_with_type),
        feature_source="migration",
        source_correlation_id=correlation_id,
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    return change


def enqueue_object_imports(parsed_objects: dict, dedup_results: dict,
                           domain, project_id: int) -> dict:
    """Stage all selected objects from a FortiGate import as queue rows.

    Args:
      parsed_objects: Output of `fgt_parser.parse_fortigate_config()`.
      dedup_results:  Output of `dedup_engine.run_dedup()`. Each section
                      ('addresses' / 'services' / etc.) has per-row
                      action='create'|'reuse'|'skip'.
      domain:         The active Domain (provides domain_id for
                      `pending_changes.domain_id`).
      project_id:     Migration project id, used for both
                      `source_correlation_id` and traceability.

    Returns a dict::

        {
          "entries":           [...log lines...],
          "objects_created":   int (= changes_enqueued),
          "objects_skipped":   int,
          "objects_errors":    int,
          "changes_enqueued":  int,
          "correlation_id":    str ("migration:<project_id>"),
          "by_type":           {host: N, network: N, ...},
        }

    The shape mirrors the legacy `smc_writer.create_objects` so the
    `migration_import` route can swap callers cleanly.
    """
    correlation_id = f"migration:{project_id}"
    out = {
        "entries": [],
        "objects_created": 0,
        "objects_skipped": 0,
        "objects_errors": 0,
        "changes_enqueued": 0,
        "correlation_id": correlation_id,
        "by_type": {},
    }

    if domain is None:
        out["entries"].append({"level": "error", "msg": (
            "Migration object enqueue: no active Domain — cannot stage. "
            "Switch Domain via topbar and retry.")})
        return out

    domain_id = domain.id

    addr_by_name = {a["name"]: a for a in parsed_objects.get("addresses", [])}
    svc_by_name = {s["name"]: s for s in parsed_objects.get("services", [])}
    addr_grp_by_name = {g["name"]: g for g in parsed_objects.get("address_groups", [])}
    svc_grp_by_name = {g["name"]: g for g in parsed_objects.get("service_groups", [])}

    # Resolve dedup parsed_name → SMC name for groups.
    addr_name_map = {
        e["parsed_name"]: e["smc_name"]
        for e in dedup_results.get("addresses", [])
        if e.get("action") in ("reuse", "create")
    }
    svc_name_map = {
        e["parsed_name"]: e["smc_name"]
        for e in dedup_results.get("services", [])
        if e.get("action") in ("reuse", "create")
    }

    def _bump(smc_type: str):
        out["objects_created"] += 1
        out["changes_enqueued"] += 1
        out["by_type"][smc_type] = out["by_type"].get(smc_type, 0) + 1

    try:
        # ── Tier 1: Addresses ──
        out["entries"].append({"level": "info",
                               "msg": "--- Queueing addresses ---"})
        for entry in dedup_results.get("addresses", []):
            if entry.get("action") != "create":
                continue
            parsed = addr_by_name.get(entry["parsed_name"])
            if not parsed:
                out["objects_skipped"] += 1
                continue
            smc_name = entry["smc_name"]
            addr_type = parsed.get("type", "")
            comment = parsed.get("comment", "") or ""

            try:
                if addr_type == "host":
                    ch = _enqueue(domain_id, "host", {
                        "name": smc_name,
                        "address": parsed.get("ip", ""),
                        "comment": comment,
                    }, correlation_id)
                    _bump("host")
                elif addr_type == "subnet":
                    cidr = parsed.get("cidr", 24)
                    ch = _enqueue(domain_id, "network", {
                        "name": smc_name,
                        "ipv4_network": f"{parsed.get('subnet', '')}/{cidr}",
                        "comment": comment,
                    }, correlation_id)
                    _bump("network")
                elif addr_type == "iprange":
                    ch = _enqueue(domain_id, "address_range", {
                        "name": smc_name,
                        "ip_range": (f"{parsed.get('start_ip', '')}-"
                                     f"{parsed.get('end_ip', '')}"),
                        "comment": comment,
                    }, correlation_id)
                    _bump("address_range")
                elif addr_type == "fqdn":
                    ch = _enqueue(domain_id, "fqdn", {
                        "name": smc_name,
                        "value": parsed.get("fqdn", ""),
                        "comment": comment,
                    }, correlation_id)
                    _bump("fqdn")
                else:
                    out["objects_skipped"] += 1
                    out["entries"].append({"level": "warning", "msg": (
                        f"Unsupported address type {addr_type!r}: {smc_name}")})
                    continue
                out["entries"].append({"level": "info", "msg": (
                    f"  ✓ Queued {addr_type}: {smc_name} (change #{ch.id})")})
            except Exception as exc:
                out["objects_errors"] += 1
                out["entries"].append({"level": "error", "msg": (
                    f"  ✗ {smc_name}: enqueue failed — "
                    f"{type(exc).__name__}: {exc}")})

        # ── Tier 2: Services ──
        out["entries"].append({"level": "info",
                               "msg": "--- Queueing services ---"})
        for entry in dedup_results.get("services", []):
            if entry.get("action") != "create":
                continue
            parsed = svc_by_name.get(entry["parsed_name"])
            if not parsed:
                out["objects_skipped"] += 1
                continue
            smc_name = entry["smc_name"]
            protocol = parsed.get("protocol", "")
            comment = parsed.get("comment", "") or ""

            if protocol in ("TCP", "TCP/UDP"):
                for min_p, max_p in parsed.get("tcp_ports", []):
                    try:
                        ch = _enqueue(domain_id, "tcp_service", {
                            "name": smc_name,
                            "min_dst_port": int(min_p),
                            "max_dst_port": (int(max_p) if max_p is not None
                                             and int(max_p) != int(min_p)
                                             else None),
                            "comment": comment,
                        }, correlation_id)
                        _bump("tcp_service")
                        out["entries"].append({"level": "info", "msg": (
                            f"  ✓ Queued tcp_service: {smc_name} "
                            f"({min_p}-{max_p}) (change #{ch.id})")})
                    except Exception as exc:
                        out["objects_errors"] += 1
                        out["entries"].append({"level": "error", "msg": (
                            f"  ✗ tcp_service {smc_name}: {exc}")})

            if protocol in ("UDP", "TCP/UDP"):
                for min_p, max_p in parsed.get("udp_ports", []):
                    try:
                        ch = _enqueue(domain_id, "udp_service", {
                            "name": smc_name,
                            "min_dst_port": int(min_p),
                            "max_dst_port": (int(max_p) if max_p is not None
                                             and int(max_p) != int(min_p)
                                             else None),
                            "comment": comment,
                        }, correlation_id)
                        _bump("udp_service")
                        out["entries"].append({"level": "info", "msg": (
                            f"  ✓ Queued udp_service: {smc_name} "
                            f"({min_p}-{max_p}) (change #{ch.id})")})
                    except Exception as exc:
                        out["objects_errors"] += 1
                        out["entries"].append({"level": "error", "msg": (
                            f"  ✗ udp_service {smc_name}: {exc}")})

        # ── Tier 3: Address groups ──
        out["entries"].append({"level": "info",
                               "msg": "--- Queueing address groups ---"})
        for entry in dedup_results.get("address_groups", []):
            if entry.get("action") != "create":
                continue
            parsed = addr_grp_by_name.get(entry["parsed_name"])
            if not parsed:
                out["objects_skipped"] += 1
                continue
            smc_name = entry["smc_name"]
            members = [addr_name_map.get(m, m)
                       for m in (parsed.get("members") or [])]
            try:
                ch = _enqueue(domain_id, "group", {
                    "name": smc_name,
                    "member_names": members,
                    "comment": parsed.get("comment", "") or "",
                }, correlation_id)
                _bump("group")
                out["entries"].append({"level": "info", "msg": (
                    f"  ✓ Queued group: {smc_name} ({len(members)} members) "
                    f"(change #{ch.id})")})
            except Exception as exc:
                out["objects_errors"] += 1
                out["entries"].append({"level": "error", "msg": (
                    f"  ✗ group {smc_name}: {exc}")})

        # ── Tier 4: Service groups ──
        out["entries"].append({"level": "info",
                               "msg": "--- Queueing service groups ---"})
        for entry in dedup_results.get("service_groups", []):
            if entry.get("action") != "create":
                continue
            parsed = svc_grp_by_name.get(entry["parsed_name"])
            if not parsed:
                out["objects_skipped"] += 1
                continue
            smc_name = entry["smc_name"]
            members = [svc_name_map.get(m, m)
                       for m in (parsed.get("members") or [])]
            try:
                ch = _enqueue(domain_id, "service_group", {
                    "name": smc_name,
                    "member_names": members,
                    "comment": parsed.get("comment", "") or "",
                }, correlation_id)
                _bump("service_group")
                out["entries"].append({"level": "info", "msg": (
                    f"  ✓ Queued service_group: {smc_name} "
                    f"({len(members)} members) (change #{ch.id})")})
            except Exception as exc:
                out["objects_errors"] += 1
                out["entries"].append({"level": "error", "msg": (
                    f"  ✗ service_group {smc_name}: {exc}")})

        # ── Tier 5: NAT hosts ──
        # NAT hosts are plain Host elements created from NAT rule IPs
        # that don't already exist as named addresses.
        out["entries"].append({"level": "info",
                               "msg": "--- Queueing NAT hosts ---"})
        for entry in dedup_results.get("nat_hosts", []):
            if entry.get("action") != "create":
                if entry.get("smc_name"):
                    out["entries"].append({"level": "info", "msg": (
                        f"Reusing existing host for NAT IP "
                        f"{entry.get('ip', '?')}: {entry['smc_name']}")})
                continue
            try:
                ch = _enqueue(domain_id, "host", {
                    "name": entry["smc_name"],
                    "address": entry["ip"],
                    "comment": (f"NAT address ({entry.get('purpose', '')}) "
                                f"from {entry.get('source_name', '?')}"),
                }, correlation_id)
                _bump("host")
                out["entries"].append({"level": "info", "msg": (
                    f"  ✓ Queued NAT host: {entry['smc_name']} "
                    f"({entry['ip']}) (change #{ch.id})")})
            except Exception as exc:
                out["objects_errors"] += 1
                out["entries"].append({"level": "error", "msg": (
                    f"  ✗ NAT host {entry.get('smc_name', '?')}: {exc}")})

        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        out["entries"].append({"level": "error", "msg": (
            f"Object enqueue aborted at top level: {exc}")})
        # Don't reset the counters — partial work might already have
        # committed in earlier flushes. The summary tells the truth.

    out["entries"].append({"level": "info", "msg": (
        f"Migration objects staged — enqueued={out['changes_enqueued']} "
        f"skipped={out['objects_skipped']} errors={out['objects_errors']}. "
        f"Visit /changes/?source={correlation_id} to review + push.")})
    return out
