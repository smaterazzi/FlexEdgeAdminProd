"""FortiGate migration rule + NAT enqueue glue (Phase E.2).

Replaces the SMC-direct path in `smc_writer.create_rules` and
`smc_writer.create_nat_rules`. Each selected rule becomes one
`pending_changes` row; sections become their own rows; everything
shares ``source_correlation_id="migration:<project_id>"``.

Push order matters because rules reference objects (sources /
destinations / services / NAT hosts) that must already exist in SMC.
The natural created_at ordering handles this:

  1. Objects already enqueued by `migration_object_writer` (tier 1-5).
  2. Rule sections (this module, tier A).
  3. Firewall rules (this module, tier B).
  4. NAT rules (this module, tier C).

So the migration import route should run object enqueue FIRST, then
rule enqueue, then NAT enqueue. The push runner's halt-on-failure
stops the cascade if a member create fails so rules don't try to
push with unresolvable members.
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


def _enqueue(domain_id: int, operation: str, smc_type: str, payload: dict,
             correlation_id: str) -> PendingChange:
    """Single enqueue helper used by all three tiers below."""
    payload_with_type = dict(payload)
    payload_with_type["smc_type"] = smc_type
    change = PendingChange(
        domain_id=domain_id,
        user_id=_current_user_id(),
        smc_object_id=None,
        scope="main",
        operation=operation,
        payload_json=json.dumps(payload_with_type),
        feature_source="migration",
        source_correlation_id=correlation_id,
        state="queued",
    )
    db.session.add(change)
    db.session.flush()
    return change


def enqueue_rule_imports(converted_rules: dict, domain, project_id: int,
                         policy_name: str) -> dict:
    """Stage firewall rule sections + rules from a converted import.

    Sections enqueue first, rules in each section enqueue right after.
    The push order respects this because each rule's
    `created_at` is later than its section's.

    Returns a dict shaped like::

        {
          "entries":            [...log lines...],
          "sections_created":   int,    # = sections enqueued
          "rules_created":      int,    # = rules enqueued
          "rules_skipped":      int,    # not selected in dedup
          "rules_errors":       int,    # enqueue errors
          "changes_enqueued":   int,    # rule + section rows total
          "correlation_id":     str,
        }

    Mirrors `smc_writer.create_rules`'s return shape so the
    `migration_import` route can swap callers cleanly.
    """
    correlation_id = f"migration:{project_id}"
    out = {
        "entries": [],
        "sections_created": 0,
        "rules_created": 0,
        "rules_skipped": 0,
        "rules_errors": 0,
        "changes_enqueued": 0,
        "correlation_id": correlation_id,
    }

    if domain is None:
        out["entries"].append({"level": "error", "msg": (
            "Migration rule enqueue: no active Domain — cannot stage. "
            "Switch Domain via topbar and retry.")})
        return out

    sections = converted_rules.get("sections") or []
    if not sections:
        out["entries"].append({"level": "info",
                               "msg": "No rule sections to import."})
        return out

    domain_id = domain.id

    try:
        for section in sections:
            section_name = (section.get("name") or "").strip()
            if not section_name:
                continue

            # Section row first.
            try:
                ch_sec = _enqueue(
                    domain_id, "create_section", "rule_section",
                    {
                        "policy_name": policy_name,
                        "section_name": section_name,
                    },
                    correlation_id,
                )
                out["sections_created"] += 1
                out["changes_enqueued"] += 1
                out["entries"].append({"level": "info", "msg": (
                    f"  ✓ Queued section: {section_name} "
                    f"(change #{ch_sec.id})")})
            except Exception as exc:
                out["rules_errors"] += 1
                out["entries"].append({"level": "error", "msg": (
                    f"  ✗ section {section_name}: {exc}")})
                continue

            # Rule rows under this section.
            for rule in (section.get("rules") or []):
                if not rule.get("selected", False):
                    out["rules_skipped"] += 1
                    out["entries"].append({"level": "info", "msg": (
                        f"  − Skipped (not selected): "
                        f"{rule.get('name', '?')}")})
                    continue
                rule_name = (rule.get("name") or "").strip()
                if not rule_name:
                    continue
                try:
                    payload = {
                        "policy_name": policy_name,
                        "section_name": section_name,
                        "name": rule_name,
                        "sources": list(rule.get("sources") or ["any"]),
                        "destinations": list(rule.get("destinations") or ["any"]),
                        "services": list(rule.get("services") or ["any"]),
                        "action": rule.get("action") or "allow",
                        "is_disabled": bool(rule.get("is_disabled", False)),
                        "comment": rule.get("comment", "") or "",
                    }
                    ch = _enqueue(domain_id, "create", "rule", payload,
                                  correlation_id)
                    out["rules_created"] += 1
                    out["changes_enqueued"] += 1
                    out["entries"].append({"level": "info", "msg": (
                        f"  ✓ Queued rule: {rule_name} "
                        f"(change #{ch.id})")})
                except Exception as exc:
                    out["rules_errors"] += 1
                    out["entries"].append({"level": "error", "msg": (
                        f"  ✗ rule {rule_name}: {exc}")})

        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        out["entries"].append({"level": "error", "msg": (
            f"Rule enqueue aborted at top level: {exc}")})

    out["entries"].append({"level": "info", "msg": (
        f"Rule migration staged — "
        f"sections={out['sections_created']} rules={out['rules_created']} "
        f"skipped={out['rules_skipped']} errors={out['rules_errors']}. "
        f"Visit /changes/?source={correlation_id} to review + push.")})
    return out


def enqueue_nat_rule_imports(converted_rules: dict, dedup_results: dict,
                             domain, project_id: int,
                             policy_name: str) -> dict:
    """Stage NAT rules from a converted import.

    Pre-resolves the `nat_host_map` (IP → SMC Host name) at enqueue
    time using `dedup_results` and writes the resolved name into the
    payload. The handler then only resolves names against SMC at
    push time — it never sees raw IPs that aren't already mapped.

    Returns a dict mirroring `smc_writer.create_nat_rules`::

        {
          "entries":          [...log lines...],
          "nat_created":      int,    # = nat rules enqueued
          "nat_skipped":      int,
          "nat_errors":       int,
          "changes_enqueued": int,
          "correlation_id":   str,
        }
    """
    correlation_id = f"migration:{project_id}"
    out = {
        "entries": [],
        "nat_created": 0,
        "nat_skipped": 0,
        "nat_errors": 0,
        "changes_enqueued": 0,
        "correlation_id": correlation_id,
    }

    if domain is None:
        out["entries"].append({"level": "error", "msg": (
            "NAT rule enqueue: no active Domain — cannot stage.")})
        return out

    nat_rules = converted_rules.get("nat_rules") or []
    if not nat_rules:
        out["entries"].append({"level": "info",
                               "msg": "No NAT rules to import."})
        return out

    # Build the IP → SMC name map exactly like the legacy writer.
    nat_host_map: dict[str, str] = {}
    for entry in dedup_results.get("nat_hosts", []):
        if entry.get("action") in ("reuse", "create"):
            ip = entry.get("ip", "")
            if ip:
                nat_host_map[ip] = entry["smc_name"]

    domain_id = domain.id

    try:
        for rule in nat_rules:
            if not rule.get("selected", False):
                out["nat_skipped"] += 1
                out["entries"].append({"level": "info", "msg": (
                    f"  − Skipped (not selected): {rule.get('name', '?')}")})
                continue
            rule_name = (rule.get("name") or "").strip()
            if not rule_name:
                continue

            try:
                nat_type = (rule.get("nat_type") or "").strip()

                # Pre-resolve SNAT/DNAT IPs → SMC Host names so the
                # handler only sees names. Raw IP fallback when
                # nat_host_map doesn't have a mapping (preserves the
                # legacy fallback semantics).
                snat_name = ""
                if nat_type in ("snat", "snat+dnat"):
                    raw = rule.get("dynamic_src_nat_ip", "") or ""
                    snat_name = nat_host_map.get(raw, raw)

                dnat_name = ""
                if nat_type in ("dnat", "snat+dnat"):
                    raw = rule.get("static_dst_nat", "") or ""
                    dnat_name = nat_host_map.get(raw, raw)

                ports = rule.get("static_dst_nat_ports")
                ports_payload = None
                if (ports and isinstance(ports, (list, tuple))
                        and len(ports) == 2 and ports[0] and ports[1]):
                    ports_payload = [ports[0], ports[1]]

                payload = {
                    "policy_name": policy_name,
                    "name": rule_name,
                    "sources": list(rule.get("sources") or ["any"]),
                    "destinations": list(rule.get("destinations") or ["any"]),
                    "services": list(rule.get("services") or ["any"]),
                    "is_disabled": bool(rule.get("is_disabled", False)),
                    "comment": rule.get("comment", "") or "",
                    "nat_type": nat_type,
                    "dynamic_src_nat_name": snat_name,
                    "static_dst_nat_name": dnat_name,
                    "static_dst_nat_ports": ports_payload,
                }
                ch = _enqueue(domain_id, "create", "nat_rule", payload,
                              correlation_id)
                out["nat_created"] += 1
                out["changes_enqueued"] += 1
                out["entries"].append({"level": "info", "msg": (
                    f"  ✓ Queued NAT rule [{nat_type}]: {rule_name} "
                    f"(change #{ch.id})")})
            except Exception as exc:
                out["nat_errors"] += 1
                out["entries"].append({"level": "error", "msg": (
                    f"  ✗ NAT rule {rule_name}: {exc}")})

        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        out["entries"].append({"level": "error", "msg": (
            f"NAT rule enqueue aborted at top level: {exc}")})

    out["entries"].append({"level": "info", "msg": (
        f"NAT migration staged — created={out['nat_created']} "
        f"skipped={out['nat_skipped']} errors={out['nat_errors']}. "
        f"Visit /changes/?source={correlation_id} to review + push.")})
    return out
