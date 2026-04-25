"""
Rule Optimizer — deterministic analysis of SMC firewall policies.

Pure input/output: takes the name-resolved rule list produced by
``smc_client.get_policy_rules()`` and returns a list of findings.
No network I/O, no Flask — easy to unit-test.

Phase 1 checks:
    - exact_duplicate         safe_auto — byte-identical rules
    - shadowed_same_action    safe_auto — earlier rule's set fully covers a
                                          later rule with the same action

Rules are identified by a human-readable position string ``"{section}.{row}"``
matching what the SMC Management Client displays. The SMC internal ``tag``
is carried alongside for deep-linking.

Limitations (addressed in Phase 2):
    - Subsumption is compared by resolved element name, not by expanded
      IP ranges. A host ``10.0.0.1`` inside a group ``WebServers`` will
      not be detected as subsumed by ``WebServers``.
    - Disabled rules are surfaced separately (``disabled_rules``) but not
      analyzed for duplicates/shadows.
    - Rules with action ``continue`` (logging/context modifiers) are
      skipped entirely — they don't make a match decision so duplicate
      detection isn't meaningful.
"""

from __future__ import annotations

from typing import Iterable


ANY_TOKEN = "any"
SKIP_ACTIONS = {"continue"}  # not a match decision — skip entirely


# ── Position assignment ──────────────────────────────────────────────────

def assign_positions(rules: list[dict]) -> tuple[list[dict], list[dict]]:
    """Walk the rule list, assign a ``pos`` string like "2.5" to each
    rule, and split into (active, disabled).

    "continue" rules and section headers are dropped entirely — they
    don't carry a match decision, so duplicate detection is meaningless.

    Each returned rule dict gains:
        pos              "{section_idx}.{row_in_section}"  — 1-based
        section_idx      int
        row_idx          int
        section_name     str  — name of the enclosing section (or "")
    """
    active: list[dict] = []
    disabled: list[dict] = []
    section_idx = 0  # becomes 1 on the first real section header
    section_name = ""
    row_idx = 0
    saw_any_section = False

    for r in rules:
        if r.get("is_section"):
            section_idx += 1
            section_name = r.get("name", "") or ""
            row_idx = 0
            saw_any_section = True
            continue

        action = (r.get("action") or "").strip().lower()
        if action in SKIP_ACTIONS:
            continue

        # Rules before any explicit section get section 0
        effective_section = section_idx if saw_any_section else 0
        row_idx += 1

        enriched = dict(r)
        enriched["section_idx"] = effective_section
        enriched["row_idx"] = row_idx
        enriched["pos"] = f"{effective_section}.{row_idx}"
        enriched["section_name"] = section_name

        if r.get("is_disabled"):
            disabled.append(enriched)
        else:
            active.append(enriched)

    return active, disabled


# ── Rule normalization ───────────────────────────────────────────────────

def _as_frozenset(values: Iterable[str]) -> frozenset[str]:
    """Lower-case and collapse a list of element names to a frozenset.
    Empty input is treated as ``{"any"}`` to match SMC semantics.
    """
    cleaned = {v.strip().lower() for v in values if v and v.strip()}
    return frozenset(cleaned) if cleaned else frozenset({ANY_TOKEN})


def _dedup_key(rule: dict) -> tuple:
    """Return the identity tuple for exact-duplicate detection."""
    return (
        _as_frozenset(rule.get("sources", [])),
        _as_frozenset(rule.get("destinations", [])),
        _as_frozenset(rule.get("services", [])),
        (rule.get("action") or "").strip().lower(),
    )


def _is_superset(outer: frozenset, inner: frozenset) -> bool:
    """True if ``outer`` covers every element in ``inner``.

    ``any`` on the outer side covers anything on the inner side.
    ``any`` on the inner side is only covered when the outer also has ``any``.
    """
    if ANY_TOKEN in outer:
        return True
    if ANY_TOKEN in inner:
        return False
    return inner.issubset(outer)


# ── Finding construction ─────────────────────────────────────────────────

def _snippet(rule: dict) -> dict:
    """A small, serializable view of a rule for rendering."""
    return {
        "pos": rule["pos"],
        "name": rule.get("name") or "",
        "action": rule.get("action") or "",
        "sources": rule.get("sources", []),
        "destinations": rule.get("destinations", []),
        "services": rule.get("services", []),
        "comment": rule.get("comment", ""),
        "tag": rule.get("tag", ""),
        "section_name": rule.get("section_name", ""),
    }


def _make_finding(fid: str, kind: str, severity: str,
                  primary: dict, redundant: list[dict],
                  rationale: str) -> dict:
    snippets = [_snippet(primary)] + [_snippet(r) for r in redundant]
    return {
        "id": fid,
        "kind": kind,
        "severity": severity,
        "primary_pos": primary["pos"],
        "redundant_pos": [r["pos"] for r in redundant],
        "rule_snippets": snippets,
        "rationale": rationale,
        # Filled in later by admin review:
        "decision": None,
        "decision_note": "",
    }


# ── Check: exact duplicates ──────────────────────────────────────────────

def find_exact_duplicates(rules: list[dict], next_id: int = 1) -> tuple[list[dict], int]:
    """Group rules with an identical (src, dst, svc, action) key.

    Rule order is preserved: the earliest rule in each group is the primary
    (kept); the rest are redundant (dead).
    """
    groups: dict[tuple, list[dict]] = {}
    for r in rules:
        groups.setdefault(_dedup_key(r), []).append(r)

    findings: list[dict] = []
    for _, group in groups.items():
        if len(group) < 2:
            continue
        primary, *rest = group
        rationale = (
            f"Rule {primary['pos']} is byte-identical to "
            f"{len(rest)} later rule(s): "
            f"{', '.join(r['pos'] for r in rest)}. "
            "The later rule(s) never match and can be removed."
        )
        findings.append(_make_finding(
            fid=f"F{next_id:03d}",
            kind="exact_duplicate",
            severity="safe_auto",
            primary=primary,
            redundant=rest,
            rationale=rationale,
        ))
        next_id += 1

    return findings, next_id


# ── Check: shadowed same-action rules ────────────────────────────────────

def find_shadows(rules: list[dict], next_id: int = 1,
                 skip_pos: set[str] | None = None) -> tuple[list[dict], int]:
    """Flag rule pairs ``(i, j)`` where ``i < j``, same action, and
    ``i``'s sources/destinations/services each cover ``j``'s.

    ``skip_pos`` — positions already flagged as exact duplicates; excluded
    to avoid double-reporting the same rule pair.
    """
    skip_pos = skip_pos or set()
    findings: list[dict] = []

    active = [r for r in rules if r["pos"] not in skip_pos]

    for i, outer in enumerate(active):
        outer_src = _as_frozenset(outer.get("sources", []))
        outer_dst = _as_frozenset(outer.get("destinations", []))
        outer_svc = _as_frozenset(outer.get("services", []))
        outer_act = (outer.get("action") or "").strip().lower()

        shadowed: list[dict] = []
        for inner in active[i + 1:]:
            if inner["pos"] in skip_pos:
                continue
            if (inner.get("action") or "").strip().lower() != outer_act:
                continue

            inner_src = _as_frozenset(inner.get("sources", []))
            inner_dst = _as_frozenset(inner.get("destinations", []))
            inner_svc = _as_frozenset(inner.get("services", []))

            # Exact match is reported by find_exact_duplicates, skip here.
            if (inner_src == outer_src
                    and inner_dst == outer_dst
                    and inner_svc == outer_svc):
                continue

            if (_is_superset(outer_src, inner_src)
                    and _is_superset(outer_dst, inner_dst)
                    and _is_superset(outer_svc, inner_svc)):
                shadowed.append(inner)

        if not shadowed:
            continue

        rationale = (
            f"Rule {outer['pos']} ({outer_act}) covers "
            f"{len(shadowed)} later rule(s) with the same action: "
            f"{', '.join(r['pos'] for r in shadowed)}. "
            "The later rule(s) never match."
        )
        findings.append(_make_finding(
            fid=f"F{next_id:03d}",
            kind="shadowed_same_action",
            severity="safe_auto",
            primary=outer,
            redundant=shadowed,
            rationale=rationale,
        ))
        next_id += 1

    return findings, next_id


# ── Public entry point ───────────────────────────────────────────────────

def analyze_rules(policy_name: str, raw_rules: list[dict]) -> dict:
    """Run all Phase 1 checks against a policy's rule list.

    Args:
        policy_name: Name of the policy being analyzed (echoed back).
        raw_rules:   Output of ``smc_client.get_policy_rules(policy_name)``.

    Returns:
        {
            "policy":          str,
            "rule_count":      int,   # active rules analyzed
            "disabled_count":  int,
            "findings":        list[dict],
            "disabled_rules":  list[dict],   # snippet view for display
            "summary": {
                "exact_duplicate":       int,
                "shadowed_same_action":  int,
            },
        }
    """
    active, disabled = assign_positions(raw_rules)

    exact_findings, next_id = find_exact_duplicates(active, next_id=1)

    # Exclude rules already flagged as exact duplicates from shadow analysis.
    already_flagged: set[str] = set()
    for f in exact_findings:
        already_flagged.update(f["redundant_pos"])

    shadow_findings, _ = find_shadows(active, next_id=next_id,
                                      skip_pos=already_flagged)

    findings = exact_findings + shadow_findings

    return {
        "policy": policy_name,
        "rule_count": len(active),
        "disabled_count": len(disabled),
        "findings": findings,
        "disabled_rules": [_snippet(r) for r in disabled],
        "summary": {
            "exact_duplicate": len(exact_findings),
            "shadowed_same_action": len(shadow_findings),
        },
    }
