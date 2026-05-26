"""Glob-based allowlist matcher for Let's Encrypt cert requests.

Roadmap item 5 / Phase LE.1 (2026-05-11). Q6 + Q6a + Q6b locked the
following model:

  * Each FEA Domain has its own list of allowed cert patterns (rows in
    `domain_cert_patterns`).
  * Patterns are glob expressions; matching is via `fnmatch.fnmatchcase`
    so the operator's mental model is standard shell globbing
    (`*` matches any sequence, `?` matches a single char, brackets
    enumerate alternatives).
  * A request is allowed iff the requested FQDN matches at least one
    pattern. Domains with NO patterns can request NOTHING (safe default).
  * Domain Admin self-service — any Domain Admin can edit their
    Domain's allowlist via `/admin/domains/<id>/edit`.

This module is pure (no Flask context, no DB writes) so the queue
handler can call it from a worker thread without app-context plumbing.
"""

from __future__ import annotations

import fnmatch
import re


# Valid pattern: lowercase ASCII, digits, `*`, `?`, `.`, `-`, brackets.
# We DON'T allow `/` (no path components) or whitespace. This catches
# operator typos before they reach fnmatch.
_VALID_PATTERN_RE = re.compile(r"^[a-z0-9*?.\[\]\-]+$")


def is_valid_pattern(pattern: str) -> tuple[bool, str]:
    """Validate a single pattern. Returns (ok, reason).

    Rules:
      * Must be lowercase.
      * Must contain at least one `.` (a single label like `*` would
        match anything, including LE rate-limit-burning typos).
      * No `/`, no whitespace.
      * Must compile under `fnmatch.translate` without error.
      * Bare `*` and bare `*.*` are refused — too permissive.
    """
    if not pattern:
        return False, "pattern is empty"
    if pattern != pattern.lower():
        return False, "pattern must be lowercase"
    if "/" in pattern or " " in pattern or "\t" in pattern:
        return False, "pattern must not contain whitespace or `/`"
    if not _VALID_PATTERN_RE.match(pattern):
        return False, ("pattern may only contain lowercase letters, digits, "
                       "`.`, `-`, `*`, `?`, and `[…]` brackets")
    if "." not in pattern:
        return False, "pattern must contain at least one `.` (single labels are too permissive)"
    if pattern in ("*", "*.*", "*.com", "*.net", "*.org"):
        return False, f"pattern {pattern!r} is too permissive (would match many TLDs)"
    try:
        fnmatch.translate(pattern)
    except Exception as exc:
        return False, f"pattern doesn't compile: {exc}"
    return True, ""


def normalize_fqdn(fqdn: str) -> str:
    """Lowercase + strip leading/trailing whitespace + trailing dots."""
    return (fqdn or "").strip().rstrip(".").lower()


def matches_any_pattern(fqdn: str, patterns: list[str]) -> tuple[bool, str]:
    """Return (matched, matching_pattern). False/empty when no match."""
    target = normalize_fqdn(fqdn)
    if not target:
        return False, ""
    for raw in patterns:
        pat = normalize_fqdn(raw)
        if not pat:
            continue
        if fnmatch.fnmatchcase(target, pat):
            return True, pat
    return False, ""


def patterns_for_domain(domain_id: int) -> list[str]:
    """Return the raw pattern strings for a FEA Domain id."""
    # Deferred import — keeps the pure helpers importable in unit tests
    # without dragging in SQLAlchemy.
    from webapp.models import DomainCertPattern
    rows = (DomainCertPattern.query
            .filter_by(domain_id=domain_id)
            .order_by(DomainCertPattern.pattern.asc())
            .all())
    return [r.pattern for r in rows]


def is_fqdn_allowed_for_domain(fqdn: str, domain_id: int) -> tuple[bool, str]:
    """High-level helper: does `fqdn` match any pattern on this Domain?

    Returns (allowed, reason_or_pattern). When allowed=True, reason is
    the matching pattern (for audit). When allowed=False, reason is a
    short human-readable explanation:
      * "no patterns configured" — Domain Admin hasn't authorised anything
      * "no pattern matched" — patterns exist but none match the FQDN
    """
    target = normalize_fqdn(fqdn)
    if not target:
        return False, "fqdn is empty"
    pats = patterns_for_domain(domain_id)
    if not pats:
        return False, ("no patterns configured for this Domain "
                       "(Domain Admin must add at least one via "
                       "Admin Portal → Domains → Edit)")
    ok, matched = matches_any_pattern(target, pats)
    if ok:
        return True, matched
    return False, "no pattern matched"
