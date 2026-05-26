"""SMC element comment audit marker (Q21 Round 3 feature request).

Every successful FEA write to an SMC element appends/replaces a
machine-readable audit marker in the element's `comment` field, so
operators can see *who* changed *what* directly in SMC Management
Client without round-tripping through FEA's Logs page.

Marker shape::

    [flexedge:audit ts=2026-05-01T10:32:00Z user=simone@enable.work prev="<=20 chars>"]

* `ts` — UTC ISO-8601 second-precision.
* `user` — email of the user who triggered the change (resolved from
  the Flask session when in a request context; `system` otherwise).
* `prev` — the *changed* field's previous value, truncated to 20
  characters with a trailing `…` if truncated. Quoted; embedded
  quotes escaped via `\\"`. May be omitted on `create` (no prior value).

Idempotent — a previous marker is replaced, not appended. The user-
authored portion of the comment is preserved across writes. Coexists
with the `[flexedge:mac=...]` marker used by DHCP reservations:
unpacking strips both markers; packing re-attaches them in known order.

Public API
----------

  pack_audit_into_comment(user_comment, *, user_email=None,
                          previous_value=None) -> str
    Return a comment string with a fresh audit marker.

  unpack_audit_from_comment(comment) -> (clean_comment, AuditInfo|None)
    Strip the marker; return the user-authored remainder + parsed info.

The MAC marker (`[flexedge:mac=...]`) is intentionally separate — both
markers can coexist in one comment. `pack_mac_into_comment` and
`pack_audit_into_comment` are commutative as long as each preserves
unrelated markers via the `_strip_markers` regex.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

# Marker pattern: matches `[flexedge:audit ts=... user=... prev="..."]`
# on its own line OR inline. Tolerates extra whitespace.
_AUDIT_MARKER_RE = re.compile(
    r"\[\s*flexedge:audit\s+"
    r"ts=(?P<ts>[^\s\]]+)"
    r"(?:\s+user=(?P<user>[^\s\]]+))?"
    r"(?:\s+prev=\"(?P<prev>(?:[^\"\\]|\\.)*)\")?"
    r"\s*\]",
    re.IGNORECASE,
)

_PREV_MAX = 20


@dataclass
class AuditInfo:
    timestamp: str = ""
    user_email: str = ""
    previous_value: str = ""


def _resolve_user_email(explicit: Optional[str]) -> str:
    """Pick the user email — explicit arg first, then the Flask session."""
    if explicit:
        return explicit.strip()
    try:
        from flask import session, has_request_context
        if has_request_context():
            user = session.get("user") or {}
            email = (user.get("email") or "").strip()
            if email:
                return email
    except Exception:
        pass
    return "system"


def _truncate_prev(value: Optional[str]) -> str:
    """Truncate prev to <= _PREV_MAX chars; add a trailing ellipsis if cut."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= _PREV_MAX:
        return s
    # 19 chars + ellipsis = 20.
    return s[:_PREV_MAX - 1] + "…"


_USER_EMAIL_MAX = 256  # RFC 5321 §4.5.3.1.3 caps mailbox at 254


def _sanitize_user_email(value: str) -> str:
    """Strip terminator chars and length-cap the audit-marker `user=` field.

    M5 (audit fix-up, 2026-05-09). The marker grammar requires `user=`
    to terminate at whitespace or `]`. An email containing either
    would break the marker structure and let a forged-email attacker
    plant fake `[flexedge:audit …]` markers in adjacent comment text.
    We strip those characters defensively, drop control chars, and cap
    at 256 (one past the RFC 5321 mailbox limit).

    Returns "system" on empty / sanitised-to-empty input — same fallback
    as `_resolve_user_email`.
    """
    if not value:
        return "system"
    s = str(value).strip()
    # Remove characters that would prematurely terminate the marker
    # field or inject sibling key=value pairs into the marker.
    cleaned = s.translate(str.maketrans("", "", " \t\r\n]"))
    if not cleaned:
        return "system"
    return cleaned[:_USER_EMAIL_MAX]


def _escape_for_marker(value: str) -> str:
    """Escape backslashes + double-quotes so the marker stays parseable."""
    return value.replace("\\", "\\\\").replace("\"", "\\\"")


def _strip_audit_marker(comment: str) -> str:
    """Remove every `[flexedge:audit ...]` block. Preserves other content."""
    if not comment:
        return ""
    cleaned = _AUDIT_MARKER_RE.sub("", comment)
    # Collapse double-blank lines created by stripping a marker that was
    # alone on its own line.
    cleaned = re.sub(r"\n\s*\n\s*\n", "\n\n", cleaned)
    return cleaned.strip("\n").rstrip()


def pack_audit_into_comment(user_comment: str = "",
                            *,
                            user_email: Optional[str] = None,
                            previous_value: Optional[str] = None,
                            timestamp: Optional[datetime] = None) -> str:
    """Return a comment with a fresh audit marker, preserving user content.

    `user_comment` may already contain a previous marker; it's stripped
    and replaced (idempotent).

    `previous_value` is optional — omitted from the marker on `create`
    operations where no prior value exists.
    """
    base = _strip_audit_marker(user_comment or "")
    ts = (timestamp or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    user = _sanitize_user_email(_resolve_user_email(user_email))
    parts = [f"ts={ts}", f"user={user}"]
    if previous_value is not None and previous_value != "":
        prev = _escape_for_marker(_truncate_prev(previous_value))
        parts.append(f'prev="{prev}"')
    marker = f"[flexedge:audit {' '.join(parts)}]"
    if base:
        return f"{base}\n{marker}"
    return marker


def unpack_audit_from_comment(comment: str) -> tuple[str, Optional[AuditInfo]]:
    """Parse the most-recent audit marker; return (clean_comment, info).

    Returns `(comment_without_marker, None)` when no marker is present.
    When multiple markers exist (defensive), returns the *last* one's
    parse — the most recent write wins.
    """
    if not comment:
        return ("", None)
    matches = list(_AUDIT_MARKER_RE.finditer(comment))
    if not matches:
        return (comment, None)
    last = matches[-1]
    info = AuditInfo(
        timestamp=last.group("ts") or "",
        user_email=last.group("user") or "",
        previous_value=(last.group("prev") or "").replace("\\\"", "\"")
                                                  .replace("\\\\", "\\"),
    )
    return (_strip_audit_marker(comment), info)
