"""
FlexEdgeAdmin — one-shot secret references for remote-agent tasks (RA-B).

Decision 1 in docs/RemoteAgents.md: a task carries `secret_ref`, never the
secret. The Portal issues a ref when it enqueues the task; the agent redeems
it exactly once via `GET /agent/secret?ref=…` with its agent key + device
fingerprint; the ref expires after REF_TTL_S and is never persisted — the
pool's restart mirror (agent_pool_state.json) only ever sees the ref string,
which is useless once redeemed or expired.

Stdlib only, framework-free (same contract as shared/agent_routes.py) so it
runs under `make test-agents` without Flask.
"""

import logging
import secrets
import threading
import time

from shared import agent_routes

REF_TTL_S = 60.0
REF_PREFIX = "sr_"

# Key names that must never appear in a task payload (case-insensitive,
# "-" folded to "_"). `secret_ref` itself is the sanctioned carrier.
SECRET_KEY_NAMES = frozenset({
    "secret", "password", "passwd", "client_secret", "token",
    "api_key", "apikey", "private_key",
})

# Values with these prefixes are the pool's own credentials (agent key /
# enrollment token) — they have no business inside a task payload either.
_FORBIDDEN_VALUE_PREFIXES = ("ak_", "et_")

_lock = threading.Lock()
_refs: dict = {}          # ref -> (plaintext, agent_name, expires_at)


def _sweep_locked(now: float) -> None:
    for ref in [r for r, (_, _, exp) in _refs.items() if exp <= now]:
        del _refs[ref]


def issue_ref(plaintext: str, *, agent_name: str, ttl_s: float = REF_TTL_S) -> str:
    """Store `plaintext` in memory for `agent_name` and return the ref the
    task payload should carry. The plaintext is held ONLY in this dict."""
    if not agent_name:
        raise ValueError("agent_name is required")
    ref = REF_PREFIX + secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        _sweep_locked(now)
        _refs[ref] = (plaintext, agent_name, now + float(ttl_s))
    return ref


def redeem_ref(ref: str, *, agent_name: str):
    """(plaintext, "") exactly once; afterwards (None, reason).

    A plain dict lookup is fine here: refs are 256-bit random values, so a
    timing side-channel on the lookup leaks nothing an attacker could use
    (no constant-time compare needed, unlike password/token hashes)."""
    now = time.time()
    with _lock:
        entry = _refs.get(ref or "")
        if entry is None:
            return None, "unknown or already redeemed"
        plaintext, owner, expires_at = entry
        if expires_at <= now:
            del _refs[ref]
            return None, "expired"
        if owner != agent_name:
            # Leave it in place — the rightful agent may still redeem it.
            return None, "bound to another agent"
        del _refs[ref]
    return plaintext, ""


def revoke_refs_for_agent(agent_name: str) -> int:
    """Drop every pending ref issued for `agent_name` (revoke / delete)."""
    with _lock:
        doomed = [r for r, (_, owner, _) in _refs.items() if owner == agent_name]
        for r in doomed:
            del _refs[r]
    return len(doomed)


def pending_count() -> int:
    with _lock:
        _sweep_locked(time.time())
        return len(_refs)


# ── Pool hook: refuse payloads that carry secrets ───────────────────────

def _norm_key(key) -> str:
    return str(key).strip().lower().replace("-", "_")


def validate_task_payload(task) -> str:
    """`validate_task` hook for AgentPool: non-empty reason when any key in
    the (recursive) payload is a secret-ish name, or any string value is an
    agent key / enrollment token. "" when clean."""
    stack = [task]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if _norm_key(key) in SECRET_KEY_NAMES:
                    return (f"task payload must not carry secrets (key {str(key)!r}) "
                            f"— use secret_ref")
                stack.append(value)
        elif isinstance(node, (list, tuple)):
            stack.extend(node)
        elif isinstance(node, str) and node.startswith(_FORBIDDEN_VALUE_PREFIXES):
            return ("task payload must not carry an agent key or enrollment token "
                    f"(value starts with {node[:3]!r})")
    return ""


# ── GET /agent/secret?ref=… ─────────────────────────────────────────────

def handle_secret_request(pool, req: agent_routes.Request) -> agent_routes.Response:
    """Dispatcher-shaped handler. 200 {"ok","secret"} once; 404 for every
    failure so a probing agent can't tell expired from foreign. The ref and
    the secret are never logged."""
    agent, err = agent_routes._authenticate(pool, req)
    if err:
        return err
    name = agent["name"]
    plaintext, reason = redeem_ref((req.query or {}).get("ref", ""), agent_name=name)
    if plaintext is None:
        agent_routes._log(logging.WARNING, f"secret refused: {reason}", {"agent": name})
        return agent_routes._json(404, {"error": reason})
    agent_routes._log(logging.INFO, "secret redeemed", {"agent": name})
    resp = agent_routes._json(200, {"ok": True, "secret": plaintext})
    resp.headers["Cache-Control"] = "no-store"
    return resp
