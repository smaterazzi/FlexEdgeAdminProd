#!/usr/bin/env python3
"""
agent_pool.py — framework-free server core for a pool of OUTBOUND-ONLY
remote agents (standard library only, Python 3.9+).

The server never dials the agents. An agent enrolls once with a single-use
token, then dials out: register → heartbeat → long-poll for tasks → run them
→ post the result (optionally streaming partial chunks). This module holds
every server-side rule of that protocol and nothing about HTTP: wire it to
any web framework through agent_routes.py (generic) or fastapi_routes.py.

WHAT IT GUARANTEES

  * Secrets: only sha256 hashes of agent keys / enrollment tokens are stored;
    comparisons are constant-time over every candidate (no early exit).
  * Enrollment: a token is single-use and expires after enroll_ttl_s;
    redeeming it mints the key, binds the device fingerprint and burns the
    token atomically. Re-enrolling an existing agent rotates its key.
  * Device binding: the key says WHICH agent, the fingerprint says WHICH
    machine. First sight binds it; any other machine is refused on every
    route until an admin re-binds.
  * Liveness: a poll or heartbeat touches the agent; offline_after_s without
    one flips it offline and its in-flight task is requeued ONCE (then
    failed). A re-register mid-task is treated the same way.
  * Queue: FIFO per agent, queued tasks expire after their ttl, results are
    accepted only from the assigned agent and only while unfinished; a final
    result for a task that was requeued (slow agent, not dead) still counts.
  * Restart safety: presence, unfinished tasks and queue order are mirrored
    to a JSON file (coalesced, atomic); on startup they are restored and a
    result for a restored task is handed to `orphan_result_hook` because the
    request that enqueued it died with the old process.

TASK CONTRACT (what an agent receives from a poll)

  {"task_id", "attempt", "type", ...anything JSON the enqueuer put in}
  The pool validates only `type` (must be in config.task_types, or pass a
  `validate_task` callable), `timeout` (number) and `ttl` (positive number).
  A `meta` key is server-side bookkeeping and is stripped before dispatch.

RESULT CONTRACT (what an agent posts to /agent/result)

  partial:  {"task_id", "partial": true, "delta": "...", "reasoning"?: true}
  final:    {"task_id", "partial": false, "ok": bool, "content"?: str,
             "error"?: str, "usage"?: {...}, "elapsed"?: float, ...}
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


# ===============================
# ⚙️ CONFIGURATION
# ===============================

@dataclass
class PoolConfig:
    data_dir: str = "."
    agents_file: str = "agents.json"          # registry (names, key hashes, bindings)
    state_file: str = "agent_pool_state.json"  # restart mirror (presence + unfinished tasks)
    offline_after_s: float = 60.0               # ≥ 3 × heartbeat_every_s
    poll_wait_max_s: float = 30.0               # ceiling of one long-poll
    heartbeat_every_s: float = 20.0             # advertised to agents
    enroll_ttl_s: float = 900.0                 # a token stays redeemable 15 min
    task_ttl_s: float = 900.0                   # default wait in queue before "expired"
    task_retention_s: float = 3600.0            # finished tasks kept for inspection
    max_finished_tasks: int = 2000
    max_partials: int = 20000
    max_tags: int = 20
    key_prefix: str = "ak_"
    enroll_prefix: str = "et_"
    task_types: tuple = ("ping", "echo", "chat")   # extend per project
    autoupdate: bool = True                     # advertised default for agent self-update
    state_flush_delay_s: float = 0.5            # coalesce bursts before writing the mirror
    agent_script_path: Optional[str] = None     # the agent file this server distributes


AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$")
DEVICE_RE = re.compile(r"^[0-9a-f]{64}$")
RESERVED_NAMES = ("local", "auto", "group")
STATE_VERSION = 1
SWEEP_EVERY = 5.0          # s, max gap between offline sweeps inside wait_result
SCRIPT_VERSION_LEN = 16


def hash_secret(raw: str) -> str:
    """sha256 hex of a raw secret — the only form ever persisted."""
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _num(val):
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    if val != val:  # NaN
        return None
    return float(val)


# ===============================
# 🏊 THE POOL
# ===============================

class AgentPool:
    """One instance per server process. Thread-safe. Every blocking wait
    (long-poll, wait_result) sits on a single Condition so a new task, a
    result or a revoke wakes the right waiter immediately."""

    def __init__(self, config: Optional[PoolConfig] = None, *,
                 validate_task: Optional[Callable[[dict], str]] = None,
                 orphan_result_hook: Optional[Callable[[dict, dict], None]] = None,
                 on_task_finished: Optional[Callable[[dict, dict], None]] = None):
        self.cfg = config or PoolConfig()
        self._validate_task_hook = validate_task
        self.orphan_result_hook = orphan_result_hook
        self.on_task_finished = on_task_finished
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._presence: dict = {}
        self._queues = collections.defaultdict(collections.deque)
        self._tasks: dict = {}
        self._store_cache = {"mtime": None, "data": None}
        self._state = {"active": False, "dirty": False, "thread": None}
        self._state_event = threading.Event()
        self._script_cache = {"key": None, "data": b"", "version": None}
        self.server_started = time.time()

    # --- registry file ------------------------------------------------------
    def agents_path(self) -> str:
        return os.path.join(self.cfg.data_dir, self.cfg.agents_file)

    def _load_store(self) -> dict:
        path = self.agents_path()
        try:
            mtime = os.stat(path).st_mtime_ns
        except OSError:
            self._store_cache = {"mtime": None, "data": {"agents": []}}
            return self._store_cache["data"]
        if self._store_cache["mtime"] == mtime and self._store_cache["data"] is not None:
            return self._store_cache["data"]
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {"agents": []}
        if not isinstance(data, dict) or not isinstance(data.get("agents"), list):
            data = {"agents": []}
        self._store_cache = {"mtime": mtime, "data": data}
        return data

    def _save_store(self, data: dict):
        path = self.agents_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        self._store_cache = {"mtime": os.stat(path).st_mtime_ns, "data": data}

    def _record(self, name: str):
        return next((a for a in self._load_store()["agents"] if a.get("name") == name), None)

    @staticmethod
    def _public(rec: dict) -> dict:
        """The record without secrets (key hash, token hash)."""
        return {"name": rec["name"], "display": rec.get("display") or rec["name"],
                "owner": rec.get("owner"), "tags": list(rec.get("tags") or []),
                "created": rec.get("created"), "enrolled": rec.get("enrolled"),
                "revoked": bool(rec.get("revoked")),
                "device_bound": rec.get("device_bound"),
                "has_key": bool(rec.get("key_hash")),
                "enrollment_pending": bool((rec.get("enrollment") or {}).get("token_hash"))}

    # ===============================
    # 🔑 REGISTRY: create / enroll / revoke
    # ===============================
    def _clean_tags(self, tags) -> list:
        out = []
        for t in tags if isinstance(tags, list) else []:
            if isinstance(t, str) and t.strip() and t.strip() not in out:
                out.append(t.strip()[:40])
        return out[:self.cfg.max_tags]

    def _new_enrollment(self):
        raw = self.cfg.enroll_prefix + new_secret()
        return raw, {"token_hash": hash_secret(raw),
                     "expires": time.time() + self.cfg.enroll_ttl_s, "created": _now_iso()}

    def create_agent(self, name, owner=None, display=None, tags=None):
        """Creates an agent WITHOUT a key and returns (public, enrollment_token).
        The token is shown once; the designated machine redeems it.
        (None, reason) on a bad or duplicate name."""
        name = name.strip() if isinstance(name, str) else ""
        if name.lower() in RESERVED_NAMES:
            return None, f"reserved agent name: {name!r}"
        if not AGENT_NAME_RE.match(name):
            return None, f"invalid agent name: {name!r} (letters, digits, _ -; max 40)"
        with self._lock:
            store = self._load_store()
            if any(a.get("name") == name for a in store["agents"]):
                return None, f"agent already exists: {name!r}"
            token, enrollment = self._new_enrollment()
            rec = {"name": name,
                   "display": (display.strip() if isinstance(display, str) else "") or name,
                   "key_hash": None, "owner": owner, "tags": self._clean_tags(tags),
                   "created": _now_iso(), "revoked": False, "enrollment": enrollment,
                   "device": None, "device_bound": None, "enrolled": None}
            store["agents"].append(rec)
            self._save_store(store)
        return self._public(rec), token

    def new_enrollment_token(self, name):
        """A fresh single-use token for an EXISTING agent (replacement machine).
        The current key keeps working until the token is redeemed, which
        rotates it. (token, None) or (None, reason)."""
        with self._cond:
            store = self._load_store()
            rec = next((a for a in store["agents"] if a.get("name") == name), None)
            if rec is None:
                return None, f"unknown agent: {name!r}"
            if rec.get("revoked"):
                return None, f"agent revoked: {name!r}"
            token, rec["enrollment"] = self._new_enrollment()
            self._save_store(store)
        return token, None

    def redeem_enrollment(self, token, device):
        """Token → key, once. (public, raw_key, 200) or (None, reason, status)."""
        token = token.strip() if isinstance(token, str) else ""
        if not token.startswith(self.cfg.enroll_prefix):
            return None, "invalid enrollment token", 400
        device = device.strip() if isinstance(device, str) else ""
        if not DEVICE_RE.match(device):
            return None, "device fingerprint required", 400
        digest = hash_secret(token)
        with self._cond:
            store = self._load_store()
            match = None
            for rec in store["agents"]:
                stored = (rec.get("enrollment") or {}).get("token_hash") or ""
                if len(stored) == len(digest) and hmac.compare_digest(stored, digest):
                    match = rec
            if match is None:
                return None, "unknown or already used enrollment token", 404
            if match.get("revoked"):
                return None, "agent revoked", 403
            if time.time() > float(match["enrollment"].get("expires") or 0):
                match["enrollment"] = None
                self._save_store(store)
                return None, "enrollment token expired — ask an admin for a new one", 410
            raw = self.cfg.key_prefix + new_secret()
            match["key_hash"] = hash_secret(raw)
            match["enrollment"] = None
            match["device"] = device
            match["device_bound"] = _now_iso()
            match["enrolled"] = _now_iso()
            self._save_store(store)
            presence = self._presence.get(match["name"])
            if presence:
                presence["moved"] = False
            return self._public(match), raw, 200

    def resolve_key(self, raw):
        """Public record of the NON-revoked agent holding `raw`, or None.
        Constant-time per candidate, no early exit."""
        if not raw or not isinstance(raw, str):
            return None
        digest = hash_secret(raw)
        match = None
        with self._lock:
            agents = list(self._load_store()["agents"])
        for rec in agents:
            stored = rec.get("key_hash") or ""
            if len(stored) == len(digest) and hmac.compare_digest(stored, digest):
                match = rec
        if match is None or match.get("revoked"):
            return None
        return self._public(match)

    def check_device(self, name, device):
        """(ok, reason). Binds on first sight; refuses any other machine."""
        device = device.strip() if isinstance(device, str) else ""
        if not DEVICE_RE.match(device):
            return False, "device fingerprint required (X-Agent-Device)"
        with self._cond:
            store = self._load_store()
            rec = next((a for a in store["agents"] if a.get("name") == name), None)
            if rec is None:
                return False, f"unknown agent: {name!r}"
            bound = rec.get("device") or ""
            if not bound:
                rec["device"] = device
                rec["device_bound"] = _now_iso()
                self._save_store(store)
                self._presence.setdefault(name, self._empty_presence())["moved"] = False
                return True, None
            if hmac.compare_digest(bound, device):
                presence = self._presence.get(name)
                if presence:
                    presence["moved"] = False
                return True, None
            presence = self._presence.setdefault(name, self._empty_presence())
            presence["moved"] = True
            presence["moved_at"] = time.time()
            self._mark_dirty()
            return False, "device mismatch: this agent is bound to another machine"

    def rebind_device(self, name):
        with self._cond:
            store = self._load_store()
            rec = next((a for a in store["agents"] if a.get("name") == name), None)
            if rec is None:
                return None, f"unknown agent: {name!r}"
            rec["device"] = None
            rec["device_bound"] = None
            self._save_store(store)
            presence = self._presence.get(name)
            if presence:
                presence["moved"] = False
            return self._public(rec), None

    def revoke_agent(self, name):
        """The key stops working at once; queued tasks fail; waiters wake."""
        with self._cond:
            store = self._load_store()
            rec = next((a for a in store["agents"] if a.get("name") == name), None)
            if rec is None:
                return False, f"unknown agent: {name!r}"
            if rec.get("revoked"):
                return False, f"agent already revoked: {name!r}"
            rec["revoked"] = True
            rec["enrollment"] = None
            self._save_store(store)
            self._presence.pop(name, None)
            for tid in list(self._queues.pop(name, ())):
                task = self._tasks.get(tid)
                if task and task["state"] == "queued":
                    self._finish(task, "failed", {"ok": False, "error": "agent revoked"})
            for task in self._tasks.values():
                if task["agent"] == name and task["state"] == "running":
                    self._finish(task, "failed", {"ok": False, "error": "agent revoked"})
            self._cond.notify_all()
            return True, None

    def delete_agent(self, name):
        """Removes a REVOKED agent's record."""
        with self._cond:
            store = self._load_store()
            rec = next((a for a in store["agents"] if a.get("name") == name), None)
            if rec is None:
                return False, f"unknown agent: {name!r}"
            if not rec.get("revoked"):
                return False, "revoke the agent first"
            store["agents"] = [a for a in store["agents"] if a.get("name") != name]
            self._save_store(store)
            return True, None

    def get_agent(self, name):
        with self._lock:
            rec = self._record(name)
            return self._public(rec) if rec else None

    def set_tags(self, name, tags):
        with self._lock:
            store = self._load_store()
            rec = next((a for a in store["agents"] if a.get("name") == name), None)
            if rec is None:
                return None, f"unknown agent: {name!r}"
            rec["tags"] = self._clean_tags(tags)
            self._save_store(store)
            return self._public(rec), None

    # ===============================
    # 📡 PRESENCE
    # ===============================
    @staticmethod
    def _empty_presence() -> dict:
        return {"host": None, "platform": None, "cpus": None, "memory_gb": None,
                "free_memory_gb": None, "load1": None, "capabilities": [],
                "current_task": None, "busy": False, "script_version": None,
                "last_seen": 0.0, "registered": None, "online": False, "moved": False}

    def _touch(self, name, now=None):
        p = self._presence.setdefault(name, self._empty_presence())
        p["last_seen"] = time.time() if now is None else now
        p["online"] = True
        return p

    @staticmethod
    def _clean_capabilities(caps) -> list:
        out = []
        for c in caps if isinstance(caps, list) else []:
            if isinstance(c, str) and c.strip():
                out.append(c.strip()[:200])
            elif isinstance(c, dict) and isinstance(c.get("id"), str) and c["id"].strip():
                out.append({k: v for k, v in c.items() if isinstance(k, str)})
        return out[:500]

    def _apply_info(self, p: dict, info: dict, full: bool):
        info = info if isinstance(info, dict) else {}
        if full:
            for key in ("host", "platform"):
                val = info.get(key)
                p[key] = val[:120] if isinstance(val, str) else None
            p["cpus"] = int(_num(info.get("cpus")) or 0) or None
            p["memory_gb"] = _num(info.get("memory_gb"))
        if "capabilities" in info:
            p["capabilities"] = self._clean_capabilities(info.get("capabilities"))
        for key in ("free_memory_gb", "load1"):
            if key in info:
                p[key] = _num(info.get(key))
        sv = info.get("script_version")
        if isinstance(sv, str) and re.fullmatch(r"[0-9a-f]{8,64}", sv):
            p["script_version"] = sv
        if "busy" in info:
            p["busy"] = bool(info.get("busy"))

    def _queue_len(self, name) -> int:
        return sum(1 for t in self._tasks.values()
                   if t["agent"] == name and t["state"] in ("queued", "running"))

    def _presence_view(self, name) -> dict:
        p = self._presence.get(name)
        queue = self._queue_len(name)
        if p is None:
            return dict(self._empty_presence(), queue=queue, registered=False,
                        script_outdated=False, last_seen=None)
        online = (time.time() - p["last_seen"]) < self.cfg.offline_after_s
        view = dict(p)
        view.update({"online": online, "queue": queue,
                     # False tells the agent to register again (server restarted)
                     "registered": (datetime.fromtimestamp(p["registered"], timezone.utc)
                                    .replace(microsecond=0).isoformat()
                                    if p.get("registered") else False),
                     "script_outdated": bool(p.get("script_version")
                                             and self.script_version()
                                             and p["script_version"] != self.script_version())})
        return view

    def register(self, name, info) -> dict:
        """A (re)announcement. A register while a task is running means the
        agent process restarted mid-task: that task is requeued once."""
        with self._cond:
            self._requeue_lost_locked(name)
            p = self._touch(name)
            p["registered"] = time.time()
            self._apply_info(p, info, full=True)
            p["current_task"] = None
            self._cond.notify_all()
            self._mark_dirty()
            return self._presence_view(name)

    def heartbeat(self, name, info) -> dict:
        with self._cond:
            p = self._touch(name)
            self._apply_info(p, info, full=False)
            self._mark_dirty()
            return self._presence_view(name)

    def note_metrics(self, name, metrics: dict):
        with self._lock:
            p = self._presence.get(name)
            if p is None:
                return
            for key in ("load1", "free_memory_gb"):
                val = _num((metrics or {}).get(key))
                if val is not None and 0 <= val < 1e6:
                    p[key] = val

    def _sweep(self, now=None):
        now = time.time() if now is None else now
        changed = False
        for name, p in list(self._presence.items()):
            if p["online"] and now - p["last_seen"] >= self.cfg.offline_after_s:
                p["online"] = False
                p["current_task"] = None
                self._mark_dirty()
                if self._requeue_lost_locked(name):
                    changed = True
        if self._expire_locked(now):
            changed = True
        if changed:
            self._cond.notify_all()

    def sweep(self, now=None):
        with self._cond:
            self._sweep(now)

    def is_online(self, name) -> bool:
        with self._cond:
            self._sweep()
            p = self._presence.get(name)
            return bool(p and p["online"])

    def online_agents(self) -> list:
        with self._cond:
            self._sweep()
            active = {a["name"] for a in self._load_store()["agents"] if not a.get("revoked")}
            return sorted(n for n, p in self._presence.items() if p["online"] and n in active)

    def list_agents(self) -> list:
        with self._cond:
            self._sweep()
            rows = []
            for rec in self._load_store()["agents"]:
                row = self._public(rec)
                row["presence"] = self._presence_view(rec["name"])
                rows.append(row)
            return rows

    # ===============================
    # 📬 TASKS
    # ===============================
    def _validate_task(self, task) -> str:
        if not isinstance(task, dict):
            return "task must be an object"
        if task.get("type") not in self.cfg.task_types:
            return (f"invalid task type: {task.get('type')!r} "
                    f"(valid: {', '.join(self.cfg.task_types)})")
        if "timeout" in task and _num(task["timeout"]) is None:
            return "timeout must be a number"
        if "ttl" in task and (_num(task["ttl"]) is None or task["ttl"] <= 0):
            return "ttl must be a positive number of seconds"
        try:
            json.dumps(task)
        except (TypeError, ValueError):
            return "task must be JSON-serialisable"
        if self._validate_task_hook:
            return self._validate_task_hook(task) or ""
        return ""

    def enqueue(self, agent_name, task) -> str:
        """Appends to the agent's FIFO and wakes its long-poll. The agent
        need not be online: the task waits (until its ttl). Raises KeyError
        (unknown/revoked agent) or ValueError (malformed task)."""
        reason = self._validate_task(task)
        if reason:
            raise ValueError(reason)
        with self._cond:
            rec = self._record(agent_name)
            if rec is None or rec.get("revoked"):
                raise KeyError(f"unknown or revoked agent: {agent_name!r}")
            task_id = uuid.uuid4().hex
            now = time.time()
            self._tasks[task_id] = {"id": task_id, "agent": agent_name, "task": dict(task),
                                    "state": "queued", "attempts": 0, "requeued": 0,
                                    "ttl": float(task.get("ttl") or self.cfg.task_ttl_s),
                                    "created": now, "queued_at": now, "started": None,
                                    "finished": None, "partials": [], "result": None,
                                    "reasoning": False}
            self._queues[agent_name].append(task_id)
            self._expire_locked()
            self._gc_tasks()
            self._cond.notify_all()
            self._mark_dirty()
            return task_id

    @staticmethod
    def _payload(task: dict) -> dict:
        body = dict(task["task"])
        body.pop("meta", None)
        body["task_id"] = task["id"]
        body["attempt"] = task["attempts"]
        return body

    def next_task(self, agent_name, wait=None):
        """Pops the next queued task, blocking up to `wait` s (capped).
        Polling counts as liveness."""
        cap = float(self.cfg.poll_wait_max_s)
        try:
            wait = max(0.0, min(float(wait), cap))
        except (TypeError, ValueError):
            wait = cap
        deadline = time.monotonic() + wait
        with self._cond:
            while True:
                rec = self._record(agent_name)
                if rec is None or rec.get("revoked"):
                    return None
                self._touch(agent_name)
                self._sweep()
                queue = self._queues.get(agent_name)
                while queue:
                    task = self._tasks.get(queue.popleft())
                    if task is None or task["state"] != "queued":
                        continue
                    task["state"] = "running"
                    task["attempts"] += 1
                    task["started"] = time.time()
                    self._presence[agent_name]["current_task"] = task["id"]
                    self._presence[agent_name]["busy"] = True
                    self._cond.notify_all()
                    self._mark_dirty()
                    return self._payload(task)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def _finish(self, task: dict, state: str, result: dict):
        task["state"] = state
        task["result"] = result
        task["finished"] = time.time()
        p = self._presence.get(task["agent"])
        if p and p.get("current_task") == task["id"]:
            p["current_task"] = None
            p["busy"] = False
        if self.on_task_finished:
            try:
                self.on_task_finished(dict(task), dict(result))
            except Exception:  # noqa: BLE001 — observers never break the pool
                pass
        self._mark_dirty()

    @staticmethod
    def _normalise_result(result: dict) -> dict:
        out = {"ok": bool(result.get("ok"))}
        for key in ("content", "error", "finish_reason"):
            if key in result:
                val = result[key]
                out[key] = val if isinstance(val, str) or val is None else str(val)
        for key in ("usage", "data", "tool_calls", "meta"):
            if key in result:
                out[key] = result[key]
        if "elapsed" in result:
            out["elapsed"] = _num(result["elapsed"])
        if not out["ok"] and not out.get("error"):
            out["error"] = "task failed"
        return out

    def submit_result(self, task_id, agent_name, result, partial=False) -> bool:
        """Records a partial chunk or the final result. Only the assigned
        agent, only while unfinished. False for unknown/foreign/finished."""
        if not isinstance(result, dict):
            return False
        orphan = None
        with self._cond:
            task = self._tasks.get(task_id)
            if task is None or task["agent"] != agent_name:
                return False
            if task["state"] not in ("queued", "running"):
                return False
            self._touch(agent_name)
            if partial:
                if task["state"] == "queued":
                    return False     # late chunk of a requeued attempt: would duplicate text
                if result.get("reasoning") is True:
                    task["reasoning"] = True
                delta = result.get("delta")
                if isinstance(delta, str) and delta and len(task["partials"]) < self.cfg.max_partials:
                    task["partials"].append(delta)
                self._cond.notify_all()
                return True
            if task["state"] == "queued":
                try:
                    self._queues[agent_name].remove(task_id)
                except ValueError:
                    pass
            final = self._normalise_result(result)
            self._finish(task, "done" if final["ok"] else "failed", final)
            self._cond.notify_all()
            if task.get("restored"):
                orphan = dict(task)
        if orphan is not None and self.orphan_result_hook is not None:
            try:
                self.orphan_result_hook(orphan, dict(final))
            except Exception:  # noqa: BLE001 — delivery is best effort
                pass
        return True

    def wait_result(self, task_id, timeout):
        """Blocks until finished or `timeout`. Final result dict, or None on
        timeout / unknown task (the task keeps running)."""
        try:
            timeout = max(0.0, float(timeout))
        except (TypeError, ValueError):
            timeout = 0.0
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                self._sweep()
                task = self._tasks.get(task_id)
                if task is None:
                    return None
                if task["state"] in ("done", "failed"):
                    return dict(task["result"] or {"ok": False, "error": task["state"]})
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(min(remaining, SWEEP_EVERY))

    def task_partials(self, task_id, since=0):
        """(chunks after index `since`, state) or (None, None)."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None, None
            return list(task["partials"][since:]), task["state"]

    def task_status(self, task_id):
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            return {"id": task_id, "agent": task["agent"], "state": task["state"],
                    "attempts": task["attempts"], "requeued": task["requeued"],
                    "reasoning": task["reasoning"], "created": task["created"],
                    "started": task["started"], "finished": task["finished"],
                    "type": task["task"].get("type"), "partials": len(task["partials"])}

    def live_tasks(self) -> dict:
        """{agent: {"queued": [...], "running": [...]}} of task summaries."""
        with self._lock:
            out = {}
            for t in self._tasks.values():
                if t["state"] not in ("queued", "running"):
                    continue
                slot = out.setdefault(t["agent"], {"queued": [], "running": []})
                slot[t["state"]].append({"id": t["id"], "type": t["task"].get("type"),
                                         "created": t["created"], "started": t["started"]})
            return out

    def _requeue_lost_locked(self, agent_name) -> int:
        changed = 0
        lost = [t for t in self._tasks.values()
                if t["agent"] == agent_name and t["state"] == "running"]
        for task in lost:
            changed += 1
            if task["requeued"] >= 1:
                self._finish(task, "failed",
                             {"ok": False, "error": "agent lost twice while running the task"})
                continue
            task["requeued"] += 1
            task["state"] = "queued"
            task["started"] = None
            task["partials"] = []       # the next attempt streams from scratch
            task["reasoning"] = False
            task["queued_at"] = time.time()
            self._queues[agent_name].appendleft(task["id"])
        p = self._presence.get(agent_name)
        if p and changed:
            p["current_task"] = None
            p["busy"] = False
        if changed:
            self._mark_dirty()
        return changed

    def _expire_locked(self, now=None) -> int:
        now = time.time() if now is None else now
        expired = 0
        for task in list(self._tasks.values()):
            if task["state"] != "queued":
                continue
            if now - (task.get("queued_at") or task["created"]) < task["ttl"]:
                continue
            try:
                self._queues[task["agent"]].remove(task["id"])
            except ValueError:
                pass
            self._finish(task, "failed", {"ok": False, "error": "expired"})
            expired += 1
        return expired

    def _gc_tasks(self):
        now = time.time()
        for t in list(self._tasks.values()):
            if t["finished"] is not None and now - t["finished"] > self.cfg.task_retention_s:
                self._tasks.pop(t["id"], None)
        finished = sorted((t for t in self._tasks.values() if t["finished"] is not None),
                          key=lambda t: t["finished"])
        for t in finished[:max(0, len(finished) - self.cfg.max_finished_tasks)]:
            self._tasks.pop(t["id"], None)

    # ===============================
    # 🎯 SELECTION
    # ===============================
    def pick_agent(self, capability=None, tags=None, peek=False):
        """Name of an ONLINE agent to route a task to: one that lists
        `capability` (string id, or a dict with that `id`) and carries every
        tag in `tags`, with the shortest queue. None when nobody fits."""
        want_tags = set(tags or [])
        with self._cond:
            self._sweep()
            best, best_load = None, None
            for rec in self._load_store()["agents"]:
                if rec.get("revoked"):
                    continue
                p = self._presence.get(rec["name"])
                if not p or not p["online"] or p.get("moved"):
                    continue
                if want_tags and not want_tags <= set(rec.get("tags") or []):
                    continue
                if capability is not None:
                    ids = {c if isinstance(c, str) else c.get("id") for c in p["capabilities"]}
                    if capability not in ids:
                        continue
                load = self._queue_len(rec["name"])
                if best is None or load < best_load:
                    best, best_load = rec["name"], load
            return best

    # ===============================
    # 💾 RESTART MIRROR
    # ===============================
    def state_path(self) -> str:
        return os.path.join(self.cfg.data_dir, self.cfg.state_file)

    def start_state_mirror(self):
        """Turns the background writer on (after load_state at startup)."""
        self._state["active"] = True
        self._mark_dirty()

    def _mark_dirty(self):
        if not self._state["active"]:
            return
        self._state["dirty"] = True
        t = self._state["thread"]
        if t is None or not t.is_alive():
            t = threading.Thread(target=self._state_writer, name="agent-pool-state", daemon=True)
            self._state["thread"] = t
            t.start()
        self._state_event.set()

    def _state_writer(self):  # pragma: no cover — exercised via flush_state
        while True:
            self._state_event.wait()
            self._state_event.clear()
            time.sleep(self.cfg.state_flush_delay_s)
            if self._state["dirty"] and self._state["active"]:
                self.flush_state()

    def _snapshot_locked(self) -> dict:
        tasks = [{k: t[k] for k in ("id", "agent", "task", "state", "attempts", "requeued",
                                     "ttl", "created", "queued_at", "started")}
                 for t in self._tasks.values() if t["state"] in ("queued", "running")]
        queues = {a: [tid for tid in q if tid in self._tasks and self._tasks[tid]["state"] == "queued"]
                  for a, q in self._queues.items() if q}
        return {"version": STATE_VERSION, "saved": time.time(), "pid": os.getpid(),
                "presence": {n: dict(p) for n, p in self._presence.items()},
                "tasks": tasks, "queues": queues}

    def flush_state(self) -> bool:
        """Writes the mirror now (atomic replace). Call it on SIGTERM."""
        with self._cond:
            snap = self._snapshot_locked()
            self._state["dirty"] = False
        path = self.state_path()
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snap, f, separators=(",", ":"))
            os.replace(tmp, path)
            return True
        except (OSError, TypeError, ValueError):
            return False

    def load_state(self, now=None) -> dict:
        """Restores presence + unfinished tasks into an EMPTY pool. Restored
        tasks are flagged so their result goes to orphan_result_hook."""
        out = {"presence": 0, "tasks": 0, "queued": 0, "running": 0, "online": 0}
        now = time.time() if now is None else now
        try:
            with open(self.state_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return out
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            return out
        with self._cond:
            if self._presence or self._tasks:
                return out
            known = {a["name"] for a in self._load_store()["agents"] if not a.get("revoked")}
            for t in data.get("tasks") or []:
                if not (isinstance(t, dict) and t.get("id") and t.get("agent") in known
                        and t.get("state") in ("queued", "running")):
                    continue
                rec = {"id": t["id"], "agent": t["agent"], "task": dict(t.get("task") or {}),
                       "state": t["state"], "attempts": int(t.get("attempts") or 0),
                       "requeued": int(t.get("requeued") or 0),
                       "ttl": float(t.get("ttl") or self.cfg.task_ttl_s),
                       "created": float(t.get("created") or now),
                       "queued_at": float(t.get("queued_at") or now),
                       "started": t.get("started"), "finished": None, "partials": [],
                       "result": None, "reasoning": False, "restored": True}
                self._tasks[rec["id"]] = rec
                out["tasks"] += 1
                out["queued" if rec["state"] == "queued" else "running"] += 1
            queued_ids = {tid for tid, t in self._tasks.items() if t["state"] == "queued"}
            for agent, ids in (data.get("queues") or {}).items():
                for tid in ids or []:
                    if tid in queued_ids and tid not in self._queues[agent]:
                        self._queues[agent].append(tid)
            for tid in sorted(queued_ids, key=lambda i: self._tasks[i]["queued_at"]):
                a = self._tasks[tid]["agent"]
                if tid not in self._queues[a]:
                    self._queues[a].append(tid)
            running = {t["id"] for t in self._tasks.values() if t["state"] == "running"}
            for name, p in (data.get("presence") or {}).items():
                if name not in known or not isinstance(p, dict):
                    continue
                presence = self._empty_presence()
                for k in presence:
                    if k in p:
                        presence[k] = p[k]
                try:
                    presence["last_seen"] = float(presence.get("last_seen") or 0.0)
                except (TypeError, ValueError):
                    presence["last_seen"] = 0.0
                presence["online"] = (now - presence["last_seen"]) < self.cfg.offline_after_s
                if presence.get("current_task") not in running:
                    presence["current_task"] = None
                presence["busy"] = presence["current_task"] is not None
                self._presence[name] = presence
                out["presence"] += 1
                out["online"] += int(presence["online"])
        return out

    # ===============================
    # 📦 AGENT SCRIPT DISTRIBUTION (self-update)
    # ===============================
    @staticmethod
    def script_version_of(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:SCRIPT_VERSION_LEN]

    def agent_script(self):
        """(bytes, version) of the agent file this server distributes, or
        (b"", None) when not configured / unreadable. Cached by mtime+size."""
        path = self.cfg.agent_script_path
        if not path:
            return b"", None
        try:
            st = os.stat(path)
        except OSError:
            return b"", None
        key = (st.st_mtime_ns, st.st_size)
        if self._script_cache["key"] != key:
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                return b"", None
            self._script_cache = {"key": key, "data": data,
                                  "version": self.script_version_of(data)}
        return self._script_cache["data"], self._script_cache["version"]

    def script_version(self):
        return self.agent_script()[1]

    def advertised_defaults(self, public_url: str) -> dict:
        """Ride on every register/heartbeat reply: the agent adopts them
        unless its own env pins a value."""
        return {"script_version": self.script_version(),
                "update_url": public_url.rstrip("/") + "/agent/script",
                "autoupdate": bool(self.cfg.autoupdate),
                "poll_wait": self.cfg.poll_wait_max_s,
                "heartbeat_every": self.cfg.heartbeat_every_s}
