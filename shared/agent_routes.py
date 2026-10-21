#!/usr/bin/env python3
"""
agent_routes.py — the HTTP contract of the agent pool as a framework-free
dispatcher. Any web framework (FastAPI, Flask, Django, aiohttp, http.server)
adapts it in a few lines: build a `Request`, call `dispatch()`, send the
`Response`. fastapi_routes.py is the reference adapter.

TWO AUTH DOMAINS — keep them separate in your framework too

  /agent/*   machine-to-machine. Authenticated by `X-Agent-Key` against the
             pool (never by a user/API key: an agent key can never act as a
             user, a user key can never impersonate an agent) PLUS the
             `X-Agent-Device` fingerprint. Dispatch these BEFORE any user
             auth middleware.
             Public exceptions: POST /agent/enroll (the token is the
             credential, once), GET /agent/script, /agent/version,
             /agent/install.sh (the agent file is not a secret).

  /api/agents*  admin-only. YOUR framework authenticates the user and sets
             `Request.is_admin`; this module only refuses when it is False.

ROUTES

  POST /agent/enroll        {token, device, host?}          → 200 {ok, key, agent, poll_wait, heartbeat_every}
  POST /agent/register      {host, platform, cpus, memory_gb, capabilities[], script_version}
  POST /agent/heartbeat     {free_memory_gb, load1, capabilities?, busy?, script_version}
  GET  /agent/poll?wait=N&load1=&free_memory_gb=             → 200 task | 204 idle
  POST /agent/result        {task_id, partial, delta | ok, content, error, usage, elapsed}
  GET  /agent/script        the agent file (header X-Agent-Script-Version = sha256[:16])
  GET  /agent/version       {version, size}
  GET  /agent/install.sh    the installer with this server's URL baked in

  GET  /api/agents                     every agent + presence
  POST /api/agents/new                 {name, display?, tags?}     → {agent, token, launch, expires_in}
  POST /api/agents/enroll-token        {name}                      → fresh token (rotates the key on redeem)
  POST /api/agents/revoke|rebind|delete {name}
  POST /api/agents/tags                {name, tags[]}
  POST /api/agents/task                {agent | capability, task:{type,...}, wait?} → {task_id, result?, status?}
  GET  /api/agents/tasks               live queued/running tasks
  GET  /api/agents/task?id=            status + (final) result of one task
"""

from __future__ import annotations

import logging
import os
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from shared.agent_pool import AgentPool

LOGGER = logging.getLogger("agent_pool")

KEY_HEADER = "X-Agent-Key"
DEVICE_HEADER = "X-Agent-Device"
SCRIPT_VERSION_HEADER = "X-Agent-Script-Version"
TASK_WAIT_MAX = 600      # s ceiling for /api/agents/task {"wait"}

PUBLIC_GET = ("/agent/script", "/agent/version", "/agent/install.sh")
PUBLIC_POST = ("/agent/enroll",)


@dataclass
class Request:
    method: str                      # "GET" | "POST"
    path: str                        # path only, no query string
    headers: dict = field(default_factory=dict)
    query: dict = field(default_factory=dict)
    body: Any = None                 # parsed JSON (dict) or None
    is_admin: bool = False           # set by YOUR user auth for /api/* paths
    actor: str = "anonymous"         # for logs / audit
    public_url: str = ""             # base URL agents should dial (see public_url_from)

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v if v is not None else default
        return default


@dataclass
class Response:
    status: int
    body: Any = None                 # dict → JSON; bytes → raw; None → empty
    content_type: str = "application/json"
    headers: dict = field(default_factory=dict)


def public_url_from(headers: dict, configured: str = "") -> str:
    """Base URL an agent should dial: the configured one, else the request's
    Host honouring a reverse proxy's X-Forwarded-* headers."""
    if configured:
        return configured.rstrip("/")

    def get(name):
        for k, v in headers.items():
            if k.lower() == name.lower():
                return (v or "").split(",")[0].strip()
        return ""
    host = get("X-Forwarded-Host") or get("Host") or "localhost"
    proto = get("X-Forwarded-Proto")
    if not proto:
        proto = "http" if host.startswith(("localhost", "127.0.0.1")) else "https"
    return f"{proto}://{host}"


def is_agent_path(path: str) -> bool:
    return path.startswith("/agent/")


def is_admin_path(path: str) -> bool:
    return path == "/api/agents" or path.startswith("/api/agents/")


def _json(status, body):
    return Response(status, body)


def _log(level, msg, ctx=None):
    try:
        LOGGER.log(level, msg, extra={"context": ctx or {}})
    except Exception:  # noqa: BLE001
        pass


# ===============================
# 🤖 AGENT-FACING
# ===============================

def _authenticate(pool: AgentPool, req: Request):
    """(agent, None) or (None, Response)."""
    agent = pool.resolve_key(req.header(KEY_HEADER).strip())
    if agent is None:
        return None, _json(401, {"error": f"invalid or missing {KEY_HEADER}"})
    ok, reason = pool.check_device(agent["name"], req.header(DEVICE_HEADER).strip())
    if not ok:
        _log(logging.WARNING, f"agent refused: {reason}", {"agent": agent["name"]})
        return None, _json(403, {"error": reason, "agent": agent["name"]})
    return agent, None


def _enroll(pool, req):
    body = req.body if isinstance(req.body, dict) else {}
    agent, secret, status = pool.redeem_enrollment(body.get("token"), body.get("device"))
    if agent is None:
        _log(logging.WARNING, f"enrollment refused: {secret}", {"status": status})
        return _json(status, {"error": secret})
    _log(logging.INFO, f"agent enrolled: {agent['name']}",
         {"agent": agent["name"], "host": (body.get("host") or "")[:80]})
    return _json(200, {"ok": True, "key": secret, "agent": agent["name"],
                       "poll_wait": pool.cfg.poll_wait_max_s,
                       "heartbeat_every": pool.cfg.heartbeat_every_s})


def _register(pool, req):
    agent, err = _authenticate(pool, req)
    if err:
        return err
    presence = pool.register(agent["name"], req.body)
    _log(logging.INFO, f"agent registered: {agent['name']}",
         {"agent": agent["name"], "host": presence.get("host")})
    out = {"ok": True, "agent": agent["name"], "presence": presence}
    out.update(pool.advertised_defaults(req.public_url))
    return _json(200, out)


def _heartbeat(pool, req):
    agent, err = _authenticate(pool, req)
    if err:
        return err
    presence = pool.heartbeat(agent["name"], req.body)
    out = {"ok": True, "presence": presence}
    out.update(pool.advertised_defaults(req.public_url))
    return _json(200, out)


def _poll(pool, req):
    agent, err = _authenticate(pool, req)
    if err:
        return err
    raw_wait = req.query.get("wait")
    if raw_wait in (None, ""):
        wait = pool.cfg.poll_wait_max_s
    else:
        try:
            wait = float(raw_wait)
        except (TypeError, ValueError):
            return _json(400, {"error": "wait must be a number of seconds"})
        if wait < 0:
            return _json(400, {"error": "wait must be >= 0"})
    metrics = {}
    for key in ("load1", "free_memory_gb"):
        raw = req.query.get(key)
        if raw in (None, ""):
            continue
        try:
            metrics[key] = float(raw)
        except (TypeError, ValueError):
            continue           # a metric never fails a poll
    if metrics:
        pool.note_metrics(agent["name"], metrics)
    task = pool.next_task(agent["name"], wait)
    if task is None:
        return Response(204, None)
    _log(logging.INFO, f"task dispatched: {task['task_id']}",
         {"agent": agent["name"], "task_id": task["task_id"], "type": task.get("type")})
    return _json(200, task)


def _result(pool, req):
    agent, err = _authenticate(pool, req)
    if err:
        return err
    body = req.body if isinstance(req.body, dict) else {}
    task_id = body.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return _json(400, {"error": "task_id is required"})
    partial = bool(body.get("partial"))
    payload = {k: v for k, v in body.items() if k not in ("task_id", "partial")}
    if pool.submit_result(task_id, agent["name"], payload, partial=partial):
        if not partial:
            _log(logging.INFO, f"task finished: {task_id}",
                 {"agent": agent["name"], "task_id": task_id, "ok": bool(payload.get("ok")),
                  "error": payload.get("error")})
        return _json(200, {"ok": True})
    status = pool.task_status(task_id)
    if status is None or status.get("agent") != agent["name"]:
        return _json(404, {"error": "unknown task or not assigned to this agent"})
    return _json(409, {"error": f"task already {status['state']}"})


def _script(pool, req):
    data, version = pool.agent_script()
    if not version:
        return _json(404, {"error": "agent script not available on this server"})
    return Response(200, data, "text/x-python; charset=utf-8",
                    {SCRIPT_VERSION_HEADER: version, "Cache-Control": "no-store"})


def _version(pool, req):
    data, version = pool.agent_script()
    if not version:
        return _json(404, {"error": "agent script not available on this server"})
    return _json(200, {"version": version, "size": len(data)})


def render_install_script(template_path, url, name=None, token=None) -> str:
    """The installer with the server URL (and optionally name / token) baked
    in. The public route never passes a secret: the one-liner supplies the
    token through the environment."""
    with open(template_path, "r", encoding="utf-8") as f:
        text = f.read()
    for placeholder, value in (("@@AGENT_SERVER_URL@@", url), ("@@AGENT_NAME@@", name),
                               ("@@AGENT_ENROLL_TOKEN@@", token)):
        text = text.replace(placeholder, shlex.quote(value) if value else "''")
    return text


def _install(pool, req, template_path):
    if not template_path:
        return _json(404, {"error": "installer not available on this server"})
    try:
        text = render_install_script(template_path, req.public_url)
    except OSError:
        return _json(404, {"error": "installer not available on this server"})
    return Response(200, text.encode("utf-8"), "text/plain; charset=utf-8",
                    {"Cache-Control": "no-store"})


# ===============================
# 🛠️ ADMIN
# ===============================

def launch_lines(url, name, token, expires_in) -> dict:
    env = (f"AGENT_SERVER_URL={shlex.quote(url)} AGENT_ENROLL_TOKEN={shlex.quote(token)} "
           f"AGENT_NAME={shlex.quote(name)}")
    return {"launch": f"curl -fsSL {shlex.quote(url + '/agent/install.sh')} | {env} sh",
            "launch_dev": f"{env} python3 remote_agent.py",
            "expires_in": expires_in}


def _name_of(req):
    body = req.body if isinstance(req.body, dict) else {}
    name = body.get("name")
    return name.strip() if isinstance(name, str) else ""


def _admin_list(pool, req):
    return _json(200, {"agents": pool.list_agents(), "server_started": pool.server_started,
                       "server_now": time.time(), "offline_after_s": pool.cfg.offline_after_s,
                       "script_version": pool.script_version()})


def _admin_new(pool, req):
    body = req.body if isinstance(req.body, dict) else {}
    tags = body.get("tags")
    if tags is not None and not isinstance(tags, list):
        return _json(400, {"error": "tags must be a list"})
    agent, token = pool.create_agent(_name_of(req), req.actor, body.get("display"), tags)
    if agent is None:
        return _json(400, {"error": token})
    _log(logging.INFO, f"agent created: {agent['name']}", {"agent": agent["name"], "by": req.actor})
    out = {"ok": True, "agent": agent, "token": token}
    out.update(launch_lines(req.public_url, agent["name"], token, pool.cfg.enroll_ttl_s))
    return _json(200, out)


def _admin_enroll_token(pool, req):
    name = _name_of(req)
    if not name:
        return _json(400, {"error": "name is required"})
    token, reason = pool.new_enrollment_token(name)
    if token is None:
        return _json(404 if reason.startswith("unknown") else 400, {"error": reason})
    _log(logging.INFO, f"enrollment token issued: {name}", {"agent": name, "by": req.actor})
    out = {"ok": True, "agent": pool.get_agent(name), "token": token}
    out.update(launch_lines(req.public_url, name, token, pool.cfg.enroll_ttl_s))
    return _json(200, out)


def _admin_simple(fn):
    def handler(pool, req):
        name = _name_of(req)
        if not name:
            return _json(400, {"error": "name is required"})
        ok, reason = fn(pool, name)
        if not ok:
            return _json(404 if (reason or "").startswith("unknown") else 400, {"error": reason})
        _log(logging.INFO, f"agent {fn.__name__}: {name}", {"agent": name, "by": req.actor})
        return _json(200, {"ok": True, "agent": pool.get_agent(name)})
    return handler


def _revoke(pool, name):
    return pool.revoke_agent(name)


def _rebind(pool, name):
    agent, reason = pool.rebind_device(name)
    return (agent is not None), reason


def _delete(pool, name):
    return pool.delete_agent(name)


def _admin_tags(pool, req):
    name = _name_of(req)
    body = req.body if isinstance(req.body, dict) else {}
    if not name:
        return _json(400, {"error": "name is required"})
    agent, reason = pool.set_tags(name, body.get("tags"))
    if agent is None:
        return _json(404, {"error": reason})
    return _json(200, {"ok": True, "agent": agent})


def _admin_task(pool, req):
    """Manual / debug enqueue. {agent} pins a target; {capability} routes to
    the least-loaded online agent that lists it."""
    body = req.body if isinstance(req.body, dict) else {}
    name = body.get("agent")
    if not (isinstance(name, str) and name.strip()):
        name = pool.pick_agent(body.get("capability"), body.get("tags"))
        if name is None:
            return _json(503, {"error": "no online agent fits (agent or capability)"})
    wait = body.get("wait")
    if wait is not None:
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or wait < 0:
            return _json(400, {"error": "wait must be a non-negative number"})
        wait = min(float(wait), float(TASK_WAIT_MAX))
    try:
        task_id = pool.enqueue(name.strip(), body.get("task"))
    except KeyError:
        return _json(404, {"error": f"unknown or revoked agent: {name.strip()!r}"})
    except ValueError as exc:
        return _json(400, {"error": str(exc)})
    _log(logging.INFO, f"task enqueued: {task_id}",
         {"agent": name.strip(), "task_id": task_id, "by": req.actor})
    reply = {"ok": True, "task_id": task_id, "agent": name.strip()}
    if wait:
        reply["result"] = pool.wait_result(task_id, wait)
        reply["status"] = pool.task_status(task_id)
    return _json(200, reply)


def _admin_tasks(pool, req):
    return _json(200, {"tasks": pool.live_tasks()})


def _admin_task_get(pool, req):
    task_id = req.query.get("id") or ""
    status = pool.task_status(task_id)
    if status is None:
        return _json(404, {"error": "unknown task"})
    chunks, _ = pool.task_partials(task_id)
    out = {"status": status, "partials": chunks}
    if status["state"] in ("done", "failed"):
        out["result"] = pool.wait_result(task_id, 0)
    return _json(200, out)


AGENT_POST = {"/agent/enroll": _enroll, "/agent/register": _register,
              "/agent/heartbeat": _heartbeat, "/agent/result": _result}
AGENT_GET = {"/agent/poll": _poll, "/agent/script": _script, "/agent/version": _version}
ADMIN_GET = {"/api/agents": _admin_list, "/api/agents/tasks": _admin_tasks,
             "/api/agents/task": _admin_task_get}
ADMIN_POST = {"/api/agents/new": _admin_new, "/api/agents/enroll-token": _admin_enroll_token,
              "/api/agents/revoke": _admin_simple(_revoke),
              "/api/agents/rebind": _admin_simple(_rebind),
              "/api/agents/delete": _admin_simple(_delete),
              "/api/agents/tags": _admin_tags, "/api/agents/task": _admin_task}


def dispatch(pool: AgentPool, req: Request, install_template_path: Optional[str] = None
             ) -> Optional[Response]:
    """Routes one request. None when the path is not ours (let the host
    framework continue)."""
    method = (req.method or "GET").upper()
    if is_agent_path(req.path):
        if method == "GET" and req.path == "/agent/install.sh":
            return _install(pool, req, install_template_path)
        table = AGENT_GET if method == "GET" else AGENT_POST if method == "POST" else {}
        fn = table.get(req.path)
        return fn(pool, req) if fn else _json(404, {"error": "unknown agent route"})
    if is_admin_path(req.path):
        if not req.is_admin:
            return _json(403, {"error": "admin only"})
        table = ADMIN_GET if method == "GET" else ADMIN_POST if method == "POST" else {}
        fn = table.get(req.path)
        return fn(pool, req) if fn else _json(404, {"error": "unknown admin route"})
    return None


def default_install_template() -> str:
    """The installer FlexEdge serves: <repo>/agent/install.sh."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "agent", "install.sh")
