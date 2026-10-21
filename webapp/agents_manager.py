"""
FlexEdgeAdmin — Remote agents (Phase A plumbing, docs/RemoteAgents.md).

Three Flask blueprints over the kit's framework-free dispatcher
(shared/agent_routes.py) and pool (shared/agent_pool.py):

  agents_machine_bp   /agent/*        machine auth (X-Agent-Key + X-Agent-Device),
                                      NO session auth, csrf-exempt (see app.py)
  agents_api_bp       /api/agents*    JSON admin API, Super Admin only
  agents_admin_bp     /admin/agents*  HTML admin UI, Super Admin only

The pool is a process-wide singleton (gunicorn runs ONE worker — see the
Dockerfile comment). `dispatch()` blocks for up to `poll_wait_max_s` on
`/agent/poll`; every online agent therefore parks one gthread thread.
"""

import atexit
import logging
import os
import re
from pathlib import Path

from flask import (
    Blueprint, Response as FlaskResponse, jsonify, render_template,
    request, redirect, url_for, flash, session,
)

from shared import agent_router, agent_routes
from shared.agent_pool import AgentPool, PoolConfig
from shared.agent_secrets import (
    handle_secret_request, revoke_refs_for_agent, validate_task_payload,
)
from shared.db import db
from shared.logging import audit, register_feature
from webapp.auth_roles import super_admin_required
from webapp.models import Domain, RemoteAgent, User

log = logging.getLogger(__name__)

AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$")
TASK_TYPES = ("ping", "netsight-query", "subnet-scan", "cancel")

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENT_SCRIPT = _REPO_ROOT / "agent" / "remote_agent.py"
_DOCKER_DATA_DIR = Path("/app/data")


def _resolve_data_dir() -> Path:
    """Same resolution as webapp/project_manager.py: env override →
    /app/data (Docker bind-mount) → <repo>/data (dev)."""
    override = os.environ.get("FLEXEDGE_AGENTS_DIR", "").strip()
    if override:
        return Path(override)
    if _DOCKER_DATA_DIR.exists():
        return _DOCKER_DATA_DIR / "agents"
    return _REPO_ROOT / "data" / "agents"


# ── Pool singleton ───────────────────────────────────────────────────────

_pool = None


def get_pool() -> AgentPool:
    global _pool
    if _pool is None:
        data_dir = _resolve_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        _pool = AgentPool(PoolConfig(
            data_dir=str(data_dir),
            task_types=TASK_TYPES,
            agent_script_path=str(_AGENT_SCRIPT),
            poll_wait_max_s=20,
            offline_after_s=60,
            heartbeat_every_s=20,
        ), validate_task=validate_task_payload)
        restored = _pool.load_state()
        _pool.start_state_mirror()
        atexit.register(_pool.flush_state)
        log.info("agent pool ready: data_dir=%s script=%s restored=%s",
                 data_dir, _AGENT_SCRIPT, restored)
    return _pool


# ── Audit hook: kit logger → platform_logs ───────────────────────────────

_ACTION_MAP = (
    ("agent enrolled", "agent.enroll"),
    ("agent refused", "agent.moved"),
    ("task dispatched", "task.dispatch"),
    ("task finished", "task.done"),
    ("secret redeemed", "secret.redeem"),
    ("secret refused", "secret.refused"),
)


class _AuditHandler(logging.Handler):
    """Maps the kit's `agent_pool` log records (extra={"context": {...}})
    to audit rows. Anything it doesn't recognise is left to normal logging."""

    def emit(self, record):
        try:
            msg = record.getMessage()
            ctx = getattr(record, "context", None) or {}
            for prefix, action in _ACTION_MAP:
                if msg.startswith(prefix):
                    break
            else:
                return
            status = "ok"
            if action == "task.done" and ctx.get("ok") is False:
                action, status = "task.failed", "error"
            if action in ("agent.moved", "secret.refused"):
                status = "error"
            detail = "; ".join(f"{k}={v}" for k, v in ctx.items() if k != "agent")
            audit("agents", action, target=str(ctx.get("agent") or ""),
                  detail=detail or msg, status=status,
                  source_correlation_id=ctx.get("task_id"))
        except Exception:  # noqa: BLE001 — logging never breaks the pool
            pass


def init_agents_manager(app):
    register_feature("agents", "Remote agents")
    kit_logger = logging.getLogger("agent_pool")
    if not any(isinstance(h, _AuditHandler) for h in kit_logger.handlers):
        kit_logger.addHandler(_AuditHandler())
    with app.app_context():
        get_pool()


# ── Flask adapter ────────────────────────────────────────────────────────

def _build_request(is_admin: bool) -> agent_routes.Request:
    headers = dict(request.headers)
    actor = "anonymous"
    if is_admin:
        actor = (session.get("user") or {}).get("email") or "admin"
    return agent_routes.Request(
        method=request.method,
        path=request.path,
        headers=headers,
        query=request.args.to_dict(),
        body=request.get_json(silent=True),
        is_admin=is_admin,
        actor=actor,
        public_url=agent_routes.public_url_from(
            headers, os.environ.get("PUBLIC_URL", "")),
    )


def _to_flask(resp):
    if resp is None:
        return jsonify({"error": "not found"}), 404
    if resp.body is None:
        return FlaskResponse(status=resp.status, headers=resp.headers)
    if isinstance(resp.body, (bytes, bytearray)):
        return FlaskResponse(bytes(resp.body), status=resp.status,
                             content_type=resp.content_type, headers=resp.headers)
    out = jsonify(resp.body)
    out.status_code = resp.status
    for k, v in (resp.headers or {}).items():
        out.headers[k] = v
    return out


def _dispatch(is_admin: bool):
    req = _build_request(is_admin)
    return _to_flask(agent_routes.dispatch(
        get_pool(), req, agent_routes.default_install_template()))


agents_machine_bp = Blueprint("agents_machine", __name__)
agents_api_bp = Blueprint("agents_api", __name__)
agents_admin_bp = Blueprint("agents_admin", __name__, url_prefix="/admin/agents")


def _machine_view():
    return _dispatch(is_admin=False)


@super_admin_required
def _api_view():
    return _dispatch(is_admin=True)


for _path in sorted(set(agent_routes.AGENT_GET) | {"/agent/install.sh"}):
    agents_machine_bp.add_url_rule(_path, endpoint="get_" + _path.strip("/").replace("/", "_").replace(".", "_"),
                                   view_func=_machine_view, methods=["GET"])
for _path in agent_routes.AGENT_POST:
    agents_machine_bp.add_url_rule(_path, endpoint="post_" + _path.strip("/").replace("/", "_"),
                                   view_func=_machine_view, methods=["POST"])
for _path in agent_routes.ADMIN_GET:
    agents_api_bp.add_url_rule(_path, endpoint="get_" + _path.strip("/").replace("/", "_"),
                               view_func=_api_view, methods=["GET"])
for _path in agent_routes.ADMIN_POST:
    agents_api_bp.add_url_rule(_path, endpoint="post_" + _path.strip("/").replace("/", "_"),
                               view_func=_api_view, methods=["POST"])

@agents_machine_bp.route("/agent/secret", methods=["GET"])
def get_agent_secret():
    """RA-B one-shot secret redemption (shared/agent_secrets.py). Machine
    auth only — the blueprint is csrf-exempt in app.py."""
    return _to_flask(handle_secret_request(get_pool(), _build_request(is_admin=False)))



# ── Admin UI ─────────────────────────────────────────────────────────────

def _public_url() -> str:
    return agent_routes.public_url_from(dict(request.headers),
                                        os.environ.get("PUBLIC_URL", ""))


def _parse_networks(raw: str):
    """One CIDR per line (commas tolerated). Returns (list, error).
    Thin (list, err) wrapper over the ONE parser in shared/agent_router."""
    try:
        return agent_router.parse_networks(raw), None
    except ValueError as exc:
        return None, str(exc)


def _current_user_id():
    email = (session.get("user") or {}).get("email")
    if not email:
        return None
    user = User.query.filter_by(email=email).first()
    return user.id if user else None


def _agent_or_404(agent_id: int):
    row = RemoteAgent.query.get(agent_id)
    if row is None:
        flash("Unknown agent.", "warning")
        return None
    return row


def _merged_rows():
    """DB rows + live presence from the pool, joined on name."""
    pool = get_pool()
    live = {a["name"]: a for a in pool.list_agents()}
    rows = RemoteAgent.query.order_by(RemoteAgent.name).all()
    out = []
    for row in rows:
        p = live.get(row.name) or {}
        out.append({"row": row, "live": p, "presence": p.get("presence") or {}})
    return out, pool


@agents_admin_bp.route("/")
@super_admin_required
def agents_list():
    items, pool = _merged_rows()
    return render_template("admin/agents.html", items=items,
                           script_version=pool.script_version(),
                           offline_after_s=pool.cfg.offline_after_s,
                           server_networks=agent_router.server_reachable_networks())


@agents_admin_bp.route("/new", methods=["GET", "POST"])
@super_admin_required
def agent_new():
    domains = Domain.query.filter_by(is_active=True).order_by(Domain.display_name).all()
    form = {"name": "", "display_name": "", "domain_id": "", "reachable_networks": "", "notes": ""}
    if request.method == "POST":
        form = {k: (request.form.get(k) or "").strip() for k in form}
        name = form["name"]
        if not AGENT_NAME_RE.match(name):
            flash("Agent name: letters, digits, '_' or '-', max 40, must start with a letter or digit.", "danger")
            return render_template("admin/agents_new.html", domains=domains, form=form)
        domain = Domain.query.get(int(form["domain_id"])) if form["domain_id"].isdigit() else None
        if domain is None or not domain.is_active:
            flash("Pick an active Domain.", "danger")
            return render_template("admin/agents_new.html", domains=domains, form=form)
        nets, err = _parse_networks(form["reachable_networks"])
        if err:
            flash(err, "danger")
            return render_template("admin/agents_new.html", domains=domains, form=form)
        if RemoteAgent.query.filter_by(name=name).first():
            flash(f"An agent named '{name}' already exists.", "danger")
            return render_template("admin/agents_new.html", domains=domains, form=form)

        pool = get_pool()
        public, token = pool.create_agent(name, owner=(session.get("user") or {}).get("email"),
                                          display=form["display_name"] or name,
                                          tags=[f"domain:{domain.slug}"])
        if public is None:
            flash(f"Could not create agent: {token}", "danger")
            return render_template("admin/agents_new.html", domains=domains, form=form)
        row = RemoteAgent(domain_id=domain.id, name=name,
                          display_name=form["display_name"] or name,
                          notes=form["notes"], created_by_id=_current_user_id())
        row.reachable_networks = nets
        try:
            db.session.add(row)
            db.session.commit()
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            pool.delete_agent(name)
            log.exception("remote_agents insert failed for %s", name)
            flash(f"Could not create agent: {exc}", "danger")
            return render_template("admin/agents_new.html", domains=domains, form=form)
        audit("agents", "agent.create", target=name,
              detail=f"domain={domain.slug} networks={','.join(nets) or '-'}")
        return _render_token(row, token, "created")
    return render_template("admin/agents_new.html", domains=domains, form=form)


def _render_token(row, token: str, reason: str):
    pool = get_pool()
    lines = agent_routes.launch_lines(_public_url(), row.name, token, pool.cfg.enroll_ttl_s)
    return render_template("admin/agents_token.html", agent=row, token=token,
                           launch=lines, reason=reason,
                           expires_min=int(pool.cfg.enroll_ttl_s // 60))


@agents_admin_bp.route("/<int:agent_id>/enroll-token", methods=["POST"])
@super_admin_required
def agent_enroll_token(agent_id):
    row = _agent_or_404(agent_id)
    if row is None:
        return redirect(url_for("agents_admin.agents_list"))
    token, err = get_pool().new_enrollment_token(row.name)
    if err:
        flash(f"Could not issue a token: {err}", "danger")
        return redirect(url_for("agents_admin.agents_list"))
    audit("agents", "agent.rotate", target=row.name,
          detail="new enrollment token issued — key rotates on redeem")
    return _render_token(row, token, "rotated")


@agents_admin_bp.route("/<int:agent_id>/rebind", methods=["POST"])
@super_admin_required
def agent_rebind(agent_id):
    row = _agent_or_404(agent_id)
    if row is None:
        return redirect(url_for("agents_admin.agents_list"))
    ok, err = get_pool().rebind_device(row.name)
    if not ok:
        flash(f"Rebind failed: {err}", "danger")
    else:
        audit("agents", "agent.rebind", target=row.name,
              detail="device binding cleared; next contact binds the machine")
        flash(f"'{row.name}' unbound — delete ~/.remote-agent/device on the machine and restart its service.", "success")
    return redirect(url_for("agents_admin.agents_list"))


@agents_admin_bp.route("/<int:agent_id>/revoke", methods=["POST"])
@super_admin_required
def agent_revoke(agent_id):
    row = _agent_or_404(agent_id)
    if row is None:
        return redirect(url_for("agents_admin.agents_list"))
    ok, err = get_pool().revoke_agent(row.name)
    if not ok:
        flash(f"Revoke failed: {err}", "danger")
    else:
        revoke_refs_for_agent(row.name)
        audit("agents", "agent.revoke", target=row.name, status="warning")
        flash(f"'{row.name}' revoked — its key is dead immediately.", "success")
    return redirect(url_for("agents_admin.agents_list"))


@agents_admin_bp.route("/<int:agent_id>/delete", methods=["POST"])
@super_admin_required
def agent_delete(agent_id):
    row = _agent_or_404(agent_id)
    if row is None:
        return redirect(url_for("agents_admin.agents_list"))
    name = row.name
    try:
        db.session.delete(row)
        db.session.commit()
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        flash(f"Could not delete agent: {exc}", "danger")
        return redirect(url_for("agents_admin.agents_list"))
    get_pool().delete_agent(name)
    revoke_refs_for_agent(name)
    audit("agents", "agent.delete", target=name, status="warning")
    flash(f"'{name}' deleted.", "success")
    return redirect(url_for("agents_admin.agents_list"))


@agents_admin_bp.route("/<int:agent_id>/ping", methods=["POST"])
@super_admin_required
def agent_ping(agent_id):
    """Round-trip a `ping` task — the operator's end-to-end check after
    enrollment. Synchronous on purpose (≤ 15 s); the JSON API needs a CSRF
    token so a curl from the docs can't do this, the button can."""
    row = _agent_or_404(agent_id)
    if row is None:
        return redirect(url_for("agents_admin.agents_list"))
    pool = get_pool()
    if not pool.is_online(row.name):
        flash(f"'{row.name}' is offline — nothing to ping.", "warning")
        return redirect(url_for("agents_admin.agents_list"))
    try:
        task_id = pool.enqueue(row.name, {"type": "ping", "ttl": 30, "timeout": 10})
    except (KeyError, ValueError) as exc:
        flash(f"Could not enqueue ping: {exc}", "danger")
        return redirect(url_for("agents_admin.agents_list"))
    result = pool.wait_result(task_id, 15)
    if result is None:
        audit("agents", "task.ping", target=row.name, status="error",
              detail="no reply within 15 s", source_correlation_id=task_id)
        flash(f"'{row.name}' took the task but did not reply within 15 s.", "warning")
    elif result.get("ok"):
        audit("agents", "task.ping", target=row.name,
              detail=f"elapsed={result.get('elapsed')}s", source_correlation_id=task_id)
        flash(f"'{row.name}' replied '{result.get('content')}' in {result.get('elapsed')} s.", "success")
    else:
        audit("agents", "task.ping", target=row.name, status="error",
              detail=str(result.get("error")), source_correlation_id=task_id)
        flash(f"'{row.name}' failed the ping: {result.get('error')}", "danger")
    return redirect(url_for("agents_admin.agents_list"))


@agents_admin_bp.route("/<int:agent_id>/networks", methods=["POST"])
@super_admin_required
def agent_networks(agent_id):
    row = _agent_or_404(agent_id)
    if row is None:
        return redirect(url_for("agents_admin.agents_list"))
    nets, err = _parse_networks(request.form.get("reachable_networks", ""))
    if err:
        flash(err, "danger")
        return redirect(url_for("agents_admin.agents_list"))
    before = row.reachable_networks
    row.reachable_networks = nets
    db.session.commit()
    audit("agents", "agent.networks", target=row.name,
          detail=f"{','.join(before) or '-'} → {','.join(nets) or '-'}")
    flash(f"Reachable networks for '{row.name}' updated.", "success")
    return redirect(url_for("agents_admin.agents_list"))


# ── Settings (RA-B router): networks reachable from the server itself ────

@agents_admin_bp.route("/settings", methods=["GET", "POST"])
@super_admin_required
def agents_settings():
    """`platform_settings.server_reachable_networks` — the CIDRs the
    FlexEdge host can reach directly. The router (shared/agent_router)
    runs a task locally when no online agent covers its targets but
    these networks do ("pure local execution")."""
    pool = get_pool()
    if request.method == "POST":
        nets, err = _parse_networks(request.form.get("server_reachable_networks", ""))
        if err:
            flash(err, "danger")
            return redirect(url_for("agents_admin.agents_settings"))
        before = agent_router.server_reachable_networks()
        me_email = (session.get("user") or {}).get("email")
        agent_router.set_server_reachable_networks(nets, by_email=me_email)
        audit("agents", "settings.update", target="server_reachable_networks",
              detail=f"{','.join(before) or '-'} → {','.join(nets) or '-'}")
        flash("Server reachable networks updated.", "success")
        return redirect(url_for("agents_admin.agents_settings"))
    return render_template(
        "admin/agents_settings.html",
        server_networks=agent_router.server_reachable_networks(),
        poll_wait_s=pool.cfg.poll_wait_max_s,
        offline_after_s=pool.cfg.offline_after_s,
        heartbeat_every_s=pool.cfg.heartbeat_every_s,
    )


# ── New-agent picker: subnets on the Domain's firewall interfaces ────────

@agents_admin_bp.route("/domain-networks/<int:domain_id>")
@super_admin_required
def domain_networks(domain_id):
    """JSON for the New-agent form: every subnet attached to an interface of
    the chosen Domain's firewalls, as reachable-network candidates.

    Reads through the shared `engines` + `cluster` caches (Loose TTL, the
    same entries /engines/clusters fills) with THAT Domain's API key — the
    Super Admin creating the agent may have another Domain active.
    `?refresh=1` refetches from SMC. One engine failing doesn't hide the
    others; its error is reported alongside."""
    domain = Domain.query.get(domain_id)
    if domain is None or not domain.is_active:
        return jsonify({"ok": False, "error": "unknown or inactive Domain"}), 404
    from webapp import domain_objects
    from webapp.dhcp_manager import _smc_cfg_dict
    refresh = request.args.get("refresh") == "1"
    try:
        cfg = _smc_cfg_dict(domain)
        engines, cv = domain_objects.engines(domain, cfg, refresh=refresh)
    except Exception as exc:  # noqa: BLE001 — SMC down / bad key: tell the form, don't 500
        log.warning("domain_networks(%s): engine list failed: %s", domain.slug, exc)
        return jsonify({"ok": False, "error": f"SMC inventory unavailable: {exc}"}), 502
    clusters, errors = [], []
    for eng in engines:
        try:
            _detail, ccv = domain_objects.cluster(domain, cfg, eng.name, refresh=refresh)
            clusters.append((eng.name, (ccv.data if ccv else None) or {}))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{eng.name}: {exc}")
    return jsonify({
        "ok": True,
        "domain": domain.slug,
        "engines": len(engines),
        "networks": agent_router.interface_networks(clusters),
        "errors": errors,
        "cached": bool(cv and cv.served_from_cache) and not refresh,
        "age_seconds": int(cv.age_seconds) if cv and cv.age_seconds is not None else None,
    })
