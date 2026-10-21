#!/usr/bin/env python3
"""
remote_agent.py — FlexEdgeAdmin's outbound-only remote agent. ONE file,
ZERO dependencies: Python 3.9+ standard library only (the python3 macOS and
most Linux distributions ship is enough — no venv, no pip).

Derived from remote-agent-kit (the protocol reference, kept in-tree); owned
and versioned by FlexEdge since RA-C — design, phases and operator procedure
in docs/RemoteAgents.md. It runs on a machine inside a customer network and
only ever DIALS OUT to the Portal:

    enroll (once) → register → heartbeat every N s → long-poll for tasks
    → run them locally → post the result (streaming partials when asked)

It opens no inbound port. The server never needs to reach the machine.

CONFIGURATION (environment, or the matching --flags)

    AGENT_SERVER_URL      https://your-server.example   (required)
    AGENT_ENROLL_TOKEN    et_…  the ONE-TIME enrollment token (valid 15 min,
                          single use) from the admin UI / POST /api/agents/new.
                          Redeemed on this machine; the key received is stored
                          in the macOS Keychain or ~/.remote-agent/key-<name>
                          (mode 600). Never typed again, never in a plist.
    AGENT_KEY             ak_…  a raw key instead (development only)
    AGENT_NAME            label; the server identifies the agent by its key
                          (default: hostname slug)
    AGENT_HEARTBEAT_EVERY seconds (5..600); unset = server's advertised value
    AGENT_POLL_WAIT       long-poll seconds (1..300); unset = server's value
    AGENT_AUTOUPDATE      0/1; unset = server's advertised default
    AGENT_KEY_FILE        override the key file path (skips the Keychain)
    AGENT_DEVICE_FILE     where the first launch records the device fingerprint
                          (default ~/.remote-agent/device)
    AGENT_EXECUTORS       optional "module[:function]" imported at start to
                          register project-specific executors (see EXECUTORS)

SELF-UPDATE

    SCRIPT_VERSION is sha256[:16] of this file, sent on register/heartbeat.
    The server answers with the version it distributes + update_url. When
    they differ the agent — between tasks only, at most once per 10 min,
    never with --once — downloads the file, checks the X-Agent-Script-Version
    header against the download's sha256 and that it compiles, atomically
    replaces this file and re-executes itself. The URL must be on the agent's
    own server origin.

DEVICE BINDING

    Every launch computes a salted sha256 of stable hardware ids (never the
    raw ids), compares it with the copy kept in AGENT_DEVICE_FILE (a copied
    install refuses to start, exit 3) and sends it on every request as
    X-Agent-Device; the server binds it on first sight and refuses any other
    machine with 403 (an admin re-binds).

EXECUTORS

    A task is {"task_id", "attempt", "type", ...}. EXECUTORS maps a type to
    a function(task, ctx) -> result dict {"ok": bool, "content"?, "error"?,
    "usage"?, "data"?}. `ctx.partial(text)` streams a chunk to the server
    (the consumer sees it live); `ctx.thinking()` flags a reasoning phase.
    Built-ins (allow-listed, never free-form — the agent never runs a
    command, path or raw query it receives):
      ping            liveness round-trip.
      netsight-query  one NAMED query (connect/devices/device/ports/vlans)
                      against an Extreme Site Engine the Portal cannot reach.
                      The task carries a one-shot `secret_ref`, never the
                      client secret: the executor redeems it once at
                      GET /agent/secret?ref= with its own key, and the
                      server's cert must be pinned (`cert_sha256`).
    Register your own with `register_executor("my-type", fn)` from the
    module named in AGENT_EXECUTORS. A crash inside an executor never kills
    the agent: it is reported as {"ok": false, "error"}.

EXIT CODES   0 ok · 1 server unreachable · 2 bad configuration · 3 device
             mismatch · 4 enrollment refused

SIGTERM      sets the stop flag; the current task finishes and is reported,
             then the loops end (a second SIGTERM is not needed).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import logging
import os
import platform
import py_compile
import random
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

LOG = logging.getLogger("remote_agent")

KEY_HEADER = "X-Agent-Key"
DEVICE_HEADER = "X-Agent-Device"
SCRIPT_VERSION_HEADER = "X-Agent-Script-Version"

HEARTBEAT_EVERY = 20
POLL_WAIT = 30
HEARTBEAT_RANGE = (5, 600)
POLL_WAIT_RANGE = (1, 300)
BACKOFF_MIN, BACKOFF_MAX = 1.0, 60.0
RESULT_RETRIES = 4           # a FINAL result is worth retrying; partials are not
PARTIAL_EVERY = 0.5          # s between streamed partial posts
UPDATE_EVERY = 600           # s minimum gap between self-update attempts
TASK_TIMEOUT = 600           # s default for a task without its own timeout

SCRIPT_PATH = os.path.abspath(__file__)
KEYCHAIN_SERVICE = "remote-agent"
KEYCHAIN_ACCOUNT = "remote-agent"
DEFAULT_DEVICE_FILE = os.path.expanduser("~/.remote-agent/device")
_DEVICE_SALT = "remote-agent-device-v1"

TRUE_WORDS = ("1", "true", "yes", "on")
FALSE_WORDS = ("0", "false", "no", "off")


def file_version(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except OSError:
        return None


SCRIPT_VERSION = file_version(SCRIPT_PATH)


# ===============================
# 🔧 SMALL HELPERS
# ===============================

def env_bool(name):
    """(pinned, value): pinned False when unset or unparseable."""
    raw = (os.environ.get(name) or "").strip().lower()
    if raw in TRUE_WORDS:
        return True, True
    if raw in FALSE_WORDS:
        return True, False
    return False, None


def clamp_num(value, lo, hi):
    try:
        val = float(value)
    except (TypeError, ValueError):
        return None
    if val != val:
        return None
    return max(lo, min(hi, val))


def env_num(name, lo, hi):
    raw = os.environ.get(name)
    return clamp_num(raw, lo, hi) if raw not in (None, "") else None


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", text or "").strip("-")[:40] or "agent"


def _run(cmd, timeout=5) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


class Backoff:
    def __init__(self, low=BACKOFF_MIN, high=BACKOFF_MAX):
        self.low, self.high, self.cur = low, high, low

    def next(self) -> float:
        delay = self.cur * (0.8 + 0.4 * random.random())
        self.cur = min(self.high, self.cur * 2)
        return delay

    def reset(self):
        self.cur = self.low


# ===============================
# 🌐 HTTP (urllib only)
# ===============================

class AuthError(Exception):
    """401: the key is revoked or wrong."""


class DeviceError(AuthError):
    """403: this machine is not the one bound to the agent."""


class ServerError(Exception):
    """5xx or a malformed reply."""


class HttpResponse:
    def __init__(self, status, headers, raw, stream=False):
        self.status_code = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._raw = raw
        self._content = None if stream else raw.read()
        if not stream:
            raw.close()

    def header(self, name, default=None):
        return self.headers.get(name.lower(), default)

    @property
    def content(self) -> bytes:
        if self._content is None:
            self._content = self._raw.read()
            self._raw.close()
        return self._content

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.text) if self.content else None

    def iter_lines(self):
        buf = b""
        while True:
            chunk = self._raw.read(1024)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                yield line.decode("utf-8", "replace").rstrip("\r")
        if buf:
            yield buf.decode("utf-8", "replace")
        self._raw.close()


class HttpSession:
    """A requests-like shim over urllib. Tests inject a fake with the same
    get/post signature."""

    def request(self, method, url, data=None, json_body=None, headers=None, params=None,
                timeout=30, stream=False):
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        body = None
        hdrs = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        elif data is not None:
            body = data if isinstance(data, bytes) else str(data).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            raw = urllib.request.urlopen(req, timeout=timeout)
            return HttpResponse(raw.status, dict(raw.headers), raw, stream=stream)
        except urllib.error.HTTPError as exc:
            return HttpResponse(exc.code, dict(exc.headers or {}), exc, stream=False)
        except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
            raise OSError(f"{method} {url}: {getattr(exc, 'reason', exc)}") from exc

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


# ===============================
# 🔐 KEY STORAGE + ENROLLMENT
# ===============================

def key_file_path(name) -> str:
    return os.environ.get("AGENT_KEY_FILE") or os.path.expanduser(f"~/.remote-agent/key-{_slug(name)}")


def _use_keychain() -> bool:
    return sys.platform == "darwin" and not os.environ.get("AGENT_KEY_FILE")


def save_key(name, key, runner=None) -> str:
    """Stores the key; returns "keychain" or "file"."""
    runner = runner or subprocess.run
    service = f"{KEYCHAIN_SERVICE}.{_slug(name)}"
    if _use_keychain():
        try:
            out = runner(["security", "add-generic-password", "-a", KEYCHAIN_ACCOUNT,
                          "-s", service, "-w", key, "-U"], capture_output=True, text=True,
                         timeout=20)
            if out.returncode == 0:
                return "keychain"
            LOG.warning("keychain store failed (%s); using a file", (out.stderr or "").strip()[:200])
        except (OSError, subprocess.SubprocessError) as exc:
            LOG.warning("keychain unavailable (%s); using a file", exc)
    path = key_file_path(name)
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    return "file"


def load_key(name, runner=None) -> str:
    runner = runner or subprocess.run
    service = f"{KEYCHAIN_SERVICE}.{_slug(name)}"
    if _use_keychain():
        try:
            out = runner(["security", "find-generic-password", "-a", KEYCHAIN_ACCOUNT,
                          "-s", service, "-w"], capture_output=True, text=True, timeout=20)
            if out.returncode == 0 and (out.stdout or "").strip():
                return out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        with open(key_file_path(name), "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def enroll(server_url, token, name, device, session=None) -> str:
    """Redeems the one-time token: returns the minted key. AuthError with
    the server's reason (expired / used / unknown / revoked)."""
    session = session or HttpSession()
    body = {"token": token, "device": device, "host": socket.gethostname(), "agent_name": name}
    resp = session.post(server_url.rstrip("/") + "/agent/enroll", json_body=body, timeout=30)
    if resp.status_code != 200:
        try:
            reason = (resp.json() or {}).get("error") or ""
        except (ValueError, AttributeError):
            reason = ""
        raise AuthError(f"enrollment refused ({resp.status_code}): {reason or 'see the server log'}")
    key = (resp.json() or {}).get("key") or ""
    if not key:
        raise AuthError("enrollment answered without a key")
    return key


# ===============================
# 🔏 DEVICE FINGERPRINT
# ===============================

def _device_components():
    parts = []
    if sys.platform == "darwin":
        text = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        for key in ("IOPlatformUUID", "IOPlatformSerialNumber"):
            m = re.search(rf'"{key}"\s*=\s*"([^"]+)"', text)
            if m:
                parts.append(f"{key}={m.group(1)}")
    elif sys.platform.startswith("linux"):
        for path in ("/etc/machine-id", "/sys/class/dmi/id/product_uuid",
                     "/sys/class/dmi/id/board_serial"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    value = f.read().strip()
            except OSError:
                value = ""
            if value:
                parts.append(f"{os.path.basename(path)}={value}")
    elif sys.platform == "win32":
        text = _run(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        m = re.search(r"MachineGuid\s+REG_SZ\s+(\S+)", text)
        if m:
            parts.append(f"MachineGuid={m.group(1)}")
    if parts:
        return parts, "hardware"
    return [f"node={uuid.getnode():012x}", f"host={socket.gethostname()}"], "weak"


def device_fingerprint(components=None) -> str:
    parts = components if components is not None else _device_components()[0]
    return hashlib.sha256((_DEVICE_SALT + "|" + "|".join(parts)).encode("utf-8")).hexdigest()


def device_identity():
    parts, strength = _device_components()
    return device_fingerprint(parts), strength


def check_device_file(path, fingerprint) -> str:
    """First launch records the fingerprint ("enrolled"); later launches
    must match ("ok") or raise DeviceError (copied install)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            stored = f.read().strip()
    except OSError:
        stored = ""
    if stored:
        if stored == fingerprint:
            return "ok"
        raise DeviceError(
            f"this agent was first launched on a different machine ({path} does not match "
            f"this hardware). Only the designated machine may run it; after a hardware change "
            f"an admin must re-bind the agent and you must delete {path}.")
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(fingerprint + "\n")
    return "enrolled"


# ===============================
# 🖥️ LOCAL FACTS
# ===============================

def machine_info() -> dict:
    info = {"host": socket.gethostname(), "platform": f"{platform.system()} {platform.machine()}",
            "cpus": os.cpu_count()}
    try:
        if sys.platform == "darwin":
            mem = int(_run(["sysctl", "-n", "hw.memsize"]).strip() or 0)
            info["memory_gb"] = round(mem / 2 ** 30, 1) if mem else None
        elif sys.platform.startswith("linux"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        info["memory_gb"] = round(int(line.split()[1]) / 2 ** 20, 1)
                        break
    except (OSError, ValueError):
        pass
    return info


def free_memory_gb():
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return round(int(line.split()[1]) / 2 ** 20, 1)
        elif sys.platform == "darwin":
            text = _run(["vm_stat"])
            page = int(re.search(r"page size of (\d+)", text).group(1))
            free = sum(int(re.search(rf"{k}:\s+(\d+)", text).group(1))
                       for k in ("Pages free", "Pages inactive", "Pages speculative")
                       if re.search(rf"{k}:\s+(\d+)", text))
            return round(free * page / 2 ** 30, 1)
    except (OSError, ValueError, AttributeError):
        pass
    return None


def load1():
    try:
        return round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        return None


# ===============================
# 🧩 EXECUTORS
# ===============================

class TaskContext:
    """What an executor gets besides the task: streaming + settings."""

    def __init__(self, agent, task):
        self.agent = agent
        self.task = task
        self.stop = agent.stop

    def partial(self, text: str):
        if text:
            self.agent.post_partial(self.task["task_id"], text)

    def thinking(self):
        self.agent.post_partial(self.task["task_id"], "", reasoning=True)


EXECUTORS = {}


def register_executor(task_type: str, fn=None):
    """register_executor("t", fn) or as a decorator: @register_executor("t")."""
    if fn is None:
        return lambda f: register_executor(task_type, f)
    EXECUTORS[task_type] = fn
    return fn


def capabilities() -> list:
    """What this agent advertises on register/heartbeat. Executors may add
    richer entries (e.g. models) through `CAPABILITY_PROVIDERS`."""
    caps = [f"task:{t}" for t in sorted(EXECUTORS)]
    for provider in CAPABILITY_PROVIDERS:
        try:
            caps.extend(provider() or [])
        except Exception as exc:  # noqa: BLE001 — a probe never breaks a heartbeat
            LOG.debug("capability provider failed: %s", exc)
    return caps


CAPABILITY_PROVIDERS = []


@register_executor("ping")
def exec_ping(task, ctx):
    return {"ok": True, "content": "pong", "data": {"attempt": task.get("attempt")}}


# === BEGIN embedded shared/netsight_client.py (keep in sync; tests/agents/test_agent.py asserts equality) ===
"""
NetSight (Extreme Site Engine / XIQ-SE) GraphQL NBI client — pure protocol
logic, no CLI, no Flask, **standard library only**. Imported by
cli/netsight.py, by the webapp (webapp/netsight_manager.py) and embedded
verbatim in agent/remote_agent.py for the `netsight-query` executor (the
agent is a single stdlib-only file, so this module must stay that way —
tests/agents/test_agent.py asserts the embedded copy is byte-identical).

Verified against Site Engine 25.08 (2026-10-21): the token endpoint takes
HTTP Basic (client_id:client_secret); /nbi/graphql takes Bearer.

TLS: Site Engine ships a self-signed cert with no SAN, so CA + hostname
verification can't succeed by IP. With `cert_sha256` the client pins the
exact leaf certificate — handshake without CA verification, then compare
sha256(DER) to the pin BEFORE a single byte of the request is sent; on
mismatch the socket is closed and NetSightTlsError raised. Without a pin
the default verified context is used; `insecure=True` disables
verification silently — it is the CALLER's job to warn the operator (the
CLI does; the webapp and the agent never allow it).
"""

import base64
import hashlib
import http.client
import json
import re
import socket
import ssl
import time

TOKEN_PATH = "/oauth/token/access-token?grant_type=client_credentials"
GRAPHQL_PATH = "/nbi/graphql"
NBI_ROOTS = ("network", "accessControl", "policy", "administration",
             "inventory", "workflows")

# What may be interpolated into a GraphQL query as a device address. The
# agent receives `ip` from a task, so this is the injection guard.
_ADDR_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
                      r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")


def normalise_fingerprint(value):
    """'AA:BB:…' / 'aabb…' → lowercase hex without separators."""
    return (value or "").replace(":", "").replace(" ", "").strip().lower()


class NetSightError(Exception):
    """Any failure talking to NetSight (auth, GraphQL, transport)."""


class NetSightTlsError(NetSightError):
    """Certificate pin mismatch or TLS handshake failure."""


class NetSightTransportError(NetSightError):
    """Connect / DNS / timeout / connection reset."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that verifies the peer's leaf-cert SHA-256 right after
    the handshake, before anything is written."""

    def __init__(self, host, port, *, pin, timeout):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # replaced by the pin check
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._pin = pin

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True) or b""
        seen = hashlib.sha256(der).hexdigest()
        if seen != self._pin:
            self.close()
            raise NetSightTlsError(
                f"certificate fingerprint mismatch: server presented "
                f"{seen[:16]}… expected {self._pin[:16]}…")


class NetSightClient:
    """Minimal GraphQL NBI client (see module docstring for TLS modes)."""

    def __init__(self, host, client_id, client_secret, port=8443,
                 cert_sha256=None, ca_bundle=None, insecure=False, timeout=30):
        self.host = host
        self.port = int(port or 8443)
        self.base = f"https://{host}:{self.port}"
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.pin = normalise_fingerprint(cert_sha256) if cert_sha256 else ""
        if self.pin and len(self.pin) != 64:
            raise NetSightError("cert_sha256 must be a 64-hex SHA-256 fingerprint")
        self.ca_bundle = ca_bundle
        self.insecure = bool(insecure) and not self.pin
        self.token = None

    # -- Transport ---------------------------------------------------------

    def _connection(self, timeout):
        if self.pin:
            return _PinnedHTTPSConnection(self.host, self.port, pin=self.pin,
                                          timeout=timeout)
        if self.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(cafile=self.ca_bundle)
        return http.client.HTTPSConnection(self.host, self.port, timeout=timeout,
                                           context=ctx)

    def _request(self, method, path, body=None, headers=None, timeout=None):
        """One HTTPS round-trip → (status, text). Transport problems become
        NetSightTransportError / NetSightTlsError."""
        hdrs = {"Accept": "application/json"}
        hdrs.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        conn = self._connection(timeout or self.timeout)
        try:
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            text = resp.read().decode("utf-8", "replace")
            return resp.status, text
        except NetSightError:
            raise
        except ssl.SSLError as exc:
            raise NetSightTlsError(f"TLS handshake failed: {exc}") from None
        except (socket.timeout, TimeoutError) as exc:
            raise NetSightTransportError(f"timeout talking to {self.base}: {exc}") from None
        except (OSError, http.client.HTTPException) as exc:
            raise NetSightTransportError(f"cannot reach {self.base}: {exc}") from None
        finally:
            conn.close()

    # -- Protocol ----------------------------------------------------------

    def login(self):
        basic = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode("utf-8")).decode("ascii")
        status, text = self._request("POST", TOKEN_PATH,
                                     headers={"Authorization": "Basic " + basic,
                                              "Content-Length": "0"})
        if status < 200 or status >= 300:
            raise NetSightError(f"Token request failed: HTTP {status} {text[:200].strip()}")
        try:
            body = json.loads(text)
        except ValueError:
            raise NetSightError(f"Token response was not JSON: {text[:200]!r}") from None
        self.token = body.get("access_token") or body.get("token")
        if not self.token:
            raise NetSightError(f"Token response had no access_token: {body}")
        return self.token

    def query(self, query, variables=None):
        if not self.token:
            self.login()
        status, text = self._request(
            "POST", GRAPHQL_PATH,
            body={"query": query, "variables": variables or {}},
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=max(self.timeout, 60),
        )
        if status < 200 or status >= 300:
            raise NetSightError(f"GraphQL HTTP {status}: {text[:500]}")
        try:
            data = json.loads(text)
        except ValueError:
            raise NetSightError(f"GraphQL response was not JSON: {text[:200]!r}") from None
        if data.get("errors"):
            msgs = "; ".join(e.get("message", "?") for e in data["errors"])
            raise NetSightError(f"GraphQL error: {msgs}")
        return data.get("data") or {}

    # -- Typed helpers -----------------------------------------------------

    DEVICE_FIELDS = ("ip sysName nickName deviceDisplayFamily firmware up down "
                     "sitePath status sysLocation sysContact baseMac")

    @staticmethod
    def _addr(ip):
        """Validate an address before it is interpolated into a query."""
        ip = (ip or "").strip()
        if not _ADDR_RE.match(ip):
            raise NetSightError(f"invalid device address: {ip!r}")
        return ip

    def devices(self):
        return self.query(f"{{ network {{ devices {{ {self.DEVICE_FIELDS} }} }} }}") \
            ["network"]["devices"] or []

    def device(self, ip):
        ip = self._addr(ip)
        q = f"""{{ network {{ device(ip: "{ip}") {{ {self.DEVICE_FIELDS}
                 deviceData {{ serialNumber productName physicalPortCount
                               macAddress sysDescr lastSeenTime }} }} }} }}"""
        return self.query(q)["network"]["device"]

    def ports(self, ip):
        ip = self._addr(ip)
        q = f"""{{ network {{ device(ip: "{ip}") {{ sysName deviceData {{ ports {{
                 portName portAlias portType portAdmin portPvid untagged tagged
                 portNeighborAddress portNeighborPortName uplink isLagMaster lagId
                 }} }} }} }} }}"""
        dev = self.query(q)["network"]["device"]
        if not dev:
            raise NetSightError(f"No device with IP {ip}")
        return dev["sysName"], (dev["deviceData"] or {}).get("ports") or []

    def vlans(self, ip):
        ip = self._addr(ip)
        q = f"""{{ network {{ deviceVlans(ip: "{ip}") {{
                 vid name primaryIp netmask vrName dot1qVlanStaticEgressPorts
                 dot1qVlanStaticUntaggedPorts }} }} }}"""
        return self.query(q)["network"]["deviceVlans"] or []

    def connect_check(self):
        """Login + probe every NBI root. JSON-serialisable summary:
        {ok, server, roots: {name: "ok"|"denied"|<error>}, elapsed_ms, error?}.
        `ok` is True only when the token was issued AND every root is readable.
        Never raises on NetSight-level errors; transport / TLS errors do
        propagate (NetSightTransportError / NetSightTlsError)."""
        started = time.monotonic()
        out = {"ok": False, "server": self.base, "roots": {}, "elapsed_ms": 0}
        try:
            self.login()
        except (NetSightTlsError, NetSightTransportError):
            raise
        except NetSightError as exc:
            out["error"] = str(exc)
            out["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            return out
        for s in NBI_ROOTS:
            try:
                self.query(f"{{ {s} {{ __typename }} }}")
                out["roots"][s] = "ok"
            except (NetSightTlsError, NetSightTransportError):
                raise
            except NetSightError as e:
                out["roots"][s] = ("denied" if "Insufficient capabilities" in str(e)
                                   else str(e)[:200])
        out["ok"] = all(v == "ok" for v in out["roots"].values())
        if not out["ok"]:
            bad = [k for k, v in out["roots"].items() if v != "ok"]
            out["error"] = "not readable: " + ", ".join(bad)
        out["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return out


# ---------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------

def portlist_from_hex(mask):
    """Decode a Q-BRIDGE-MIB PortList hex string (bit 1 = port 1, MSB first)."""
    if not mask:
        return ""
    ports = []
    for byte_idx in range(0, len(mask), 2):
        byte = int(mask[byte_idx:byte_idx + 2], 16)
        for bit in range(8):
            if byte & (0x80 >> bit):
                ports.append(byte_idx // 2 * 8 + bit + 1)
    # Collapse runs: 1,2,3,5 -> 1-3,5
    out, start, prev = [], None, None
    for p in ports:
        if start is None:
            start = prev = p
        elif p == prev + 1:
            prev = p
        else:
            out.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = p
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(out)


def tname(t):
    """Render a GraphQL introspection type reference as `Name`, `[Name]`, `Name!`."""
    if not t:
        return "?"
    if t.get("name"):
        return t["name"]
    inner = tname(t.get("ofType"))
    return f"[{inner}]" if t["kind"] == "LIST" else f"{inner}!"
# === END embedded shared/netsight_client.py ===


NETSIGHT_QUERIES = ("connect", "devices", "device", "ports", "vlans")
SECRET_REDEEM_TIMEOUT = 15


def _redeem_secret(agent, ref):
    """GET /agent/secret?ref= with the agent's own key + device. Returns
    (secret, "") or (None, reason). Never logs the ref or the secret."""
    if not isinstance(ref, str) or not ref:
        return None, "secret_ref missing"
    try:
        resp = agent.session.get(agent.server + "/agent/secret", params={"ref": ref},
                                 headers=agent._headers(), timeout=SECRET_REDEEM_TIMEOUT)
    except (OSError, ValueError) as exc:
        return None, f"secret ref redeem failed: {exc.__class__.__name__}"
    if resp.status_code != 200:
        return None, f"secret ref refused (HTTP {resp.status_code})"
    try:
        secret = (resp.json() or {}).get("secret")
    except (ValueError, AttributeError):
        secret = None
    if not secret:
        return None, "secret ref refused (empty reply)"
    return secret, ""


@register_executor("netsight-query")
def exec_netsight_query(task, ctx):
    """{"host","port","cert_sha256","client_id","secret_ref","query","args":{ip},"timeout"}
    → {"ok": true, "content": <JSON rows>, "query", "elapsed_ms"}."""
    q = task.get("query")
    if q not in NETSIGHT_QUERIES:
        return {"ok": False, "error": f"query not allowed: {q!r} "
                                      f"(allowed: {', '.join(NETSIGHT_QUERIES)})"}
    host = str(task.get("host") or "").strip()
    if not host:
        return {"ok": False, "error": "host required", "query": q}
    pin = normalise_fingerprint(task.get("cert_sha256"))
    if not pin:
        return {"ok": False, "error": "pinned fingerprint required (cert_sha256)", "query": q}
    args = task.get("args") if isinstance(task.get("args"), dict) else {}
    ip = args.get("ip")
    if q in ("device", "ports", "vlans") and not ip:
        return {"ok": False, "error": f"query {q!r} needs args.ip", "query": q}
    port = task.get("port") or 8443
    timeout = float(task.get("timeout") or 30)
    ctx.partial(f"netsight-query {q} → {host}:{port}\n")

    secret, reason = _redeem_secret(ctx.agent, task.get("secret_ref"))
    if secret is None:
        return {"ok": False, "error": reason, "query": q}
    try:
        client = NetSightClient(host, task.get("client_id") or "", secret, port=port,
                                cert_sha256=pin, timeout=timeout)
    finally:
        secret = None   # the client holds it; nothing else should
    started = time.monotonic()
    try:
        if q == "connect":
            data = client.connect_check()
        elif q == "devices":
            data = client.devices()
        elif q == "device":
            data = client.device(ip)
        elif q == "ports":
            sys_name, ports = client.ports(ip)
            data = {"sysName": sys_name, "ports": ports}
        else:
            data = client.vlans(ip)
    except NetSightError as exc:
        return {"ok": False, "error": str(exc)[:500], "query": q}
    return {"ok": True, "content": json.dumps(data), "query": q,
            "elapsed_ms": int((time.monotonic() - started) * 1000)}


def load_extra_executors(spec: str):
    """AGENT_EXECUTORS="pkg.module" imports it (its decorators register) or
    "pkg.module:setup" also calls setup(register_executor)."""
    if not spec:
        return
    mod_name, _, fn_name = spec.partition(":")
    sys.path.insert(0, os.path.dirname(SCRIPT_PATH))
    mod = importlib.import_module(mod_name)
    if fn_name:
        getattr(mod, fn_name)(register_executor)
    LOG.info("executors: %s", ", ".join(sorted(EXECUTORS)))


# ===============================
# 🤖 THE AGENT
# ===============================

class Agent:
    """One agent process. Every I/O seam is injectable for tests:
    `session` (HttpSession-like), `runner` (subprocess.run-like), `sleep`,
    `clock`, `execv`."""

    def __init__(self, server_url, key, name=None, *, device="", session=None, runner=None,
                 sleep=time.sleep, clock=time.monotonic, script_path=None,
                 script_version=None, autoupdate=None, execv=None, heartbeat_every=None,
                 poll_wait=None):
        self.server = (server_url or "").rstrip("/")
        self.key = key or ""
        self.device = device or ""
        self.name = name or _slug(socket.gethostname().split(".")[0])
        self.session = session or HttpSession()
        self.runner = runner or subprocess.run
        self.sleep, self.clock = sleep, clock
        hb = (clamp_num(heartbeat_every, *HEARTBEAT_RANGE) if heartbeat_every is not None
              else env_num("AGENT_HEARTBEAT_EVERY", *HEARTBEAT_RANGE))
        self._heartbeat_pinned = hb is not None
        self.heartbeat_every = hb if hb is not None else HEARTBEAT_EVERY
        pw = (clamp_num(poll_wait, 0, POLL_WAIT_RANGE[1]) if poll_wait is not None
              else env_num("AGENT_POLL_WAIT", *POLL_WAIT_RANGE))
        self._poll_pinned = pw is not None
        self.poll_wait = pw if pw is not None else POLL_WAIT
        env_pinned, env_value = env_bool("AGENT_AUTOUPDATE")
        if autoupdate is not None:
            self.autoupdate, self._autoupdate_pinned = bool(autoupdate), True
        elif env_pinned:
            self.autoupdate, self._autoupdate_pinned = env_value, True
        else:
            self.autoupdate, self._autoupdate_pinned = True, False
        self.script_path = script_path or SCRIPT_PATH
        self.script_version = script_version if script_version is not None else SCRIPT_VERSION
        self.execv = execv or os.execv
        self.once = False
        self.pending_update = None
        self._last_update_attempt = None
        self._update_lock = threading.Lock()
        self.current_task = None
        self.stop = threading.Event()
        self.backoff = Backoff()
        self.registered = False

    # --- server I/O -----------------------------------------------------
    def _headers(self) -> dict:
        headers = {KEY_HEADER: self.key, "Content-Type": "application/json"}
        if self.device:
            headers[DEVICE_HEADER] = self.device
        return headers

    def _check(self, resp):
        if resp.status_code == 401:
            raise AuthError("server rejected the agent key (401): revoked or wrong key")
        if resp.status_code == 403:
            try:
                reason = (resp.json() or {}).get("error") or ""
            except (ValueError, AttributeError):
                reason = ""
            raise DeviceError("server refused this machine (403): "
                              + (reason or "the agent is bound to another device"))
        if resp.status_code >= 500:
            raise ServerError(f"server answered {resp.status_code}")
        return resp

    def _post(self, path, body, timeout=30):
        resp = self.session.post(self.server + path, json_body=body, headers=self._headers(),
                                 timeout=timeout)
        return self._check(resp)

    def info(self, full=True) -> dict:
        info = {"capabilities": capabilities(), "script_version": self.script_version,
                "free_memory_gb": free_memory_gb(), "load1": load1(),
                "busy": self.current_task is not None}
        if full:
            info.update(machine_info())
        return info

    def register(self) -> dict:
        resp = self._post("/agent/register", self.info(full=True))
        if resp.status_code != 200:
            raise ServerError(f"register answered {resp.status_code}")
        LOG.info("registered with %s as %s", self.server, self.name)
        body = resp.json()
        self.registered = True
        self.note_server_reply(body)
        return body

    def register_with_backoff(self) -> bool:
        while not self.stop.is_set():
            try:
                self.register()
                self.backoff.reset()
                return True
            except AuthError as exc:
                LOG.error("%s", exc)
                self.sleep(BACKOFF_MAX)
            except (OSError, ServerError, ValueError) as exc:
                delay = self.backoff.next()
                LOG.warning("register failed (%s); retrying in %.0fs", exc, delay)
                self.sleep(delay)
        return False

    def send_heartbeat(self):
        """Best effort. When the server holds no registration (it restarted),
        presence.registered is False and the agent registers again."""
        try:
            resp = self._post("/agent/heartbeat", self.info(full=False), timeout=15)
        except Exception as exc:  # noqa: BLE001 — heartbeats are best effort
            LOG.debug("heartbeat failed: %s", exc)
            return
        try:
            body = resp.json() if resp.status_code == 200 else None
        except Exception:  # noqa: BLE001
            body = None
        self.note_server_reply(body)
        presence = body.get("presence") if isinstance(body, dict) else None
        if isinstance(presence, dict) and presence.get("registered") is False:
            LOG.info("server has no registration for %s; re-registering", self.name)
            try:
                self.register()
            except Exception as exc:  # noqa: BLE001 — next heartbeat retries
                LOG.warning("re-register failed: %s", exc)

    def note_server_reply(self, body):
        """Adopts advertised defaults (unless pinned) and notes a pending
        script update when the server's version differs from ours."""
        if not isinstance(body, dict):
            return
        hb = clamp_num(body.get("heartbeat_every"), *HEARTBEAT_RANGE)
        if hb is not None and not self._heartbeat_pinned:
            self.heartbeat_every = hb
        pw = clamp_num(body.get("poll_wait"), *POLL_WAIT_RANGE)
        if pw is not None and not self._poll_pinned:
            self.poll_wait = pw
        adv = body.get("autoupdate")
        if isinstance(adv, bool) and not self._autoupdate_pinned:
            self.autoupdate = adv
        version = body.get("script_version")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{8,64}", version):
            return
        if version == self.script_version:
            self.pending_update = None
            return
        url = body.get("update_url")
        if not isinstance(url, str) or not url.startswith(self.server + "/"):
            url = self.server + "/agent/script"
        if not self.pending_update or self.pending_update.get("version") != version:
            LOG.info("server distributes agent script %s (running %s)", version, self.script_version)
        self.pending_update = {"version": version, "url": url}

    # --- self-update ----------------------------------------------------
    def maybe_self_update(self) -> bool:
        pending = self.pending_update
        if not pending or not self.autoupdate or self.once or self.current_task:
            return False
        now = self.clock()
        if self._last_update_attempt is not None and now - self._last_update_attempt < UPDATE_EVERY:
            return False
        if not self._update_lock.acquire(blocking=False):
            return False
        try:
            self._last_update_attempt = now
            version = self.self_update(pending["url"])
        finally:
            self._update_lock.release()
        if not version:
            return False
        self.restart()
        return True

    def self_update(self, url):
        """Downloads, verifies (header == sha256, compiles) and installs the
        new file atomically. Returns the version, or None (logged)."""
        new_path = self.script_path + ".new"
        try:
            resp = self.session.get(url, timeout=60)
            if resp.status_code != 200:
                raise ValueError(f"download answered {resp.status_code}")
            data = resp.content
            header = (resp.header(SCRIPT_VERSION_HEADER) or "").strip()
            got = hashlib.sha256(data).hexdigest()[:16]
            if not header or header != got:
                raise ValueError(f"version header {header or '(missing)'} != sha256 {got}")
            with open(new_path, "wb") as f:
                f.write(data)
            cfile = new_path + "c"
            try:
                py_compile.compile(new_path, cfile=cfile, doraise=True)
            finally:
                try:
                    os.remove(cfile)
                except OSError:
                    pass
            try:
                os.chmod(new_path, os.stat(self.script_path).st_mode & 0o7777)
            except OSError:
                pass
            os.replace(new_path, self.script_path)
        except Exception as exc:  # noqa: BLE001 — retried after UPDATE_EVERY
            LOG.warning("self-update failed (%s); retrying in %ds", exc, UPDATE_EVERY)
            try:
                os.remove(new_path)
            except OSError:
                pass
            return None
        LOG.info("updated to %s", got)
        self.script_version = got
        return got

    def restart(self):
        self.stop.set()
        for handler in logging.getLogger().handlers:
            try:
                handler.flush()
            except Exception:  # noqa: BLE001
                pass
        self.execv(sys.executable, [sys.executable, self.script_path, *sys.argv[1:]])

    # --- tasks ----------------------------------------------------------
    def heartbeat_loop(self):
        while not self.stop.wait(self.heartbeat_every):
            self.send_heartbeat()

    def poll_once(self, wait=None):
        """One long-poll. Returns the handled task id, or None when idle."""
        if wait is None:
            wait = self.poll_wait
        params = {"wait": wait}
        for key, val in (("load1", load1()), ("free_memory_gb", free_memory_gb())):
            if val is not None:
                params[key] = val
        resp = self.session.get(self.server + "/agent/poll", params=params,
                                headers=self._headers(), timeout=wait + 15)
        self._check(resp)
        if resp.status_code == 204:
            return None
        if resp.status_code != 200:
            raise ServerError(f"poll answered {resp.status_code}")
        try:
            task = resp.json()
        except ValueError:
            raise ServerError("poll answered non-JSON")
        if not isinstance(task, dict) or not task.get("task_id"):
            LOG.warning("ignoring malformed task: %r", task)
            return None
        self.handle_task(task)
        return task["task_id"]

    def handle_task(self, task: dict):
        task_id = task["task_id"]
        self.current_task = task_id
        started = self.clock()
        try:
            result = self.run_task(task)
            if not isinstance(result, dict):
                result = {"ok": False, "error": "executor returned no result dict"}
        except Exception as exc:  # noqa: BLE001 — a bad task must not kill the agent
            LOG.exception("task %s crashed", task_id)
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        result["elapsed"] = round(self.clock() - started, 3)
        self.current_task = None
        self.post_result(task_id, result)

    def run_task(self, task: dict) -> dict:
        fn = EXECUTORS.get(task.get("type"))
        if fn is None:
            return {"ok": False, "error": f"unknown task type: {task.get('type')!r}"}
        return fn(task, TaskContext(self, task))

    def post_result(self, task_id, result):
        body = dict(result, task_id=task_id, partial=False)
        backoff = Backoff()
        for attempt in range(RESULT_RETRIES):
            try:
                resp = self._post("/agent/result", body)
                if resp.status_code != 200:
                    LOG.warning("result for %s refused: %s", task_id, resp.status_code)
                return
            except AuthError:
                raise
            except (OSError, ServerError) as exc:
                if attempt == RESULT_RETRIES - 1:
                    LOG.error("could not deliver result for %s: %s", task_id, exc)
                    return
                self.sleep(backoff.next())

    def post_partial(self, task_id, delta, reasoning=False):
        body = {"task_id": task_id, "partial": True, "delta": delta}
        if reasoning:
            body["reasoning"] = True
        try:
            self._post("/agent/result", body, timeout=15)
        except Exception as exc:  # noqa: BLE001 — losing a partial is cosmetic
            LOG.debug("partial for %s failed: %s", task_id, exc)

    # --- loops ----------------------------------------------------------
    def run_forever(self):
        if not self.register_with_backoff():
            return
        threading.Thread(target=self.heartbeat_loop, daemon=True, name="agent-heartbeat").start()
        while not self.stop.is_set():
            try:
                self.poll_once()
                self.backoff.reset()
                self.maybe_self_update()        # between tasks only
            except AuthError as exc:
                LOG.error("%s — retrying in %.0fs", exc, BACKOFF_MAX)
                self.sleep(BACKOFF_MAX)
            except (OSError, ServerError) as exc:
                delay = self.backoff.next()
                LOG.warning("poll failed (%s); retrying in %.0fs", exc, delay)
                self.sleep(delay)
            except Exception:  # noqa: BLE001 — the loop itself must never die
                LOG.exception("unexpected error in poll loop")
                self.sleep(self.backoff.next())

    def run_once(self, wait=None):
        """Register, poll once, run at most one task. Never self-updates."""
        self.once = True
        self.register()
        return self.poll_once(wait=wait)


# ===============================
# 🚪 ENTRY POINT
# ===============================

def main(argv=None, session=None, runner=None, configure_logging=True) -> int:
    parser = argparse.ArgumentParser(description="Outbound-only remote agent")
    parser.add_argument("--url", default=os.environ.get("AGENT_SERVER_URL"))
    parser.add_argument("--key", default=os.environ.get("AGENT_KEY"))
    parser.add_argument("--enroll", default=os.environ.get("AGENT_ENROLL_TOKEN"), metavar="TOKEN",
                        help="redeem a one-time enrollment token for this machine")
    parser.add_argument("--enroll-only", action="store_true",
                        help="with --enroll: store the key and exit (the installer's step)")
    parser.add_argument("--name", default=os.environ.get("AGENT_NAME"))
    parser.add_argument("--once", action="store_true",
                        help="register, poll once, run at most one task, exit")
    parser.add_argument("--wait", type=float, default=None, help="long-poll seconds (pins it)")
    parser.add_argument("--device-file", default=os.environ.get("AGENT_DEVICE_FILE")
                        or DEFAULT_DEVICE_FILE)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    if configure_logging:
        logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s")
    name = args.name or _slug(socket.gethostname().split(".")[0])
    if args.url and not args.key and not args.enroll:
        args.key = load_key(name, runner)
    if not args.url or not (args.key or args.enroll):
        print("AGENT_SERVER_URL and AGENT_KEY (or AGENT_ENROLL_TOKEN) are required", file=sys.stderr)
        return 2
    fingerprint, strength = device_identity()
    try:
        state = check_device_file(args.device_file, fingerprint)
    except DeviceError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"cannot record the device fingerprint at {args.device_file}: {exc}", file=sys.stderr)
        return 3
    LOG.info("device %s… (%s fingerprint, %s)", fingerprint[:12], strength, state)
    if strength == "weak":
        LOG.warning("no platform hardware id found; fingerprint falls back to MAC + hostname")
    if args.enroll:
        try:
            key = enroll(args.url, args.enroll, name, fingerprint, session=session)
        except AuthError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        except (OSError, ValueError) as exc:
            print(f"server unreachable for enrollment: {exc}", file=sys.stderr)
            return 1
        where = save_key(name, key, runner)
        LOG.info("enrolled as %s; key stored in the %s", name, where)
        args.key = key
        if args.enroll_only:
            print(f"enrolled {name}: key stored in the {where}")
            return 0
    try:
        load_extra_executors(os.environ.get("AGENT_EXECUTORS") or "")
    except Exception as exc:  # noqa: BLE001
        print(f"cannot load AGENT_EXECUTORS: {exc}", file=sys.stderr)
        return 2
    agent = Agent(args.url, args.key, name, device=fingerprint, session=session, runner=runner,
                  poll_wait=args.wait)
    agent.once = bool(args.once)
    LOG.info("agent script %s (%s); executors: %s", agent.script_version, agent.script_path,
             ", ".join(sorted(EXECUTORS)))

    def _terminate(signum, frame):
        LOG.info("signal %s: finishing the current task, then stopping", signum)
        agent.stop.set()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _terminate)
        except (ValueError, OSError):   # not the main thread / unsupported
            pass

    if args.once:
        try:
            task_id = agent.run_once(wait=args.wait)
        except AuthError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except (OSError, ServerError) as exc:
            print(f"server unreachable: {exc}", file=sys.stderr)
            return 1
        print(f"handled task {task_id}" if task_id else "no task")
        return 0
    agent.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
