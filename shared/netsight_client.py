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
