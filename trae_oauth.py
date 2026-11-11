#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trae native IDE OAuth (authorization code + PKCE) for the local gateway.

Scope and evidence
------------------
This module implements the native IDE sign-in flow against Trae's own
authorization page.  The public parameters below are the ones the IDE puts on
https://www.trae.cn/authorization / https://www.trae.ai/authorization:
client_id=ono9krqynydwx5, login_version=1, auth_from=trae,
login_channel=native_ide, plugin_version=2.3.83560, auth_type=local,
redirect=0, login_trace_id/state, auth_callback_url, device/machine ids and an
S256 PKCE challenge.  Public community clients were read only as corroboration
for the shape of the authorization URL, callback fields and the ExchangeToken
response.  Their state handling (for example accepting a callback without a
single-use trace) is deliberately not copied: every callback here must match a
live, owner-bound, single-use login_trace_id.

The local callback listener is intentionally strict: it only answers
GET /authorize on 127.0.0.1:<random port>, validates Host and, when present,
Origin, sends no CORS headers, never logs the raw query string and uses
Cache-Control: no-store / Referrer-Policy: no-referrer.  Query data is not
reflected into the HTML page.

What is not done here: no real upstream login is performed by this module or
its tests.  Tests inject transport and use a temporary loopback HTTP server.
Credentials never leave the process except through on_complete(row); public
poll/complete results are filtered so tokens, PKCE verifiers and private keys
cannot be returned by accident.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

try:  # Reuse the repository's audited P-256 arithmetic.
    from trae_client import P256_N, p256_public_point
except Exception as exc:  # pragma: no cover - import environment failure
    raise RuntimeError("trae_client P-256 helpers are required") from exc

CLIENT_ID = "ono9krqynydwx5"
PLUGIN_VERSION = "2.3.83560"
APP_VERSIONS = {"cn": "3.3.100", "intl": "3.5.51"}
AUTH_URLS = {
    "cn": "https://www.trae.cn/authorization",
    "intl": "https://www.trae.ai/authorization",
}
AUTH_ORIGINS = {"cn": "https://www.trae.cn", "intl": "https://www.trae.ai"}
DEFAULT_API = {
    "cn": "https://api.trae.cn",
    "intl": "https://grow-normal.trae.ai",
}
# Fixed identity endpoint hosts (GetUserInfo), not caller-selected.
USER_INFO_HOST = {
    "cn": "https://api.trae.com.cn",
    "intl": "https://grow-normal.trae.ai",
}
HOST_WHITELIST = {
    "cn": frozenset(("api.trae.cn", "api.trae.com.cn")),
    "intl": frozenset((
        "api.trae.ai",
        "api-sg-central.trae.ai",
        "api-us-east.trae.ai",
        "grow-normal.trae.ai",
        "growsg-normal.trae.ai",
        "grow-normal.traeapi.us",
        "ug-normal.trae.ai",
        "ug-normal.us.trae.ai",
    )),
}
EXCHANGE_PATH = "/trae/api/v3/oauth/ExchangeToken"
USER_INFO_PATH = "/cloudide/api/v3/trae/GetUserInfo"
CALLBACK_PATH = "/authorize"
MAX_PENDING = 16
SESSION_TTL = 600
TERMINAL_TTL = 300
MAX_CALLBACK_PARAMS = 64
MAX_CALLBACK_BYTES = 8192
MAX_RESPONSE_BYTES = 1024 * 1024
HTTP_TIMEOUT = 30
POLL_INTERVAL = 2

_MESSAGES = {
    "invalid_realm": "不支持的账号区域",
    "invalid_platform": "不支持的平台",
    "invalid_owner": "owner 参数非法",
    "invalid_redirect_uri": "回调地址必须是 HTTPS 或 127.0.0.1",
    "too_many_sessions": "同时进行的授权会话过多，请稍后重试",
    "callback_server_failed": "无法启动本机回调监听",
    "manager_closed": "授权管理器已关闭",
    "unknown_state": "授权会话不存在或已过期",
    "owner_mismatch": "该授权会话不属于当前用户",
    "state_expired": "授权会话已过期",
    "state_cancelled": "授权已取消",
    "state_used": "该授权回调已使用，不能重放",
    "invalid_callback": "授权回调参数无效",
    "authorization_denied": "授权被拒绝",
    "authorization_expired": "授权码已过期",
    "exchange_failed": "授权换取失败",
    "identity_mismatch": "无法确认授权账号身份",
    "storage_failed": "账号保存失败，授权未生效",
    "unapproved_host": "上游地址不在允许列表",
    "unexpected": "授权处理失败",
}


class OAuthError(Exception):
    """Internal error carrying only a public-safe code."""

    def __init__(self, code: str = "unexpected"):
        self.code = str(code or "unexpected")
        super().__init__(self.code)


def _public_error(code: str, state: str | None = None) -> dict:
    code = code if code in _MESSAGES else "unexpected"
    out = {"status": "failed", "error": {"code": code,
                                         "message": _MESSAGES[code]}}
    if state:
        out["state"] = state
    return out


def _not_found() -> dict:
    return {"status": "not_found",
            "message": "授权会话不存在或已结束，请重新开始登录。"}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _default_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _canonical_platform(value: Any) -> str:
    if value is None:
        return _default_platform()
    text = str(value).strip().lower()
    aliases = {"win32": "windows", "win": "windows", "windows": "windows",
               "darwin": "macos", "mac": "macos", "osx": "macos",
               "macos": "macos", "linux": "linux"}
    result = aliases.get(text)
    if not result:
        raise OAuthError("invalid_platform")
    return result


def _canonical_realm(value: Any) -> str:
    realm = str(value or "cn").strip().lower()
    if realm not in ("cn", "intl"):
        raise OAuthError("invalid_realm")
    return realm


def _now_seconds(value: Any) -> int:
    """Best-effort epoch seconds; never trust a JWT for this."""
    if value is None or value == "":
        return 0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number <= 0:
        return 0
    if number > 100_000_000_000:      # milliseconds since epoch
        number /= 1000.0
    if number < 100_000_000:          # a duration, not an epoch
        return int(time.time() + number)
    return int(number)


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _first_text(mapping: Mapping[str, Any], *keys: str) -> str:
    value = _first(mapping, *keys)
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return ""
    return str(value)


def _value_text(value: Any) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return str(value)


def _pick_value(data: Any, *keys: str) -> Any:
    return _find_value(data, tuple(keys))


def _pick_text(data: Any, *keys: str) -> str:
    return _value_text(_pick_value(data, *keys))


def _find_value(data: Any, keys: tuple[str, ...], depth: int = 0) -> Any:
    """Find a key through Result/Data/UserInfo wrappers, without JWT decoding."""
    if depth > 5:
        return None
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if value not in (None, ""):
                return value
        for wrapper in ("Result", "result", "Data", "data",
                        "UserInfo", "userInfo", "Account", "account"):
            if wrapper not in data:
                continue
            value = data[wrapper]
            if isinstance(value, str):
                text = value.strip()
                if text[:1] in ("{", "["):
                    try:
                        value = json.loads(text)
                    except Exception:
                        continue
            found = _find_value(value, keys, depth + 1)
            if found not in (None, ""):
                return found
    return None


# ---------------------------------------------------------------------------
# Minimal DER/PEM encoding for a P-256 device key
# ---------------------------------------------------------------------------
def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(raw),)) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _der_length(len(value)) + value


def _der_sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _der_integer(value: int) -> bytes:
    raw = int(value).to_bytes((int(value).bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _der_octets(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _der_bit_string(value: bytes) -> bytes:
    return _tlv(0x03, b"\x00" + value)


def _base128(number: int) -> bytes:
    parts = [number & 0x7F]
    number >>= 7
    while number:
        parts.append(0x80 | (number & 0x7F))
        number >>= 7
    return bytes(reversed(parts))


def _der_oid(dotted: str) -> bytes:
    parts = [int(part) for part in str(dotted).split(".")]
    if len(parts) < 2:
        raise ValueError("OID needs at least two components")
    body = bytearray(_base128(parts[0] * 40 + parts[1]))
    for part in parts[2:]:
        body.extend(_base128(part))
    return _tlv(0x06, bytes(body))


_OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
_OID_PRIME256V1 = "1.2.840.10045.3.1.7"


def _pem(label: str, der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN %s-----\n%s\n-----END %s-----\n"
            % (label, "\n".join(lines), label))


def generate_device_key() -> tuple[int, str, str, dict]:
    """Return (private scalar, SEC1 PEM, SPKI PEM, public point)."""
    scalar = secrets.randbelow(P256_N - 1) + 1
    point = p256_public_point(scalar)
    x, y = point
    xb = int(x).to_bytes(32, "big")
    yb = int(y).to_bytes(32, "big")
    public_point = b"\x04" + xb + yb
    spki = _der_sequence(
        _der_sequence(_der_oid(_OID_EC_PUBLIC_KEY), _der_oid(_OID_PRIME256V1)),
        _der_bit_string(public_point),
    )
    sec1 = _der_sequence(
        _der_integer(1),
        _der_octets(int(scalar).to_bytes(32, "big")),
        _tlv(0xA0, _der_oid(_OID_PRIME256V1)),
        _tlv(0xA1, _der_bit_string(public_point)),
    )
    return (scalar, _pem("EC PRIVATE KEY", sec1),
            _pem("PUBLIC KEY", spki), {"x": x, "y": y})


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _default_transport(url: str, payload: Mapping[str, Any],
                       headers: Mapping[str, str]) -> dict:
    """POST JSON once; no retries, no redirects, bounded body."""
    body = json.dumps(dict(payload), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers=dict(headers or {}),
    )
    try:
        with _OPENER.open(request, timeout=HTTP_TIMEOUT) as response:
            status = int(getattr(response, "status", 0) or 0)
            if status < 200 or status >= 300:
                raise OAuthError("exchange_failed")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise OAuthError("exchange_failed")
    except OAuthError:
        raise
    except (urllib.error.HTTPError, urllib.error.URLError,
            TimeoutError, OSError, ValueError):
        raise OAuthError("exchange_failed")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise OAuthError("exchange_failed")
    if not isinstance(data, dict):
        raise OAuthError("exchange_failed")
    return data


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------
@dataclass
class _Session:
    state: str
    realm: str
    owner: str
    redirect_uri: str
    authorization_url: str
    expires_at: float
    created_at: float
    verifier: str
    challenge: str
    device_id: str
    machine_id: str
    private_key_pem: str
    public_key_pem: str
    device_info: dict
    app_version: str
    platform: str
    status: str = "pending"
    claimed: bool = False
    result: dict | None = None
    error: dict | None = None
    terminal_at: float | None = None
    server: Any = None
    thread: Any = None


_TERMINAL = frozenset(("complete", "success", "failed", "cancelled", "expired"))
_SAFE_KEYS = frozenset((
    "uid", "uidHash", "uidTail", "name", "username", "nickname",
    "display_name", "avatar_url", "realm", "realmName", "host",
    "user_region", "userRegion", "source", "expired_at",
    "refresh_expired_at", "expiresAt", "refreshExpiresAt",
    "hasRefreshToken", "status", "enabled", "created", "updated",
))


def _safe_public(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    out = {}
    for key in _SAFE_KEYS:
        if key in value and not isinstance(value[key], (dict, list)):
            out[key] = value[key]
    account = value.get("account")
    if isinstance(account, dict):
        clean = {}
        for key in ("username", "name", "nickname", "display_name",
                    "avatar_url"):
            if isinstance(account.get(key), str):
                clean[key] = account[key]
        if clean:
            out["account"] = clean
    return out


def _normalize_params(params: Any) -> dict:
    if not isinstance(params, dict):
        raise OAuthError("invalid_callback")
    out = {}
    total = 0
    if len(params) > MAX_CALLBACK_PARAMS:
        raise OAuthError("invalid_callback")
    for key, value in params.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            raise OAuthError("invalid_callback")
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                raise OAuthError("invalid_callback")
            value = value[0]
        if not isinstance(value, str) or len(value) > 4096:
            raise OAuthError("invalid_callback")
        total += len(key) + len(value)
        if total > MAX_CALLBACK_BYTES:
            raise OAuthError("invalid_callback")
        out[key] = value
    return out


def _trace_from_params(params: Mapping[str, str]) -> str:
    primary = params.get("loginTraceID") or ""
    alias = params.get("login_trace_id") or ""
    if primary and alias and primary != alias:
        raise OAuthError("invalid_callback")
    trace = primary or alias
    state = params.get("state") or ""
    if trace and state and trace != state:
        raise OAuthError("invalid_callback")
    trace = trace or state
    if not trace or len(trace) > 128:
        raise OAuthError("invalid_callback")
    return trace


def _json_object(raw: str, code: str = "invalid_callback") -> dict:
    try:
        value = json.loads(raw)
    except Exception:
        raise OAuthError(code)
    if not isinstance(value, dict):
        raise OAuthError(code)
    return value


def _api_origin(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        raise OAuthError("invalid_callback")
    if "://" not in text:
        text = "https://" + text
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise OAuthError("invalid_callback")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise OAuthError("invalid_callback")
    if parsed.port not in (None, 443):
        raise OAuthError("invalid_callback")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise OAuthError("invalid_callback")
    return "https://" + host


def _validate_redirect_uri(raw: str) -> str:
    parsed = urllib.parse.urlsplit(str(raw or ""))
    if parsed.fragment or parsed.username or parsed.password:
        raise OAuthError("invalid_redirect_uri")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise OAuthError("invalid_redirect_uri")
    if parsed.scheme == "https":
        return urllib.parse.urlunsplit(parsed)
    if parsed.scheme == "http" and host == "127.0.0.1":
        return urllib.parse.urlunsplit(parsed)
    raise OAuthError("invalid_redirect_uri")


class OAuthManager:
    """Thread-safe native IDE authorization manager.

    on_complete(row) is called exactly once for a successful, non-cancelled
    authorization.  It receives a plain row containing the access token,
    refresh token, realm, host and device material; its return value must be a
    dict (typically the account layer's redacted public view).  Raising means
    the authorization is reported as failed and never as complete.
    """

    def __init__(self, on_complete: Callable[[dict], dict],
                 clock: Callable[[], float] = time.time,
                 transport: Callable[[str, dict, dict], dict] | None = None):
        if not callable(on_complete):
            raise TypeError("on_complete must be callable")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._on_complete = on_complete
        self._clock = clock
        self._transport = transport
        self._lock = threading.RLock()
        self._complete_lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}
        self._closed = False

    # -- public API --------------------------------------------------------
    def start(self, realm: str = "cn", platform: str | None = None,
              owner: str = "", redirect_uri: str | None = None) -> dict:
        try:
            realm = _canonical_realm(realm)
            platform = _canonical_platform(platform)
            if not isinstance(owner, str) or len(owner) > 128:
                raise OAuthError("invalid_owner")
            explicit = None
            if redirect_uri is not None:
                explicit = _validate_redirect_uri(redirect_uri)
        except OAuthError as exc:
            return _public_error(exc.code)

        now = self._clock()
        state = secrets.token_hex(16)
        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        _scalar, private_pem, public_pem, _point = generate_device_key()
        machine_id = secrets.token_hex(16)
        digits = 16 if realm == "cn" else 19
        device_id = str(secrets.randbelow(9) + 1) + "".join(
            str(secrets.randbelow(10)) for _ in range(digits - 1))
        app_version = APP_VERSIONS[realm]
        device_info = {
            "DeviceID": device_id,
            "MachineID": machine_id,
            "PlatformCode": "IDE_PC",
            "DeviceType": "PC",
            "ClientVersion": app_version,
            "DeviceName": "", "DeviceModel": "", "DeviceCPU": "", "OSInfo": platform,
            "DevicePublicKey": public_pem,
            "DeviceBrand": "PC",
            "OSVersion": platform,
            "AppType": "stable",
            "ChannelName": "common",
        }

        server = None
        thread = None
        if explicit is None:
            try:
                server = _CallbackServer(("127.0.0.1", 0), _CallbackHandler)
                server.daemon_threads = True
                server.manager = self
                server.server_port = int(server.server_address[1])
                callback_uri = "http://127.0.0.1:%d%s" % (
                    server.server_port, CALLBACK_PATH)
            except Exception:
                return _public_error("callback_server_failed")
        else:
            callback_uri = explicit

        query = {
            "client_id": CLIENT_ID,
            "login_version": "1",
            "auth_from": "trae",
            "login_channel": "native_ide",
            "plugin_version": PLUGIN_VERSION,
            "auth_type": "local",
            "redirect": "0",
            "login_trace_id": state,
            "auth_callback_url": callback_uri,
            "machine_id": machine_id,
            "device_id": device_id,
            "x_device_id": device_id,
            "x_machine_id": machine_id,
            "x_device_type": platform,
            "x_device_brand": "PC", "x_os_version": platform, "x_env": "",
            "x_app_version": app_version,
            "x_app_type": "stable",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "channel_name": "common",
        }
        authorization_url = AUTH_URLS[realm] + "?" + urllib.parse.urlencode(query)

        with self._lock:
            if self._closed:
                if server is not None:
                    server.server_close()
                return _public_error("manager_closed")
            self._prune_locked(now)
            pending = sum(1 for item in self._sessions.values()
                          if item.status in ("pending", "committing"))
            if pending >= MAX_PENDING:
                if server is not None:
                    server.server_close()
                return _public_error("too_many_sessions")
            while state in self._sessions:
                state = secrets.token_hex(16)
            session = _Session(
                state=state, realm=realm, owner=owner,
                redirect_uri=callback_uri, authorization_url=authorization_url,
                expires_at=now + SESSION_TTL, created_at=now,
                verifier=verifier, challenge=challenge,
                device_id=device_id, machine_id=machine_id,
                private_key_pem=private_pem, public_key_pem=public_pem,
                device_info=device_info, app_version=app_version,
                platform=platform, server=server,
            )
            self._sessions[state] = session

        if server is not None:
            thread = threading.Thread(
                target=server.serve_forever, name="trae-oauth-callback",
                daemon=True)
            session.thread = thread
            server.session_state = state
            try:
                thread.start()
            except Exception:
                with self._lock:
                    self._sessions.pop(state, None)
                server.server_close()
                return _public_error("callback_server_failed")

        return {
            "status": "pending",
            "state": state,
            "authorization_url": authorization_url,
            "verification_uri": authorization_url,
            "redirect_uri": callback_uri,
            "expires_at": int(now + SESSION_TTL),
            "interval": POLL_INTERVAL,
            "realm": realm,
        }

    def poll(self, state: str, owner: str = "") -> dict:
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            session = self._sessions.get(str(state or ""))
            if session is None:
                return _not_found()
            if session.owner != (owner or ""):
                return _not_found()
            if session.status == "pending" and not session.claimed \
                    and now >= session.expires_at:
                self._fail_locked(session, "state_expired", now)
            return self._view_locked(session)

    def cancel(self, state: str, owner: str = "") -> bool:
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            session = self._sessions.get(str(state or ""))
            if session is None or session.owner != (owner or ""):
                return False
            if session.status in _TERMINAL or session.status == "committing":
                return False
            session.status = "cancelled"
            session.error = {"code": "state_cancelled",
                             "message": _MESSAGES["state_cancelled"]}
            session.terminal_at = now
            self._retire_locked(session)
            return True

    def complete_callback(self, params: Any, owner: str | None = None) -> dict:
        try:
            normalized = _normalize_params(params)
            trace = _trace_from_params(normalized)
        except OAuthError as exc:
            return _public_error(exc.code)
        return self._complete(normalized, trace, owner, listener=False)

    # -- listener hook (not a public API) ---------------------------------
    def _complete_from_listener(self, params: dict) -> dict:
        try:
            normalized = _normalize_params(params)
            trace = _trace_from_params(normalized)
        except OAuthError as exc:
            return _public_error(exc.code)
        with self._lock:
            session = self._sessions.get(trace)
            if session is None:
                return _not_found()
            owner = session.owner
        return self._complete(normalized, trace, owner, listener=True)

    def _listener_origin_ok(self, origin: str | None, params: dict) -> bool:
        if not origin:
            return True
        origin = str(origin).rstrip("/")
        try:
            trace = _trace_from_params(_normalize_params(params))
        except OAuthError:
            return True
        with self._lock:
            session = self._sessions.get(trace)
            allowed = ({AUTH_ORIGINS[session.realm]} if session is not None
                       else set(AUTH_ORIGINS.values()))
        return origin in allowed

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            servers = []
            threads = []
            for session in self._sessions.values():
                if session.status in ("pending", "committing"):
                    session.status = "cancelled"
                    session.error = {"code": "state_cancelled",
                                     "message": _MESSAGES["state_cancelled"]}
                    session.terminal_at = self._clock()
                if session.server is not None:
                    servers.append(session.server)
                if session.thread is not None:
                    threads.append(session.thread)
            self._sessions.clear()
        for server in servers:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        for thread in threads:
            try:
                thread.join(timeout=2)
            except Exception:
                pass

    # -- internals ---------------------------------------------------------
    def _retire_locked(self, session: _Session) -> None:
        # Terminal credentials need not remain live for the status retention TTL.
        session.verifier = ""
        session.private_key_pem = ""
        server = session.server
        if server is None or getattr(server, "retiring", False):
            return
        server.retiring = True
        def stop():
            server.shutdown()
            server.server_close()
        threading.Thread(target=stop, name="trae-oauth-retire", daemon=True).start()

    def _maintain_listener(self, server) -> None:
        with self._lock:
            self._prune_locked(self._clock())
            session = self._sessions.get(getattr(server, "session_state", ""))
            if session is not None and session.status in _TERMINAL:
                self._retire_locked(session)

    def _prune_locked(self, now: float) -> None:
        for state, session in list(self._sessions.items()):
            if (session.status == "pending" and not session.claimed
                    and now >= session.expires_at):
                self._fail_locked(session, "state_expired", now)
            elif (session.status in _TERMINAL and session.terminal_at
                  and now - session.terminal_at > TERMINAL_TTL):
                self._sessions.pop(state, None)

    def _fail_locked(self, session: _Session, code: str, now: float) -> None:
        if session.status in _TERMINAL:
            return
        if code == "state_cancelled":
            session.status = "cancelled"
        elif code == "state_expired":
            session.status = "expired"
        else:
            session.status = "failed"
        session.error = {"code": code,
                         "message": _MESSAGES.get(code,
                                                  _MESSAGES["unexpected"])}
        session.terminal_at = now
        self._retire_locked(session)

    def _view_locked(self, session: _Session) -> dict:
        if session.status in _TERMINAL:
            self._retire_locked(session)
        base = {"state": session.state, "realm": session.realm, "redirect_uri": session.redirect_uri}
        if session.status == "committing" or (session.status == "pending" and session.claimed):
            return dict(base, status="exchanging", expires_at=int(session.expires_at))
        if session.status == "pending":
            base.update({
                "status": "pending",
                "expires_at": int(session.expires_at),
                "interval": POLL_INTERVAL,
                "redirect_uri": session.redirect_uri,
            })
            return base
        if session.status == "complete":
            base.update({"status": "success",
                         "message": "登录成功，账号已加入网关。",
                         "account": dict(session.result or {})})
            account = session.result or {}
            if isinstance(account.get("uid"), str) and account["uid"]:
                base["uid"] = account["uid"]
            return base
        if session.status == "cancelled":
            base.update({"status": "cancelled",
                         "error": dict(session.error or {})})
            return base
        if session.status == "expired":
            base.update({"status": "expired",
                         "error": dict(session.error or {})})
            return base
        base.update({"status": "failed",
                     "error": dict(session.error or {
                         "code": "unexpected",
                         "message": _MESSAGES["unexpected"]})})
        return base

    def _parse_callback(self, session: _Session,
                        params: Mapping[str, str]) -> dict:
        if "error" in params or params.get("error_code") not in (None, "", "0"):
            raise OAuthError("authorization_denied")
        # Callback userInfo is untrusted for identity. It may supply a display
        # name only; the uid is resolved exclusively from ExchangeToken or the
        # authenticated GetUserInfo response.
        user_id = ""
        screen_name = ""
        raw_user = params.get("userInfo")
        if raw_user:
            try:
                user_doc = _json_object(raw_user)
            except OAuthError:
                user_doc = {}
            screen_name = _first_text(user_doc, "ScreenName", "screenName",
                                      "UserName", "userName")[:128]
        user_region = str(params.get("userRegion") or "")[:2048]
        raw_host = str(params.get("host") or "")
        if raw_host:
            host = _api_origin(raw_host)
            hostname = urllib.parse.urlsplit(host).hostname or ""
            if hostname not in HOST_WHITELIST[session.realm]:
                raise OAuthError("invalid_callback")
        else:
            host = DEFAULT_API[session.realm]

        raw_code = params.get("authCodeInfo")
        if raw_code:
            info = _json_object(raw_code)
            code = _first_text(info, "AuthCode", "authCode", "code")
            if not code or len(code) > 4096:
                raise OAuthError("invalid_callback")
            expire = _first(info, "ExpireAt", "expireAt")
            expire_at = 0
            if expire not in (None, ""):
                try:
                    stamp = float(expire)
                    if stamp > 100_000_000_000:
                        stamp /= 1000.0
                    if stamp < 100_000_000:
                        stamp = self._clock() + stamp
                    if stamp <= self._clock():
                        raise OAuthError("authorization_expired")
                    expire_at = int(stamp)
                except OAuthError:
                    raise
                except (TypeError, ValueError):
                    raise OAuthError("invalid_callback")
            return {"kind": "code", "code": code, "host": host,
                    "user_id": user_id, "screen_name": screen_name,
                    "user_region": user_region, "expire_at": expire_at}

        token = _first_text(params, "accessToken", "access_token",
                            "userJwt", "user_jwt")
        refresh = _first_text(params, "refreshToken", "refresh_token")
        if not token or not refresh:
            raise OAuthError("invalid_callback")
        return {"kind": "token", "token": token, "refresh": refresh,
                "host": host, "user_id": user_id,
                "screen_name": screen_name, "user_region": user_region,
                "expire_at": 0}

    def _complete(self, params: dict, trace: str, owner: str | None,
                  listener: bool) -> dict:
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            session = self._sessions.get(trace)
            if session is None:
                return _not_found()
            if session.owner != (owner or ""):
                return _not_found()
            if session.status in _TERMINAL:
                code = ("state_cancelled" if session.status == "cancelled"
                        else "state_expired" if session.status == "expired"
                        else "state_used")
                return _public_error(code, session.state)
            if session.claimed:
                return _public_error("state_used", session.state)
            if now >= session.expires_at:
                self._fail_locked(session, "state_expired", now)
                return _public_error("state_expired", session.state)
            try:
                context = self._parse_callback(session, params)
            except OAuthError as exc:
                self._fail_locked(session, exc.code, now)
                return _public_error(exc.code, session.state)
            session.claimed = True

        try:
            row = self._exchange_context(session, context)
        except OAuthError as exc:
            with self._lock:
                if session.status in _TERMINAL:
                    return self._view_locked(session)
                self._fail_locked(session, exc.code, self._clock())
                return self._view_locked(session)
        except Exception:
            with self._lock:
                if session.status in _TERMINAL:
                    return self._view_locked(session)
                self._fail_locked(session, "exchange_failed", self._clock())
                return self._view_locked(session)

        with self._complete_lock:
            with self._lock:
                if session.status == "cancelled":
                    return self._view_locked(session)
                if session.status in _TERMINAL:
                    return self._view_locked(session)
                if not session.claimed:
                    return _public_error("state_used", session.state)
                if self._clock() >= session.expires_at:
                    self._fail_locked(session, "state_expired", self._clock())
                    return self._view_locked(session)
                session.status = "committing"
            try:
                public = self._on_complete(row)
            except BaseException:
                with self._lock:
                    if session.status == "committing":
                        session.status = "failed"
                        session.error = {
                            "code": "storage_failed",
                            "message": _MESSAGES["storage_failed"]}
                        session.terminal_at = self._clock()
                    return self._view_locked(session)
            if not isinstance(public, dict):
                with self._lock:
                    if session.status == "committing":
                        session.status = "failed"
                        session.error = {
                            "code": "storage_failed",
                            "message": _MESSAGES["storage_failed"]}
                        session.terminal_at = self._clock()
                    return self._view_locked(session)
            clean = _safe_public(public)
            with self._lock:
                if session.status == "cancelled":
                    return self._view_locked(session)
                session.status = "complete"
                session.result = clean
                session.terminal_at = self._clock()
                return self._view_locked(session)

    def _exchange_context(self, session: _Session, context: dict) -> dict:
        host = context["host"]
        if host not in ("https://" + item for item in HOST_WHITELIST[session.realm]):
            raise OAuthError("unapproved_host")
        if context["kind"] == "token":
            uid, name = self._get_user_info(context["token"], session.realm, host)
            self._check_identity(uid, context.get("user_id"))
            if not uid:
                raise OAuthError("identity_mismatch")
            return self._row(session, context, host, uid,
                             context["refresh"], 0, 0,
                             name or context.get("screen_name") or "")

        url = host + EXCHANGE_PATH
        self._validate_endpoint(url, session.realm)
        payload = {
            "ClientID": CLIENT_ID,
            "AuthCode": context["code"],
            "CodeVerifier": session.verifier,
            "DeviceInfo": dict(session.device_info),
            "IDEVersion": session.app_version,
        }
        headers = {"Content-Type": "application/json", "x-cloudide-token": ""}
        data = self._request(url, payload, headers, session.realm)
        token = _pick_text(data, "Token", "token", "AccessToken",
                           "accessToken", "access_token")
        refresh = _pick_text(data, "RefreshToken", "refreshToken",
                             "refresh_token")
        uid = _pick_text(data, "UserID", "userId", "user_id", "uid")
        name = _pick_text(data, "ScreenName", "screenName", "UserName",
                          "userName", "name")
        if not token or not refresh:
            raise OAuthError("exchange_failed")
        self._check_identity(uid, context.get("user_id"))
        if not uid:
            uid, fetched = self._get_user_info(token, session.realm, host)
            self._check_identity(uid, context.get("user_id"))
            name = name or fetched
        if not uid:
            raise OAuthError("identity_mismatch")
        expired = _now_seconds(_pick_value(data, "ExpiredAt", "expiredAt",
                                           "TokenExpireAt", "tokenExpireAt",
                                           "expired_at"))
        if not expired:
            duration = _pick_value(data, "TokenExpireDuration", "ExpireDuration",
                                   "expiresIn", "expire_in")
            try:
                if duration not in (None, ""):
                    expired = int(self._clock() + max(0.0, float(duration)))
            except (TypeError, ValueError):
                expired = 0
        refresh_expired = _now_seconds(_pick_value(
            data, "RefreshExpireAt", "refreshExpireAt", "RefreshExpiredAt",
            "refreshExpiredAt", "refresh_expired_at"))
        if not refresh_expired:
            refresh_duration = _pick_value(
                data, "RefreshExpireDuration", "refreshExpireDuration",
                "refreshExpiresIn")
            try:
                if refresh_duration not in (None, ""):
                    refresh_expired = int(
                        self._clock() + max(0.0, float(refresh_duration)))
            except (TypeError, ValueError):
                refresh_expired = 0
        context["token"] = token
        return self._row(session, context, host, uid, refresh, expired,
                         refresh_expired,
                         name or context.get("screen_name") or "")

    def _check_identity(self, actual: str, claimed: str) -> None:
        if actual and claimed and str(actual) != str(claimed):
            raise OAuthError("identity_mismatch")

    def _user_region(self, realm: str, raw: Any) -> dict:
        default = {"cn": ("CN", "CN"), "intl": ("US", "US")}[realm]
        data = raw
        if isinstance(data, str):
            text = data.strip()
            if text[:1] == "{":
                try:
                    data = json.loads(text)
                except Exception:
                    data = None
            elif text:
                data = {"region": text}
        if isinstance(data, dict):
            region = str(data.get("region") or data.get("userRegion")
                         or default[0])[:32]
            ai_region = str(data.get("_aiRegion") or data.get("aiRegion")
                            or data.get("AIRegion") or region)[:32]
        else:
            region, ai_region = default
        return {"region": region, "_aiRegion": ai_region}

    def _row(self, session: _Session, context: dict, host: str, uid: str,
             refresh: str, expired: int, refresh_expired: int,
             name: str) -> dict:
        return {
            "uid": str(uid),
            "token": context.get("token") or "",
            "refresh_token": str(refresh or ""),
            "expired_at": int(expired or 0),
            "refresh_expired_at": int(refresh_expired or 0),
            "realm": session.realm,
            "host": host,
            "user_region": self._user_region(session.realm,
                                             context.get("user_region")),
            "account": {"username": str(name or "")},
            "source": "oauth",
            "extra": {
                "device_id": session.device_id,
                "machine_id": session.machine_id,
                "privateKeyPEM": session.private_key_pem,
                "deviceInfo": dict(session.device_info),
            },
        }

    def _get_user_info(self, token: str,
                       realm: str, host: str | None = None) -> tuple[str, str]:
        url = (host or USER_INFO_HOST[realm]) + USER_INFO_PATH
        self._validate_endpoint(url, realm)
        headers = {
            "Content-Type": "application/json",
            "x-cloudide-token": token,
            "X-Cloudide-Token": token,
            "Authorization": "Cloud-IDE-JWT " + token,
        }
        data = self._request(url, {"ReqSource": "IDE",
                                   "IDEVersion": APP_VERSIONS[realm]},
                             headers, realm)
        uid = _pick_text(data, "UserID", "userId", "user_id", "uid")
        name = _pick_text(data, "ScreenName", "screenName", "UserName",
                          "userName", "name")
        return uid, name

    def _validate_endpoint(self, url: str, realm: str) -> None:
        parsed = urllib.parse.urlsplit(str(url or ""))
        if parsed.scheme != "https" or parsed.username or parsed.password:
            raise OAuthError("unapproved_host")
        if parsed.port not in (None, 443):
            raise OAuthError("unapproved_host")
        if parsed.query or parsed.fragment:
            raise OAuthError("unapproved_host")
        if parsed.path not in (EXCHANGE_PATH, USER_INFO_PATH):
            raise OAuthError("unapproved_host")
        host = (parsed.hostname or "").strip().lower()
        if host not in HOST_WHITELIST[realm]:
            raise OAuthError("unapproved_host")

    def _request(self, url: str, payload: Mapping[str, Any],
                 headers: Mapping[str, str], realm: str) -> dict:
        self._validate_endpoint(url, realm)
        try:
            if self._transport is not None:
                data = self._transport(url, dict(payload), dict(headers))
            else:
                data = _default_transport(url, payload, headers)
        except OAuthError:
            raise
        except Exception:
            raise OAuthError("exchange_failed")
        if not isinstance(data, dict):
            raise OAuthError("exchange_failed")
        metadata = data.get("ResponseMetadata")
        if isinstance(metadata, dict) and metadata.get("Error"):
            raise OAuthError("exchange_failed")
        if data.get("Error") or data.get("error"):
            raise OAuthError("exchange_failed")
        for key in ("Code", "code"):
            if key in data and data[key] not in (0, "0", "", None):
                raise OAuthError("exchange_failed")
        return data


# ---------------------------------------------------------------------------
# Loopback callback listener
# ---------------------------------------------------------------------------
_PAGE_OK = (b"<!doctype html><html lang=\"zh\"><meta charset=\"utf-8\">"
            b"<title>Trae authorization</title><body><p>"
            + "授权已完成，请返回管理面板。".encode("utf-8") +
            b"</p></body></html>")
_PAGE_FAIL = (b"<!doctype html><html lang=\"zh\"><meta charset=\"utf-8\">"
              b"<title>Trae authorization</title><body><p>"
              + "授权未完成，请返回管理面板重试。".encode("utf-8") +
              b"</p></body></html>")


class _CallbackServer(http.server.ThreadingHTTPServer):
    def service_actions(self):
        manager = getattr(self, "manager", None)
        if manager is not None:
            manager._maintain_listener(self)


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "trae-oauth"
    sys_version = ""

    def log_message(self, fmt, *args):  # never log a callback query string
        return

    def do_OPTIONS(self):
        self._respond(405, b"", "text/plain; charset=utf-8")

    def do_POST(self):
        self._respond(405, b"", "text/plain; charset=utf-8")

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        # HEAD must never consume a single-use authorization.
        self._respond(405, b"", "text/plain; charset=utf-8", head=True)

    def _handle(self, head=False):
        manager = getattr(self.server, "manager", None)
        port = int(getattr(self.server, "server_port", 0) or 0)
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != CALLBACK_PATH:
            return self._respond(404, b"", "text/plain; charset=utf-8",
                                 head=head)
        if len(parsed.query) > MAX_CALLBACK_BYTES:
            return self._respond(414, b"", "text/plain; charset=utf-8",
                                 head=head)
        host = (self.headers.get("Host") or "").strip().lower()
        if host != "127.0.0.1:%d" % port:
            return self._respond(421, b"", "text/plain; charset=utf-8",
                                 head=head)
        try:
            params = _normalize_params(
                urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
        except OAuthError:
            return self._respond(400, _PAGE_FAIL,
                                 "text/html; charset=utf-8", head=head)
        origin = self.headers.get("Origin")
        if manager is None or not manager._listener_origin_ok(origin, params):
            return self._respond(403, b"", "text/plain; charset=utf-8",
                                 head=head)
        try:
            if _trace_from_params(params) != getattr(self.server, "session_state", ""):
                return self._respond(400, _PAGE_FAIL, "text/html; charset=utf-8", head=head)
        except OAuthError:
            return self._respond(400, _PAGE_FAIL, "text/html; charset=utf-8", head=head)
        result = manager._complete_from_listener(params)
        status = result.get("status")
        if status == "success":
            self._respond(200, _PAGE_OK, "text/html; charset=utf-8", head=head)
        elif status == "cancelled":
            self._respond(200, _PAGE_FAIL, "text/html; charset=utf-8",
                          head=head)
        else:
            self._respond(400, _PAGE_FAIL, "text/html; charset=utf-8",
                          head=head)

    def _respond(self, status: int, body: bytes, content_type: str,
                 head: bool = False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "frame-ancestors 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass


__all__ = [
    "OAuthManager", "OAuthError", "CLIENT_ID", "PLUGIN_VERSION",
    "AUTH_URLS", "APP_VERSIONS", "EXCHANGE_PATH", "USER_INFO_PATH",
    "generate_device_key",
]
