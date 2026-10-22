#!/usr/bin/env python3
"""Trae -> OpenAI-compatible reverse proxy (CN + Intl dual realm).

把 Trae 国内版 (trae.com.cn / trae-api-cn.mchost.guru) 与国际版
(trae.ai / core-normal.traeapi.us) 的 IDE 数据面封装为标准 OpenAI 兼容接口。
上游链路（协议事实源见 .team/PROTOCOL.md）：

    客户端 OpenAI 请求
      -> build_trae_body()        (messages parts 化 + system 工具 schema 注入)
      -> trae_client.open_chat()  (IDE 鉴权头 + POST /api/ide/v1/llm_raw_chat)
      -> SSE 事件解包             (metadata/output/token_usage/done/error)
      -> 工具标记转换             (<|FunctionCallBegin|>[…]<|FunctionCallEnd|>)
      -> 标准 OpenAI SSE / chat.completion 回给客户端

暴露：
    GET  /v1/models
    POST /v1/chat/completions     (stream=true / false)
    POST /v1/responses            (Responses API 双向转换)
    POST /v1/messages             (Anthropic Messages 转换)
    GET  /health
    以及看板全套管理接口 (accounts / usage / tasks / scheduler / settings / logs)

仅使用 Python 标准库（流解析、工具标记、用量归一全部内置实现）。
trae_client 存在时优先使用它（协议客户端），缺失时回落到本文件内置实现，
因此数据面可以在 trae_client 尚未落地时独立闭环。

    python trae_proxy.py                    # bind 127.0.0.1:8791
    python trae_proxy.py --port 9000
    python trae_proxy.py --api-key sk-local  # require a bearer token
"""
import argparse
import hashlib
import shutil
import tarfile
import tempfile
from collections import deque
import re
import json
import os
MAX_PAYLOAD_BYTES = int(os.environ.get("TRAE_MAX_PAYLOAD_BYTES", 50 * 1024 * 1024))  # 50MB limit
import ipaddress
import socket
import ssl
import sys
import threading
import fnmatch
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import subprocess

import trae_accounts
import trae_agents
import trae_anthropic
import trae_catalog
import trae_fingerprint
import trae_probe
import trae_settings
from trae_accounts import (get_realm_config, gateway_candidates, CLIENT_UA)
from pathlib import Path

# 协议客户端：由 doudou 维护（.team/PROTOCOL.md §十）。缺失时本文件内置
# 同签名实现（下方 "内置协议客户端" 段），数据面不因缺模块而停摆。
try:                                        # pragma: no cover - 环境相关
    import trae_client as _trae_client
except Exception:                           # ImportError / 语法错误都回落
    _trae_client = None

TRAE_CLIENT_SOURCE = "trae_client" if _trae_client is not None else "embedded"

VERSION = "1.1.5"

CURRENT_REALM = os.environ.get("TRAE_PROXY_DEFAULT_REALM", "cn")


def is_model_banned(model):
    """P1-4：True = 该模型在本机被全局封禁，不送去上游。

    配置源：settings 的 banned_models（fnmatch pattern 列表，默认空 = 不封禁）。
    读配置失败一律 fail-open（不误封）。与 wb 的差异：配置在 settings 而非代码
    常量——本仓已有面板/设置机制。
    """
    name = str(model or "").strip().lower()
    if not name:
        return False
    try:
        patterns = trae_settings.banned_models(ACCOUNTS_DIR)
    except Exception:
        return False
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def banned_model_message(model):
    """封禁模型的本机拒绝文案（完全不碰上游）。"""
    return ("模型 %s 已被本机网关封禁（settings 的 banned_models 配置）。"
            "如需使用，请在设置页或 settings.json 里调整 banned_models。"
            % model)


def key_model_message(entry, model):
    """每 Key 模型限制的拒绝文案（与全局封禁同风格）。"""
    name = (entry or {}).get("name") or "未命名"
    allowed = "、".join((entry or {}).get("models") or []) or "-"
    asked = str(model or "").strip() or "(未指定模型)"
    return ("API Key「%s」的模型限制不允许 %s。该 Key 目前允许：%s。"
            "请在设置页修改该 Key 的模型限制，或改用允许该模型的 Key。"
            % (name, asked, allowed))


# 198.18.0.0/15 (RFC 2544 benchmarking) 与 fdfe:dcba:9876::/48 被 Clash/mihomo
# 等本地代理用作 fake-IP DNS 段：开启透明代理的机器上所有公网域名都会解析到
# 这些网段。命中它说明 DNS 已被本机代理接管、真实 IP 不可见，此时跳过解析级
# 校验（名称级校验已完成）。
_FAKEIP_NETS = [
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("2001:2::/48"),
    ipaddress.ip_network("fdfe:dcba:9876::/48"),
]


def _host_boundary_violation(ip, allow_local):
    """True when the resolved/IP address must be refused."""
    if ip.is_loopback:
        return not allow_local
    if (ip.is_private or ip.is_reserved or ip.is_link_local
            or ip.is_multicast or ip.is_unspecified):
        return True
    return False


def validate_public_http_url(url, allow_local=False):
    """SSRF 防护：仅允许 http/https，且 host 不得指向本机/私有/保留网段。

    与 trae_accounts.validate_public_http_url 同逻辑、独立实现防同错：
    本文件的 urlopen 调用点必须经过本文件的边界校验（签名链路上的 URL
    在 sess.headers() 之后再校验一次，确保进入 Request 的字符串是洁净的）。
    allow_local 仅供显式面向本机网关的开发/验证脚本使用。
    """
    parsed = urllib.parse.urlsplit(str(url or ""))
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http/https URLs are allowed")
    host = (parsed.hostname or "").strip().strip("[]").lower()
    if not host:
        raise ValueError("URL host is required")
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        if not allow_local:
            raise ValueError("requests to localhost are not allowed")
        return url
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _host_boundary_violation(literal, allow_local):
            raise ValueError(
                "requests to private/reserved address %s are not allowed" % literal)
        return url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("cannot resolve URL host %r: %s" % (host, exc))
    addrs = []
    for info in infos:
        addr = str(info[4][0]).strip("[]")
        try:
            addrs.append(ipaddress.ip_address(addr))
        except ValueError:
            raise ValueError("URL host resolved to a non-IP address: %r" % addr)
    if addrs and all(any(ip in net for net in _FAKEIP_NETS) for ip in addrs):
        return url  # fake-IP DNS：真实 IP 不可见，名称级校验已通过
    for ip in addrs:
        if _host_boundary_violation(ip, allow_local):
            raise ValueError(
                "requests to private/reserved address %s are not allowed" % ip)
    return url


# 双区自动路由（#26 步1/步2）：默认开启。**显式指定永远优先** —— 本开关只作用于
# 「用户没指定区域」时的兜底路径（?realm= / Key 绑定 / X-Realm 任一存在时都不会走到这里）。
AUTO_REALM_ENABLED = os.environ.get("QD_AUTO_REALM", "1").lower() not in (
    "0", "false", "no", "off")


def _quota_state(quota, warn_below=10):
    """Return exhausted/low/ok/unknown for a notify_usage snapshot."""
    if not isinstance(quota, dict):
        return "unknown"
    remain = quota.get("remain_usage")
    if not isinstance(remain, dict):
        return "unknown"
    vals = []
    for key in ("advanced_model", "premium_model_fast_request",
                "premium_model_slow_request", "dollar_basic", "dollar_bonus"):
        if key in remain:
            try:
                vals.append(float(remain.get(key) or 0))
            except (TypeError, ValueError):
                pass
    if not vals:
        return "unknown"
    if all(v <= 0 for v in vals):
        return "exhausted"
    if any(v <= float(warn_below or 0) for v in vals):
        return "low"
    return "ok"


def _realm_quota_exhausted(realm, accounts=None):
    """True when every enabled account in the realm has a zero quota snapshot."""
    realm = str(realm or "").lower()
    if realm not in ("intl", "cn"):
        return False
    rows = accounts if accounts is not None else (POOL.accounts if POOL else [])
    found = False
    for account in rows:
        if getattr(account, "realm", "") != realm or not getattr(account, "enabled", True):
            continue
        found = True
        snap = (getattr(account, "extra", {}) or {}).get("intl_quota")
        if _quota_state(snap) != "exhausted":
            return False
    return found


def _model_needs_upgrade(model, realm):
    try:
        meta = None
        for m in fetch_models(realm=realm):
            if str(m.get("id") or "").lower() == str(model or "").lower():
                meta = m
                break
        return bool(meta and (meta.get("upgrade_required")
                              or meta.get("catalog_only")))
    except Exception:
        return False


def detect_model_realm(model_id):
    """模型 -> 出口区域（**纯数据判断，不查账号可用性**）。

    优先级：区域独占硬表 > 清单驱动自动路由（步1）> 全局开关。
    清单驱动只在「该模型只在一个区域存在」时换区；双区都有的模型维持当前区
    （判不出就不猜 —— 双区同名模型物理上无法靠名字区分，见评估 §2）。
    账号可用性不在这里判（那会污染 row_matches_realm 等纯统计路径），
    由 fallback_realm_by_accounts() 在选号前单独做（步2）。
    """
    owner = exclusive_realm(model_id)
    if owner:
        return owner
    if not model_id:
        return CURRENT_REALM
    if AUTO_REALM_ENABLED:
        realm, reason = trae_catalog.auto_realm_for_model(model_id, CURRENT_REALM)
        if realm:
            log("auto realm switch: %s (model=%r, current=%s -> %s)"
                % (reason, model_id, CURRENT_REALM, realm), tag="realm")
            return realm
    return CURRENT_REALM


def auto_realm_reason(model, realm):
    """本次自动换区的**确定性**原因（给面板显示结论，不让它自己推断）。

      model_missing  当前区的官方清单里没有这个模型（独占表与清单驱动都归此类）
      no_account     模型本身在当前区有（或无法判断），是账号可用性把我们推过去的
    用同一份数据源复算（catalog 的 auto_realm_for_model），与 detect_model_realm
    同源，不做二次猜测。
    """
    try:
        hint, _why = trae_catalog.auto_realm_for_model(model, CURRENT_REALM)
        if hint == realm:
            return "model_missing"
    except Exception:
        pass
    return "no_account"


def fallback_realm_by_accounts(realm, model):
    """步2：当前区**一个可用账号都没有**时回退另一区（判不出就维持现状）。

    只在未显式指定区域时被调用（open_upstream 内）。判据三段：
      当前区 count_ready > 0        -> 不动
      当前区 == 0 且 另一区 > 0     -> 换区（打日志）
      两区都是 0 / 异常 / 无池      -> 不动（交给既有错误路径，不猜）
    """
    if not AUTO_REALM_ENABLED or POOL is None:
        return realm
    if realm != CURRENT_REALM:
        # **模型归属优先于账号可用性**：realm 已被模型规则（独占表/清单驱动）推走，
        # 说明当前区根本没有这个模型；此时再按账号把请求换回去，只会打到
        # 「没有这个模型」的上游。停在目标区、由选号给出「无可用账号」的明确错误
        # 才是正确行为。
        return realm
    try:
        if POOL.count_ready(realm, model=model or None) > 0:
            return realm
        other = "intl" if realm == "cn" else "cn"
        if POOL.count_ready(other, model=model or None) > 0:
            log("auto realm switch (no ready account): realm %s has no usable "
                "account for %r -> %s" % (realm, model or "?", other), tag="realm")
            return other
    except Exception as exc:
        log("auto realm fallback skipped: %s" % exc, level="WARN")
    return realm


# 目前双区模型清单不同（源自官方 catalog 快照差集），独占表给区域特供模型。
INTL_EXCLUSIVE_PREFIXES = getattr(trae_catalog, "INTL_EXCLUSIVE_PREFIXES", ())
CN_EXCLUSIVE_PREFIXES = getattr(trae_catalog, "CN_EXCLUSIVE_PREFIXES", ())
INTL_EXCLUSIVE = getattr(trae_catalog, "INTL_EXCLUSIVE", set())
CN_EXCLUSIVE = getattr(trae_catalog, "CN_EXCLUSIVE", set())


def exclusive_realm(model_id):
    """"intl"/"cn" when only that exit serves the model, else "".

    先把人类可读别名解析成上游 key 再判独占（glm-5.2 -> gm51model 是国内独占）。
    """
    if not model_id:
        return ""
    m = str(model_id).lower()
    resolved = trae_catalog.resolve_upstream_key(model_id).lower()
    for cand in (resolved, m):
        if cand in INTL_EXCLUSIVE or cand.startswith(INTL_EXCLUSIVE_PREFIXES):
            return "intl"
        if cand in CN_EXCLUSIVE or cand.startswith(CN_EXCLUSIVE_PREFIXES):
            return "cn"
    return ""


from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def install_console_close_handler():
    """Release the port when the console window is closed by the user.

    Windows does not kill child processes when a console window closes, so
    the proxy (started by the .bat as a child of cmd.exe) would survive and
    keep the port bound - the next launch then wrongly reports "another
    proxy is already running". Registering an event-driven handler for
    CTRL_CLOSE_EVENT is the reliable signal. Harmless without a console.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
        CTRL_CLOSE_EVENT = 2
        CTRL_LOGOFF_EVENT = 5
        CTRL_SHUTDOWN_EVENT = 6

        def _handler(event):
            if event in (CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT):
                try:
                    sys.stdout.flush()
                except Exception:
                    pass
                os._exit(0)
            return False

        handler = PHANDLER_ROUTINE(_handler)   # keep the callback referenced
        if not ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True):
            return None
        return handler
    except Exception:
        return None


# Launcher names differ per platform; the messages below are read by whoever
# is staring at the terminal, so point at the file that actually exists there.
IS_WINDOWS = os.name == "nt"
START_SCRIPT = "start-trae2api-hub.bat" if IS_WINDOWS \
    else "start-trae2api-hub.sh"
FIREWALL_SCRIPT = "allow-firewall.bat" if IS_WINDOWS else "allow-firewall.sh"


def port_owner_hint(port):
    """One-liner(s) the user can paste to see which process holds a port."""
    cmds = ["netstat -ano | findstr :%d" % port] if IS_WINDOWS else \
        ["ss -ltnp | grep :%d" % port,
         "lsof -iTCP:%d -sTCP:LISTEN" % port]
    return cmds


# ---------------------------------------------------------------------------
# Trae 双区出口（PROTOCOL.md §一 / §二）
#
# 事实源是 Desktop 客户端的动态解析结果：CN 走 mchost.guru，INTL 走
# traeapi.us（US 账号）/ trae.ai（默认与 SG）。区域只决定「打哪台机器 +
# 带什么 UA」，鉴权头结构两区同构。
# ---------------------------------------------------------------------------
TRAE_REALMS = {
    "cn": {
        "core": "https://trae-api-cn.mchost.guru",
        "core_fallbacks": (),
        "account": "https://api.trae.com.cn",
        "ua": "Trae CN/3.4.3",
        "version_code": "20260212",
        "region": "CN",
        "ai_region": "CN",
    },
    "intl": {
        "core": "https://core-normal.traeapi.us",
        "core_fallbacks": ("https://core-normal.trae.ai",
                           "https://coresg-normal.trae.ai"),
        "account": "https://grow-normal.trae.ai",
        "ua": "Trae/3.6.2",
        "version_code": "20260212",
        "region": "US",
        "ai_region": "US",
    },
}

TRAE_CHAT_PATH = "/api/ide/v1/llm_raw_chat"
TRAE_MODEL_LIST_PATH = "/api/ide/v1/model_list"
TRAE_APP_ID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
TRAE_PLUGIN_CHANNEL = "icube-ai"

CHAT_PATH = TRAE_CHAT_PATH          # 兼容既有引用（数据面已无 query 参数）
MODELS_PATH = TRAE_MODEL_LIST_PATH
DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant."


NOISE_KEYS = ("extra_fields", "refusal", "reasoning_content")

# DeepSeek 上游 model key（官方目录：dmodel=DeepSeek-V4-Pro / dfmodel=DeepSeek-Flash）。
# 这族模型的多轮一致性与 reasoning_content 强相关，见 is_deepseek_model。
DEEPSEEK_MODEL_KEYS = ("dmodel", "dfmodel")


class BodyTooLarge(Exception):
    """Raised when a request body exceeds the configured cap."""

    def __init__(self, length):
        super(BodyTooLarge, self).__init__(length)
        self.length = length


class BadJSON(Exception):
    """Raised when a request body is present but not a JSON object."""


class UpstreamStatus(Exception):
    """Raised when the upstream SSE envelope carries a non-200 status."""

    def __init__(self, status, detail=""):
        super(UpstreamStatus, self).__init__("upstream status %s" % status)
        self.status = status
        self.detail = str(detail or "")


# CORS is only needed by browser-based chat clients that call the OpenAI-style
# API from another origin. Management routes serve the dashboard (same-origin)
# and get no ACAO header - that keeps a stray LAN page from reading them.
CORS_PATH_PREFIXES = ("/v1", "/chat", "/completions", "/models", "/responses")
MANAGEMENT_PATH_PREFIXES = ("/v1/usage", "/usage", "/accounts", "/settings",
                            "/tasks", "/scheduler", "/panel", "/logs")


def cors_origin_allowed(path):
    """True when the OpenAI-style API path should advertise CORS."""
    path = (path or "").split("?")[0]
    if path.startswith(MANAGEMENT_PATH_PREFIXES):
        return False
    return path.startswith(CORS_PATH_PREFIXES)


_lock = threading.Lock()
_login_lock = threading.Lock()
_login_attempts = {}  # ip -> list of timestamp


def _prune_login_attempts(now=None, window=60):
    """Drop stale per-IP entries so the dict cannot grow without bound.

    Caller must hold _login_lock.
    """
    now = now or time.time()
    for ip in list(_login_attempts.keys()):
        recent = [t for t in _login_attempts[ip] if now - t < window]
        if recent:
            _login_attempts[ip] = recent
        else:
            del _login_attempts[ip]


_models_cache = {"intl": {"at": 0.0, "data": None}, "cn": {"at": 0.0, "data": None}}

# Usage accounting: every upstream response carries a usage block, and the
# proxy also records one JSONL line per request.
USAGE_DIR = os.environ.get("TRAE_PROXY_USAGE_DIR") \
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage")
USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
USAGE_SUMMARY = os.path.join(USAGE_DIR, "usage-summary.json")
try:
    trae_probe.set_health_path(os.path.join(USAGE_DIR, "model_health.json"))
except Exception:
    pass
STATIC_ASSETS = {
    "/dashboard-v3.css": ("dashboard-v3.css", "text/css; charset=utf-8"),
    "/dashboard-charts.js": ("dashboard-charts.js", "application/javascript; charset=utf-8"),
    "/dashboard-v3.js": ("dashboard-v3.js", "application/javascript; charset=utf-8"),
}
DASHBOARD_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "dashboard.html")
USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "reasoning_tokens",
                "cached_tokens", "total_tokens", "credit",
                # issue #22：折扣时段对账要用的原价积分（数值，参与聚合）。
                # billable 是布尔值，**不做聚合**、只写进 JSONL 行（见 _extract_usage）。
                "original_credits",
                # 参考花费（OpenRouter 公开价折算；不是 Trae 官方账单）
                "cost_usd", "cost_cny")

# Web-panel access control. The panel is gated by its own password (default
# "admin"), independent of the /v1 API key. Sessions are signed tokens whose key
# lives in accounts/settings.json, so a restart no longer forces a re-login.
PANEL = trae_settings.PanelSessions(lambda: ACCOUNTS_DIR)
API_KEY_FILE_SET = False


def configured_keys():
    """Panel-managed API keys, always read fresh so panel edits apply at once."""
    try:
        return trae_settings.api_keys(ACCOUNTS_DIR)
    except Exception as exc:
        log("could not read api keys: %s" % exc)
        return []


def auth_required():
    """Whether /v1 calls must present a key at all."""
    if trae_settings.auth_disabled(ACCOUNTS_DIR):
        return False
    if any(entry.get("enabled") for entry in configured_keys()):
        return True
    return bool(API_KEY)


def identify_key(supplied):
    """Return the key entry a caller used, or None when nothing matches.

    Once the panel has at least one key, those keys are the only accepted
    credentials - otherwise a launcher key left in a .bat file would silently
    keep working after the panel was locked down.
    """
    extra = () if configured_keys() else (API_KEY,)
    return trae_settings.match_api_key(ACCOUNTS_DIR, supplied, extra_keys=extra)


def _empty_stats():
    return {"requests": 0, "errors": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "reasoning_tokens": 0, "cached_tokens": 0,
            "total_tokens": 0, "credit": 0.0, "original_credits": 0.0,
            "cost_usd": 0.0, "cost_cny": 0.0,
            "started": time.time(),
            "by_model": {},
            "ttft_ms_sum": 0, "ttft_samples": 0,
            "gen_ms_sum": 0, "gen_samples": 0,
            "wall_ms_sum": 0, "wall_samples": 0}


_usage = _empty_stats()


def _extract_usage(usage):
    """Normalize the upstream usage block into the fields we track."""
    if not usage:
        return {}
    details = usage.get("completion_tokens_details") or {}
    prompt_details = usage.get("prompt_tokens_details") or {}
    return {
        "prompt_tokens": usage.get("prompt_tokens") or 0,
        "completion_tokens": usage.get("completion_tokens") or 0,
        "reasoning_tokens": details.get("reasoning_tokens") or 0,
        "cached_tokens": usage.get("prompt_cache_hit_tokens")
        or details.get("cached_tokens") or prompt_details.get("cached_tokens") or 0,
        "total_tokens": usage.get("total_tokens") or 0,
        # issue #22：上游给的是**复数 credits** —— 旧实现只读单数 credit，
        # 恒为 None -> 所有 usage 记录成 0（历史数据无法回填，原始值未落盘）。
        # 保留单数兜底以兼容其它区域/版本的字段差异。
        "credit": usage.get("credits") or usage.get("credit") or 0,
        "original_credits": usage.get("original_credits") or 0,
        # billable 只记录不聚合（布尔求和无意义）：进 JSONL 行，不进
        # USAGE_FIELDS 的累加与 by_model。
        "billable": bool(usage.get("billable")),
    }


def realm_scope(value):
    """面板 realm 取值的归一：显式 "all"（大小写不敏感）= 全部区域 → None（无过滤）。

    只有字面 "all" 被当作通配：None / "" 本来就表示"无过滤"（各路由会先回落到
    CURRENT_REALM 再传进来），"cn" / "intl" / 其它未知值**一律原样保留既有语义**
    （按字面比较；未知值自然过滤出空集 —— 不在这里替面板猜意图）。
    """
    v = str(value if value is not None else "").strip()
    return None if v.lower() in ("", "all") else v


def row_matches_realm(row, realm):
    realm = realm_scope(realm)
    if not realm:
        return True
    r = row.get("realm")
    if r:
        return r == realm
    acct_uid = row.get("account")
    if acct_uid and POOL:
        acc = POOL.get(acct_uid)
        if acc:
            return acc.realm == realm
    model = row.get("model")
    if model:
        return detect_model_realm(model) == realm
    return realm == "cn"


def record_quota(account, payload):
    """把上游 notify_usage 的剩余额度写到账号 extra（只读展示，不参与路由）。"""
    if account is None or not isinstance(payload, dict):
        return
    remain = payload.get("remain_usage") or payload.get("usage")
    if not isinstance(remain, dict):
        return
    snap = {
        "remain_usage": {str(k): v for k, v in remain.items()},
        "usage": (payload.get("usage") if isinstance(payload.get("usage"), dict)
                  else {}),
        "at": int(time.time()),
    }
    try:
        extra = getattr(account, "extra", None)
        if not isinstance(extra, dict):
            extra = {}
            account.extra = extra
        if extra.get("intl_quota") == snap:
            return
        extra["intl_quota"] = snap
        save = getattr(account, "save", None)
        if callable(save):
            save()
    except Exception:
        pass


def record_usage(model, usage, stream=None, elapsed_ms=None, ttft_ms=None,
                 gen_ms=None, fp=None, account=None, effort=None,
                 effort_requested=None, key_id=None, realm_reason=None):
    """Accumulate stats, append a JSONL row, and persist the summary.

    P1-3（推理档位审计 + key 归属）：后三个参数都是**可选**的，旧调用路径不传
    就一个键都不写 —— 行格式与改动前逐字节一致。
      effort            实际下发给上游的档位（None = 本次没有下发该参数）
      effort_requested  客户端请求的原始档位（归一化之前）
      key_id            API key 的**标识**（panel id / legacy / launcher），不涉明文
    请求档位与实际档位同时落盘，才能看出归一化有没有把它们改掉/丢掉。
    """
    fields = _extract_usage(usage)
    if not fields:
        return None
    row = {
        "at": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": model,
        "stream": bool(stream),
        "elapsed_ms": elapsed_ms,
        "ttft_ms": ttft_ms,
        "gen_ms": gen_ms,
    }
    # 参考花费：OpenRouter 公开价（USD/1M tokens）按本次 token 估算。
    # 未定价模型 cost=0、priced=False，看板显示「未定价」，绝不猜。
    try:
        import trae_pricing
        _cost = trae_pricing.compute_row(dict(row, **fields))
        fields["cost_usd"] = _cost.get("usd") or 0.0
        fields["cost_cny"] = _cost.get("cny") or 0.0
        row["priced"] = bool(_cost.get("priced"))
        row["price_or_id"] = _cost.get("or_id") or ""
        if _cost.get("band") is not None:
            row["price_band"] = _cost.get("band")
    except Exception:
        fields["cost_usd"] = 0.0
        fields["cost_cny"] = 0.0
        row["priced"] = False
    row.update(fields)
    if fp:
        row.update(fp)
    if account:
        row["account"] = account
    # P1-3：推理档位审计（请求档位 vs 实际下发档位）与 API key 归属。
    # 三者都是可选参数：不传则一个键都不写，旧行格式不变。
    if effort_requested:
        row["reasoning_effort_requested"] = str(effort_requested)
    if effort:
        row["reasoning_effort"] = str(effort)
    elif effort_requested:
        # 请求了档位但归一化后不下发（模型无档位表 / 被丢弃）：显式记空串，
        # 便于区分「客户端没请求」与「请求了但没生效」两种情况。
        row["reasoning_effort"] = ""
    if key_id:
        # 只记 key 的**标识**（panel 分配的 id / legacy / launcher），绝无明文 key。
        row["key_id"] = str(key_id)
    if realm_reason is not None:
        # #26：本次是否**自动换区**及原因（持久化，面板不依赖响应头即可读到）。
        #   "model_missing" 当前区官方清单里没有这个模型（独占表 / 清单驱动）
        #   "no_account"    模型本区有（或无法判断），是账号可用性把它推走的
        #   ""（空串）      本次**没有换区**（正常路径）
        #   键不存在        该行产生于本字段上线前（旧行）—— 与「没换区」明确区分
        row["realm_reason"] = str(realm_reason)
    acc = POOL.get(account) if (account and POOL) else None
    row["realm"] = acc.realm if acc else CURRENT_REALM
    if gen_ms and gen_ms > 0:
        row["tokens_per_sec"] = round(
            fields["completion_tokens"] / (gen_ms / 1000.0), 2)
    if fields["prompt_tokens"] > 0:
        row["cache_hit_pct"] = round(
            fields["cached_tokens"] * 100.0 / fields["prompt_tokens"], 1)
    with _lock:
        _usage["requests"] += 1
        for k in USAGE_FIELDS:
            if k in fields:
                _usage[k] += fields[k]
        if ttft_ms is not None:
            _usage["ttft_ms_sum"] += ttft_ms
            _usage["ttft_samples"] += 1
        if gen_ms is not None:
            _usage["gen_ms_sum"] += gen_ms
            _usage["gen_samples"] += 1
        if elapsed_ms is not None:
            _usage["wall_ms_sum"] += elapsed_ms
            _usage["wall_samples"] += 1
        per = _usage["by_model"].setdefault(
            model, {"requests": 0, **{k: 0 for k in USAGE_FIELDS}})
        per["requests"] += 1
        for k in USAGE_FIELDS:
            if k in fields:
                per[k] += fields[k]
        summary = json.loads(json.dumps(_usage))
    _persist_usage(row, summary, "usage persist failed")
    # issue #43：把「这个号刚被用过」告诉余额刷新器（**只打标，不联网**）。
    # 打标失败绝不能影响记账/响应，所以整段吞异常。
    try:
        if account and POOL is not None and hasattr(POOL, "note_usage"):
            POOL.note_usage(account)
    except Exception:
        pass
    try:
        t_tokens = fields.get("total_tokens", 0)
        dur = " %dms" % elapsed_ms if elapsed_ms is not None else ""
        acc_tag = " acct=%s" % account[:8] if account else ""
        speed_tag = " %st/s" % row.get("tokens_per_sec", 0) \
            if row.get("tokens_per_sec") else ""
        log("chat done: model=%s%s%s tokens=%d (in=%d out=%d)%s"
            % (model, acc_tag, dur, t_tokens, fields.get("prompt_tokens", 0),
               fields.get("completion_tokens", 0), speed_tag), tag="chat")
    except Exception:
        pass
    return row


def _persist_usage(row, summary, fail_label):
    """Append one JSONL row and atomically rewrite the summary.

    The temp file carries a unique suffix: two threads writing the same
    "<summary>.tmp" race, and the loser's os.replace() fails with ENOENT
    because the winner already renamed the file away.
    """
    try:
        usage_dir = Path(USAGE_DIR).resolve()
        usage_dir.mkdir(parents=True, exist_ok=True)
        log_path = usage_dir / os.path.basename(USAGE_LOG)
        summary_path = usage_dir / os.path.basename(USAGE_SUMMARY)
        if not (log_path.is_relative_to(usage_dir)
                and summary_path.is_relative_to(usage_dir)):
            raise ValueError("usage path escapes base directory")
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        tmp_summary = usage_dir / (
            os.path.basename(USAGE_SUMMARY)
            + ".%d.%d.tmp" % (os.getpid(), threading.get_ident()))
        if not tmp_summary.is_relative_to(usage_dir):
            raise ValueError("usage path escapes base directory")
        try:
            tmp_summary.write_text(json.dumps(summary, ensure_ascii=False,
                                              indent=2), encoding="utf-8")
            os.replace(tmp_summary, summary_path)
        except Exception:
            try:
                os.unlink(tmp_summary)
            except Exception:
                pass
            raise
    except Exception as exc:
        log("%s: %s" % (fail_label, exc))


def record_error(model, status, message, elapsed_ms=None):
    """Count a failed request and append it to the log so errors are visible."""
    row = {
        "at": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": model,
        "error": True,
        "status": status,
        # 保留更完整的上游错误（provider_error 的内层 details 常在 200+ 字节）
        "message": str(message)[:400],
        "elapsed_ms": elapsed_ms,
    }
    with _lock:
        _usage["errors"] += 1
        if elapsed_ms is not None:
            _usage["wall_ms_sum"] += elapsed_ms
            _usage["wall_samples"] += 1
        summary = json.loads(json.dumps(_usage))
    _persist_usage(row, summary, "error persist failed")
    dur = " %dms" % elapsed_ms if elapsed_ms is not None else ""
    log("request error: model=%s%s status=%s msg=%s"
        % (model, dur, status, str(message)[:360]),
        level="ERROR", tag="chat")
    return row


def _pct(values, q):
    """Nearest-rank percentile (no interpolation) - good enough for latency."""
    if not values:
        return None
    ordered = sorted(values)
    idx = int(round((q / 100.0) * (len(ordered) - 1)))
    return ordered[max(0, min(len(ordered) - 1, idx))]


# ---------------------------------------------------------------------------
# 时间窗口：?range=day|week|month|all|custom&since=&until=
# ---------------------------------------------------------------------------
# 语义（与面板选择器、wb 参考实现一致）：day/week/month 是**锚到本地零点**的日历
# 窗口（week 从周一起算、month 从 1 号起算），custom 取面板传来的两个 epoch（任一端
# 可缺省，反了自动交换），all / 空 / 未知值 = 不设窗口（历史全量）。返回 (since, until)，
# None 表示该侧无界；两侧都 None 时下游**完全不做过滤**（_row_in_window 直接返回 True，
# 连 at 都不读），因此不传 range 的输出与改动前逐字节一致。
def _epoch_or_none(value):
    """面板传来的 epoch 秒；负值/不可解析一律丢弃（不做钳制，宁可不设界）。"""
    if value in (None, "", False):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None


def _local_day_start(ts):
    """任意时间戳 -> 本地自然日 0 点（epoch 秒）。"""
    lt = time.localtime(ts)
    return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                            0, 0, 0, 0, 0, -1)))


def _local_midnight(days_back=0):
    return _local_day_start(time.time() - days_back * 86400)


def range_window(value, since=None, until=None):
    v = str(value or "").strip().lower()
    if v in ("today", "day", "1d"):
        return _local_midnight(), None
    if v in ("week", "w"):
        return _local_midnight(days_back=time.localtime().tm_wday), None
    if v in ("month", "m"):
        lt = time.localtime()
        return time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1)), None
    if v == "custom":
        lo, hi = _epoch_or_none(since), _epoch_or_none(until)
        if lo is not None and hi is not None and hi < lo:
            lo, hi = hi, lo
        return lo, hi
    return None, None


def range_query(query):
    """从 parse_qs 的查询串里取 (range, since, until)；缺省一律 None。"""
    def first(name):
        values = query.get(name) or [None]
        return values[0] if values else None
    return first("range"), first("since"), first("until")


def _row_in_window(row, since, until):
    """窗口过滤：两侧都 None 时不做任何读取（老路径零开销、零差异）。"""
    if since is None and until is None:
        return True
    at = row.get("at")
    if not isinstance(at, (int, float)):
        at = 0
    if since is not None and at < since:
        return False
    if until is not None and at > until:
        return False
    return True


_perf_cache = {}
_perf_lock = threading.Lock()


def perf_stats(sample=5000, realm=None, ttl=10, range=None, since=None, until=None):
    """Cached wrapper: parsing thousands of rows is CPU-heavy, and the
    dashboard polls this endpoint every few seconds."""
    r = realm or CURRENT_REALM
    lo, hi = range_window(range, since, until)
    try:
        # 缓存键带上**解析后的边界**（不是 range 标签）：week 与 month 相互重叠，
        # 一个标签无法描述两个窗口，否则会拿一个窗口的数据冒充另一个。
        key = (int(sample), r, lo, hi)
    except Exception:
        key = (5000, r, lo, hi)
    now = time.time()
    with _perf_lock:
        hit = _perf_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    data = _perf_stats_uncached(sample, realm, since=lo, until=hi)
    with _perf_lock:
        _perf_cache[key] = (time.time(), data)
    return data


def _perf_stats_uncached(sample=5000, realm=None, since=None, until=None):
    """Latency percentiles + derived rates, computed from the JSONL log.

    since/until 为窗口边界（None=该侧无界）；两者都 None 时行为与改动前一致。
    """
    ttfts, gens, walls, rates, hits, tok_rates = [], [], [], [], [], []
    total = ok = err = 0
    m_buckets = {}
    # 只读日志末尾 sample 行：readlines() 会把整个日志读成字符串列表。
    rows = [raw.decode("utf-8", "replace") for raw in _tail_lines(USAGE_LOG, sample)]
    for line in rows:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if realm and not row_matches_realm(r, realm):
            continue
        if not _row_in_window(r, since, until):
            continue
        total += 1
        if r.get("error"):
            err += 1
            if r.get("elapsed_ms"):
                walls.append(r["elapsed_ms"])
            continue
        ok += 1
        if r.get("ttft_ms") is not None:
            ttfts.append(r["ttft_ms"])
        if r.get("gen_ms") is not None:
            gens.append(r["gen_ms"])
        if r.get("elapsed_ms") is not None:
            walls.append(r["elapsed_ms"])
        if r.get("tokens_per_sec"):
            tok_rates.append(r["tokens_per_sec"])
        if r.get("cache_hit_pct") is not None:
            hits.append(r["cache_hit_pct"])
        m_id = r.get("model") or "unknown"
        mb = m_buckets.setdefault(m_id, {"total": 0, "ok": 0, "err": 0,
                                         "ttfts": [], "gens": [], "walls": [],
                                         "tok_rates": [], "hits": []})
        mb["total"] += 1
        if r.get("error"):
            mb["err"] += 1
        else:
            mb["ok"] += 1
        if r.get("ttft_ms") is not None:
            mb["ttfts"].append(r["ttft_ms"])
        if r.get("gen_ms") is not None:
            mb["gens"].append(r["gen_ms"])
        if r.get("elapsed_ms") is not None:
            mb["walls"].append(r["elapsed_ms"])
        if r.get("tokens_per_sec"):
            mb["tok_rates"].append(r["tokens_per_sec"])
        if r.get("cache_hit_pct") is not None:
            mb["hits"].append(r["cache_hit_pct"])

    def block(vals):
        if not vals:
            return None
        return {
            "avg": round(sum(vals) / len(vals), 1),
            "p50": _pct(vals, 50),
            "p90": _pct(vals, 90),
            "p99": _pct(vals, 99),
            "max": max(vals),
            "samples": len(vals),
        }

    return {
        "sampled": total,
        "success": ok,
        "errors": err,
        "inner_errors": inner_error_snapshot(),
        "success_rate_pct": round(ok * 100.0 / total, 1) if total else None,
        "ttft_ms": block(ttfts),
        "generation_ms": block(gens),
        "wall_ms": block(walls),
        "tokens_per_sec": block(tok_rates),
        "cache_hit_pct": block(hits),
        "by_model": {
            mid: {
                "requests": mb["total"],
                "errors": mb["err"],
                "success_rate_pct": round(mb["ok"] * 100.0 / mb["total"], 1)
                if mb["total"] else None,
                "ttft_ms": block(mb["ttfts"]),
                "generation_ms": block(mb["gens"]),
                "wall_ms": block(mb["walls"]),
                "tokens_per_sec": block(mb["tok_rates"]),
                "cache_hit_pct": block(mb["hits"]),
            } for mid, mb in m_buckets.items()
        },
    }


_snap_cache = {}
_snap_lock = threading.Lock()


def usage_snapshot(realm=None, ttl=10):
    """Cached wrapper: the dashboard polls this every few seconds."""
    r = realm or CURRENT_REALM
    now = time.time()
    with _snap_lock:
        hit = _snap_cache.get(r)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    data = _usage_snapshot_uncached(r)
    with _snap_lock:
        _snap_cache[r] = (time.time(), data)
    return data


def _usage_snapshot_uncached(realm=None):
    r = realm or CURRENT_REALM
    rep = POOL.representative(realm=r) if POOL else current_account()
    snap = _empty_stats()
    snap["started"] = _usage.get("started", time.time())
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if r and not row_matches_realm(row, r):
                    continue
                if row.get("error"):
                    snap["errors"] += 1
                else:
                    snap["requests"] += 1
                    for k in USAGE_FIELDS:
                        if k in row:
                            snap[k] += (row[k] or 0)
                    m = row.get("model") or "unknown"
                    per = snap["by_model"].setdefault(
                        m, {"requests": 0, "accounts": {},
                            **{k: 0 for k in USAGE_FIELDS}})
                    per["requests"] += 1
                    for k in USAGE_FIELDS:
                        if k in row:
                            per[k] += (row[k] or 0)
                    acct_id = row.get("account")
                    if acct_id:
                        per.setdefault("accounts", {})
                        per["accounts"][acct_id] = per["accounts"].get(acct_id, 0) + 1
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("usage snapshot read failed: %s" % exc)
    snap["since"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(snap.get("started", time.time())))
    snap["log_file"] = USAGE_LOG
    snap["realm"] = r
    snap["accounts_map"] = {a.uid: {"nickname": account_label(a),
                                    "realm": a.realm}
                            for a in POOL.accounts} if POOL else {}
    snap["account"] = {
        "uid": (rep.uid if rep else ""),
        "domain": (rep.domain if rep else ""),
        "issuer": ("trae" if rep else ""),
        "credential_file": (os.path.basename(rep.path) if rep and rep.path else ""),
        "expires_at": (rep.expires_at if rep else 0),
        "accounts": (len(POOL.accounts) if POOL else 0),
        "accounts_ready": (POOL.count_ready() if POOL else 0),
    }
    return snap


def _tail_lines(path, max_lines, chunk=256 * 1024):
    """Return up to the last `max_lines` non-empty lines, oldest first.

    The usage log passes 20MB within a day. Scanning it end to end on every
    dashboard poll was the dominant cost behind slow /usage/* responses.
    """
    lines = []
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0 and len(lines) < max_lines:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                parts = buf.split(b"\n")
                buf = parts[0]
                for raw in reversed(parts[1:]):
                    if not raw.strip():
                        continue
                    lines.append(raw)
                    if len(lines) >= max_lines:
                        break
            if len(lines) < max_lines and buf.strip():
                lines.append(buf)
    except FileNotFoundError:
        return []
    except Exception as exc:
        log("tail read failed: %s" % exc)
        return []
    lines.reverse()
    return lines


def count_usage_rows(realm=None):
    """Cheap row count - substring match instead of a full JSON parse."""
    realm = realm_scope(realm)      # realm=all 走无 needles 分支，与逐行过滤一致
    needles = ()
    if realm:
        needles = ('"realm": "%s"' % realm, '"realm":"%s"' % realm)
    n = 0
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                if not needles:
                    n += 1
                    continue
                if any(x in line for x in needles):
                    n += 1
                    continue
                if '"realm"' in line:
                    continue
                try:
                    if row_matches_realm(json.loads(line), realm):
                        n += 1
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return n


def recent_usage(limit=100, realm=None, page=1):
    """Paginated rows from the tail of the log (page 1 is latest)."""
    try:
        limit = max(1, int(limit))
    except Exception:
        limit = 100
    try:
        page = max(1, int(page))
    except Exception:
        page = 1
    total = count_usage_rows(realm)
    total_pages = max(1, (total + limit - 1) // limit) if total > 0 else 1
    page = min(page, total_pages)
    target_count = page * limit
    matching = []
    chunk = 256 * 1024
    try:
        with open(USAGE_LOG, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0 and len(matching) < target_count:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                parts = buf.split(b"\n")
                buf = parts[0]
                for raw in reversed(parts[1:]):
                    st = raw.strip()
                    if not st:
                        continue
                    try:
                        item = json.loads(st.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    if realm and not row_matches_realm(item, realm):
                        continue
                    matching.append(item)
                    if len(matching) >= target_count:
                        break
            if len(matching) < target_count and buf.strip():
                try:
                    item = json.loads(buf.strip().decode("utf-8", "replace"))
                    if not realm or row_matches_realm(item, realm):
                        matching.append(item)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("recent_usage read failed: %s" % exc)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    page_rows = matching[start_idx:end_idx]
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "rows": page_rows,
    }


POOL = None
# issue #43：使用驱动的余额刷新器（main() 里创建；单测/CLI 场景保持 None）
CREDITS_USAGE_REFRESHER = None
SCHEDULER = None
ACCOUNTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts")
REALM_STATE_FILE = os.path.join(ACCOUNTS_DIR, "active_realm.json")


def load_persisted_realm():
    global CURRENT_REALM
    if os.path.isfile(REALM_STATE_FILE):
        try:
            with open(REALM_STATE_FILE, "r", encoding="utf-8") as fh:
                d = json.load(fh)
                r = d.get("realm")
                if r in ("intl", "cn"):
                    CURRENT_REALM = r
                    return CURRENT_REALM
        except Exception as e:
            log("could not load active realm: %s" % e)
    return CURRENT_REALM


def save_persisted_realm(realm):
    global CURRENT_REALM
    if realm in ("intl", "cn"):
        CURRENT_REALM = realm
        try:
            state_dir = Path(ACCOUNTS_DIR).resolve()
            state_dir.mkdir(parents=True, exist_ok=True)
            state_file = state_dir / os.path.basename(REALM_STATE_FILE)
            if not state_file.is_relative_to(state_dir):
                raise ValueError("realm state path escapes base directory")
            state_file.write_text(
                json.dumps({"realm": realm, "updated_at": time.time(),
                            "updated_iso": time.strftime("%Y-%m-%d %H:%M:%S")},
                           indent=2),
                encoding="utf-8")
            log("persisted active realm '%s' to disk" % realm)
        except Exception as exc:
            log("failed to persist active realm: %s" % exc)
    return CURRENT_REALM


API_KEY = None
SYSTEM_PROMPT = DEFAULT_SYSTEM_PROMPT


def account_credit_view(account):
    """Normalize plan + check-in credits + quota for dashboard/API."""
    ent = getattr(account, "entitlement", None) or {}
    usage = ent.get("ent_usage") if isinstance(ent.get("ent_usage"), dict) else {}
    packs = usage.get("user_entitlement_pack_list") or []
    pack = {}
    if isinstance(packs, list):
        for item in packs:
            if isinstance(item, dict):
                pack = item
                break
    plan = str(pack.get("display_desc") or "")
    quota = pack.get("quota") if isinstance(pack.get("quota"), dict) else {}
    used = pack.get("usage") if isinstance(pack.get("usage"), dict) else {}
    summary = usage.get("usage_summary") if isinstance(usage.get("usage_summary"), dict) else {}
    try:
        if summary.get("total_amount") is not None:
            limit = float(summary.get("total_amount") or 0)
            consumed = float(summary.get("consumed_amount") or 0)
        else:
            limit = int(quota.get("advanced_model_request_limit") or 0)
            consumed = int(used.get("advanced_model_request_usage") or 0)
    except (TypeError, ValueError):
        limit, consumed = 0, 0
    remain = max(0, limit - consumed)
    if isinstance(remain, float):
        remain = round(remain, 2)
    checkin = (getattr(account, "extra", {}) or {}).get("checkin") or {}
    try:
        checkin_credits = int(checkin.get("credits") or 0)
    except (TypeError, ValueError):
        checkin_credits = 0
    return {
        "checkin": checkin_credits,
        "checkin_at": checkin.get("at") or "",
        "checked_in": bool(checkin.get("checked_in")),
        "plan": plan,
        "remain": remain,
        "limit": limit,
        "used": consumed,
        "total": limit,
        "updated_at": getattr(account, "usage_updated_at", 0) or 0,
        "source": "entitlement+checkin",
    }


def account_fetch_credits(account):
    """Refresh upstream usage/entitlement + CN check-in credits, then persist.

    The old Account.fetch_credits() only read the local snapshot, so clicking
    “刷新权益” never actually talked to Trae. This function is the single
    upstream refresh path used by /accounts/credits and the dashboard button.
    """
    errors = []
    raw_usage = raw_ent = None
    client = _trae_client
    if client is not None:
        fn = getattr(client, "fetch_usage", None)
        if callable(fn):
            try:
                raw_usage = fn(account, realm=getattr(account, "realm", None))
            except Exception as exc:
                errors.append("fetch_usage: %s" % str(exc)[:160])
        fn = getattr(client, "fetch_entitlement", None)
        if callable(fn):
            try:
                raw_ent = fn(account, realm=getattr(account, "realm", None))
            except Exception as exc:
                errors.append("fetch_entitlement: %s" % str(exc)[:160])
        # CN check-in credits are user-visible “积分”; INTL has no such endpoint.
        if str(getattr(account, "realm", "")) == "cn":
            fn = getattr(client, "checkin_status", None)
            if callable(fn):
                try:
                    st = fn(account, realm="cn")
                    if isinstance(st, dict) and st.get("credits") is not None:
                        extra = getattr(account, "extra", None)
                        if not isinstance(extra, dict):
                            extra = {}
                            account.extra = extra
                        extra["checkin"] = {
                            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "checked_in": bool(st.get("checked_in")),
                            "credits": int(st.get("credits") or 0),
                            "earned_credit": 0,
                        }
                except Exception as exc:
                    errors.append("checkin_status: %s" % str(exc)[:160])
    if isinstance(raw_usage, dict):
        account.usage = raw_usage
    if isinstance(raw_ent, dict):
        account.entitlement = raw_ent
    account.usage_updated_at = time.time()
    try:
        account.save()
    except Exception as exc:
        errors.append("save: %s" % str(exc)[:160])
    view = account_credit_view(account)
    ok = bool(raw_usage or raw_ent or view.get("checkin") or view.get("plan"))
    return {"ok": ok, "credits": view, "usage": account.usage,
            "entitlement": account.entitlement,
            "updated_at": account.usage_updated_at,
            "errors": errors}




def account_fetch_plan(account):
    """查订阅计划：同上，缺失实现返回空 dict（不抛、不 500）。"""
    for name in ("fetch_plan", "refresh_plan"):
        fn = getattr(account, name, None)
        if callable(fn):
            try:
                return fn() or {}
            except Exception as exc:
                return {"error": str(exc)[:200]}
    return {}


def account_refreshable(account):
    """是否值得打上游查余额（启用 + 有凭证 + 未在冷却）。"""
    if account is None:
        return False
    if not getattr(account, "enabled", True):
        return False
    if not account_token(account):
        return False
    try:
        if getattr(account, "ready", None) and not account.ready():
            return False
    except Exception:
        pass
    return True


def _refreshable_accounts(accounts):
    """从账号集合里挑出**可以安全打上游**的号（#25 遗留其二）。

    判据与 pick/count_ready 的准入一致：enabled 且有凭证。禁用号 / 坏凭证号
    打上游不但没有意义，还可能被上游回一个**空账本**，把本地账本再零化一次
    （本仓那个 enabled=False 的 intl 号正是这个形态）。

    返回 (targets, skipped)：skipped 是 [{"uid", "reason"}]，调用方**必须**把它
    放进响应里 —— 否则「少刷新了几个号」会变成静默行为，排查时看不见。
    """
    targets, skipped = [], []
    for a in accounts or []:
        if a is None:
            continue
        if not a.enabled:
            skipped.append({"uid": a.uid, "reason": "disabled"})
            continue
        if not a.access_token:
            skipped.append({"uid": a.uid, "reason": "no_credential"})
            continue
        targets.append(a)
    return targets, skipped


def account_views(realm=None):
    """List view of every account, including a live readiness flag."""
    if not POOL:
        return []
    return POOL.list_public(realm=realm)


_CREDITS_SUMMARY_NOTE = ("registered values only; freshness depends on "
                         "check-in and consumption write-back")

# 按**解析后的窗口边界**分键：(since, until) -> (at, data)。week/month 相互重叠，
# 一个"范围标签"键会让一个窗口的数据冒充另一个（见 range_window 的注释）。
_byacct_cache = {}
_byacct_lock = threading.Lock()
# P1-3 收尾：按 key 聚合用**同形状**的缓存（同 key 口径：解析后的窗口边界）
_bykey_cache = {}
_bykey_lock = threading.Lock()


def credits_summary():
    """issue #21：只读积分汇总（**绝不触发上游查询**）。

    数据源是 accounts/*.json 里**已登记**的 credits（fetch_credits 写入 +
    每次消耗回写）；同宿主机轮询方（API Pool 面板）用它替代裸读目录文件。
    与 /accounts/credits 的区别：那个会逐号强刷上游，只适合手动点击 ——
    本函数一次网络调用都不发。

    防御：POOL 为 None / 列表为空 / 账号没有 credits（新号还没登过）/
    credits 结构残缺 —— 都只影响该行取值（None）与它是否计入汇总，
    绝不抛异常、绝不 500。
    """
    by_realm = {}
    rows = []
    total_remain = 0
    accounts = list(POOL.accounts) if POOL else []
    for a in accounts:
        try:
            view = a._credit_view(a)
        except Exception:
            view = {}
        cred = dict(view)
        cred["size"] = view.get("limit", 0)
        cred["updated_at"] = view.get("updated_at", 0)
        realm = getattr(a, "realm", "") or ""
        remain = cred.get("remain")
        # issue #39：团队账号的套餐 may 用满而共享池仍有余额——汇总按有效余额，
        # 同时保留原始 remain 便于核对（两者都会出现在行里）。
        # 新 v2 usage_summary 的 remain 是小数（如 899.61）；不要走
        # effective_remain 的 int() 截断，否则汇总会丢两位小数。
        eff = remain if isinstance(remain, (int, float)) and not isinstance(remain, bool) else trae_accounts.effective_remain(cred)
        rows.append({
            "uid": getattr(a, "uid", "") or "",
            "nickname": account_label(a),
            "realm": realm,
            "credits_remain": remain,
            "credits_remain_effective": eff,
            "credits_shared_remain": (cred.get("shared") or {}).get("remain")
            if isinstance(cred.get("shared"), dict) else None,
            "credits_used": cred.get("used"),
            "credits_size": cred.get("size"),
            "checkin": cred.get("checkin"),
            "checkin_at": cred.get("checkin_at"),
            # 登记时间：credits.updated_at（fetch_credits 写入），不是文件 mtime。
            "registered_at": cred.get("updated_at"),
        })
        if isinstance(eff, (int, float)) and not isinstance(eff, bool):
            by_realm[realm] = round(by_realm.get(realm, 0) + float(eff), 2)
            total_remain = round(total_remain + float(eff), 2)
    return {
        "by_realm": by_realm,
        "totals": {"remain": total_remain, "accounts": len(rows)},
        "accounts": rows,
        "note": _CREDITS_SUMMARY_NOTE,
    }


def usage_by_account(ttl=10, range=None, since=None, until=None):
    """Cached wrapper: full aggregation over the whole log is expensive."""
    lo, hi = range_window(range, since, until)
    now = time.time()
    key = (lo, hi)
    with _byacct_lock:
        hit = _byacct_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    data = _usage_by_account_uncached(since=lo, until=hi)
    with _byacct_lock:
        _byacct_cache[key] = (time.time(), data)
    return data


def _usage_by_account_uncached(since=None, until=None):
    """Aggregate the JSONL log per account id（可选窗口过滤）。"""
    buckets = {}
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get("error"):
                    continue
                if not _row_in_window(row, since, until):
                    continue
                key = row.get("account") or "(unattributed)"
                bucket = buckets.setdefault(key, {
                    "account": key, "requests": 0, "prompt_tokens": 0,
                    "completion_tokens": 0, "reasoning_tokens": 0,
                    "cached_tokens": 0, "total_tokens": 0, "models": {},
                })
                bucket["requests"] += 1
                for field in ("prompt_tokens", "completion_tokens",
                              "reasoning_tokens", "cached_tokens",
                              "total_tokens"):
                    bucket[field] += row.get(field) or 0
                model = row.get("model") or "?"
                bucket["models"][model] = bucket["models"].get(model, 0) + 1
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("usage_by_account failed: %s" % exc)
    out = sorted(buckets.values(), key=lambda b: -b["total_tokens"])
    for item in out:
        item["models"] = sorted(item["models"].items(), key=lambda kv: -kv[1])[:5]
    return out


def usage_by_key(ttl=10, range=None, since=None, until=None):
    """Cached wrapper：与 usage_by_account 同缓存 key、同 TTL、同窗口解析。"""
    lo, hi = range_window(range, since, until)
    now = time.time()
    key = (lo, hi)
    with _bykey_lock:
        hit = _bykey_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    data = _usage_by_key_uncached(since=lo, until=hi)
    with _bykey_lock:
        _bykey_cache[key] = (time.time(), data)
    return data


def _usage_by_key_uncached(since=None, until=None):
    """Aggregate the JSONL log per API key id（可选窗口过滤）。

    P1-3 收尾：与 _usage_by_account_uncached **逐行同判**——同一套
    _row_in_window 过滤、同一套「error 行跳过」规则、同样的字段与排序，
    只把分桶键从 account 换成 key_id。因此两个视图在同一 range 下：
        sum(by_key.total_tokens) == sum(by_account.total_tokens)
    （这条不变量可直接当作「同源」的回归断言。）

    注意：
      - 缺 key_id 的行（P1-3 字段上线前的历史行、未带 key 的面板会话）归入
        "(no-key)" 桶，**不静默丢弃**——丢弃会让「按 key 求和」小于总量；
      - 只读本地 usage.jsonl，**不触发任何上游调用**；
      - credit / original_credits 是 USAGE_FIELDS 的既有成员（by-account 目前
        只累 token），这里一并累上：同名数字字段的算法与 by-account 完全一致，
        属**字段超集**，不会让两个视图的数字对不上。
    """
    buckets = {}
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get("error"):
                    continue
                if not _row_in_window(row, since, until):
                    continue
                key = row.get("key_id") or "(no-key)"
                bucket = buckets.setdefault(key, {
                    "key_id": key, "requests": 0, "prompt_tokens": 0,
                    "completion_tokens": 0, "reasoning_tokens": 0,
                    "cached_tokens": 0, "total_tokens": 0,
                    "credit": 0.0, "original_credits": 0.0, "models": {},
                })
                bucket["requests"] += 1
                for field in ("prompt_tokens", "completion_tokens",
                              "reasoning_tokens", "cached_tokens",
                              "total_tokens"):
                    bucket[field] += row.get(field) or 0
                bucket["credit"] += row.get("credit") or 0
                bucket["original_credits"] += row.get("original_credits") or 0
                model = row.get("model") or "?"
                bucket["models"][model] = bucket["models"].get(model, 0) + 1
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("usage_by_key failed: %s" % exc)
    out = sorted(buckets.values(), key=lambda b: -b["total_tokens"])
    for item in out:
        item["models"] = sorted(item["models"].items(), key=lambda kv: -kv[1])[:5]
        item["credit"] = round(item["credit"], 6)
        item["original_credits"] = round(item["original_credits"], 6)
    return out


_key_detail_cache = {}
_key_detail_lock = threading.Lock()


def usage_key_detail(key_id, days=7, ttl=10):
    """Per-API-key graphical usage: daily tokens, model split, latency, recent.

    Only reads local usage.jsonl; never calls upstream. key_id is the panel's
    stable id (not the secret key). Returns zero-filled days for chart continuity.
    """
    key_id = str(key_id or "")
    try:
        days = max(1, min(90, int(days or 7)))
    except (TypeError, ValueError):
        days = 7
    since = _local_day_start(time.time())
    for _ in range(days - 1):
        since = _local_day_start(since - 86400)
    cache_key = (key_id, days, since)
    now = time.time()
    with _key_detail_lock:
        hit = _key_detail_cache.get(cache_key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    series, index = [], {}
    for i in range(days):
        start = since
        for _ in range(i):
            start = _local_day_start(start + 86400 + 43200)
        item = {
            "at": start, "day": time.strftime("%Y-%m-%d", time.localtime(start)),
            "label": time.strftime("%m-%d", time.localtime(start)),
            "requests": 0, "errors": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "cached_tokens": 0,
            "total_tokens": 0, "elapsed_ms": 0, "elapsed_n": 0,
        }
        series.append(item)
        index[start] = item
    totals = {"requests": 0, "errors": 0, "prompt_tokens": 0,
              "completion_tokens": 0, "cached_tokens": 0,
              "total_tokens": 0, "elapsed_ms": 0, "elapsed_n": 0}
    models, recent = {}, []
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if (row.get("key_id") or "(no-key)") != key_id:
                    continue
                at = row.get("at")
                if not isinstance(at, (int, float)) or at < since:
                    continue
                is_err = bool(row.get("error"))
                item = index.get(_local_day_start(at))
                bucket = item if item is not None else None
                if bucket is not None:
                    bucket["errors" if is_err else "requests"] += 1
                    if not is_err:
                        for field in ("prompt_tokens", "completion_tokens",
                                      "cached_tokens", "total_tokens"):
                            bucket[field] += row.get(field) or 0
                        bucket["elapsed_ms"] += row.get("elapsed_ms") or 0
                        bucket["elapsed_n"] += 1
                totals["errors" if is_err else "requests"] += 1
                if not is_err:
                    for field in ("prompt_tokens", "completion_tokens",
                                  "cached_tokens", "total_tokens"):
                        totals[field] += row.get(field) or 0
                    totals["elapsed_ms"] += row.get("elapsed_ms") or 0
                    totals["elapsed_n"] += 1
                    model = row.get("model") or "?"
                    m = models.setdefault(model, {"model": model, "requests": 0,
                                                 "total_tokens": 0})
                    m["requests"] += 1
                    m["total_tokens"] += row.get("total_tokens") or 0
                recent.append({
                    "at": at, "iso": row.get("iso") or "",
                    "model": row.get("model") or "",
                    "error": bool(row.get("error")),
                    "total_tokens": row.get("total_tokens") or 0,
                    "elapsed_ms": row.get("elapsed_ms") or 0,
                })
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("usage_key_detail failed: %s" % exc)
    recent.sort(key=lambda r: r.get("at") or 0, reverse=True)
    data = {
        "ok": True, "key_id": key_id, "days": days,
        "since": since, "until": time.time(),
        "series": series,
        "totals": totals,
        "models": sorted(models.values(),
                         key=lambda m: -int(m.get("total_tokens") or 0)),
        "recent": recent[:30],
    }
    with _key_detail_lock:
        if len(_key_detail_cache) > 32:
            oldest = min(_key_detail_cache,
                         key=lambda k: _key_detail_cache[k][0])
            _key_detail_cache.pop(oldest, None)
        _key_detail_cache[cache_key] = (time.time(), data)
    return data


_series_cache = {}
_series_lock = threading.Lock()


def usage_timeseries(realm=None, range=None, since=None, until=None,
                     bucket_seconds=None, ttl=10):
    """分桶的 token/积分时序（面板时序图）。

    桶宽随窗口自适应：minute（span <= 6h）/ hour（<= 14d）/ day（其余），
    显式 bucket_seconds 覆盖（下限 60 秒）。计数口径与 KPI/模型表一致：
    非 error 行计入 requests 与各 token 字段，error 行计入 errors；credit 对
    所有行累加（与 _usage_snapshot_uncached 的 USAGE_FIELDS 口径相同）。
    最近 50 条 credit > 0 的请求随行返回，面板无需再打一个端点。

    缓存按**解析后的边界 + 桶宽**分键：week/month 相互重叠，一个"范围标签"
    无法描述两个窗口；桶宽不同即载荷不同（自动桶宽会随 span 翻转）。
    """
    r = realm or CURRENT_REALM
    lo, hi = range_window(range, since, until)
    pinned_lo, pinned_hi = lo, hi
    # 「显式给了窗口参数」与「完全没给」必须分开：
    #   · 没给（老面板/裸调用）→ 图表默认看最近 24 小时（改动前的既有行为）；
    #   · 给了 range=all（或 custom 但只给了一端）→ 该侧是**真的无界**，
    #     不能悄悄缩成 24 小时，否则 KPI(range=all=全量) 与序列(近 24h) 不自洽。
    explicit = not (range is None and since is None and until is None)
    if hi is None:
        hi = time.time()
    if lo is None:
        lo = 0 if explicit else hi - 86400
    span = max(1.0, hi - lo)
    if bucket_seconds:
        step = max(60, int(bucket_seconds))
    elif span <= 6 * 3600:
        step = 60
    elif span <= 14 * 86400:
        step = 3600
    else:
        step = 86400
    now = time.time()
    edge = "unbounded" if explicit else "auto"
    key = (r or "all", pinned_lo if pinned_lo is not None else edge,
           pinned_hi if pinned_hi is not None else edge, step)
    with _series_lock:
        hit = _series_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
    data = _usage_timeseries_uncached(r, lo, hi, step)
    with _series_lock:
        _series_cache[key] = (time.time(), data)
    return data


def _usage_timeseries_uncached(realm, lo, hi, step):
    """One uncached pass over the log, folding rows into fixed-width buckets."""
    buckets = {}
    credits = []
    try:
        with open(USAGE_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if realm and not row_matches_realm(row, realm):
                    continue
                at = row.get("at")
                at = at if isinstance(at, (int, float)) else 0
                if at < lo or at > hi:
                    continue
                key = int((at - lo) // step)
                bucket = buckets.setdefault(key, {
                    "at": lo + key * step, "requests": 0, "errors": 0,
                    "prompt_tokens": 0, "completion_tokens": 0,
                    "reasoning_tokens": 0, "cached_tokens": 0,
                    "total_tokens": 0, "credit": 0.0,
                })
                if row.get("error"):
                    bucket["errors"] += 1
                else:
                    bucket["requests"] += 1
                    for field in ("prompt_tokens", "completion_tokens",
                                  "reasoning_tokens", "cached_tokens",
                                  "total_tokens"):
                        bucket[field] += (row.get(field) or 0)
                credit = row.get("credit") or 0
                bucket["credit"] += credit
                if credit > 0:
                    credits.append({
                        "at": at, "iso": row.get("iso") or "",
                        "model": row.get("model") or "",
                        "account": row.get("account") or "",
                        "credit": credit,
                        "total_tokens": row.get("total_tokens") or 0,
                    })
    except FileNotFoundError:
        pass
    except Exception as exc:
        log("usage timeseries read failed: %s" % exc)
    credits.sort(key=lambda item: item.get("at") or 0, reverse=True)
    return {
        "ok": True, "realm": realm or "all", "bucket_seconds": step,
        "since": lo, "until": hi,
        "series": [buckets[key] for key in sorted(buckets)],
        "credits": credits[:50],
    }


# ---------------------------------------------------------------------------
# 7 天 / 30 天 Token 用量图（日期 × 分组 两个维度）
# ---------------------------------------------------------------------------
# 与 /usage/timeseries 的关系：那边只有「日期」一个维度（分桶总量），这里多
# 一个分组维度（模型 / 区域 / Key / 账号），供堆叠柱状图用。两者口径一致
# （error 行计入 errors、token 字段与 credit 的累加方式相同）。
# 性能：日志是单进程顺序 append 的，所以从尾部倒读、遇到早于窗口的行即停——
# 30 天窗口不必从文件头扫起（日志实测可长到几十 MB/天）。
DAILY_MAX_DAYS = 90
DAILY_GROUPS = ("model", "realm", "key", "account")
_daily_cache = {}
_daily_lock = threading.Lock()


def _iter_usage_rows_since(since, chunk=256 * 1024):
    """逆序产出 usage 行，遇到早于 since 的行即停止（生成器，内存 O(1)）。

    只在倒读终止时依赖时间有序性：单进程 append 保证同一时刻附近的行总在
    相邻块内，所以按 at 截断不会漏掉窗口内的行。
    """
    try:
        fh = open(USAGE_LOG, "rb")
    except FileNotFoundError:
        return
    try:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        buf = b""
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            parts = buf.split(b"\n")
            buf = parts[0]
            for raw in reversed(parts[1:]):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except Exception:
                    continue
                at = row.get("at")
                if not isinstance(at, (int, float)) or at < since:
                    return
                yield row
        raw = buf.strip()
        if raw:
            try:
                row = json.loads(raw)
            except Exception:
                return
            at = row.get("at")
            if isinstance(at, (int, float)) and at >= since:
                yield row
    except Exception as exc:
        log("daily usage tail read failed: %s" % exc)
    finally:
        fh.close()


def _daily_group_id(row, group):
    """一行归入哪个分组。缺失键不静默丢弃（与 by-key 视图同口径）。"""
    if group == "model":
        return row.get("model") or "(unknown)"
    if group == "realm":
        return row.get("realm") or "(unknown)"
    if group == "key":
        return row.get("key_id") or "(no-key)"
    return row.get("account") or "(unattributed)"


def usage_daily(days=7, group="model", realm=None, ttl=10):
    """Cached wrapper：面板轮询用，同一窗口+分组 10 秒内不重复扫日志。"""
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 7
    days = max(1, min(DAILY_MAX_DAYS, days))
    group = str(group or "model").strip().lower()
    if group not in DAILY_GROUPS:
        group = "model"
    since = _local_day_start(time.time())
    for _ in range(days - 1):
        # 逐个「减一天再取本地零点」而不是 once 减 (days-1)*86400：
        # 有夏令时的时区上按秒回推会得到 01:00 而不是 00:00，随后桶键与行的
        # 本地零点全 miss → 30 天窗口的前半段被静默丢掉（7 天档碰不到）。
        since = _local_day_start(since - 86400)
    key = (realm_scope(realm) or "all", days, group, since)
    now = time.time()
    with _daily_lock:
        hit = _daily_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            # 命中时刷新时间戳 => 淘汰变成 LRU 而不是 FIFO。不刷新的话
            # min(...) 挑的是「最早创建」的那个，也就是正在被轮询的热点条目。
            _daily_cache[key] = (now, hit[1])
            return hit[1]
    data = _usage_daily_uncached(days, group, realm, since)
    with _daily_lock:
        if len(_daily_cache) > 32:
            # 只淘汰**最旧的单个**条目。原先这里是 clear()——清空会把其它
            # 仍在被轮询的 (realm, days, group) 组合一起作废，下一轮全部重算。
            oldest = min(_daily_cache, key=lambda k: _daily_cache[k][0])
            _daily_cache.pop(oldest, None)
        _daily_cache[key] = (time.time(), data)
    return data


def _iter_usage_rows_forward(since, chunk=256 * 1024):
    """顺序读整个日志，只产出 at >= since 的行（倒读失明时的兜底用）。

    record_usage 是顺序 append 的，所以正常情况永远走不到这里；只有当日志
    被外部重排、或系统时钟大幅回拨导致倒读第一行就早于 since 时才需要它。
    """
    try:
        with open(USAGE_LOG, "rb") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except Exception:
                    continue
                at = row.get("at")
                if isinstance(at, (int, float)) and at >= since:
                    yield row
    except FileNotFoundError:
        return
    except Exception as exc:
        log("daily usage forward read failed: %s" % exc)


def _usage_log_size():
    try:
        return os.path.getsize(USAGE_LOG)
    except OSError:
        return 0


def _usage_log_head_ts(probe_bytes=4096):
    """读 usage 日志**第一条**记录的 at（只读开头几 KB）。

    用来区分「窗口内本来就没数据」与「倒读被乱序日志阻死」——倒读对这两种
    情况都产出 0 行，正确处置却相反（前者不该扫，后者必须扫）。正常日志是
    单进程顺序 append 的，头行 at 最小；头行落在窗口内却一行都倒读不到，
    只能是文件被重排过。
    """
    try:
        with open(USAGE_LOG, "rb") as fh:
            chunk = fh.read(probe_bytes)
    except OSError:
        return None
    for raw in chunk.split(b"\n"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            at = json.loads(raw).get("at")
        except Exception:
            return None
        return at if isinstance(at, (int, float)) else None
    return None


def _usage_daily_uncached(days, group, realm, since):
    until = since + days * 86400
    series = []
    index = {}
    for i in range(days):
        # 同 since 的理由：索引用**重算出来的本地零点**，与 fold() 里的
        # _local_day_start(at) 同一口径；直接 since + i*86400 在 DST 时区会
        # 错位一小时，index.get() 全 miss。
        start = since
        for _ in range(i):
            # +1 天再 +12h：只加 86400 在秋季回拨那天会落在「次日 23:00」
            # （再取零点就退回去了），加半天余量能保证跨到下一自然日。
            start = _local_day_start(start + 86400 + 43200)
        lt = time.localtime(start)
        item = {
            "at": start,
            "day": time.strftime("%Y-%m-%d", lt),
            "label": time.strftime("%m-%d", lt),
            "requests": 0, "errors": 0,
            "prompt_tokens": 0, "completion_tokens": 0,
            "reasoning_tokens": 0, "cached_tokens": 0,
            "total_tokens": 0, "credit": 0.0,
            "cost_usd": 0.0, "cost_cny": 0.0,
            "groups": {},
        }
        series.append(item)
        index[start] = item
    groups = {}
    totals = {"requests": 0, "errors": 0, "total_tokens": 0, "credit": 0.0,
              "cost_usd": 0.0, "cost_cny": 0.0}
    day_cache = {}
    seen = [0]

    def fold(row):
        if realm and not row_matches_realm(row, realm):
            return
        at = row.get("at") or 0
        hour = int(at // 3600)
        day_start = day_cache.get(hour)
        if day_start is None:
            day_start = _local_day_start(at)
            day_cache[hour] = day_start
        item = index.get(day_start)
        if item is None:
            return
        is_err = bool(row.get("error"))
        if is_err:
            item["errors"] += 1
        else:
            item["requests"] += 1
        tokens = row.get("total_tokens") or 0
        for field in ("prompt_tokens", "completion_tokens", "reasoning_tokens",
                      "cached_tokens", "total_tokens"):
            item[field] += (row.get(field) or 0)
        credit = row.get("credit") or 0
        item["credit"] += credit
        item["cost_usd"] += (row.get("cost_usd") or 0.0)
        item["cost_cny"] += (row.get("cost_cny") or 0.0)
        gid = _daily_group_id(row, group)
        item["groups"][gid] = item["groups"].get(gid, 0) + tokens
        agg = groups.get(gid)
        if agg is None:
            agg = groups[gid] = {"id": gid, "requests": 0, "errors": 0,
                                 "total_tokens": 0, "credit": 0.0}
        if is_err:
            agg["errors"] += 1
        else:
            agg["requests"] += 1
        agg["total_tokens"] += tokens
        agg["credit"] += credit
        totals["total_tokens"] += tokens
        totals["credit"] += credit
        totals["cost_usd"] += (row.get("cost_usd") or 0.0)
        totals["cost_cny"] += (row.get("cost_cny") or 0.0)
        if is_err:
            totals["errors"] += 1
        else:
            totals["requests"] += 1

    bad_rows = [0]

    def fold_safe(row):
        # usage.jsonl 是历史追加的，_extract_usage 不做类型收敛（上游给什么写
        # 什么），一行 "total_tokens": "123" 就足以让 += 抛 TypeError。裸调会让
        # 整个端点永久 500（脏行通常在尾部，倒读天天先撞它）；而同口径的
        # _usage_timeseries_uncached 是 except 住降级的——这里对齐成「跳坏行」。
        try:
            fold(row)
        except Exception:
            bad_rows[0] += 1

    for row in _iter_usage_rows_since(since):
        seen[0] += 1
        fold_safe(row)
    if not seen[0]:
        # 倒读一行都没产出：要么「窗口内本来就无数据」（新装、隔很久没请求），
        # 要么「倒读被乱序日志/时钟回拨阻死」。两者在倒读侧都是 0 行，正确处置
        # 却完全相反。用**文件头第一条 at** 区分：正常日志从早到晚递增，头行
        # 早于窗口起点就是合法空窗口，不必扫；头行落在窗口内却一行都读不到，
        # 只能是文件被重排过，值得付一次顺序全扫。
        # （曾用「文件小于 8MB 才兜底」的体积门限，那恰好只在不需要兜底的小
        #   日志上生效，在大日志上留下静默空图。）
        head = _usage_log_head_ts()
        if isinstance(head, (int, float)) and head >= since:
            log("daily usage: backward read went blind, falling back to full scan",
                level="WARN", tag="usage")
            for row in _iter_usage_rows_forward(since):
                fold_safe(row)
    if bad_rows[0]:
        log("daily usage: skipped %d inconsistent rows" % bad_rows[0],
            level="WARN", tag="usage")
    ordered = sorted(groups.values(), key=lambda g: -(g["total_tokens"] or 0))
    return {
        "ok": True,
        "realm": realm or "all",
        "days": days,
        "group_by": group,
        "bucket_seconds": 86400,
        "since": since,
        "until": until,
        "series": series,
        "groups": ordered,
        "totals": totals,
    }


def compute_usage_analytics(range=None, since=None, until=None):
    """Detailed analytics for Token, Cache, and Reasoning metrics page.

    range/since/until 为可选时间窗口，语义见 range_window()。**不传时是 legacy
    模式：不新增任何键、不过滤任何行**，输出与改动前逐字节一致（老面板不受影响）；
    传了才追加顶层 window 边界、summary.window 桶与每账号/每模型的 window 桶。
    """
    now = time.localtime()
    today_ts = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, -1))
    lo, hi = range_window(range, since, until)
    legacy = (not str(range or "").strip() and since is None and until is None)

    def new_stat():
        return {
            "requests": 0, "errors": 0,
            "prompt_tokens": 0, "completion_tokens": 0,
            "reasoning_tokens": 0, "cached_tokens": 0, "total_tokens": 0,
            "ttft_sum": 0.0, "ttft_n": 0,
            "speed_sum": 0.0, "speed_n": 0,
            "elapsed_sum": 0.0, "elapsed_n": 0,
            "cost_usd": 0.0, "cost_cny": 0.0, "priced_rows": 0,
        }

    all_summary = new_stat()
    today_summary = new_stat()
    # 窗口桶：legacy 模式下不进入输出，但循环结构保持统一（避免复制一份过滤逻辑）
    window_summary = new_stat()
    win_acct = {}       # uid -> {"stat": stat, "models": {model: {...}}}
    win_model = {}      # model id -> stat
    acct_map = {}
    model_map = {}
    if os.path.exists(USAGE_LOG):
        try:
            with open(USAGE_LOG, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    is_err = bool(r.get("error"))
                    at = r.get("at", 0)
                    is_today = (at >= today_ts)
                    in_window = _row_in_window(r, lo, hi)
                    acct_uid = r.get("account") or "(unattributed)"
                    m_id = r.get("model") or "(unknown)"

                    def feed(stat_obj, is_error):
                        if is_error:
                            stat_obj["errors"] += 1
                        else:
                            stat_obj["requests"] += 1
                            stat_obj["prompt_tokens"] += (r.get("prompt_tokens") or 0)
                            stat_obj["completion_tokens"] += (r.get("completion_tokens") or 0)
                            stat_obj["reasoning_tokens"] += (r.get("reasoning_tokens") or 0)
                            stat_obj["cached_tokens"] += (r.get("cached_tokens") or 0)
                            stat_obj["total_tokens"] += (r.get("total_tokens") or 0)
                            if r.get("ttft_ms"):
                                stat_obj["ttft_sum"] += r["ttft_ms"]
                                stat_obj["ttft_n"] += 1
                            if r.get("tokens_per_sec"):
                                stat_obj["speed_sum"] += r["tokens_per_sec"]
                                stat_obj["speed_n"] += 1
                            if r.get("elapsed_ms"):
                                stat_obj["elapsed_sum"] += r["elapsed_ms"]
                                stat_obj["elapsed_n"] += 1
                            stat_obj["cost_usd"] += (r.get("cost_usd") or 0.0)
                            stat_obj["cost_cny"] += (r.get("cost_cny") or 0.0)
                            if r.get("priced"):
                                stat_obj["priced_rows"] += 1

                    feed(all_summary, is_err)
                    if is_today:
                        feed(today_summary, is_err)
                    if in_window:
                        feed(window_summary, is_err)
                    if acct_uid not in acct_map:
                        acct_map[acct_uid] = {
                            "uid": acct_uid,
                            "nickname": acct_uid,
                            "realm": r.get("realm", ""),
                            "domain": "",
                            "today": new_stat(),
                            "all_time": new_stat(),
                            "today_models": {},
                            "all_models": {},
                        }
                    feed(acct_map[acct_uid]["all_time"], is_err)
                    if is_today:
                        feed(acct_map[acct_uid]["today"], is_err)
                    if in_window:
                        slot = win_acct.setdefault(
                            acct_uid, {"stat": new_stat(), "models": {}})
                        feed(slot["stat"], is_err)
                        if not is_err:
                            wm = slot["models"].setdefault(
                                m_id, {"requests": 0, "tokens": 0, "reasoning": 0})
                            wm["requests"] += 1
                            wm["tokens"] += (r.get("total_tokens") or 0)
                            wm["reasoning"] += (r.get("reasoning_tokens") or 0)
                    if not is_err:
                        tm = acct_map[acct_uid]["all_models"].setdefault(
                            m_id, {"requests": 0, "tokens": 0, "reasoning": 0})
                        tm["requests"] += 1
                        tm["tokens"] += (r.get("total_tokens") or 0)
                        tm["reasoning"] += (r.get("reasoning_tokens") or 0)
                        if is_today:
                            tdm = acct_map[acct_uid]["today_models"].setdefault(
                                m_id, {"requests": 0, "tokens": 0, "reasoning": 0})
                            tdm["requests"] += 1
                            tdm["tokens"] += (r.get("total_tokens") or 0)
                            tdm["reasoning"] += (r.get("reasoning_tokens") or 0)
                    if m_id not in model_map:
                        model_map[m_id] = {"model": m_id, "today": new_stat(),
                                           "all_time": new_stat()}
                    feed(model_map[m_id]["all_time"], is_err)
                    if is_today:
                        feed(model_map[m_id]["today"], is_err)
                    if in_window:
                        feed(win_model.setdefault(m_id, new_stat()), is_err)
        except Exception as exc:
            log("compute_usage_analytics failed: %s" % exc)
    if POOL:
        for a in POOL.accounts:
            if a.uid in acct_map:
                acct_map[a.uid]["nickname"] = account_label(a)
                acct_map[a.uid]["realm"] = a.realm
                acct_map[a.uid]["domain"] = a.domain
                acct_map[a.uid]["credits"] = getattr(a, "credits", None) or {}
            else:
                acct_map[a.uid] = {
                    "uid": a.uid,
                    "nickname": account_label(a),
                    "realm": a.realm,
                    "domain": a.domain,
                    "credits": getattr(a, "credits", None) or {},
                    "today": new_stat(),
                    "all_time": new_stat(),
                    "today_models": {},
                    "all_models": {},
                }

    def finalize(stat_obj):
        p = stat_obj["prompt_tokens"]
        c = stat_obj["cached_tokens"]
        out = stat_obj["completion_tokens"]
        reas = stat_obj["reasoning_tokens"]
        stat_obj["cache_hit_pct"] = round((c / p * 100), 1) if p > 0 else 0.0
        stat_obj["reasoning_ratio"] = round((reas / out * 100), 1) if out > 0 else 0.0
        stat_obj["ttft_ms_avg"] = round(stat_obj["ttft_sum"] / stat_obj["ttft_n"]) \
            if stat_obj["ttft_n"] > 0 else 0
        stat_obj["speed_avg"] = round(stat_obj["speed_sum"] / stat_obj["speed_n"], 1) \
            if stat_obj["speed_n"] > 0 else 0.0
        stat_obj["elapsed_ms_avg"] = round(stat_obj["elapsed_sum"] / stat_obj["elapsed_n"]) \
            if stat_obj["elapsed_n"] > 0 else 0
        stat_obj["cost_usd"] = round(stat_obj.get("cost_usd", 0.0), 6)
        stat_obj["cost_cny"] = round(stat_obj.get("cost_cny", 0.0), 4)
        return stat_obj

    finalize(all_summary)
    finalize(today_summary)
    for a in acct_map.values():
        finalize(a["today"])
        finalize(a["all_time"])
    for m in model_map.values():
        finalize(m["today"])
        finalize(m["all_time"])
    if not legacy:
        finalize(window_summary)
        for slot in win_acct.values():
            finalize(slot["stat"])
        for stat in win_model.values():
            finalize(stat)
    accts_list = sorted(acct_map.values(),
                        key=lambda a: (-a["today"]["total_tokens"],
                                       -a["all_time"]["total_tokens"]))
    models_list = sorted(model_map.values(),
                         key=lambda m: (-m["today"]["total_tokens"],
                                        -m["all_time"]["total_tokens"]))
    result = {
        "today_ts": today_ts,
        "summary": {"today": today_summary, "all_time": all_summary},
        "accounts": accts_list,
        "models": models_list,
    }
    if not legacy:
        # 只在实际传了窗口时追加这三个桶；legacy 输出逐字节不变（老面板零影响）。
        # 排序仍沿用 today/all_time（面板可自行按 window 重排），避免改变既有顺序。
        result["window"] = {"since": lo, "until": hi}
        result["summary"]["window"] = window_summary
        for a in accts_list:
            slot = win_acct.get(a["uid"])
            a["window"] = slot["stat"] if slot else finalize(new_stat())
            a["window_models"] = slot["models"] if slot else {}
        for m in models_list:
            m["window"] = win_model.get(m["model"]) or finalize(new_stat())
    return result


def free_model_names(realm=None):
    """目录里 is_free 的模型名集合（含上游 key 与别名）。

    与护栏阈值**同批**推给池（R3）：free 名单为空集时 credit 守卫会拦住
    全部模型，所以只要启用了 daily_credit_limit，名单就必须一起推。
    只读本地目录快照，不联网；失败只记 WARN 并返回已收集部分。
    """
    names = set()
    try:
        for mid, meta in fetch_models(realm=realm or CURRENT_REALM):
            meta = meta if isinstance(meta, dict) else {}
            if not meta.get("is_free"):
                continue
            vals = [mid, meta.get("key"), meta.get("alias"),
                    meta.get("display_name")]
            extra = meta.get("aliases")
            if isinstance(extra, (list, tuple, set)):
                vals.extend(extra)
            for cand in vals:
                if isinstance(cand, str) and cand.strip():
                    names.add(cand.strip())
    except Exception as exc:
        log("free model list probe failed: %s" % exc, level="WARN")
    return names


def gateway_models_for_agents(realm=None):
    """面板「智能体配置」页的模型预填清单（与 /v1/models 同源裁剪）。"""
    try:
        entries = fetch_models_merged(realm=realm) if realm else             fetch_models_merged()
    except Exception:
        entries = []
    out = []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict):
            continue
        mid = str(e.get("id") or "").strip()
        if not mid:
            continue
        item = {"id": mid}
        try:
            if e.get("context_length"):
                item["context_window"] = int(e["context_length"])
        except (TypeError, ValueError):
            pass
        try:
            if e.get("max_output_tokens"):
                item["max_output"] = int(e["max_output_tokens"])
        except (TypeError, ValueError):
            pass
        out.append(item)
    return {"models": out[:80]}


def runtime_settings_view():
    """Current panel-visible settings (never returns the password or the key)."""
    key = API_KEY or ""
    if len(key) > 8:
        masked = key[:4] + "*" * 6 + key[-4:]
    else:
        masked = "*" * len(key)
    keys = []
    for entry in configured_keys():
        raw = entry.get("key") or ""
        keys.append({
            "id": entry.get("id") or "",
            "name": entry.get("name") or "",
            "realm": entry.get("realm") or "",
            "enabled": entry.get("enabled", True) is not False,
            "masked": (raw[:4] + "*" * 6 + raw[-4:]) if len(raw) > 8
            else "*" * len(raw),
            "source": entry.get("source") or "panel",
            "created_at": entry.get("created_at") or "",
            "models": list(entry.get("models") or []),
            "daily_requests": int(entry.get("daily_requests") or 0),
            "daily_tokens": int(entry.get("daily_tokens") or 0),
        })
    return {
        "panel_password_is_default":
            trae_settings.panel_password_is_default(ACCOUNTS_DIR),
        "api_key_set": bool(key),
        "api_key_set_by_panel": API_KEY_FILE_SET,
        "api_key_masked": masked,
        "auth_required": auth_required(),
        "api_keys": keys,
        # limits 与保存分支同源：limits_data 返回**完整形状**（每个守卫都补齐
        # global/intl/cn，未设时全为 0/None），面板读到即可安全回显、再保存不会
        # 把已有阈值覆盖成默认值。
        "limits": trae_settings.limits_data(ACCOUNTS_DIR),
        "auto_degrade": trae_settings.auto_degrade(ACCOUNTS_DIR),
        "accounts_dir": ACCOUNTS_DIR,
        "usage_dir": USAGE_DIR,
        "settings_file": trae_settings.settings_path(ACCOUNTS_DIR),
        "version": VERSION,
    }


def current_account():
    """Account used for display purposes (health / usage summaries)."""
    return POOL.representative() if POOL else None


# ---------------------------------------------------------------------------
# 前缀会话亲和（同一对话固定同一账号，命中上游按账号的 prompt 缓存）
# ---------------------------------------------------------------------------
AFFINITY_BY_PREFIX = os.environ.get("QD_AFFINITY_BY_PREFIX", "1").lower() not in (
    "0", "false", "no", "off")
AFFINITY_DEBUG = os.environ.get("QD_AFFINITY_DEBUG", "0").lower() in (
    "1", "true", "yes", "on")
# P1-6 会话亲和长度上限：对话超过该条数就不再绑定账号（长对话的请求体只会越来越大，
# 钉在同一账号等于让下一轮同样超长）。0 = 关闭上限，**默认关闭**，行为与改动前一致。
# 阈值不照搬参考项目：那张断连率表来自其单一实例的 333 个请求、上游也不同，本仓无
# 自有曲线，因此先给机制、等实测再定值。非数字取值按 0 处理（不在 import 期抛异常）。
try:
    AFFINITY_MAX_MSGS = int(os.environ.get("QD_AFFINITY_MAX_MSGS", "0") or 0)
except (TypeError, ValueError):
    AFFINITY_MAX_MSGS = 0


def derive_affinity_key(messages):
    """Derive a stable affinity key from a conversation's stable prefix.

    前两条消息（system + 首轮 user）在整段对话生命周期内不变，因此同一对话
    每一轮都落到同一上游账号 —— 正是 prompt 缓存需要的；不同对话首轮不同，
    依旧分散到各账号，负载均衡不受影响。
    """
    if not AFFINITY_BY_PREFIX:
        return None
    try:
        msgs = messages or []
        if not msgs:
            return None
        # P1-6：超长对话放弃亲和（== 上限仍绑定，> 上限释放）
        if AFFINITY_MAX_MSGS > 0 and len(msgs) > AFFINITY_MAX_MSGS:
            if AFFINITY_DEBUG:
                log("affinity: skip %d msgs (> %d), letting the pool rotate"
                    % (len(msgs), AFFINITY_MAX_MSGS))
            return None
        head = msgs[:2]
        blob = json.dumps(head, ensure_ascii=False,
                          sort_keys=True).encode("utf-8")
        return "pfx-" + hashlib.sha256(blob).hexdigest()[:16]
    except Exception:
        return None


def prompt_fingerprint(messages):
    """Privacy-safe fingerprint of the outgoing prompt.

    Cache hits need a byte-identical prefix, so these hashes answer "is my
    prefix stable / is my conversation continuous?" without storing any text.
    """
    try:
        def h(obj):
            blob = json.dumps(obj, ensure_ascii=False,
                              sort_keys=True).encode("utf-8")
            return hashlib.sha256(blob).hexdigest()[:12]
        msgs = messages or []
        out = {"msgs_sha": h(msgs), "n_msgs": len(msgs)}
        if msgs:
            out["system_sha"] = h(msgs[0]) if msgs[0].get("role") == "system" else ""
            out["prefix_sha"] = h(msgs[:-1]) if len(msgs) > 1 else ""
        return out
    except Exception:
        return {}


LOG_BUFFER = deque(maxlen=2000)
_LOG_LOCK = threading.Lock()
_LOG_COUNTER = 0


def add_log_entry(msg, level=None, tag=None):
    global _LOG_COUNTER
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    t_short = time.strftime("%H:%M:%S")
    msg_str = str(msg).rstrip()
    if not level:
        lower = msg_str.lower()
        if any(k in lower for k in ("error", "exception", "failed", "traceback",
                                    "errno", "fatal", "token_expire", "12153")):
            level = "ERROR"
        elif any(k in lower for k in ("warn", "warning", "retry", "timeout")):
            level = "WARN"
        else:
            level = "INFO"
    if not tag:
        lower = msg_str.lower()
        if "chat:" in lower or "chat done" in lower or "/v1/chat" in lower \
                or "/chat/completions" in lower or "responses" in lower:
            tag = "chat"
        elif "scheduler" in lower or "调度器" in lower:
            tag = "scheduler"
        elif "task" in lower or "任务" in lower or "签到" in lower \
                or "checkin" in lower or "福利" in lower:
            tag = "tasks"
        elif "account" in lower or "账号" in lower or "pool" in lower \
                or "imported" in lower:
            tag = "accounts"
        elif "model" in lower or "catalog" in lower or "模型" in lower:
            tag = "catalog"
        elif "auth" in lower or "token" in lower or "oauth" in lower:
            tag = "auth"
        elif "settings" in lower or "设置" in lower:
            tag = "settings"
        else:
            tag = "system"
    with _LOG_LOCK:
        _LOG_COUNTER += 1
        entry = {
            "id": _LOG_COUNTER,
            "ts": ts,
            "time": t_short,
            "level": level,
            "tag": tag,
            "msg": msg_str,
        }
        LOG_BUFFER.append(entry)
    return entry


def log(msg, level=None, tag=None):
    sys.stderr.write("[trae2api] %s %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()
    add_log_entry(msg, level=level, tag=tag)


def get_logs(limit=200, level="", tag="", search="", since_id=0):
    with _LOG_LOCK:
        items = list(LOG_BUFFER)
    if since_id > 0:
        items = [x for x in items if x["id"] > since_id]
    if level:
        items = [x for x in items if x["level"] == level.upper()]
    if tag:
        items = [x for x in items if x["tag"].lower() == tag.lower()]
    if search:
        s = search.lower()
        items = [x for x in items if s in x["msg"].lower() or s in x["tag"].lower()]
    total = len(items)
    if limit and limit > 0 and since_id == 0:
        items = items[-limit:]
    max_id = items[-1]["id"] if items else since_id
    return {"total": total, "logs": items, "max_id": max_id}


def clear_logs():
    with _LOG_LOCK:
        LOG_BUFFER.clear()


# ---------------------------------------------------------------------------
# 模型目录（动态 COSY model/list + 静态兜底）
# ---------------------------------------------------------------------------
NON_CHAT_MODELS = {"lite"}
NON_CHAT_PREFIXES = ("codewise-", "completion-")
NON_CHAT_SUFFIXES = ("-image-alpha", "-image-alpha-edit", "-taco-completion")


def is_chat_model(mid):
    if not mid:
        return False
    if mid in NON_CHAT_MODELS:
        return False
    if mid.startswith(NON_CHAT_PREFIXES):
        return False
    if mid.endswith(NON_CHAT_SUFFIXES):
        return False
    return True


CN_UI_ORDER = [m["key"] for m in trae_catalog.STATIC_CN_MODELS]
INTL_UI_ORDER = [m["key"] for m in trae_catalog.STATIC_INTL_MODELS]


def merge_catalog(primary, realm=None):
    """静态目录打底（补元数据），按官方 UI 顺序输出。

    **清单以 primary（动态接口或本机官方目录）为准**：桌面版此刻显示什么
    这里就显示什么（如动态返回 15 条就不额外塞静态独有的 2 条）；
    primary 为空时回退静态快照全量。enable/strategies 等状态不做任何裁剪。
    """
    r = realm or CURRENT_REALM
    merged = {}
    source_static = getattr(trae_catalog, "STATIC_CN_MODELS" if r == "cn"
                            else "STATIC_INTL_MODELS", trae_catalog.STATIC_MODELS)
    for item in source_static:
        mid = item.get("key") or item.get("id")
        if mid and is_chat_model(mid):
            merged[mid] = dict(item)
    primary = list(primary or [])
    primary_keys = None
    for mid, meta in primary:
        if not is_chat_model(mid):
            continue
        if meta:
            base = merged.get(mid) or {}
            # None 值不覆盖：动态接口对部分条目返回 null（如 context_config/
            # thinking_config/description），静默 null 会把静态快照里的真实
            # 值抹掉——只用有值字段做增量覆盖。
            base.update({k: v for k, v in meta.items() if v is not None})
            merged[mid] = base
        elif mid not in merged:
            merged[mid] = {}
    if primary:
        primary_keys = {mid for mid, _ in primary if is_chat_model(mid)}
    order = CN_UI_ORDER if r == "cn" else INTL_UI_ORDER
    out = []
    seen = set()

    def wanted(mid):
        return bool(is_chat_model(mid))

    for mid in order:
        if mid in merged and wanted(mid):
            out.append((mid, merged[mid]))
            seen.add(mid)
    for mid, meta in merged.items():
        if mid not in seen and wanted(mid):
            out.append((mid, meta))
    # 静态目录全量保留：动态清单里没有的标 available=False，
    # 但不要从 /v1/models 里删掉（用户需要看到“目录里有、当前套餐未开通”）。
    for mid, meta in out:
        if primary_keys is None:
            meta.setdefault("available", True)
        else:
            meta["available"] = mid in primary_keys
            meta["dynamic"] = mid in primary_keys
    return out


def read_local_models(realm=None):
    """读取本仓内置的双区目录快照（原本地缓存路径已失效）。

    数据源：trae_catalog 的快照（trae_catalog_cn.json / trae_catalog_intl.json，
    由真实客户端缓存生成，字段忠实保留）。返回 [(key, meta)]；失败返回 []
    （再由 merge_catalog 回退静态快照），因此本函数永不阻断模型清单。
    """
    r = trae_realm(realm or CURRENT_REALM)
    try:
        rows = trae_catalog.models_for_realm(r)
    except Exception as exc:
        log("local model catalog read skipped: %s" % str(exc)[:140])
        return []
    out = []
    for m in rows or []:
        if not isinstance(m, dict):
            continue
        key = m.get("key") or m.get("id") or m.get("name")
        if not key:
            continue
        row = dict(m)
        row["id"] = key
        row.setdefault("name", m.get("display_name") or key)
        row.setdefault("display_name", m.get("display_name") or key)
        out.append((key, row))
    if out:
        log("model catalog read from bundled snapshot: %d models (%s)"
            % (len(out), r))
    return out


def fetch_models(realm=None, refresh=False):
    r = trae_realm(realm or CURRENT_REALM)
    with _lock:
        c = _models_cache.get(r) or {"at": 0.0, "data": None}
        if not refresh and c["data"] and time.time() - c["at"] < 300:
            return c["data"]
    # trae_catalog.available_models 是唯一目录装配入口：
    #   - 动态 model_list 决定 available，快照全量保留并补元数据；
    #   - INTL 无动态接口时快照全量 available=True；
    #   - 上下文 / max_tokens / thinking 等字段由快照原样带出。
    account = POOL.pick(realm=r) if POOL else None
    entries = []
    source = "snapshot"
    try:
        rows = trae_catalog.available_models(r, account=account,
                                             refresh=bool(refresh))
        entries = [(row.get("upstream_key") or row.get("key"), row)
                   for row in rows
                   if (row.get("upstream_key") or row.get("key"))]
        source = "dynamic" if any(row.get("dynamic") for row in rows) else "snapshot"
    except Exception as exc:
        log("available_models failed (%s): %s" % (r, str(exc)[:160]),
            level="WARN", tag="models")
        entries = []
    if not entries:
        # 最后一道兜底：动态发现 + 本地快照 + overlay（保证目录不空）
        live = read_dynamic_models(realm=r)
        if not live:
            live = read_local_models(realm=r)
            known = {mid for mid, _ in live}
            for key, meta in _overlay_models(r):
                if key not in known:
                    live.append((key, meta))
        entries = merge_catalog(live, realm=r)
    with _lock:
        _models_cache[r] = {"at": time.time(), "data": entries,
                            "source": source}
    return entries


def discovery_path(realm):
    return os.path.join(USAGE_DIR, "model_discovery_%s.json" % realm)


def load_discovery(realm):
    try:
        with open(discovery_path(realm), encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_discovery(realm, rows, source="dynamic"):
    """保存最近一次成功发现的模型（运行期 overlay，不写内置快照）。"""
    old = load_discovery(realm)
    old_keys = {str(item.get("key")) for item in (old.get("models") or [])
                if isinstance(item, dict) and item.get("key")}
    new_keys = {str(item.get("key")) for item in (rows or [])
                if isinstance(item, dict) and item.get("key")}
    doc = {
        "realm": realm,
        "at": time.time(),
        "source": source,
        "count": len(new_keys),
        "added": sorted(new_keys - old_keys),
        "removed": sorted(old_keys - new_keys),
        "models": rows or [],
    }
    try:
        os.makedirs(USAGE_DIR, exist_ok=True)
        tmp = discovery_path(realm) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, discovery_path(realm))
    except Exception as exc:
        log("model discovery overlay save failed: %s" % str(exc)[:140],
            level="WARN", tag="models")
    return doc


def _overlay_models(realm):
    doc = load_discovery(realm)
    out = []
    for item in doc.get("models") or []:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not key:
            continue
        meta = dict(item.get("meta") or {})
        meta.setdefault("discovered", True)
        meta.setdefault("discovery_source", doc.get("source") or "dynamic")
        out.append((key, meta))
    return out


def refresh_model_discovery(realm=None):
    """强制刷新一个区的模型发现，写 overlay 并返回差异。"""
    r = trae_realm(realm or CURRENT_REALM)
    live = read_dynamic_models(realm=r)
    source = "dynamic"
    rows = []
    if live:
        rows = [{"key": mid, "meta": dict(meta or {})} for mid, meta in live]
        save_discovery(r, rows, source="dynamic")
    else:
        source = "snapshot"
        local = read_local_models(realm=r)
        rows = [{"key": mid, "meta": dict(meta or {})} for mid, meta in local]
        # 官方动态接口不可用时，保留上次成功发现的模型
        known = {item["key"] for item in rows}
        for key, meta in _overlay_models(r):
            if key not in known:
                rows.append({"key": key, "meta": meta})
        # 首次没有 overlay 时把本地快照也记一份，面板能看到“10 个快照模型”；
        # 已有动态 overlay 时不覆盖，避免动态发现的新模型被快照冲掉。
        if not load_discovery(r).get("count"):
            save_discovery(r, rows, source="snapshot")
    with _lock:
        _models_cache.pop(r, None)
    try:
        trae_catalog.reload()
    except Exception:
        pass
    doc = load_discovery(r)
    return {"ok": True, "realm": r, "source": source,
            "count": len(rows), "added": doc.get("added") or [],
            "removed": doc.get("removed") or [],
            "at": doc.get("at") or time.time(),
            "models": [row["key"] for row in rows]}


MODEL_PROBE_LOCK = threading.RLock()
MODEL_PROBE_STATE = {
    "state": "idle", "scope": "current", "started_at": 0, "finished_at": 0,
    "total": 0, "done": 0, "ok": 0, "failed": 0, "skipped": 0,
    "current": "", "results": [], "error": "",
}


def probe_state():
    with MODEL_PROBE_LOCK:
        return json.loads(json.dumps(MODEL_PROBE_STATE))


def _probe_models_for_scope(scope):
    realms = ["cn", "intl"] if scope == "all" else [CURRENT_REALM]
    out = []
    for realm in realms:
        for mid, meta in fetch_models(realm=realm):
            # 目录里 available=false 的模型当前账号/套餐不允许调用，
            # 默认不探测；否则自动探测会拿 20 个 4023 把任务打成失败。
            if meta.get("available") is False:
                continue
            out.append({"key": mid, "realm": realm,
                        "meta": meta or {}})
    return out


def _run_model_probe(scope="current", limit=0, force=False):
    started = time.time()
    try:
        models = _probe_models_for_scope(scope)
        with MODEL_PROBE_LOCK:
            MODEL_PROBE_STATE.update({
                "state": "running", "scope": scope, "started_at": started,
                "finished_at": 0, "total": len(models), "done": 0,
                "ok": 0, "failed": 0, "skipped": 0, "current": "",
                "results": [], "error": "",
            })
        accounts = [a for a in (POOL.accounts if POOL else [])
                    if getattr(a, "enabled", True)]

        def progress(done, total, key, row):
            with MODEL_PROBE_LOCK:
                MODEL_PROBE_STATE["total"] = total
                MODEL_PROBE_STATE["done"] = done
                MODEL_PROBE_STATE["current"] = key
                MODEL_PROBE_STATE["results"].append({
                    "model": key, "realm": (row or {}).get("realm", ""),
                    "ok": bool((row or {}).get("ok")),
                    "status": (row or {}).get("status", ""),
                    "elapsed_ms": (row or {}).get("elapsed_ms", 0),
                    "error": (row or {}).get("error", ""),
                    "reply": (row or {}).get("reply", ""),
                    "at": (row or {}).get("at", 0),
                })
                if (row or {}).get("cached"):
                    MODEL_PROBE_STATE["skipped"] += 1
                elif (row or {}).get("ok"):
                    MODEL_PROBE_STATE["ok"] += 1
                elif (row or {}).get("status") == "no_account":
                    MODEL_PROBE_STATE["skipped"] += 1
                else:
                    MODEL_PROBE_STATE["failed"] += 1

        result = trae_probe.probe_models(accounts, models, limit=limit,
                                         force=force, on_progress=progress)
        with MODEL_PROBE_LOCK:
            MODEL_PROBE_STATE.update({
                "state": "done", "finished_at": time.time(),
                "done": (result.get("summary") or {}).get("total", len(models)),
                "ok": (result.get("summary") or {}).get("ok", 0),
                "failed": (result.get("summary") or {}).get("failed", 0),
                "skipped": (result.get("summary") or {}).get("skipped", 0),
                "current": "",
            })
        log("model probe done: %s" % MODEL_PROBE_STATE, tag="models")
    except Exception as exc:                           # noqa: BLE001
        with MODEL_PROBE_LOCK:
            MODEL_PROBE_STATE.update({"state": "failed",
                                      "finished_at": time.time(),
                                      "error": str(exc)[:300]})
        log("model probe failed: %s" % str(exc)[:200], level="WARN", tag="models")


def start_model_probe(scope="current", limit=0, force=False):
    with MODEL_PROBE_LOCK:
        if MODEL_PROBE_STATE.get("state") == "running":
            return {"started": False, "reason": "already running",
                    "job": probe_state()}
        MODEL_PROBE_STATE.update({"state": "starting", "scope": scope,
                                  "started_at": time.time(),
                                  "finished_at": 0, "total": 0, "done": 0,
                                  "ok": 0, "failed": 0, "skipped": 0,
                                  "current": "", "results": [],
                                  "error": ""})
    thread = threading.Thread(target=_run_model_probe,
                              args=(scope, limit, force), daemon=True)
    thread.start()
    return {"started": True, "job": probe_state()}


def model_health_summary():
    data = trae_probe.load_health()
    realms = data.get("models") or {}
    summary = {"updated_at": data.get("updated_at") or 0, "realms": {}}
    for realm, bucket in realms.items():
        rows = list((bucket or {}).values()) if isinstance(bucket, dict) else []
        summary["realms"][realm] = {
            "total": len(rows),
            "ok": sum(1 for row in rows if row.get("ok")),
            "failed": sum(1 for row in rows if not row.get("ok")),
            "updated_at": max([float(row.get("at") or 0) for row in rows] or [0]),
        }
    return summary


def fetch_models_merged():
    """#26 步4：两区并集，逐条附区域标注。返回 [(mid, meta, realm)]。

    同一上游 key 在两区都有的**只保留一条**（当前区优先），避免客户端看到
    重复 id；顺序为「当前区在前 + 各自清单顺序」。
    """
    out = []
    seen = set()
    cur = CURRENT_REALM if CURRENT_REALM in ("cn", "intl") else "cn"
    for r in (cur, "intl" if cur == "cn" else "cn"):
        for mid, meta in fetch_models(realm=r):
            if mid in seen:
                continue
            seen.add(mid)
            out.append((mid, meta, r))
    return out


def read_dynamic_models(realm=None):
    """Trae model_list 动态拉取（PROTOCOL §八）。失败返回 []（回落快照）。

    CN：POST {core}/api/ide/v1/model_list body {"type":"chat"} -> model_configs[]
    INTL：该 host/path 未注册，返回 403 no schema found -> 走本机缓存/快照。
    鉴权失败（HTTP 401/403 且不是 no-schema）时先刷新一次 token 再重试。
    """
    r = trae_realm(realm or CURRENT_REALM)
    if r == "intl":
        # 国际版 model_list 未注册（403 no schema found），直接走内置快照：
        # 既省上游压力，也避免 403 触发一次无意义的 token 刷新。
        return []
    account = POOL.pick(realm=r) if POOL else None
    if account is None:
        return []
    body = json.dumps({"type": "chat"}).encode("utf-8")
    payload = None
    refreshed = False
    for host in trae_core_candidates(r):
        for attempt in (0, 1):
            url = validate_public_http_url(
                host.rstrip("/") + TRAE_MODEL_LIST_PATH)
            try:
                req = urllib.request.Request(
                    url, data=body, method="POST",
                    headers=trae_auth_headers(account, r, sse=False))
                with urllib.request.urlopen(req, timeout=15) as resp:
                    payload = json.loads(resp.read().decode("utf-8", "replace"))
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403) and not refreshed and attempt == 0:
                    if trae_refresh_account(account, r):
                        refreshed = True
                        continue
                log("model discovery failed on %s: HTTP %s" % (host, exc.code))
                break
            except Exception as exc:
                log("model discovery failed on %s: %s"
                    % (host, str(exc)[:160]))
                break
        if payload is not None:
            break
    if payload is None:
        return []
    configs = payload.get("model_configs") or payload.get("models") or []
    out = []
    for m in configs:
        if not isinstance(m, dict):
            continue
        mid = m.get("name") or m.get("id") or m.get("key")
        if not mid:
            continue
        # 官方原始条目**全字段原样**透传（display_name/model_type/multimodal/
        # is_default/custom_config/icon... 一律不裁剪），仅补 id/name 兼容键。
        row = dict(m)
        row["id"] = mid
        row.setdefault("name", mid)
        row.setdefault("display_name", m.get("display_name") or mid)
        out.append((mid, row))
    if out:
        log("model discovery ok: %d chat models from %s" % (len(out), r))
        try:
            save_discovery(r, [{"key": mid, "meta": dict(meta or {})}
                               for mid, meta in out], source="dynamic")
        except Exception:
            pass
    return out


def _parse_hhmm(value):
    """'22:00' -> 1320 分钟数；解析失败返回 None。"""
    try:
        parts = str(value).split(":")
        return int(parts[0]) * 60 + int(parts[1])
    except Exception:
        return None


def off_peak_active_now(window_start, window_end, tz=None, now=None):
    """判断当前时刻是否处于官方低谷（Off-Peak）时段。

    官方 promotion.window 为 22:00-08:00（跨午夜），文案标注 UTC+8；
    官方时区 Asia/Shanghai / Asia/Singapore 均为 UTC+8，因此按固定 +8
    计算（无 tzdata 依赖），未知时区也按官方标注的 UTC+8 兜底。
    返回 True（窗口内）/ False（窗口外）/ None（无有效窗口）。
    """
    s = _parse_hhmm(window_start)
    e = _parse_hhmm(window_end)
    if s is None or e is None:
        return None
    if now is None:
        now = time.time()
    import datetime
    offset_hours = 8
    if isinstance(tz, str):
        if tz.upper().startswith("UTC"):
            m = re.search(r"UTC([+-]\d{1,2})", tz.upper())
            if m:
                offset_hours = int(m.group(1))
        # Asia/Shanghai / Asia/Singapore -> +8（默认即 8）
    utc = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    local = utc + datetime.timedelta(hours=offset_hours)
    cur = local.hour * 60 + local.minute
    if s == e:
        return True
    if s < e:
        return s <= cur < e
    return cur >= s or cur < e      # 跨午夜窗口（22:00-08:00）


def model_availability(mid, realm=None, meta=None):
    """该模型此刻在本机是否「可发车」：有就绪账号 + 未禁用 + 未在模型冷却。

    只做内存判定（不发上游），供 /v1/models 的 available 标记与面板角标。
    """
    r = trae_realm(realm or CURRENT_REALM)
    if meta is not None and meta.get("enable") is False:
        return False
    if POOL is None:
        return False
    try:
        return bool(POOL.count_ready(realm=r, model=mid))
    except Exception:
        try:
            return bool(POOL.count_ready(realm=r))
        except Exception:
            return False


INTL_UPGRADE_MODELS = set() if os.environ.get("TRAE_INTL_PAID") == "1" else {
    "aws_claude_4.7_opus", "aws_claude_4.6_sonnet",
    "gpt-6-astra", "gpt-5.5",
}
INTL_UNAVAILABLE_MODELS = {}


def model_entry(mid, meta, realm=None):
    """Build a rich /v1/models entry.

    - `id` = **官方模型名 display_name**（如 `Qwen3.8-Max`）——客户端唯一需要
      填的值，与官方桌面版选择器显示一致；`upstream_key` 保留缩写 key，
      `aliases` 列出所有可接受形式（key / 「key (Name)」/ 人类别名）。
    - `description` = 官方桌面版介绍文案（dynamic-text zh.detail）。
    - `name_local` = 官方本地化名（zh.label 与 display_name 不同时，如
      Ultimate -> 极致、旧文案 Kimi-K2.7-Code）。
    - 上下文窗口来自官方 context_config；思考档位来自 thinking_config。
    - 峰谷价来自 promotion（peak -> valley + 时段窗口与官方错峰文案）。
    - `enabled=false` 时给出 `disabled_reason`（官方原文：需要升级或购买
      千问官方套餐开放）与上游 `disabled_message_key`。
    - **最大输出**：官方（catalog / 动态接口原始响应）均无此字段，因此
      仅当来源真实携带时才输出，绝不编造。
    """
    meta = meta or {}
    # 官方显示名优先；name 是上游 key，不能拿来当 id。
    display_name = (meta.get("display_name") or meta.get("name") or mid)
    if meta.get("enabled") is False or meta.get("status") is False \
            or meta.get("selectable") is False:
        enabled = False
    else:
        enabled = True
    created = 0
    try:
        created = int((trae_catalog.load_snapshot(realm or CURRENT_REALM)
                       or {}).get("generated_at") or 0)
    except Exception:
        created = 0
    item = {
        "id": display_name,
        "object": "model",
        "created": created,
        "owned_by": "trae",
        "upstream_key": mid,
        "enabled": enabled,
    }
    item["name"] = display_name
    item["display_name"] = display_name
    catalog_available = meta.get("available")
    pool_available = model_availability(mid, realm, meta)
    if catalog_available is None:
        item["available"] = bool(pool_available)
    else:
        item["available"] = bool(catalog_available) and bool(pool_available)
        if catalog_available is False:
            item["catalog_only"] = True
            item["access"] = "client_catalog"
            item["disabled_reason"] = (
                "官方客户端目录中存在该模型；但当前账号的 raw_chat model_list "
                "未返回它。网关暂未接入 Agent 通道，直接请求会返回 4023；"
                "这不等于账号套餐不可用。")
    if realm == "intl" and mid in INTL_UNAVAILABLE_MODELS:
        item["available"] = False
        item["catalog_only"] = True
        item["access"] = "unavailable"
        item["disabled_reason"] = INTL_UNAVAILABLE_MODELS[mid]
    if realm == "intl" and mid in INTL_UPGRADE_MODELS:
        # 官方客户端 restrictedModelKeys：Claude Opus/Sonnet、GPT-6/GPT-5.5
        # 在 Free 计划下只显示锁，需升级套餐；不是风控。
        item["upgrade_required"] = True
        item["available"] = False
        item["access"] = "upgrade_required"
        item["disabled_reason"] = "需要升级套餐：当前 Free 计划不可用（官方客户端同样加锁）"
    item["catalog_available"] = catalog_available
    if catalog_available is not None:
        item["live"] = bool(meta.get("dynamic")) or bool(catalog_available and not meta.get("dynamic"))
    item["dynamic"] = bool(meta.get("dynamic"))
    if realm:
        # #26 步4：该条来自哪个区域（默认单区视图也带，便于面板/客户端标注）
        item["realm"] = realm
        try:
            _span = trae_catalog.key_realm_span(mid)
            if len(_span) == 1:
                # 只在**一个**区域存在（如仅 intl 的 Sonus）—— 面板据此打「仅国际版」角标；
                # 双区都有的不给该字段（避免把「都能用」误标成独占）。
                item["realm_exclusive"] = _span[0]
        except Exception:
            pass
    # 描述：来源自带动态/本地 description，否则取官方桌面版文案
    desc = meta.get("description") or ""
    if not desc:
        try:
            desc = trae_catalog.official_description(mid)
        except Exception:
            desc = ""
    if desc:
        item["description"] = desc
    # 官方本地化显示名（与 display_name 不同时透出）
    try:
        local = trae_catalog.official_local_name(mid)
    except Exception:
        local = ""
    if local:
        item["name_local"] = local
    # 所有可接受的填写形式
    aliases = []
    for alias in ([mid, display_name] + list(meta.get("aliases") or ())):
        if alias and alias not in aliases:
            aliases.append(str(alias))
    for ak, av in trae_catalog.MODEL_ALIASES.items():
        if av == mid and ak not in aliases:
            aliases.append(ak)
    item["aliases"] = aliases
    for key in ("groups", "model_type", "is_default", "is_new", "status",
                "consumption_rate", "fee_model_level", "max_mode", "selectable",
                "is_preset", "config_source"):
        if meta.get(key) is not None:
            item[key] = meta[key]
    # 禁用态：官方原因文案（未开通千问套餐时官方桌面版所示）
    if not item["enabled"]:
        item["disabled_reason"] = getattr(
            trae_catalog, "OFFICIAL_DISABLED_REASON",
            "需要升级或购买千问官方套餐开放")
        strategies = meta.get("strategies")
        if isinstance(strategies, list):
            for st in strategies:
                if isinstance(st, dict) and st.get("disabled_message_key"):
                    item["disabled_message_key"] = st["disabled_message_key"]
                    break
            item["strategies"] = strategies
    features = meta.get("features") if isinstance(meta.get("features"), dict) else {}
    feat_vision = bool((features.get("multimodal") or {}).get("enable")) \
        if isinstance(features.get("multimodal"), dict) else False
    vision = bool(meta.get("multimodal") or meta.get("is_vl")
                  or meta.get("supportsImages") or feat_vision) \
        and not meta.get("disabledMultimodal")
    custom = meta.get("custom_config")
    if isinstance(custom, str):
        try:
            custom = json.loads(custom)
        except Exception:
            custom = {}
    if not isinstance(custom, dict):
        custom = {}
    tools = bool(meta.get("supportsToolCall", custom.get("native_function_call", True)))
    parallel_tools = bool(custom.get("parallel_tool_calling")) if custom else False
    thinking_cfg = _thinking_config(meta)
    thinks = bool(meta.get("is_reasoning") or meta.get("supportsReasoning")
                  or meta.get("model_type") == "reasoning_model"
                  or thinking_cfg.get("supported") is True
                  or thinking_cfg.get("support_thinking") is True
                  or (isinstance(features.get("reasoning"), dict)
                      and features["reasoning"].get("enable") is True)
                  or isinstance(thinking_cfg.get("enabled"), dict))
    inputs = ["text"] + (["image"] if vision else [])
    item["capabilities"] = {"vision": vision, "tool_calls": tools,
                            "parallel_tool_calls": parallel_tools,
                            "reasoning": thinks}
    item["supports_vision"] = vision
    item["supports_images"] = vision
    item["supports_tool_calls"] = tools
    item["supports_reasoning"] = thinks
    item["vision"] = vision
    item["multimodal"] = vision
    item["abilities"] = {"vision": vision, "functionCall": tools,
                         "function_call": tools, "reasoning": thinks}
    item["input_modalities"] = inputs
    item["output_modalities"] = ["text"]
    item["modalities"] = {"input": inputs, "output": ["text"]}
    item["architecture"] = {
        "input_modalities": inputs,
        "output_modalities": ["text"],
        "modality": "+".join(inputs) + "->text",
    }
    # ---- limits：官方快照字段优先（context_window / max_tokens / thinking）----
    ctx_tokens = meta.get("context_window_tokens") if isinstance(
        meta.get("context_window_tokens"), dict) else {}
    ctx_size = meta.get("context_window_size") if isinstance(
        meta.get("context_window_size"), dict) else {}
    default_ctx = (meta.get("context_window") or ctx_tokens.get("dev")
                   or ctx_size.get("default"))
    max_ctx = (meta.get("context_window_max") or ctx_tokens.get("max"))
    if max_ctx is None:
        raw_max = ctx_size.get("max")
        if isinstance(raw_max, list):
            max_ctx = max([int(x) for x in raw_max if isinstance(x, (int, float))] or [0]) or None
        elif isinstance(raw_max, (int, float)):
            max_ctx = raw_max
    prompt_max = meta.get("prompt_max_tokens")
    context_length = max_ctx or default_ctx or prompt_max
    if default_ctx:
        item["context_window"] = default_ctx
        item["context_window_default"] = default_ctx
    if max_ctx:
        item["context_window_max"] = max_ctx
    if context_length:
        item["context_length"] = context_length
    windows = []
    for value in (default_ctx, max_ctx):
        if value and value not in windows:
            windows.append(int(value))
    if windows:
        item["context_windows"] = windows
    if prompt_max:
        item["prompt_max_tokens"] = prompt_max
        item["max_input_tokens"] = prompt_max
    elif context_length:
        item["max_input_tokens"] = context_length
    if meta.get("max_tokens") is not None:
        item["max_output_tokens"] = meta["max_tokens"]
        item["max_completion_tokens"] = meta["max_tokens"]
    elif meta.get("maxOutputTokens") is not None:
        item["max_output_tokens"] = meta["maxOutputTokens"]
        item["max_completion_tokens"] = meta["maxOutputTokens"]
    if meta.get("max_turn") is not None:
        item["max_turns"] = meta["max_turn"]
    if not (context_length or item.get("max_output_tokens")):
        item["metadata_missing"] = True
    if meta.get("saas_usage") is not None:
        item["saas_usage"] = meta["saas_usage"]

    # ---- 思考档位：thinking.options / reasoning_effort_config ----
    raw_efforts = thinking_cfg.get("options")
    if not raw_efforts and isinstance(thinking_cfg.get("enabled"), dict):
        eff_map = thinking_cfg["enabled"].get("efforts") or {}
        order = ["low", "medium", "high", "xhigh", "max"]
        raw_efforts = [e for e in order if e in eff_map]
    if isinstance(raw_efforts, list) and raw_efforts:
        item["reasoning_efforts"] = [str(e) for e in raw_efforts]
    # OpenAI 常用档位 -> Trae 原生档位的显式映射；原值永远保留在
    # reasoning_efforts 里，客户端可自己决定怎么展示。
    canonical = {"light": "low", "high": "high", "extra_high": "xhigh",
                 "low": "low", "medium": "medium", "xhigh": "xhigh", "max": "max"}
    if isinstance(raw_efforts, list) and raw_efforts:
        item["reasoning_effort_map"] = {str(e): canonical.get(str(e), str(e))
                                        for e in raw_efforts}
    default_effort = thinking_cfg.get("default_level") or thinking_cfg.get(
        "default")
    if default_effort:
        item["reasoning_default_effort"] = str(default_effort)
    if thinking_cfg.get("supported") is False:
        item["reasoning_can_disable"] = True
    item["thinking"] = {
        "supported": bool(thinks),
        "options": [str(e) for e in (raw_efforts or [])],
        "default_level": str(default_effort) if default_effort else None,
    }
    # 兼容旧 catalog 形态
    effort_fixed = (meta.get("reasoning") or {}).get("effort")
    if effort_fixed:
        item["reasoning_fixed_effort"] = effort_fixed
    efforts_old = (meta.get("reasoning") or {}).get("supportedEfforts")
    if efforts_old and "reasoning_efforts" not in item:
        item["reasoning_efforts"] = efforts_old
    if (meta.get("reasoning") or {}).get("defaultEffort") \
            and "reasoning_default_effort" not in item:
        item["reasoning_default_effort"] = meta["reasoning"]["defaultEffort"]
    # ---- 计费：峰谷价（官方 promotion） ----
    price_now = meta.get("price_factor")
    promo = meta.get("promotion") if isinstance(meta.get("promotion"), dict) else {}
    if price_now is not None:
        item["price_factor"] = price_now
    peak = None
    if promo.get("before_promotion_price_factor") is not None:
        peak = promo.get("before_promotion_price_factor")
    elif meta.get("original_price_factor") is not None:
        peak = meta.get("original_price_factor")
    if peak is not None:
        item["price_factor_peak"] = peak
    # 低谷价 = 峰值 × 折扣（官方 promotion 的定义，与快照抓取时刻无关）。
    # 旧实现直接把"当前 price_factor"当成低谷价：快照若在非低谷时段抓取，
    # 报出的低谷价就会等于峰价（看板/客户端据此算错费用）。
    discount = promo.get("discount_factor")
    valley = None
    try:
        if peak is not None and discount and 0 < float(discount) <= 1:
            valley = round(float(peak) * float(discount), 4)
    except (TypeError, ValueError):
        valley = None
    if valley is None and price_now is not None:
        valley = price_now
    if valley is not None:
        item["price_factor_valley"] = valley
    # 只要官方给了 promotion 就下发峰谷元数据（不限于"此刻正在打折"）：
    # 高峰期抓取的快照里 promo.active=False，旧实现会整块跳过，客户端于是
    # 既看不到低谷窗口、也看不到峰价。active 如实透传官方值，"现在是否处于
    # 低谷"另由 off_peak_active_now（按本地时间复算）给出。
    if promo:
        badge = promo.get("badge") or {}
        desc_p = promo.get("description") or {}
        link = promo.get("link_url") or {}
        item["off_peak"] = {
            "active": bool(promo.get("active")),
            "window_start": promo.get("window_start"),
            "window_end": promo.get("window_end"),
            "timezone": promo.get("timezone"),
            "discount_factor": promo.get("discount_factor"),
            "badge": badge.get("zh") or badge.get("en") or "",
            "badge_en": badge.get("en") or "",
            "description": desc_p.get("zh") or desc_p.get("en") or "",
            "description_en": desc_p.get("en") or "",
            "link": link.get("zh") or link.get("en") or "",
        }
        item["off_peak_window"] = "%s-%s" % (promo.get("window_start"),
                                             promo.get("window_end"))
        item["promotion"] = promo
        # 当前是否正处于低谷时段（供看板做视觉高亮；前端亦会按本地时间复算）
        active = off_peak_active_now(promo.get("window_start"),
                                     promo.get("window_end"),
                                     tz=promo.get("timezone"))
        item["off_peak_active_now"] = bool(active)
    if meta.get("original_price_factor") is not None:
        item["original_price_factor"] = meta.get("original_price_factor")
    if meta.get("is_free") is not None:
        item["is_free"] = bool(meta.get("is_free"))
    if meta.get("is_new"):
        item["is_new"] = True
    if meta.get("icon"):
        item["icon"] = meta.get("icon")
    if meta.get("credits"):
        item["credits"] = meta["credits"]
    # ---- 自动探测结果（有记录才下发，未探测不伪造）----
    try:
        probe = trae_probe.health_for(mid, realm)
        if isinstance(probe, dict):
            item["probe"] = {
                "ok": bool(probe.get("ok")),
                "status": probe.get("status") or "",
                "elapsed_ms": probe.get("elapsed_ms") or 0,
                "at": probe.get("at") or 0,
                "error": probe.get("error") or "",
                "reply": probe.get("reply") or "",
            }
            item["probe_available"] = bool(probe.get("ok"))
    except Exception:
        pass
    if meta.get("discovered"):
        item["discovered"] = True
        item["discovery_source"] = meta.get("discovery_source") or "dynamic"
    # ---- 参考价（OpenRouter 公开价；不是 Trae 官方账单）----
    try:
        import trae_pricing
        price = trae_pricing.entry_for(mid)
        if price:
            flat = price.get("flat") or {}
            item["price"] = {
                "source": "openrouter",
                "currency": "USD",
                "unit": 1000000,
                "input_cache_hit": flat.get("input_cache_hit"),
                "input_cache_miss": flat.get("input_cache_miss"),
                "output": flat.get("output"),
                "or_id": price.get("or_id"),
                "exact": price.get("exact", True),
                "note": price.get("note") or "",
            }
    except Exception:
        pass
    return item


# ---------------------------------------------------------------------------
# 请求清洗与归一化
# ---------------------------------------------------------------------------
def strip_data_prefix(line):
    line = line.strip()
    if not line or line.startswith(":"):
        return ""
    while line.startswith("data:"):
        line = line[5:].strip()
    if not line or line.startswith(":"):
        return ""
    return line


def clean_chunk(raw):
    """Drop the empty noise fields the gateway pads deltas with."""
    try:
        obj = json.loads(raw)
    except Exception:
        return raw
    if not isinstance(obj, dict):
        return raw
    changed = False
    for choice in obj.get("choices") or []:
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            continue
        fc = delta.get("function_call")
        if fc is not None:
            fc_empty = (not fc) if not isinstance(fc, dict) else (not fc.get("name"))
            if fc_empty:
                delta.pop("function_call", None)
                changed = True
        if isinstance(delta.get("tool_calls"), list) and not delta["tool_calls"]:
            delta.pop("tool_calls")
            changed = True
        for key in NOISE_KEYS:
            if key in delta and not delta.get(key):
                delta.pop(key)
                changed = True
        if not delta and not choice.get("finish_reason"):
            return ""
    return json.dumps(obj, ensure_ascii=False) if changed else raw


def _strip_empty_fc(obj):
    """递归剔除空 function_call 占位（Responses/chat 通用）。"""
    changed = False
    if isinstance(obj, dict):
        fc = obj.get("function_call")
        if isinstance(fc, dict) and not fc.get("name"):
            obj.pop("function_call", None)
            changed = True
        tc = obj.get("tool_calls")
        if isinstance(tc, list) and not tc:
            obj.pop("tool_calls")
            changed = True
        for v in list(obj.values()):
            if _strip_empty_fc(v):
                changed = True
    elif isinstance(obj, list):
        for v in obj:
            if _strip_empty_fc(v):
                changed = True
    return changed


def clean_responses_frame(frame):
    """清洗 Responses SSE 帧（bytes）。只改写 data: 行，event: 行原样保留。"""
    if not frame:
        return frame
    try:
        text = frame.decode("utf-8")
    except Exception:
        return frame
    out, changed = [], False
    for line in text.splitlines():
        st = line.strip()
        if st.startswith("data:"):
            payload = st[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    obj = json.loads(payload)
                    if _strip_empty_fc(obj):
                        line = "data: " + json.dumps(obj, ensure_ascii=False)
                        changed = True
                except Exception:
                    pass
        out.append(line)
    return ("\n".join(out) + "\n\n").encode("utf-8") if changed else frame


def normalize_roles(messages):
    """Map role names the upstream rejects onto ones it accepts.

    Trae raw chat 只认识 system / user / assistant。OpenAI 新的
    "developer" 角色等价于 "system"。
    """
    out = []
    for m in messages or []:
        if not isinstance(m, dict):
            out.append(m)
            continue
        item = m
        if m.get("role") == "developer":
            item = dict(m)
            item["role"] = "system"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 出站提示词脱敏（防御性保留：过滤常见客户端指纹串）
# ---------------------------------------------------------------------------
SANITIZE_FEATURES = (
    "x-anthropic-billing-header",
    "cc_entrypoint=",
    "You are Claude Code, Anthropic's official CLI for Claude",
    "You are a coding agent running in the Codex CLI",
    "github.com/anthropics/",
)
SANITIZE_REWRITES = (
    ("You are Claude Code, Anthropic's official CLI for Claude",
     "You are Claude Code, Anthropic's official CLI tool for Claude"),
    ("You are a coding agent running in the Codex CLI, a terminal-based coding assistant.",
     "You are a coding agent running in the Codex CLI tool, a terminal-based coding assistant."),
)
SANITIZE_HDR_RE = re.compile(r"(?i)x-anthropic-billing-header:[^;\r\n]*;?\s*")
SANITIZE_BARE_HDR_RE = re.compile(r"(?i)x-anthropic-billing-header")
SANITIZE_KV_RE = re.compile(r"(?i)\bcc_[a-z0-9_]+=[^;\r\n]*;?\s*")


def has_fingerprint(text):
    if not isinstance(text, str) or not text:
        return False
    for f in SANITIZE_FEATURES:
        if f in text:
            return True
    return bool(SANITIZE_BARE_HDR_RE.search(text))


def sanitize_text(text):
    if not isinstance(text, str) or not text:
        return text
    if not has_fingerprint(text):
        return text
    for old, new in SANITIZE_REWRITES:
        text = text.replace(old, new)
    text = SANITIZE_HDR_RE.sub("", text)
    if "cc_" in text:
        prev = ""
        while prev != text:
            prev = text
            text = SANITIZE_KV_RE.sub("", text)
    text = SANITIZE_BARE_HDR_RE.sub("x-anthropic-billing-hdr", text)
    return text.strip()


def sanitize_content(content):
    if isinstance(content, str):
        return sanitize_text(content)
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" \
                    and "text" in part:
                p = dict(part)
                p["text"] = sanitize_text(p["text"])
                out.append(p)
            else:
                out.append(part)
        return out
    return content


def sanitize_tool_calls(tool_calls):
    if not isinstance(tool_calls, list):
        return tool_calls
    out = []
    for tc in tool_calls:
        if isinstance(tc, dict):
            item = dict(tc)
            fn = item.get("function")
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                fn = dict(fn)
                fn["arguments"] = sanitize_text(fn["arguments"])
                item["function"] = fn
            out.append(item)
        else:
            out.append(tc)
    return out


def sanitize_messages(messages):
    out = []
    for m in messages or []:
        if isinstance(m, dict):
            item = dict(m)
            if "content" in item:
                item["content"] = sanitize_content(item["content"])
            if isinstance(item.get("reasoning_content"), str):
                item["reasoning_content"] = sanitize_text(item["reasoning_content"])
            if "tool_calls" in item:
                item["tool_calls"] = sanitize_tool_calls(item["tool_calls"])
            out.append(item)
        else:
            out.append(m)
    return out


# 思考档位的官方词表顺序（用于把客户端档位映射到模型支持档位）
EFFORT_RANK = {"none": 0, "minimal": 1, "low": 2, "medium": 3, "high": 4,
               "xhigh": 5, "max": 6}
_EFFORT_OFF = ("none", "off", "disabled", "disable", "false", "0", "no")


_EFFORT_NATIVE_TO_EXTERNAL = {
    "light": "low", "low": "low", "medium": "medium",
    "high": "high", "extra_high": "xhigh", "xhigh": "xhigh", "max": "max",
}
_EFFORT_EXTERNAL_TO_NATIVE = {
    "low": "light", "medium": "medium", "high": "high",
    "xhigh": "extra_high", "max": "extra_high",
}


def _thinking_config(meta):
    meta = meta or {}
    fallback = None
    for key in ("thinking", "reasoning_effort_config", "thinking_config"):
        cfg = meta.get(key)
        if not isinstance(cfg, dict) or not cfg:
            continue
        if fallback is None:
            fallback = cfg
        if cfg.get("options") or cfg.get("support_thinking") is True:
            return cfg
    return fallback or {}


def native_effort_options(meta):
    """Trae 原生档位（light/high/extra_high 等），来自快照 thinking.options。"""
    cfg = _thinking_config(meta)
    options = cfg.get("options")
    if isinstance(options, list):
        return [str(e) for e in options if e]
    enabled = cfg.get("enabled")
    if isinstance(enabled, dict):
        efforts = enabled.get("efforts")
        if isinstance(efforts, dict):
            return [e for e in EFFORT_RANK if e in efforts]
    return []


def supported_efforts(meta):
    """对外的思考档位（low/high/xhigh），由 Trae 原生档位映射。

    空列表表示该模型只有"开/关"没有档位（如部分 Qwen / MiniMax）。
    """
    native = native_effort_options(meta)
    out = []
    for e in native:
        ext = _EFFORT_NATIVE_TO_EXTERNAL.get(e, e)
        if ext not in out:
            out.append(ext)
    return out


def catalog_meta_for(model_key, realm=None):
    """按上游 key 取该模型在官方目录里的元数据（找不到返回 {}）。

    Anthropic 入口在调用 trae_anthropic.messages_to_chat 时需要一个 meta，
    否则 effort_from_anthropic 取不到 supported 档位表 -> 思考档位被静默丢弃。
    """
    for m in trae_catalog.models_for_realm(realm or CURRENT_REALM):
        if m.get("key") == model_key:
            return m
    for m in trae_catalog.STATIC_INTL_MODELS + trae_catalog.STATIC_CN_MODELS:
        if m.get("key") == model_key:
            return m
    return {}


def default_effort(meta):
    """该模型的默认思考档位（外部 low/high/xhigh）。"""
    cfg = _thinking_config(meta)
    native = cfg.get("default_level") or cfg.get("default")
    if native:
        return _EFFORT_NATIVE_TO_EXTERNAL.get(str(native), str(native))
    enabled = cfg.get("enabled")
    if isinstance(enabled, dict):
        efforts = enabled.get("efforts")
        if isinstance(efforts, dict):
            for e, econf in efforts.items():
                if isinstance(econf, dict) and econf.get("is_default"):
                    return _EFFORT_NATIVE_TO_EXTERNAL.get(e, e)
    sup = supported_efforts(meta)
    return sup[len(sup) // 2] if sup else ""


def normalize_reasoning_effort(effort, meta):
    """把请求里的思考档位归一化到该模型**官方支持**的档位集合。

    为什么必须做：上游对不支持的档位**不报错、直接忽略**（回落到模型默认档）。
    实测：dfmodel 官方只支持 low/high/max（默认 max），传 medium/xhigh 时输出
    与默认档一致——客户端以为"思考档位没生效"；cn 的 qmodel 只有开/关，传任何
    档位都被忽略（只有 none 能关掉思考）。

    规则：
      - 关闭类取值（none/off/disabled/...）统一映射为 "none"（官方通用关闭值）；
      - 模型有档位表：命中则原样透传；未命中取"最近的合法档位"（同距时偏向
        模型默认档），并给出说明性 note；
      - 模型有 thinking_config 但无档位表（仅开/关）：除 none 外不下发该参数
        （避免给上游发它不认识的档位）；
      - 模型没有 thinking_config（如路由器 `auto`）：**原样透传**，不做猜测。

    返回 (value|None, note)：value=None 表示不下发 reasoning_effort。
    """
    e = str(effort or "").strip().lower()
    if not e:
        return None, ""
    if e in _EFFORT_OFF:
        return "none", ""
    cfg = _thinking_config(meta)
    if not cfg:
        # 目录里没有该模型的思考配置（路由器/未知模型）：不猜测，原样透传
        return e, ""
    native = native_effort_options(meta)
    if not native:
        return None, "dropped (model has no effort levels; use none to disable)"
    if e in native:
        return e, ""
    if e in _EFFORT_EXTERNAL_TO_NATIVE:
        wanted_native = _EFFORT_EXTERNAL_TO_NATIVE[e]
        if wanted_native in native:
            return wanted_native, ""
    ext_sup = supported_efforts(meta)
    if e in ext_sup:
        idx = ext_sup.index(e)
        # 外部档位可能在 native 里重复（extra_high/max 都映射 xhigh），取第一个
        return native[min(idx, len(native) - 1)], ""
    if e not in EFFORT_RANK:
        d = default_effort(meta)
        return _EFFORT_EXTERNAL_TO_NATIVE.get(d, native[0]), \
            "unknown level -> %s" % (d or native[0])
    d = default_effort(meta)
    want = EFFORT_RANK[e]

    def key(cand):
        ext = _EFFORT_NATIVE_TO_EXTERNAL.get(cand, cand)
        return (abs(EFFORT_RANK.get(ext, 3) - want),
                abs(EFFORT_RANK.get(ext, 3) - EFFORT_RANK.get(d, want)))

    best = sorted(native, key=key)[0]
    return best, "unsupported level %s -> %s" % (e, best)


def requested_effort(payload):
    """请求侧的**原始**思考档位（归一化之前），供 usage 记账与请求体构造共用。

    取值顺序与 build_trae_body 下发时完全一致（同源，避免两处漂移）：
    reasoning_effort -> reasoning.effort -> thinking.effort / thinking.level。
    仅做提取，不做任何归一化或猜测；空值返回 None。
    """
    if not isinstance(payload, dict):
        return None
    effort = payload.get("reasoning_effort")
    if not effort and isinstance(payload.get("reasoning"), dict):
        effort = (payload.get("reasoning") or {}).get("effort")
    if not effort and isinstance(payload.get("thinking"), dict):
        # 兼容 thinking.effort / thinking_level 风格客户端
        effort = (payload.get("thinking") or {}).get("effort")             or (payload.get("thinking") or {}).get("level")
    return effort or None


# ---------------------------------------------------------------------------
# 项目新版本检测（对比 GitHub 最新 release；结果缓存 6 小时）
# ---------------------------------------------------------------------------
UPDATE_CHECK_URL = ("https://api.github.com/repos/shuishuipingan/"
                    "trae2api-hub/releases/latest")
UPDATE_CHECK_TTL = 300
_update_cache = {"at": 0.0, "data": None}


def version_tuple(value):
    """'v1.2.3' -> (1, 2, 3)；容忍前缀与不足位数。"""
    out = []
    for chunk in str(value or "").lstrip("vV").split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        out.append(int(digits or 0))
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


def check_for_update(force=False):
    """检查项目是否有新版本（对比当前 VERSION 与 GitHub 最新 release）。

    返回 {ok, current, latest, has_update, url, published_at, name, checked_at, error}
    网络不可用/被墙时 ok=False + error，看板据此显示"检查失败"而不是误报。
    """
    now = time.time()
    cached = _update_cache.get("data")
    if cached and not force and now - _update_cache.get("at", 0) < UPDATE_CHECK_TTL:
        return cached
    info = {"ok": False, "current": VERSION, "latest": "", "has_update": False,
            "url": "", "tarball_url": "", "published_at": "", "name": "",
            "checked_at": int(now), "error": ""}
    try:
        url = validate_public_http_url(UPDATE_CHECK_URL)
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "trae2api-hub-update-check",
        })
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag = str(data.get("tag_name") or "").strip()
        info.update({
            "ok": True,
            "latest": tag,
            "url": str(data.get("html_url") or ""),
            "tarball_url": str(data.get("tarball_url") or ""),
            "published_at": str(data.get("published_at") or ""),
            "name": str(data.get("name") or ""),
            "has_update": bool(tag) and version_tuple(tag) > version_tuple(VERSION),
        })
    except Exception as exc:
        info["error"] = str(exc)[:160]
    _update_cache.update({"at": now, "data": info})
    return info


# ---------------------------------------------------------------------------
# 一键更新：下载 GitHub release tarball -> staging -> 备份 -> 退出并重启
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
UPDATE_REPO = "shuishuipingan/trae2api-hub"
UPDATE_LOCK = threading.Lock()
_UPDATE_SKIP = {"accounts", "usage", ".git", "update-backups", "__pycache__",
                ".pytest_cache", "_update_staging", "update-staging"}


def _update_is_docker():
    return os.path.exists("/.dockerenv") or os.environ.get(
        "TRAE_UPDATE_DOCKER", "").lower() in ("1", "true", "yes")


def _download_update(url, dest, max_bytes=80 * 1024 * 1024):
    url = validate_public_http_url(url)
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "trae2api-hub-updater",
    })
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
        total = 0
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError("update archive is too large")
            fh.write(chunk)
    return dest


def _extract_update(archive, dest):
    """Safely extract a GitHub tarball into dest (no absolute/.. paths)."""
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            name = member.name.replace("\\", "/")
            parts = [p for p in name.split("/") if p not in ("", ".")]
            if not parts or any(p == ".." for p in parts):
                continue
            target = os.path.join(dest, *parts)
            if member.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            if not member.isfile():
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    # GitHub tarball has one top-level directory; find the real project root.
    candidates = [os.path.join(dest, n) for n in os.listdir(dest)]
    roots = [c for c in candidates if os.path.isfile(os.path.join(c, "trae_proxy.py"))]
    return roots[0] if roots else dest


def _copy_update_tree(src, dst):
    """Copy archive project files over dst, never touching runtime data."""
    copied = 0
    for name in os.listdir(src):
        if name in _UPDATE_SKIP or name.startswith("_self_update"):
            continue
        source = os.path.join(src, name)
        target = os.path.join(dst, name)
        if os.path.isdir(source):
            if os.path.islink(source):
                continue
            shutil.copytree(source, target, dirs_exist_ok=True)
            copied += 1
        else:
            shutil.copy2(source, target)
            copied += 1
    return copied


def _make_update_backup(root):
    out_dir = os.path.join(root, "update-backups")
    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(out_dir, "update-%s.tar.gz" % stamp)
    with tarfile.open(path, "w:gz") as tar:
        for name in sorted(os.listdir(root)):
            if name in _UPDATE_SKIP or name.startswith("_self_update"):
                continue
            tar.add(os.path.join(root, name), arcname=name)
    return path


def _write_update_runner(root, staging, argv, log_path):
    """Write a detached helper; parent exits 0.8s after returning the API reply."""
    payload = {
        "root": root,
        "staging": staging,
        "argv": list(argv or []),
        "log": log_path,
    }
    fd, path = tempfile.mkstemp(prefix="trae2api-update-", suffix=".py")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "import json, os, shutil, subprocess, sys, time\n"
            "cfg=json.loads(%r)\n"
            "time.sleep(2.0)\n"
            "root=cfg['root']; staging=cfg['staging']; log=cfg['log']\n"
            "try:\n"
            "    for name in os.listdir(staging):\n"
            "        if name in ('accounts','usage','.git','update-backups') "
            "or name.startswith('_self_update'): continue\n"
            "        s=os.path.join(staging,name); d=os.path.join(root,name)\n"
            "        if os.path.isdir(s): shutil.copytree(s,d,dirs_exist_ok=True)\n"
            "        else: shutil.copy2(s,d)\n"
            "    shutil.rmtree(staging, ignore_errors=True)\n"
            "    fh=open(log,'a',encoding='utf-8')\n"
            "    fh.write('\\\\n[update] files applied at '+time.strftime('%%Y-%%m-%%d %%H:%%M:%%S')+'\\\\n')\n"
            "    fh.flush()\n"
            "    flags=0\n"
            "    if os.name=='nt': flags=0x00000008 | 0x00000200\n"
            "    subprocess.Popen([sys.executable, os.path.join(root,'trae_proxy.py')]+cfg['argv'],"
            "cwd=root,stdout=fh,stderr=fh,stdin=subprocess.DEVNULL,"
            "creationflags=flags, start_new_session=(os.name!='nt'))\n"
            "    fh.write('[update] restarted\\\\n'); fh.flush()\n"
            "except Exception as exc:\n"
            "    try:\n"
            "        open(log,'a',encoding='utf-8').write('\\\\n[update] FAILED: %%r\\\\n' %% (exc,))\n"
            "    except Exception: pass\n"
            % json.dumps(payload, ensure_ascii=False)
        )
    return path


def apply_project_update(tag="", tarball_url=""):
    """Stage a release and return restart metadata; caller exits shortly after."""
    if _update_is_docker():
        raise RuntimeError("Docker 部署请执行 docker compose pull / up -d，不能容器内自更新")
    if not UPDATE_LOCK.acquire(False):
        raise RuntimeError("已有更新任务在执行")
    try:
        info = check_for_update(force=True)
        if not info.get("has_update"):
            raise RuntimeError("当前已是最新版本：%s" % info.get("current"))
        latest = str(info.get("latest") or tag or "")
        url = str(info.get("tarball_url") or tarball_url or "")
        if not url:
            url = "https://api.github.com/repos/%s/tarball/%s" % (UPDATE_REPO, latest)
        archive = tempfile.mktemp(prefix="trae2api-release-", suffix=".tar.gz")
        _download_update(url, archive)
        extract_dir = tempfile.mkdtemp(prefix="trae2api-update-extract-")
        source = _extract_update(archive, extract_dir)
        staging = tempfile.mkdtemp(prefix="trae2api-update-stage-")
        shutil.copytree(source, staging, dirs_exist_ok=True)
        backup = _make_update_backup(PROJECT_ROOT)
        log_path = os.path.join(PROJECT_ROOT, "update.log")
        argv = list(sys.argv[1:])
        runner = _write_update_runner(PROJECT_ROOT, staging, argv, log_path)
        flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0
        subprocess.Popen(
            [sys.executable, runner],
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
            start_new_session=(os.name != "nt"),
            close_fds=True,
        )
        # flush the HTTP response, then release the port for the helper.
        threading.Timer(0.8, lambda: os._exit(0)).start()
        return {
            "ok": True,
            "restarting": True,
            "from": VERSION,
            "to": latest,
            "backup": os.path.basename(backup),
            "log": os.path.basename(log_path),
        }
    finally:
        try:
            if 'archive' in locals() and os.path.exists(archive):
                os.remove(archive)
        except Exception:
            pass
        UPDATE_LOCK.release()


def is_deepseek_model(model="", model_key=""):
    """判断这次请求最终打到的是不是一个 DeepSeek 上游模型。

    必须同时看**上游 key**（dmodel / dfmodel）和客户端写的名字：
    客户端完全可能直接写 `dfmodel`/`dmodel`（仓库文档里就把 DeepSeek-Flash
    标为「内部 key：dfmodel」），而展示名是 `DeepSeek-Flash`。此前只按名字
    前缀 "deepseek" 判断，走 key 的请求拿不到 reasoning_content 兼容处理，
    多轮会话会被上游拒绝——表现为"偶发失败、重试有时能过"。
    """
    key = str(model_key or "").strip().lower()
    if key in DEEPSEEK_MODEL_KEYS:
        return True
    low = str(model or "").strip().lower()
    if not low:
        return False
    if low in DEEPSEEK_MODEL_KEYS or low.startswith("deepseek"):
        return True
    # 展示 id「dfmodel (DeepSeek-Flash)」/ 别名 deepseek-v4-flash 等
    return "deepseek" in low


def backfill_reasoning_content(messages, model, model_key=""):
    """DeepSeek 多轮一致性：assistant 历史补 reasoning_content。

    触发条件只看"上游是不是 DeepSeek"，与客户端用 key 还是展示名无关。
    """
    if not is_deepseek_model(model, model_key):
        return messages
    has_trace = False
    for m in messages:
        if isinstance(m, dict):
            if m.get("reasoning") or "reasoning_content" in m:
                has_trace = True
                break
    if not has_trace:
        return messages
    out = []
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "assistant":
            item = dict(m)
            if "reasoning_content" not in item:
                if item.get("reasoning"):
                    item["reasoning_content"] = str(item["reasoning"])
                else:
                    item["reasoning_content"] = ""
            out.append(item)
        else:
            out.append(m)
    return out


# P2-2：tool_choice="none" 时是否连 tools 一起删（历史行为）。
# 默认**保留** tools 并把 "none" 原样写回 —— 工具能力声明与「本轮不许调用」是两件事，
# 且上游实测对 tools+none 返回纯文本、不报 400。若某天上游不再遵守 none（参考项目
# wb 的上游就有此现象：保留 tools 后仍回 tool_calls），设 QD_TOOLCHOICE_NONE_DROPS_TOOLS=1
# 可一键回到「连 tools 一起删」的旧行为，无需改代码发版。
TOOLCHOICE_NONE_DROPS_TOOLS = os.environ.get(
    "QD_TOOLCHOICE_NONE_DROPS_TOOLS", "0").lower() in ("1", "true", "yes", "on")


def normalize_tool_choice(obj):
    """把 OpenAI tool_choice 归一成上游可接受的形态（避免 400）。"""
    if "tool_choice" not in obj:
        return
    tc = obj["tool_choice"]
    if isinstance(tc, str):
        val = tc.strip().lower()
        if val == "none":
            if TOOLCHOICE_NONE_DROPS_TOOLS:
                obj.pop("tool_choice", None)
                obj.pop("tools", None)
            else:
                # 保留 tools 声明，只把「本轮不许调用」写在 tool_choice 上（上游只认字符串）
                obj["tool_choice"] = "none"
        return
    if isinstance(tc, dict):
        typ = (tc.get("type") or "").strip().lower()
        if typ == "none":
            if TOOLCHOICE_NONE_DROPS_TOOLS:
                obj.pop("tool_choice", None)
                obj.pop("tools", None)
            else:
                # 对象形式降级为字符串 "none"（与 auto/required 的既有降级风格一致）
                obj["tool_choice"] = "none"
        elif typ in ("auto", "required"):
            obj["tool_choice"] = typ
        elif typ == "function":
            name = (tc.get("function") or {}).get("name") or tc.get("name") or ""
            obj["tool_choice"] = name.strip() or "auto"
        else:
            obj.pop("tool_choice", None)
    else:
        obj.pop("tool_choice", None)


def normalize_tools(obj):
    """把顶层 name 型工具定义包成 Chat Completions function schema。"""
    tools = obj.get("tools")
    if not tools or not isinstance(tools, list):
        return
    norm = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        if "name" in t and "function" not in t and t.get("type") == "function":
            fn = {
                "name": t.get("name") or "",
                "description": t.get("description") or "",
                "parameters": t.get("parameters") or {},
            }
            if "strict" in t:
                fn["strict"] = t["strict"]
            norm.append({"type": "function", "function": fn})
        else:
            norm.append(t)
    obj["tools"] = norm


def translate_max_completion_tokens(obj):
    alias = obj.pop("max_completion_tokens", None)
    if alias is None:
        return
    if "max_tokens" in obj:
        return
    try:
        val = int(alias)
        if val > 0:
            obj["max_tokens"] = val
    except (TypeError, ValueError):
        pass


# ---------------------------------------------------------------------------
# DeepSeek DSML 工具调用回退解析
# ---------------------------------------------------------------------------
TAG_START = r"<[^>]*DSML[^>]*"
DSML_CALLS_RE = re.compile(TAG_START + r"calls>(.*?)</[^>]*DSML[^>]*calls>",
                           re.DOTALL)
DSML_INVOKE_RE = re.compile(
    TAG_START + r"invoke\s+name=[\x22\x27]([^\x22\x27]+)[\x22\x27]>(.*?)</[^>]*invoke>",
    re.DOTALL)
DSML_PARAM_RE = re.compile(
    TAG_START + r"parameter\s+name=[\x22\x27]([^\x22\x27]+)[\x22\x27][^>]*>(.*?)</[^>]*parameter>",
    re.DOTALL)


def parse_dsml_tool_calls(text):
    if not text or "DSML" not in text:
        return None, text
    match = DSML_CALLS_RE.search(text)
    if not match:
        return None, text
    calls_block = match.group(1)
    tool_calls = []
    for inv_match in DSML_INVOKE_RE.finditer(calls_block):
        func_name = inv_match.group(1)
        params_block = inv_match.group(2)
        params = {}
        for p_match in DSML_PARAM_RE.finditer(params_block):
            p_name = p_match.group(1)
            p_val = p_match.group(2).strip()
            params[p_name] = p_val
        tool_calls.append({
            "id": _new_id("call_"),
            "name": func_name,
            "arguments": json.dumps(params, ensure_ascii=False),
        })
    clean = (text[:match.start()].strip() + " " + text[match.end():].strip()).strip()
    return tool_calls, clean


# ---------------------------------------------------------------------------
# 历史工具调用文本形态的「回读」（issue #8）
# ---------------------------------------------------------------------------
# flatten_messages() 会把 assistant 历史里的 tool_calls 序列化成
#   marker（LEAK_MARKER，见下）+ 一个 JSON 数组 [{name, arguments}, ...]
# 给上游模型当上下文。长会话里模型偶发**照格式复述**成正文（没有结构化
# tool_calls），客户端就会把这段 JSON 当正文显示、本轮工具调用不执行。
# 这里补齐回读：在严格守卫下还原成结构化 tool_calls 并从正文移除。
LEAK_MARKER = "[assistant 请求调用工具]"
# issue #36 follow-up: the same upstream converter also emits the marker
# with ANGLE brackets (<assistant 请求调用工具>). Normalize it to the square-bracket
# form at every entry so there is exactly one code path for detection.
LEAK_MARKER_ALT = "<assistant 请求调用工具>"


def _normalize_leak_marker(text):
    """Rewrite a leading angle-bracket marker variant into the
    square-bracket form (also through a ``` fence).

    Only a LEADING hit is rewritten; the variant appearing mid-prose is
    untouched (that is not the start of an echo block).
    """
    if not text:
        return text
    t = text.lstrip()
    lead = text[:len(text) - len(t)]
    if t.startswith(LEAK_MARKER_ALT):
        return lead + LEAK_MARKER + t[len(LEAK_MARKER_ALT):]
    if t.startswith("```"):
        rest = t[3:]
        low = rest.lstrip().lower()
        if low.startswith("json"):
            after = rest.lstrip()[4:].lstrip()
        else:
            after = rest.lstrip()
        if after.startswith(LEAK_MARKER_ALT):
            return (lead + t[:len(t) - len(after)]
                    + LEAK_MARKER + after[len(LEAK_MARKER_ALT):])
    return text


# issue #36：上游把 DSML 工具调用转成「marker + JSON 数组」后，偶尔还会在
# 数组之后漏出原始 DSML 闭合标签（</｜DSML｜parameter> / </｜DSML｜invoke>
# / </｜DSML｜calls>，全角或半角竖线）。这些残片落在 hold 尾部会让
# _json_array_prefix_ok 在 "Extra data" 处证伪 -> 整段被当正文补发，工具调用
# 不执行且内部协议文本泄漏给用户。剥离只作用于尾部（内部出现则不属于此形态）。
_DSML_CLOSE_TAG_RE = re.compile(r"</[^>]*DSML[^>]*>\s*$")


def _strip_dsml_close_tail(text):
    """反复剥掉正文尾部连续的 DSML 闭合标签 + 空白；返回剥离后的文本。"""
    prev = None
    while prev != text:
        prev = text
        text = _DSML_CLOSE_TAG_RE.sub("", text)
    return text


def _dsml_tail_holdable(tail):
    """Extra-data 尾巴是否是「DSML 闭合标签（完整 / 帧边界截断的半截）」。

    先剥掉所有尾部完整标签，剩余若空（全是标签）或以 </ 开头（标签
    进行中）→ 值得暂留。宽松只影响延迟：流末 parse 入口的完整剥离是
    最终兜底（issue #36 后续）。
    """
    s = (tail or "").strip()
    if not s:
        return True
    prev = None
    while prev != s:
        prev = s
        s = _DSML_CLOSE_TAG_RE.sub("", s).strip()
    if not s:
        return True
    # 半截标签进行中：已见 "</" 或恰好切在首字符 "<"（1 字符/帧的真实边界）。
    # 长度护栏：真实 DSML 标签 <= ~25 字符，80 已留足余量；更长的大概率是
    # 散文，不再压住（fail-open 语义不破坏）。
    if s.startswith("</"):
        return len(s) <= 80
    return s == "<"


# issue #37：回声块**外层数组合法、内层 arguments 非法**（未转义换行/引号、
# 截断、尾部多余文本、非法转义）。这种块能确定是工具协议回声（marker + 数组 +
# 已声明的工具名），只是参数坏了——绝不能当正文放出去（协议泄漏），也不能
# 伪造一个可执行调用（会写坏文件）。统一替换为一句明确的失败说明。
BAD_ARGS_NOTICE = ("（上游返回的工具调用参数不是合法 JSON，网关已丢弃该调用，"
                   "未执行任何工具；请重试。）")

# issue #37（fail-closed）：错误详情是**固定串**——它会写进日志与客户端响应，
# 绝不能把实际参数、路径或正文带出去。
BAD_ARGS_ERROR_DETAIL = ("upstream tool-call echo contains invalid JSON "
                         "arguments; no tools were emitted")


# issue #49 方向 C 的节流状态：一分钟最多一条 WARN，其余只计数——
# 形态3（54 组空壳）一次会话就能刷出几十条，不节流会把日志淹掉。
_LEAK_WARN_STATE = {"last": 0.0, "suppressed": 0, "total": 0}
_LEAK_WARN_INTERVAL = 60.0


def _log_unrecovered_leak(text, where="chat"):
    """识别到「像工具协议回声、但四条回读路径都没认」时记一条 WARN（issue #49 方向 C）。

    为什么必须可见：失败路径是 fail-open（原样透传），于是**协议失败**被转换成
    **语义失真**——模型说「已清理」，工具其实没执行，客户端看到的是正常结束。
    日志至少让发生率可观测，而不是只能靠用户去查磁盘。
    节流：一分钟一条，其余计入 suppressed（下一条日志里带出来）。
    """
    try:
        t = text or ""
        marks = t.count(LEAK_MARKER) + t.count(LEAK_MARKER_ALT)
        dsml = t.count("DSML")
        if not marks and not dsml:
            return
        st = _LEAK_WARN_STATE
        st["total"] += 1
        now = time.time()
        if now - st["last"] < _LEAK_WARN_INTERVAL:
            st["suppressed"] += 1
            return
        sup = st["suppressed"]
        st["last"] = now
        st["suppressed"] = 0
        log("unrecovered tool-protocol leak passed through (%d chars, "
            "markers=%d, dsml=%d) at %s — issue #49 (total=%d, suppressed=%d)"
            % (len(t), marks, dsml, where, st["total"], sup),
            level="WARN", tag="chat")
    except Exception:
        pass


class InvalidToolArguments(UpstreamStatus):
    """已确认是工具协议回声，但内层 arguments 不是合法 JSON（issue #37）。

    fail-closed：不泄漏协议文本、不伪造可执行调用，也**不伪装成成功结束**。
    抛到上层后由各协议的错误出口转成明确失败：
      · chat 流式   -> data: {"error": ...} + [DONE]（不再发正常 finish）
      · Responses   -> response.failed（不再发 response.completed）
      · Anthropic   -> event: error（不再发 message_stop）
      · 非流式      -> HTTP 502 + 标准错误信封
    重试与账号冷却入口都显式排除本异常（见 should_retry_envelope /
    _handle_envelope_account_cooldown）：它不是账号问题，也不该自动重发收费请求。
    """

    def __init__(self):
        super(InvalidToolArguments, self).__init__(502, BAD_ARGS_ERROR_DETAIL)


_JSON_FENCE = chr(96) * 3


def _strip_json_fence(text):
    """剥掉**首/尾**代码围栏残余（头部 ```[json]`、尾部 ```）。

    为什么需要：流式里 `_find_marker_split` 会把开围栏切进散文，hold 只剩
    「marker + 数组 + 换行 + 闭围栏」；旧实现只在「整串被围栏包住」时才剥，
    于是这种形状被判成非回声 -> 当正文补发（issue #37 fail-closed 的漏检）。
    只动首尾，不碰中段。
    """
    t = (text or "").strip()
    if t.startswith(_JSON_FENCE):
        inner = t[len(_JSON_FENCE):]
        if inner[:4].lower() == "json":
            inner = inner[4:]
        t = inner.lstrip()
    if t.endswith(_JSON_FENCE) and len(t) > len(_JSON_FENCE):
        t = t[:-len(_JSON_FENCE)].rstrip()
    return t


def _echo_with_bad_args(text, allowed_names=None):
    """这段正文是否是「工具协议回声 + 内层参数非法」？（issue #37）

    判定链（全部满足才算）：
      1) 整段是 marker（方/尖括号）+ JSON 数组（可带围栏、可带 DSML 尾标签）；
      2) 外层数组能解析、非空，每项是 dict 且有非空字符串 name；
      3) 声明了 tools 时，所有 name 都在声明集合里；
      4) 至少一个 arguments 是**非空字符串但解析失败**。
    普通散文 / 讨论 marker / 合法 JSON 示例都不会命中。
    """
    if not text:
        return False
    t = _strip_json_fence(_normalize_leak_marker((text or "").strip()))
    # 围栏与 DSML 尾标签可能交替出现（围栏 -> DSML、DSML -> 围栏），
    # 剥两轮直到稳定；每轮都只动**首尾**，中段正文不受影响。
    prev = None
    while prev != t:
        prev = t
        t = _strip_json_fence(_strip_dsml_close_tail(t).strip()).strip()
    # issue #49：允许「散文 + 重复 marker」——取最后一个 marker，跳过连续重复。
    _mpos = t.rfind(LEAK_MARKER)
    if _mpos < 0:
        return False
    t = t[_mpos:]
    while t.startswith(LEAK_MARKER):
        t = t[len(LEAK_MARKER):].lstrip()
    t = _strip_dsml_close_tail(t)
    if t.endswith(_JSON_FENCE) and len(t) > len(_JSON_FENCE):
        t = _strip_dsml_close_tail(t[:-len(_JSON_FENCE)].rstrip())
    rest = t.strip()
    if not (rest.startswith("[") and rest.endswith("]")):
        return False
    try:
        arr = json.loads(rest)
    except Exception:
        return False
    if not isinstance(arr, list) or not arr:
        return False
    bad = 0
    for item in arr:
        if not isinstance(item, dict):
            return False
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            return False
        if allowed_names and name.strip() not in allowed_names:
            return False
        if "arguments" not in item:
            return False
        args = item.get("arguments")
        if isinstance(args, (dict, list)):
            continue
        if not isinstance(args, str):
            return False
        if not args.strip():
            continue
        try:
            json.loads(args)
        except Exception:
            bad += 1
    return bad > 0


# issue #11：tool 角色消息被序列化进 content 时的开标记（写入侧见
# flatten_messages）。网关只写开标记、不写闭标记；模型常自造一个
# 「[工具结果结束]」闭标记，甚至夹带自造的 <system_warning> 残片。
# 更根本的修法是不把 tool 结果序列化进 content（issue #11 作者建议），
# 那属于协议层重构（需要 tool_call_id 配对与结构化 message 透传），
# 本轮不做，只在回读侧兜住已被放大到正文里的回声块。
TOOL_RESULT_MARKER = "[工具结果"
TOOL_RESULT_CLOSE = "[工具结果结束]"

# issue #16-B1：跨帧补全窗口 = 最长标记长度 - 1（LEAK_MARKER 18 字符 -> 17）。
# 只有帧/缓冲**末尾**的这 17 个字符内匹配到某个标记的真前缀时才暂留；
# 下一帧一旦证伪立即补发（fail-open），不会无限压住正常文本。
_MARKER_HOLD_WINDOW = max(len(LEAK_MARKER), len(LEAK_MARKER_ALT),
                           len(TOOL_RESULT_MARKER)) - 1

# issue #16 兜底：hold 缓冲上限。正常文本长期"看起来仍是候选"时（模型写超长
# JSON/正则示例），hold 会持续增长 -> 内存与首字延迟风险。超限即 fail-open
# 放行并记一条 WARN：宁可漏一次，也不无限压住客户端。
_HOLD_MAX_CHARS = 32768            # 32KB（真实回声块远小于此；见档案 §13）
_HOLD_MAX_FRAMES = 200             # 连续空转帧上限（帧不增长才算一帧）


def parse_leaked_tool_calls(text, allowed_names=None):
    """把模型复述的「marker + JSON 数组」还原成结构化 tool_calls。

    严格守卫（避免把"讨论该标记的普通回复"误判为工具调用）：
      1) 整段正文 strip 后必须**恰好**是 marker + JSON 数组（可带 ``` 围栏）；
      2) 数组非空，每项 name 为非空字符串、arguments 为合法 JSON（字符串或对象）；
      3) 本次请求声明了 tools 时，所有 name 必须命中声明集合。

    返回 (tool_calls|None, clean_text)：识别成功时 clean_text 为空串
    （整段都是该块）；未识别时原样返回 text。
    """
    t = (text or "").strip()
    # issue #36 follow-up: normalize the angle-bracket marker variant.
    t = _normalize_leak_marker(t)
    # issue #36：整段解析前先剥尾部 DSML 闭合标签残片。
    t = _strip_dsml_close_tail(t)
    # 整段被 ``` 围栏包裹时先剥壳（模型复述时常带围栏）
    if t.startswith("```") and t.endswith("```") and len(t) > 6:
        inner = t[3:]
        if inner[:4].lower() == "json":
            inner = inner[4:]
        t = inner[:-3].strip()
    # issue #49：模型在长会话里会写成「散文 + marker + marker + 数组 + DSML 尾」。
    # 取**最后一个** marker 起算（前面散文作为 clean 返回，由调用方补发），
    # 再剥掉连续重复的 marker 与尾部围栏——这些都不放松后面的严格校验。
    _mpos = t.rfind(LEAK_MARKER)
    if _mpos < 0:
        return None, text
    prefix = t[:_mpos]
    # 前缀尾部可能残留 marker（「散文 + marker1 + marker2 + 数组」时，
    # marker1 落在 prefix 里）——它绝不能当正文发给客户端。
    prefix = prefix.rstrip()
    for _mk in (LEAK_MARKER, LEAK_MARKER_ALT):
        while prefix.endswith(_mk):
            prefix = prefix[:-len(_mk)].rstrip()
    t = t[_mpos:]
    while t.startswith(LEAK_MARKER):
        t = t[len(LEAK_MARKER):].lstrip()
    t = _strip_dsml_close_tail(t)
    if t.endswith(_JSON_FENCE) and len(t) > len(_JSON_FENCE):
        t = _strip_dsml_close_tail(t[:-len(_JSON_FENCE)].rstrip())
    rest = t.strip()
    if not (rest.startswith("[") and rest.endswith("]")):
        return None, text
    try:
        arr = json.loads(rest)
    except Exception:
        return None, text
    if not isinstance(arr, list) or not arr:
        return None, text
    calls = []
    for item in arr:
        if not isinstance(item, dict):
            return None, text
        name = item.get("name")
        args = item.get("arguments")
        if not isinstance(name, str) or not name.strip():
            return None, text
        if isinstance(args, (dict, list)):
            args = json.dumps(args, ensure_ascii=False)
        if not isinstance(args, str):
            return None, text
        if args.strip():
            try:
                json.loads(args)
            except Exception:
                return None, text
        calls.append({
            "id": _new_id("call_"),
            "type": "function",
            "function": {"name": name.strip(), "arguments": args},
        })
    if allowed_names:
        if not all(c["function"]["name"] in allowed_names for c in calls):
            return None, text
    return calls, prefix


def _leak_body_offset(text):
    """把「marker 之前的围栏前缀 / marker 之后的正文」解析出来。

    返回 (state, body)：state='pre'（还处在围栏/前缀区，未到 marker）、
    state='body'（已越过 marker，body 为其后文本）、state='no'（显然不是）。
    流式暂存与判真共用同一套前缀规则（含 ``` 与 ```json 围栏）。
    """
    t = _normalize_leak_marker((text or "")).lstrip()
    if not t or LEAK_MARKER.startswith(t):
        return "pre", None
    if t.startswith(LEAK_MARKER):
        # issue #49：模型会连写两个 marker（数组在第二个之后）——跳过重复的，
        # 否则 hold 会被判成「body 不是数组」而在流式中途证伪、整块补发。
        body = t[len(LEAK_MARKER):]
        b = body.lstrip()
        while b.startswith(LEAK_MARKER):
            b = b[len(LEAK_MARKER):].lstrip()
        # 重复 marker 还没打完（跨帧，如 "[assista"）——仍算候选，内容留空等下一帧。
        # 不回 "pre" 是因为此处已越过首个 marker，语义上是 body 但"暂时没内容"。
        if b and (LEAK_MARKER.startswith(b) or LEAK_MARKER_ALT.startswith(b)):
            return "body", ""
        return "body", b
    # issue #36 后续：尖括号变体的**真前缀**（跨帧进行中）同样算 pre——
    # 1 字符/帧时 '<' 单独到达，不能当散文放出（否则 marker 开头丢失）。
    if LEAK_MARKER_ALT.startswith(t):
        return "pre", None
    if not t.startswith("`"):
        return "no", None
    if len(t) < 3:
        return ("pre", None) if "```".startswith(t) else ("no", None)
    if not t.startswith("```"):
        return "no", None
    rest = t[3:]
    low = rest.lstrip().lower()
    if low.startswith("json"):
        after = rest.lstrip()[4:].lstrip()
    elif LEAK_MARKER.startswith(low) or low.startswith(LEAK_MARKER):
        after = rest.lstrip()          # 无语言标记的 ``` 围栏
    elif "json".startswith(low):
        return "pre", None             # 语言标记还没打完（j/js/json）
    else:
        return "no", None
    if LEAK_MARKER.startswith(after):
        return "pre", None
    if after.startswith(LEAK_MARKER):
        return "body", after[len(LEAK_MARKER):]
    return "no", None


def _leak_prefix_hold(text):
    """文本仍可能是泄漏块的前缀？（流式 hold-back 用）"""
    return _leak_body_offset(text)[0] != "no"


def _tool_names_from_payload(payload):
    """取客户端本次请求声明的工具名集合（回读守卫用）。"""
    names = set()
    for t in (payload or {}).get("tools") or []:
        if not isinstance(t, dict):
            continue
        fn = t.get("function") if isinstance(t.get("function"), dict) else t
        name = fn.get("name") or ""
        if name:
            names.add(str(name))
    return names or None


def _json_array_prefix_ok(text):
    """text 是否仍可能扩展成合法 JSON 数组字面量（流式暂存判定用）。"""
    s = (text or "").strip()
    if not s:
        return True
    if not s.startswith("["):
        return False
    try:
        json.loads(s)
        return True
    except Exception as exc:
        msg = str(exc)
        # 未闭合字符串的报错位置在字符串开头，但仍可继续扩展
        if msg.startswith("Unterminated string"):
            return True
        pos = getattr(exc, "pos", None)
        if pos is None:
            return False
        if msg.startswith("Invalid \\uXXXX escape"):
            # issue #16-B3：截断落在未写完的转义里（"...\\u6" / "...\\u63a2"）。
            # json.loads 的报错位置在**反斜杠**处而非末尾，旧的
            # `pos >= len(s) - 1` 兜底会判 False -> 不吞 -> 泄漏。
            # 「未写完」（hex 不足）与「彻底非法」（如 \\uZZZZ）在异常消息层面
            # 无法区分，一律宽松 hold —— 流末仍会走吞掉/补发判定（parse_leaked /
            # _leaked_partial_droppable），宽松只影响延迟、不改变最终结论。
            # 实测（Python 3.13）：pos 指向 'u' 本身（如 s[pos-1] == "\\"）；
            # 为稳妥两种位置都检查。
            return (s[max(0, pos - 1):pos + 1] == "\\u"
                    or s[pos:pos + 2] == "\\u")
        if msg.startswith("Extra data"):
            # 数组已完整，尾随的只能是（可能还没打完的）``` 收尾围栏
            tail = s[pos:].strip()
            # issue #36 follow-up: the tail may also be upstream DSML
            # close tags (complete, or cut mid-tag by a frame boundary
            # before the closing >). Hold those too - the stream-end
            # parse strips them; leniency only delays, never changes
            # the final verdict.
            if (not tail) or "```".startswith(tail):
                return True
            # issue #37 follow-up：闭围栏**之后**还可能跟 DSML 尾标签。小分块时
            # 会出现「``` + 换行 + 半截 </…」——旧逻辑直接喂给
            # _dsml_tail_holdable，它看到开头是反引号就判 False，于是候选被
            # 中途证伪、整块当正文补发（真·泄漏）。先剥掉完整闭围栏再看剩余。
            if tail.startswith(_JSON_FENCE):
                tail = tail[len(_JSON_FENCE):].strip()
                if not tail:
                    return True
            return _dsml_tail_holdable(tail)
        # 语法错误点落在末尾（未闭合括号等）→ 还允许继续扩展
        return pos >= len(s) - 1


def _find_marker_split(text, allow_prefix=True):
    """把正文切成 (立即发出, 暂存候选)：在首个完整标记处切开（issue #16-B1）。

    - 命中完整标记 -> (标记之前的散文, 标记及其后)；
    - allow_prefix=True 且**末尾**是某标记的真前缀（长度 < 标记）时，把这段
      前缀留给下一帧（跨帧补全窗口 _MARKER_HOLD_WINDOW）；
    - 无命中 -> (text, "")。

    背景：服务端 delta 切分不可控，"散文 + marker" 可能落在同一帧，而
    _leak_prefix_hold 只认「整帧以标记开头」-> 整帧被透传 -> 泄漏。
    """
    t = _normalize_leak_marker(text or "")
    if not t:
        return "", ""
    best = -1
    for mk in (LEAK_MARKER, TOOL_RESULT_MARKER):
        i = t.find(mk)
        if i != -1 and (best == -1 or i < best):
            best = i
    if best != -1:
        return t[:best], t[best:]
    if not allow_prefix:
        return t, ""
    tail = t[-_MARKER_HOLD_WINDOW:] if len(t) > _MARKER_HOLD_WINDOW else t
    for mk in (LEAK_MARKER, LEAK_MARKER_ALT, TOOL_RESULT_MARKER):
        for n in range(min(len(tail), len(mk) - 1), 0, -1):
            if tail.endswith(mk[:n]):
                return t[:-n], t[-n:]
    return t, ""


def _marker_starts_at(text):
    """text 是否以某标记开头，或整段就是它的真前缀（跨帧补全中）。"""
    t = text or ""
    if not t:
        return True
    for mk in (LEAK_MARKER, LEAK_MARKER_ALT, TOOL_RESULT_MARKER):
        if t.startswith(mk):
            return True
        if len(t) < len(mk) and mk.startswith(t):
            return True
    return False


def _still_leak_candidate(text):
    """整段文本目前是否仍是「marker + JSON 数组」候选？（流式暂存判定用）"""
    state, body = _leak_body_offset(text)
    if state == "pre":
        return True
    if state == "no":
        return False
    rest = (body or "").lstrip()
    if not rest:
        return True
    if rest.endswith("```"):
        rest = rest[:-3]
    return _json_array_prefix_ok(rest)


def _leaked_partial_droppable(text, allowed_names=None):
    """issue #9：正文是网关自己写入历史的工具调用回声、但被截断（JSON 不完整/
    非法）时，应吞掉整段而不是透传给终端用户。三个条件同时成立才吞：
      1) strip 后以 LEAK_MARKER 开头（真实散文回复几乎不会这样开头）；
      2) 本次请求声明了 tools（allowed_names 非空）——与恢复路径同前置条件；
      3) marker 之后（剥掉围栏后）仍是 JSON 数组字面量的前缀
         （复用现成的 _json_array_prefix_ok）——即"本该是数组，只是没写完"。
    返回 True = 应吞掉正文（输出空 content）。

    完整且合法的 JSON 数组不算：那种情况下恢复失败另有原因（工具名未声明 /
    arguments 非法），保持既有 fail-open 透传语义（见 _test_trae.py 的 [27]
    断言"未声明工具名 -> 不吞正文"），只有"数组本身没写完 / 非法"才吞。
    """
    if not text or not allowed_names:
        return False
    t = text.strip()
    if not t:
        return False
    if t == LEAK_MARKER:
        # 只有 marker、连数组都没开始写：判据 3 的退化情形，同样是回声。
        return True
    state, body = _leak_body_offset(t)
    if state != "body":
        return False
    rest = (body or "").strip()
    if rest.endswith("```"):
        rest = rest[:-3].strip()
    if not _json_array_prefix_ok(rest):
        return False
    try:
        json.loads(rest)
        return False
    except Exception:
        return True


def _tool_echo_head(text):
    """切分「[工具结果<name>]」开标记行 → (body, ok)；ok=False 表示不是合法开标记。"""
    t = (text or "").strip()
    if not t.startswith(TOOL_RESULT_MARKER):
        return None, False
    rest = t[len(TOOL_RESULT_MARKER):]
    close = rest.find("]")
    if close == -1 or "\n" in rest[:close]:
        return None, False          # 标记行未闭合 / 换行后才有 ]：非本网关形态
    return rest[close + 1:], True


def _tool_echo_droppable(text, allowed_names=None):
    """issue #11：正文是「[工具结果...]」回声块时吞掉整段（与 issue #9 同形态）。

    三个条件同时成立才吞：
      1) strip 后是合法开标记行（TOOL_RESULT_MARKER + 可选 name + ]）；
      2) 本次请求声明了 tools（allowed_names 非空）——与既有回读同一前置；
      3) 形态自洽：出现模型自造的闭标记 TOOL_RESULT_CLOSE，或标记之后（忽略空白）
         以 JSON/标签起始字符开头（含被截断、永不闭合的块）。

    为什么吞掉而不是还原成 tool 消息：还原需要把回声与历史上的 tool_call_id
    配对（网关现在压平进 content 时并未保留 call_id），本轮不引入该复杂度，
    只做「不把内部协议文本交给终端用户」。

    不吞（fail-open）：不以标记开头；标记后跟自然语言散文；未声明 tools。
    """
    if not text or not allowed_names:
        return False
    body, ok = _tool_echo_head(text)
    if not ok:
        return False
    if TOOL_RESULT_CLOSE in body:
        return True
    rest = body.lstrip()
    if not rest:
        return True                 # 只有开标记：退化形态（与 #9 的纯 marker 一致）
    return rest[0] in "{[\"<"


def _tool_echo_prefix_hold(text):
    """流式 hold-back：这段缓冲仍可能是 issue #11 的回声块吗？（宽松版判据）"""
    t = (text or "").lstrip()
    if not t:
        return True
    if TOOL_RESULT_MARKER.startswith(t):
        return True                 # 标记本身还没打完
    body, ok = _tool_echo_head(t)
    if not ok:
        return False                # 不是标记形态 -> 证伪，立即放行
    if TOOL_RESULT_CLOSE in body:
        return True
    rest = body.lstrip()
    if not rest:
        return True
    return rest[0] in "{[\"<"


def _echo_hold_candidate(text):
    """统一暂存判定：仍可能是 #8 数组回声或 #11 工具结果回声？"""
    return _still_leak_candidate(text) or _tool_echo_prefix_hold(text)


def _leak_chunk_frame(meta, delta, finish_reason=None):
    """按流式 chat.completion.chunk 形态合成一帧（沿用上游的 id/model）。"""
    payload = {
        "id": meta.get("id") or "chatcmpl-trae",
        "object": "chat.completion.chunk",
        "created": meta.get("created") or int(time.time()),
        "model": meta.get("model") or "",
        "choices": [{"index": 0, "delta": delta,
                     "finish_reason": finish_reason}],
    }
    return ("data: " + json.dumps(payload, ensure_ascii=False)
            + "\n\n").encode("utf-8")


def _frame_without_content(payload):
    """复制一帧并去掉 delta.content（保留 tool_calls/reasoning/收尾信息）。"""
    out = dict(payload)
    choices = []
    for ch in payload.get("choices") or []:
        if not isinstance(ch, dict):
            choices.append(ch)
            continue
        ch2 = dict(ch)
        delta = ch2.get("delta")
        if isinstance(delta, dict) and "content" in delta:
            d2 = dict(delta)
            d2.pop("content", None)
            ch2["delta"] = d2
        choices.append(ch2)
    out["choices"] = choices
    return out


def _sse_fill_tool_call_ids(frames):
    """流式出口保证：tool_call 增量的 id 必须非空（issue #47）。

    上游偶尔给出**缺 id**（甚至缺 function）的增量帧，网关此前原样透传；
    下游客户端会把 id="" 落盘，而它的会话加载器要求非空字符串 —— 一条空 id
    （校验发生在「从 seq 0 顺序回放整份会话」的状态机里，不是跳过坏行）
    就让整份会话报废。三层客户端都把 "" 一路放行，**只有网关出口能拦**。

    规则：
      - 上游给了 id -> 原样保留（不改写、不重新造号），并让同 index 的后续
        分帧沿用同一个 id（下游靠 id 把 tool_call 与 tool_result 配对）；
      - 缺 id -> 补 _new_id("call_")，**按 index 记忆**（分帧到达时换号会断链）；
      - 非 tool_call 帧（[DONE] / 纯正文 / 非 JSON）**字节级原样透传**。
    放在出口而不是各产出点：流式侧有多个来源（上游原生增量 / #8 泄漏回读 /
    DSML 回放），逐个补必然漏，这是唯一合流点。
    """
    ids = {}          # key -> 已分配的 id
    named = set()     # 该 key 是否已经「用掉」过一次 function.name（新调用的起点）

    def _key_for(tc, pos, n_calls):
        """tool_call 的**稳定**记忆键（issue #47 补充）。

        1) 有 int index -> 用它（协议正解）；
        2) 缺 index -> 用**帧内位置**：多调用同帧各得不同键（并行不再撞号），
           单调用恒为 0（与 index=0 归一到同一键，避免 None/0 两套记忆）；
        3) index 是不可哈希/畸形值（list/dict/str）-> 同样按位置，
           **绝不让它进 dict key**（否则 TypeError 会一路冒到 socket）。
        """
        idx = tc.get("index")
        if isinstance(idx, int) and not isinstance(idx, bool):
            return ("i", idx)
        return ("i", pos if n_calls > 1 else 0)

    for raw in frames:
        text = (raw.decode("utf-8", "replace")
                if isinstance(raw, bytes) else raw)
        data = strip_data_prefix(text)
        if not data or data == "[DONE]":
            yield raw
            continue
        try:
            payload = json.loads(data)
        except Exception:
            yield raw
            continue
        choices = payload.get("choices") if isinstance(payload, dict) else None
        if not isinstance(choices, list):
            yield raw
            continue
        touched = False
        try:
            for ch in choices:
                if not isinstance(ch, dict):
                    continue
                delta = ch.get("delta")
                if not isinstance(delta, dict):
                    continue
                calls = delta.get("tool_calls")
                if not isinstance(calls, list):
                    continue
                for pos, tc in enumerate(calls):
                    if not isinstance(tc, dict):
                        continue
                    key = _key_for(tc, pos, len(calls))
                    cur = tc.get("id")
                    fn = tc.get("function")
                    name = str((fn or {}).get("name") or "").strip() \
                        if isinstance(fn, dict) else ""
                    if isinstance(cur, str) and cur.strip():
                        # 上游给了 id：原样保留；**覆盖式**记忆让后到的真 id
                        # 收敛（旧实现 setdefault 会让后续帧回落到旧补值）。
                        ids[key] = cur
                        if name:
                            named.add(key)
                        continue
                    # 同一 key 第二次带 name = 无 index 场景下的**另一个**调用
                    # （串行两次调用都落在位置 0），必须换号，否则配对断裂。
                    if name and key in named:
                        ids[key] = _new_id("call_")
                    new_id = ids.get(key) or _new_id("call_")
                    ids[key] = new_id
                    if name:
                        named.add(key)
                    tc["id"] = new_id
                    touched = True
        except Exception:
            # 兜底：任何意外都不得让异常冒到 socket（fail-open，与其余分支一致）
            yield raw
            continue
        if touched:
            yield ("data: " + json.dumps(payload, ensure_ascii=False)
                   + "\n\n").encode("utf-8")
        else:
            yield raw


def _recover_leaked_tool_calls_inner(frames, allowed_names=None):
    """流式回读（issue #8）：把模型逐块吐出的「marker + JSON 数组」正文恢复
    成结构化 tool_calls 增量帧；其余内容原样透传（fail-open）。

    与 parse_leaked_tool_calls 同一套严格守卫，另加：
      - 只有当已输出的正文仍是该块的「前缀/候选」时才暂存（期间不发正文）；
      - 候选被证伪（出现别的字 / JSON 非法）→ 立刻把暂存整段补发为正文；
      - 收尾帧暂存到流末，识别成功时改写 finish_reason=tool_calls；
      - 上游中断时暂存直接丢弃（正文未发，交给上游重试/错误帧处理）。
    """
    hold = None          # 正在暂存的候选正文（None = 未暂存）
    hold_frames = 0      # 连续未增长的帧数（空转保护，issue #16/#36 后续）
    finished = None      # 暂存的收尾帧：(payload, 原 finish_reason)
    recovered = False
    meta = {"id": None, "model": None, "created": None}

    for raw in frames:
        text = (raw.decode("utf-8", "replace")
                if isinstance(raw, bytes) else raw)
        data = strip_data_prefix(text)
        payload = None
        if data and data != "[DONE]":
            try:
                payload = json.loads(data)
            except Exception:
                payload = None
        if not isinstance(payload, dict):
            yield raw
            continue
        if payload.get("id"):
            meta["id"] = payload["id"]
        if payload.get("model"):
            meta["model"] = payload["model"]
        if payload.get("created"):
            meta["created"] = payload["created"]
        choices = payload.get("choices") or []
        choice = (choices[0] if choices and isinstance(choices[0], dict)
                  else {})
        delta = choice.get("delta") or {}
        piece_raw = delta.get("content")
        piece = piece_raw if isinstance(piece_raw, str) else ""
        fin = choice.get("finish_reason")
        if piece_raw is not None and not isinstance(piece_raw, str):
            # 非字符串 content（罕见）：不参与暂存判断，原样透传
            if hold is not None:
                yield _leak_chunk_frame(meta, {"content": hold})
                hold = None
                hold_frames = 0
            yield raw
            continue
        if hold is not None:
            hold += piece
            # issue #36 后续：帧上限只防**空转**（连续空帧不增长），有增长的
            # 合法回声块（每帧 1 字符也会推进长度）交给 32KB 字符上限兜底——
            # 否则 201 字符的合法块在 1 字符/帧下会在 200 帧处被误伤 fail-open。
            if piece:
                hold_frames = 0
            else:
                hold_frames += 1
            # issue #36：尾部 DSML 闭合标签是上游协议残片，剥掉再判候选；
            # 只有剥掉后仍是候选时才采纳（讨论 DSML 的普通散文不被误伤）。
            _stripped = _strip_dsml_close_tail(hold)
            if _stripped != hold and _still_leak_candidate(_stripped):
                hold = _stripped
            if _echo_hold_candidate(hold):
                # issue #16 兜底：超限即 fail-open 放行（内存 + 首字延迟）。
                if len(hold) > _HOLD_MAX_CHARS \
                        or hold_frames > _HOLD_MAX_FRAMES:
                    log("released oversized leak hold (%d chars / %d frames) "
                        "— fail-open" % (len(hold), hold_frames),
                        level="WARN", tag="chat")
                    yield _leak_chunk_frame(meta, {"content": hold})
                    hold = None
                    hold_frames = 0
                    if fin:
                        finished = (_frame_without_content(payload), fin)
                    continue
                if fin:
                    # 该帧 content 已进入 hold（可能被吞或稍后补发），收尾帧必须
                    # 去掉 content，否则同一段内容会被发两次（issue #16）。
                    finished = (_frame_without_content(payload), fin)
                elif (delta.get("tool_calls")
                      or delta.get("reasoning_content")
                      or delta.get("role")):
                    other = _frame_without_content(payload)
                    yield ("data: "
                           + json.dumps(other, ensure_ascii=False)
                           + "\n\n").encode("utf-8")
                continue
            # issue #37 fail-closed：块虽已「证伪」（后续还有别的字/围栏/DSML
            # 标签），但内容足以认定是**协议回声 + 内层参数非法**时，绝不能
            # 当正文补发——直接升级为协议错误（提前判定，不等流末）。
            if _echo_with_bad_args(hold, allowed_names):
                raise InvalidToolArguments()
            # issue #49 方向 C：候选被证伪 -> 整段当正文补发，这里同样留痕
            # （形态3「marker + <terminal></terminal> 空壳」就走这条：没有 JSON
            # 可恢复，但必须让发生率可见，而不是静默失真）。
            _log_unrecovered_leak(hold, "stream-falsified")
            # 证伪：暂存整段补发为普通正文
            yield _leak_chunk_frame(meta, {"content": hold})
            hold = None
            hold_frames = 0
            if fin:
                    # 该帧 content 已进入 hold（可能被吞或稍后补发），收尾帧必须
                    # 去掉 content，否则同一段内容会被发两次（issue #16）。
                finished = (_frame_without_content(payload), fin)
            continue
        if fin and not piece:
            finished = (payload, fin)
            continue
        if piece:
            # issue #16-B1：散文与 marker 落在同一帧时，_leak_prefix_hold
            # 对整帧判 False（它要求 lstrip 后以标记开头）-> 整帧透传 -> 泄漏。
            # 这里先按标记切分：标记之前的散文**立即发出**（不拖首字延迟），
            # 标记及其后进既有 hold 流程；帧尾的真前缀也在这里被暂留。
            _emit16, _hold16 = _find_marker_split(piece)
            if _hold16:
                if _emit16:
                    yield _leak_chunk_frame(meta, {"content": _emit16})
                hold = _hold16
                hold_frames = 1
                if fin:
                    # 该帧 content 已进入 hold（可能被吞或稍后补发），收尾帧必须
                    # 去掉 content，否则同一段内容会被发两次（issue #16）。
                    finished = (_frame_without_content(payload), fin)
                continue
            if _leak_prefix_hold(piece) or _tool_echo_prefix_hold(piece):
                hold = piece
                hold_frames = 1
                if fin:
                    # 该帧 content 已进入 hold（可能被吞或稍后补发），收尾帧必须
                    # 去掉 content，否则同一段内容会被发两次（issue #16）。
                    finished = (_frame_without_content(payload), fin)
                continue
            if fin:
                yield _leak_chunk_frame(meta, {"content": piece}, fin)
            else:
                yield _leak_chunk_frame(meta, {"content": piece})
            continue
        yield raw

    if hold is not None:
        calls, clean = parse_leaked_tool_calls(hold, allowed_names)
        if calls:
            recovered = True
            for i, call in enumerate(calls):
                yield _leak_chunk_frame(meta, {"tool_calls": [{
                    "index": i,
                    "id": call.get("id"),
                    "type": call.get("type") or "function",
                    "function": call.get("function") or {},
                }]})
            if clean:
                yield _leak_chunk_frame(meta, {"content": clean})
        elif _echo_with_bad_args(hold, allowed_names):
            # issue #37（fail-closed）**必须先于 #9/#11 判定**：坏参数块的外层
            # 数组是**完整合法**的，只是后面跟着 DSML/围栏残片——这会让
            # _leaked_partial_droppable 误判成"截断回声"并静默吞掉（正常 stop），
            # 既不是失败语义也不是恢复。判定互斥：真截断的数组 parse 不过，
            # 走不到这里（仍由 #9 吞掉）。
            # issue #37（fail-closed）：能确定是工具协议回声（marker + 合法外层
            # 数组 + 已声明工具名），只是内层 arguments 坏了——不泄漏协议、不
            # 伪造可执行调用，也**不以普通 stop 结束**，改为协议级失败。
            log("tool-call echo has invalid JSON arguments (%d chars) — "
                "failing the turn closed (issue #37)" % len(hold),
                level="WARN", tag="chat")
            raise InvalidToolArguments()
        elif _leaked_partial_droppable(hold, allowed_names):
            # issue #9：截断的 marker+JSON 回声无法还原成结构化调用，吞掉整段，
            # 绝不把网关内部协议文本透传给终端用户。
            log("dropped truncated leaked tool-call echo (%d chars) — issue #9"
                % len(hold), level="WARN", tag="chat")
        elif _tool_echo_droppable(hold, allowed_names):
            # issue #11：模型把 [工具结果...] 回声块当正文吐出（自造闭标记或
            # 未闭合的截断块）——吞掉，不还原（需 tool_call_id 配对）。
            log("dropped leaked tool-result echo (%d chars) — issue #11"
                % len(hold), level="WARN", tag="chat")
        else:
            # issue #49 方向 C：认不出但**看起来就是协议回声**的，必须留痕。
            _log_unrecovered_leak(hold, "stream")
            yield _leak_chunk_frame(meta, {"content": hold})
    if finished is not None:
        payload, fin = finished
        if recovered:
            payload = json.loads(json.dumps(payload))
            for ch in payload.get("choices") or []:
                if isinstance(ch, dict) and ch.get("finish_reason"):
                    ch["finish_reason"] = "tool_calls"
        yield ("data: " + json.dumps(payload, ensure_ascii=False)
               + "\n\n").encode("utf-8")
    elif recovered:
        yield _leak_chunk_frame(meta, {}, "tool_calls")


def recover_leaked_tool_calls(frames, allowed_names=None):
    """流式出口：回读（issue #8）+ **tool_call id 保证**（issue #47）。

    保持同名：三条调用点（chat 主链路 / Anthropic / Responses）都不用改。
    """
    for frame in _sse_fill_tool_call_ids(
            _recover_leaked_tool_calls_inner(frames, allowed_names)):
        yield frame


# ---------------------------------------------------------------------------
# Trae 数据面：请求体构造
# ---------------------------------------------------------------------------
def _flatten_content_text(content):
    """把 OpenAI content（str 或 parts 列表）压成纯文本；图片另行收集。"""
    if content is None:
        return "", []
    if isinstance(content, str):
        return content, []
    if isinstance(content, dict):
        # 单 part 形态（部分客户端把单个 part 对象直接当 content 而非列表）：
        # 当单元素列表处理，绝不 str() —— 否则图像 dict 被字符串化成 Python
        # 字面量文本，模型收到的是一段 {'type': 'image_url', ...}，
        # 图像从未真正到达模型（issue #33 的反馈根因）。
        content = [content]
    elif not isinstance(content, list):
        return str(content), []
    texts, images = [], []
    for piece in content:
        if isinstance(piece, str):
            texts.append(piece)
            continue
        if not isinstance(piece, dict):
            continue
        ptype = piece.get("type") or ""
        if ptype in ("text", "input_text", "output_text", "summary_text"):
            texts.append(piece.get("text") or "")
        elif ptype in ("image_url", "image", "input_image") or "image_url" in piece:
            url = piece.get("image_url") or piece.get("url")
            if isinstance(url, dict):
                url = url.get("url")
            if not url and piece.get("data"):
                mime = piece.get("mimeType") or piece.get("mime_type") or "image/png"
                url = "data:%s;base64,%s" % (mime, piece["data"])
            if url:
                images.append(url)
    return "\n".join(t for t in texts if t), images


# ---------------------------------------------------------------------------
# 写入侧暴露面削减（评估报告路线 3：历史工具结果首尾保留 + 中间省略）
# ---------------------------------------------------------------------------
# 动机（issue #8/#11）：长会话里工具结果被全文回灌、且每轮全量重放，模型反复
# 看到同一套「信封 + 长正文」样本 -> 复述概率升高，token 成本也随轮数线性增长。
# 这里只削减**历史**（当前轮的 tool 结果必须完整保留）：信封前缀
# （TOOL_RESULT_MARKER + name + "]\n"）逐字节不变，只动正文。
TOOL_RESULT_KEEP_DEFAULT = 2000        # 单侧保留字符数（默认值，可由环境覆盖）
_TOOL_RESULT_SHRINK_MARGIN = 200       # 削后至少要省这么多字符，才值得加省略标记


def _tool_result_keep_chars():
    """单侧保留字符数；返回 0 表示**完全关闭**削减（回退全文回灌）。

    环境变量 QD_TOOL_RESULT_KEEP：正整数 = 单侧保留字符数；
    0 / off / none / false / no / disable[d] = 关闭；非法值 = 用默认值。
    每次调用都读环境变量，便于运行期调整与离线测试。
    """
    raw = (os.environ.get("QD_TOOL_RESULT_KEEP") or "").strip().lower()
    if not raw:
        return TOOL_RESULT_KEEP_DEFAULT
    if raw in ("0", "off", "none", "false", "no", "disable", "disabled"):
        return 0
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return TOOL_RESULT_KEEP_DEFAULT
    return val if val > 0 else 0


def _is_complete_json(text):
    s = (text or "").strip()
    if not s or s[0] not in "{[":
        return False
    try:
        json.loads(s)
        return True
    except Exception:
        return False


def _shrink_tool_result(text, keep):
    """历史工具结果：首尾各保留 keep 字符，中间换成明确的省略标记。

    为什么首尾保留：工具输出的信息密度两端最高——头部是命令回显/首个错误/
    文件起始，尾部是错误堆栈结尾、退出状态、diff 末尾；中间通常是重复的滚动
    日志。按换行边界对齐，避免切出半行。
    完整 JSON 额外宽限到 2*keep：结构化数据被截断即失去可解析性。
    返回原文本表示「不值得削或不能削」。
    """
    if not isinstance(text, str) or keep <= 0:
        return text
    if len(text) <= keep * 2 + _TOOL_RESULT_SHRINK_MARGIN:
        return text                       # 本来就不长：原样保留
    if _is_complete_json(text) and len(text) <= keep * 4:
        return text                       # 完整 JSON 给双倍预算，保住可解析性
    head = text[:keep]
    nl = head.rfind("\n")
    if nl > keep // 2:                    # 尽量切在行边界（且别把头部砍太多）
        head = head[:nl]
    tail = text[-keep:]
    nl2 = tail.find("\n")
    if nl2 != -1 and nl2 < keep // 2:
        tail = tail[nl2 + 1:]
    # issue #48：省略标记必须是**固定串**——带字数会让「同一条工具结果」
    # 在不同轮次产生不同字节（内容一旦变化/重试，数字就变），直接打断上游
    # 前缀缓存。字数信息换不来什么，去掉。
    marker = ("\n[[trae2api-hub: 已省略中间内容；"
              "需要完整内容请重新执行该命令]]\n")
    return head + marker + tail


def _tool_result_scope():
    """削减范围策略（issue #48）：返回 ("tail", N) / ("all", 0) / ("turn", 0)。

    为什么需要它：旧规则 `_current_turn_start` 会随请求形态**滑动**——
    连续工具调用时 `_cur_start=1`（全不削），用户插一句话后 `_cur_start` 跳到
    末尾（**每条**历史工具结果全部改写成省略版）。同一条历史消息在不同轮次被
    序列化成不同字节，上游前缀缓存从第一条被削处开始整段失效（实测命中率
    从 95-99% 掉到 8%）。

    新默认 `tail`：只保护**最后 N 条**工具结果（默认 1），更早的一律削——
    同一结果一旦被削，字节里不再有任何随轮次变化的成分（标记已改固定串），
    因此只有「从最后一条滑出保护窗」的那一条会变，缓存中断点被限制在一处。

    环境变量 QD_TOOL_RESULT_SCOPE：
      tail（默认） 保护最后 QD_TOOL_RESULT_KEEP_TAIL 条（默认 1）
      all          全部削减（缓存最稳，但当轮长输出也会被截）
      turn         旧行为（当前轮全保，形态相关——仅兼容用）
    """
    scope = str(os.environ.get("QD_TOOL_RESULT_SCOPE") or "tail").strip().lower()
    if scope in ("all", "stable", "everything"):
        return "all", 0
    if scope in ("turn", "history", "legacy", "current"):
        return "turn", 0
    try:
        n = int(os.environ.get("QD_TOOL_RESULT_KEEP_TAIL") or 1)
    except Exception:
        n = 1
    return "tail", max(0, n)


def _current_turn_start(messages):
    """返回「当前轮」起始下标（索引 >= 它的 tool 结果不削减）。

    **仅 QD_TOOL_RESULT_SCOPE=turn 时使用**（issue #48：该规则随请求形态滑动，
    会让历史工具结果在不同轮次序列化成不同字节 -> 前缀缓存每轮失效）。

    判定：从末尾往前找最后一条 user/system/developer 消息——它开启当前回合，
    其后的一切（assistant 工具调用 + tool 结果）都属于当前轮。找不到则返回 0
    （全部视为当前轮：宁可不削，也不误削模型正在用的结果）。
    """
    msgs = messages or []
    for i in range(len(msgs) - 1, -1, -1):
        m = msgs[i]
        if isinstance(m, dict) and m.get("role") in ("user", "system",
                                                    "developer"):
            return i + 1
    return 0


# ---------------------------------------------------------------------------
# 结构化工具历史（task-32：tool 消息 / assistant.tool_calls 原样透传）
# ---------------------------------------------------------------------------
# 依据 task-31 实测（.team/tiedan.md §17）：legacy 通道在 Qwen 全系 / GLM 上
# 接受结构化历史并被正确消费（含 3 轮链、结构化+旧文本信封混合、并行调用、
# id 不匹配）；DeepSeek / Kimi 在 assistant.content=null 时被拒，**content=""
# 即通过**。因此本实现恒用空字符串，绝不发 null。
STRUCTURED_TOOL_HISTORY_WHITELIST = ("qwen", "glm", "gm4", "gm5")
_STRUCTURED_LOG_ONCE = {"done": False}


def _structured_mode():
    """QD_STRUCTURED_TOOL_HISTORY 三态：'on' / 'off' / 'auto'（默认）。"""
    raw = (os.environ.get("QD_STRUCTURED_TOOL_HISTORY") or "").strip().lower()
    if not raw or raw == "auto":
        return "auto"
    if raw in ("1", "on", "true", "yes", "enable", "enabled", "force"):
        return "on"
    if raw in ("0", "off", "false", "no", "disable", "disabled"):
        return "off"
    return "auto"


def _tool_ids_ok(messages):
    """结构化前提：每条 tool 有 tool_call_id，每个 assistant.tool_calls 条目有 id。"""
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "tool":
            if not str(m.get("tool_call_id") or "").strip():
                return False
        elif role == "assistant" and m.get("tool_calls"):
            for tc in m["tool_calls"] or []:
                if not isinstance(tc, dict) \
                        or not str(tc.get("id") or "").strip():
                    return False
    return True


def structured_tool_history_enabled(model="", model_key="", realm="",
                                    messages=None):
    """本次请求是否走结构化工具历史。

    - off          -> False（一键回退文本化）
    - on           -> True（显式强制：DeepSeek / Kimi / INTL 补验证用）
    - auto（默认） -> 仅「CN 出口 + provider 白名单 + id 齐备」为真：
        task-31 实测只在 CN / legacy 通道覆盖过（INTL 超时未取得结果），
        故 auto 不在 INTL 启用；DeepSeek / Kimi 待补端到端验证，同样排除。
    任何模式下 id 不齐备都回退文本化（fail-safe：宁可少用，不发畸形请求）。
    """
    if not _tool_ids_ok(messages):
        return False
    mode = _structured_mode()
    if mode == "off":
        return False
    if mode == "on":
        return True
    if (realm or "") != "cn":
        return False
    for cand in (str(model_key or ""), str(model or "")):
        low = cand.strip().lower()
        if low and low.startswith(STRUCTURED_TOOL_HISTORY_WHITELIST):
            if not _STRUCTURED_LOG_ONCE["done"]:
                _STRUCTURED_LOG_ONCE["done"] = True
                log("structured tool history: ON (model=%s key=%s realm=%s)"
                    % (model, model_key, realm), tag="chat")
            return True
    return False


def flatten_messages(messages, keep_reasoning=False, structured=False):
    """把客户端会话压平成 Trae 上游可接受的 {role, content} 序列。

    返回 (system_text, flat_msgs, images)：
      - 首个 system/developer 消息抽为 system_text（模板 system 的替换源）
      - user/assistant 原位保留（content 压平为字符串）
      - tool 结果：structured=True 时保留 {role:"tool", tool_call_id, content}
        （content 恒为空字符串而非 null——task-31 实测 null 会让上游转换层丢掉
        配对的 assistant 消息，DeepSeek/Kimi 直接 provider_error）；
        否则降级为 user 文本（上游历史上不认识 tool 角色）
      - assistant 的 tool_calls：structured=True 时原样透传
        （id/type/function，arguments 统一为 JSON 字符串）；
        否则序列化进 content（LEAK_MARKER + JSON 数组）
      - assistant 的 reasoning_content 仅在 keep_reasoning=True（DeepSeek 族）
        时保留：这族模型的多轮一致性与该字段绑定，其它模型不带（避免上游
        因未知字段拒答）。此前 flatten 无条件丢弃该字段，使
        backfill_reasoning_content 的兼容处理在真实请求路径上完全失效。
    """
    system_text = None
    flat, images = [], []
    # 暴露面削减只作用于历史（当前轮的 tool 结果必须完整保留）。
    _keep = _tool_result_keep_chars()
    # issue #48：削减范围必须**与请求形态无关**。旧规则按「当前轮起点」滑动，
    # 用户每发一条消息就把全部历史工具结果重削一遍 -> 同一条消息在不同轮次
    # 序列化成不同字节 -> 上游前缀缓存整段失效（实测命中率 95%+ -> 8%）。
    # 新默认 tail：只保护最后 N 条工具结果，更早的一律削（且削后字节恒定）。
    _scope, _tail_n = _tool_result_scope()
    _protect = set()
    if _keep:
        if _scope == "turn":
            _protect = set(range(_current_turn_start(messages) or 0,
                                 len(messages or [])))
        elif _scope == "tail" and _tail_n > 0:
            _tool_idx = [i for i, m in enumerate(messages or [])
                         if isinstance(m, dict) and m.get("role") == "tool"]
            _protect = set(_tool_idx[-_tail_n:])
    for _idx, m in enumerate(messages or []):
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        text, imgs = _flatten_content_text(m.get("content"))
        images.extend(imgs)
        text = sanitize_text(text) if isinstance(text, str) else text
        if role in ("system", "developer"):
            if system_text is None and text:
                system_text = text
            continue
        if role == "tool":
            name = ""
            tc = m.get("name") or ""
            if tc:
                name = " (%s)" % tc
            body = text or ""
            if _keep and _idx not in _protect:
                body = _shrink_tool_result(body, _keep)
            if structured:
                # 结构化直传：保留 tool 角色与配对 id；content 用空字符串而非
                # null（task-31：null 会让上游丢掉配对的 assistant 消息）。
                flat.append({"role": "tool",
                             "tool_call_id": str(m.get("tool_call_id") or ""),
                             "content": body})
                continue
            flat.append({"role": "user",
                         # 前缀逐字节不变（TOOL_RESULT_MARKER + name + "]\n"）；
                         # 削减只发生在正文部分。
                         "content": TOOL_RESULT_MARKER + name + "]\n" + body})
            continue
        if role == "assistant" and m.get("tool_calls"):
            if structured:
                # 结构化直传：保 id/type/function；content 恒为空字符串。
                # arguments 统一成 JSON 字符串（OpenAI 规范形态；dict 会被
                # 客户端/上游两侧的转换层按字符串处理，字符串最稳）。
                calls = []
                for tc in m["tool_calls"]:
                    tc = tc if isinstance(tc, dict) else {}
                    fn = tc.get("function") or {}
                    args = fn.get("arguments")
                    if isinstance(args, (dict, list)):
                        args = json.dumps(args, ensure_ascii=False)
                    elif not isinstance(args, str):
                        args = "" if args is None else str(args)
                    calls.append({"id": str(tc.get("id") or ""),
                                  "type": tc.get("type") or "function",
                                  "function": {"name": fn.get("name") or "",
                                               "arguments": args}})
                item = {"role": "assistant", "content": text or "",
                        "tool_calls": calls}
                if keep_reasoning and m.get("reasoning_content") is not None:
                    item["reasoning_content"] = m.get("reasoning_content") or ""
                flat.append(item)
                continue
            calls = []
            for tc in m["tool_calls"]:
                fn = (tc or {}).get("function") or {}
                calls.append({"name": fn.get("name") or "",
                              "arguments": fn.get("arguments") or ""})
            if calls:
                text = (text or "") + "\n\n" + LEAK_MARKER + "\n" + \
                    json.dumps(calls, ensure_ascii=False)
            item = {"role": "assistant", "content": text or ""}
            if keep_reasoning and m.get("reasoning_content") is not None:
                item["reasoning_content"] = m.get("reasoning_content") or ""
            flat.append(item)
            continue
        if role in ("user", "assistant"):
            if imgs:
                # 上游只读消息 content 里的结构化 image_url parts，**不读**
                # 顶层 image_urls / chat_context.imageUrls（实测：image_urls
                # 填了模型仍回「我没有收到图片」，改 parts 后正确识别颜色）。
                # 带图消息保留 parts 形态；顶层 image_urls 仍照填（兼容无害）。
                _parts = _flatten_content(m.get("content"))
                item = {"role": role,
                        "content": _parts if isinstance(_parts, list)
                        else (text or "")}
            else:
                item = {"role": role, "content": text or ""}
            if role == "assistant" and keep_reasoning \
                    and m.get("reasoning_content") is not None:
                item["reasoning_content"] = m.get("reasoning_content") or ""
            flat.append(item)
        elif role:  # 未知角色一律降级为 user，不静默丢弃
            flat.append({"role": "user", "content": text or ""})
    return system_text, flat, images


# ---------------------------------------------------------------------------
# Trae 协议层：区域 / 鉴权 / 工具标记 / 事件解析 / 用量 / 错误映射
#
# 本段是数据面的**唯一上游适配层**。trae_client 存在时转发给它（协议客户端
# 由 doudou 维护），缺失时用同签名的内置实现，保证网关可独立闭环。
# ---------------------------------------------------------------------------
TRAE_LOGIN_CLIENT_ID = "ono9krqynydwx5"
TRAE_DEVICE_HEADERS = os.environ.get(
    "TRAE_DEVICE_HEADERS", "0").strip().lower() in ("1", "true", "yes", "on")


def _account_view(account):
    """账号对象 -> 协议层要的映射形态（trae_client 全系列只吃 dict）。

    Account 走 to_desktop_dict()（含 token/refreshToken/host/userRegion），
    裸 dict 原样返回；其它对象退化为属性字典。
    """
    if account is None:
        return {}
    if isinstance(account, dict):
        return account
    for name in ("to_desktop_dict", "to_dict"):
        fn = getattr(account, name, None)
        if callable(fn):
            try:
                out = fn()
                if isinstance(out, dict):
                    return out
            except Exception:
                pass
    try:
        return dict(vars(account))
    except Exception:
        return {}


def account_token(account):
    """access token（账号域字段叫 token；兼容旧 access_token/accessToken）。"""
    for key in ("token", "access_token", "accessToken", "ide_token"):
        value = getattr(account, key, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if isinstance(account, dict):
        for key in ("token", "access_token", "accessToken"):
            value = account.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def account_label(account):
    """账号展示名：绝不假设 nickname 存在（账号域重构后已无该字段）。"""
    if account is None:
        return ""
    for key in ("display_name", "nickname", "name", "email"):
        value = getattr(account, key, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    profile = getattr(account, "account", None)
    if isinstance(profile, dict):
        for key in ("username", "email"):
            value = profile.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    uid = str(getattr(account, "uid", "") or "")
    return uid[:8]


def trae_realm(value):
    """区域名归一：只认 cn / intl，未知一律回落到当前默认区。"""
    v = str(value or "").strip().lower()
    if v in TRAE_REALMS:
        return v
    if v in ("us", "sg", "global", "international"):
        return "intl"
    return CURRENT_REALM if CURRENT_REALM in TRAE_REALMS else "cn"


def trae_realm_config(realm):
    return TRAE_REALMS.get(trae_realm(realm)) or TRAE_REALMS["cn"]


def trae_core_candidates(realm):
    """该区域的推理主机候选：主选 + 官方备用（协议 §一）。

    换主机只影响传输层，鉴权头与请求体与主机无关，因此故障切换很便宜。
    """
    cfg = trae_realm_config(realm)
    out = [cfg["core"]]
    for host in cfg.get("core_fallbacks") or ():
        if host and host not in out:
            out.append(host)
    return out


def trae_auth_headers(account, realm, sse=True, extra=None):
    """IDE 数据面鉴权头（PROTOCOL §二）。

    实测（.recon/probe_cn_chat.py -> cn_chat_stream.txt）证明「最小集」即可
    正常对话：X-App-Id / x-plugin-channel / x-ide-version-code / x-ide-token /
    Authorization / Content-Type / Accept / User-Agent。
    设备头（X-Device-*）默认不发：国际版风控成因排查已排除设备头（§11.4），
    而多发未验证的头反而可能改变风控判定。需要时用 TRAE_DEVICE_HEADERS=1 打开。
    """
    if _trae_client is not None and hasattr(_trae_client, "auth_headers"):
        try:
            headers = dict(_trae_client.auth_headers(
                _account_view(account), trae_realm(realm)))
            if extra:
                headers.update(extra)
            return headers
        except Exception as exc:      # 协议客户端内部异常不得打死数据面
            log("trae_client.auth_headers failed (%s) - falling back"
                % str(exc)[:120], level="WARN", tag="chat")
    cfg = trae_realm_config(realm)
    token = account_token(account)
    headers = {
        "X-App-Id": TRAE_APP_ID,
        "x-plugin-channel": TRAE_PLUGIN_CHANNEL,
        "x-ide-version-code": str(cfg.get("version_code") or "20260212"),
        "x-ide-token": token,
        "Authorization": "Cloud-IDE-JWT " + token,
        "Content-Type": "application/json",
        "Accept": "text/event-stream" if sse else "application/json",
        "User-Agent": cfg.get("ua") or CLIENT_UA,
    }
    uid = str(getattr(account, "uid", "") or "")
    if TRAE_DEVICE_HEADERS and uid:
        try:
            headers["X-Device-Id"] = uid
            headers["X-Machine-Id"] = trae_fingerprint.derive_id(uid, "machine")
            headers["X-Device-Type"] = "windows"
        except Exception:
            pass
    if extra:
        headers.update(extra)
    return headers


def trae_open_chat(account, realm, body, host=None, timeout=600):
    """打开一次 llm_raw_chat（始终流式返回 SSE，协议 §六）。"""
    realm = trae_realm(realm)
    if _trae_client is not None and hasattr(_trae_client, "open_chat") \
            and host is None:
        try:
            return _trae_client.open_chat(_account_view(account), realm, body,
                                          timeout=timeout)
        except TypeError:
            # 协议签名差异（位置参数版）：按 §十 的定义再试一次
            return _trae_client.open_chat(_account_view(account), realm, body,
                                          timeout)
    cfg = trae_realm_config(realm)
    url = validate_public_http_url(
        (host or cfg["core"]).rstrip("/") + TRAE_CHAT_PATH)
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers=trae_auth_headers(account, realm, sse=True))
    return urllib.request.urlopen(req, timeout=timeout)


def trae_exc_code_detail(exc):
    """把上游异常统一成 (http_code, detail)。

    三种来源：
      · urllib.error.HTTPError     -> (exc.code, 已读详情)
      · trae_client.UpstreamError  -> 业务码经 TRAE_ERROR_MAP 映射成 HTTP 语义
      · 其它传输异常               -> (502, 文本)
    """
    if isinstance(exc, urllib.error.HTTPError):
        detail = getattr(exc, "trae_detail", "") or \
            getattr(exc, "trae_detail", "") or getattr(exc, "qoder_detail", "")
        return int(exc.code), detail or ""
    code = getattr(exc, "code", None)
    status = getattr(exc, "status", None)
    message = getattr(exc, "message", "") or str(exc)
    if isinstance(code, int) and code in TRAE_ERROR_MAP:
        http_status, kind = TRAE_ERROR_MAP[code]
        return http_status, "trae %s %s: %s" % (code, kind,
                                                str(message)[:300])
    if isinstance(status, int) and status >= 400:
        return status, str(message)[:400]
    if isinstance(code, int) and 400 <= code < 600:
        return code, str(message)[:400]
    return 502, str(message)[:400]


# 客户端自身参数问题（换号/重试都解决不了）：快速失败
TRAE_CLIENT_FAULT_CODES = (4001, 4023)


class SlottedResponse(object):
    """上游响应代理：持有账号并发槽，close 时释放。

    slot() 必须在**整条流**期间生效（否则并发上限形同虚设），而
    open_upstream 只负责开流：用响应代理把生命周期接起来，close() 幂等，
    with resp / resp.close() / 异常路径都能正确释放。
    """

    def __init__(self, resp, account):
        self._resp = resp
        self._account = account
        self._released = False

    def __getattr__(self, name):
        return getattr(self._resp, name)

    def __iter__(self):
        return iter(self._resp)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def release(self):
        if self._released:
            return
        self._released = True
        try:
            self._account.release_inflight()
        except Exception:
            pass

    def close(self):
        self.release()
        try:
            self._resp.close()
        except Exception:
            pass

    @property
    def closed(self):
        return getattr(self._resp, "closed", False)


def trae_hold_slot(account, resp):
    """开流成功后占槽（生命周期由响应代理负责释放）。"""
    if account is None or resp is None:
        return resp
    if not hasattr(account, "add_inflight"):
        return resp
    try:
        account.add_inflight()
    except Exception:
        return resp
    return SlottedResponse(resp, account)


# 刷新失败冷却：失败后 10 分钟内不再尝试（避免 INTL 这类必失败场景
# 每 1-2 秒打一次 ExchangeToken）。内存态即可，重启清零。
TRAE_REFRESH_FAIL_COOLDOWN = float(
    os.environ.get("TRAE_REFRESH_FAIL_COOLDOWN", "600") or 600)
_REFRESH_GUARD_LOCK = threading.Lock()
_REFRESH_FAILED_UNTIL = {}


def _refresh_blocked(uid, now=None):
    with _REFRESH_GUARD_LOCK:
        return _REFRESH_FAILED_UNTIL.get(str(uid or ""), 0.0) > \
            (now or time.time())


def _note_refresh_failure(uid, seconds=None):
    until = time.time() + float(
        TRAE_REFRESH_FAIL_COOLDOWN if seconds is None else seconds)
    with _REFRESH_GUARD_LOCK:
        _REFRESH_FAILED_UNTIL[str(uid or "")] = until


def _clear_refresh_failure(uid):
    with _REFRESH_GUARD_LOCK:
        _REFRESH_FAILED_UNTIL.pop(str(uid or ""), None)


def trae_token_expired(account, skew=120):
    """token 是否已过期/临近过期（账号域给了 expired_at 就信它）。"""
    if account is None:
        return True
    fn = getattr(account, "token_expired", None)
    if callable(fn):
        try:
            return bool(fn(skew=skew))
        except Exception:
            pass
    expires = getattr(account, "expired_at", 0) or 0
    try:
        return bool(expires) and float(expires) <= time.time() + skew
    except (TypeError, ValueError):
        return False


def trae_refresh_account(account, realm=None, force=False):
    """刷新 access token（账号域优先，PROTOCOL §五 ExchangeToken）。

    返回 True = 拿到**新** token（调用方可原地重试）；False = 交给换号逻辑。
    绝不打印 token 内容，只记录长度。
    """
    if account is None:
        return False
    uid = str(getattr(account, "uid", "") or "")
    if _refresh_blocked(uid):
        # 失败冷却期（默认 10min）：绝不在冷却里反复打 ExchangeToken
        return False
    # 只有「鉴权失败」这类显式信号（force=True）或 token 真过期才刷新
    if not force and not trae_token_expired(account):
        return False
    before = account_token(account)

    # 0) 桌面端优先：桌面端可能刚刷新过；先读 storage.json，避免用旧
    #    refreshToken 再轮换一次（那会把桌面端踢下线）。
    if _trae_client is not None and hasattr(_trae_client, "reload_desktop_auth"):
        try:
            fresh = _trae_client.reload_desktop_auth(_account_view(account),
                                                    realm or getattr(account, "realm", None))
        except Exception as exc:
            fresh = None
            log("desktop token reload skipped: %s" % str(exc)[:120],
                level="WARN", tag="chat")
        if isinstance(fresh, dict) and fresh.get("token") \
                and fresh.get("token") != before:
            try:
                normalized = trae_accounts.normalize_refresh_result(fresh)
                apply = getattr(account, "apply_refresh_result", None)
                if callable(apply):
                    apply(normalized)
                else:
                    account.token = normalized["token"]
                    account.save()
                _clear_refresh_failure(uid)
                log("token reloaded from desktop storage for %s (len=%d)"
                    % (uid[:8], len(account_token(account))), tag="chat")
                return True
            except Exception as exc:
                log("desktop token apply failed: %s" % str(exc)[:120],
                    level="WARN", tag="chat")

    # 1) 账号域自带刷新（轮换回写 + 原子落盘都在 trae_accounts 里）
    #
    # 关键：账号域只要**提供**了刷新能力，就是本次刷新的唯一出口 —— 失败后
    # 绝不再串行去打 trae_client / 内置 ExchangeToken。否则一个坏账号会一次
    # 请求打三次上游（日志刷屏 + 风控升级，实测踩过）。
    domain_attempted = False
    for name in ("ensure_fresh", "refresh"):
        fn = getattr(account, name, None)
        if not callable(fn):
            continue
        domain_attempted = True
        try:
            fn()
        except Exception as exc:
            log("%s failed for account %s: %s"
                % (name, uid[:8], str(exc)[:140]), level="WARN", tag="chat")
        after = account_token(account)
        if after and after != before:
            _clear_refresh_failure(uid)
            log("token refreshed via account.%s for %s (len=%d)"
                % (name, uid[:8], len(after)), tag="chat")
            return True
        break
    if domain_attempted:
        _note_refresh_failure(uid)
        return False

    # 2) 协议客户端直连刷新（账号域没有可用实现时）
    if _trae_client is not None and hasattr(_trae_client, "refresh_account"):
        try:
            result = _trae_client.refresh_account(_account_view(account))
        except Exception as exc:
            log("trae_client.refresh_account failed: %s" % str(exc)[:140],
                level="WARN", tag="chat")
            _note_refresh_failure(uid)
            result = None
        if isinstance(result, dict):
            token = result.get("token") or result.get("Token") or ""
            if token:
                apply = getattr(account, "apply_refresh_result", None)
                try:
                    if callable(apply):
                        apply(result)
                    else:
                        setattr(account, "token", str(token))
                except Exception as exc:
                    log("refresh write-back failed: %s" % str(exc)[:120],
                        level="WARN", tag="chat")
                    return False
                after = account_token(account)
                _clear_refresh_failure(uid)
                log("token refreshed via trae_client for %s (len=%d)"
                    % (uid[:8], len(after)), tag="chat")
                return bool(after) and after != before

    # 3) 内置 ExchangeToken 兜底（无账号域、无协议客户端时）
    realm = trae_realm(realm or getattr(account, "realm", CURRENT_REALM))
    cfg = trae_realm_config(realm)
    refresh_token = str(getattr(account, "refresh_token", "") or "")
    if not refresh_token:
        return False
    url = cfg["account"].rstrip("/") + \
        "/cloudide/api/v3/trae/oauth/ExchangeToken"
    body = json.dumps({
        "ClientID": TRAE_LOGIN_CLIENT_ID,
        "RefreshToken": refresh_token,
        "ClientSecret": "-",
        "UserID": "",
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            validate_public_http_url(url), data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "application/json",
                     "User-Agent": cfg.get("ua") or CLIENT_UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            doc = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        _note_refresh_failure(uid)
        log("token refresh failed for account %s: %s"
            % (uid[:8], str(exc)[:140]), level="WARN", tag="chat")
        return False
    result = doc.get("Result") or doc.get("result") or {}
    if not isinstance(result, dict):
        return False
    token = result.get("Token") or result.get("token")
    if not token:
        return False
    if hasattr(account, "token"):
        account.token = str(token)
    else:
        try:
            account.access_token = str(token)
        except Exception:
            pass
    rotated = result.get("RefreshToken") or result.get("refreshToken")
    if rotated and hasattr(account, "refresh_token"):
        account.refresh_token = str(rotated)      # 轮换式，必须回写
    try:
        save = getattr(account, "save", None)
        if callable(save):
            save()
    except Exception as exc:
        log("token persist failed for account %s: %s"
            % (str(getattr(account, "uid", ""))[:8], str(exc)[:120]),
            level="WARN")
    log("token refreshed (embedded ExchangeToken) for %s (len=%d)"
        % (str(getattr(account, "uid", ""))[:8], len(str(token))), tag="chat")
    return True


# ---- 上游错误码映射（PROTOCOL §六 / §11.4）--------------------------------
TRAE_ERROR_MAP = {
    1001: (401, "auth"),             # 鉴权失败 -> 刷新 token / 换号
    4001: (400, "invalid_request"),  # 参数非法 -> 直接回客户端，不重试
    3003: (502, "prompt_pipeline"),
    4015: (403, "risk_control"),     # 国际版账号/出口风控 -> 冷却换号
    4019: (403, "risk_control"),
    4008: (429, "quota_exceeded"),   # 免费额度用尽，不是 4015 风控
    4023: (400, "model_unknown"),    # 模型未知 -> 用 model_list 的 name
}


def trae_error_status(code, message="", error=""):
    """Trae 错误码 -> (http_status, detail, kind)。

    detail 里带 kind 与原始文案：上层（friendly_upstream_error /
    _handle_envelope_account_cooldown）据此决定「换号 / 不重试 / 冷却」。
    """
    try:
        code_i = int(code)
    except (TypeError, ValueError):
        code_i = 0
    status, kind = TRAE_ERROR_MAP.get(code_i, (502, "upstream_error"))
    text = (str(message or "").strip() or str(error or "").strip())
    detail = "trae %s %s: %s" % (code_i or "?", kind,
                                 text[:300] or "(no upstream message)")
    return status, detail, kind


# ---- 用量归一 -------------------------------------------------------------
def trae_usage_to_openai(usage):
    """Trae token_usage -> OpenAI usage（标准三字段 + details），原始字段保留。"""
    u = usage if isinstance(usage, dict) else {}

    def _i(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    prompt = _i(u.get("prompt_tokens"))
    completion = _i(u.get("completion_tokens"))
    total = _i(u.get("total_tokens")) or (prompt + completion)
    cache_read = _i(u.get("cache_read_input_tokens"))
    cache_write = _i(u.get("cache_creation_input_tokens"))
    reasoning = _i(u.get("reasoning_tokens"))
    out = {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "prompt_tokens_details": {"cached_tokens": cache_read},
        "completion_tokens_details": {"reasoning_tokens": reasoning},
        # 面板/记账直接可用的 Trae 原生口径
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_write,
    }
    for k, v in u.items():
        out.setdefault(k, v)
    return out


# ---- 工具标记协议（PROTOCOL §七）------------------------------------------
TRAE_TOOL_BEGIN = "<|FunctionCallBegin|>"
TRAE_TOOL_END = "<|FunctionCallEnd|>"
TRAE_TOOL_MAX_BUFFER = 256 * 1024

TRAE_TOOL_SYSTEM_TEMPLATE = (
    "你可以调用工具。需要调用工具时，**只**输出下面这一种格式，"
    "不要输出任何解释、前后缀或 markdown 代码块：\n"
    "%s[{\"name\":\"工具名\",\"parameters\":{...}}]%s\n"
    "可以一次输出多个调用（JSON 数组）。不需要调用工具时正常回答。\n"
    "可用工具（JSON Schema）：\n%s"
)


def trae_tool_specs(tools):
    """客户端 tools -> [{name, description, parameters}]（兼容嵌套/平铺两种）。"""
    specs = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        fn = t.get("function") if isinstance(t.get("function"), dict) else t
        name = str(fn.get("name") or "").strip()
        if not name:
            continue
        params = fn.get("parameters")
        if not isinstance(params, dict):
            params = {"type": "object", "properties": {}}
        specs.append({
            "name": name,
            "description": str(fn.get("description") or "")[:500],
            "parameters": params,
        })
    return specs


def tools_system_prompt(tools):
    """把工具 schema 变成 system 注入文本；无工具返回 ""。"""
    specs = trae_tool_specs(tools)
    if not specs:
        return ""
    try:
        blob = json.dumps(specs, ensure_ascii=False)
    except Exception:
        return ""
    return TRAE_TOOL_SYSTEM_TEMPLATE % (TRAE_TOOL_BEGIN, TRAE_TOOL_END, blob)


def _trae_normalise_calls(raw, allowed_names=None):
    """工具调用的统一形态 -> [{name, arguments(JSON 字符串)}]；认不出返回 None。

    接受：JSON 数组 / 单个对象 / {"calls":[...]} / {"tool_calls":[...]}；
    参数键接受 parameters / arguments / input / args，嵌套 function 子对象也算。
    任一调用缺名字或名字不在 allowed_names 内 -> None（交由调用方 fail-open）。
    """
    if isinstance(raw, dict):
        for key in ("calls", "tool_calls", "function_calls"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
        else:
            raw = [raw]
    if not isinstance(raw, list) or not raw:
        return None
    calls = []
    for item in raw:
        if not isinstance(item, dict):
            return None
        fn = item.get("function") if isinstance(item.get("function"), dict) else {}
        name = str(item.get("name") or item.get("tool")
                   or item.get("tool_name") or fn.get("name") or "").strip()
        if not name:
            return None
        args = None
        for key in ("parameters", "arguments", "input", "args"):
            if key in item and item[key] is not None:
                args = item[key]
                break
        if args is None:
            args = fn.get("arguments")
        if isinstance(args, str):
            text = args.strip() or "{}"
        elif args is None:
            text = "{}"
        else:
            try:
                text = json.dumps(args, ensure_ascii=False)
            except Exception:
                return None
        if allowed_names and name not in allowed_names:
            return None
        calls.append({"name": name, "arguments": text})
    return calls or None


def _trae_parse_call_payload(payload, allowed_names=None):
    """标记内部的 JSON 文本 -> calls（失败返回 None，调用方 fail-open）。"""
    text = _strip_json_fence((payload or "").strip())
    if not text:
        return None
    try:
        obj = json.loads(text)
    except Exception:
        return None
    return _trae_normalise_calls(obj, allowed_names)


def convert_tool_markers(text, allowed_names=None):
    """非流式：从完整正文里剥出工具标记。返回 (干净正文, calls)。

    calls = [{"name": str, "arguments": str}]（OpenAI tool_calls 的 function 形态）。
    规则（PROTOCOL §七.4 fail-open）：
      · 标记完整且 JSON 合法 -> 转 calls，正文里不留标记
      · JSON 坏 / 名字不认识 / 未闭合 -> 原样保留在正文里，一个字都不吞
    """
    text = text or ""
    if TRAE_TOOL_BEGIN not in text:
        return text, []
    out, calls = [], []
    rest = text
    while True:
        i = rest.find(TRAE_TOOL_BEGIN)
        if i < 0:
            out.append(rest)
            break
        out.append(rest[:i])
        j = rest.find(TRAE_TOOL_END, i + len(TRAE_TOOL_BEGIN))
        if j < 0:
            out.append(rest[i:])          # 未闭合：按原样留着（fail-open）
            break
        payload = rest[i + len(TRAE_TOOL_BEGIN):j]
        parsed = _trae_parse_call_payload(payload, allowed_names)
        if parsed:
            calls.extend(parsed)
        else:
            out.append(rest[i:j + len(TRAE_TOOL_END)])
        rest = rest[j + len(TRAE_TOOL_END):]
    return "".join(out), calls


def _trae_marker_prefix_hold(buf):
    """buf 末尾有多少字符可能是标记的前缀（跨 chunk 切断时必须留住）。"""
    limit = min(len(buf), len(TRAE_TOOL_BEGIN) - 1)
    for k in range(limit, 0, -1):
        if TRAE_TOOL_BEGIN.startswith(buf[-k:]):
            return k
    return 0


class ToolMarkerStream(object):
    """流式工具标记状态机（跨 chunk 缓冲，PROTOCOL §11.1）。

    用法：
        st = ToolMarkerStream(allowed_names={"get_weather"})
        st.feed("<|Func")     -> []            # 标记被切断：先缓冲，不吐正文
        st.feed("tionCallBegin|>[{\"na") -> []
        st.feed("me\":\"get_weather\",\"parameters\":{}}]<|FunctionCallEnd|>")
        -> [{"tool_calls": [{"index": 0, "id": "call_..", "type": "function",
                             "function": {"name": "get_weather",
                                          "arguments": "{}"}}]}]
        st.flush()            -> []            # 收尾（未闭合块原样吐回）

    feed/flush 产出的是 **OpenAI delta 片段**：
        {"content": "..."} 或 {"tool_calls": [...]}
    正文顺序与工具标记的相对位置均保持不变；解析失败一律 fail-open
    （把 BEGIN+payload+END 原样当正文吐出，绝不吞内容）。
    """

    def __init__(self, allowed_names=None):
        self.allowed = set(allowed_names) if allowed_names else None
        self.buf = ""
        self.in_call = False
        self.emitted = 0
        self.failed = 0

    def calls_delta(self, parsed):
        tcs = []
        for call in parsed:
            tcs.append({
                "index": self.emitted,
                "id": _new_id("call_"),
                "type": "function",
                "function": {"name": call["name"],
                             "arguments": call["arguments"]},
            })
            self.emitted += 1
        return {"tool_calls": tcs}

    def feed(self, text):
        if text:
            self.buf += text
        return self._drain()

    def _drain(self):
        out = []
        while True:
            if not self.in_call:
                i = self.buf.find(TRAE_TOOL_BEGIN)
                if i < 0:
                    hold = _trae_marker_prefix_hold(self.buf)
                    cut = len(self.buf) - hold
                    if cut > 0:
                        out.append({"content": self.buf[:cut]})
                        self.buf = self.buf[cut:]
                    break
                if i > 0:
                    out.append({"content": self.buf[:i]})
                    self.buf = self.buf[i:]
                self.buf = self.buf[len(TRAE_TOOL_BEGIN):]
                self.in_call = True
                continue
            j = self.buf.find(TRAE_TOOL_END)
            if j < 0:
                if len(self.buf) > TRAE_TOOL_MAX_BUFFER:
                    # 病态超长未闭合块：原样吐回，避免内容被困死在缓冲里
                    out.append({"content": TRAE_TOOL_BEGIN + self.buf})
                    self.buf = ""
                    self.in_call = False
                    self.failed += 1
                break
            payload = self.buf[:j]
            self.buf = self.buf[j + len(TRAE_TOOL_END):]
            self.in_call = False
            parsed = _trae_parse_call_payload(payload, self.allowed)
            if parsed:
                out.append(self.calls_delta(parsed))
            else:
                self.failed += 1
                out.append({"content": TRAE_TOOL_BEGIN + payload
                            + TRAE_TOOL_END})
        return out

    def flush(self):
        out = []
        if self.in_call:
            out.append({"content": TRAE_TOOL_BEGIN + self.buf})
        elif self.buf:
            out.append({"content": self.buf})
        self.buf = ""
        self.in_call = False
        return out


# ---- 上游 SSE 事件解析（PROTOCOL §六）--------------------------------------
def _trae_json_or_none(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def iter_trae_events(resp):
    """把上游 SSE 字节流解析成 (event, data)。

    帧形态（实测，见 .recon/cn_chat_stream.txt）：
        event: metadata  / data: {...}
        event: output    / data: {"response","reasoning_content","tool_calls","phase"}
        event: token_usage / data: {...}
        event: done      / data: {"finish_reason":"stop"}
        event: error     / data: {"code":4023,"error":"","message":"..."}
    容错：缺 event 名按 "message"；非 JSON 的 data 跳过；多行 data 合并。
    """
    event = ""
    data_lines = []
    for raw in resp:
        if isinstance(raw, bytes):
            line = raw.decode("utf-8", "replace")
        else:
            line = str(raw)
        line = line.rstrip("\r\n")
        if not line:
            if data_lines:
                payload = _trae_json_or_none("\n".join(data_lines))
                if payload is not None:
                    yield (event or "message", payload)
            event, data_lines = "", []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        payload = _trae_json_or_none("\n".join(data_lines))
        if payload is not None:
            yield (event or "message", payload)


def build_trae_body(payload, account=None, model_key=None, realm=None):
    """构造 /api/ide/v1/llm_raw_chat 请求体。

    实测约束（.recon/probe_body_schema.py / probe_body2.py）：
      · messages[].content **必须是 parts 数组** —— 纯字符串直接 400；
      · 模型名走 model_name，错模型返回 HTTP200 + event:error(4023)；
      · stream:false 也仍返回 SSE，因此恒发 stream=True 由网关聚合；
      · 额外字段（tools / parameters / temperature）不报错；
      · image_url part 与 role:"tool" 历史均被接受（§11.2）。
    """
    realm = trae_realm(realm or getattr(account, "realm", CURRENT_REALM))
    model = str(payload.get("model") or "")
    messages = normalize_roles(payload.get("messages") or [])
    messages = sanitize_messages(messages)
    messages = backfill_reasoning_content(messages, model, model_key)

    # Trae raw chat 没有结构化 tool 协议：历史一律走文本化（structured=False），
    # 由 LEAK_MARKER / TOOL_RESULT_MARKER 承载，回读守卫照常工作。
    system_text, flat, images = flatten_messages(
        messages, keep_reasoning=is_deepseek_model(model, model_key),
        structured=False)

    system_parts = []
    if system_text:
        system_parts.append(system_text)
    elif SYSTEM_PROMPT and SYSTEM_PROMPT != DEFAULT_SYSTEM_PROMPT:
        system_parts.append(SYSTEM_PROMPT)
    tool_prompt = tools_system_prompt(payload.get("tools"))
    if tool_prompt:
        system_parts.append(tool_prompt)

    out = []
    if system_parts:
        out.append({"role": "system",
                    "content": [{"type": "text",
                                 "text": "\n\n".join(system_parts)}]})
    for m in flat:
        item = _trae_message(m)
        if item is not None:
            out.append(item)
    if not out:
        # 上游对空 messages 的拒绝方式不可读：显式兜一个最小轮次
        out.append({"role": "user",
                    "content": [{"type": "text", "text": "hi"}]})

    body = {
        "model_name": model_key or model,
        "messages": out,
        "stream": True,
    }
    params = {}
    max_tokens = payload.get("max_tokens") or payload.get("max_completion_tokens")
    if max_tokens:
        try:
            params["max_tokens"] = int(max_tokens)
        except (TypeError, ValueError):
            pass
    effort = requested_effort(payload)
    if effort:
        catalog_meta = catalog_meta_for(model_key or model, realm)
        norm, note = normalize_reasoning_effort(effort, catalog_meta)
        if note:
            log("reasoning_effort %s on '%s' (supported=%s)"
                % (note, model_key or model,
                   supported_efforts(catalog_meta)), tag="chat")
        if norm:
            # 官方客户端：内置 Trae 模型走 reasoning_effort_level（原生
            # light/high/extra_high），外部/自定义模型才走 reasoning_effort
            # （low/medium/high/xhigh）。这里按模型来源选字段。
            custom = bool(catalog_meta.get("provider")
                          or catalog_meta.get("config_source") not in (None, 1))
            if custom:
                params["reasoning_effort"] = norm
            else:
                params["reasoning_effort_level"] = norm
    for key in ("temperature", "top_p"):
        if payload.get(key) is not None:
            params[key] = payload[key]
    if payload.get("stop"):
        stop = payload["stop"]
        params["stop"] = stop if isinstance(stop, list) else [stop]
    if params:
        body["parameters"] = params
    return body


def _trae_message(message):
    """把 chat 形态消息转成 Trae parts 形态；空内容返回 None（不造幽灵轮次）。

    只保留 role / content / tool_call_id 三个上游认识的字段：
    reasoning_content 等额外键不发（raw chat 无此约定，发了只是噪音）。
    """
    if not isinstance(message, dict):
        return None
    role = str(message.get("role") or "user")
    if role not in ("system", "user", "assistant", "tool"):
        role = "user"
    parts = _trae_parts(message.get("content"), message.get("tool_calls"))
    if not parts:
        return None
    item = {"role": role, "content": parts}
    if role == "tool":
        # 上游接受 role:"tool"（§11.2），没有配对 id 时留空字符串
        item["tool_call_id"] = str(message.get("tool_call_id") or "")
        if message.get("name"):
            item["name"] = str(message["name"])
    return item


def _trae_parts(content, tool_calls=None):
    """content 任意形态 -> Trae parts 数组（text / image_url）。

    纯字符串会被上游 400，因此**任何**非空文本都要包成 text part。
    """
    parts = []
    if isinstance(content, str):
        if content.strip():
            parts.append({"type": "text", "text": content})
    elif isinstance(content, dict):
        parts.extend(_trae_parts([content]))
    elif isinstance(content, list):
        for piece in content:
            if isinstance(piece, str):
                if piece.strip():
                    parts.append({"type": "text", "text": piece})
                continue
            if not isinstance(piece, dict):
                continue
            ptype = piece.get("type") or ""
            if ptype in ("text", "input_text", "output_text"):
                text = piece.get("text")
                if isinstance(text, str) and text.strip():
                    parts.append({"type": "text", "text": text})
            elif ptype in ("image_url", "input_image", "image"):
                url = piece.get("image_url")
                if isinstance(url, dict):
                    url = url.get("url")
                if not url:
                    url = piece.get("url")
                if url:
                    # 实测 image_url part 被上游接受（probe_body2.py）
                    parts.append({"type": "image_url",
                                  "image_url": {"url": str(url)}})
    if not parts and tool_calls:
        # assistant 只带 tool_calls 时不能是空 content（上游 400），补空文本
        parts.append({"type": "text", "text": ""})
    return parts


# ---------------------------------------------------------------------------
# Trae 数据面：上游打开与 SSE 事件解包
# ---------------------------------------------------------------------------
class RateLimited(Exception):
    """Upstream throttled this request (429 / 频控)。"""

    def __init__(self, http_error=None, detail="", wait=60):
        self.http_error = http_error
        self.detail = detail or ""
        self.wait = max(1, int(wait or 60))
        super(RateLimited, self).__init__(
            "upstream rate limit: %s" % (self.detail[:200] or "429"))


# 账号级错误短冷却的“等待续上”上限：单账号池在传输/瞬时故障后只有
# 3s（多账号 15s）冷却，此时**等待**比报 429 更正确——429 只留给真正的
# 上游频控（model_cooldowns，由上游 HTTP 429 设置）。
ERROR_COOLDOWN_WAIT_MAX = 10.0


def _realm_ready_total(realm, model=None):
    """本区域当前可轮换的就绪账号数 —— **唯一口径**（#29 的成因就是两处口径分叉）。

    冷却函数曾用 len(POOL.accounts)（全局），open_upstream 用 count_ready(realm)。
    双区池（1 cn + 1 intl）下前者是 2、后者是 1，于是「本区域唯一账号」被当成
    多号池，single_account 判定反了 -> 冷却不再压到 3s。两处都必须走这里。
    """
    if not POOL or not realm:
        # 无池、或调用方给不出 realm（例如仅实现部分接口的测试桩对象）-> 保守 1
        # （= 单号池语义：冷却压短）。绝不因为「判不出区域」而误判成多号池。
        return 1
    try:
        return max(1, POOL.count_ready(realm, model=model))
    except Exception:
        return 1


def _short_error_cooldown_wait(realm, model, exclude=None):
    """账号级短冷却（含**预算内**的模型级频控窗）的最短剩余秒数；不适用返回 0。

    两条冷却来源**一起收集、取最小值**（#29 起）：
      · cooldown_until：账号级错误/传输冷却（原有语义）；
      · model_cooldowns[model]：**仅当剩余 <= ERROR_COOLDOWN_WAIT_MAX(10s)** 时纳入；
        超出预算的长频控仍交回 429 路径（客户端退避），不在这里吞掉。
    为什么不再短路：旧实现「遇到任一 model_cooldowns > now 就 return 0」，会让
    「号 A 长频控」连带把「号 B 只有 3s 可自愈」一起放弃（#29 的次生坑）。
    本函数**只决定等不等、不写任何冷却字段**，退避写者语义不变。
    已登记的语义变化：真 429 窗口 <=10s 时会被「等待 + 重试」，客户端收到
    延迟后的成功而不是 429（>10s 的行为不变）。
    - exclude（本请求已试过的账号）**不算**：等它冷却好了也不会再被本请求使用。
    """
    if not POOL:
        return 0.0
    exclude = exclude or set()
    now = time.time()
    waits = []
    for a in POOL.accounts:
        if a.realm != realm or not a.enabled or not a.access_token:
            continue
        if a.uid in exclude:
            continue
        m_remain = a.model_cooldowns.get(model, 0.0) - now
        if m_remain > 0:
            if m_remain <= ERROR_COOLDOWN_WAIT_MAX:
                waits.append(m_remain)      # 预算内的频控窗：值得等它过去
            continue                        # 超预算：跳过该号（别的号仍可纳入）
        remain = a.cooldown_until - now
        if 0 < remain <= ERROR_COOLDOWN_WAIT_MAX:
            waits.append(remain)
    return min(waits) if waits else 0.0


def retry_after_seconds(model, realm):
    """上游频控的最短等待（仅 model_cooldowns——429 的正当语义）。"""
    if not POOL:
        return 60
    now = time.time()
    waits = [a.model_cooldowns.get(model, 0.0) - now
             for a in POOL.accounts
             if a.realm == realm and a.enabled and a.access_token]
    active = [w for w in waits if w > 0]
    return int(min(active)) if active else 60


def realm_model_throttled(realm, model):
    """True 仅当该区域账号全部被**上游频控**（model_cooldowns）挡住。

    账号级错误冷却（cooldown_until）不算频控——否则传输故障后客户端会连续
    收到误导性的 `429 usage exceeds frequency limit`。
    """
    if not POOL:
        return (False, 0)
    existing = [a for a in POOL.accounts
                if a.realm == realm and a.enabled and a.access_token]
    if not existing:
        return (False, 0)
    now = time.time()
    waits = [a.model_cooldowns.get(model, 0.0) - now for a in existing]
    if waits and all(w > 0 for w in waits):
        return (True, max(1, int(min(waits))))
    return (False, 0)


def extract_session_key(headers, payload):
    key = (
        headers.get("X-Conversation-Id") or
        headers.get("Conversation-Id") or
        headers.get("X-Session-Id") or
        headers.get("Session-Id") or
        payload.get("conversation_id") or
        payload.get("session_id") or
        (payload.get("metadata") or {}).get("conversation_id")
    )
    if key:
        return str(key).strip()
    return None


# 上游瞬时故障（与客户端参数无关，值得同账号快速重试）
TRANSIENT_HTTP_CODES = (418, 500, 502, 503, 504)
TRANSIENT_MAX_RETRIES = 2          # 同账号额外重试次数（1s、2s 退避）

# issue #38：上游「排队」（403 + isQueued/10605 + retryAfterSeconds）时，
# 网关**等队列放行后重试**，而不是把排队 JSON 当错误交给客户端——客户端会把
# 它当成请求被拒（直接结束本轮）。三档都是可调的，默认值保守：
#   单轮最长等 QUEUE_WAIT_MAX_SECS；整次请求总预算 QUEUE_WAIT_BUDGET_SECS；
#   最多等 QUEUE_MAX_ROUNDS 轮。超出预算仍按原错误返回（fail-open 语义不变）。
QUEUE_MAX_ROUNDS = int(os.environ.get("QD_QUEUE_MAX_ROUNDS") or 3)
QUEUE_WAIT_MAX_SECS = int(os.environ.get("QD_QUEUE_WAIT_MAX_SECS") or 180)
QUEUE_WAIT_BUDGET_SECS = int(os.environ.get("QD_QUEUE_WAIT_BUDGET_SECS") or 300)


def _queue_wait_seconds(detail):
    """从上游 403/排队响应体里解析「等多久」；不是排队信号则返回 0。

    形如：{"code":"10605","message":"...","isQueued":true,
           "retryAfterSeconds":30}
    """
    d = detail or ""
    low = d.lower()
    if "10605" not in d and "isqueued" not in low and "queue" not in low:
        return 0
    m = re.search(r'retryAfterSeconds\D+(\d+)', d)
    if not m:
        return 30                       # 排队但没给时长：按 30s 保守处理
    try:
        return max(1, int(m.group(1)))
    except Exception:
        return 30
CHECKIN_MIN_GAP = 1.0              # 签到防风控：账号之间的最小间隔（秒）
_CLIENT_FAULT_MARKERS = (
    "invalid_parameter_error",     # 如 Range of max_tokens 校验失败
    "invalid_request_error",
    "authentication_error",
    "permission_error",
    '"Range of ',
    # 上游内容安全审核：确定性拒绝，重试无效（本轮日志实证
    # InternalError.Algo.DataInspectionFailed: Input text data may contain
    # inappropriate content.）
    "DataInspectionFailed",
    "inappropriate content",
    "input text data may contain",
    "ContentFilter",
    "SensitiveContent",
)

# 内容审核类错误（用户输入侧问题，需专门的中文解释）
_CONTENT_POLICY_MARKERS = (
    "DataInspectionFailed",
    "inappropriate content",
    "input text data may contain",
    "ContentFilter",
    "SensitiveContent",
)


def _is_transient_upstream(code, detail):
    """判断一次上游 HTTP 错误是否属于瞬时故障（可重试）。

    - 客户端参数/权限类错误（invalid_parameter_error 等）→ 永不重试
    - 418（上游把自己的 provider 故障包装成 418+provider_error）与 5xx → 瞬时
    - 其余 4xx 带 provider_error（"Error in upstream response"）→ 瞬时
    """
    detail = detail or ""
    if code in (401, 403, 429):
        return False        # 凭证/频控各自有专门处理路径，不属瞬时重试类
    if any(m in detail for m in _CLIENT_FAULT_MARKERS):
        return False
    if code in TRANSIENT_HTTP_CODES or code >= 500:
        return True
    if 400 <= code < 500 and "provider_error" in detail:
        return True
    return False


def _is_transient_transport(exc):
    """传输层瞬时故障（对上游域的 TLS/连接抖动很常见）：可同账号重试。

    覆盖 SSL EOF/重置、连接重置/中止、超时、以及 URLError 包装的上述原因
    （含按字符串描述判断的情形，如 "SSL: UNEXPECTED_EOF_WHILE_READING"）。
    """
    if isinstance(exc, urllib.error.URLError):
        return _is_transient_transport(getattr(exc, "reason", None))
    if isinstance(exc, (ssl.SSLError, ConnectionResetError,
                        ConnectionAbortedError, TimeoutError,
                        ConnectionError, OSError)):
        return True
    if isinstance(exc, str):
        low = exc.lower()
        return any(k in low for k in ("ssl", "eof", "reset", "timed out",
                                      "broken pipe", "connection"))
    return False


def friendly_upstream_error(code, detail):
    """把上游错误转成对客户端可读的消息；瞬时故障给出重试指引。

    返回 (message, err_type)。
    """
    detail = (detail or "").strip()
    try:
        code_i = int(code)
    except Exception:
        code_i = 502
    # 0) issue #37：工具参数非法（确定性、可重试但不是账号问题）
    if "invalid JSON arguments" in detail:
        return ("上游生成的工具调用参数不是合法 JSON，本轮**未执行任何工具**；"
                "网关已按协议返回失败，请重试该轮。上游详情：%s"
                % (detail[:200] or "(无详情)"),
                "invalid_tool_arguments")
    # 0.5) Trae 业务码（PROTOCOL §六）：给客户端可执行的中文说明
    if "4008" in detail or "exceeded the quota" in detail.lower():
        return ("Trae 免费额度已用尽（4008 quota exceeded）：等待额度恢复或升级套餐；"
                "这不是 4015 风控。上游详情：%s" % (detail[:240] or "(无详情)"),
                "quota_exceeded")
    if "risk_control" in detail:
        return ("上游风控命中（Trae 4015/4019：账号或出口地区限制）。网关已冷却"
                "该账号并换号；请使用与账号同区的出口、稍后重试或更换账号——"
                "原地重试不会解决。上游详情：%s" % (detail[:240] or "(无详情)"),
                "risk_control")
    if "trae 4023" in detail or "model_unknown" in detail:
        return ("上游不认识该模型（Trae 4023）。若 /v1/models 里该条 "
                "available=false / catalog_only=true，表示目录里有、但当前账号的 "
                "model_list 未返回它（套餐/账号未开通）；否则请检查 id 是否拼错。"
                "上游详情：%s" % (detail[:200] or "(无详情)"), "model_unknown")
    if "trae 4001" in detail or "invalid_request" in detail:
        return ("请求参数非法（Trae 4001）：检查 messages 的 parts 结构与模型名。"
                "上游详情：%s" % (detail[:200] or "(无详情)"),
                "invalid_request_error")
    if "trae 1001" in detail or " auth:" in detail:
        return ("上游鉴权失败（Trae 1001）：网关已尝试刷新 token 并换号；"
                "若持续出现请重新导入该账号凭证。上游详情：%s"
                % (detail[:200] or "(无详情)"), "authentication_error")
    # 1) 上游内容安全审核（确定性拒绝，先于瞬时判断——重试无效）
    if any(m in detail for m in _CONTENT_POLICY_MARKERS):
        return ("上游内容安全审核未通过 (DataInspectionFailed)：输入可能含不当内容，"
                "属确定性拒绝、重试无效。请检查/缩短输入（系统提示词、超长历史、"
                "工具定义或粘贴的代码/文本）后重试。上游详情：%s"
                % detail[:300],
                "content_policy_rejected")
    if _is_transient_upstream(code_i, detail) or (
            "provider_error" in detail and "invalid_" not in detail):
        return ("上游瞬时故障 (HTTP %s)：网关已对同账号自动重试仍失败，"
                "请稍后重试。上游详情：%s"
                % (code_i, detail[:300] or "(无详情)"),
                "upstream_transient_error")
    return ("upstream %s: %s" % (code_i, detail)), "upstream_error"


def _to_int_status(status):
    """信封 statusCodeValue 可能是 int 或 str，统一成 int（失败回 502）。"""
    try:
        return int(status)
    except Exception:
        return 502


def _handle_envelope_account_cooldown(account, exc, model=None, session_key=None):
    """信封层非 200（如 403 队列满/Token被拒、429 等）冷却该账号并解绑会话，触发下次选号轮换。"""
    detail = getattr(exc, "detail", "") or ""
    if "4008" in detail or "exceeded the quota" in detail.lower():
        return
    if isinstance(exc, InvalidToolArguments):
        # issue #37：坏参数是模型生成内容的问题，**不是账号不可用**——
        # 记录成账号冷却会让一个健康账号被无辜停用（还会解绑会话）。
        return
    if not account or not hasattr(account, "note_error"):
        return
    status_int = _to_int_status(getattr(exc, "status", 502))
    detail = getattr(exc, "detail", "") or ""
    if session_key and POOL:
        try:
            POOL.affinity.unbind(session_key)
        except Exception:
            pass
    # #29：口径必须与 open_upstream 一致 —— 用**本区域**就绪数，而不是全局账号数，
    # 否则双区池里本区域唯一账号会被当成多号池，冷却不压 3s。
    total = _realm_ready_total(getattr(account, "realm", "") or "", model)
    # 针对 10605 / retryAfterSeconds 解析冷却时长
    retry_secs = 30
    m = re.search(r'retryAfterSeconds\D+(\d+)', detail)
    if m:
        try:
            retry_secs = int(m.group(1))
        except Exception:
            pass
    if status_int == 429:
        actual = account.note_error("envelope 429", model=model,
                                    cooldown=retry_secs)
        log("account %s throttled via envelope (429), cooling for %.0fs "
            "(requested %ds, realm_ready=%d)"
            % (account.uid[:8], float(actual or 0), retry_secs, total),
            level="WARN", tag="chat")
    elif status_int in (401, 403):
        dead = trae_accounts.session_dead(detail)
        # 10605 排队冷却为模型级或账号级
        is_queue = "10605" in detail or "isQueued" in detail
        risk = "risk_control" in detail
        cd = 300 if dead else (retry_secs if is_queue else (120 if risk else 60))
        if "trae 1001" in detail or " auth:" in detail:
            # 鉴权失败：先尝试刷新 token（换号之前最省的一步）
            try:
                if trae_refresh_account(account, getattr(account, "realm", None),
                                        force=True):
                    log("account %s token refreshed after auth failure - "
                        "cooldown kept short" % account.uid[:8],
                        level="WARN", tag="chat")
                    cd = 15
            except Exception:
                pass
        actual = account.note_error("envelope HTTP %s: %s"
                                    % (status_int, detail[:80]),
                                    code=status_int, cooldown=cd,
                                    model=model if is_queue else None)
        if risk:
            log("account %s hit upstream RISK CONTROL (HTTP %s): cooling %.0fs "
                "and rotating - use a same-realm egress / another account, "
                "do not retry in place" % (account.uid[:8], status_int, cd),
                level="WARN", tag="chat")
        log("account %s rejected via envelope (HTTP %s, queue=%s), cooling for "
            "%.0fs (requested %ds, realm_ready=%d) and rotating"
            % (account.uid[:8], status_int, is_queue, float(actual or 0), cd,
               total), level="WARN", tag="chat")
        if dead:
            account.enabled = False
            try:
                account.save()
            except Exception:
                pass
            log("account %s session dead via envelope (TOKEN_EXPIRE) - disabled"
                % account.uid[:8], level="ERROR")
    else:
        account.note_error("envelope HTTP %s: %s" % (status_int, detail[:80]),
                           code=status_int, cooldown=15)

def should_retry_envelope(exc, emitted_bytes, attempt):
    # issue #37：坏参数是**模型内容问题**，不是瞬时上游故障——绝不自动重发
    # （否则会重复计费，且下一次很可能同样非法）。客户端想重试由它自己决定。
    """流内错误信封是否值得**重开上游**再试。

    关键前提（access log 记 200 而业务错 418 的根因）：上游先以 HTTP200
    建流，provider 故障以 SSE 信封 statusCodeValue=418 投递——此时 urlopen
    层重试覆盖不到。只要 **尚未向客户端发出任何字节**、未超预算、且错误属
    瞬时类（418/5xx/provider_error，且非客户端参数错），就值得重开。
    """
    if isinstance(exc, InvalidToolArguments):
        return False
    if emitted_bytes:
        return False
    if attempt >= TRANSIENT_MAX_RETRIES:
        return False
    status_int = _to_int_status(getattr(exc, "status", 502))
    detail = getattr(exc, "detail", "") or ""
    # 401/403 (含 10605 排队被拒) 与 429 在未吐出字节前均允许通过 reopen 换号重试
    # 风控（国际版 4015/4019）换号也没用、重开只会加速风控升级：
    # 一次就够，交给客户端退避（PROTOCOL §11.4）。
    if "risk_control" in detail:
        return False
    if status_int in (401, 403, 429):
        return True
    return _is_transient_upstream(status_int, detail)


def aggregate_with_envelope_retry(resp, payload, session_key, realm, model,
                                  holder, account):
    """非流式：流内瞬时错误信封 / 传输抖动 -> 重开上游重新聚合。

    仅用于客户端尚未收到任何字节的非流式路径。返回 (chat_obj, account)：
      - 最终信封错误以 UpstreamStatus 抛出（调用方既有分支处理：记账+友好提示）
      - 重开时 open_upstream 的 RateLimited/HTTPError 记日志后仍以**原信封**
        错误上抛（原错误才是本次请求的真实结果，且其分支已具备友好映射）
      - 传输层瞬时错误（TLS EOF 等）同样触发重开
    传入的 resp 由调用方的 with/finally 关闭；本函数只负责关闭重开的新连接。
    """
    cur = resp
    try:
        for attempt in range(TRANSIENT_MAX_RETRIES + 1):
            try:
                obj = aggregate_stream(cur, model, None, holder=holder,
                                       allowed_names=_tool_names_from_payload(payload))
                return obj, account
            except UpstreamStatus as exc:
                _handle_envelope_account_cooldown(account, exc, model=model, session_key=session_key)
                if not should_retry_envelope(exc, False, attempt):
                    raise
                log("in-stream envelope status %s on model '%s' "
                    "(try %d/%d), reopening upstream"
                    % (exc.status, model, attempt + 1,
                       TRANSIENT_MAX_RETRIES + 1), level="WARN", tag="chat")
                time.sleep(attempt + 1)
                try:
                    new_resp, account, _ = open_upstream(
                        payload, session_key=session_key, target_realm=realm)
                except Exception as reopen_exc:
                    log("reopen after envelope error failed: %s"
                        % str(reopen_exc)[:160], level="WARN", tag="chat")
                    raise exc      # 以原信封错误进入既有处理路径
                if cur is not resp:
                    try:
                        cur.close()
                    except Exception:
                        pass
                cur = new_resp
            except Exception as exc:
                if attempt >= TRANSIENT_MAX_RETRIES or \
                        not _is_transient_transport(exc):
                    raise
                log("in-stream transport error on model '%s' (try %d/%d): "
                    "%s - reopening upstream"
                    % (model, attempt + 1, TRANSIENT_MAX_RETRIES + 1,
                       str(exc)[:120]), level="WARN", tag="chat")
                time.sleep(attempt + 1)
                try:
                    new_resp, account, _ = open_upstream(
                        payload, session_key=session_key, target_realm=realm)
                except Exception as reopen_exc:
                    log("reopen after transport error failed: %s"
                        % str(reopen_exc)[:160], level="WARN", tag="chat")
                    raise exc
                if cur is not resp:
                    try:
                        cur.close()
                    except Exception:
                        pass
                cur = new_resp
    finally:
        if cur is not resp:
            try:
                cur.close()
            except Exception:
                pass


class QuotaBlocked(Exception):
    """账号护栏/配额拦截：请求**未送上游**，直接回 429 quota_exceeded。"""

    def __init__(self, code="quota_exceeded", message=""):
        self.code = str(code or "quota_exceeded")
        self.message = message or (
            "账号护栏拦截：本次请求未发送到上游（配额/余额/日限/模型限）。")
        super(QuotaBlocked, self).__init__(self.message)


def estimate_request_tokens(payload):
    """本次请求的 token 预估（护栏用）：优先 max_tokens 一类的输出上限。"""
    payload = payload if isinstance(payload, dict) else {}
    for key in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
        try:
            value = int(payload.get(key))
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0


def pool_guard(account, model, realm, tokens=0):
    """账号护栏（trae_accounts.AccountPool.guard）→ (ok, code, message)。

    账号域未提供 guard（或签名不一致）时一律**放行**：护栏是增益能力，
    缺失实现不能反过来挡业务。
    """
    fn = getattr(POOL, "guard", None) if POOL is not None else None
    if not callable(fn):
        return True, "", ""
    try:
        result = fn(account, model, realm, tokens=tokens)
    except TypeError:
        try:
            result = fn(account, model, realm, tokens)
        except Exception:
            return True, "", ""
    except Exception as exc:
        log("pool.guard failed (%s) - allowing request" % str(exc)[:120],
            level="WARN", tag="chat")
        return True, "", ""
    if isinstance(result, tuple) and len(result) >= 2:
        ok = bool(result[0])
        code = str(result[1] or "") if len(result) > 1 else ""
        msg = str(result[2] or "") if len(result) > 2 else ""
        return ok, code, msg
    if isinstance(result, dict):
        return (bool(result.get("ok", True)), str(result.get("code") or ""),
                str(result.get("message") or ""))
    return bool(result), "", ""


def open_upstream(payload, session_key=None, target_realm=None, usage_ctx=None):
    """构造 Trae 请求体并打开上游 SSE。返回 (resp, account, body_bytes)。

    usage_ctx：可选**出参** dict，回填推理档位审计信息（effort_requested =
    客户端原值；effort = 实际下发的档位；realm = 实际出口）。

    账号轮换规则（PROTOCOL §六 / §11.4，code 语义由 trae_accounts.note_error 定义）：
      · 1001 / HTTP 401/403：先刷新 token 原地重试一次，仍失败 -> breaker 换号
      · 4001 / 4023        ：客户端参数 / 模型名问题 -> 立即失败，不换号不重试
      · 4015 / 4019        ：账号/出口风控 -> 冷却换号，绝不原地轰炸
      · 429                ：模型粒度频控 -> 冷却换号
      · 5xx / 传输抖动     ：同账号快速重试（1s/2s），仍失败短冷却换号
    HTTP 200 + event:error 形态由 iter_inner_sse 抛 UpstreamStatus，交给
    _handle_envelope_account_cooldown / should_retry_envelope 处理。
    """
    model = str(payload.get("model") or "")
    realm = trae_realm(target_realm or detect_model_realm(model) or CURRENT_REALM)
    if not target_realm:
        realm = fallback_realm_by_accounts(realm, model)
        if realm != CURRENT_REALM:
            log("request routed to realm %s (default=%s, model=%r)"
                % (realm, CURRENT_REALM, model), tag="realm")
            if usage_ctx is not None:
                usage_ctx["realm_reason"] = auto_realm_reason(model, realm)
    model_key = trae_catalog.resolve_upstream_key(model, realm=realm)

    # 请求体与账号无关（鉴权在头上），构造一次即可
    body_obj = build_trae_body(payload, None, model_key, realm=realm)
    body_bytes = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
    if usage_ctx is not None:
        usage_ctx["effort_requested"] = requested_effort(payload)
        usage_ctx["effort"] = (body_obj.get("parameters") or {}).get(
            "reasoning_effort")
        usage_ctx["realm"] = realm
        usage_ctx["model_key"] = model_key

    if not session_key:
        session_key = derive_affinity_key(body_obj.get("messages"))
        if session_key and AFFINITY_DEBUG:
            log("affinity: derived %s for %d msgs"
                % (session_key, len(body_obj.get("messages") or [])))

    total = _realm_ready_total(realm, model)
    tried = set()
    guard_hit = None
    last_code = 0
    last_detail = ""
    last_429_detail = ""
    saw_429 = False
    waited_cool = False

    for _ in range(total + 2):
        account = POOL.pick_for_session(realm=realm, session_key=session_key,
                                        exclude=tried, model=model) if POOL else None
        if account is None:
            if not waited_cool:
                wait = _short_error_cooldown_wait(realm, model, exclude=tried)
                if wait > 0:
                    waited_cool = True
                    log("accounts in short error-cooldown for '%s' "
                        "(%.1fs left) - waiting instead of failing"
                        % (model, wait), level="WARN", tag="chat")
                    time.sleep(wait + 0.25)
                    continue
            break
        if trae_realm(account.realm) != realm:
            if session_key and POOL:
                POOL.affinity.unbind(session_key)
            continue
        tried.add(account.uid)

        # 护栏（G1/G2/G3/G4）：命中即跳过该号；全被挡 -> 429 quota_exceeded。
        # 请求体估算 token 用输出上限（无则 0，由账号域按自己的口径处理）。
        _ok, _gcode, _gmsg = pool_guard(account, model, realm,
                                        estimate_request_tokens(payload))
        if not _ok:
            guard_hit = (_gcode or "quota_exceeded",
                         _gmsg or "账号护栏拦截：本次请求未发送到上游。")
            log("account %s blocked by quota guard on '%s' (%s): %s"
                % (account.uid[:8], model, guard_hit[0], guard_hit[1][:160]),
                level="WARN", tag="chat")
            continue

        resp = None
        code = 0
        detail = ""
        exc_obj = None
        tries = 0
        refreshed = False
        hosts = trae_core_candidates(realm)
        host_i = 0

        while True:
            try:
                if _trae_client is not None and hasattr(_trae_client, "open_chat"):
                    resp = trae_open_chat(account, realm, body_obj, timeout=600)
                else:
                    url = validate_public_http_url(
                        hosts[host_i].rstrip("/") + TRAE_CHAT_PATH)
                    req = urllib.request.Request(
                        url, data=body_bytes, method="POST",
                        headers=trae_auth_headers(account, realm, sse=True))
                    resp = urllib.request.urlopen(req, timeout=600)
                break
            except urllib.error.HTTPError as exc:
                try:
                    detail = exc.read(600).decode("utf-8", "replace")
                except Exception:
                    detail = ""
                try:
                    exc.qoder_detail = detail
                    exc.trae_detail = detail
                except Exception:
                    pass
                exc_obj = exc
                code = int(exc.code)
            except Exception as exc:
                exc_obj = exc
                code, detail = trae_exc_code_detail(exc)

            if code in (401, 403) and not refreshed:
                if trae_refresh_account(account, realm, force=True):
                    refreshed = True
                    continue
            if code in TRAE_CLIENT_FAULT_CODES:
                raise UpstreamStatus(code, detail or "invalid request")
            if code in (401, 403, 429):
                break
            if _is_transient_upstream(code, detail) \
                    and tries < TRANSIENT_MAX_RETRIES:
                backoff = tries + 1
                log("transient upstream HTTP %d on '%s' model '%s' "
                    "(try %d/%d), retry in %ds"
                    % (code, account.uid[:8], model, tries + 1,
                       TRANSIENT_MAX_RETRIES + 1, backoff),
                    level="WARN", tag="chat")
                tries += 1
                time.sleep(backoff)
                continue
            if _is_transient_transport(exc_obj) \
                    and tries < TRANSIENT_MAX_RETRIES:
                if host_i + 1 < len(hosts):
                    host_i += 1
                    log("transient transport error on '%s' model '%s' "
                        "(try %d/%d): %s - switching gateway host to %s"
                        % (account.uid[:8], model, tries + 1,
                           TRANSIENT_MAX_RETRIES + 1,
                           str(exc_obj)[:120], hosts[host_i]),
                        level="WARN", tag="chat")
                else:
                    log("transient transport error on '%s' model '%s' "
                        "(try %d/%d): %s - retry in %ds"
                        % (account.uid[:8], model, tries + 1,
                           TRANSIENT_MAX_RETRIES + 1,
                           str(exc_obj)[:120], tries + 1),
                        level="WARN", tag="chat")
                tries += 1
                time.sleep(tries)
                continue
            break

        if resp is not None:
            account.note_success(model=model)
            return trae_hold_slot(account, resp), account, body_bytes

        last_code, last_detail = code, detail
        if code == 429:
            # 4008 是免费额度用尽，不是账号/出口故障：不要冷却账号、不要换号，
            # 直接把 429 交给客户端（额度恢复后可立即继续用）。
            if "4008" in detail or "exceeded the quota" in detail.lower():
                raise UpstreamStatus(429, detail or "quota exceeded")
            account.note_error("HTTP 429 (model throttled)", code=429,
                               model=model, cooldown=60)
            log("account %s throttled on '%s' (429), cooling 60s"
                % (account.uid[:8], model), level="WARN", tag="chat")
            if session_key and POOL:
                POOL.affinity.unbind(session_key)
            saw_429 = True
            last_429_detail = detail
            continue
        if code in (401, 403):
            dead = trae_accounts.session_dead(detail)
            account.note_error("HTTP %s: %s" % (code, detail[:120]),
                               code=code, model=model,
                               cooldown=300 if dead else None)
            if dead:
                account.enabled = False
                try:
                    account.save()
                except Exception:
                    pass
                log("account %s session dead (TOKEN_EXPIRE) - disabled"
                    % account.uid[:8], level="ERROR")
            log("account %s rejected (HTTP %s), rotating"
                % (account.uid[:8], code), level="WARN", tag="chat")
            if session_key and POOL:
                POOL.affinity.unbind(session_key)
            continue
        if _is_transient_upstream(code, detail) \
                or _is_transient_transport(exc_obj):
            account.note_error("HTTP %s upstream transient: %s"
                               % (code, detail[:100]), code=code,
                               model=model, cooldown=15)
            log("upstream still transient (HTTP %d) after %d tries on '%s' "
                "- short cooldown, rotating"
                % (code, TRANSIENT_MAX_RETRIES + 1, account.uid[:8]),
                level="WARN", tag="chat")
            if session_key and POOL:
                POOL.affinity.unbind(session_key)
            continue
        if 400 <= code < 500:
            account.note_error("HTTP %s: %s" % (code, detail[:120]),
                               code=code, model=model)
            if session_key and POOL:
                POOL.affinity.unbind(session_key)
            continue
        raise UpstreamStatus(code or 502, detail or str(exc_obj)[:300])

    if guard_hit is not None:
        raise QuotaBlocked(guard_hit[0], guard_hit[1])
    if saw_429:
        raise RateLimited(None, last_429_detail,
                          wait=retry_after_seconds(model, realm))
    if last_code:
        raise UpstreamStatus(last_code, last_detail or "upstream failed")
    throttled, wait = realm_model_throttled(realm, model)
    if throttled:
        raise RateLimited(None, "usage exceeds frequency limit", wait=wait)
    raise RuntimeError(
        "no usable account for realm '%s': all are disabled, cooling down, "
        "or expired" % realm)


def sse_with_heartbeat(source, send, interval=None, idle_limit=None):
    """在等待上游数据的空档里发送 SSE 注释心跳（`: ping`），并原样转发数据。

    背景：`xhigh` 长上下文请求的上游首字延迟可达 40–71 秒（实测日志），
    这段时间网关对客户端一言不发；客户端/中间代理一旦空闲超时就会断开并
    重连（表现为“一直重连”）。SSE 规范允许以 `:` 开头的注释行，客户端会
    忽略，因此用它做保活。

    source     : 上游数据迭代器（iter_inner_sse 的输出，产出 bytes）
    send       : 发送函数（接收 bytes）
    interval   : 空闲多久发一次心跳（秒），默认 5（可用 QD_SSE_HEARTBEAT 覆盖）
    idle_limit : 单次等待上限（秒），默认 900；超过抛 TimeoutError

    读线程把上游数据放入队列，主线程只在“队列空闲”时补心跳，保证顺序与
    错误传播（上游异常原样在主线程抛出）。
    """
    if interval is None:
        try:
            interval = float(os.environ.get("QD_SSE_HEARTBEAT", "5") or 5)
        except Exception:
            interval = 5.0
    if interval <= 0:
        # 显式关闭心跳：退化为直通
        for item in source:
            yield item
        return
    if idle_limit is None:
        idle_limit = 900.0

    import queue as _queue
    import threading as _threading

    box = _queue.Queue()
    done = object()

    def _reader():
        try:
            for item in source:
                box.put(item)
        except BaseException as exc:          # 上游错误/断连也要送主线程
            box.put(exc)
        finally:
            box.put(done)

    reader = _threading.Thread(target=_reader, daemon=True)
    reader.start()

    waited = 0.0
    while True:
        try:
            item = box.get(timeout=interval)
        except _queue.Empty:
            send(b": ping\n\n")               # SSE 注释：客户端忽略
            waited += interval
            if waited >= idle_limit:
                raise TimeoutError(
                    "upstream produced no data for %.0fs" % waited)
            continue
        if item is done:
            return
        if isinstance(item, BaseException):
            raise item
        waited = 0.0
        yield item


# ---------------------------------------------------------------------------
# 上游内层错误可观测性（task-34）
# ---------------------------------------------------------------------------
# 形态：HTTP 200 + 信封 statusCodeValue=200，但**内层 chunk** 里带 error
# （如 provider_error → invalid_request_error："Messages with role 'tool'
# must be a response to a preceding message with 'tool_calls'"）。
# 既有路径对此完全无感：客户端只看到 200 的空正文，排障成本极高。
# 本段只做计数 + 按类别首次告警，**绝不改行为**（不吞、不改映射、不改重试）。
_INNER_ERR_LOCK = threading.Lock()
_INNER_ERR_STATS = {"total": 0, "kinds": {}, "warned": set()}


def inner_error_snapshot():
    """内层错误计数快照（挂到 /usage/perf 等运行信息输出）。"""
    with _INNER_ERR_LOCK:
        return {"total": _INNER_ERR_STATS["total"],
                "kinds": dict(_INNER_ERR_STATS["kinds"]),
                "warned": sorted(_INNER_ERR_STATS["warned"])}


def _inner_error_kind(code, message):
    """把内层错误归类（用于首次告警去重）。返回 "" = 不是错误形态。"""
    low = ("%s %s" % (code or "", message or "")).lower().strip()
    if not low:
        return ""
    if any(k in low for k in ("datainspectionfailed", "inappropriate content",
                              "contentfilter", "sensitivecontent",
                              "data_inspection")):
        return "content_policy"
    if any(k in low for k in ("rate_limit", "throttl", "frequency limit",
                              "10605", "too many")):
        return "rate_limit"
    if any(k in low for k in ("invalid_request", "invalid_parameter",
                              "provider_error", "not found",
                              "must be a response", "unsupported")):
        return "invalid_request"
    if any(k in low for k in ("unauthor", "forbidden", "permission",
                              "expired", "token")):
        return "auth"
    return "other"


def note_inner_upstream_error(obj, status=None):
    """检测内层 chunk 的错误指示：计数 + 按类别首次 WARN。返回命中类别。

    只观测、不改行为：调用点不做任何分支，yield 与清洗流程原样继续。
    """
    if not isinstance(obj, dict):
        return ""
    err = obj.get("error")
    if isinstance(err, dict):
        code = err.get("code") or err.get("type") or ""
        msg = err.get("message") or ""
    elif isinstance(err, str):
        code, msg = "", err
    else:
        return ""
    kind = _inner_error_kind(code, msg)
    if not kind:
        return ""
    with _INNER_ERR_LOCK:
        _INNER_ERR_STATS["total"] += 1
        kinds = _INNER_ERR_STATS["kinds"]
        kinds[kind] = kinds.get(kind, 0) + 1
        total = _INNER_ERR_STATS["total"]
        first = kind not in _INNER_ERR_STATS["warned"]
        if first:
            _INNER_ERR_STATS["warned"].add(kind)
    if first:
        log("upstream error hidden in HTTP 200 envelope: kind=%s status=%s "
            "code=%s total=%d | %s"
            % (kind, status, str(code)[:40], total,
               ("%s %s" % (code, msg)).strip()[:300]),
            level="WARN", tag="chat")
    return kind


def iter_inner_sse(resp, holder=None, allowed_names=None):
    """把 Trae SSE 事件流转换成标准 OpenAI chat chunk 的 "data: ..." 行。

    Trae 帧（PROTOCOL §六）：
        metadata    -> 会话 id / 模型（首次 chunk 带 role）
        output      -> response / reasoning_content / tool_calls / phase
        token_usage -> OpenAI usage（归一后同时写 holder）
        done        -> finish_reason（有工具调用时强制 tool_calls）
        error       -> 抛 UpstreamStatus（错误码按 §六 映射）

    工具标记（§七）：正文里的 <|FunctionCallBegin|>[…]<|FunctionCallEnd|>
    经 ToolMarkerStream 跨 chunk 缓冲后转成 tool_calls delta；标记不透传。
    JSON 坏 / 名字不认识 -> fail-open：标记原样留在正文里，一个字都不吞。
    """
    holder = holder if isinstance(holder, dict) else {}
    if allowed_names is None:
        allowed_names = holder.get("allowed_names")
    allowed = set(allowed_names) if allowed_names else None
    stream = ToolMarkerStream(allowed_names=allowed)

    created = int(time.time())
    meta = {"id": "chatcmpl-trae-" + uuid.uuid4().hex[:24],
            "model": str(holder.get("requested_model") or "")}

    def frame(delta, finish_reason=None, usage=None):
        payload = {
            "id": meta["id"],
            "object": "chat.completion.chunk",
            "created": created,
            "model": meta["model"],
            "choices": [],
        }
        if delta is not None:
            payload["choices"] = [{"index": 0, "delta": delta,
                                   "finish_reason": finish_reason}]
        if usage:
            payload["usage"] = usage
        return ("data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
                ).encode("utf-8")

    for event, data in iter_trae_events(resp):
        obj = data if isinstance(data, dict) else {}
        if event == "metadata":
            session_id = str(obj.get("session_id") or "")
            if session_id:
                meta["id"] = "chatcmpl-" + session_id.replace("-", "")[:24]
            model_name = str(obj.get("model") or "")
            if model_name:
                meta["model"] = model_name
            yield frame({"role": "assistant", "content": ""})
            continue
        if event in ("output", "message"):
            reasoning = obj.get("reasoning_content")
            if isinstance(reasoning, str) and reasoning:
                yield frame({"reasoning_content": reasoning})
            # 上游原生 tool_calls（当前协议未见，防御性支持）
            native = obj.get("tool_calls")
            if isinstance(native, list) and native:
                parsed = _trae_normalise_calls(native, allowed)
                if parsed:
                    yield frame(stream.calls_delta(parsed))
            text = obj.get("response")
            if isinstance(text, str) and text:
                for delta in stream.feed(text):
                    yield frame(delta)
            continue
        if event == "notify_usage":
            if isinstance(holder, dict):
                holder["quota"] = obj
                try:
                    record_quota(holder.get("account"), obj)
                except Exception:
                    pass
            continue
        if event in ("token_usage", "usage"):
            usage = trae_usage_to_openai(obj)
            holder["usage"] = usage
            yield frame(None, usage=usage)
            continue
        if event == "done":
            for delta in stream.flush():
                yield frame(delta)
            finish = str(obj.get("finish_reason") or "stop") or "stop"
            if stream.emitted:
                finish = "tool_calls"
            yield frame({}, finish_reason=finish)
            return
        if event == "error":
            status, detail, _kind = trae_error_status(
                obj.get("code"), obj.get("message"), obj.get("error"))
            raise UpstreamStatus(status, detail)
        # 其它事件（keepalive / phase / 未知）：忽略，不制造空帧

    # 流提前结束（缺 done 帧）：flush 缓冲并给出终态，客户端不会挂死
    for delta in stream.flush():
        yield frame(delta)
    yield frame({}, finish_reason="tool_calls" if stream.emitted else "stop")


def aggregate_stream(resp, model, resp_id=None, holder=None, allowed_names=None):
    """把上游信封流折叠成一个非流式 chat.completion 对象。

    allowed_names：本次请求声明的工具名集合；用于「泄漏文本回读」的守卫
    （见 parse_leaked_tool_calls / issue #8）。
    """
    content, reasoning, finish = [], [], "stop"
    tool_calls_map = {}
    usage = holder.get("usage") if holder else None
    started = time.time()
    first_chunk_at = None
    created = None

    for line in iter_inner_sse(resp, holder=holder,
                               allowed_names=allowed_names):
        data = strip_data_prefix(line.decode("utf-8", "replace"))
        if not data or data == "[DONE]":
            continue
        try:
            chunk = json.loads(data)
        except Exception:
            continue
        if not isinstance(chunk, dict):
            continue
        if first_chunk_at is None:
            first_chunk_at = time.time()
        if chunk.get("id"):
            resp_id = chunk["id"]
        if chunk.get("model"):
            model = chunk["model"]
        if chunk.get("created"):
            created = chunk["created"]
        if chunk.get("usage"):
            usage = chunk["usage"]
            if holder is not None:
                holder["usage"] = usage
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}
            if delta.get("content"):
                _c = delta["content"]
                if isinstance(_c, str):
                    content.append(_c)
                elif isinstance(_c, list):
                    for _p in _c:
                        if isinstance(_p, str):
                            content.append(_p)
                        elif (isinstance(_p, dict)
                              and isinstance(_p.get("text"), str)):
                            content.append(_p["text"])
            if delta.get("reasoning_content"):
                reasoning.append(delta["reasoning_content"])
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index")
                if idx is None:
                    idx = len(tool_calls_map)
                fn = tc.get("function") or {}
                call_id = tc.get("id")
                fn_name = fn.get("name") or ""
                fn_args = fn.get("arguments") or ""
                if idx not in tool_calls_map:
                    tool_calls_map[idx] = {
                        "id": call_id or _new_id("call_"),
                        "type": tc.get("type") or "function",
                        "function": {"name": fn_name, "arguments": fn_args},
                    }
                else:
                    entry = tool_calls_map[idx]
                    if call_id:
                        entry["id"] = call_id
                    if fn_name:
                        entry["function"]["name"] = \
                            (entry["function"]["name"] or "") + fn_name
                    if fn_args:
                        entry["function"]["arguments"] = \
                            (entry["function"]["arguments"] or "") + fn_args
            fc = delta.get("function_call")
            if fc and isinstance(fc, dict) and fc.get("name"):
                idx = 0
                if idx not in tool_calls_map:
                    tool_calls_map[idx] = {
                        "id": _new_id("call_"),
                        "type": "function",
                        "function": {"name": fc.get("name") or "",
                                     "arguments": fc.get("arguments") or ""},
                    }
                else:
                    entry = tool_calls_map[idx]
                    if fc.get("name") and not entry["function"]["name"]:
                        entry["function"]["name"] = fc["name"]
                    if fc.get("arguments"):
                        entry["function"]["arguments"] += fc["arguments"]
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]

    message = {"role": "assistant", "content": "".join(content)}
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    # 回读（issue #8）：上游未给结构化 tool_calls，但正文恰好是网关自己写入
    # 历史的「LEAK_MARKER + JSON 数组」形态（模型照格式复述）——还原为结构化
    # 调用并从正文移除，避免客户端把 JSON 当正文显示、本轮调用不执行。
    if not tool_calls_map and message.get("content"):
        # issue #16-B1（非流式侧）：正文可能是「散文 + 回声块」。先按标记切分，
        # 散文照常保留，只对标记起的那一段做回读/吞掉判定。
        _head16, _block16 = _find_marker_split(message["content"],
                                               allow_prefix=False)
        _echo_src = _block16 or ""
        if _echo_src:
            _rec, _clean = parse_leaked_tool_calls(_echo_src, allowed_names)
            if _rec:
                message["content"] = _head16 + (_clean or "")
                tool_calls_map = {i: c for i, c in enumerate(_rec)}
            elif _echo_with_bad_args(_echo_src, allowed_names):
                # issue #37（fail-closed，**先于 #9/#11**）：外层数组完整合法、
                # 只是内层参数坏了——不泄漏、不伪造调用，也不拼装成功对象：
                # 整轮以协议错误失败（HTTP 502）。真截断的数组 parse 不过，
                # 不会被这里抢走（仍由 #9 吞掉）。
                log("tool-call echo has invalid JSON arguments (%d chars) — "
                    "failing the turn closed (issue #37)" % len(_echo_src),
                    level="WARN", tag="chat")
                raise InvalidToolArguments()
            elif _leaked_partial_droppable(_echo_src, allowed_names):
                # issue #9：截断的 marker+JSON 回声不还原、也不透传。
                log("dropped truncated leaked tool-call echo (%d chars) — issue #9"
                    % len(_echo_src), level="WARN", tag="chat")
                message["content"] = _head16
            elif _tool_echo_droppable(_echo_src, allowed_names):
                # issue #11：工具结果回声块同样不还原、不透传。
                log("dropped leaked tool-result echo (%d chars) — issue #11"
                    % len(_echo_src), level="WARN", tag="chat")
                message["content"] = _head16
            else:
                # issue #49 方向 C：四条路径都没认出来 -> 至少留痕（非流式侧）
                _log_unrecovered_leak(_echo_src, "aggregate")
    # 二次防御：剔除「无函数名」的空 tool_call，防止客户端死等
    if tool_calls_map:
        tool_calls_map = {k: v for k, v in tool_calls_map.items()
                          if (v.get("function") or {}).get("name")}
    if tool_calls_map:
        ordered = [tool_calls_map[k] for k in sorted(tool_calls_map.keys())]
        message["tool_calls"] = ordered
        if finish in ("stop", None):
            finish = "tool_calls"
    elif finish == "tool_calls":
        # 占位被全部过滤掉 -> 降级为正常结束，防止客户端无限挂起
        finish = "stop"
    out = {
        "id": resp_id or "chatcmpl-trae",
        "object": "chat.completion",
        "created": created or int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
    }
    if usage:
        out["usage"] = usage
    out["elapsed_ms"] = int((time.time() - started) * 1000)
    out["first_chunk_at"] = first_chunk_at
    return out


# ---------------------------------------------------------------------------
# Responses API (/v1/responses) <-> Chat Completions translation
# ---------------------------------------------------------------------------
def local_ip_addresses():
    """Every non-loopback IPv4 address this machine answers on."""
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in found and not ip.startswith("127."):
                found.append(ip)
    except Exception:
        pass
    if not found:
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 80))
            found.append(probe.getsockname()[0])
            probe.close()
        except Exception:
            pass
    return found


def _new_id(prefix):
    return prefix + uuid.uuid4().hex


def _flatten_content(content):
    """Flatten Responses-style content into text, or OpenAI vision parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        # 单 part 形态当单元素列表（同 _flatten_content_text 的 dict 修复）
        content = [content]
    elif not isinstance(content, list):
        return str(content)
    texts, parts = [], []
    for piece in content:
        if isinstance(piece, str):
            texts.append(piece)
            parts.append({"type": "text", "text": piece})
            continue
        if not isinstance(piece, dict):
            continue
        ptype = piece.get("type") or ""
        if ptype in ("input_text", "output_text", "text", "summary_text"):
            t = piece.get("text") or ""
            texts.append(t)
            parts.append({"type": "text", "text": t})
        elif ptype in ("input_image", "image_url", "image") or "image_url" in piece:
            url = piece.get("image_url") or piece.get("url")
            if isinstance(url, dict):
                url = url.get("url")
            if not url and piece.get("data"):
                mime = piece.get("mimeType") or piece.get("mime_type") or "image/png"
                url = "data:%s;base64,%s" % (mime, piece["data"])
            if url:
                parts.append({"type": "image_url", "image_url": {"url": url}})
    if any(p.get("type") == "image_url" for p in parts):
        return parts          # multimodal: keep structured parts
    return "\n".join(t for t in texts if t)


# ---------------------------------------------------------------------------
# Responses API "custom" (freeform) tools
#
# Codex 等客户端把文件编辑工具声明为 custom freeform tool：
#     {"type": "custom", "name": "apply_patch", "format": {...grammar...}}
# 上游 chat 端点没有 custom 概念 -> 出站降级为单 "input" 字符串参数的
# function tool，入站再还原为 custom_tool_call。否则工具被静默忽略。
# ---------------------------------------------------------------------------
CUSTOM_TOOL_HINT = (
    "This is a freeform tool. Put the COMPLETE raw payload into the single "
    "'input' string parameter, verbatim. Do not wrap it in JSON, do not wrap "
    "it in markdown code fences, do not add commentary."
)


def _is_custom_tool(tool):
    return isinstance(tool, dict) and str(tool.get("type") or "").lower() == "custom"


def custom_tool_names(tools):
    """Names of tools declared as freeform/custom in a Responses request."""
    names = set()
    for t in tools or []:
        if _is_custom_tool(t) and t.get("name"):
            names.add(str(t["name"]))
    return names


def _downgrade_custom_tool(tool):
    """Rewrite a Responses custom tool into a Chat function tool."""
    desc = tool.get("description") or ""
    fmt = tool.get("format") or {}
    extra = ""
    if isinstance(fmt, dict) and fmt.get("definition"):
        extra = "\n\nGrammar:\n" + str(fmt["definition"])
    elif isinstance(fmt, dict) and fmt.get("syntax"):
        extra = "\n\nGrammar syntax: %s" % str(fmt["syntax"])
    return {
        "type": "function",
        "name": tool.get("name") or "",
        "description": (desc + "\n\n" + CUSTOM_TOOL_HINT + extra).strip(),
        "parameters": {
            "type": "object",
            "properties": {
                "input": {
                    "type": "string",
                    "description": "Complete raw payload for this tool, verbatim.",
                }
            },
            "required": ["input"],
        },
    }


def _tools_for_chat(tools):
    """Downgrade custom tools; leave everything else untouched."""
    out = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        out.append(_downgrade_custom_tool(t) if _is_custom_tool(t) else t)
    return out


def _unwrap_custom_input(args):
    """Pull the freeform string back out of an {"input": "..."} argument blob."""
    if not isinstance(args, str):
        return json.dumps(args or "", ensure_ascii=False)
    try:
        parsed = json.loads(args)
    except Exception:
        return args
    if isinstance(parsed, dict):
        val = parsed.get("input")
        if isinstance(val, str):
            return val
        if val is not None:
            return json.dumps(val, ensure_ascii=False)
    if isinstance(parsed, str):
        return parsed
    return args


def responses_to_chat(payload):
    """Translate a Responses API request body into a Chat Completions body."""
    messages = []
    instructions = payload.get("instructions")
    if isinstance(instructions, str) and instructions.strip():
        messages.append({"role": "system", "content": instructions})
    inp = payload.get("input")
    pending_reasoning = ""
    if isinstance(inp, str):
        messages.append({"role": "user", "content": inp})
    elif isinstance(inp, list):
        for item in inp:
            if isinstance(item, str):
                messages.append({"role": "user", "content": item})
                continue
            if not isinstance(item, dict):
                continue
            itype = item.get("type")
            if itype in (None, "message"):
                body = _flatten_content(item.get("content"))
                if body:
                    role = item.get("role") or "user"
                    if role == "developer":
                        role = "system"
                    # 与相邻 function_call 的 assistant 文本合并到同一条，
                    # 避免打断 tool 序列
                    if role == "assistant" and messages \
                            and messages[-1].get("role") == "assistant":
                        prev = messages[-1]
                        if prev.get("content"):
                            prev["content"] = str(prev["content"]) + "\n" + str(body)
                        else:
                            prev["content"] = body
                        if pending_reasoning and "reasoning_content" not in prev:
                            prev["reasoning_content"] = pending_reasoning
                            pending_reasoning = ""
                    else:
                        msg_dict = {"role": role, "content": body}
                        if role == "assistant" and pending_reasoning:
                            msg_dict["reasoning_content"] = pending_reasoning
                            pending_reasoning = ""
                        messages.append(msg_dict)
            elif itype == "reasoning":
                r_text = ""
                summ = item.get("summary")
                if isinstance(summ, list):
                    r_text = "\n".join(p.get("text", "") for p in summ
                                       if isinstance(p, dict) and p.get("text"))
                elif isinstance(summ, str):
                    r_text = summ
                if not r_text:
                    cnt = item.get("content")
                    if isinstance(cnt, str):
                        r_text = cnt
                    elif isinstance(cnt, list):
                        r_text = _flatten_content(cnt)
                if r_text:
                    if messages and messages[-1].get("role") == "assistant":
                        messages[-1]["reasoning_content"] = r_text
                    else:
                        pending_reasoning = r_text
            elif itype == "function_call_output":
                raw_out = item.get("output")
                if isinstance(raw_out, list):
                    content = _flatten_content(raw_out)
                elif isinstance(raw_out, dict):
                    if raw_out.get("type") in ("input_image", "image_url", "image") \
                            or "image_url" in raw_out:
                        content = _flatten_content([raw_out])
                    else:
                        content = json.dumps(raw_out, ensure_ascii=False)
                elif isinstance(raw_out, str):
                    content = raw_out
                else:
                    content = str(raw_out)
                messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("call_id") or "",
                    "content": content,
                })
            elif itype == "function_call":
                tc_item = {
                    "id": item.get("call_id") or item.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": item.get("name") or "",
                        "arguments": item.get("arguments") or "{}",
                    },
                }
                if messages and messages[-1].get("role") == "assistant":
                    prev = messages[-1]
                    if "tool_calls" in prev:
                        prev["tool_calls"].append(tc_item)
                    else:
                        prev["tool_calls"] = [tc_item]
                    if pending_reasoning and "reasoning_content" not in prev:
                        prev["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                else:
                    msg_dict = {"role": "assistant", "content": "",
                                "tool_calls": [tc_item]}
                    if pending_reasoning:
                        msg_dict["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                    messages.append(msg_dict)
            elif itype == "custom_tool_call":
                raw_input = item.get("input")
                if isinstance(raw_input, (dict, list)):
                    raw_input = json.dumps(raw_input, ensure_ascii=False)
                if not isinstance(raw_input, str):
                    raw_input = "" if raw_input is None else str(raw_input)
                tc_item = {
                    "id": item.get("call_id") or item.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": item.get("name") or "",
                        "arguments": json.dumps({"input": raw_input},
                                                ensure_ascii=False),
                    },
                }
                if messages and messages[-1].get("role") == "assistant":
                    prev = messages[-1]
                    if "tool_calls" in prev:
                        prev["tool_calls"].append(tc_item)
                    else:
                        prev["tool_calls"] = [tc_item]
                    if pending_reasoning and "reasoning_content" not in prev:
                        prev["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                else:
                    msg_dict = {"role": "assistant", "content": "",
                                "tool_calls": [tc_item]}
                    if pending_reasoning:
                        msg_dict["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                    messages.append(msg_dict)
            elif itype == "custom_tool_call_output":
                raw_out = item.get("output")
                if isinstance(raw_out, list):
                    content = _flatten_content(raw_out)
                elif isinstance(raw_out, dict):
                    content = json.dumps(raw_out, ensure_ascii=False)
                elif isinstance(raw_out, str):
                    content = raw_out
                else:
                    content = str(raw_out)
                messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("call_id") or "",
                    "content": content,
                })
            else:
                # 未知 item 不静默丢弃：丢工具调用会让上游记录不一致
                log("responses: WARNING unhandled input item type=%r keys=%s"
                    % (itype, sorted(item.keys())[:8]))
    chat = {"model": payload.get("model"), "messages": messages}
    for key in ("temperature", "top_p", "seed"):
        if payload.get(key) is not None:
            chat[key] = payload[key]
    if payload.get("max_output_tokens") is not None:
        chat["max_tokens"] = payload["max_output_tokens"]
    effort = None
    reasoning = payload.get("reasoning")
    if isinstance(reasoning, dict):
        effort = reasoning.get("effort")
    if not effort:
        effort = payload.get("reasoning_effort")
    if effort:
        chat["reasoning_effort"] = effort
    if payload.get("tools"):
        chat["tools"] = _tools_for_chat(payload["tools"])
    if payload.get("tool_choice"):
        chat["tool_choice"] = payload["tool_choice"]
    if payload.get("parallel_tool_calls") is not None:
        chat["parallel_tool_calls"] = payload["parallel_tool_calls"]
    return chat


def _responses_usage(u):
    if not u:
        return None
    det = u.get("completion_tokens_details") or {}
    pdet = u.get("prompt_tokens_details") or {}
    return {
        "input_tokens": u.get("prompt_tokens") or 0,
        "input_tokens_details": {
            "cached_tokens": u.get("prompt_cache_hit_tokens")
            or det.get("cached_tokens") or pdet.get("cached_tokens") or 0,
        },
        "output_tokens": u.get("completion_tokens") or 0,
        "output_tokens_details": {
            "reasoning_tokens": det.get("reasoning_tokens") or 0},
        "total_tokens": u.get("total_tokens") or 0,
    }


def chat_to_response(chat_obj, model, custom_names=None):
    """Fold a Chat Completions object into a Responses API response object.

    custom_names: the set of tool names the client declared as freeform.
    Calls to those tools are re-inflated into custom_tool_call items so
    clients such as Codex recognise them.
    """
    custom_names = custom_names or set()
    choice = (chat_obj.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    text = msg.get("content") or ""
    reasoning = msg.get("reasoning_content") or ""
    output = []
    if reasoning:
        output.append({
            "id": _new_id("rs_"),
            "type": "reasoning",
            "status": "completed",
            "summary": [{"type": "summary_text", "text": reasoning}],
        })
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        call_id = tc.get("id") or _new_id("call_")
        name = fn.get("name") or ""
        if name and name in custom_names:
            output.append({
                "id": _new_id("ctc_"),
                "type": "custom_tool_call",
                "status": "completed",
                "call_id": call_id,
                "name": name,
                "input": _unwrap_custom_input(fn.get("arguments") or ""),
            })
        else:
            output.append({
                "id": _new_id("fc_"),
                "type": "function_call",
                "status": "completed",
                "call_id": call_id,
                "name": name,
                "arguments": fn.get("arguments") or "{}",
            })
    # DeepSeek DSML 工具调用回退
    if not (msg.get("tool_calls")):
        dsml_calls, clean_t = parse_dsml_tool_calls(text)
        if dsml_calls:
            for dc in dsml_calls:
                output.append({
                    "id": _new_id("fc_"),
                    "type": "function_call",
                    "status": "completed",
                    "call_id": dc.get("id") or _new_id("call_"),
                    "name": dc.get("name") or "",
                    "arguments": dc.get("arguments") or "{}",
                })
            text = clean_t
    if text or not output:
        output.append({
            "id": _new_id("msg_"),
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text,
                         "annotations": []}] if text else [],
        })
    finish = choice.get("finish_reason") or "stop"
    obj = {
        "id": _new_id("resp_"),
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed" if finish != "length" else "incomplete",
        "model": model,
        "output": output,
        "output_text": text,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "metadata": {},
    }
    u = _responses_usage(chat_obj.get("usage"))
    if u:
        obj["usage"] = u
    if finish == "length":
        obj["incomplete_details"] = {"reason": "max_output_tokens"}
    return obj


def stream_responses_events(inner_lines, model, holder):
    """Yield Responses-API SSE frames translated from chat-completions chunks.

    inner_lines: 已解包的 "data: {chunk}" 行迭代器（iter_inner_sse 输出）。
    """
    resp_id, msg_id, rs_id = _new_id("resp_"), _new_id("msg_"), _new_id("rs_")
    created = int(time.time())
    # 上游重开后本生成器会被重建：若 seq 从 0 重来，客户端看到的
    # sequence_number 会回退。从 holder 恢复历史最大号，保证严格单调。
    seq = int(holder.get("seq") or 0) if isinstance(holder, dict) else 0
    if isinstance(holder, dict):
        holder["resp_id"] = resp_id
    text_parts, reason_parts = [], []
    outputs = []
    reason_index = None
    msg_index = None
    finish = "stop"
    usage = None
    tool_calls_map = {}
    text_buffer = ""
    dsml_tool_calls = []
    custom_names = set(holder.get("custom_names") or ())

    def resp_obj(status):
        obj = {
            "id": resp_id,
            "object": "response",
            "created_at": created,
            "status": status,
            "model": model,
            "output": [o for o in outputs if o],
            "output_text": "".join(text_parts),
            "parallel_tool_calls": True,
            "tool_choice": "auto",
            "tools": [],
            "metadata": {},
        }
        u = _responses_usage(usage)
        if u:
            obj["usage"] = u
        return obj

    def ev(etype, payload_obj):
        nonlocal seq
        seq += 1
        if isinstance(holder, dict):
            holder["seq"] = seq        # 供外层补发终态事件时续号
        data = {"type": etype, "sequence_number": seq}
        data.update(payload_obj)
        body = json.dumps(data, ensure_ascii=False)
        return ("event: " + etype + "\ndata: " + body + "\n\n").encode("utf-8")

    def reason_item(status):
        return {
            "id": rs_id,
            "type": "reasoning",
            "status": status,
            "summary": [{"type": "summary_text", "text": "".join(reason_parts)}],
        }

    def msg_item(status):
        item = {"id": msg_id, "type": "message", "status": status,
                "role": "assistant", "content": []}
        if text_parts:
            item["content"] = [{"type": "output_text",
                                "text": "".join(text_parts),
                                "annotations": []}]
        return item

    yield ev("response.created", {"response": resp_obj("in_progress")})
    yield ev("response.in_progress", {"response": resp_obj("in_progress")})
    for raw in inner_lines:
        data = strip_data_prefix(raw.decode("utf-8", "replace")
                                 if isinstance(raw, bytes) else raw)
        if not data or data == "[DONE]":
            continue
        try:
            chunk = json.loads(data)
        except Exception:
            continue
        if usage is None and chunk.get("usage"):
            usage = chunk["usage"]
            holder["usage"] = usage
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}
            piece = delta.get("reasoning_content")
            if piece:
                if reason_index is None:
                    reason_index = len(outputs)
                    outputs.append(None)
                    yield ev("response.output_item.added",
                             {"output_index": reason_index,
                              "item": reason_item("in_progress")})
                    yield ev("response.reasoning_summary_part.added", {
                        "item_id": rs_id, "output_index": reason_index,
                        "summary_index": 0,
                        "part": {"type": "summary_text", "text": ""},
                    })
                reason_parts.append(piece)
                yield ev("response.reasoning_summary_text.delta", {
                    "item_id": rs_id, "output_index": reason_index,
                    "summary_index": 0, "delta": piece,
                })
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                fn = tc.get("function") or {}
                fn_name = fn.get("name") or ""
                fn_args = fn.get("arguments") or ""
                call_id = tc.get("id") or ""
                if idx not in tool_calls_map:
                    out_idx = len(outputs)
                    outputs.append(None)
                    c_id = call_id or _new_id("call_")
                    is_custom = bool(fn_name) and fn_name in custom_names
                    entry = {
                        "output_index": out_idx,
                        "id": c_id,
                        "name": fn_name,
                        "arguments": fn_args,
                        "custom": is_custom,
                        "item_id": _new_id("ctc_" if is_custom else "fc_"),
                    }
                    tool_calls_map[idx] = entry
                    item = {"id": entry["item_id"], "status": "in_progress",
                            "call_id": c_id, "name": fn_name}
                    if is_custom:
                        item["type"] = "custom_tool_call"
                        item["input"] = ""
                    else:
                        item["type"] = "function_call"
                        item["arguments"] = ""
                    yield ev("response.output_item.added",
                             {"output_index": out_idx, "item": item})
                else:
                    entry = tool_calls_map[idx]
                    if fn_name and not entry["name"]:
                        entry["name"] = fn_name
                        if fn_name in custom_names:
                            entry["custom"] = True
                    if fn_args:
                        entry["arguments"] += fn_args
                        if entry.get("custom"):
                            yield ev("response.custom_tool_call_input.delta", {
                                "output_index": entry["output_index"],
                                "item_id": entry["item_id"],
                                "call_id": entry["id"],
                                "delta": fn_args,
                            })
                        else:
                            yield ev("response.function_call_arguments.delta", {
                                "output_index": entry["output_index"],
                                "call_id": entry["id"],
                                "delta": fn_args,
                            })
            piece = delta.get("content")
            if piece:
                if msg_index is None:
                    if reason_index is not None:
                        full_r = "".join(reason_parts)
                        yield ev("response.reasoning_summary_text.done", {
                            "item_id": rs_id, "output_index": reason_index,
                            "summary_index": 0, "text": full_r,
                        })
                        yield ev("response.reasoning_summary_part.done", {
                            "item_id": rs_id, "output_index": reason_index,
                            "summary_index": 0,
                            "part": {"type": "summary_text", "text": full_r},
                        })
                        outputs[reason_index] = reason_item("completed")
                        yield ev("response.output_item.done",
                                 {"output_index": reason_index,
                                  "item": outputs[reason_index]})
                    msg_index = len(outputs)
                    outputs.append(None)
                    yield ev("response.output_item.added", {
                        "output_index": msg_index,
                        "item": {"id": msg_id, "type": "message",
                                 "status": "in_progress", "role": "assistant",
                                 "content": []},
                    })
                    yield ev("response.content_part.added", {
                        "item_id": msg_id, "output_index": msg_index,
                        "content_index": 0,
                        "part": {"type": "output_text", "text": "",
                                 "annotations": []},
                    })
                # DSML 缓冲：不把原始 DSML 标签流给客户端
                text_buffer += piece
                # issue #16-B1：散文与 marker 同帧 -> 先把 marker 之前的散文
                # 发出（不拖字），marker 起留在缓冲里等流末判定。
                # 含 "<" 的散文不走这条捷径（交给下面的 DSML 剥离逻辑）。
                _emit16, _hold16 = _find_marker_split(text_buffer)
                if _hold16 and _emit16 and "<" not in _emit16:
                    text_parts.append(_emit16)
                    yield ev("response.output_text.delta", {
                        "item_id": msg_id, "output_index": msg_index,
                        "content_index": 0, "delta": _emit16,
                    })
                    text_buffer = _hold16
                # 泄漏回读（issue #8）：缓冲本身是标记/候选时先压住，流末统一判定。
                _leak_defer = _marker_starts_at(text_buffer) or (
                    not any(text_parts) and (
                        _leak_prefix_hold(text_buffer)
                        or _tool_echo_prefix_hold(text_buffer)))
                while text_buffer and not _leak_defer:
                    idx = text_buffer.find("<")
                    if idx == -1:
                        text_parts.append(text_buffer)
                        yield ev("response.output_text.delta", {
                            "item_id": msg_id, "output_index": msg_index,
                            "content_index": 0, "delta": text_buffer,
                        })
                        text_buffer = ""
                        break
                    m = DSML_CALLS_RE.search(text_buffer)
                    if m and m.start() == idx:
                        if idx > 0:
                            lead = text_buffer[:idx]
                            text_parts.append(lead)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": lead,
                            })
                        calls_found, _ = parse_dsml_tool_calls(m.group(0))
                        if calls_found:
                            dsml_tool_calls.extend(calls_found)
                        text_buffer = text_buffer[m.end():]
                        continue
                    cand = text_buffer[idx:idx + 30]
                    is_cand = ("DSML" in cand) or (
                        len(cand) < 10 and not any(c in cand
                                                   for c in (" ", "\t", "\n", ">")))
                    if is_cand:
                        lead = text_buffer[:idx]
                        text_parts.append(lead)
                        yield ev("response.output_text.delta", {
                            "item_id": msg_id, "output_index": msg_index,
                            "content_index": 0, "delta": lead,
                        })
                        text_buffer = text_buffer[idx:]
                        break
                    else:
                        next_lt = text_buffer[idx + 1:].find("<")
                        if next_lt != -1:
                            flush_len = idx + 1 + next_lt
                            lead = text_buffer[:flush_len]
                            text_parts.append(lead)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": lead,
                            })
                            text_buffer = text_buffer[flush_len:]
                        else:
                            text_parts.append(text_buffer)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": text_buffer,
                            })
                            text_buffer = ""
                            break
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
    if reason_index is not None and outputs[reason_index] is None:
        full_r = "".join(reason_parts)
        yield ev("response.reasoning_summary_text.done", {
            "item_id": rs_id, "output_index": reason_index,
            "summary_index": 0, "text": full_r,
        })
        yield ev("response.reasoning_summary_part.done", {
            "item_id": rs_id, "output_index": reason_index,
            "summary_index": 0,
            "part": {"type": "summary_text", "text": full_r},
        })
        outputs[reason_index] = reason_item("completed")
        yield ev("response.output_item.done",
                 {"output_index": reason_index, "item": outputs[reason_index]})
    # 1. 已完成的结构化工具调用
    for idx in sorted(tool_calls_map.keys()):
        entry = tool_calls_map[idx]
        if entry.get("custom"):
            yield ev("response.custom_tool_call_input.done", {
                "output_index": entry["output_index"],
                "item_id": entry["item_id"],
                "call_id": entry["id"],
                "input": _unwrap_custom_input(entry["arguments"]),
            })
            fc_item = {
                "id": entry["item_id"],
                "type": "custom_tool_call",
                "status": "completed",
                "call_id": entry["id"],
                "name": entry["name"],
                "input": _unwrap_custom_input(entry["arguments"]),
            }
        else:
            yield ev("response.function_call_arguments.done", {
                "output_index": entry["output_index"],
                "call_id": entry["id"],
                "arguments": entry["arguments"],
            })
            fc_item = {
                "id": entry["item_id"],
                "type": "function_call",
                "status": "completed",
                "call_id": entry["id"],
                "name": entry["name"],
                "arguments": entry["arguments"],
            }
        outputs[entry["output_index"]] = fc_item
        yield ev("response.output_item.done",
                 {"output_index": entry["output_index"], "item": fc_item})
    # 冲刷剩余缓冲文本
    if text_buffer:
        leak_calls, leak_clean = (None, text_buffer)
        dropped_leak = False
        dropped_tool_echo = False
        dropped_bad_args = False
        # issue #16-B1：散文已先发出时 any(text_parts) 为真，但缓冲本身若以
        # 标记开头（切分后剩下的回声块）仍必须走回读/吞掉判定，否则会漏。
        if not any(text_parts) or _marker_starts_at(text_buffer):
            leak_calls, leak_clean = parse_leaked_tool_calls(
                text_buffer, holder.get("allowed_names"))
            # issue #37（fail-closed）**先于 #9/#11**：坏参数块的外层数组完整
            # 合法，带 DSML/围栏残片时会被 _leaked_partial_droppable 误判成
            # 「截断」并静默吞掉（正常完成）——那既不是失败也不是恢复。
            if leak_calls is None and _echo_with_bad_args(
                    text_buffer, holder.get("allowed_names")):
                dropped_bad_args = True
            elif leak_calls is None and _leaked_partial_droppable(
                    text_buffer, holder.get("allowed_names")):
                dropped_leak = True
            elif leak_calls is None and _tool_echo_droppable(
                    text_buffer, holder.get("allowed_names")):
                dropped_tool_echo = True
        if leak_calls:
            dsml_tool_calls.extend(
                {"id": c.get("id"),
                 "name": (c.get("function") or {}).get("name") or "",
                 "arguments": (c.get("function") or {}).get("arguments") or "{}"}
                for c in leak_calls)
            calls_rem, clean_rem = None, leak_clean
        elif dropped_leak:
            # issue #9：截断的 marker+JSON 回声 -> 不输出文本、不走 DSML 回退。
            log("dropped truncated leaked tool-call echo (%d chars) — issue #9"
                % len(text_buffer), level="WARN", tag="chat")
            calls_rem, clean_rem = None, None
        elif dropped_tool_echo:
            # issue #11：工具结果回声块 -> 同样吞掉，不走 DSML 回退。
            log("dropped leaked tool-result echo (%d chars) — issue #11"
                % len(text_buffer), level="WARN", tag="chat")
            calls_rem, clean_rem = None, None
        elif dropped_bad_args:
            # issue #37（fail-closed）：不输出协议，也不走正常完成——抛错，
            # 由 Responses 出口发 response.failed。
            log("tool-call echo has invalid JSON arguments (%d chars) — "
                "failing the turn closed (issue #37)" % len(text_buffer),
                level="WARN", tag="chat")
            raise InvalidToolArguments()
        else:
            calls_rem, clean_rem = parse_dsml_tool_calls(text_buffer)
            if not calls_rem:
                # issue #49 方向 C：Responses 侧同样留痕（DSML 也解析不出来时）
                _log_unrecovered_leak(clean_rem or text_buffer, "responses")
        if calls_rem:
            dsml_tool_calls.extend(calls_rem)
        if clean_rem:
            text_parts.append(clean_rem)
            if msg_index is not None:
                yield ev("response.output_text.delta", {
                    "item_id": msg_id, "output_index": msg_index,
                    "content_index": 0, "delta": clean_rem,
                })
        text_buffer = ""
    # 2. DSML 回退：无结构化工具调用时用解析出的 DSML 调用
    full_text = "".join(text_parts)
    dsml_calls = dsml_tool_calls
    if not dsml_calls:
        extra_calls, clean_text = parse_dsml_tool_calls(full_text)
        if extra_calls:
            dsml_calls = extra_calls
            full_text = clean_text
    if dsml_calls and not tool_calls_map:
        for dc in dsml_calls:
            out_idx = len(outputs)
            fc_item = {
                "id": _new_id("fc_"),
                "type": "function_call",
                "status": "completed",
                "call_id": dc.get("id") or _new_id("call_"),
                "name": dc.get("name") or "",
                "arguments": dc.get("arguments") or "{}",
            }
            outputs.append(fc_item)
            yield ev("response.output_item.added", {
                "output_index": out_idx,
                "item": dict(fc_item, status="in_progress", arguments=""),
            })
            yield ev("response.function_call_arguments.delta", {
                "output_index": out_idx,
                "call_id": fc_item["call_id"],
                "delta": fc_item["arguments"],
            })
            yield ev("response.function_call_arguments.done", {
                "output_index": out_idx,
                "call_id": fc_item["call_id"],
                "arguments": fc_item["arguments"],
            })
            yield ev("response.output_item.done",
                     {"output_index": out_idx, "item": fc_item})
    # 3. 有文本或没有任何输出项时，补 message 项
    has_other_items = any(o for o in outputs if o)
    if msg_index is not None or full_text or not has_other_items:
        if msg_index is None:
            msg_index = len(outputs)
            outputs.append(None)
            yield ev("response.output_item.added", {
                "output_index": msg_index,
                "item": {"id": msg_id, "type": "message",
                         "status": "in_progress", "role": "assistant",
                         "content": []},
            })
            yield ev("response.content_part.added", {
                "item_id": msg_id, "output_index": msg_index,
                "content_index": 0,
                "part": {"type": "output_text", "text": "",
                         "annotations": []},
            })
        yield ev("response.output_text.done", {
            "item_id": msg_id, "output_index": msg_index,
            "content_index": 0, "text": full_text,
        })
        yield ev("response.content_part.done", {
            "item_id": msg_id, "output_index": msg_index,
            "content_index": 0,
            "part": {"type": "output_text", "text": full_text,
                     "annotations": []},
        })
        outputs[msg_index] = msg_item("completed")
        yield ev("response.output_item.done",
                 {"output_index": msg_index, "item": outputs[msg_index]})
    status = "completed" if finish != "length" else "incomplete"
    final = resp_obj(status)
    if finish == "length":
        final["incomplete_details"] = {"reason": "max_output_tokens"}
    yield ev("response.completed", {"response": final})


def _responses_failed_frame(holder, code, message):
    """Responses 流的终态失败事件（response.failed）。

    stream_responses_events 的 ev() 闭包把最新 sequence_number 同步进
    holder["seq"]，这里在其上 +1 续号，保证严格大于已发出的事件——
    Responses 客户端只认终态事件，缺了它会一直等（原实现只 _sse_end）。
    """
    seq = int((holder or {}).get("seq") or 0) + 1
    data = {
        "type": "response.failed",
        "sequence_number": seq,
        "response": {
            "id": (holder or {}).get("resp_id") or _new_id("resp_"),
            "object": "response",
            "status": "failed",
            "error": {"code": str(code), "message": message},
        },
    }
    return ("event: response.failed\ndata: "
            + json.dumps(data, ensure_ascii=False) + "\n\n").encode("utf-8")


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Which configured API key the caller used, set by _key_ok(). Its bound
    # realm decides the upstream exit for this request alone.
    key_entry = None

    def handle(self):
        try:
            super(Handler, self).handle()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    def finish(self):
        try:
            super(Handler, self).finish()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    server_version = "trae2api-hub/" + VERSION

    def log_message(self, fmt, *args):
        # 静默看板高频轮询的正常 200 GET，异常状态与业务操作照常记录。
        try:
            req_path = (getattr(self, "path", None)
                        or (args[0] if args else "")).split("?")[0]
            if req_path == "/favicon.ico":
                return           # 浏览器自动请求的 404 不刷屏
            status_code = int(args[1]) if len(args) > 1 \
                and str(args[1]).isdigit() else 200
            if status_code < 400 and getattr(self, "command", "GET") == "GET":
                quiet_prefixes = (
                    "/logs", "/usage", "/accounts", "/scheduler",
                    "/health", "/panel/status", "/realm",
                )
                if any(req_path == p or req_path.startswith(p + "/")
                       for p in quiet_prefixes):
                    return
        except Exception:
            pass
        log(fmt % args)

    def _sse_begin(self):
        """开始一个 HTTP/1.1 SSE 流：用 chunked 编码，保持连接可复用。

        之前用 `Connection: close` + 裸写字节：客户端（连接池型 harness）
        会把该连接视为可复用，下一次请求落在已半关闭的连接上，表现为
        “一直重连 / 连不上”。改为 chunked 后，流结束发 0 长度的终止块，
        连接保持 keep-alive，可安全复用。
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        realm_used = getattr(self, "realm_used", "") or ""
        if realm_used:
            # #26：流式响应同样标注实际出口 + 原因
            self.send_header("X-Trae-Realm", realm_used)
            realm_reason = getattr(self, "realm_reason", "") or ""
            if realm_reason:
                self.send_header("X-Trae-Realm-Reason", realm_reason)
        degraded = getattr(self, "degraded_from", "") or ""
        if degraded:
            self.send_header("X-Trae-Degraded", degraded)
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self._chunked = True

    def _sse_write(self, data):
        """按 chunked 编码写一段数据（data: bytes）。"""
        if not data:
            return
        if not getattr(self, "_chunked", False):
            # 理论上不会发生；保守回退成裸写
            self.wfile.write(data)
            self.wfile.flush()
            return
        self.wfile.write(("%x\r\n" % len(data)).encode("ascii"))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    def _sse_end(self):
        """结束 chunked 流（写 0 长度终止块），连接保持可复用。"""
        if not getattr(self, "_chunked", False):
            return
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass
        self._chunked = False

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if code == 429:
            self.send_header("Retry-After", "60")
        realm_used = getattr(self, "realm_used", "") or ""
        if realm_used:
            # #26：本次**实际出口**（自动路由后可能与请求开始时不同）
            self.send_header("X-Trae-Realm", realm_used)
            realm_reason = getattr(self, "realm_reason", "") or ""
            if realm_reason:
                self.send_header("X-Trae-Realm-Reason", realm_reason)
        degraded = getattr(self, "degraded_from", "") or ""
        if degraded:
            self.send_header("X-Trae-Degraded", degraded)
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message, err_type="server_error"):
        self._json(code, {"error": {"message": message, "type": err_type,
                                    "code": code}})

    def _quota_error(self, exc):
        """账号护栏拦截 -> HTTP 429（quota_exceeded，中文原因）。

        Anthropic 链路用官方错误信封（rate_limit_error），其余走 OpenAI 形态；
        两条都把语义码放在 code 里，便于客户端/面板区分「配额」与「上游限流」。
        """
        message = getattr(exc, "message", "") or "账号配额拦截"
        reason = getattr(exc, "code", "quota_exceeded") or "quota_exceeded"
        try:
            is_anthropic = "/messages" in (self.path or "")
        except Exception:
            is_anthropic = False
        if is_anthropic:
            return self._json(429, {
                "type": "error",
                "error": {"type": "rate_limit_error", "message": message,
                          "code": reason},
            })
        return self._json(429, {"error": {
            "message": message, "type": "quota_exceeded",
            "code": reason, "status": 429}})

    def _rate_limited(self, exc):
        """429 with Retry-After, so clients back off instead of hammering."""
        wait = max(1, int(getattr(exc, "wait", 60) or 60))
        body = json.dumps({
            "error": {
                "message": ("upstream rate limit reached for this model; "
                            "retry in %ds" % wait)
                + ((" - " + exc.detail[:200]) if getattr(exc, "detail", "") else ""),
                "type": "rate_limit_error",
                "code": 429,
                "retry_after": wait,
            }
        }, ensure_ascii=False).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", str(wait))
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _download(self, filename, obj):
        """Send a JSON document as a browser download.

        Content-Disposition is quoted because the filename is generated from
        user-controlled parts (the realm filter) and could otherwise break the
        header or allow a response-splitting attempt.
        """
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        safe = re.sub(r'[^A-Za-z0-9._-]', "_", str(filename))[:120] \
            or "export.json"
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % safe)
        self.send_header("Cache-Control", "no-store")
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _supplied_key(self):
        """The key the caller presented, from the header or the ?key= query."""
        supplied = (self.headers.get("Authorization") or "").removeprefix(
            "Bearer ").strip()
        if supplied:
            return supplied
        # Anthropic 客户端（Claude Code 等）用 x-api-key 头，而不是
        # Authorization: Bearer —— 漏掉这一路回退会让 /v1/messages 全量 401。
        anthropic_key = (self.headers.get("x-api-key") or "").strip()
        if anthropic_key:
            return anthropic_key
        # 浏览器顶层导航无法设置头，所以 ?key= 也接受（看板跨设备打开用）。
        try:
            query = parse_qs(urlparse(self.path).query)
            return (query.get("key") or [""])[0].strip()
        except Exception:
            return ""

    def _key_ok(self):
        """True when the request carries a right key (or no key is needed)."""
        # 面板会话同时解锁管理 API，浏览器无需在 localStorage 存 API key。
        if self._panel_ok():
            return True
        self.key_entry = identify_key(self._supplied_key())
        if self.key_entry:
            return True
        if not auth_required():
            return True
        return False

    def _key_realm(self):
        """Realm bound to the key this request used, or "" when unbound."""
        return (self.key_entry or {}).get("realm") or ""

    def _key_id_for_usage(self):
        """usage 行归属用的 API key 标识（panel 分配的 id / legacy / launcher）。

        只取 `key_entry["id"]`——它是 panel 生成的稳定 id，**绝不含明文 key**
        （本仓红线）；无 key（面板会话 / 未开鉴权）时返回空串，调用方据此不写该键。
        """
        return str((self.key_entry or {}).get("id") or "")

    def _cross_realm_error(self, model, realm):
        """解释模型/出口错配，替代上游晦涩的 403。"""
        if not realm or not model:
            return ""
        owner = exclusive_realm(model)
        if not owner or owner == realm:
            return ""
        name = (self.key_entry or {}).get("name") or "本次请求显式指定的出口"
        served = "国内版" if owner == "cn" else "国际版"
        used = "国内版" if realm == "cn" else "国际版"
        return ("模型 %s 只在%s提供，但「%s」绑定的是%s出口。"
                "请改用对应出口的 Key，或把该 Key 的出口改为「跟随面板切换」。"
                % (model, served, name, used))

    def _banned_model_error(self, model):
        """P1-4 全局封禁：命中即返回文案（不碰上游、不扣任何点数）。"""
        if not is_model_banned(model):
            return ""
        return banned_model_message(model)

    def _key_model_error(self, model):
        """P1-4 每 Key 模型白名单：在请求到达上游之前拒绝。

        未设 models 的 Key 不受限（空列表 = 不限制），因此这是 no-op，
        除非管理员显式配置了限制。
        """
        entry = getattr(self, "key_entry", None)
        if not entry:
            return ""
        if trae_settings.key_allows_model(entry, model):
            return ""
        return key_model_message(entry, model)

    def _key_quota_error(self):
        """P1-5：每 Key 当日请求/Token 配额（0 = 不限制）。

        只读本地 usage 行（10s 缓存），不触发上游；面板会话/未带 key 不受限。
        当前请求尚未记账，因此 used >= limit 就拒绝。
        """
        entry = getattr(self, "key_entry", None) or {}
        req_limit = int(entry.get("daily_requests") or 0)
        tok_limit = int(entry.get("daily_tokens") or 0)
        if req_limit <= 0 and tok_limit <= 0:
            return ""
        kid = str(entry.get("id") or "")
        if not kid:
            return ""
        used_req = used_tok = 0
        try:
            for row in usage_by_key(range="today"):
                if row.get("key_id") == kid:
                    used_req = int(row.get("requests") or 0)
                    used_tok = int(row.get("total_tokens") or 0)
                    break
        except Exception:
            return ""  # fail-open：统计故障不误伤流量
        if req_limit > 0 and used_req >= req_limit:
            return ("API Key「%s」今日请求数已达上限（%d/%d），明日 00:00 重置。"
                    % (entry.get("name") or kid, used_req, req_limit))
        if tok_limit > 0 and used_tok >= tok_limit:
            return ("API Key「%s」今日 Token 已达上限（%d/%d），明日 00:00 重置。"
                    % (entry.get("name") or kid, used_tok, tok_limit))
        return ""

    def _prepare_degrade(self, model, realm):
        """Return (fallback_model, fallback_realm, reason) or None.

        只做预检降级：已配置 fallback 且（模型需升级 / 当前区域额度耗尽）时
        在请求上游前改模型；未知 quota 的首次 4008 仍按正常 429 返回。
        """
        cfg = trae_settings.auto_degrade(ACCOUNTS_DIR)
        if not cfg.get("enabled") or not cfg.get("fallback_model"):
            return None
        fallback = str(cfg.get("fallback_model") or "").strip()
        if not fallback or fallback == model:
            return None
        reason = ""
        if cfg.get("on_upgrade") and _model_needs_upgrade(model, realm):
            reason = "upgrade"
        elif cfg.get("on_quota") and _realm_quota_exhausted(realm):
            reason = "quota"
        if not reason:
            return None
        target = str(cfg.get("fallback_realm") or "").strip().lower()
        if target not in ("intl", "cn"):
            target = detect_model_realm(fallback) or realm
        return fallback, target, reason

    def _model_precheck(self, model, realm):
        """模型级前置拒绝（统一落点，全部在 open_upstream 之前）。

        顺序：跨区错配[既有] -> 全局封禁[P1-4] -> Key 白名单[P1-4]。
        三处请求入口（chat / responses / anthropic messages）**共用本方法**——
        新增入口必须一并挂上，否则会出现「chat 被拦、别的协议绕过」的缺口。
        """
        self._precheck_status = 400
        quota_error = self._key_quota_error()
        if quota_error:
            self._precheck_status = 429
            return quota_error
        return (self._cross_realm_error(model, realm)
                or self._banned_model_error(model)
                or self._key_model_error(model))

    def _request_realm(self, explicit=None):
        """Pick the upstream exit for this request.

        Priority: an explicit ?realm= argument, then the realm bound to the
        API key, then the X-Realm header / ?realm= query, and finally the
        global switch. Returning None lets open_upstream() fall back to
        model-based detection.
        """
        if explicit:
            return explicit
        bound = self._key_realm()
        if bound:
            return bound
        header = self.headers.get("X-Realm")
        if header:
            return header
        try:
            return parse_qs(urlparse(self.path).query).get("realm", [None])[0]
        except Exception:
            return None

    def _effective_realm(self, model):
        """本请求实际出口区域：显式指定/Key 绑定优先，否则按模型归属自动换区。

        背景（自动换区 bug）：三个请求入口此前一律
        `_request_realm() or CURRENT_REALM`，未绑 Key 时恒为 cn；随后
        _model_precheck -> _cross_realm_error 会把 INTL 独占模型判成 400
        「出口错配」，永远走不到 open_upstream 的 detect_model_realm。
        这里把「模型归属」提到预检之前，同时保持：
          · 显式 ?realm= / X-Realm  → 硬约束（错配仍 400）
          · API Key 绑定区域        → 硬约束（错配仍 400）
        """
        explicit = self._request_realm()
        if explicit:
            return trae_realm(explicit)
        if AUTO_REALM_ENABLED:
            auto = detect_model_realm(model)
            if auto:
                return trae_realm(auto)
        return CURRENT_REALM

    def _authorized(self):
        if self._key_ok():
            return True
        self._error(401, "invalid api key", "invalid_request_error")
        return False

    # ---- web panel access ----
    def _panel_token(self):
        """Session token from the X-Panel-Token header.

        Deliberately header-only: a token in the query string leaks through
        browser history, the Referer header and any reverse-proxy access log.
        """
        return (self.headers.get("X-Panel-Token") or "").strip()

    def _panel_ok(self):
        return PANEL.valid(self._panel_token())

    def _client_is_loopback(self):
        """agents 写配置只信 loopback：改的是网关本机的文件。"""
        try:
            host = self.client_address[0]
            return ipaddress.ip_address(host).is_loopback
        except Exception:
            return False

    @staticmethod
    def _is_panel_route(path):
        """Management endpoints shown in the web panel.

        Model listings stay reachable with the API key alone so that plain
        OpenAI clients can keep discovering models.
        """
        if path.startswith("/accounts"):
            return True
        if path.startswith("/usage") or path.startswith("/v1/usage"):
            return True
        if path.startswith("/tasks") or path.startswith("/scheduler"):
            return True
        if path.startswith("/settings"):
            return True
        if path.startswith("/logs"):
            return True
        if path.startswith("/diag"):
            return True
        if path.startswith("/update"):
            return True
        if path.startswith("/agents"):
            # /agents/cli 是唯一的例外：公开只读的配置器源码端点（远程机器
            # curl 取用），面板拦截会挡掉它的目标用户。
            return path != "/agents/cli"
        return False

    def do_OPTIONS(self):
        self.send_response(204)
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        # #26：每个请求入口清空「本次实际出口」标注。self 在 keep-alive 连接上是
        # **复用**的，不清空的话后续非 chat 端点（/v1/models、/usage/*、/realm）
        # 会带回上一次 chat 的残留值 —— 那会让面板把「上一次的出口」当成「本次的」。
        self.realm_used = ""
        self.realm_reason = ""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if self._is_panel_route(path) and not self._panel_ok():
            return self._error(401, "panel password required",
                               "invalid_request_error")
        if path in STATIC_ASSETS:
            return self._static_asset(*STATIC_ASSETS[path])
        if path in ("/", "/dashboard", "/ui"):
            return self._dashboard()
        if path == "/panel/status":
            # 不带 token 也要回答：看板需要先知道是否显示登录页。
            info = {
                "panel_password_required": True,
                "panel_password_is_default":
                    trae_settings.panel_password_is_default(ACCOUNTS_DIR),
                "authenticated": self._panel_ok(),
            }
            info["api_key_set"] = bool(API_KEY)
            return self._json(200, info)
        if path in ("/ping", "/healthz", "/livez", "/readyz"):
            # 极简探活端点：**不需要面板密码/API Key、不查账号池**。
            # 客户端/守护脚本常用 GET /ping 判活，之前返回 404 会被判成
            # “网关不可用” → 反复重连。这里返回纯文本 pong。
            body = b"pong\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if cors_origin_allowed(self.path):
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            return self.wfile.write(body)
        if path == "/agents/cli":
            # 配置器 CLI 源码（远程机器直接 curl 取用，免面板鉴权；
            # 与仓库内 trae_agents.py 逐字节一致）。只读。
            try:
                cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "trae_agents.py")
                with open(cli_path, "rb") as fh:
                    body = fh.read()
            except OSError as exc:
                return self._error(500, "agents cli source unavailable: %s" % exc)
            self.send_response(200)
            self.send_header("Content-Type", "text/x-python; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if cors_origin_allowed(self.path):
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            return self.wfile.write(body)
        if path == "/agents":
            if not self._authorized():
                return
            try:
                return self._json(200, trae_agents.overview(ACCOUNTS_DIR))
            except trae_agents.AgentConfigError as exc:
                return self._error(500, str(exc))
        if path == "/agents/models":
            # 网关自己的模型清单（面板配置页预填用；与 /v1/models 同源字段）
            if not self._authorized():
                return
            realm_q = query.get("realm", [None])[0]
            return self._json(200, gateway_models_for_agents(realm_q))
        if path == "/update/check":
            # 项目新版本检测（看板「运行信息 · 新版本检测」；结果缓存 6h，force=1 强制刷新）
            _u = parse_qs(urlparse(self.path).query)
            try:
                return self._json(200, check_for_update(
                    force=bool(_u.get("force", [None])[0])))
            except Exception as exc:
                return self._error(500, "update check failed: %s" % exc)
        if path == "/diag/vm":
            # 本机虚拟化检测：runtime-info 桥已随账号域重构下线（账号契约由
            # trae_accounts 提供）。这里保留路由，返回结构化「不可用」而不是
            # 404/500，避免老看板轮询时报错刷屏。
            _q = parse_qs(urlparse(self.path).query)
            return self._json(200, {
                "available": False,
                "realm": trae_realm(_q.get("realm", [None])[0] or CURRENT_REALM),
                "vm": None,
                "note": "虚拟化检测随账号域重构下线；风控处置见 /accounts 与日志 tag=chat",
            })
        if path == "/health":
            rep = current_account()
            info = {
                "ok": True,
                "service": "trae2api-hub",
                "version": VERSION,
                "realm": CURRENT_REALM,
                "accounts": len(POOL.accounts) if POOL else 0,
                "accounts_ready": POOL.count_ready() if POOL else 0,
                "api_key_required": bool(API_KEY),
            }
            if self._key_ok():
                info.update({
                    "uid": rep.uid if rep else None,
                    "domain": rep.domain if rep else None,
                    "issuer": "trae" if rep else None,
                    "credential_file": os.path.basename(rep.path)
                    if rep and rep.path else None,
                    "expires_at": rep.expires_at if rep else None,
                })
            return self._json(200, info)
        if path == "/realm":
            # #26：面板需要知道「自动路由是否开着」——mode 由 auto_enabled + current
            # 推导：自动开 = 未显式指定时会按模型/账号可用性兜底换区；否则恒用 current。
            return self._json(200, {"current": CURRENT_REALM,
                                    "options": ["intl", "cn"],
                                    "auto_enabled": bool(AUTO_REALM_ENABLED),
                                    "auto_env": "QD_AUTO_REALM"})
        if path == "/models/discovery":
            if not self._authorized():
                return
            docs = {}
            for realm in ("cn", "intl"):
                doc = load_discovery(realm)
                docs[realm] = {
                    "at": doc.get("at") or 0,
                    "source": doc.get("source") or "",
                    "count": doc.get("count") or 0,
                    "added": doc.get("added") or [],
                    "removed": doc.get("removed") or [],
                    "age_seconds": int(time.time() - float(doc.get("at") or 0))
                    if doc.get("at") else None,
                }
            return self._json(200, {"realms": docs,
                                    "probe": model_health_summary(),
                                    "job": probe_state()})
        if path == "/models/probe/status":
            if not self._authorized():
                return
            return self._json(200, {"job": probe_state(),
                                    "health": model_health_summary()})
        if path == "/models/health":
            if not self._authorized():
                return
            return self._json(200, {"health": trae_probe.load_health(),
                                    "summary": model_health_summary(),
                                    "job": probe_state()})
        if path in ("/v1/models", "/models"):
            if not self._authorized():
                return
            req_realm = self._request_realm() or CURRENT_REALM
            try:
                entries = fetch_models(realm=req_realm)
            except Exception as exc:
                return self._error(502, str(exc))
            merge = str((query.get("merge_realms") or [""])[0]).lower() in (
                "1", "true", "yes", "on")
            if merge:
                # #26 步4：两区并集（**opt-in**）。默认必须保持单区视图 ——
                # 否则 _verify_models 与既有客户端会看到「多出来的」别区模型。
                merged = fetch_models_merged()
                data = [model_entry(mid, meta, realm=r)
                        for mid, meta, r in merged]
                return self._json(200, {
                    "object": "list", "data": data,
                    "realm": "all", "merged": True,
                    "count": len(data),
                    "available_count": sum(1 for m in data
                                           if m.get("available") is True),
                    "realms": ["cn", "intl"]})
            data = [model_entry(mid, meta, realm=req_realm)
                    for mid, meta in entries]
            try:
                try:
                    catalog_source = trae_catalog.available_source(req_realm)
                except Exception:
                    catalog_source = trae_catalog.snapshot_source(req_realm)
            except Exception as exc:   # 只读探针：失败也不能拖垮模型列表
                catalog_source = "unknown"
                log("catalog source probe failed: %s" % exc, level="WARN")
            return self._json(200, {
                "object": "list", "data": data,
                "realm": req_realm or CURRENT_REALM,
                "count": len(data),
                "available_count": sum(1 for m in data
                                       if m.get("available") is True),
                "catalog_source": catalog_source})
        if path in ("/usage", "/v1/usage"):
            if not self._authorized():
                return
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            return self._json(200, usage_snapshot(realm=req_realm))
        if path == "/usage/recent":
            if not self._authorized():
                return
            try:
                limit = max(1, min(1000, int((query.get("limit") or ["100"])[0])))
            except ValueError:
                limit = 100
            try:
                page = max(1, int((query.get("page") or ["1"])[0]))
            except ValueError:
                page = 1
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            return self._json(200, recent_usage(limit, realm=req_realm, page=page))
        if path == "/credits/summary":
            # issue #21：只读积分汇总。**刻意不放进 _is_panel_route** ——
            # 同宿主机轮询方用 API key 即可拉取；实现内绝不触发上游查询
            # （对照 /accounts/credits 的逐号强刷，那个适合手动点击）。
            if not self._authorized():
                return
            return self._json(200, credits_summary())
        if path == "/accounts/credits":
            if not self._authorized():
                return
            # #25：只强刷 enabled 且有凭证的号 —— 禁用号/坏凭证号打上游会被
            # 回一个空账本，把本地账本再零化一次；被跳过的号在 skipped 里可区分。
            targets, skipped = _refreshable_accounts(POOL.accounts if POOL else [])
            for a in targets:
                res = account_fetch_credits(a)
                # 新账号契约：用量/权益快照由 pool.note_usage 统一登记，
                # 手动查询成功后同步一次即可（不再有 mark_manual）。

            return self._json(200, {"accounts": account_views(),
                                    "skipped": skipped,
                                    "refreshed": len(targets)})
        if path == "/accounts":
            if not self._authorized():
                return
            return self._json(200, {
                "accounts": account_views(realm=query.get("realm", [None])[0]
                                          or CURRENT_REALM),
                "storage": ACCOUNTS_DIR,
                "usable": POOL.count_ready() if POOL else 0,
            })
        if path in ("/quota", "/quotas", "/v1/quota"):
            if not self._authorized():
                return
            rows = account_views()
            return self._json(200, {
                "object": "quota",
                "accounts": [{
                    "uid": a.get("uid"),
                    "uidHash": a.get("uidHash"),
                    "realm": a.get("realm"),
                    "intlQuota": a.get("intlQuota"),
                    "intlQuotaState": a.get("intlQuotaState")
                        or _quota_state(a.get("intlQuota")),
                    "cooldownFor": a.get("cooldownFor"),
                } for a in rows],
            })
        if path == "/config/export":
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            doc = {
                "format": "trae2api-config",
                "version": 1,
                "exportedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                "settings": trae_settings.load(ACCOUNTS_DIR),
                "accounts": trae_accounts.build_export_document(
                    POOL.accounts if POOL else [], include_secrets=True),
            }
            if (query.get("download") or ["0"])[0] in ("1", "true", "yes"):
                name = "trae2api-config-%s.json" % time.strftime("%Y%m%d-%H%M%S")
                return self._download(name, doc)
            return self._json(200, doc)
        if path == "/accounts/export":
            if not self._authorized():
                return
            realm = (query.get("realm") or [None])[0] or None
            if realm not in ("intl", "cn"):
                realm = None
            include_secrets = (query.get("secrets") or ["1"])[0] \
                not in ("0", "false", "no")
            uids = []
            for raw in query.get("uid") or []:
                uids.extend(part.strip() for part in str(raw).split(",")
                            if part.strip())
            if uids:
                known = {a.uid for a in (POOL.accounts if POOL else [])}
                missing = [u for u in uids if u not in known]
                if missing:
                    return self._error(404, "no such account: %s"
                                       % ", ".join(missing[:5]),
                                       "invalid_request_error")
            doc = trae_accounts.build_export_document(
                POOL.accounts if POOL else [],
                realm=realm, include_secrets=include_secrets,
                uids=uids or None)
            if (query.get("download") or ["0"])[0] in ("1", "true", "yes"):
                stamp = time.strftime("%Y%m%d-%H%M%S")
                if len(uids) == 1:
                    label = uids[0][:8]
                else:
                    label = realm + "-" if realm else ""
                name = "trae-accounts-%s%s.json" % (label, stamp)
                return self._download(name, doc)
            return self._json(200, doc)
        if path == "/accounts/login/poll":
            if not self._authorized():
                return
            state = (query.get("state") or [""])[0]
            return self._json(200, POOL.poll_login(state))
        if path == "/usage/analytics":
            if not self._authorized():
                return
            # ?range=day|week|month|all|custom&since=&until=（不传 = 历史全量，
            # 输出与改动前逐字节一致；语义见 range_window）
            req_range, req_since, req_until = range_query(query)
            return self._json(200, compute_usage_analytics(
                range=req_range, since=req_since, until=req_until))
        if path == "/usage/by-account":
            if not self._authorized():
                return
            req_range, req_since, req_until = range_query(query)
            return self._json(200, {"accounts": usage_by_account(
                range=req_range, since=req_since, until=req_until)})
        if path == "/usage/by-key":
            if not self._authorized():
                return
            # P1-3 收尾：按 API key 聚合（key_id 已脱敏；缺失归 "(no-key)"）。
            # 与 /usage/by-account 同源同 range —— 同一窗口下两者合计相等。
            req_range, req_since, req_until = range_query(query)
            return self._json(200, {"keys": usage_by_key(
                range=req_range, since=req_since, until=req_until)})
        if path == "/usage/by-key/detail":
            if not self._authorized():
                return
            key_id = (query.get("key_id") or ["(no-key)"])[0]
            try:
                days = int((query.get("days") or ["7"])[0])
            except ValueError:
                days = 7
            detail = usage_key_detail(key_id, days=days)
            entry = None
            for item in trae_settings.api_keys(ACCOUNTS_DIR):
                if str(item.get("id")) == key_id:
                    entry = item
                    break
            detail["key"] = ({
                "id": entry.get("id"), "name": entry.get("name"),
                "realm": entry.get("realm"), "enabled": entry.get("enabled"),
                "models": entry.get("models") or [],
                "daily_requests": entry.get("daily_requests") or 0,
                "daily_tokens": entry.get("daily_tokens") or 0,
            } if entry else None)
            return self._json(200, detail)
        if path == "/usage/perf":
            if not self._authorized():
                return
            try:
                sample = max(10, min(20000,
                                     int((query.get("sample") or ["5000"])[0])))
            except ValueError:
                sample = 5000
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            req_range, req_since, req_until = range_query(query)
            return self._json(200, perf_stats(sample, realm=req_realm,
                                              range=req_range,
                                              since=req_since,
                                              until=req_until))
        if path == "/usage/timeseries":
            if not self._authorized():
                return
            # 时序图：分桶 token/积分序列（桶宽自适应，可 ?bucket= 覆盖）
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            req_range, req_since, req_until = range_query(query)
            return self._json(200, usage_timeseries(
                realm=req_realm, range=req_range, since=req_since,
                until=req_until,
                bucket_seconds=(query.get("bucket") or [None])[0]))
        if path == "/usage/daily":
            if not self._authorized():
                return
            # 7 天 / 30 天堆叠柱状图：日期 × 分组（模型/区域/Key/账号）
            req_realm = query.get("realm", [None])[0] \
                or self.headers.get("X-Realm") or CURRENT_REALM
            return self._json(200, usage_daily(
                days=(query.get("days") or ["7"])[0],
                group=(query.get("group") or ["model"])[0],
                realm=req_realm))
        if path == "/tasks":
            if not self._authorized():
                return
            import trae_tasks
            uid = (query.get("uid") or [None])[0]
            # 账号池与积分按视图分区：?realm=cn|intl 时只列该区域账号
            realm_q = (query.get("realm") or [None])[0]
            if realm_q not in ("cn", "intl"):
                realm_q = None
            view = trae_tasks.fetch_tasks_view(POOL, realm=realm_q, uid=uid)
            if view.get("msg") and not view.get("tasks"):
                return self._json(200, view)
            return self._json(200, view)
        if path == "/scheduler":
            if not self._authorized():
                return
            return self._json(200, SCHEDULER.status() if SCHEDULER
                              else {"enabled": False, "msg": "未运行"})
        if path == "/settings":
            if not self._authorized():
                return
            return self._json(200, runtime_settings_view())
        if path == "/logs":
            if not self._authorized():
                return
            try:
                limit = int(query.get("limit", ["200"])[0])
            except (ValueError, TypeError):
                limit = 200
            level = query.get("level", [""])[0]
            tag = query.get("tag", [""])[0]
            search = query.get("search", [""])[0]
            try:
                since_id = int(query.get("since_id", ["0"])[0])
            except (ValueError, TypeError):
                since_id = 0
            return self._json(200, get_logs(limit=limit, level=level, tag=tag,
                                            search=search, since_id=since_id))
        if path == "/logs/export":
            if not self._authorized():
                return
            log_data = get_logs(limit=5000)
            lines = ["[%s] [%s] [%s] %s" % (item["ts"], item["level"],
                                             item["tag"], item["msg"])
                     for item in log_data["logs"]]
            text_content = "\n".join(lines).encode("utf-8")
            filename = "trae2api-%s.log" % time.strftime("%Y%m%d-%H%M%S")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"' % filename)
            self.send_header("Content-Length", str(len(text_content)))
            if cors_origin_allowed(self.path):
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(text_content)
            return
        if path == "/settings/reveal":
            # 看板只画掩码 Key，复制明文需要显式请求；必须面板会话。
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            if trae_settings.panel_password_is_default(ACCOUNTS_DIR):
                # 默认密码 = 局域网内任何人都能登录；明文 Key 不能这样交出去。
                return self._error(
                    403,
                    "面板仍在使用默认密码，局域网内任何人都能登录后读到明文 API "
                    "Key。请先在「设置 → 面板密码」修改密码，再查看明文 Key。",
                    "permission_error")
            wanted = (query.get("id") or [""])[0]
            for entry in configured_keys():
                if entry.get("id") == wanted:
                    return self._json(200, {"id": wanted,
                                            "key": entry.get("key") or ""})
            return self._error(404, "no such key", "invalid_request_error")
        return self._error(404, "not found", "invalid_request_error")

    def _static_asset(self, filename, content_type):
        """看板静态资源（CSS/JS）；白名单固定文件名，不暴露目录遍历。"""
        base = os.path.dirname(DASHBOARD_HTML)
        target = os.path.join(base, filename)
        try:
            with open(target, "rb") as fh:
                body = fh.read()
        except Exception as exc:
            return self._error(404, "asset unavailable: %s" % exc)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _dashboard(self):
        try:
            with open(DASHBOARD_HTML, "rb") as fh:
                body = fh.read()
        except Exception as exc:
            return self._error(500, "dashboard.html unavailable: %s" % exc)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_payload(self, max_bytes=MAX_PAYLOAD_BYTES, allow_list=False):
        """Parse the request body into a dict (or a list when allow_list)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length > max_bytes:
            raise BodyTooLarge(length)
        if length < 0:
            raise BadJSON()
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(raw or "{}")
        except Exception:
            raise BadJSON()
        if isinstance(data, dict):
            return data
        if allow_list and isinstance(data, list):
            return data
        return {}

    def _payload_or_error(self, allow_list=False):
        """Read the body, replying with the right error and returning None."""
        try:
            return self._read_payload(allow_list=allow_list)
        except BodyTooLarge as exc:
            self._error(413, "payload too large (%d bytes > %d limit)"
                        % (exc.length, MAX_PAYLOAD_BYTES),
                        "invalid_request_error")
            return None
        except BadJSON:
            self._error(400, "invalid JSON body", "invalid_request_error")
            return None

    def _handle_settings_save(self):
        """Persist panel-managed settings from the web settings tab."""
        payload = self._payload_or_error()
        if payload is None:
            return
        reply = {}
        if "api_keys" in payload:
            raw = payload.get("api_keys")
            if not isinstance(raw, list):
                return self._error(400, "api_keys must be a list",
                                   "invalid_request_error")
            # 面板只画掩码 Key：空值表示“保留原值”，不是“清空”。
            existing = {entry.get("id"): entry for entry in configured_keys()}
            cleaned = []
            for index, item in enumerate(raw):
                if not isinstance(item, dict):
                    return self._error(400, "each api key must be an object",
                                       "invalid_request_error")
                entry_id = str(item.get("id") or "").strip()
                value = str(item.get("key") or "").strip()
                if not value and entry_id and entry_id in existing:
                    value = existing[entry_id].get("key") or ""
                if not entry_id:
                    entry_id = "k%d" % index
                if value and len(value) < 4:
                    return self._error(400,
                                       "api key must be at least 4 characters",
                                       "invalid_request_error")
                if not value:
                    return self._error(400,
                                       "a key entry is empty - fill it in or "
                                       "remove the row",
                                       "invalid_request_error")
                realm = str(item.get("realm") or "").strip().lower()
                if realm not in ("", "intl", "cn"):
                    return self._error(400, "realm must be intl, cn or empty",
                                       "invalid_request_error")
                created_at = item.get("created_at") \
                    or (existing.get(entry_id, {}).get("created_at")
                        if entry_id in existing else None) \
                    or time.strftime("%Y/%m/%d %H:%M")
                cleaned.append({
                    "id": entry_id,
                    "name": str(item.get("name") or "").strip(),
                    "key": value,
                    "realm": realm,
                    "enabled": item.get("enabled", True) is not False,
                    "created_at": created_at,
                    # P1-4：每 Key 模型白名单（原样透传；规范化统一在
                    # trae_settings._clean_key_entry 一处完成）。
                    "models": item.get("models"),
                    "daily_requests": item.get("daily_requests"),
                    "daily_tokens": item.get("daily_tokens"),
                })
            trae_settings.set_api_keys(ACCOUNTS_DIR, cleaned)
            reply["api_keys_saved"] = len(cleaned)
        if "banned_models" in payload:
            # P1-4：全局封禁列表（逗号/分号/换行分隔均可，清洗在 trae_settings）。
            reply["banned_models"] = trae_settings.set_banned_models(
                ACCOUNTS_DIR, payload.get("banned_models"))
        if "auto_degrade" in payload:
            raw_auto = payload.get("auto_degrade")
            if not isinstance(raw_auto, dict):
                return self._error(400, "auto_degrade must be an object",
                                   "invalid_request_error")
            reply["auto_degrade"] = trae_settings.set_auto_degrade(
                ACCOUNTS_DIR, raw_auto)
        if "auth_disabled" in payload:
            trae_settings.set_auth_disabled(ACCOUNTS_DIR,
                                             payload.get("auth_disabled"))
            reply["auth_disabled"] = bool(payload.get("auth_disabled"))
        new_key = payload.get("api_key")
        if new_key is not None:
            new_key = str(new_key).strip()
            if new_key and len(new_key) < 4:
                return self._error(400, "api key must be at least 4 characters",
                                   "invalid_request_error")
            global API_KEY, API_KEY_FILE_SET
            trae_settings.set_api_key(ACCOUNTS_DIR, new_key)
            API_KEY = new_key
            API_KEY_FILE_SET = True
            reply["api_key_set"] = bool(new_key)
        if "limits" in payload:
            raw_limits = payload.get("limits")
            if not isinstance(raw_limits, dict):
                return self._error(400, "limits must be an object",
                                   "invalid_request_error")
            # 先全量校验、后落盘：避免一半合法一半 400 时留下部分应用。
            updates = []
            for key, scopes in raw_limits.items():
                if key not in trae_settings.LIMIT_KEYS:
                    return self._error(400, "unknown limit: %s" % key,
                                       "invalid_request_error")
                if not isinstance(scopes, dict):
                    return self._error(400, "limits.%s must be an object" % key,
                                       "invalid_request_error")
                for scope, value in scopes.items():
                    if scope not in trae_settings.LIMIT_SCOPES:
                        return self._error(400, "unknown scope: %s" % scope,
                                           "invalid_request_error")
                    updates.append((key, scope, value))
            for key, scope, value in updates:
                trae_settings.set_limit(ACCOUNTS_DIR, key, scope, value)
            reply["limits"] = trae_settings.limits_data(ACCOUNTS_DIR)
            # task-61：保存后立刻推给池（阈值 + free 名单同批），让配置真正生效；
            # 推完若某个阈值 > 0，池会自行惰性启动后台余额刷新线程。
            try:
                POOL.apply_settings(limits_data=reply["limits"],
                                    free_models=free_model_names(CURRENT_REALM))
            except Exception as exc:
                reply["limits_apply_error"] = str(exc)
                log("quota limits apply failed after save: %s" % exc,
                    level="WARN")
        if payload.get("restart_scheduler"):
            if SCHEDULER:
                SCHEDULER.stop()
                SCHEDULER.start()
            reply["scheduler"] = "restarted"
        reply.update(runtime_settings_view())
        return self._json(200, reply)

    def _handle_panel(self, path):
        """Panel login, logout and the settings screen (password)."""
        payload = self._payload_or_error()
        if payload is None:
            return
        if path == "/panel/login":
            client_ip = self.client_address[0] \
                if hasattr(self, "client_address") and self.client_address \
                else "127.0.0.1"
            now = time.time()
            with _login_lock:
                _prune_login_attempts(now)
                attempts = [t for t in _login_attempts.get(client_ip, [])
                            if now - t < 60]
                _login_attempts[client_ip] = attempts
                if len(attempts) >= 5:
                    wait_sec = int(60 - (now - attempts[0]))
                    return self._error(429,
                                       "too many login attempts, please wait %ds"
                                       % max(1, wait_sec),
                                       "rate_limit_error")
            password = str(payload.get("password") or "")
            if not trae_settings.verify_panel_password(ACCOUNTS_DIR, password):
                with _login_lock:
                    _login_attempts.setdefault(client_ip, []).append(now)
                time.sleep(0.5)   # 撞库缓解
                return self._error(401, "invalid panel password",
                                   "invalid_request_error")
            with _login_lock:
                _login_attempts.pop(client_ip, None)
            token = PANEL.create()
            return self._json(200, {
                "ok": True,
                "token": token,
                "using_default_password":
                    trae_settings.panel_password_is_default(ACCOUNTS_DIR),
            })
        if path == "/panel/logout":
            # 退出登录不能只往内存黑名单里写一笔：那份 dict 重启即丢，已退出的
            # token 会活到 TTL（7 天）结束——比改动前的「重启全清」更差。
            # 直接换密钥：本 token 与其它浏览器的会话一起作废。本地单人面板无感，
            # 多人/局域网场景反而更安全。
            PANEL.revoke_all()
            return self._json(200, {"ok": True})
        # 之后所有路由都要面板会话
        if not self._panel_ok():
            return self._error(401, "panel password required",
                               "invalid_request_error")
        if path == "/panel/password":
            current = str(payload.get("current") or "")
            new = str(payload.get("new") or "")
            if not trae_settings.verify_panel_password(ACCOUNTS_DIR, current):
                # issue #41：原密码错是**业务校验失败**，不是会话失效。
                # 401 会让前端弹回登录遮罩（用户看到「登录 UI」而不是原因）；
                # 403 保持「已登录但不允许」的语义，前端直接显示 msg。
                return self._error(403, "当前密码不正确",
                                   "invalid_request_error")
            if len(new) < 4:
                return self._error(400, "new password must be at least 4 characters",
                                   "invalid_request_error")
            trae_settings.set_panel_password(ACCOUNTS_DIR, new)
            if new != trae_settings.DEFAULT_PANEL_PASSWORD:
                # 换密码使其它浏览器会话全部失效
                PANEL.revoke_all()
            token = PANEL.create()
            return self._json(200, {"ok": True, "token": token})
        return self._error(404, "not found", "invalid_request_error")

    def _handle_accounts(self, path, payload):
        """Account-management endpoints (dashboard uses these)."""
        if POOL is None:
            return self._error(503, "account pool unavailable")
        if path == "/accounts/import" and isinstance(payload, list):
            payload = {"data": payload}
        if not isinstance(payload, dict):
            return self._error(400, "expected a JSON object",
                               "invalid_request_error")
        if path in ("/accounts/credits", "/accounts/credits/fetch"):
            uid = payload.get("uid")
            realm = payload.get("realm")
            if uid:
                targets = [POOL.get(uid)]
            elif realm and realm != "all":
                targets = [a for a in POOL.accounts if a.realm == realm]
            else:
                targets = list(POOL.accounts)
            # #25：与 GET 同一条守卫（显式 uid 指向禁用号时也会落到 skipped）
            targets, skipped = _refreshable_accounts(targets)
            results = []
            for account in targets:
                res = account_fetch_credits(account)
                account_fetch_plan(account)
                results.append({"uid": account.uid, "ok": res.get("ok", False),
                                "credits": res.get("credits") or account_credit_view(account),
                                "plan": account.plan,
                                "errors": res.get("errors") or [],
                                "error": "; ".join(res.get("errors") or [])[:200]})
            return self._json(200, {"results": results, "skipped": skipped,
                                    "accounts": account_views()})
        if path == "/models/discover":
            if not self._authorized():
                return
            realm = payload.get("realm") or CURRENT_REALM
            try:
                result = refresh_model_discovery(realm)
            except Exception as exc:
                return self._error(502, "model discovery failed: %s" % exc)
            return self._json(200, result)
        if path == "/models/probe":
            if not self._authorized():
                return
            scope = payload.get("scope") or "current"
            if scope not in ("current", "all"):
                scope = "current"
            try:
                limit = int(payload.get("limit") or 0)
            except (TypeError, ValueError):
                limit = 0
            result = start_model_probe(scope=scope, limit=limit,
                                       force=bool(payload.get("force")))
            return self._json(200, result)
        if path == "/tasks/run":
            import trae_tasks
            if not POOL:
                return self._json(200, {"ok": False, "msg": "账号池不可用"})
            uid = payload.get("uid")
            if uid and uid != "all":
                target = POOL.get(uid)
                if not target:
                    return self._json(200, {"ok": False,
                                            "msg": "未找到指定的账号"})
                targets = [target]
            else:
                # 不再按区域过滤：签到能力运行时探测，接口不存在的账号会在
                # 日志里给出明确原因（历史问题：国际版点签到完全没反应）。
                targets = [a for a in POOL.accounts
                           if a.enabled and a.access_token]
            if not targets:
                return self._json(200, {"ok": False, "msg": "未找到可用账号（账号已禁用或缺少凭证）"})
            res = trae_tasks.run_batch_checkin(targets, gap=1.0)
            trae_tasks.invalidate_panel_cache()   # 写操作后失效面板短缓存
            return self._json(200, {
                "ok": res["ok"],
                "credit_added": res["credit_added"],
                "logs": res["logs"],
                "accounts_count": res["accounts_count"],
            })
        if path == "/tasks/travel":
            # 看板福利按钮的对应动作：批量领取 Pro 福利包（官方仅国内版 sash 活动）
            import trae_tasks
            if not POOL:
                return self._json(200, {"ok": False, "msg": "账号池不可用"})
            uid = payload.get("uid")
            if uid and uid != "all":
                target = POOL.get(uid)
                if not target:
                    return self._json(200, {"ok": False,
                                            "msg": "未找到指定的账号"})
                targets = [target]
            else:
                targets = [a for a in POOL.accounts
                           if a.enabled and a.access_token]
            if not targets:
                return self._json(200, {"ok": False, "msg": "未找到可用账号（账号已禁用或缺少凭证）"})
            res = trae_tasks.run_batch_pro_claim(targets)
            trae_tasks.invalidate_panel_cache()   # 写操作后失效面板短缓存
            return self._json(200, {
                "ok": True,
                "results": res["results"],
                "msg": res["msg"],
                "logs": res["logs"],
                "accounts_count": res["accounts_count"],
            })
        if path == "/scheduler/trigger":
            if SCHEDULER:
                return self._json(200, SCHEDULER.trigger_now())
            return self._json(200, {"ok": False, "msg": "调度器未初始化"})
        if path == "/scheduler/toggle":
            if SCHEDULER:
                SCHEDULER.enabled = not SCHEDULER.enabled
                SCHEDULER.log("用户切换调度器状态为: %s"
                              % ("启用" if SCHEDULER.enabled else "暂停"))
                return self._json(200, SCHEDULER.status())
            return self._json(200, {"ok": False, "msg": "调度器未初始化"})
        if path == "/logs/clear":
            clear_logs()
            return self._json(200, {"ok": True})
        if path == "/realm":
            new_realm = payload.get("realm")
            if new_realm in ("intl", "cn"):
                save_persisted_realm(new_realm)
            return self._json(200, {"ok": True, "current": CURRENT_REALM,
                                    "persisted": True})
        if path == "/accounts/checkin":
            # 账号面板的「每日签到」按钮：**只做每日签到领积分**——Credits 类活动
            # （如"每天领 100 Credits"，旧 sash 接口兜底），不领券/兑换码类活动，
            # 也不领 Pro 福利包（那些走签到与福利中心的按钮）。
            import trae_tasks
            uid = payload.get("uid")
            targets = [POOL.get(uid)] if uid else list(POOL.accounts)
            results = []
            last_at = None
            for account in targets:
                if account is None:
                    continue
                if not account.enabled or not account.access_token:
                    continue            # 跳过的账号不占用防风控等待
                if last_at is not None:
                    # 账号之间保持 >= CHECKIN_MIN_GAP（与 trae_tasks.py 声明的
                    # >=1.0s 一致）；try/finally 让失败路径同样计时间隔。
                    idle = CHECKIN_MIN_GAP - (time.time() - last_at)
                    if idle > 0:
                        time.sleep(idle)
                try:
                    res = trae_tasks.run_checkin(account, gap=CHECKIN_MIN_GAP,
                                                  only_daily=True)
                finally:
                    last_at = time.time()
                results.append({
                    "uid": account.uid,
                    "nickname": account_label(account),
                    "ok": bool(res.get("ok")),
                    "earned_credit": res.get("earned_credit") or 0,
                    "msg": (res.get("logs") or [""])[-1],
                    "logs": res.get("logs") or [],
                    "credits": res.get("credits"),
                    # issue #20：透传 trae_tasks 的精确结论（前端一直在读
                    # message / claimed / next_available_*，此前永远 undefined）。
                    # 新增而非替换：msg/logs/credits 原样保留。naonao 的契约
                    # （trae_tasks 活动平台路径）保证 claimed 是**字符串列表**；
                    # 老路径（旧 sash 兜底）不带该键 -> 这里统一给 []，
                    # 让前端只需 Array.isArray 判定，不用再判 None。
                    # message / next_available_* 缺失时仍为 None（不编造）。
                    "message": res.get("message"),
                    "claimed": res.get("claimed") or [],
                    "next_available_at": res.get("next_available_at"),
                    "next_available_note": res.get("next_available_note"),
                })
            trae_tasks.invalidate_panel_cache()   # 写操作后失效面板短缓存
            return self._json(200, {"results": results,
                                    "accounts": account_views()})
        if path == "/accounts/login/start":
            platform = payload.get("platform") or "CLI"
            target_realm = payload.get("realm") or CURRENT_REALM
            if target_realm not in ("intl", "cn"):
                target_realm = "cn"
            try:
                started = POOL.start_login(realm=target_realm,
                                           platform=platform)
            except Exception as exc:
                return self._error(502, "could not start login: %s" % exc)
            log("oauth device login started (realm=%s, state=%s)"
                % (target_realm, started["state"][:8]))
            return self._json(200, started)
        if path == "/accounts/login/cancel":
            state = payload.get("state") or ""
            return self._json(200, {"cancelled": POOL.cancel_login(state)})
        if path == "/accounts/import/pat":
            pat = payload.get("pat") or ""
            realm = payload.get("realm") or CURRENT_REALM
            if realm not in ("intl", "cn"):
                realm = "cn"
            # 账号域重构中：新方法 add_from_refresh 优先，旧 import_pat 兜底，
            # 两者都缺时明确 501（而不是 500 堆栈）。
            add = getattr(POOL, "add_from_refresh", None) or \
                getattr(POOL, "import_pat", None)
            if not callable(add):
                return self._error(
                    501, "account import is unavailable in this build "
                         "(account pool has neither add_from_refresh nor "
                         "import_pat)", "invalid_request_error")
            try:
                account = add(pat, realm=realm)
            except Exception as exc:
                return self._error(400, "PAT import failed: %s" % exc)
            log("imported PAT account %s (realm=%s)"
                % (account.uid[:8], realm))
            return self._json(200, {"imported": [account.public()],
                                    "accounts": account_views()})
        if path == "/accounts/import/desktop":
            # 两步确认：{} 只读扫描（双区：桌面 App auth.v1.dat + CLI user）；
            # {"path":...} 按确认导入该凭证；{"all":true} 导入全部有效项。
            target_path = payload.get("path")
            if target_path:
                realm = payload.get("realm")
                try:
                    account = trae_accounts.import_desktop_credential(
                        path=target_path, realm=realm)
                except Exception as exc:
                    return self._error(400, "import failed: %s" % exc)
                log("imported %s (%s) from local client credential"
                    % (account.uid[:8], account.realm), tag="accounts")
                return self._json(200, {
                    "imported": [account.public()],
                    "accounts": account_views(),
                    "pool_uids": [a.uid for a in POOL.accounts],
                })
            if payload.get("all"):
                try:
                    imported = trae_accounts.import_desktop_credential()
                except Exception as exc:
                    return self._error(400, "import failed: %s" % exc)
                for account in imported:
                    log("imported %s (%s) from local client credential"
                        % (account.uid[:8], account.realm), tag="accounts")
                return self._json(200, {
                    "imported": [a.public() for a in imported],
                    "accounts": account_views(),
                    "pool_uids": [a.uid for a in POOL.accounts],
                })
            try:
                detected = trae_accounts.scan_desktop_credentials()
            except Exception as exc:
                detected = []
                log("desktop credential scan failed: %s" % exc)
            return self._json(200, {
                "detected": detected,
                "accounts": account_views(),
                "pool_uids": [a.uid for a in POOL.accounts],
            })
        if path == "/accounts/refresh":
            uid = payload.get("uid")
            targets = [POOL.get(uid)] if uid else list(POOL.accounts)
            # #25：第三个同类入口 —— 同样只对 enabled 且有凭证的号打上游
            # （refresh 会打 OAuth 端点并 save 落盘，对禁用号纯属副作用）。
            targets, skipped = _refreshable_accounts(targets)
            results = []
            for account in targets:
                ok = account.refresh()
                account.save(ACCOUNTS_DIR)
                results.append({"uid": account.uid, "ok": ok,
                                "error": account.last_error})
            return self._json(200, {"results": results, "skipped": skipped})
        if path == "/accounts/test":
            uid = payload.get("uid")
            if not uid:
                return self._error(400, "uid required")
            account = POOL.get(uid)
            if not account:
                return self._error(404, "no such account")
            test_model = payload.get("model") or "auto"
            test_payload = {
                "model": test_model,
                "messages": [{"role": "user", "content": "hi"}],
                "stream": False,
            }
            t0 = time.time()
            try:
                resp, acc, _ = open_upstream(test_payload, target_realm=acc_realm(account))
                with resp:
                    chat_obj = aggregate_stream(resp, test_model, None)
                wall_ms = int((time.time() - t0) * 1000)
                choices = chat_obj.get("choices") or []
                msg = (choices[0].get("message") or {}) if choices else {}
                reply_text = (msg.get("content") or msg.get("reasoning_content")
                              or "OK").strip()
                if len(reply_text) > 80:
                    reply_text = reply_text[:77] + "..."
                account.clear_error()
                log("account test: uid=%s model=%s wall=%dms ok=True"
                    % (account.uid[:8], test_model, wall_ms), tag="accounts")
                return self._json(200, {"ok": True, "uid": account.uid,
                                        "model": test_model,
                                        "elapsed_ms": wall_ms,
                                        "reply": reply_text})
            except RateLimited as exc:
                wall_ms = int((time.time() - t0) * 1000)
                return self._json(200, {"ok": False, "uid": account.uid,
                                        "status": 429,
                                        "error": "rate limited: %s" % exc.detail[:150],
                                        "elapsed_ms": wall_ms})
            except urllib.error.HTTPError as exc:
                wall_ms = int((time.time() - t0) * 1000)
                try:
                    detail = exc.read(400).decode("utf-8", "replace")
                except Exception:
                    detail = ""
                account.note_error("HTTP %d: %s" % (exc.code, detail[:80]),
                                   cooldown=60)
                log("account test: uid=%s model=%s wall=%dms error=%d"
                    % (account.uid[:8], test_model, wall_ms, exc.code),
                    level="WARN", tag="accounts")
                return self._json(200, {"ok": False, "uid": account.uid,
                                        "status": exc.code,
                                        "error": "HTTP %d: %s"
                                        % (exc.code, detail[:150]),
                                        "elapsed_ms": wall_ms})
            except Exception as exc:
                wall_ms = int((time.time() - t0) * 1000)
                account.note_error(str(exc)[:80], cooldown=60)
                log("account test: uid=%s model=%s wall=%dms exc=%s"
                    % (account.uid[:8], test_model, wall_ms, exc),
                    level="WARN", tag="accounts")
                return self._json(200, {"ok": False, "uid": account.uid,
                                        "status": 500, "error": str(exc),
                                        "elapsed_ms": wall_ms})
        if path == "/accounts/set":
            uid = payload.get("uid")
            if not uid:
                return self._error(400, "uid required")
            updated = POOL.set_enabled(uid, bool(payload.get("enabled")))
            if updated is None:
                return self._error(404, "no such account")
            log("account %s %s" % (uid[:8],
                                   "enabled" if payload.get("enabled")
                                   else "disabled"))
            return self._json(200, {"account": updated})
        if path == "/accounts/set-all":
            POOL.set_all_enabled(bool(payload.get("enabled")))
            return self._json(200, {"accounts": account_views()})
        if path == "/accounts/delete":
            uid = payload.get("uid")
            if not uid:
                return self._error(400, "uid required")
            removed = POOL.remove(uid)
            log("account %s deleted" % uid[:8])
            return self._json(200, {"deleted": removed,
                                    "accounts": account_views()})
        if path == "/accounts/import":
            # 支持的文档形态见 trae_accounts._coerce_account_rows。
            # 选项：dryRun / overwrite / realm ("intl"|"cn")
            blob = payload.get("data") if "data" in payload else payload
            if not isinstance(blob, (dict, list)):
                return self._error(400, "the document must be a JSON object "
                                   "or array", "invalid_request_error")
            rows, problem = trae_accounts._coerce_account_rows(blob)
            if problem:
                return self._error(400, "cannot read the document: %s" % problem,
                                   "invalid_request_error")
            dry_run = bool(payload.get("dryRun"))
            overwrite = bool(payload.get("overwrite"))
            forced_realm = (payload.get("realm") or "").strip().lower() or None
            if forced_realm and forced_realm not in ("intl", "cn"):
                return self._error(400, "realm must be intl or cn",
                                   "invalid_request_error")
            if dry_run:
                return self._json(200, {
                    "dryRun": True,
                    "count": len(rows),
                    "result": POOL.preview_import_rows(rows, realm=forced_realm,
                                                       overwrite=overwrite),
                    "accounts": account_views(),
                })
            report = POOL.import_rows(rows, realm=forced_realm,
                                      overwrite=overwrite)
            log("account import: %d added, %d updated, %d skipped, %d invalid"
                % (len(report["added"]), len(report["updated"]),
                   len(report["skipped"]), len(report["invalid"])))
            return self._json(200, {
                "count": len(rows),
                "result": report,
                "accounts": account_views(),
            })
        return self._error(404, "unknown account endpoint",
                           "invalid_request_error")

    def _handle_anthropic(self, path, payload):
        """Anthropic /v1/messages（task-78 接线；设计文档 .team/72-ANTHROPIC-BRIDGE-DESIGN.md §7）。

        三条易错点逐条落地：
          1) 形态决策**只算一次**（写进 chat_req["_qd_structured"] 下传）；
          2) 流式守卫链与 chat 链逐字一致，allowed_names 取**转换后的 chat_req**；
          3) 出站只做协议翻译，不在本层重写吞掉/回读。
        能力差异（有意）：流式**不做流内信封重开** —— Anthropic 客户端对重复
        message_start 的容忍度未知，宁可给明确的 event: error 收尾；非流式仍走
        aggregate_with_envelope_retry（此时尚未向客户端写任何字节，重试安全）。
        """
        if path.endswith("/count_tokens"):
            # 纯本地估算：**不发上游**（判据 4）
            return self._json(
                200, trae_anthropic.estimate_anthropic_tokens(payload))
        ok, problem = trae_anthropic.validate_request(payload)
        if not ok:
            return self._error(400, problem, "invalid_request_error")
        model_hint = payload.get("model") or "auto"
        # 自动换区：未显式指定且未绑 Key 时，按模型归属决定出口
        req_realm = self._effective_realm(model_hint)
        model_key = trae_catalog.resolve_upstream_key(model_hint, realm=req_realm)
        # 传 supported 档位表，否则 effort_from_anthropic 会静默丢弃思考档位。
        meta = catalog_meta_for(model_key, req_realm)
        chat_req = trae_anthropic.messages_to_chat(
            payload, catalog_meta=meta, supported=supported_efforts(meta))
        model = chat_req.get("model") or payload.get("model") or "auto"
        want_stream = bool(payload.get("stream"))
        session_key = extract_session_key(self.headers, chat_req)
        fp = prompt_fingerprint(chat_req.get("messages"))
        t_start = time.time()
        # ---- 形态决策单点：在这里算唯一一次，随 chat_req 下传 ----
        chat_req["_qd_structured"] = structured_tool_history_enabled(
            model=model, model_key=model_key, realm=req_realm,
            messages=chat_req.get("messages"))
        holder = {"usage": None, "requested_model": model,
                  "allowed_names": _tool_names_from_payload(chat_req)}
        log("anthropic: model=%s stream=%s msgs=%d effort=%r structured=%s"
            % (model, want_stream, len(chat_req.get("messages") or []),
               chat_req.get("reasoning_effort"),
               bool(chat_req.get("_qd_structured"))))
        try:
            usage_ctx = {}
            deg = self._prepare_degrade(chat_req.get("model") or model, req_realm)
            if deg:
                _orig = chat_req.get("model") or model
                chat_req["model"], req_realm, _why = deg
                model = chat_req["model"]
                model_key = trae_catalog.resolve_upstream_key(model, realm=req_realm)
                self.degraded_from = "%s -> %s (%s)" % (_orig, model, _why)
            blocked = self._model_precheck(chat_req.get("model"), req_realm)
            if blocked:
                _st = int(getattr(self, "_precheck_status", 400) or 400)
                return self._error(_st, blocked,
                                   "quota_exceeded" if _st == 429
                                   else "invalid_request_error")
            upstream, account, _ = open_upstream(
                chat_req, session_key=session_key, target_realm=req_realm,
                usage_ctx=usage_ctx)
            # #26：记录实际出口（自动路由后可能与 req_realm 不同）→ 响应头可见
            self.realm_used = usage_ctx.get("realm") or req_realm
            self.realm_reason = usage_ctx.get("realm_reason") or ""
            holder["account"] = account
        except QuotaBlocked as exc:
            record_error(model, 429, exc.message[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000))
            log("request blocked by quota guard: model=%s %s"
                % (model, exc.message[:200]), level="WARN", tag="chat")
            return self._quota_error(exc)
        except RateLimited as exc:
            record_error(model, 429, exc.detail[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000))
            return self._rate_limited(exc)
        except urllib.error.HTTPError as exc:
            detail = getattr(exc, "trae_detail", "") or getattr(exc, "qoder_detail", "")
            if not detail:
                try:
                    detail = exc.read(600).decode("utf-8", "replace")
                except Exception:
                    detail = ""
            record_error(model, exc.code, detail,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            msg, etype = friendly_upstream_error(exc.code, detail)
            return self._error(exc.code, msg, etype)
        except Exception as exc:
            message = str(exc)
            record_error(model, 502, message,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            if message.startswith("no usable account"):
                return self._error(503, message
                                   + " - add or enable one at the dashboard (/)")
            return self._error(502, "upstream unreachable: %s" % exc)
        with upstream:
            if want_stream:
                self._sse_begin()
                first_ms = None
                try:
                    # 守卫链与 chat 主链路**逐字一致**（顺序与参数都不能改）：
                    #   sse_with_heartbeat(recover_leaked_tool_calls(
                    #       iter_inner_sse(...), allowed_names=...))
                    # allowed_names 必须来自**转换后的 chat_req**；用 Anthropic
                    # 原始 payload 会取不到工具名 -> 回读守卫失效 -> #9/#11 泄漏回归。
                    inner = sse_with_heartbeat(
                        recover_leaked_tool_calls(
                            iter_inner_sse(upstream, holder=holder),
                            allowed_names=_tool_names_from_payload(chat_req)),
                        self._sse_write)
                    for frame in trae_anthropic.stream_anthropic_events(
                            inner, model, holder):
                        if first_ms is None:
                            first_ms = int((time.time() - t_start) * 1000)
                        self._sse_write(frame)
                except (BrokenPipeError, ConnectionResetError,
                        ConnectionAbortedError):
                    wall = int((time.time() - t_start) * 1000)
                    record_usage(model, holder.get("usage"), stream=True,
                                 elapsed_ms=wall, ttft_ms=first_ms,
                                 gen_ms=(wall - first_ms)
                                 if first_ms is not None else None,
                                 fp=fp, account=account.uid,
                                 effort=usage_ctx.get("effort"),
                                 effort_requested=usage_ctx.get("effort_requested"),
                                 key_id=self._key_id_for_usage(),
                                 realm_reason=usage_ctx.get("realm_reason", ""))
                    return
                except UpstreamStatus as exc:
                    # Anthropic 侧不重开（见 docstring）：直接给终态 error 事件。
                    _handle_envelope_account_cooldown(account, exc, model=model,
                                                      session_key=session_key)
                    wall = int((time.time() - t_start) * 1000)
                    record_error(model, exc.status, exc.detail, elapsed_ms=wall)
                    msg, _ = friendly_upstream_error(_to_int_status(exc.status),
                                                     exc.detail)
                    log("anthropic upstream status %s: %s"
                        % (exc.status, msg[:200]), level="ERROR", tag="chat")
                    self._sse_write(trae_anthropic.anthropic_error_frame(msg))
                    self._sse_end()
                    return
                self._sse_end()
                wall = int((time.time() - t_start) * 1000)
                record_usage(model, holder.get("usage"), stream=True,
                             elapsed_ms=wall, ttft_ms=first_ms,
                             gen_ms=(wall - first_ms)
                             if first_ms is not None else None,
                             fp=fp, account=account.uid,
                             effort=usage_ctx.get("effort"),
                             effort_requested=usage_ctx.get("effort_requested"),
                             key_id=self._key_id_for_usage(),
                             realm_reason=usage_ctx.get("realm_reason", ""))
                return
            try:
                chat_obj, account = aggregate_with_envelope_retry(
                    upstream, chat_req, session_key, req_realm, model,
                    holder, account)
            except UpstreamStatus as exc:
                record_error(model, exc.status, exc.detail,
                             elapsed_ms=int((time.time() - t_start) * 1000))
                msg, etype = friendly_upstream_error(_to_int_status(exc.status),
                                                     exc.detail)
                return self._error(
                    exc.status if str(exc.status).isdigit() else 502, msg, etype)
            except Exception as exc:
                record_error(model, 502, str(exc),
                             elapsed_ms=int((time.time() - t_start) * 1000))
                return self._error(502, "upstream stream error: %s" % exc)
            wall = int((time.time() - t_start) * 1000)
            result = trae_anthropic.chat_to_messages(chat_obj, model=model)
            record_usage(model, chat_obj.get("usage"), stream=False,
                         elapsed_ms=wall, fp=fp, account=account.uid,
                         effort=usage_ctx.get("effort"),
                         effort_requested=usage_ctx.get("effort_requested"),
                         key_id=self._key_id_for_usage(),
                         realm_reason=usage_ctx.get("realm_reason", ""))
            return self._json(200, result)

    def _handle_responses(self, payload):
        """Serve /v1/responses by translating to chat completions upstream."""
        session_key = extract_session_key(self.headers, payload)
        custom_names = custom_tool_names(payload.get("tools"))
        chat_req = responses_to_chat(payload)
        model = payload.get("model") or "auto"
        want_stream = bool(payload.get("stream"))
        t_start = time.time()
        fp = prompt_fingerprint(chat_req.get("messages"))
        log("responses: model=%s stream=%s msgs=%d effort=%r custom_tools=%s"
            % (model, want_stream, len(chat_req.get("messages") or []),
               chat_req.get("reasoning_effort"),
               sorted(custom_names) or "-"))
        holder = {"usage": None, "requested_model": model,
                  "custom_names": custom_names,
                  "allowed_names": _tool_names_from_payload(chat_req)}
        try:
            # 自动换区：同上（Responses 的模型在 chat_req 里）
            req_realm = self._effective_realm(chat_req.get("model") or model)
            usage_ctx = {}          # P1-3：推理档位审计出参（下传给 open_upstream）
            deg = self._prepare_degrade(chat_req.get("model") or model, req_realm)
            if deg:
                _orig = chat_req.get("model") or model
                chat_req["model"], req_realm, _why = deg
                model = chat_req["model"]
                self.degraded_from = "%s -> %s (%s)" % (_orig, model, _why)
            blocked = self._model_precheck(chat_req.get("model"), req_realm)
            if blocked:
                _st = int(getattr(self, "_precheck_status", 400) or 400)
                return self._error(_st, blocked,
                                   "quota_exceeded" if _st == 429
                                   else "invalid_request_error")
            upstream, account, _ = open_upstream(
                chat_req, session_key=session_key, target_realm=req_realm,
                usage_ctx=usage_ctx)
            # #26：记录实际出口（自动路由后可能与 req_realm 不同）→ 响应头可见
            self.realm_used = usage_ctx.get("realm") or req_realm
            self.realm_reason = usage_ctx.get("realm_reason") or ""
            holder["account"] = account
        except QuotaBlocked as exc:
            record_error(model, 429, exc.message[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000))
            log("request blocked by quota guard: model=%s %s"
                % (model, exc.message[:200]), level="WARN", tag="chat")
            return self._quota_error(exc)
        except RateLimited as exc:
            t = time.time() - t_start
            record_error(model, 429, exc.detail[:200],
                         elapsed_ms=int(t * 1000))
            return self._rate_limited(exc)
        except urllib.error.HTTPError as exc:
            # 错误体在 open_upstream 中已读过（挂在 qoder_detail），二次 read
            # 会拿到残缺内容——优先取挂载值。
            detail = getattr(exc, "trae_detail", "") or getattr(exc, "qoder_detail", "")
            if not detail:
                try:
                    detail = exc.read(600).decode("utf-8", "replace")
                except Exception:
                    detail = ""
            record_error(model, exc.code, detail,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            msg, etype = friendly_upstream_error(exc.code, detail)
            return self._error(exc.code, msg, etype)
        except Exception as exc:
            message = str(exc)
            record_error(model, 502, message,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            if message.startswith("no usable account"):
                return self._error(503, message
                                   + " - add or enable one at the dashboard (/)")
            return self._error(502, "upstream unreachable: %s" % exc)
        with upstream:
            if want_stream:
                self._sse_begin()
                first_ms = None
                # 流内信封重试：上游可能 HTTP200 建流后在信封里投 418
                # （access log 记 200 + 业务错 418 即此形态）。只要还没向
                # 客户端写出任何上游字节，就重开上游再试。
                attempts = 0
                cur = upstream
                pump_exc = None
                try:
                    while True:
                        try:
                            # 统计已消费的上游数据行：错误信封本身不产出
                            # 行，故 n==0 表示还没消费到任何上游数据 → 可重开
                            consumed = {"n": 0}

                            def _count_src(src, _c=consumed):
                                for item in src:
                                    _c["n"] += 1
                                    yield item

                            inner = _count_src(
                                sse_with_heartbeat(
                                    iter_inner_sse(cur, holder=holder),
                                    self._sse_write))
                            for frame in stream_responses_events(inner, model, holder):
                                if first_ms is None:
                                    first_ms = int((time.time() - t_start) * 1000)
                                self._sse_write(clean_responses_frame(frame))
                            break
                        except (BrokenPipeError, ConnectionResetError,
                                ConnectionAbortedError):
                            wall = int((time.time() - t_start) * 1000)
                            record_usage(model, holder.get("usage"), stream=True,
                                         elapsed_ms=wall, ttft_ms=first_ms,
                                         gen_ms=(wall - first_ms)
                                         if first_ms is not None else None,
                                         fp=fp, account=account.uid,
                                         effort=usage_ctx.get("effort"),
                                         effort_requested=usage_ctx.get("effort_requested"),
                                         key_id=self._key_id_for_usage(),
                                         realm_reason=usage_ctx.get("realm_reason", ""))
                            return
                        except UpstreamStatus as exc:
                            _handle_envelope_account_cooldown(account, exc, model=model, session_key=session_key)
                            # 控制帧（response.created 等）先于数据，不能算
                            # “已输出”；以上游数据行计数判断能否重开。
                            if should_retry_envelope(exc, False, attempts) \
                                    and consumed.get("n", 0) == 0:
                                attempts += 1
                                log("responses in-stream envelope status %s "
                                    "(try %d/%d), reopening upstream"
                                    % (exc.status, attempts + 1,
                                       TRANSIENT_MAX_RETRIES + 1),
                                    level="WARN", tag="chat")
                                time.sleep(attempts)
                                try:
                                    # 必须用转换后的 chat 请求体重开：原始
                                    # Responses 体的会话在 input 字段里，而
                                    # build_trae_body 只读 messages -> 空会话。
                                    cur2, account, _ = open_upstream(
                                        chat_req, session_key=session_key,
                                        target_realm=req_realm,
                                        usage_ctx=usage_ctx)
                                except Exception as rex:
                                    log("responses reopen failed: %s"
                                        % str(rex)[:160], level="WARN")
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            pump_exc = exc
                            break
                finally:
                    if cur is not upstream:
                        try:
                            cur.close()
                        except Exception:
                            pass
                if pump_exc is not None:
                    record_error(model, pump_exc.status, pump_exc.detail,
                                 elapsed_ms=int((time.time() - t_start) * 1000))
                    msg, _ = friendly_upstream_error(
                        _to_int_status(pump_exc.status), pump_exc.detail)
                    log("responses upstream status %s: %s"
                        % (pump_exc.status, msg[:200]), level="ERROR",
                        tag="chat")
                    # Responses 协议靠终态事件收尾：只关流会让客户端一直等。
                    try:
                        self._sse_write(_responses_failed_frame(
                            holder, _to_int_status(pump_exc.status), msg))
                    except Exception:
                        pass
                    self._sse_end()
                    return
                self._sse_end()
                wall = int((time.time() - t_start) * 1000)
                record_usage(model, holder.get("usage"), stream=True,
                             elapsed_ms=wall, ttft_ms=first_ms,
                             gen_ms=(wall - first_ms)
                             if first_ms is not None else None,
                             fp=fp, account=account.uid,
                             effort=usage_ctx.get("effort"),
                             effort_requested=usage_ctx.get("effort_requested"),
                             key_id=self._key_id_for_usage(),
                             realm_reason=usage_ctx.get("realm_reason", ""))
                return
            try:
                chat_obj, account = aggregate_with_envelope_retry(
                    upstream, chat_req, session_key, req_realm, model,
                    holder, account)
            except UpstreamStatus as exc:
                record_error(model, exc.status, exc.detail,
                             elapsed_ms=int((time.time() - t_start) * 1000))
                msg, etype = friendly_upstream_error(_to_int_status(exc.status),
                                                     exc.detail)
                return self._error(exc.status if str(exc.status).isdigit() else 502,
                                   msg, etype)
            except Exception as exc:
                record_error(model, 502, str(exc),
                             elapsed_ms=int((time.time() - t_start) * 1000))
                return self._error(502, "upstream stream error: %s" % exc)
            wall = int((time.time() - t_start) * 1000)
            result = chat_to_response(chat_obj, model, custom_names)
            record_usage(model, chat_obj.get("usage"), stream=False,
                         elapsed_ms=wall, fp=fp, account=account.uid,
                         effort=usage_ctx.get("effort"),
                         effort_requested=usage_ctx.get("effort_requested"),
                         key_id=self._key_id_for_usage(),
                         realm_reason=usage_ctx.get("realm_reason", ""))
            return self._json(200, result)

    def do_POST(self):
        # #26：同 do_GET —— 每次请求入口清空，避免 keep-alive 复用实例时把上一次
        # chat 的出口/原因带到别的响应上。
        self.realm_used = ""
        self.realm_reason = ""
        self.degraded_from = ""
        path = self.path.split("?")[0]
        if path == "/update/apply":
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            payload = self._payload_or_error()
            if payload is None:
                return
            try:
                result = apply_project_update(
                    tag=str(payload.get("tag") or ""),
                    tarball_url=str(payload.get("tarball_url") or ""))
                return self._json(200, result)
            except RuntimeError as exc:
                return self._error(409, str(exc), "update_error")
            except Exception as exc:
                return self._error(500, "update failed: %s" % exc)
        if path == "/config/restore":
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            payload = self._payload_or_error()
            if payload is None:
                return
            doc = payload.get("config") if isinstance(payload.get("config"), dict) else payload
            if not isinstance(doc, dict) or not (
                    doc.get("format") == "trae2api-config"
                    or isinstance(doc.get("accounts"), list)):
                return self._error(400, "not a trae2api config document",
                                   "invalid_request_error")
            try:
                stamp = time.strftime("%Y%m%d-%H%M%S")
                backup = os.path.join(ACCOUNTS_DIR, "config-backup-%s.json" % stamp)
                with open(backup, "w", encoding="utf-8") as fh:
                    json.dump({
                        "format": "trae2api-config",
                        "version": 1,
                        "exportedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "settings": trae_settings.load(ACCOUNTS_DIR),
                        "accounts": trae_accounts.build_export_document(
                            POOL.accounts if POOL else [], include_secrets=True),
                    }, fh, ensure_ascii=False, indent=2)
                accounts_src = doc.get("accounts")
                if not isinstance(accounts_src, (dict, list)):
                    accounts_src = doc
                rows, problem = trae_accounts._coerce_account_rows(accounts_src)
                if problem:
                    return self._error(400, "cannot read accounts: %s" % problem,
                                       "invalid_request_error")
                settings = doc.get("settings")
                if isinstance(settings, dict):
                    trae_settings.save(ACCOUNTS_DIR, settings)
                report = POOL.import_rows(rows, overwrite=True)
                log("config restore: %s accounts, backup=%s"
                    % (len(rows), os.path.basename(backup)))
                return self._json(200, {
                    "ok": True,
                    "accounts": len(rows),
                    "imported": report,
                    "backup": os.path.basename(backup),
                    "relogin": True,
                })
            except Exception as exc:
                return self._error(500, "restore failed: %s" % exc)
        if path == "/settings/save":
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            return self._handle_settings_save()
        if path in ("/panel/login", "/panel/logout", "/panel/password"):
            return self._handle_panel(path)
        if self._is_panel_route(path) and not self._panel_ok():
            return self._error(401, "panel password required",
                               "invalid_request_error")
        if path in ("/agents/apply", "/agents/restore"):
            # 写**网关所在机器**的客户端配置文件：面板会话不够，还必须来自
            # loopback（远程/容器调用按设计拒绝——那是配置器 CLI 的活）。
            if not self._panel_ok():
                return self._error(401, "panel password required",
                                   "invalid_request_error")
            if not self._client_is_loopback():
                return self._error(
                    403,
                    "agent config writes are loopback-only: run the "
                    "configurator CLI on the machine where the client "
                    "lives (curl /agents/cli)",
                    "invalid_request_error")
            payload = self._payload_or_error()
            if payload is None:
                return
            try:
                client_id = str(payload.get("client") or "").strip()
                base_url = str(payload.get("base_url") or "").strip()
                api_key = str(payload.get("api_key") or "").strip()
                model = str(payload.get("model") or "").strip() or None
                if path == "/agents/apply":
                    models = None
                    if payload.get("fetch_models"):
                        models = trae_agents.fetch_models_from_gateway(
                            base_url, api_key)
                    result = trae_agents.integrate(
                        ACCOUNTS_DIR, client_id, base_url, api_key,
                        model=model, models=models)
                else:
                    result = trae_agents.restore(ACCOUNTS_DIR, client_id)
                return self._json(200, result)
            except trae_agents.AgentConfigError as exc:
                return self._error(400, str(exc), "invalid_request_error")
        is_account_route = (
            path.startswith("/accounts/")
            or path == "/realm"
            or path.startswith("/tasks")
            or path.startswith("/scheduler")
            or path.startswith("/logs")
            or path.startswith("/models/")
        )
        if not is_account_route and path not in (
                "/v1/chat/completions", "/chat/completions",
                "/v1/responses", "/responses",
                # Anthropic Messages（task-78 接线）：两条都要进白名单，
                # 否则会在 404 分支被拦掉（CORS 无需另加，"/v1" 前缀已覆盖）。
                "/v1/messages", "/v1/messages/count_tokens"):
            if path in ("/v1/completions", "/completions"):
                # legacy Completions（prompt 而非 messages）本网关不实现：
                # 明确 404 优于"接受请求却按空会话转发上游"。
                return self._error(
                    404,
                    "the legacy /v1/completions API is not supported here: "
                    "this gateway speaks Chat Completions and Responses. "
                    "Use /v1/chat/completions with messages=[...] instead.",
                    "invalid_request_error")
            return self._error(404, "not found", "invalid_request_error")
        if not self._authorized():
            return
        payload = self._payload_or_error(allow_list=(path == "/accounts/import"))
        if payload is None:
            return
        if is_account_route:
            return self._handle_accounts(path, payload)
        if path in ("/v1/responses", "/responses"):
            return self._handle_responses(payload)
        if path in ("/v1/messages", "/v1/messages/count_tokens"):
            return self._handle_anthropic(path, payload)

        # ---- Chat Completions 主链路 ----
        normalize_tool_choice(payload)
        normalize_tools(payload)
        translate_max_completion_tokens(payload)
        model = payload.get("model") or "auto"
        payload.setdefault("stream", False)
        # 保持原始终端 stream 意图
        want_stream = bool(payload.get("stream"))
        # 转换统一在 build_trae_body 内做（压平/parts/工具注入）
        session_key = extract_session_key(self.headers, payload)
        fp = prompt_fingerprint(payload.get("messages"))
        t_start = time.time()
        effort = requested_effort(payload)   # 与 usage 记账、请求体构造同源
        log("chat: model=%s client_effort=%r stream=%s msgs=%d"
            % (model, effort, want_stream,
               len(payload.get("messages") or [])))
        try:
            # 自动换区：未显式指定且未绑 Key 时，按模型归属决定出口
            req_realm = self._effective_realm(model)
            usage_ctx = {}          # P1-3：推理档位审计出参（下传给 open_upstream）
            deg = self._prepare_degrade(model, req_realm)
            if deg:
                _orig = model
                model, req_realm, _why = deg
                payload["model"] = model
                self.degraded_from = "%s -> %s (%s)" % (_orig, model, _why)
            blocked = self._model_precheck(model, req_realm)
            if blocked:
                _st = int(getattr(self, "_precheck_status", 400) or 400)
                return self._error(_st, blocked,
                                   "quota_exceeded" if _st == 429
                                   else "invalid_request_error")
            upstream, account, _ = open_upstream(payload, session_key=session_key,
                                                 target_realm=req_realm,
                                                 usage_ctx=usage_ctx)
            # #26：记录实际出口（自动路由后可能与 req_realm 不同）→ 响应头可见
            self.realm_used = usage_ctx.get("realm") or req_realm
            self.realm_reason = usage_ctx.get("realm_reason") or ""
        except QuotaBlocked as exc:
            record_error(model, 429, exc.message[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000))
            log("request blocked by quota guard: model=%s %s"
                % (model, exc.message[:200]), level="WARN", tag="chat")
            return self._quota_error(exc)
        except RateLimited as exc:
            record_error(model, 429, exc.detail[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000))
            return self._rate_limited(exc)
        except urllib.error.HTTPError as exc:
            # 错误体在 open_upstream 中已读过（挂在 qoder_detail），二次 read
            # 会拿到残缺内容——优先取挂载值。
            detail = getattr(exc, "trae_detail", "") or getattr(exc, "qoder_detail", "")
            if not detail:
                try:
                    detail = exc.read(600).decode("utf-8", "replace")
                except Exception:
                    detail = ""
            record_error(model, exc.code, detail,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            msg, etype = friendly_upstream_error(exc.code, detail)
            return self._error(exc.code, msg, etype)
        except Exception as exc:
            message = str(exc)
            record_error(model, 502, message,
                         elapsed_ms=int((time.time() - t_start) * 1000))
            if message.startswith("no usable account"):
                return self._error(503, message
                                   + " - add or enable one at the dashboard (/)")
            return self._error(502, "upstream unreachable: %s" % exc)

        with upstream:
            holder = {"usage": None, "requested_model": model,
                      "allowed_names": _tool_names_from_payload(payload),
                      "account": account}
            if want_stream:
                self._sse_begin()
                emitted = False
                first_ms = None
                # 流内信封重试（同上：200 建流后信封投 418 的形态），仅在
                # 尚未向客户端写出任何上游字节时重开。
                attempts = 0
                cur = upstream
                pump_exc = None
                try:
                    while True:
                        try:
                            for line in sse_with_heartbeat(
                                    recover_leaked_tool_calls(
                                        iter_inner_sse(cur, holder=holder),
                                        allowed_names=_tool_names_from_payload(payload)),
                                    self._sse_write):
                                if first_ms is None:
                                    first_ms = int((time.time() - t_start) * 1000)
                                emitted = True
                                self._sse_write(line)
                            break
                        except (BrokenPipeError, ConnectionResetError,
                                ConnectionAbortedError):
                            # 客户端断开；上游已产出的部分照常记账。
                            wall = int((time.time() - t_start) * 1000)
                            record_usage(model, holder.get("usage"), stream=True,
                                         elapsed_ms=wall, ttft_ms=first_ms,
                                         gen_ms=(wall - first_ms)
                                         if first_ms is not None else None,
                                         fp=fp, account=account.uid,
                                         effort=usage_ctx.get("effort"),
                                         effort_requested=usage_ctx.get("effort_requested"),
                                         key_id=self._key_id_for_usage(),
                                         realm_reason=usage_ctx.get("realm_reason", ""))
                            return
                        except UpstreamStatus as exc:
                            _handle_envelope_account_cooldown(account, exc, model=model, session_key=session_key)
                            if should_retry_envelope(exc, emitted, attempts):
                                attempts += 1
                                log("chat in-stream envelope status %s on "
                                    "model '%s' (try %d/%d), reopening upstream"
                                    % (exc.status, model, attempts + 1,
                                       TRANSIENT_MAX_RETRIES + 1),
                                    level="WARN", tag="chat")
                                time.sleep(attempts)
                                try:
                                    cur2, account, _ = open_upstream(
                                        payload, session_key=session_key,
                                        target_realm=req_realm,
                                        usage_ctx=usage_ctx)
                                except Exception as rex:
                                    log("chat reopen failed: %s"
                                        % str(rex)[:160], level="WARN")
                                    pump_exc = exc
                                    break
                                if cur is not upstream:
                                    try:
                                        cur.close()
                                    except Exception:
                                        pass
                                cur = cur2
                                continue
                            pump_exc = exc
                            break
                finally:
                    if cur is not upstream:
                        try:
                            cur.close()
                        except Exception:
                            pass
                if pump_exc is not None:
                    exc = pump_exc
                    wall = int((time.time() - t_start) * 1000)
                    record_error(model, exc.status, exc.detail, elapsed_ms=wall)
                    msg, etype = friendly_upstream_error(
                        _to_int_status(exc.status), exc.detail)
                    err = json.dumps({"error": {
                        "message": msg, "type": etype,
                        "code": exc.status}}, ensure_ascii=False)
                    try:
                        self._sse_write(("data: %s\n\n" % err).encode("utf-8"))
                        self._sse_write(b"data: [DONE]\n\n")
                    except Exception:
                        pass
                    self._sse_end()
                    return
                if not emitted:
                    err = json.dumps({"error": {
                        "message": "empty upstream stream",
                        "type": "server_error"}})
                    self._sse_write(("data: %s\n\n" % err).encode("utf-8"))
                self._sse_write(b"data: [DONE]\n\n")
                self._sse_end()
                wall = int((time.time() - t_start) * 1000)
                record_usage(model, holder.get("usage"), stream=True,
                             elapsed_ms=wall, ttft_ms=first_ms,
                             gen_ms=(wall - first_ms)
                             if first_ms is not None else None,
                             fp=fp, account=account.uid,
                             effort=usage_ctx.get("effort"),
                             effort_requested=usage_ctx.get("effort_requested"),
                             key_id=self._key_id_for_usage(),
                             realm_reason=usage_ctx.get("realm_reason", ""))
                return
            try:
                result, account = aggregate_with_envelope_retry(
                    upstream, payload, session_key, req_realm, model,
                    holder, account)
            except UpstreamStatus as exc:
                record_error(model, exc.status, exc.detail,
                             elapsed_ms=int((time.time() - t_start) * 1000))
                code = exc.status if str(exc.status).isdigit() else 502
                try:
                    code = int(code)
                except Exception:
                    code = 502
                if code < 400 or code > 599:
                    code = 502
                msg, etype = friendly_upstream_error(
                    _to_int_status(exc.status), exc.detail)
                return self._error(code, msg, etype)
            except Exception as exc:
                record_error(model, 502, str(exc),
                             elapsed_ms=int((time.time() - t_start) * 1000))
                return self._error(502, "upstream stream error: %s" % exc)
            wall = int((time.time() - t_start) * 1000)
            first_at = result.get("first_chunk_at")
            first_ms = int((first_at - t_start) * 1000) if first_at else None
            record_usage(model, result.get("usage"), stream=False,
                         elapsed_ms=wall, ttft_ms=first_ms,
                         gen_ms=(wall - first_ms) if first_ms is not None else None,
                         fp=fp, account=account.uid,
                         effort=usage_ctx.get("effort"),
                         effort_requested=usage_ctx.get("effort_requested"),
                         key_id=self._key_id_for_usage(),
                         realm_reason=usage_ctx.get("realm_reason", ""))
            return self._json(200, result)


def acc_realm(account):
    return account.realm if account else CURRENT_REALM


def main():
    global POOL, ACCOUNTS_DIR, API_KEY, SYSTEM_PROMPT, USAGE_DIR, USAGE_LOG, \
        USAGE_SUMMARY, SCHEDULER
    API_KEY_GENERATED = False
    ap = argparse.ArgumentParser(
        description="Trae (trae.com.cn / trae.ai) -> OpenAI-compatible proxy")
    ap.add_argument("--host", default=os.environ.get("HOST") or "127.0.0.1")
    # 8788 被 mimo-api-proxy.mjs 占用，8789 是 wb-proxy 默认端口；
    # Trae 网关默认 8791（部署面已统一；PORT 环境变量可覆盖）。
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("PORT") or "8791"))
    ap.add_argument("--lan", action="store_true",
                    help="listen on every interface so other devices on the "
                         "LAN can reach it (implies --host 0.0.0.0 and forces "
                         "an api key)")
    ap.add_argument("--api-key",
                    default=os.environ.get("API_KEY")
                    or os.environ.get("TRAE_PROXY_KEY") or None,
                    help="require this bearer token on /v1/* (optional)")
    ap.add_argument("--system-prompt", default=DEFAULT_SYSTEM_PROMPT,
                    help="system message used when the request has none "
                         "(default: keep the gateway built-in system prompt)")
    ap.add_argument("--usage-dir", default=None,
                    help="where to store usage.jsonl / usage-summary.json "
                         "(default: ./usage)")
    ap.add_argument("--accounts-dir",
                    default=os.environ.get("ACCOUNTS_DIR") or None,
                    help="where the per-account credential files live "
                         "(default: ./accounts)")
    ap.add_argument("--panel-password", default=None,
                    help="set the web panel password on startup (default: "
                         "admin)")
    args = ap.parse_args()

    if args.lan and args.host == "127.0.0.1":
        args.host = "0.0.0.0"
    if args.usage_dir:
        USAGE_DIR = os.path.abspath(args.usage_dir)
        try:
            trae_probe.set_health_path(os.path.join(USAGE_DIR, "model_health.json"))
        except Exception:
            pass
        USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
        USAGE_SUMMARY = os.path.join(USAGE_DIR, "usage-summary.json")

    # 拒绝启动第二份：Windows 上 SO_REUSEADDR 会让两个 socket 绑同一端口，
    # 连接被静默分流，极难诊断。
    try:
        probe = urllib.request.urlopen(
            "http://%s:%d/health"
            % ("127.0.0.1" if args.host == "0.0.0.0" else args.host, args.port),
            timeout=2)
        existing = json.loads(probe.read().decode("utf-8"))
    except Exception:
        existing = None   # 没人应答 /health —— 让下面的 bind 决定
    if isinstance(existing, dict):
        # 只有我们的 /health 带账号池字段（"accounts"）。其它服务可能占用
        # 同端口也应答 /health JSON（例如 wb-proxy / mimo-api-proxy）。
        foreign = existing.get("service") not in (None, "trae2api-hub") \
            or "accounts" not in existing
        if foreign:
            who = existing.get("service") or "an unknown HTTP service"
            print()
            print("  [ERROR] port %d is already taken by another program: %s"
                  % (args.port, who))
            print("          trae2api itself is NOT running - nothing was "
                  "started.")
            print()
            print("  Fix: start trae2api-hub on a different port, e.g.")
            print("          %s %d" % (START_SCRIPT, args.port + 1))
            print("          python trae_proxy.py --port %d" % (args.port + 1))
            print()
            for cmd in port_owner_hint(args.port):
                print("  Check who owns the port:  %s" % cmd)
            print()
            raise SystemExit(1)
        print()
        print("  [已有一个反代在 %d 端口运行，无需重复启动]" % args.port)
        print("  账号: %s @ %s" % (existing.get("uid", "?"),
                                   existing.get("domain", "?")))
        print("  看板: http://127.0.0.1:%d/" % args.port)
        print()
        print("  如果要重启: 先把原来那个窗口关掉（或结束 python 进程），"
              "再运行本程序。")
        print()
        return

    API_KEY = args.api_key
    SYSTEM_PROMPT = args.system_prompt
    if args.accounts_dir:
        ACCOUNTS_DIR = os.path.abspath(args.accounts_dir)
    # LAN 模式绝不能带默认密钥：网关花的是账号自己的上游额度，
    # 可猜的默认值等于让全网段的人白嫖。首次生成一次并持久化。
    if args.lan and not API_KEY:
        API_KEY, API_KEY_GENERATED = trae_settings.ensure_launcher_key(
            ACCOUNTS_DIR)
    # 面板保存的 Key 优先于自动生成的 LAN Key（.bat 重启后浏览器改动仍生效）；
    # 命令行 --api-key 依然最高优先级。
    global API_KEY_FILE_SET
    saved_key, key_from_panel = trae_settings.api_key_override(ACCOUNTS_DIR)
    if key_from_panel and not args.api_key:
        API_KEY = saved_key
        API_KEY_FILE_SET = True
    if args.panel_password:
        trae_settings.set_panel_password(ACCOUNTS_DIR, args.panel_password)
        log("panel      : password set from --panel-password")
    elif trae_settings.panel_password_is_default(ACCOUNTS_DIR):
        log("panel      : password is still the default 'admin' - change it "
            "in the panel")
        if args.host == "0.0.0.0":
            log("SECURITY   : LAN mode + default panel password 'admin' - "
                "anyone on this network can log in and read your API key. "
                "Change it in the panel, or restart with --panel-password.",
                level="WARN")

    POOL = trae_accounts.AccountPool(ACCOUNTS_DIR, log=log)
    POOL.load()
    load_persisted_realm()
    # task-61：把设置里的护栏阈值 + free 名单**同批**推给池（R3）；阈值全 0 时
    # 不产生任何副作用，任一 > 0 则惰性启动后台上新线程（G1 的恢复路径）。
    try:
        POOL.apply_settings(limits_data=trae_settings.limits_data(ACCOUNTS_DIR),
                            free_models=free_model_names(CURRENT_REALM))
    except Exception as exc:
        log("quota limits apply failed at startup: %s" % exc, level="WARN")
    # 余额/用量刷新已并入账号域（pool.note_usage / pool.refresh_due），
    # 网关侧不再持有独立刷新线程（账号契约重构后 CreditsUsageRefresher 已删除）。
    global CREDITS_USAGE_REFRESHER
    CREDITS_USAGE_REFRESHER = None
    from trae_scheduler import Scheduler
    SCHEDULER = Scheduler(POOL)
    SCHEDULER.start()

    if not POOL.accounts:
        # 永不静默采用本机客户端登录：先报告扫描结果，由用户在看板确认导入。
        try:
            detected = trae_accounts.scan_desktop_credentials()
        except Exception:
            detected = []
        usable = [d for d in detected if d.get("valid")]
        if usable:
            log("no accounts yet - detected %d local credential(s), NOT importing"
                % len(usable))
            for d in usable:
                log("  available: %s  %s  %s" % (
                    (d.get("uid") or "?")[:8], d.get("nickname") or "(no name)",
                    d.get("realmName") or d.get("realm")))
            log("open the dashboard and click [Scan local credentials] to import")
        else:
            log("no accounts yet - no local Trae credentials found on this machine")
        # 不在这里退出：看板必须可达，才能通过浏览器完成登录。
    rep = current_account()
    log("accounts   : %d total, %d usable"
        % (len(POOL.accounts), POOL.count_ready()))
    for account in POOL.accounts:
        log("  - %s  %s  %s  %s" % (
            account.uid[:8], account_label(account) or "(no name)",
            account.realm, account.domain))
    log("store      : %s" % ACCOUNTS_DIR)
    log("credential : %s" % (rep.path if rep else "-"))
    log("account    : %s @ %s" % (rep.uid if rep else "-",
                                  rep.domain if rep else "-"))
    log("realm      : %s (%s)" % (
        CURRENT_REALM,
        TRAE_REALMS[trae_realm(CURRENT_REALM)]["account"]))
    try:
        _n_cn = len(trae_catalog.models_for_realm("cn"))
        _n_intl = len(trae_catalog.models_for_realm("intl"))
        log("catalog    : trae_catalog snapshot (cn=%d, intl=%d models)"
            % (_n_cn, _n_intl))
    except Exception as exc:
        log("catalog    : snapshot unavailable (%s)" % str(exc)[:120],
            level="WARN")

    if args.host == "0.0.0.0":
        ips = local_ip_addresses() or ["<this-pc-ip>"]
        print()
        print("  " + "=" * 62)
        print("  LAN MODE - reachable from other devices")
        print()
        for ip in ips:
            print("    API       : http://%s:%s/v1" % (ip, args.port))
            print("    Dashboard : http://%s:%s/" % (ip, args.port))
        print()
        print("    API Key   : %s" % API_KEY)
        if API_KEY_GENERATED:
            print("                (newly generated & saved to "
                  "accounts/settings.json)")
        else:
            print("                (reused from accounts/settings.json)")
        print()
        print("    Open the dashboard (key already included):")
        print("      http://%s:%s/?key=%s" % (ips[0], args.port, API_KEY))
        print()
        print("    Clients: Base URL = the API address above, then paste "
              "the key.")
        print()
        if IS_WINDOWS:
            print("    If nothing can connect, allow python through the")
            print("    firewall: run %s once as administrator." % FIREWALL_SCRIPT)
        else:
            print("    If nothing can connect, open the port in the firewall")
            print("    once:  sudo ./%s %d" % (FIREWALL_SCRIPT, args.port))
        print("  " + "=" * 62)
        print()
        sys.stdout.flush()

    if not POOL.accounts:
        print()
        print("  " + "=" * 62)
        print("  NO ACCOUNTS YET")
        print()
        print("  Open the dashboard and click [+ 添加账号 (OAuth)]:")
        print("      http://127.0.0.1:%d/" % args.port)
        print()
        print("  The browser flow adds the account automatically.")
        print("  This window must stay open.")
        print("  " + "=" * 62)
        print()
        sys.stdout.flush()

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        # bind 前探测与 bind 之间端口被抢，或被不答 /health 的程序占着
        print()
        print("  [ERROR] failed to listen on %s:%d - %s"
              % (args.host, args.port, exc))
        print("          the port is reserved or held by another program;")
        print("          trae2api did NOT start.")
        print()
        print("  Fix: stop the program holding the port, or pick another "
              "port:")
        for cmd in port_owner_hint(args.port):
            print("          %s" % cmd)
        print("          %s %d" % (START_SCRIPT, args.port + 1))
        print()
        raise SystemExit(1)
    log("listening  : http://%s:%d/v1  (api key: %s)"
        % (args.host, args.port, "on" if API_KEY else "off"))
    log("dashboard  : http://%s:%d/" % (args.host, args.port))
    # 进程生命周期内保持 handler 引用：SetConsoleCtrlHandler 存的是裸指针，
    # 回调被 GC 会在关窗时崩溃。
    _ctrl_handler = install_console_close_handler()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("bye")
    finally:
        try:
            server.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()