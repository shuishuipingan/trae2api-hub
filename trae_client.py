"""trae_client.py —— Trae 双区上游协议层（纯标准库 / 零运行时依赖）

事实源：.team/PROTOCOL.md（本机 Desktop 国际版 3.6.2 / 国内版 3.4.3 静态逆向 +
真实请求复现）。本模块只做"协议翻译"，不含账号池/路由/看板逻辑：

    账号对象 (desktop 解密 / 账号池)  ──┐
                                        ├─ auth_headers() ──> urllib 请求
    OpenAI 风格 messages ── build_chat_body() ──> llm_raw_chat ──> iter_events()

对外契约（PROTOCOL 第十节，签名保持一致）：

    REALMS                                  双区常量表
    auth_headers(account, realm)            鉴权头 + 设备头
    build_chat_body(model, messages, **opts) content 字符串 -> parts 数组
    open_chat(account, realm, body, timeout) 流式 POST，返回原始 response
    iter_events(resp)                       逐帧产出 (event, data)
    refresh_account(account)                ExchangeToken 轮换刷新
    fetch_model_list(account, realm)        model_list
    fetch_usage(account, realm)             get_session_usage
    fetch_entitlement(account, realm)       权益包 / 付费状态
    import_desktop_accounts()               解密 iCubeAuthInfo://icube.cloudide

硬约束（团队规则，改代码前先改 .team/PROTOCOL.md）：
  1. 只用标准库：urllib / json / hashlib / base64 / datetime …；
  2. 任何日志、异常文案、repr 都不出现完整 token（本模块只暴露长度/前缀）；
  3. 代理走环境变量：TRAE_PROXY 优先，其次 http(s)_proxy / all_proxy；
  4. 上游错误统一 UpstreamError(code, message, status)。

实测要点（复现命令见各函数 docstring）：
  - CN 聊天：POST https://trae-api-cn.mchost.guru/api/ide/v1/llm_raw_chat
    头 x-ide-token 与 Authorization 用同一个 access token；
    content 必须是 parts 数组，传字符串会 400（PROTOCOL 第六节）。
  - 服务端永远回 SSE，stream=false 也一样，聚合由上层负责。
  - INTL 账号在 4015/4019 风控下会给出 error 帧，本模块如实上抛不吞。
"""
import base64
import datetime
import hashlib
import json
import os
import socket
import sys
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request

import trae_fingerprint

__all__ = [
    "REALMS", "UpstreamError", "auth_headers", "build_chat_body", "open_chat",
    "iter_events", "collect", "chat_once", "refresh_account", "ensure_token",
    "is_expired", "fetch_model_list", "fetch_usage", "fetch_entitlement", "checkin_status", "claim_checkin",
    "import_desktop_accounts", "decrypt_icube_blob", "decode_auth_blob",
    "build_icube_blob", "aes_cbc_encrypt", "aes_cbc_decrypt", "realm_of",
    "account_public", "self_test", "request_json", "chat_once",
    "import_desktop_devices", "build_device_proof", "ec_private_key_from_pem",
    "p256_sign", "p256_verify", "fetch_activity", "generate_temp_token",
    "classify_error", "_as_mapping", "refresh_backoff_remaining",
    "reset_refresh_backoff",
]

# ---------------------------------------------------------------------------
# 常量（PROTOCOL 第一节 / 第二节）
# ---------------------------------------------------------------------------
APP_ID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
PLUGIN_CHANNEL = "icube-ai"
IDE_VERSION_CODE = "20260212"
CLIENT_ID = "ono9krqynydwx5"
CLIENT_SECRET = "-"

REALMS = {
    "cn": {
        "key": "cn",
        "label": "国内版",
        # 客户端动态解析结果；api.trae.com.cn 只承接 CloudIDE/OAuth/pay，
        # /api/ide/v1/* 打过去是 404（PROTOCOL 第一节）。
        "core": "https://trae-api-cn.mchost.guru",
        "core_fallbacks": (),
        "account": "https://api.trae.com.cn",
        "account_fallbacks": (),
        "pay": "https://api.trae.com.cn",
        "pay_fallbacks": (),
        # 每日签到/活动（/trae/api/v2/ug/*）只在 api.trae.cn 上注册；
        # api.trae.com.cn 打过去是 404（Lead 实测 2026-10-19）。
        "ug": "https://api.trae.cn",
        "ua": "Trae CN/3.4.3",
        "version_code": IDE_VERSION_CODE,
        "region": "CN",
        "ai_region": "CN",
        "model_list_supported": True,
    },
    "intl": {
        "key": "intl",
        "label": "国际版",
        # USTTP 账号会给 grow-normal.traeapi.us；核心数据面 US/SG 双主机。
        "core": "https://core-normal.traeapi.us",
        "core_fallbacks": ("https://core-normal.trae.ai", "https://coresg-normal.trae.ai"),
        "account": "https://grow-normal.trae.ai",
        "account_fallbacks": ("https://grow-normal.traeapi.us",),
        # 实测（Lead，2026-10-19）：INTL 的 ent_usage / pay_status 都在
        # grow-normal.traeapi.us 上返回 200；api.trae.ai 是两个 404。
        "pay": "https://grow-normal.traeapi.us",
        "pay_fallbacks": ("https://grow-normal.trae.ai",),
        # INTL 的 ug/activity 接口实测 404；签到仅国内版可用。
        "ug": "https://grow-normal.traeapi.us",
        "ua": "Trae/3.6.2",
        "version_code": IDE_VERSION_CODE,
        "region": "US",
        "ai_region": "US",
        # INTL 的 model_list 返回 403 no schema found（PROTOCOL 第一节）；
        # 模型清单走上层本地缓存，这里只把错误如实抛出。
        "model_list_supported": False,
    },
}

PATH_CHAT = "/api/ide/v1/llm_raw_chat"
PATH_MODEL_LIST = "/api/ide/v1/model_list"
PATH_SESSION_USAGE = "/api/v1/commercial/get_session_usage"
PATH_ACTIVITY = "/api/v1/commercial/get_user_activity"
PATH_EXCHANGE_TOKEN = "/cloudide/api/v3/trae/oauth/ExchangeToken"
PATH_TEMP_TOKEN = "/cloudide/api/v3/trae/GenerateTempToken"
PATH_ENT_USAGE = "/trae/api/v1/pay/ide_user_ent_usage"
PATH_ENT_USAGE_V2 = "/trae/api/v2/pay/ide_user_ent_usage"
PATH_PAY_STATUS = "/trae/api/v1/pay/ide_user_pay_status"

# 上游错误码（PROTOCOL 第六节表格）
ERR_AUTH = 1001
ERR_PARAM = 4001
ERR_REJECTED = 4015
ERR_RISK = 4019
ERR_MODEL_UNKNOWN = 4023
ERR_PIPELINE = 3003

ERROR_HINTS = {
    ERR_AUTH: "鉴权失败：access token 过期或无效，先 refresh_account 再重试",
    ERR_PARAM: "参数非法：检查 messages 的 parts 数组与 model_name",
    ERR_REJECTED: "上游拒绝（国际版账号风控 / 模型权限），换账号或降级模型",
    ERR_RISK: "风控命中（设备头 / 出口区域），保持同区出口并冷却",
    ERR_MODEL_UNKNOWN: "模型未知：name 必须来自 model_list",
    ERR_PIPELINE: "prompt pipeline 失败（/chat 专用，非 raw chat）",
}

DEFAULT_TIMEOUT = 300


# ---------------------------------------------------------------------------
# 错误类型
# ---------------------------------------------------------------------------
class UpstreamError(Exception):
    """上游统一错误：code 可能是上游业务码（int）或本层字符串码。"""

    def __init__(self, code, message, status=None, payload=None, retry_after=None):
        self.code = code
        self.message = str(message or "")
        self.status = status
        self.payload = payload
        self.retry_after = retry_after
        super().__init__(self.__str__())

    def __str__(self):
        bits = ["[%s]" % (self.code,)]
        if self.status is not None:
            bits.append("HTTP %s" % (self.status,))
        bits.append(self.message or "上游错误")
        hint = ERROR_HINTS.get(self.code) if isinstance(self.code, int) else None
        if hint:
            bits.append("（%s）" % hint)
        return " ".join(bits)

    def as_dict(self):
        return {"code": self.code, "message": self.message,
                "status": self.status, "payload": self.payload,
                "retry_after": self.retry_after}

    @classmethod
    def from_event(cls, data, status=None):
        """把 SSE 的 event: error 帧转成异常对象。"""
        data = data if isinstance(data, dict) else {"message": str(data)}
        return cls(data.get("code") or "upstream_error",
                   data.get("message") or data.get("error") or "上游错误帧",
                   status, payload=data)


# ---------------------------------------------------------------------------
# 账号对象适配（dict / trae_accounts.Account / dataclass / 任意带字段对象）
# ---------------------------------------------------------------------------
_ACCOUNT_ATTR_ALIASES = (
    ("userId", ("userId", "uid", "user_id")),
    ("uid", ("uid", "userId", "user_id")),
    ("token", ("token", "access_token", "accessToken")),
    ("refreshToken", ("refreshToken", "refresh_token")),
    ("expiredAt", ("expiredAt", "expired_at")),
    ("refreshExpiredAt", ("refreshExpiredAt", "refresh_expired_at",
                          "refreshExpireAt")),
    ("host", ("host", "domain")),
    ("realm", ("realm",)),
    ("userRegion", ("userRegion", "user_region")),
    ("account", ("account", "profile")),
    ("proxy", ("proxy", "egress", "proxy_own")),
    ("headersExtra", ("headersExtra", "headers_extra")),
)


def _as_mapping(account):
    """把任意账号对象统一成 dict 视图（不修改入参，不依赖 trae_accounts）。

    支持：dict / 有 to_desktop_dict()、to_dict()、as_dict() 的对象 /
    dataclass 或普通对象（__dict__、vars()）/ 已知属性名兜底。
    协议层只认 dict，所有入口先过这里，Account 对象即可直接传入。
    """
    if account is None:
        return {}
    if isinstance(account, dict):
        return dict(account)
    merged = {}
    for name in ("to_desktop_dict", "to_dict", "as_dict"):
        method = getattr(account, name, None)
        if not callable(method):
            continue
        try:
            data = method()
        except Exception:
            continue
        if isinstance(data, dict):
            for key, value in data.items():
                merged.setdefault(key, value)
    if getattr(account, "refresh_payload", None) is not None:
        method = getattr(account, "refresh_payload", None)
        if callable(method):
            try:
                data = method()
            except Exception:
                data = None
            if isinstance(data, dict):
                for key, value in data.items():
                    merged.setdefault(key, value)
            else:
                try:
                    for key in data.keys():
                        merged.setdefault(key, data[key])
                except Exception:
                    pass
    attrs = getattr(account, "__dict__", None)
    if isinstance(attrs, dict):
        for key, value in attrs.items():
            if not key.startswith("_"):
                merged.setdefault(key, value)
    for target, sources in _ACCOUNT_ATTR_ALIASES:
        if merged.get(target) not in (None, ""):
            continue
        for source in sources:
            value = getattr(account, source, None)
            if value not in (None, ""):
                merged[target] = value
                break
    return merged


# ---------------------------------------------------------------------------
# 账号字段读取（兼容 desktop 解密对象 / 账号池对象 / 裸 dict）
# ---------------------------------------------------------------------------
def _token(account):
    account = _as_mapping(account)
    for key in ("token", "access_token", "accessToken", "ide_token", "userJwt"):
        value = account.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _uid(account):
    account = _as_mapping(account)
    for key in ("userId", "user_id", "uid", "user_unique_id"):
        value = account.get(key)
        if value not in (None, ""):
            return str(value)
    inner = account.get("account")
    if isinstance(inner, dict):
        for key in ("userId", "uid", "user_unique_id"):
            if inner.get(key) not in (None, ""):
                return str(inner[key])
    return ""


def normalize_realm(realm):
    """'cn'/'CN'/'china' -> 'cn'；其余一律 intl（双区只有两种）。"""
    raw = str(realm or "").strip().lower()
    if raw in ("cn", "china", "zh", "国内", "国内版"):
        return "cn"
    if raw in ("intl", "us", "global", "sg", "国际", "国际版"):
        return "intl"
    return "intl"


def realm_of(account):
    """从账号对象推断区域（desktop 字段优先，其次 host / storeRegion）。"""
    account = _as_mapping(account)
    explicit = str(account.get("realm") or "").strip().lower()
    if explicit in ("cn", "intl"):
        return explicit
    region = account.get("userRegion")
    if isinstance(region, dict):
        if str(region.get("region") or "").upper() == "CN":
            return "cn"
        if str(region.get("_aiRegion") or "").upper() == "CN":
            return "cn"
    host = str(account.get("host") or "")
    if "trae.com.cn" in host or "mchost.guru" in host:
        return "cn"
    inner = account.get("account")
    if isinstance(inner, dict):
        store = str(inner.get("storeRegion") or "").upper()
        country = str(inner.get("storeCountryCode") or "").lower()
        if store.startswith("CN") or country == "cn":
            return "cn"
    return "intl"


def _hosts(account, realm, base="core"):
    """候选基址：账号显式 override > 区域主选 > 区域备选（去重保序）。"""
    account = _as_mapping(account)
    realm = normalize_realm(realm)
    cfg = REALMS[realm]
    overrides = {
        "core": ("coreHost", "core_host"),
        "account": ("accountHost", "account_host"),
        "pay": ("payHost", "pay_host"),
        "ug": ("ugHost", "ug_host"),
    }[base]
    primary, fallbacks = {
        "core": (cfg["core"], cfg.get("core_fallbacks") or ()),
        "account": (cfg["account"], cfg.get("account_fallbacks") or ()),
        "pay": (cfg["pay"], cfg.get("pay_fallbacks") or ()),
        "ug": (cfg.get("ug") or cfg["account"], cfg.get("ug_fallbacks") or ()),
    }[base]
    hosts = []
    for key in overrides:
        value = str((account or {}).get(key) or "").strip()
        if value:
            hosts.append(value)
    # PROTOCOL 第五节：ExchangeToken 打 {account_host}，即账号对象自己的 host。
    # INTL USTTP 账号的 host 是 grow-normal.traeapi.us（与区域默认的 .ai 不同）。
    if base == "account":
        account_host = str((account or {}).get("host") or "").strip()
        if account_host:
            hosts.append(account_host)
    hosts.append(primary)
    hosts.extend(fallbacks)
    seen, out = set(), []
    for host in hosts:
        host = host.rstrip("/")
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


# ---------------------------------------------------------------------------
# 代理 / 连接层（零依赖，尊重环境变量）
# ---------------------------------------------------------------------------
_OPENER_LOCK = threading.Lock()
_OPENERS = {}


def _proxy_map():
    """TRAE_PROXY 优先；否则读标准代理环境变量（含 no_proxy 语义）。"""
    explicit = (os.environ.get("TRAE_PROXY") or os.environ.get("trae_proxy") or "").strip()
    if explicit:
        return {"http": explicit, "https": explicit}
    try:
        return {k: v for k, v in urllib.request.getproxies().items() if v}
    except Exception:
        return {}


def _opener(proxy=None):
    """opener 按代理配置缓存；proxy 传入时做本次调用的临时覆盖（账号级出口）。"""
    proxies = {"http": proxy, "https": proxy} if proxy else _proxy_map()
    key = tuple(sorted((str(k), str(v)) for k, v in proxies.items()))
    with _OPENER_LOCK:
        opener = _OPENERS.get(key)
        if opener is None:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler(dict(key)))
            _OPENERS[key] = opener
        return opener


def _open(req, timeout, proxy=None):
    return _opener(proxy).open(req, timeout=timeout)


def _decode(raw):
    if isinstance(raw, str):
        return raw
    if raw is None:
        return ""
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return str(raw)


def _http_error(exc):
    """HTTPError -> UpstreamError（保留上游业务码与原始 payload）。"""
    status = getattr(exc, "code", None)
    try:
        text = _decode(exc.read()).strip()
    except Exception:
        text = ""
    code = status if status is not None else "http_error"
    message = text[:800] or ("HTTP %s" % (status,))
    payload = None
    if text:
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
    if isinstance(payload, dict):
        inner = payload.get("error")
        upstream_code = payload.get("code")
        if upstream_code is None and isinstance(inner, dict):
            upstream_code = inner.get("code")
        if upstream_code not in (None, ""):
            code = upstream_code
        upstream_msg = payload.get("message") or payload.get("msg")
        if not upstream_msg:
            if isinstance(inner, dict):
                upstream_msg = inner.get("message")
            elif isinstance(inner, str):
                upstream_msg = inner
        if upstream_msg:
            message = str(upstream_msg)
    return UpstreamError(code, message, status, payload=payload)


def _network_error(hosts, exc):
    detail = "%s: %s" % (type(exc).__name__, exc)
    return UpstreamError("network", "无法连接上游 %s（%s）" % (",".join(hosts), detail), None)


# ---------------------------------------------------------------------------
# 错误分类（给网关做冷却 / 换号 / 退避决策）
# ---------------------------------------------------------------------------
ERROR_KIND_HINTS = {
    "auth": "鉴权失败或权限不足：先 refresh token；仍失败就换账号，别原地重放",
    "param": "请求参数非法：检查 messages 的 parts 数组、model_name、是否带了未知字段",
    "risk": "上游风控命中：同区冷却 + 换账号/换出口，禁止立即重试同一请求",
    "model": "模型不可用：name 必须来自 model_list / 目录快照，换模型再试",
    "rate": "限流：按 Retry-After/指数退避后重试",
    "network": "网络或上游 5xx：退避重试（换备选主机也在此类）",
    "unknown": "未归类错误：记录 code/status/原文后人工判定",
}
_AUTH_CODES = {1001, 401, 403}
_PARAM_CODES = {4001, 400}
_RISK_CODES = {4015, 4019}
_MODEL_CODES = {4023, 3003}
_RATE_CODES = {429}
_NETWORK_CODES = {"network", "timeout", "idle_timeout", "connection", "bad_json",
                  "http_error", "remote_disconnected"}
_AUTH_NAMES = {"auth", "unauthorized", "forbidden", "no_token",
               "no_refresh_token", "refresh_failed"}
_PARAM_NAMES = {"param", "bad_request", "invalid_argument", "validation"}
_MODEL_NAMES = {"model", "model_unknown", "no_model"}


def _error_code_status(exc_or_code):
    """从异常 / 字典 / 码值里取 (code, status, message)。"""
    if isinstance(exc_or_code, UpstreamError):
        return exc_or_code.code, exc_or_code.status, exc_or_code.message
    if isinstance(exc_or_code, dict):
        return (exc_or_code.get("code") or exc_or_code.get("error"),
                exc_or_code.get("status"),
                exc_or_code.get("message") or "")
    if isinstance(exc_or_code, BaseException):
        code = getattr(exc_or_code, "code", None) or type(exc_or_code).__name__
        status = getattr(exc_or_code, "status", None) or getattr(exc_or_code, "status_code", None)
        return code, status, str(exc_or_code)
    return exc_or_code, None, ""


def classify_error(exc_or_code):
    """把上游错误归类成网关可直接消费的决策三件套。

    入参可以是 UpstreamError、任意异常、SSE error 帧 dict、或裸 code（int/str）。
    返回 {"kind": auth|param|risk|model|rate|network|unknown,
          "retryable": bool, "hint": str}

    约定（与 PROTOCOL 第六节错误码表一致）：
      1001 -> auth（先刷新/换号，不原地重试）
      4001 -> param（改请求）
      4015/4019 -> risk（冷却 + 换号，不可立即重试）
      4023/3003 -> model（换模型）
      429 -> rate（退避可重试）
      5xx / 网络类 -> network（退避可重试）
    """
    code, status, message = _error_code_status(exc_or_code)
    numeric = None
    if isinstance(code, bool):
        numeric = None
    elif isinstance(code, int):
        numeric = code
    else:
        text = str(code or "").strip()
        numeric = int(text) if text.isdigit() else None
        lowered = text.lower()
        if lowered == "refresh_backoff":
            return {"kind": "rate", "retryable": True,
                    "hint": "刷新失败冷却中：等 retry_after 秒后再试或直接换号"}
        if lowered in _AUTH_NAMES:
            return {"kind": "auth", "retryable": False, "hint": ERROR_KIND_HINTS["auth"]}
        if lowered in _PARAM_NAMES:
            return {"kind": "param", "retryable": False, "hint": ERROR_KIND_HINTS["param"]}
        if lowered in _MODEL_NAMES:
            return {"kind": "model", "retryable": False, "hint": ERROR_KIND_HINTS["model"]}
        if lowered in _NETWORK_CODES:
            return {"kind": "network", "retryable": True, "hint": ERROR_KIND_HINTS["network"]}
    try:
        status_number = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_number = None
    if numeric in _RISK_CODES:
        return {"kind": "risk", "retryable": False, "hint": ERROR_KIND_HINTS["risk"]}
    if numeric in _AUTH_CODES:
        return {"kind": "auth", "retryable": False, "hint": ERROR_KIND_HINTS["auth"]}
    if numeric in _PARAM_CODES:
        return {"kind": "param", "retryable": False, "hint": ERROR_KIND_HINTS["param"]}
    if numeric in _MODEL_CODES:
        return {"kind": "model", "retryable": False, "hint": ERROR_KIND_HINTS["model"]}
    if numeric in _RATE_CODES or status_number == 429:
        return {"kind": "rate", "retryable": True, "hint": ERROR_KIND_HINTS["rate"]}
    if numeric is not None and 500 <= numeric <= 599:
        return {"kind": "network", "retryable": True, "hint": ERROR_KIND_HINTS["network"]}
    if status_number is not None and 500 <= status_number <= 599:
        return {"kind": "network", "retryable": True, "hint": ERROR_KIND_HINTS["network"]}
    if status_number is not None and status_number >= 400:
        kind = "auth" if status_number in (401, 403) else "param"
        return {"kind": kind, "retryable": False, "hint": ERROR_KIND_HINTS[kind]}
    if message and ("timed out" in message.lower() or "connection" in message.lower()):
        return {"kind": "network", "retryable": True, "hint": ERROR_KIND_HINTS["network"]}
    return {"kind": "unknown", "retryable": False, "hint": ERROR_KIND_HINTS["unknown"]}


# ---------------------------------------------------------------------------
# 鉴权头
# ---------------------------------------------------------------------------
def auth_headers(account, realm=None):
    """IDE 数据面请求头（PROTOCOL 第二节）。

    x-ide-token 与 Authorization 携带同一个 access token（实测结论，
    不要"顺手"换成两种 token）。设备头由 trae_fingerprint 稳定派生，
    保证同一账号长期同一台"虚拟物理机"。
    """
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    token = _token(account)
    if not token:
        raise UpstreamError("no_token", "账号缺少 access token（先导入或刷新）", None)
    headers = {
        "X-App-Id": APP_ID,
        "x-plugin-channel": PLUGIN_CHANNEL,
        "x-ide-version-code": REALMS[realm]["version_code"],
        "x-ide-token": token,
        "Authorization": "Cloud-IDE-JWT " + token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": REALMS[realm]["ua"],
    }
    headers.update(trae_fingerprint.trae_device_headers(_uid(account)))
    headers["X-Request-Id"] = trae_fingerprint.trae_request_id()
    return headers


# ---------------------------------------------------------------------------
# 请求体
# ---------------------------------------------------------------------------
def _text_part(text):
    return {"type": "text", "text": "" if text is None else str(text)}


def normalize_content(content):
    """把任意 content 变成 Trae 认的 parts 数组。

    上游只认 [{"type":"text","text":...}]；传字符串直接 400（4001）。
    字符串 / 字符串列表 / parts 列表 / 单 part dict 全部归一化。
    """
    if content is None:
        return [_text_part("")]
    if isinstance(content, str):
        return [_text_part(content)]
    if isinstance(content, dict):
        content = [content]
    if isinstance(content, (list, tuple)):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(_text_part(item))
            elif isinstance(item, dict):
                if "text" in item and not item.get("type"):
                    parts.append(_text_part(item.get("text")))
                elif item.get("type") == "text":
                    parts.append(_text_part(item.get("text")))
                else:
                    # 图片等非文本 part 原样透传（多模态开关由账号/模型决定）
                    parts.append(dict(item))
        return parts or [_text_part("")]
    return [_text_part(content)]


ROLE_ALIASES = {"human": "user", "ai": "assistant", "model": "assistant"}


def normalize_messages(messages):
    """统一成 [{"role","content":[parts]}]；未知 role 归一到 user。"""
    if isinstance(messages, dict):
        messages = [messages]
    if not isinstance(messages, (list, tuple)) or not messages:
        raise ValueError("messages 不能为空")
    out = []
    for index, raw in enumerate(messages):
        if isinstance(raw, str):
            out.append({"role": "user", "content": [_text_part(raw)]})
            continue
        if not isinstance(raw, dict):
            raise ValueError("messages[%d] 不是对象：%r" % (index, type(raw)))
        role = str(raw.get("role") or "user").strip().lower()
        role = ROLE_ALIASES.get(role, role)
        if role not in ("system", "user", "assistant"):
            role = "user"
        out.append({"role": role, "content": normalize_content(raw.get("content"))})
    return out


# 实测（2026-10-19，CN deepseek-V3）下列参数逐个单独发送均未触发 4001：
#   temperature=0.2 / max_tokens=16 / top_p=0.9+stop / presence+frequency_penalty
# 未在 PROTOCOL 记录的字段一律不发送，避免 4001。
PASSTHROUGH_OPTIONS = ("temperature", "top_p", "max_tokens", "stop",
                       "presence_penalty", "frequency_penalty")


def build_chat_body(model, messages, **opts):
    """构造 llm_raw_chat 请求体（PROTOCOL 第六节）。

    opts:
      stream=True           服务端始终 SSE，这里只是把开关透传；
      temperature/top_p/... 白名单透传，None 不发；
      extra={...}           显式透传额外字段（调用方自担 4001 风险）；
      session_id="..."      可选会话标识。
    """
    model_name = str(model or "").strip()
    if not model_name:
        raise ValueError("model 不能为空")
    body = {
        "model_name": model_name,
        "messages": normalize_messages(messages),
        "stream": bool(opts.get("stream", True)),
    }
    for key in PASSTHROUGH_OPTIONS:
        value = opts.get(key)
        if value is not None:
            body[key] = value
    extra = opts.get("extra")
    if isinstance(extra, dict):
        body.update(extra)
    session_id = opts.get("session_id")
    if session_id:
        body["session_id"] = str(session_id)
    return body


# ---------------------------------------------------------------------------
# 聊天（流式）
# ---------------------------------------------------------------------------
def open_chat(account, realm=None, body=None, timeout=DEFAULT_TIMEOUT,
              headers_extra=None, proxy=None):
    """POST llm_raw_chat，返回未读取的原始 response（流式，调用方负责关闭）。

    只在"连不上"时切换备选主机；HTTP 状态码/业务错误立即抛 UpstreamError，
    避免把 4015 风控误当成网络抖动反复重放。

    headers_extra：账号级头覆盖（换设备指纹 / 加 x-tt-token 等排障字段）；
      键名大小写不敏感，value=None 表示删除该头。
    proxy：本次调用专用出口（如 http://127.0.0.1:7890），不传则走环境变量。
    """
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    if body is None:
        raise ValueError("body 不能为空")
    # 国际版直连：raw_chat 使用当前客户端版本头 + Bearer（见下方 auth）。
    if isinstance(body, (bytes, bytearray)):
        data = bytes(body)
    elif isinstance(body, str):
        data = body.encode("utf-8")
    else:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = auth_headers(account, realm)
    if realm == "intl":
        # 国际版 raw_chat 使用 Bearer（不是 Cloud-IDE-JWT）；
        # 同时必须使用当前客户端版本，否则 4015。
        token = _token(account)
        headers["Authorization"] = "Bearer " + token
        headers["x-ide-token"] = token
        headers["x-ide-version-code"] = "20260924"
        headers["x-ide-version"] = "3.6.2"
        headers["x-app-version"] = "3.6.2"
        headers["x-app-version-code"] = "20260924"
        headers["User-Agent"] = "TraeClient/TTNet"
        headers["store-country-code"] = "us"
    headers["Accept"] = "text/event-stream"
    headers["Cache-Control"] = "no-cache"
    if headers_extra:
        for key, value in dict(headers_extra).items():
            for existing in [k for k in headers if k.lower() == str(key).lower()]:
                headers.pop(existing, None)
            if value is not None:
                headers[str(key)] = str(value)
    if proxy is None:
        # 账号级出口（Account.proxy / egress）优先于环境变量
        proxy = account.get("proxy") or account.get("egress") or None
    hosts = _hosts(account, realm, "core")
    last_exc = None
    attempts = []
    for host in hosts:
        url = host + PATH_CHAT
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        attempts.append(url)
        try:
            return _open(req, timeout, proxy=proxy)
        except urllib.error.HTTPError as exc:
            raise _http_error(exc)
        except (urllib.error.URLError, socket.timeout, TimeoutError,
                ConnectionError, OSError) as exc:
            last_exc = exc
            continue
    raise _network_error(attempts, last_exc)


def _line_reader(source):
    """把 response / 文件对象 / 行列表 / 可迭代行 统一成 next_line()。

    测试与离线回放常直接喂 list[bytes]，生产是 urllib response（有 readline），
    两种形态都必须能解析，所以这里做一层薄适配，不引入任何依赖。
    """
    if source is None:
        return lambda: b""
    readline = getattr(source, "readline", None)
    if callable(readline):
        return readline
    iterator = iter(source)

    def _next():
        try:
            return next(iterator)
        except StopIteration:
            return b""

    return _next


def _set_read_timeout(resp, seconds):
    """尽力把底层 socket 的读超时改成 seconds；返回是否成功。

    list/BytesIO 这类离线输入没有 socket，调用方会退化成 monotonic 计时检查。
    """
    if not seconds or seconds <= 0:
        return False
    sock = None
    fp = getattr(resp, "fp", None)
    raw = getattr(fp, "raw", None)
    sock = getattr(raw, "_sock", None) or getattr(resp, "_sock", None)
    if sock is None:
        return False
    try:
        sock.settimeout(float(seconds))
        return True
    except Exception:
        return False


def _idle_payload(seconds):
    return {"code": "idle_timeout", "error": "idle_timeout",
            "message": "上游 %s 秒无数据，判定连接挂死" % (int(seconds),),
            "extra": None}


def iter_events(resp, raise_on_error=False, close=True, idle_timeout=60):
    """逐帧解析 SSE，产出 (event, data)。

    - 兼容 CRLF、多行 data、注释行、data: [DONE]；
    - data 能 JSON 解析就转 dict，否则保留原始字符串；
    - event: error 默认原样产出（流式场景不能让异常打断已产出的正文），
      raise_on_error=True 时在产出后立刻抛 UpstreamError；
    - idle_timeout：连续 N 秒收不到任何字节就产出一次 error 帧并停止，
      防止半死连接把网关 worker 挂住（<=0 表示关闭；离线输入用 monotonic 兜底）；
    - 生成器结束时关闭 response（close=False 可关闭该行为）。
    """
    event = None
    data_lines = []
    reader = _line_reader(resp)
    idle_seconds = float(idle_timeout) if idle_timeout and idle_timeout > 0 else 0.0
    socket_timeout_set = _set_read_timeout(resp, idle_seconds)
    last_activity = time.monotonic()

    def _dispatch(ev, raw):
        if raw.strip() == "[DONE]":
            return ("done", {"finish_reason": "stop"})
        try:
            payload = json.loads(raw)
        except Exception:
            payload = raw
        return (ev or "message", payload)

    def _close():
        if close and resp is not None:
            try:
                resp.close()
            except Exception:
                pass

    try:
        while True:
            try:
                line = reader()
            except (socket.timeout, TimeoutError):
                # 先把已经收全的半帧交出去，再报空闲超时，避免丢正文
                if data_lines:
                    ev, pending = _dispatch(event, "\n".join(data_lines))
                    event, data_lines = None, []
                    yield ev, pending
                payload = _idle_payload(idle_seconds or 0)
                yield "error", payload
                if raise_on_error:
                    raise UpstreamError.from_event(payload)
                break
            if not line:
                # 离线输入（无 socket）也要防挂死：读端阻塞由调用方控制，
                # 这里只对"空行 + 超时"这一可观测信号兜底。
                if (idle_seconds and not socket_timeout_set
                        and time.monotonic() - last_activity > idle_seconds):
                    payload = _idle_payload(idle_seconds)
                    yield "error", payload
                    if raise_on_error:
                        raise UpstreamError.from_event(payload)
                break
            last_activity = time.monotonic()
            line = _decode(line).rstrip("\r\n")
            if not line:
                if data_lines:
                    ev, payload = _dispatch(event, "\n".join(data_lines))
                    event, data_lines = None, []
                    yield ev, payload
                    if ev == "error" and raise_on_error:
                        raise UpstreamError.from_event(payload)
                event = None
                continue
            if line.startswith(":"):
                continue
            field, _, value = line.partition(":")
            field = field.strip()
            if value.startswith(" "):
                value = value[1:]
            if field == "event":
                event = value.strip()
            elif field == "data":
                data_lines.append(value)
            # id / retry 与协议无关，忽略
        if data_lines:
            ev, payload = _dispatch(event, "\n".join(data_lines))
            yield ev, payload
            if ev == "error" and raise_on_error:
                raise UpstreamError.from_event(payload)
    finally:
        _close()


def collect(resp, raise_on_error=False):
    """把整条 SSE 聚合成结构化结果（非流式网关 / 自检用）。

    返回:
      {"events": [event 名称序列], "text", "reasoning", "tool_calls",
       "usage", "finish_reason", "metadata", "errors"}
    """
    out = {
        "events": [],
        "text": "",
        "reasoning": "",
        "tool_calls": [],
        "usage": {},
        "finish_reason": None,
        "metadata": {},
        "errors": [],
    }
    for event, data in iter_events(resp, raise_on_error=raise_on_error):
        out["events"].append(event)
        if event == "metadata" and isinstance(data, dict):
            out["metadata"] = data
        elif event == "output" and isinstance(data, dict):
            out["text"] += data.get("response") or ""
            out["reasoning"] += data.get("reasoning_content") or ""
            if data.get("tool_calls"):
                out["tool_calls"].append(data["tool_calls"])
        elif event == "token_usage" and isinstance(data, dict):
            out["usage"] = data
        elif event == "done" and isinstance(data, dict):
            out["finish_reason"] = data.get("finish_reason") or "stop"
        elif event == "error":
            out["errors"].append(data)
    if out["finish_reason"] is None:
        out["finish_reason"] = "stop" if out["text"] else "error"
    return out


def chat_once(account, realm=None, model=None, messages=None, **opts):
    """一次性聊天：返回 collect() 的结构化结果（诊断 / 非流式网关）。"""
    body = build_chat_body(model, messages or [], **opts)
    resp = open_chat(_as_mapping(account), realm, body,
                     timeout=opts.get("timeout", DEFAULT_TIMEOUT))
    return collect(resp)


# ---------------------------------------------------------------------------
# Token 刷新（ExchangeToken，轮换式）
# ---------------------------------------------------------------------------
def _ms_to_iso(ms):
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return None
    dt = datetime.datetime.fromtimestamp(ms / 1000.0, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ms % 1000)


def _parse_iso(value):
    """ISO8601 / epoch（秒或毫秒）-> aware datetime；失败返回 None。"""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e11:  # 毫秒
            seconds /= 1000.0
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(text)
    except ValueError:
        try:
            seconds = float(text)
        except ValueError:
            return None
        if seconds > 1e11:
            seconds /= 1000.0
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)


def is_expired(account, skew=60):
    """access token 是否已过期（skew=提前量秒）。无 expiredAt 时按未过期处理。

    兼容 ISO 字符串与 epoch（秒/毫秒），所以 Account 的 expired_at 也直接可用。
    """
    account = _as_mapping(account)
    expired_at = _parse_iso(account.get("expiredAt") or account.get("expired_at")
                            or account.get("expiredAtMs"))
    if expired_at is None:
        return False
    if expired_at.tzinfo is None:
        expired_at = expired_at.replace(tzinfo=datetime.timezone.utc)
    return expired_at <= datetime.datetime.now(datetime.timezone.utc) + \
        datetime.timedelta(seconds=skew)


def _post_no_auth(url, payload, timeout=30, realm="intl"):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": REALMS[normalize_realm(realm)]["ua"],
    }
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with _open(req, timeout) as resp:
            return json.loads(_decode(resp.read()) or "{}")
    except urllib.error.HTTPError as exc:
        raise _http_error(exc)


# 刷新失败缓存（进程内）：同一账号连续失败按指数退避，避免网关 1-2 秒打一次
# 401 把账号/IP 彻底打黑。键不含 refreshToken 原文（uid 或哈希）。
_REFRESH_FAILURE_LOCK = threading.Lock()
_REFRESH_FAILURES = {}
REFRESH_BACKOFF_BASE = float(os.environ.get("TRAE_REFRESH_BACKOFF_BASE") or 30)
REFRESH_BACKOFF_MAX = float(os.environ.get("TRAE_REFRESH_BACKOFF_MAX") or 1800)


def _refresh_failure_key(account):
    account = _as_mapping(account)
    realm = normalize_realm(account.get("realm") or realm_of(account))
    uid = _uid(account)
    if uid:
        return "%s:%s" % (realm, uid)
    refresh = str(account.get("refreshToken") or account.get("refresh_token") or "")
    digest = hashlib.sha256(refresh.encode("utf-8")).hexdigest()[:16]
    return "%s:rt-%s" % (realm, digest)


def _refresh_backoff_state(key):
    with _REFRESH_FAILURE_LOCK:
        return dict(_REFRESH_FAILURES.get(key) or {})


def refresh_backoff_remaining(account):
    """距离下次允许刷新还有多少秒（0 = 可以刷）。"""
    state = _refresh_backoff_state(_refresh_failure_key(account))
    if not state:
        return 0.0
    return max(0.0, float(state.get("next_at") or 0) - time.monotonic())


def reset_refresh_backoff(account=None):
    """清空失败缓存（account=None 清全部）；运维/测试用。"""
    with _REFRESH_FAILURE_LOCK:
        if account is None:
            _REFRESH_FAILURES.clear()
            return
        _REFRESH_FAILURES.pop(_refresh_failure_key(account), None)


def _note_refresh_failure(key, exc):
    with _REFRESH_FAILURE_LOCK:
        entry = dict(_REFRESH_FAILURES.get(key) or {})
        count = int(entry.get("count") or 0) + 1
        delay = min(REFRESH_BACKOFF_BASE * (2 ** (count - 1)), REFRESH_BACKOFF_MAX)
        entry.update({
            "count": count,
            "delay": delay,
            "next_at": time.monotonic() + delay,
            "code": getattr(exc, "code", "refresh_failed"),
            "message": str(getattr(exc, "message", exc))[:200],
            "status": getattr(exc, "status", None),
        })
        _REFRESH_FAILURES[key] = entry


def _clear_refresh_failure(key):
    with _REFRESH_FAILURE_LOCK:
        _REFRESH_FAILURES.pop(key, None)


def refresh_account(account, timeout=30, force=False, ignore_backoff=False):
    """ExchangeToken 轮换刷新（PROTOCOL 第五节），带失败退避。

    连续失败按指数退避（默认 30s 起，封顶 1800s，可用环境变量
    TRAE_REFRESH_BACKOFF_BASE / TRAE_REFRESH_BACKOFF_MAX 调整）；
    冷却期内直接抛 UpstreamError(code="refresh_backoff", retry_after=秒)，
    不发网络请求——避免网关 1-2 秒一次 401 把账号彻底打黑。
    force=True 仅表示忽略"token 未到期"窗口；要强制重打用 ignore_backoff=True。

    返回**新 dict**，不修改入参：上游每次返回新的 RefreshToken，旧的立即失效，
    因此调用方必须把返回值原子落盘（账号池的职责），否则下次刷新会失败。
    """
    account = _as_mapping(account)
    key = _refresh_failure_key(account)
    remaining = refresh_backoff_remaining(account)
    # force 只表示"忽略 token 未到期的窗口"，**不允许**绕过失败退避；
    # 只有 ignore_backoff=True（人工排障）才真的清空计时器重打一次。
    if remaining > 0 and not ignore_backoff:
        raise UpstreamError(
            "refresh_backoff",
            "刷新失败冷却中：约 %.0f 秒后可重试（连续失败 %d 次，上次 %s）"
            % (remaining, int(_refresh_backoff_state(key).get("count") or 0),
               _refresh_backoff_state(key).get("message") or "-"),
            None,
            payload={"retry_after": round(remaining, 1)},
            retry_after=remaining,
        )
    try:
        fresh = _refresh_account_request(account, timeout=timeout, key=key)
    except UpstreamError as exc:
        _note_refresh_failure(key, exc)
        raise
    except Exception as exc:
        _note_refresh_failure(key, UpstreamError(type(exc).__name__, str(exc)))
        raise
    _clear_refresh_failure(key)
    return fresh


def _refresh_account_request(account, timeout=30, key=None):
    """真正发 ExchangeToken 的实现（refresh_account 负责失败退避）。

    返回**新 dict**，不修改入参：上游每次返回新的 RefreshToken，旧的立即失效，
    因此调用方必须把返回值原子落盘（账号池的职责），否则下次刷新会失败。

    实测响应（Result 字段）：
      Token / RefreshToken / TokenExpireAt(ms) / RefreshExpireAt(ms) /
      TokenExpireDuration / UserJwt / ClientID
    """
    account = _as_mapping(account)
    realm = normalize_realm(account.get("realm") or realm_of(account))
    refresh = account.get("refreshToken") or account.get("refresh_token")
    if not refresh:
        raise UpstreamError("no_refresh_token", "账号缺少 refreshToken，无法刷新", None)
    payload = {
        "ClientID": CLIENT_ID,
        "RefreshToken": refresh,
        "ClientSecret": CLIENT_SECRET,
        "UserID": _uid(account),
    }
    # INTL 客户端会带设备证明（iCubeAuthInfo://icube-dc 私钥 + ECDSA-SHA256）。
    # 没有私钥时不带，CN 也不需要（Lead 实测 CN 不带也能刷）。
    proof = None
    if realm == "intl":
        device = _resolve_device_credentials(account, realm)
        if device:
            try:
                proof = build_device_proof(account, "POST", PATH_EXCHANGE_TOKEN, refresh,
                                           private_key_pem=device.get("privateKeyPEM"))
                payload["DeviceInfo"] = proof["DeviceInfo"]
                payload["DeviceProof"] = proof["DeviceProof"]
            except UpstreamError as exc:
                proof = {"error": str(exc)}
    hosts = _hosts(account, realm, "account")
    last_exc = None
    parsed = None
    used = None
    for host in hosts:
        url = host + PATH_EXCHANGE_TOKEN
        try:
            parsed = _post_no_auth(url, payload, timeout=timeout, realm=realm)
            used = url
            break
        except UpstreamError as exc:
            # 业务错误（如刷新令牌失效）不换主机重放
            if exc.status is not None:
                raise
            last_exc = exc
        except (urllib.error.URLError, socket.timeout, TimeoutError,
                ConnectionError, OSError) as exc:
            last_exc = exc
            continue
    if parsed is None:
        if isinstance(last_exc, UpstreamError):
            raise last_exc
        raise _network_error([h + PATH_EXCHANGE_TOKEN for h in hosts], last_exc)

    result = parsed.get("Result") if isinstance(parsed, dict) else None
    if not isinstance(result, dict):
        result = parsed if isinstance(parsed, dict) else {}
    token = result.get("Token") or result.get("token")
    if not token:
        code = (parsed or {}).get("Code") or (parsed or {}).get("code") or "refresh_failed"
        message = ((parsed or {}).get("Message") or (parsed or {}).get("message")
                   or "ExchangeToken 未返回 Token")
        raise UpstreamError(code, message, None, payload=parsed)

    fresh = dict(account)
    fresh["token"] = token
    fresh["refreshToken"] = result.get("RefreshToken") or result.get("refresh_token") or refresh
    expired_iso = _ms_to_iso(result.get("TokenExpireAt"))
    if expired_iso:
        fresh["expiredAt"] = expired_iso
    refresh_iso = _ms_to_iso(result.get("RefreshExpireAt"))
    if refresh_iso:
        fresh["refreshExpiredAt"] = refresh_iso
    if result.get("TokenExpireDuration") is not None:
        fresh["tokenExpireDuration"] = result.get("TokenExpireDuration")
    if result.get("UserJwt"):
        fresh["userJwt"] = result.get("UserJwt")
    fresh["realm"] = realm
    fresh["refreshedAt"] = datetime.datetime.now(datetime.timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    fresh["refreshHost"] = used
    fresh["deviceProofUsed"] = bool(isinstance(proof, dict) and "DeviceProof" in proof)
    return fresh


def ensure_token(account, skew=120, persist=None):
    """到期才刷新；给了 persist(new_account) 就原子回写（轮换安全）。

    没有 persist 时仍然返回新账号，但调用方必须自己落盘，
    否则磁盘上的旧 refreshToken 已被上游作废。
    """
    account = _as_mapping(account)
    if not is_expired(account, skew=skew):
        return dict(account)
    fresh = refresh_account(account)
    if callable(persist):
        try:
            persist(fresh)
        except Exception as exc:
            # 轮换已经发生：新 token 只在返回值里，调用方必须补一次落盘
            fresh["persistError"] = "%s: %s" % (type(exc).__name__, exc)
    return fresh


# ---------------------------------------------------------------------------
# 通用 JSON 请求
# ---------------------------------------------------------------------------
def request_json(account, realm=None, path="", body=None, base="core",
                 timeout=60, method="POST"):
    """带鉴权头的 JSON 请求；连不上时按区域备选主机重试。"""
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    proxy = account.get("proxy") or account.get("egress") or None
    hosts = _hosts(account, realm, base)
    last_exc = None
    raw = None
    for host in hosts:
        url = host + path
        headers = auth_headers(account, realm)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with _open(req, timeout, proxy=proxy) as resp:
                raw = resp.read()
            break
        except urllib.error.HTTPError as exc:
            raise _http_error(exc)
        except (urllib.error.URLError, socket.timeout, TimeoutError,
                ConnectionError, OSError) as exc:
            last_exc = exc
            continue
    if raw is None:
        raise _network_error([h + path for h in hosts], last_exc)
    text = _decode(raw).strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except ValueError:
        raise UpstreamError("bad_json", "上游返回非 JSON：%s" % text[:200], None)


def fetch_model_list(account, realm=None, type="chat"):
    """model_list（PROTOCOL 第八节），返回 model_configs 列表。

    CN 可用；INTL 该接口 403 no schema found —— 这里如实抛 UpstreamError，
    模型目录由上层本地快照兜底。
    """
    realm = normalize_realm(realm or realm_of(account))
    if not REALMS[realm]["model_list_supported"]:
        raise UpstreamError(403, "no schema found（%s 区 model_list 不可用，走上层本地快照）"
                            % REALMS[realm]["label"], 403)
    payload = request_json(account, realm, PATH_MODEL_LIST, {"type": type},
                           base="core", timeout=45)
    models = []
    if isinstance(payload, dict):
        models = payload.get("model_configs") or payload.get("models") or []
    elif isinstance(payload, list):
        models = payload
    return [m for m in models if isinstance(m, dict)]


def fetch_usage(account, realm=None, timeout=45):
    """会话用量（PROTOCOL 第九节）：返回 get_session_usage 原始 JSON。"""
    realm = normalize_realm(realm or realm_of(account))
    return request_json(account, realm, PATH_SESSION_USAGE, {}, base="core",
                        timeout=timeout)


def fetch_activity(account, realm=None, timeout=45):
    """用户活跃度（activity_map），失败由调用方决定是否忽略。"""
    realm = normalize_realm(realm or realm_of(account))
    return request_json(account, realm, PATH_ACTIVITY, {}, base="core",
                        timeout=timeout)


def fetch_entitlement(account, realm=None, strict=False, timeout=45):
    """权益包 / 付费状态（PROTOCOL 第九节）。

    两个 pay 接口任一失败都不影响主链路：默认把错误收进 errors 列表返回
    （strict=True 时第一个错误直接抛）。INTL 的 pay host 可能与 CN 不同，
    hosts 里已带备选。
    """
    realm = normalize_realm(realm or realm_of(account))
    out = {"realm": realm, "ent_usage": None, "pay_status": None, "errors": []}
    ent_path = PATH_ENT_USAGE_V2 if realm == "cn" else PATH_ENT_USAGE
    for key, path in (("ent_usage", ent_path), ("pay_status", PATH_PAY_STATUS)):
        try:
            out[key] = request_json(account, realm, path, {}, base="pay",
                                    timeout=timeout)
        except UpstreamError as exc:
            if strict:
                raise
            out["errors"].append({"endpoint": key, "code": exc.code,
                                  "message": exc.message, "status": exc.status})
        except Exception as exc:  # 兜底：绝不因权益接口打断聊天
            if strict:
                raise
            out["errors"].append({"endpoint": key, "code": "exception",
                                  "message": str(exc), "status": None})
    return out


PATH_CHECKIN_STATUS = "/trae/api/v2/ug/checkin_credits/status"
PATH_CHECKIN_CLAIM = "/trae/api/v2/ug/checkin_credits/claim"


def _checkin_req_source(realm):
    """客户端：国内版 1、国际版 2（main.js li(this.P)?2:1）。"""
    return 2 if normalize_realm(realm) == "intl" else 1


def checkin_status(account, realm=None, timeout=30):
    """每日签到状态（仅国内版真实可用）。

    实测响应（CN，2026-10-19）：
      {"checked_in":true,"code":0,"credits":100,"did_checked_in":false,
       "enable":true,"extra_credits":100,"message":"success"}

    INTL 返回 404/业务错误；本函数如实抛 UpstreamError，不伪造状态。
    """
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    body = {"req_source": _checkin_req_source(realm)}
    data = request_json(account, realm, PATH_CHECKIN_STATUS, body, base="ug",
                        timeout=timeout)
    if not isinstance(data, dict):
        data = {}
    return data


def claim_checkin(account, realm=None, timeout=30):
    """领取每日签到；返回统一结构：

      {"ok": bool, "checked_in": bool, "already": bool,
       "credits": int, "earned_credit": int, "message": str, "raw": {...}}

    幂等：已签到直接返回 already=True，不重复领取；领取后再查一次状态，
    用 credits 差额计算真实到账，绝不把「接口 200」当成「已到账」。
    """
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    before = checkin_status(account, realm, timeout=timeout)
    if before.get("checked_in"):
        return {"ok": True, "checked_in": True, "already": True,
                "credits": int(before.get("credits") or 0),
                "earned_credit": 0,
                "message": "今日已签到（积分 %s）" % int(before.get("credits") or 0),
                "raw": before}
    body = {"req_source": _checkin_req_source(realm)}
    raw = request_json(account, realm, PATH_CHECKIN_CLAIM, body, base="ug",
                       timeout=timeout)
    after = checkin_status(account, realm, timeout=timeout)
    before_credits = int(before.get("credits") or 0)
    after_credits = int(after.get("credits") or 0)
    earned = max(0, after_credits - before_credits)
    ok = bool(after.get("checked_in")) and (not isinstance(raw, dict)
                                            or raw.get("code") in (0, None))
    return {"ok": ok, "checked_in": bool(after.get("checked_in")),
            "already": False, "credits": after_credits,
            "earned_credit": earned,
            "message": (("签到成功（积分 %s）" % after_credits) if ok
                        else (after.get("message") or (raw or {}).get("message")
                              or "签到未生效")),
            "raw": {"claim": raw, "status": after}}


def generate_temp_token(account, realm=None, timeout=30):
    """CloudIDE 临时 token（7 天，PROTOCOL 第五节；仅排障用）。"""
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    token = _token(account)
    if not token:
        raise UpstreamError("no_token", "账号缺少 access token", None)
    headers = auth_headers(account, realm)
    headers["x-cloudide-token"] = token
    hosts = _hosts(account, realm, "account")
    last_exc = None
    ide_version = REALMS[realm]["ua"].split("/")[-1]
    for host in hosts:
        url = host + PATH_TEMP_TOKEN
        data = json.dumps({"IDEVersion": ide_version}).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with _open(req, timeout) as resp:
                return json.loads(_decode(resp.read()) or "{}")
        except urllib.error.HTTPError as exc:
            raise _http_error(exc)
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            last_exc = exc
    raise _network_error(hosts, last_exc)


# ---------------------------------------------------------------------------
# 纯标准库 AES-128 解密（Desktop 凭证）
# ---------------------------------------------------------------------------
def _gmul(a, b):
    """GF(2^8) 乘法（不可约多项式 0x11B）。"""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return product


def _rotl8(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _build_sbox():
    """按 FIPS-197 定义现场生成 S-box（逆元 + 仿射变换）。"""
    inverse = [0] * 256
    for i in range(1, 256):
        for x in range(1, 256):
            if _gmul(i, x) == 1:
                inverse[i] = x
                break
    sbox = []
    for i in range(256):
        v = inverse[i]
        sbox.append(v ^ _rotl8(v, 1) ^ _rotl8(v, 2) ^ _rotl8(v, 3)
                    ^ _rotl8(v, 4) ^ 0x63)
    return sbox


_SBOX = _build_sbox()
_INV_SBOX = [0] * 256
for _index, _value in enumerate(_SBOX):
    _INV_SBOX[_value] = _index
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _expand_key(key):
    """AES 密钥扩展（16/24/32 字节；Trae 凭证固定 16 字节）。"""
    size = len(key)
    if size == 16:
        words, rounds = [list(key[i:i + 4]) for i in range(0, 16, 4)], 44
    elif size == 24:
        words, rounds = [list(key[i:i + 4]) for i in range(0, 24, 4)], 52
    elif size == 32:
        words, rounds = [list(key[i:i + 4]) for i in range(0, 32, 4)], 60
    else:
        raise ValueError("AES 密钥长度必须是 16/24/32 字节，实际 %d" % size)
    nk = size // 4
    for i in range(nk, rounds):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(rounds // 4):
        rk = []
        for c in range(4):
            rk.extend(words[r * 4 + c])
        round_keys.append(rk)
    return round_keys


def _decrypt_block(block, round_keys):
    """AES 单块解密（InvSubBytes+InvShiftRows -> AddRoundKey -> InvMixColumns）。"""
    nr = len(round_keys) - 1
    state = [block[i] ^ round_keys[nr][i] for i in range(16)]

    def inv_sub_shift(s):
        out = [0] * 16
        for c in range(4):
            for r in range(4):
                out[r + 4 * ((c + r) % 4)] = _INV_SBOX[s[r + 4 * c]]
        return out

    def inv_mix_col(s):
        out = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            out[4 * c + 0] = (_gmul(a[0], 14) ^ _gmul(a[1], 11)
                              ^ _gmul(a[2], 13) ^ _gmul(a[3], 9))
            out[4 * c + 1] = (_gmul(a[0], 9) ^ _gmul(a[1], 14)
                              ^ _gmul(a[2], 11) ^ _gmul(a[3], 13))
            out[4 * c + 2] = (_gmul(a[0], 13) ^ _gmul(a[1], 9)
                              ^ _gmul(a[2], 14) ^ _gmul(a[3], 11))
            out[4 * c + 3] = (_gmul(a[0], 11) ^ _gmul(a[1], 13)
                              ^ _gmul(a[2], 9) ^ _gmul(a[3], 14))
        return out

    for rnd in range(nr - 1, 0, -1):
        state = inv_sub_shift(state)
        state = [state[i] ^ round_keys[rnd][i] for i in range(16)]
        state = inv_mix_col(state)
    state = inv_sub_shift(state)
    return bytes(state[i] ^ round_keys[0][i] for i in range(16))


def _encrypt_block(block, round_keys):
    """AES 单块加密（SubBytes+ShiftRows -> MixColumns -> AddRoundKey）。"""
    nr = len(round_keys) - 1
    state = [block[i] ^ round_keys[0][i] for i in range(16)]

    def sub_shift(s):
        out = [0] * 16
        for c in range(4):
            for r in range(4):
                out[r + 4 * c] = _SBOX[s[r + 4 * ((c + r) % 4)]]
        return out

    def mix_col(s):
        out = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            out[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            out[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            out[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            out[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        return out

    for rnd in range(1, nr):
        state = sub_shift(state)
        state = mix_col(state)
        state = [state[i] ^ round_keys[rnd][i] for i in range(16)]
    state = sub_shift(state)
    return bytes(state[i] ^ round_keys[nr][i] for i in range(16))


def aes_cbc_encrypt(plain, key, iv):
    """AES-CBC 加密 + PKCS#7 填充（仅为测试构造合成 iCube 封装，运行时不用）。"""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥长度非法：%d" % len(key))
    if len(iv) != 16:
        raise ValueError("AES IV 必须是 16 字节")
    pad = 16 - len(plain) % 16
    data = bytes(plain) + bytes([pad]) * pad
    round_keys = _expand_key(key)
    out = bytearray()
    prev = iv
    for offset in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[offset:offset + 16], prev))
        encrypted = _encrypt_block(block, round_keys)
        out.extend(encrypted)
        prev = encrypted
    return bytes(out)


def aes_cbc_decrypt(data, key, iv):
    """AES-CBC 解密 + 严格 PKCS#7 校验（只解密方向，够用即止）。"""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥长度非法：%d" % len(key))
    if len(iv) != 16:
        raise ValueError("AES IV 必须是 16 字节")
    if not data or len(data) % 16:
        raise ValueError("密文长度 %d 不是 16 的整数倍" % len(data))
    round_keys = _expand_key(key)
    out = bytearray()
    prev = iv
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        decrypted = _decrypt_block(block, round_keys)
        out.extend(a ^ b for a, b in zip(decrypted, prev))
        prev = block
    pad = out[-1]
    if pad < 1 or pad > 16 or bytes(out[-pad:]) != bytes([pad] * pad):
        raise ValueError("PKCS#7 填充校验失败")
    return bytes(out[:-pad])


def _aes_self_check():
    """NIST FIPS-197 附录 C 测试向量（AES-128 单块 ECB 解密）。

    用单块解密直接比对，不经过 CBC/PKCS#7：CBC 自检需要构造"密文 + 合法填充块"，
    很容易写成假阳性/假阴性，单块 ECB 才是密码学层面的权威向量。
    """
    key = bytes(range(16))
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    return _decrypt_block(cipher, _expand_key(key)) == plain


# Trae 客户端 byteCrypto.js 里的两份 64 字节常量（PROTOCOL 第四节）
_ULE = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243,
              215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68,
              196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76,
              149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178,
              118, 91, 162, 73, 109, 139, 209, 37])
_DLE = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128,
              236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159,
              147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200,
              235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214,
              38, 225, 105, 20, 99, 85, 33, 12, 125])

ICUBE_MAGIC = b"tc"


def decrypt_icube_blob(value):
    """解密 storage.json 里的 iCubeAuthInfo://icube.cloudide 值。

    二进制封装（PROTOCOL 第四节）：
      0..1  't','c' | 2 version | 3 0x10 | 4..5 0,0 | 6..37 key material(32B)
      38..  AES-128-CBC 密文
    派生：o=SHA512(keymat); a=ULE^DLE; n=o||a; n[0:64]=SHA512(n);
          key=n[0:16]; iv=n[16:32]；明文 = SHA512(body)(64B) || body。
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("iCubeAuthInfo 值不是非空字符串")
    try:
        raw = base64.b64decode(value.strip())
    except Exception as exc:
        raise ValueError("base64 解码失败：%s" % exc)
    if len(raw) < 38 + 16:
        raise ValueError("封装过短（%d 字节）" % len(raw))
    if raw[:2] != ICUBE_MAGIC:
        raise ValueError("magic 不是 tc（实际 %r）" % raw[:2])
    version = raw[2]
    if version != 5:
        raise ValueError("未知封装版本：%d" % version)
    key_material = raw[6:38]
    cipher = raw[38:]
    outer = hashlib.sha512(key_material).digest()
    mixed = bytes(x ^ y for x, y in zip(_ULE, _DLE))
    seed = bytearray(outer + mixed)
    seed[0:64] = hashlib.sha512(bytes(seed)).digest()
    aes_key = bytes(seed[0:16])
    iv = bytes(seed[16:32])
    plain = aes_cbc_decrypt(cipher, aes_key, iv)
    digest, body = plain[:64], plain[64:]
    if hashlib.sha512(body).digest() != digest:
        raise ValueError("正文 SHA512 摘要校验失败（密钥或封装不匹配）")
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise ValueError("正文不是合法 JSON：%s" % exc)
    if not isinstance(data, dict):
        raise ValueError("正文 JSON 不是对象")
    return data


def build_icube_blob(payload, key_material=None):
    """构造一个符合 Trae tc 封装的密文（测试夹具；生产只解密不加密）。

    payload: dict（会被 json 序列化）或 bytes/str。
    返回 base64 字符串，形状与 storage.json 里的 iCubeAuthInfo 值一致。
    """
    if isinstance(payload, dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = bytes(payload)
    if key_material is None:
        key_material = os.urandom(32)
    if len(key_material) != 32:
        raise ValueError("key material 必须是 32 字节")
    outer = hashlib.sha512(key_material).digest()
    mixed = bytes(x ^ y for x, y in zip(_ULE, _DLE))
    seed = bytearray(outer + mixed)
    seed[0:64] = hashlib.sha512(bytes(seed)).digest()
    aes_key = bytes(seed[0:16])
    iv = bytes(seed[16:32])
    plain = hashlib.sha512(body).digest() + body
    header = ICUBE_MAGIC + bytes([5, 0x10, 0, 0]) + key_material
    return base64.b64encode(header + aes_cbc_encrypt(plain, aes_key, iv)).decode("ascii")


# 对外别名：测试用合成 blob 做 AES 往返，不必碰真实 storage.json
decode_auth_blob = decrypt_icube_blob


# ---------------------------------------------------------------------------
# 纯标准库 ECDSA P-256（INTL ExchangeToken 的 DeviceProof）
# ---------------------------------------------------------------------------
# Trae 客户端刷新国际版 token 时带设备证明：iCubeAuthInfo://icube-dc:<holder>
# 解密得到 privateKeyPEM（PKCS#8 / SEC1, prime256v1），对
#   "METHOD PATH ClientID RefreshToken timestamp nonce"
# 做 ECDSA-SHA256，签名 base64 放进 DeviceProof.Signature。
# 这条链路**未线上实测**（轮换会让桌面端 refreshToken 失效），实现按客户端字段
# 结构落地，可被账号池注入的 privateKeyPEM 覆盖。
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (P256_GX, P256_GY)


def _ec_add(P, Q):
    """仿射点加；None 表示无穷远点。"""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None
        # 倍点
        lam = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def _ec_mul(k, P=P256_G):
    """标量乘（double-and-add）；k 为 0 返回 None。"""
    k %= P256_N
    result = None
    addend = P
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _der_tlv(data, offset):
    """读一个 DER TLV，返回 (tag, value, next_offset)。"""
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def _der_children(value):
    """把 SEQUENCE 的 value 拆成子 TLV 列表。"""
    items = []
    offset = 0
    while offset < len(value):
        tag, chunk, offset = _der_tlv(value, offset)
        items.append((tag, chunk))
    return items


def _pem_to_der(pem):
    lines = [line.strip() for line in str(pem).strip().splitlines()]
    body = "".join(line for line in lines if line and not line.startswith("-----"))
    return base64.b64decode(body)


def ec_private_key_from_pem(pem):
    """PKCS#8 或 SEC1 PEM -> 私钥整数 d（prime256v1）。"""
    der = _pem_to_der(pem)
    tag, body, _ = _der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("私钥 PEM 不是 DER SEQUENCE")
    items = _der_children(body)
    if not items:
        raise ValueError("私钥 PEM 为空")
    # PKCS#8: INTEGER 0, SEQUENCE(alg), OCTET STRING(ECPrivateKey)
    if items[0][0] == 0x02 and len(items) >= 3 and items[2][0] == 0x04:
        outer_d = items[2][1]
        tag2, body2, _ = _der_tlv(outer_d, 0)
        if tag2 != 0x30:
            raise ValueError("PKCS#8 内层不是 ECPrivateKey")
        inner = _der_children(body2)
        if len(inner) < 2 or inner[1][0] != 0x04:
            raise ValueError("ECPrivateKey 缺少私钥字段")
        d = int.from_bytes(inner[1][1], "big")
    # SEC1: INTEGER 1, OCTET STRING(d)
    elif items[0][0] == 0x02 and len(items) >= 2 and items[1][0] == 0x04:
        d = int.from_bytes(items[1][1], "big")
    else:
        raise ValueError("无法识别的 EC 私钥 PEM 结构")
    if not 1 <= d < P256_N:
        raise ValueError("EC 私钥标量超出 P-256 范围")
    return d


def ec_public_key_from_pem(pem):
    """SPKI PEM -> (x, y)；仅用于自检（生产只需要私钥）。"""
    der = _pem_to_der(pem)
    tag, body, _ = _der_tlv(der, 0)
    items = _der_children(body)
    bit = None
    for item_tag, chunk in items:
        if item_tag == 0x03:
            bit = chunk
    if bit is None:
        raise ValueError("SPKI 缺少 BIT STRING")
    point = bit[1:]  # 去掉 unused-bits 字节
    if point[:1] != b"\x04" or len(point) != 65:
        raise ValueError("公钥不是未压缩 P-256 点")
    return (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big"))


def _der_encode_integer(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def der_encode_signature(r, s):
    """ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }"""
    body = _der_encode_integer(r) + _der_encode_integer(s)
    return b"\x30" + bytes([len(body)]) + body


def p256_sign(private_key, message, k=None):
    """ECDSA-SHA256 签名，返回 (r, s)；s 归一化为 low-S（客户端常见做法）。"""
    d = private_key
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    while True:
        if k is None:
            nonce = int.from_bytes(os.urandom(32), "big") % P256_N
        else:
            nonce = k % P256_N
        point = _ec_mul(nonce)
        if point is None:
            if k is not None:
                raise ValueError("k 无效")
            continue
        r = point[0] % P256_N
        if r == 0:
            if k is not None:
                raise ValueError("r=0")
            continue
        s = (pow(nonce, -1, P256_N) * (z + r * d)) % P256_N
        if s == 0:
            if k is not None:
                raise ValueError("s=0")
            continue
        if s > P256_N // 2:
            s = P256_N - s
        return r, s


def p256_verify(public_point, message, r, s):
    """ECDSA 验签（自检/夹具用）。"""
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, P256_N)
    point = _ec_add(_ec_mul(z * w % P256_N), _ec_mul(r * w % P256_N, public_point))
    if point is None:
        return False
    return point[0] % P256_N == r


def p256_public_point(private_key):
    """由私钥标量导出公钥点。"""
    point = _ec_mul(private_key)
    if point is None:
        raise ValueError("私钥导出公钥失败")
    return point


def _ecdsa_self_check():
    """RFC 6979 A.2.5（P-256/SHA-256, message='sample'）向量校验。

    本实现统一做 low-S 归一化（s > n/2 时取 n-s），因此 s 与 RFC 明文值可能互补；
    这里按 min(s, n-s) 比对，并额外用公钥验签，两条都过才算正确。
    """
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    k = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    r, s = p256_sign(d, b"sample", k=k)
    expect_r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    expect_s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    ok_r = r == expect_r
    ok_s = min(s, P256_N - s) == min(expect_s, P256_N - expect_s)
    ok_verify = p256_verify(p256_public_point(d), b"sample", r, s)
    return bool(ok_r and ok_s and ok_verify)


def _device_proof_message(method, path, client_id, refresh_token, timestamp, nonce):
    return " ".join([str(method), str(path), str(client_id),
                     str(refresh_token), str(timestamp), str(nonce)]).encode("utf-8")


def build_device_proof(account, method="POST", path=PATH_EXCHANGE_TOKEN,
                       refresh_token="", private_key_pem=None,
                       timestamp=None, nonce=None, uid=None):
    """构造 DeviceInfo + DeviceProof（INTL ExchangeToken 用）。

    message = "METHOD PATH ClientID RefreshToken timestamp nonce"（空格连接），
    ECDSA-SHA256 签名后 base64 放入 DeviceProof.Signature。
    timestamp 默认毫秒时间戳（int，线上要求 int），nonce 默认 uuid4().hex（字符串）。
    """
    account = _as_mapping(account)
    pem = private_key_pem or account.get("privateKeyPEM") \
        or account.get("devicePrivateKeyPEM")
    if not pem:
        raise UpstreamError("no_device_key", "缺少 icube-dc 设备私钥，无法签名 DeviceProof", None)
    d = ec_private_key_from_pem(pem)
    # 线上实测（Lead，2026-10-19）：DeviceProof.Timestamp 必须是 **int 毫秒**；
    # 传字符串会被 ExchangeToken 以 400 拒绝（回显 actual value: ... (string)）。
    stamp = int(timestamp) if timestamp is not None else int(time.time() * 1000)
    random_part = str(nonce if nonce is not None else uuid.uuid4().hex)
    # 签名原文仍按空格拼接字符串，与客户端一致
    message = _device_proof_message(method, path, CLIENT_ID, refresh_token,
                                    stamp, random_part)
    r, s = p256_sign(d, message)
    signature = base64.b64encode(der_encode_signature(r, s)).decode("ascii")
    device_uid = str(uid or _uid(account) or "")
    device_info = account.get("deviceInfo") or {
        "DeviceId": trae_fingerprint.trae_device_id(device_uid),
        "MachineId": trae_fingerprint.trae_machine_id(device_uid),
        "DeviceType": "windows",
        "OsVersion": trae_fingerprint.trae_os_version(),
        "DeviceBrand": trae_fingerprint.trae_device_brand(),
    }
    return {
        "DeviceInfo": device_info,
        "DeviceProof": {"Signature": signature, "Timestamp": stamp,  # int 毫秒
                        "Nonce": random_part},
        "message": message.decode("utf-8"),
    }


def _resolve_device_credentials(account, realm):
    """账号自带私钥优先，否则从本机 storage 的 icube-dc 条目取（同区）。"""
    account = _as_mapping(account)
    pem = account.get("privateKeyPEM") or account.get("devicePrivateKeyPEM")
    if pem:
        return {"privateKeyPEM": pem, "source": "account"}
    uid = _uid(account)
    candidates = [item for item in import_desktop_devices() if item.get("realm") == realm]
    for item in candidates:
        if uid and item.get("holderId") == uid:
            return item
    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# Desktop 凭证导入
# ---------------------------------------------------------------------------
REGION_CODES = {"cn": "CN", "intl": "US"}


def _appdata():
    return (os.environ.get("APPDATA")
            or os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))


def desktop_storage_paths():
    """候选 storage.json：TRAE_DESKTOP_DIRS 优先（测试用），否则两个官方目录。"""
    entries = []
    extra = os.environ.get("TRAE_DESKTOP_DIRS") or ""
    roots = []
    for part in extra.split(os.pathsep):
        part = part.strip()
        if part:
            roots.append((part, ""))
    if not roots:
        appdata = _appdata()
        roots = [(os.path.join(appdata, "Trae"), "intl"),
                 (os.path.join(appdata, "Trae CN"), "cn")]
    for root, hint in roots:
        storage = os.path.join(root, "User", "globalStorage", "storage.json")
        if os.path.isfile(storage):
            if not hint:
                low = root.lower()
                hint = "cn" if ("trae cn" in low or low.endswith("trae-cn")) else "intl"
            entries.append({"path": storage, "realm": hint})
    return entries


def _read_json_file(path):
    with open(path, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def _realm_from_body(body, hint):
    region = body.get("userRegion") if isinstance(body.get("userRegion"), dict) else {}
    region_code = str(region.get("region") or region.get("_aiRegion") or "").upper()
    if region_code == "CN":
        return "cn"
    if region_code:
        return "intl"
    host = str(body.get("host") or "")
    if "trae.com.cn" in host or "mchost.guru" in host:
        return "cn"
    inner = body.get("account") if isinstance(body.get("account"), dict) else {}
    if str(inner.get("storeCountryCode") or "").lower() == "cn":
        return "cn"
    return hint or "intl"


def _temp_token_accounts(existing_realms):
    """兜底：~/.trae-cn/trae-jwt-token（7 天临时 token，仅 IDE 数据面可用）。"""
    home = os.path.expanduser("~")
    candidates = ((".trae-cn", "cn"), (".trae", "intl"))
    out = []
    for directory, realm in candidates:
        if realm in existing_realms:
            continue
        path = os.path.join(home, directory, "trae-jwt-token")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read().strip()
        except OSError:
            continue
        token = text
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
                token = (parsed.get("token") or parsed.get("accessToken")
                         or parsed.get("Token") or "")
            except ValueError:
                token = ""
        if not token:
            continue
        out.append({
            "token": token,
            "userId": "",
            "realm": realm,
            "host": REALMS[realm]["account"],
            "userRegion": {"region": REGION_CODES[realm]},
            "tokenSource": "desktop-temp-token",
            "tempToken": True,
            "ideOnly": True,
            "source": path,
        })
    return out


def import_desktop_devices():
    """解密 storage.json 的 iCubeAuthInfo://icube-dc:<holderId>（设备证明私钥）。

    返回 [{"realm","holderId","privateKeyPEM","publicKeyPEM","source"}]。
    私钥只用于本地签名，任何日志/看板都不得输出。
    """
    devices = []
    seen = set()
    for entry in desktop_storage_paths():
        try:
            storage = _read_json_file(entry["path"])
        except Exception:
            continue
        if not isinstance(storage, dict):
            continue
        for key, value in storage.items():
            if not isinstance(key, str) or not key.startswith("iCubeAuthInfo://icube-dc"):
                continue
            holder = key.split(":", 2)[-1]
            try:
                body = value if isinstance(value, dict) else decrypt_icube_blob(value)
            except Exception:
                continue
            pem = body.get("privateKeyPEM") if isinstance(body, dict) else None
            if not pem:
                continue
            dedupe = (entry["realm"], holder)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            devices.append({
                "realm": entry["realm"],
                "holderId": holder,
                "privateKeyPEM": pem,
                "publicKeyPEM": body.get("publicKeyPEM"),
                "source": entry["path"],
            })
    return devices


def import_desktop_accounts():
    """解密本机 Trae / Trae CN 的 storage.json，返回账号对象列表。

    - 国际版：%APPDATA%/Trae/User/globalStorage/storage.json
    - 国内版：%APPDATA%/Trae CN/User/globalStorage/storage.json
    - key：iCubeAuthInfo://icube.cloudide（tc/AES-128-CBC 封装）
    - 兜底：~/.trae-cn/trae-jwt-token（临时 token，仅作 IDE 数据面兜底）

    去重键 (realm, userId)；同一区域只保留第一份。任何异常只跳过该条目，
    不会让整次导入失败（一个文件坏了不影响另一个区）。返回值含敏感字段，
    打印请先过 account_public()。
    """
    accounts = []
    seen = set()
    now = datetime.datetime.now(datetime.timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    errors = []
    for entry in desktop_storage_paths():
        try:
            storage = _read_json_file(entry["path"])
        except Exception as exc:
            errors.append({"path": entry["path"], "error": str(exc)})
            continue
        if not isinstance(storage, dict):
            continue
        for key, value in storage.items():
            if not isinstance(key, str) or not key.startswith("iCubeAuthInfo://"):
                continue
            if not key.endswith("icube.cloudide"):
                continue  # usertag 等明文条目不含 token，不导入
            try:
                body = value if isinstance(value, dict) else decrypt_icube_blob(value)
            except Exception as exc:
                errors.append({"path": entry["path"], "key": key, "error": str(exc)})
                continue
            if not isinstance(body, dict) or not _token(body):
                continue
            realm = _realm_from_body(body, entry["realm"])
            uid = _uid(body)
            dedupe = (realm, uid or _token(body)[-8:])
            if dedupe in seen:
                continue
            seen.add(dedupe)
            account = dict(body)
            account["realm"] = realm
            account["uid"] = uid
            account["tokenSource"] = "desktop-storage"
            account["source"] = entry["path"]
            account["storageKey"] = key
            account["importedAt"] = now
            accounts.append(account)
    realms = {a["realm"] for a in accounts}
    for extra in _temp_token_accounts(realms):
        dedupe = (extra["realm"], "temp-token")
        if dedupe in seen:
            continue
        seen.add(dedupe)
        extra["importedAt"] = now
        accounts.append(extra)
    accounts.sort(key=lambda a: (0 if a.get("realm") == "cn" else 1,
                                 str(a.get("uid") or "")))
    # 错误只带路径与原因，不带任何 token 片段
    if errors:
        for account in accounts:
            account.setdefault("importErrors", errors)
        if not accounts:
            raise UpstreamError("desktop_import_failed",
                                "Desktop 凭证导入失败：%s" % errors[0]["error"], None)
    return accounts


def _desktop_storage_for(realm):
    realm = normalize_realm(realm)
    for entry in desktop_storage_paths():
        if entry.get("realm") == realm:
            return entry
    return None


def desktop_auth_body(realm):
    """读取本机 Desktop 当前 iCubeAuthInfo 明文 body（dict），失败返回 None。"""
    entry = _desktop_storage_for(realm)
    if not entry:
        return None
    try:
        storage = _read_json_file(entry["path"])
        blob = storage.get("iCubeAuthInfo://icube.cloudide")
        if not blob:
            return None
        body = decrypt_icube_blob(blob)
        if isinstance(body, bytes):
            body = json.loads(body.decode("utf-8"))
        return body if isinstance(body, dict) else None
    except Exception:
        return None


def reload_desktop_auth(account, realm=None):
    """从 Desktop storage.json 重新读取 token/refreshToken（不联网）。

    用途：TRAE_REFRESH_POLICY=readonly 时，桌面端刷新后网关自动跟上；
    或网关 401 时先尝试读取桌面端最新 token，再决定是否轮换。
    """
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    body = desktop_auth_body(realm)
    if not body:
        return None
    token = body.get("token") or ""
    if not token:
        return None
    fresh = dict(account)
    fresh["token"] = token
    if body.get("refreshToken"):
        fresh["refreshToken"] = body["refreshToken"]
    if body.get("expiredAt"):
        fresh["expiredAt"] = body["expiredAt"]
    if body.get("refreshExpiredAt"):
        fresh["refreshExpiredAt"] = body["refreshExpiredAt"]
    fresh["realm"] = realm
    fresh["tokenSource"] = "desktop-reload"
    return fresh


def sync_desktop_auth(account, realm=None, backup=True):
    """把网关当前 token 写回 Desktop storage.json（保持桌面端不掉线）。

    刷新令牌是轮换式：网关 ExchangeToken 成功后旧 refreshToken 失效，
    因此必须把新值同步回桌面端，否则桌面端下次刷新会 401。
    写入前备份 storage.json；使用 tmp + os.replace 原子替换，保留其余键。
    """
    account = _as_mapping(account)
    realm = normalize_realm(realm or realm_of(account))
    entry = _desktop_storage_for(realm)
    if not entry:
        return {"ok": False, "error": "desktop storage not found", "realm": realm}
    path = entry["path"]
    token = _token(account)
    refresh = account.get("refreshToken") or account.get("refresh_token") or ""
    if not token:
        return {"ok": False, "error": "no token", "realm": realm}
    try:
        storage = _read_json_file(path)
        blob = storage.get("iCubeAuthInfo://icube.cloudide")
        body = decrypt_icube_blob(blob) if blob else None
        if isinstance(body, bytes):
            body = json.loads(body.decode("utf-8"))
        if not isinstance(body, dict):
            body = {}
        body["token"] = token
        if refresh:
            body["refreshToken"] = refresh
        if account.get("expiredAt"):
            body["expiredAt"] = account["expiredAt"]
        if account.get("refreshExpiredAt"):
            body["refreshExpiredAt"] = account["refreshExpiredAt"]
        storage["iCubeAuthInfo://icube.cloudide"] = build_icube_blob(body)
        if backup:
            try:
                import shutil
                shutil.copy2(path, path + ".bak-trae-gateway")
            except Exception:
                pass
        tmp = path + ".tmp-trae-gateway"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(storage, handle, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return {"ok": True, "path": path, "realm": realm}
    except Exception as exc:                           # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__, "realm": realm}


def pick_account(accounts, realm=None):
    """按区域挑第一个可用账号（自检/诊断用；账号池请用自己的调度）。"""
    realm = normalize_realm(realm) if realm else None
    for raw in accounts or []:
        account = _as_mapping(raw)
        if realm is None or normalize_realm(account.get("realm")) == realm:
            if _token(account):
                return raw
    return None


def account_public(account):
    """脱敏视图：只暴露长度/前缀/到期时间，绝不输出完整 token。"""
    account = _as_mapping(account)
    token = _token(account)
    refresh = account.get("refreshToken") or ""
    email = ""
    inner = account.get("account")
    if isinstance(inner, dict):
        email = str(inner.get("email") or inner.get("username") or "")
    if email and "@" in email:
        local, _, domain = email.partition("@")
        email = "%s***@%s" % (local[:2], domain)
    uid = _uid(account)
    return {
        "realm": account.get("realm") or realm_of(account),
        # 团队硬规则第 5 条：日志/文档只出现 uid 哈希与尾号，不落原始 uid
        "uidHash": hashlib.sha256(uid.encode("utf-8")).hexdigest()[:12] if uid else "",
        "uidTail": uid[-4:] if uid else "",
        "email": email,
        "tokenLen": len(token),
        "tokenPrefix": token[:6],
        "refreshLen": len(refresh),
        "expiredAt": account.get("expiredAt"),
        "refreshExpiredAt": account.get("refreshExpiredAt"),
        "host": account.get("host"),
        "tokenSource": account.get("tokenSource"),
        "expired": is_expired(account),
    }


# ---------------------------------------------------------------------------
# 自检（真实打上游；只打印事件类型序列与前 80 字符正文）
# ---------------------------------------------------------------------------
def _short(text, limit=80):
    text = (text or "").replace("\n", " ").strip()
    return text[:limit]


def _run_chat_check(account, realm, model, prompt, timeout):
    """跑一次真实 llm_raw_chat，返回可直接打印的摘要（不含 token）。"""
    summary = {
        "realm": realm,
        "model": model,
        "status": "ok",
        "events": [],
        "text": "",
        "usage": {},
        "finish_reason": None,
        "error": None,
        "elapsed": None,
    }
    started = time.time()
    try:
        body = build_chat_body(model, [
            {"role": "system", "content": "你是协议自检助手，回答尽量短。"},
            {"role": "user", "content": prompt},
        ])
        resp = open_chat(account, realm, body, timeout=timeout)
        result = collect(resp)
        summary["events"] = result["events"]
        summary["text"] = _short(result["text"])
        summary["usage"] = result["usage"]
        summary["finish_reason"] = result["finish_reason"]
        if result["errors"]:
            summary["status"] = "error_frame"
            summary["error"] = result["errors"][0]
    except UpstreamError as exc:
        summary["status"] = "upstream_error"
        summary["error"] = {"code": exc.code, "message": exc.message,
                            "status": exc.status}
    except Exception as exc:
        summary["status"] = "exception"
        summary["error"] = {"code": type(exc).__name__, "message": str(exc),
                            "status": None}
    summary["elapsed"] = round(time.time() - started, 2)
    return summary


def _log_chat(log, label, summary):
    log("   %s：status=%s 事件序列=%s 用时=%ss"
        % (label, summary.get("status"),
           " -> ".join(summary.get("events") or []) or "-",
           summary.get("elapsed")))
    if summary.get("text"):
        log("        正文前80字符：%s" % summary["text"])
    if summary.get("usage"):
        usage = summary["usage"]
        log("        usage: prompt=%s completion=%s total=%s"
            % (usage.get("prompt_tokens"), usage.get("completion_tokens"),
               usage.get("total_tokens")))
    if summary.get("error"):
        log("        错误：%s" % json.dumps(summary["error"], ensure_ascii=False))


def self_test(model="deepseek-V3", prompt="用一句话介绍你自己",
              timeout=90, include_intl=True, log=print):
    """端到端自检：AES 向量 -> Desktop 解密 -> CN 聊天 -> INTL 聊天。

    token 只以长度/前缀出现；事件序列与正文前 80 字符原样打印，便于对账
    PROTOCOL 第六节。INTL 遇到 4015/4019 如实记录，不视为失败。
    """
    report = {"aes": _aes_self_check(), "ecdsa": _ecdsa_self_check(),
              "devices": [], "accounts": [], "cn": None, "intl": None}
    log("== AES-128 自检（FIPS-197 向量）: %s" % ("通过" if report["aes"] else "失败"))
    log("== ECDSA P-256 自检（RFC 6979 A.2.5 向量）: %s"
        % ("通过" if report["ecdsa"] else "失败"))
    try:
        for item in import_desktop_devices():
            ok = False
            try:
                point = p256_public_point(ec_private_key_from_pem(item["privateKeyPEM"]))
                ok = bool(item.get("publicKeyPEM")
                          and ec_public_key_from_pem(item["publicKeyPEM"]) == point)
            except Exception:
                ok = False
            report["devices"].append({"realm": item["realm"], "holderId": item["holderId"],
                                      "keyPairMatchesPem": ok})
            log("   设备私钥 realm=%s holder=%s 私钥/公钥匹配=%s"
                % (item["realm"], item["holderId"][:4] + "***", "是" if ok else "否"))
    except Exception as exc:
        log("   设备私钥读取失败：%s" % exc)
    accounts = import_desktop_accounts()
    report["accounts"] = [account_public(a) for a in accounts]
    for item in report["accounts"]:
        log("   账号 realm=%s uidHash=%s…%s tokenLen=%s tokenPrefix=%s*** expiredAt=%s 来源=%s"
            % (item["realm"], item["uidHash"] or "-", item["uidTail"] or "-",
               item["tokenLen"], item["tokenPrefix"], item["expiredAt"],
               item["tokenSource"]))
    cn = pick_account(accounts, "cn")
    if cn is not None:
        if is_expired(cn):
            report["cn"] = {"status": "token_expired",
                            "error": "CN access token 已过期；请用账号池 refresh 并落盘后再自检"}
        else:
            report["cn"] = _run_chat_check(cn, "cn", model, prompt, timeout)
        if report["cn"]:
            _log_chat(log, "CN", report["cn"])
    else:
        report["cn"] = {"status": "no_account"}
        log("   CN：本机没有可用的 Desktop 账号")
    if include_intl:
        intl = pick_account(accounts, "intl")
        if intl is None:
            report["intl"] = {"status": "no_account"}
            log("   INTL：本机没有可用的 Desktop 账号")
        elif is_expired(intl):
            report["intl"] = {"status": "token_expired"}
            log("   INTL：access token 已过期（不阻塞）")
        else:
            intl_model = model if model != "deepseek-V3" else "seed_m8"
            report["intl"] = _run_chat_check(intl, "intl", intl_model, prompt, timeout)
            _log_chat(log, "INTL", report["intl"])
    return report


# ---------------------------------------------------------------------------
# CLI（自检 / 排障；生产入口是网关）
# ---------------------------------------------------------------------------
def _setup_stdio():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main(argv=None):
    import argparse
    _setup_stdio()
    parser = argparse.ArgumentParser(description="Trae 双区协议层自检工具")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("accounts", help="列出本机 Desktop 账号（脱敏）")
    sub.add_parser("selftest", help="AES + 解密 + CN/INTL 真实聊天自检")

    chat = sub.add_parser("chat", help="真实跑一次 llm_raw_chat")
    chat.add_argument("--realm", default="cn", choices=("cn", "intl"))
    chat.add_argument("--model", default=None)
    chat.add_argument("--prompt", default="用一句话介绍你自己")
    chat.add_argument("--timeout", type=float, default=90)

    models = sub.add_parser("models", help="拉取 model_list")
    models.add_argument("--realm", default="cn", choices=("cn", "intl"))

    usage = sub.add_parser("usage", help="拉取会话用量")
    usage.add_argument("--realm", default="cn", choices=("cn", "intl"))

    ent = sub.add_parser("ent", help="拉取权益 / 付费状态")
    ent.add_argument("--realm", default="cn", choices=("cn", "intl"))

    refresh = sub.add_parser("refresh", help="调用 ExchangeToken（会轮换 refreshToken！）")
    refresh.add_argument("--realm", default="cn", choices=("cn", "intl"))

    args = parser.parse_args(argv)
    if not args.cmd:
        return self_test()

    if args.cmd == "accounts":
        for item in [account_public(a) for a in import_desktop_accounts()]:
            print(json.dumps(item, ensure_ascii=False))
        return None

    if args.cmd == "selftest":
        report = self_test()
        print("\n=== JSON 摘要 ===")
        print(json.dumps(report, ensure_ascii=False, indent=1)[:4000])
        return report

    accounts = import_desktop_accounts()
    realm = args.realm
    account = pick_account(accounts, realm)
    if account is None:
        print("本机没有 %s 区账号" % realm)
        return None

    try:
        if args.cmd == "chat":
            model = args.model or ("deepseek-V3" if realm == "cn" else "seed_m8")
            result = _run_chat_check(account, realm, model, args.prompt, args.timeout)
            _log_chat(print, realm.upper(), result)
            print(json.dumps(result, ensure_ascii=False))
        elif args.cmd == "models":
            names = [m.get("name") for m in fetch_model_list(account, realm)]
            print("model_list(%s): %s" % (realm, names))
        elif args.cmd == "usage":
            print(json.dumps(fetch_usage(account, realm), ensure_ascii=False)[:2000])
        elif args.cmd == "ent":
            print(json.dumps(fetch_entitlement(account, realm), ensure_ascii=False)[:2000])
        elif args.cmd == "refresh":
            fresh = refresh_account(account)
            print(json.dumps(account_public(fresh), ensure_ascii=False))
            print("注意：refreshToken 已轮换，必须由账号池原子落盘；这里不会写回。")
    except UpstreamError as exc:
        print("上游错误：%s" % exc)
        print(json.dumps(exc.as_dict(), ensure_ascii=False)[:1000])
    return None


if __name__ == "__main__":
    main()
