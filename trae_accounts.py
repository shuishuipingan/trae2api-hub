"""trae_accounts.py —— Trae 双区（CN / INTL）账号池与凭证生命周期

本文件只负责「账号域」，不承载上游协议细节：

  - REALMS：双区出口表（cn / intl），与 .team/PROTOCOL.md 第一节一致
  - Account：字段 / 落盘 / 脱敏视图 / 冷却熔断 / token 刷新（轮换原子回写）
  - AccountPool：按 realm 选号、会话粘性、加权轮转、并发闸门、导入导出、
    Desktop 凭证导入（CN + INTL）
  - 落盘：accounts/<uid>.json（0600，临时文件 + os.replace 原子替换）

硬纪律（与 .team/README.md 一致）：

  1. 刷新只调 trae_client.refresh_account，Desktop 导入只调
     trae_client.import_desktop_accounts；本文件不复刻协议。仅当 trae_client
     不可导入时，刷新退化为内置 ExchangeToken 兜底（并打一次 WARN）。
  2. 真实 token / refreshToken 只落在 accounts/<uid>.json。public() 只给
     「前缀 3 字符 + 长度」；日志与报错文本一律过 _scrub_secrets。
  3. 只用标准库。
"""

import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# 双区出口表（.team/PROTOCOL.md 第一节）
# ---------------------------------------------------------------------------
REALMS = {
    "cn": {
        "name": "国内版 (China)",
        "core": "https://trae-api-cn.mchost.guru",
        "account": "https://api.trae.com.cn",
        "ua": "Trae CN/3.4.3",
        "version_code": "20260212",
        "region": "CN",
        "ai_region": "CN",
        "domain": "trae.com.cn",
        "home_dir": ".trae-cn",
        "app_dir": "Trae CN",
        "core_fallbacks": (),
    },
    "intl": {
        "name": "国际版 (Global)",
        "core": "https://core-normal.traeapi.us",
        "account": "https://grow-normal.trae.ai",
        "ua": "Trae/3.6.2",
        "version_code": "20260212",
        "region": "US",
        "ai_region": "US",
        "domain": "trae.ai",
        "home_dir": ".trae",
        "app_dir": "Trae",
        # 国际版按账号落点切主机（US / SG），用于故障切换
        "core_fallbacks": ("https://core-normal.trae.ai",
                           "https://coresg-normal.trae.ai"),
    },
}

DEFAULT_REALM = "cn"
CLIENT_UA = "trae2api-hub/1.0"

# ExchangeToken（.team/PROTOCOL.md 第五节）：仅兜底路径使用
LOGIN_CLIENT_ID = "ono9krqynydwx5"
PATH_EXCHANGE_TOKEN = "/cloudide/api/v3/trae/oauth/ExchangeToken"

# 冷却 / 熔断参数（秒）
COOLDOWN_BASE = 30
COOLDOWN_CAP = 900
BREAKER_AUTH = 300          # 1001 / 401 / 403：凭证类硬错误
BREAKER_RISK = 1800         # 4019：风控命中，同区出口需要长冷却
COOLDOWN_RATE = 120         # 429：速率
REFRESH_SKEW = 120          # 兼容旧参数：显式传 skew 时仍按秒级窗口
# 自动刷新窗口：只剩 24 小时才刷新（token 有效期约 30 天；旧实现见冷却就刷，
# 导致 INTL 号在风控冷却期间被 model discovery 每 1-2 秒刷一次）。
REFRESH_AHEAD = 24 * 3600
# 刷新失败退避：10 分钟起，按连续失败加倍，最多 1 小时（时钟取 last_error_at）
REFRESH_FAIL_BACKOFF = 600
REFRESH_FAIL_BACKOFF_MAX = 3600

TOKEN_PREFIX_KEEP = 3

# 每日限额护栏（trae_settings.limits_data 的键；credit 类在 Trae 无口径，恒 0=关）
LIMIT_KEYS = ("reserve_credits", "daily_token_limit", "daily_credit_limit",
              "model_daily_token_limit", "expiring_window_days")
LIMIT_SCOPES = ("global", "intl", "cn")
LEDGER_CACHE_TTL = 5.0          # usage.jsonl 合计缓存（秒）

_SAVE_LOCK = threading.Lock()
_MISSING = object()
_ACTIVE_POOL = None
_CLIENT = None
_CLIENT_ERROR = ""
_FALLBACK_WARNED = False


class AccountError(Exception):
    """账号域错误（不含明文凭证；message 已脱敏）。"""

    def __init__(self, message, code=None, status=None):
        super().__init__(message)
        self.code = code
        self.status = status

class RefreshSummary(dict):
    """刷新结果：本质是 dict（可 JSON），真假值按「是否真的刷新成功」判定。

    网关既有 ok = account.refresh() 这类布尔用法，也有读字段的用法，本类
    同时满足：skipped / error 时 __bool__ 为 False。
    """

    @property
    def ok(self):
        return not self.get("skipped") and not self.get("error")

    def __bool__(self):
        return self.ok


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _now():
    return time.time()


def normalize_epoch(value):
    """把时间戳归一到 epoch 秒（int）；无法解析返回 0。

    支持：秒 / 毫秒整数、数字字符串、ISO 8601（含 Z 与毫秒小数）。
    """
    if value is None or value == "" or isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        num = float(value)
        if num <= 0:
            return 0
        if num > 1e11:          # 毫秒（1e11 秒 ≈ 5138 年，安全分界）
            num /= 1000.0
        return int(num)
    text = str(value).strip()
    if not text:
        return 0
    if re.fullmatch(r"\d+(\.\d+)?", text):
        return normalize_epoch(float(text))
    iso = text
    if iso.endswith(("Z", "z")):
        iso = iso[:-1] + "+00:00"
    for candidate in (iso, iso.replace(" ", "T", 1)):
        try:
            dt = datetime.datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    # 末级兜底：截断到秒的旧格式 %Y-%m-%dT%H:%M:%S
    try:
        dt = datetime.datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
        return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        return 0


def iso_utc(epoch):
    """epoch 秒 -> ISO8601（UTC，秒精度）；0 -> 空串。"""
    epoch = normalize_epoch(epoch)
    if not epoch:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def human_delta(seconds):
    """秒 -> 中文可读时长（看板展示用）。"""
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return "?"
    if seconds <= 0:
        return "已过期"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return "%d 天 %d 小时" % (days, hours)
    if hours:
        return "%d 小时 %d 分" % (hours, minutes)
    return "%d 分" % minutes


def _truthy(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def accounts_dir():
    """账号目录：显式 ACCOUNTS_DIR > <repo>/accounts。"""
    base = (os.environ.get("ACCOUNTS_DIR") or "").strip()
    if base:
        return os.path.abspath(os.path.expanduser(base))
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts")


def usage_log_path():
    """usage.jsonl 路径：TRAE_PROXY_USAGE_LOG > TRAE_PROXY_USAGE_DIR > <repo>/usage。"""
    explicit = (os.environ.get("TRAE_PROXY_USAGE_LOG") or "").strip()
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    base = (os.environ.get("TRAE_PROXY_USAGE_DIR") or "").strip()
    if not base:
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage")
    return os.path.join(os.path.abspath(os.path.expanduser(base)), "usage.jsonl")


def local_day(epoch=None):
    """本地日期字符串（与 usage.jsonl 的 at / iso 对齐）。"""
    return time.strftime("%Y-%m-%d",
                         time.localtime(epoch if epoch is not None else time.time()))


def _coerce_limit(value):
    """限额值归一：>=0 的整数；非法/None -> 0（= 关闭）。"""
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return 0


def _usage_tokens(usage):
    """从 usage 字典取本次 token 数（total_tokens 优先，其次 in+out）。"""
    if not isinstance(usage, dict):
        return 0
    for key in ("total_tokens", "totalTokens", "tokens", "total"):
        raw = usage.get(key)
        if raw in (None, ""):
            continue
        try:
            return max(0, int(float(raw)))
        except (TypeError, ValueError):
            continue
    total = 0
    for key in ("prompt_tokens", "completion_tokens"):
        try:
            total += int(float(usage.get(key) or 0))
        except (TypeError, ValueError):
            pass
    return max(0, total)


def _row_day(row):
    """usage 行的本地日期：优先 at(epoch)，其次 iso 前缀。"""
    raw = row.get("at")
    if isinstance(raw, (int, float)) and raw > 0:
        return local_day(float(raw))
    iso = str(row.get("iso") or "")
    return iso[:10] if len(iso) >= 10 else ""


def _uid_matches(uid, recorded):
    """账本 uid 匹配：完整相等 / 互为前缀（网关曾用 uid[:8] 记账）。"""
    uid = str(uid or "")
    recorded = str(recorded or "")
    if not uid or not recorded:
        return False
    if uid == recorded:
        return True
    shorter, longer = sorted((uid, recorded), key=len)
    return len(shorter) >= 4 and longer.startswith(shorter)


# ---------------------------------------------------------------------------
# 脱敏（token / uid / email 一律不裸奔）
# ---------------------------------------------------------------------------
def redact_token(token):
    """token 摘要：前缀 3 字符 + 长度。永不返回原值。"""
    token = str(token or "")
    if not token:
        return {"present": False, "prefix": "", "length": 0}
    return {"present": True,
            "prefix": token[:TOKEN_PREFIX_KEEP],
            "length": len(token)}


def uid_tail(uid):
    uid = str(uid or "")
    return uid[-4:] if len(uid) >= 4 else uid


def mask_uid(uid):
    """uid 只露后 4 位。"""
    uid = str(uid or "")
    if not uid:
        return ""
    if len(uid) <= 4:
        return "…" + uid
    return "…" + uid[-4:]


def uid_digest(uid):
    """uid 的稳定短摘要（看板/接口用的不透明操作键，不可逆）。"""
    return hashlib.sha256(("trae-uid:" + str(uid or "")).encode("utf-8")).hexdigest()[:16]


def mask_email(email):
    email = str(email or "")
    if not email:
        return ""
    if "@" in email:
        local, _, domain = email.partition("@")
        keep = local[:1] if local else ""
        return "%s***@%s" % (keep, domain)
    return email[:1] + "***"


def mask_name(name):
    name = str(name or "")
    if not name:
        return ""
    return name[:1] + "***"


_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4", "socks4a")


def normalize_proxy(value):
    """规范化出口代理：空 / direct / none -> ''（直连）；缺 scheme 补 http://。"""
    if value is None or isinstance(value, (dict, list, tuple)):
        return ""
    text = str(value).strip().strip('"').strip("'")
    if not text or text.lower() in ("direct", "none", "off", "null", "-", "false"):
        return ""
    if "://" not in text:
        text = "http://" + text
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() not in _PROXY_SCHEMES:
        raise ValueError("unsupported proxy scheme: %r" % parsed.scheme)
    if not parsed.hostname:
        raise ValueError("proxy has no host")
    try:
        parsed.port
    except ValueError:
        raise ValueError("proxy port invalid")
    return text


def mask_proxy(proxy):
    """代理 URL 脱敏：隐藏 userinfo，保留 scheme/host/port。"""
    text = str(proxy or "")
    if not text:
        return ""
    parsed = urllib.parse.urlsplit(text if "://" in text else "http://" + text)
    host = parsed.hostname or ""
    port = ":%d" % parsed.port if parsed.port else ""
    auth = "***@" if parsed.username else ""
    return "%s://%s%s%s" % (parsed.scheme, auth, host, port)


def _load_settings(accounts_dir_path=None):
    """读取 trae_settings 文档（模块缺失 / 读失败 -> {}）。"""
    try:
        import trae_settings
        doc = trae_settings.load(accounts_dir_path or accounts_dir())
    except Exception:
        return {}
    return doc if isinstance(doc, dict) else {}


_PROXY_KEYS = ("proxy", "proxies", "egress", "egresses", "realm_proxy",
               "realmProxy", "realm_proxies")


def proxy_from_settings(settings, realm=None):
    """从 settings 解析某区域出口代理（找不到返回 ''）。

    兼容三种形态：
      {"proxy": "http://127.0.0.1:7890"}            全局兜底（任何区域）
      {"proxy": {"cn": "...", "intl": "..."}}       按区域
      {"proxy_cn": "...", "proxy_intl": "..."}      扁平键
    """
    if not isinstance(settings, dict):
        return ""
    realm = str(realm or "").strip().lower()
    if realm not in REALMS:
        realm = ""
    if realm:
        for key in ("proxy_%s" % realm, "%s_proxy" % realm):
            raw = settings.get(key)
            if raw not in (None, ""):
                try:
                    value = normalize_proxy(raw)
                except ValueError:
                    value = ""
                if value:
                    return value
    for key in _PROXY_KEYS:
        raw = settings.get(key)
        if isinstance(raw, dict):
            for sub in ("global", realm, "default"):
                if not sub or raw.get(sub) in (None, ""):
                    continue
                try:
                    value = normalize_proxy(raw.get(sub))
                except ValueError:
                    continue
                if value:
                    return value
        elif raw not in (None, ""):
            try:
                value = normalize_proxy(raw)
            except ValueError:
                value = ""
            if value:
                return value
    return ""


def settings_realm_proxy(realm=None, accounts_dir_path=None, settings=None):
    """区域兜底出口：显式 settings 文档 > 读取 trae_settings 落盘。"""
    doc = settings if isinstance(settings, dict) else _load_settings(accounts_dir_path)
    return proxy_from_settings(doc, realm)


def _scrub_secrets(text, *accounts):
    """把文本里出现的明文 token / refreshToken 替换为脱敏摘要。"""
    out = str(text or "")
    for account in accounts:
        if account is None:
            continue
        for secret in (getattr(account, "token", ""),
                       getattr(account, "refresh_token", "")):
            secret = str(secret or "")
            if len(secret) >= 8 and secret in out:
                out = out.replace(secret, "***%d***" % len(secret))
    return out


# ---------------------------------------------------------------------------
# 区域判定
# ---------------------------------------------------------------------------
def get_realm_config(realm):
    """取区域配置（未知值回落 cn）。含旧字段别名，方便过渡期调用方。"""
    key = str(realm or "").strip().lower()
    if key not in REALMS:
        key = DEFAULT_REALM
    cfg = dict(REALMS[key])
    cfg["realm"] = key
    # 过渡别名：旧调用方（网关/诊断脚本）读写这些键
    cfg.setdefault("openapi", cfg["account"])
    cfg.setdefault("gateway", cfg["core"])
    cfg.setdefault("website", "https://www." + cfg["domain"])
    return cfg


def gateway_candidates(realm):
    """数据面主机候选（主选 + 故障切换），去重保序。"""
    cfg = get_realm_config(realm)
    out = [cfg["core"]]
    for host in cfg.get("core_fallbacks") or ():
        if host not in out:
            out.append(host)
    return out


def detect_realm(host="", user_region=None, store_region="", fallback=DEFAULT_REALM):
    """按 host / userRegion / storeRegion 判区域。

    规则顺序：host 是 trae.com.cn -> cn；region == CN -> cn；其它明确 region
    -> intl；host 含 trae.ai / traeapi -> intl；否则 fallback。
    """
    host = str(host or "").lower()
    if "trae.com.cn" in host or host.endswith(".trae.cn"):
        return "cn"
    region = ""
    if isinstance(user_region, dict):
        for key in ("region", "_aiRegion", "aiRegion"):
            if user_region.get(key):
                region = str(user_region.get(key))
                break
    if not region:
        region = str(store_region or "")
    region = region.strip().upper()
    if region == "CN":
        return "cn"
    if region:
        return "intl"
    if "trae.ai" in host or "traeapi" in host or "trae.us" in host:
        return "intl"
    return fallback if fallback in REALMS else DEFAULT_REALM


def detect_realm_from_domain(domain):
    """兼容旧调用方：domain -> realm。"""
    return detect_realm(host=str(domain or ""))


def realm_key(realm):
    """把 cn/CN/国内/intl/US/global 归一成 cn|intl；无法判定返回 ''（不猜）。"""
    raw = str(realm or "").strip().lower()
    if raw in ("cn", "china", "zh", "国内", "国内版"):
        return "cn"
    if raw in ("intl", "us", "global", "sg", "国际", "国际版"):
        return "intl"
    return ""


# ---------------------------------------------------------------------------
# URL 校验 / 会话失效判定 / 配额读取（网关共用的小工具）
# ---------------------------------------------------------------------------
def _blocked_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def validate_public_http_url(url, allow_local=False):
    """只允许 http/https 公网主机；allow_local=True 放行内网（测试夹具用）。"""
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme: %r" % parsed.scheme)
    host = parsed.hostname
    if not host:
        raise ValueError("url has no host")
    if allow_local:
        return parsed
    if host.lower() in ("localhost", "localhost.localdomain"):
        raise ValueError("host is local: %s" % host)
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443,
                                   proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError("cannot resolve host %s: %s" % (host, exc))
    for info in infos:
        ip = info[4][0]
        if _blocked_ip(ip):
            raise ValueError("host %s resolves to a private address (%s)" % (host, ip))
    return parsed


_DEAD_SESSION_MARKERS = ("session not found", "session expired", "session closed",
                         "invalid session", "conversation not found",
                         "session_id invalid", "no such session")


def session_dead(detail):
    """上游报错是否属于「会话已失效」（网关据此重建会话而非换号）。"""
    text = str(detail or "").lower()
    return any(marker in text for marker in _DEAD_SESSION_MARKERS)


def effective_remain(value):
    """读「剩余额度」数字（usage / entitlement 由 trae_tasks 填充）。

    兼容：Account 对象、{"remaining":..}、{"credits":..}、{"size":..}。
    读不到返回 0（fail-open 由调用方决定）。
    """
    if isinstance(value, Account):
        value = value.entitlement or value.usage
    if not isinstance(value, dict):
        return 0
    for key in ("remaining", "remain", "left", "available", "credits", "size",
                "quota_remaining", "balance"):
        raw = value.get(key)
        if isinstance(raw, bool) or raw is None:
            continue
        try:
            return int(float(raw))
        except (TypeError, ValueError):
            continue
    return 0


# ---------------------------------------------------------------------------
# trae_client 桥（延迟导入：trae_client 未就绪不影响本模块可用）
# ---------------------------------------------------------------------------
def _load_client(force=False):
    """取 trae_client 模块；不可用返回 None（原因见 client_status()）。"""
    global _CLIENT, _CLIENT_ERROR
    if _CLIENT is not None and not force:
        return _CLIENT
    try:
        import importlib
        module = importlib.import_module("trae_client")
    except Exception as exc:          # ImportError / 语法错误 / 依赖缺失
        _CLIENT = None
        _CLIENT_ERROR = "%s: %s" % (type(exc).__name__, exc)
        return None
    _CLIENT = module
    _CLIENT_ERROR = ""
    return _CLIENT


def client_status(force=False):
    client = _load_client(force=force)
    return {"available": client is not None,
            "module": getattr(client, "__name__", ""),
            "error": _CLIENT_ERROR}


def _note_fallback(message):
    global _FALLBACK_WARNED
    if _FALLBACK_WARNED:
        return
    _FALLBACK_WARNED = True
    try:
        import sys
        print("[trae_accounts] WARN: %s" % message, file=sys.stderr)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 刷新结果归一（多种上游形态统一成一套字段）
# ---------------------------------------------------------------------------
def normalize_refresh_result(raw):
    """把刷新响应归一为 {token, refresh_token, expired_at, refresh_expired_at}。

    兼容：ExchangeToken 的 Result 包装、camelCase、snake_case、毫秒时间戳。
    """
    if raw is None:
        raise AccountError("refresh returned nothing")
    if not isinstance(raw, dict):
        raise AccountError("refresh returned %s" % type(raw).__name__)
    body = raw
    for wrapper in ("Result", "result", "data", "Data"):
        if isinstance(body.get(wrapper), dict):
            body = body[wrapper]
            break

    def pick(*keys):
        for key in keys:
            if body.get(key) not in (None, ""):
                return body.get(key)
        return None

    token = str(pick("token", "Token", "accessToken", "access_token") or "").strip()
    if not token:
        raise AccountError("refresh response has no token")
    refresh = str(pick("refreshToken", "refresh_token", "RefreshToken") or "").strip()
    expired_at = normalize_epoch(pick("expiredAt", "expired_at", "TokenExpireAt",
                                      "expire_time", "expiresAt"))
    refresh_expired_at = normalize_epoch(pick("refreshExpiredAt", "refresh_expired_at",
                                              "RefreshExpireAt"))
    uid = str(pick("uid", "userId", "user_id", "UserID") or "").strip()
    return {"token": token,
            "refresh_token": refresh,
            "expired_at": expired_at,
            "refresh_expired_at": refresh_expired_at,
            "uid": uid}


def _fallback_refresh(account, timeout=30):
    """trae_client 不可用时的内建 ExchangeToken 兜底（轮换式）。"""
    _note_fallback("trae_client 不可导入（%s），刷新使用内建 ExchangeToken 兜底"
                   % (_CLIENT_ERROR or "unknown"))
    cfg = get_realm_config(account.realm)
    host = str(account.host or cfg["account"]).rstrip("/")
    url = host + PATH_EXCHANGE_TOKEN
    payload = json.dumps({"ClientID": LOGIN_CLIENT_ID,
                          "RefreshToken": account.refresh_token,
                          "ClientSecret": "-",
                          "UserID": ""}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": cfg["ua"],
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        raise AccountError("ExchangeToken http %d %s"
                           % (exc.code, _scrub_secrets(body, account)),
                           status=exc.code)
    except Exception as exc:
        raise AccountError("ExchangeToken failed: %s"
                           % _scrub_secrets("%s: %s" % (type(exc).__name__, exc),
                                            account))
    try:
        return json.loads(raw)
    except ValueError:
        raise AccountError("ExchangeToken returned non-JSON body")


def _scrub_value(text, secret):
    """把文本里出现的单个敏感串替换成 *** 摘要。"""
    out = str(text or "")
    secret = str(secret or "")
    if len(secret) >= 8 and secret in out:
        out = out.replace(secret, "***%d***" % len(secret))
    return out


def _refresh_with_token(refresh_token, realm, client=None, uid=""):
    """用裸 refreshToken 调 trae_client.refresh_account，返回归一结果。

    区域必须由调用方显式给出（refreshToken 不携带区域信息）。
    """
    realm = realm_key(realm)
    if not realm:
        raise AccountError("请显式指定 realm（cn 或 intl）：refreshToken 不携带区域信息")
    cfg = get_realm_config(realm)
    payload = RefreshPayload({
        "refreshToken": refresh_token,
        "refresh_token": refresh_token,
        "token": "",
        "realm": realm,
        "uid": str(uid or ""),
        "userId": str(uid or ""),
        "host": cfg["account"],
        "userRegion": {"region": cfg["region"], "_aiRegion": cfg["ai_region"]},
    })
    client = client or _load_client()
    if client is None:
        stub = Account({"uid": str(uid or "pending"), "realm": realm,
                        "refresh_token": refresh_token,
                        "host": cfg["account"]})
        return normalize_refresh_result(_fallback_refresh(stub))
    fn = getattr(client, "refresh_account", None) or getattr(client, "refresh", None)
    if not callable(fn):
        raise AccountError("trae_client 缺少 refresh_account()")
    try:
        raw = fn(payload)
    except AccountError:
        raise
    except Exception as exc:
        raise AccountError("refresh failed: %s"
                           % _scrub_value("%s: %s" % (type(exc).__name__, exc),
                                          refresh_token))
    return normalize_refresh_result(raw)


def _call_client_refresh(account, client=None):
    """委托 trae_client.refresh_account；返回归一后的结果 dict。"""
    client = client or _load_client()
    if client is None:
        return normalize_refresh_result(_fallback_refresh(account))
    fn = getattr(client, "refresh_account", None) or getattr(client, "refresh", None)
    if not callable(fn):
        raise AccountError("trae_client 缺少 refresh_account()")
    payload = account.refresh_payload()
    try:
        raw = fn(payload)
    except (TypeError, AttributeError, KeyError):
        # 双接口载荷仍不匹配（客户端期望真实的 Account 对象）才重试一次
        raw = fn(account)
    except AccountError:
        raise
    except Exception as exc:
        raise AccountError("refresh failed: %s"
                           % _scrub_secrets("%s: %s" % (type(exc).__name__, exc),
                                            account))
    return normalize_refresh_result(raw)


# ---------------------------------------------------------------------------
# Desktop 凭证扫描（真正解密在 trae_client；这里只做调度与脱敏）
# ---------------------------------------------------------------------------
def desktop_storage_paths():
    """双区 Desktop 凭证文件位置（只读展示，不含内容）。"""
    appdata = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    home = os.path.expanduser("~")
    out = []
    for realm in ("cn", "intl"):
        cfg = get_realm_config(realm)
        out.append({
            "realm": realm,
            "realmName": cfg["name"],
            "storage": os.path.join(appdata, cfg["app_dir"], "User",
                                    "globalStorage", "storage.json"),
            "key": "iCubeAuthInfo://icube.cloudide",
            "tempToken": os.path.join(home, cfg["home_dir"], "trae-jwt-token"),
        })
    return out


def scan_desktop_accounts(client=None, realms=None):
    """调用 trae_client.import_desktop_accounts() 取本机双区凭证。

    返回 (rows, error)。rows 为 trae_client 给出的桌面结构 dict 列表；
    本函数不做任何网络请求，也不打印任何令牌。
    """
    client = client or _load_client()
    if client is None:
        return [], ("trae_client 不可用（%s），无法读取 Desktop 凭证"
                    % (_CLIENT_ERROR or "未找到 trae_client.py"))
    fn = getattr(client, "import_desktop_accounts", None)
    if not callable(fn):
        return [], "trae_client 未提供 import_desktop_accounts()"
    try:
        rows = fn()
    except Exception as exc:
        return [], "import_desktop_accounts failed: %s: %s" % (type(exc).__name__, exc)
    if isinstance(rows, dict):
        rows = rows.get("accounts") or rows.get("rows") or []
    if not isinstance(rows, (list, tuple)):
        return [], "import_desktop_accounts returned %s" % type(rows).__name__
    wanted = {str(r).lower() for r in (realms or ()) if r} or None
    kept = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        explicit = str(row.get("realm") or "").strip().lower()
        realm = explicit if explicit in REALMS else detect_realm(
            row.get("host") or row.get("domain"),
            row.get("userRegion") or row.get("user_region"),
            (row.get("account") or {}).get("storeRegion")
            if isinstance(row.get("account"), dict) else "")
        if wanted and realm not in wanted:
            continue
        kept.append(row)
    return kept, ""


def import_desktop_accounts(client=None, realms=None):
    """兼容别名：返回原始桌面结构行（解密由 trae_client 完成）。"""
    rows, error = scan_desktop_accounts(client=client, realms=realms)
    if error:
        raise AccountError(error)
    return rows


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
def _first_present(data, *keys, **kwargs):
    """按顺序取第一个非空值；可选在各层（row / auth / account）里找。"""
    layers = [data]
    for layer in ("auth", "credentials"):
        if isinstance(data.get(layer), dict):
            layers.append(data[layer])
    for key in keys:
        for layer in layers:
            if isinstance(layer, dict):
                value = layer.get(key)
                if value not in (None, ""):
                    return value
    return kwargs.get("default")


class RefreshPayload(dict):
    """刷新载荷：同时支持 dict 下标与属性访问。

    trae_client.refresh_account 可能按「桌面结构 dict」实现（payload["token"]），
    也可能按「账号对象」实现（account.token）。本类两种写法都能吃，避免为探测
    接口而重试 —— refresh 是轮换式，重复调用有让旧 refreshToken 失效的风险。
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def to_desktop_dict(self):
        return dict(self)


class Account(object):
    """一个 Trae 账号（跨 CN / INTL 同构）。

    持久化字段（写进 accounts/<uid>.json）：
      uid / realm / token / refresh_token / expired_at / refresh_expired_at /
      host / user_region / account / enabled / disabled_models / weight /
      proxy / last_error / source / added_at / updated_at / last_ok_at /
      last_error_at / cooldown_until / breaker_until / fails / usage /
      entitlement / usage_updated_at / token_release_at / extra

    出口：proxy_own 是账号级出口（落盘）；proxy/egress 属性读「实际出口」
    ＝ 账号级 > 区域兜底（settings 的 proxy 字段）> 空 = 直连。
    """

    def __init__(self, data=None, path=None, directory=None):
        data = data if isinstance(data, dict) else {}
        profile = data.get("account") if isinstance(data.get("account"), dict) else {}
        user_region = data.get("user_region") or data.get("userRegion") or {}
        if not isinstance(user_region, dict):
            user_region = {"region": str(user_region)}

        self.uid = str(_first_present(data, "uid", "userId", "user_id",
                                      "id", default="") or "")
        self.host = str(_first_present(data, "host", "domain", default="") or "")
        self.realm = str(data.get("realm") or "").strip().lower()
        if self.realm not in REALMS:
            self.realm = detect_realm(
                host=self.host,
                user_region=user_region,
                store_region=str(profile.get("storeRegion") or ""))
        cfg = get_realm_config(self.realm)
        if not self.host:
            self.host = cfg["account"]

        self.token = str(_first_present(data, "token", "accessToken",
                                        "access_token", default="") or "")
        self.refresh_token = str(_first_present(data, "refresh_token", "refreshToken",
                                                default="") or "")
        self.expired_at = normalize_epoch(_first_present(
            data, "expired_at", "expiredAt", "expire_time", "expiresAt"))
        self.refresh_expired_at = normalize_epoch(_first_present(
            data, "refresh_expired_at", "refreshExpiredAt", "refreshExpireAt"))
        self.token_release_at = normalize_epoch(_first_present(
            data, "token_release_at", "tokenReleaseAt"))

        self.user_region = dict(user_region)
        if not self.user_region:
            self.user_region = {"region": cfg["region"],
                                "_aiRegion": cfg["ai_region"]}
        self.account = dict(profile)

        self.enabled = _truthy(data.get("enabled"), True)
        disabled = data.get("disabled_models", data.get("disabledModels"))
        self.disabled_models = [str(m) for m in (disabled or []) if str(m).strip()]
        try:
            self.weight = float(data.get("weight", 1.0) or 1.0)
        except (TypeError, ValueError):
            self.weight = 1.0
        if self.weight <= 0:
            self.weight = 1.0

        self.source = str(data.get("source") or "desktop")
        self.added_at = normalize_epoch(data.get("added_at") or data.get("addedAt")) \
            or int(_now())
        self.updated_at = normalize_epoch(data.get("updated_at")) or self.added_at
        self.last_ok_at = normalize_epoch(data.get("last_ok_at") or data.get("lastOkAt"))
        self.last_error_at = normalize_epoch(data.get("last_error_at"))
        self.cooldown_until = float(data.get("cooldown_until")
                                    or data.get("cooldownUntil") or 0)
        self.breaker_until = float(data.get("breaker_until")
                                   or data.get("breakerUntil") or 0)
        self.fails = int(data.get("fails") or 0)
        self.last_error = str(data.get("last_error") or data.get("lastError") or "")

        self.usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
        self.entitlement = (data.get("entitlement")
                            if isinstance(data.get("entitlement"), dict) else None)
        self.usage_updated_at = normalize_epoch(data.get("usage_updated_at"))
        self.extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
        # 账号级出口（落盘，空 = 走区域兜底 / 直连）
        try:
            self.proxy_own = normalize_proxy(data.get("proxy") or data.get("egress"))
        except ValueError:
            self.proxy_own = ""
        self.proxy_source = "account" if self.proxy_own else "none"

        # 运行期状态（不落盘）
        self.model_cooldowns = {}
        self.inflight = 0
        self._proxy_effective = ""
        self._lock = threading.RLock()

        self.path = path
        self.directory = directory

    # -- 持久化 ----------------------------------------------------------
    def to_dict(self):
        return {
            "uid": self.uid,
            "realm": self.realm,
            "token": self.token,
            "refresh_token": self.refresh_token,
            "expired_at": self.expired_at,
            "refresh_expired_at": self.refresh_expired_at,
            "host": self.host,
            "user_region": self.user_region,
            "account": self.account,
            "enabled": bool(self.enabled),
            "disabled_models": list(self.disabled_models),
            "weight": self.weight,
            "proxy": self.proxy_own,
            "last_error": self.last_error,
            "source": self.source,
            "added_at": self.added_at,
            "updated_at": self.updated_at,
            "last_ok_at": self.last_ok_at,
            "last_error_at": self.last_error_at,
            "cooldown_until": self.cooldown_until,
            "breaker_until": self.breaker_until,
            "fails": self.fails,
            "usage": self.usage,
            "entitlement": self.entitlement,
            "usage_updated_at": self.usage_updated_at,
            "token_release_at": self.token_release_at,
            "extra": self.extra,
        }

    def to_desktop_dict(self):
        """桌面结构（交给 trae_client 的协议层对象）。"""
        return {
            "userId": self.uid,
            "token": self.token,
            "refreshToken": self.refresh_token,
            "expiredAt": iso_utc(self.expired_at),
            "expiredAtMs": int(self.expired_at * 1000) if self.expired_at else 0,
            "refreshExpiredAt": iso_utc(self.refresh_expired_at),
            "tokenReleaseAt": iso_utc(self.token_release_at),
            "host": self.host,
            "userRegion": dict(self.user_region),
            "account": dict(self.account),
            "realm": self.realm,
            "proxy": self.proxy,
            "egress": self.proxy,
        }

    def refresh_payload(self):
        """刷新载荷：桌面结构 + snake_case 别名 + 常用属性，双接口兼容。"""
        data = self.to_desktop_dict()
        data.update({
            "uid": self.uid,
            "realm": self.realm,
            "token": self.token,
            "refresh_token": self.refresh_token,
            "expired_at": self.expired_at,
            "refresh_expired_at": self.refresh_expired_at,
            "host": self.host,
            "user_region": dict(self.user_region),
            "account": dict(self.account),
        })
        return RefreshPayload(data)

    # -- 出口代理 --------------------------------------------------------
    @property
    def proxy(self):
        """实际出口：账号级 > 区域兜底（由账号池注入）> 空 = 直连。"""
        return self._proxy_effective or self.proxy_own

    @proxy.setter
    def proxy(self, value):
        self.proxy_own = normalize_proxy(value)
        self.proxy_source = "account" if self.proxy_own else "none"

    @property
    def egress(self):
        """proxy 的别名（看板/网关都可用）。"""
        return self.proxy

    def set_egress(self, realm_proxy="", source="realm"):
        """账号池注入区域兜底出口（运行期，不落盘）。"""
        value = ""
        if not self.proxy_own and realm_proxy:
            try:
                value = normalize_proxy(realm_proxy)
            except ValueError:
                value = ""
        self._proxy_effective = value
        if self.proxy_own:
            self.proxy_source = "account"
        elif value:
            self.proxy_source = "realm"
        else:
            self.proxy_source = "none"
        return self.proxy

    # -- 网关兼容视图 ----------------------------------------------------
    @property
    def nickname(self):
        """展示名（只读）：account.username > account.email > uid…后4位。"""
        profile = self.account or {}
        for key in ("username", "name", "displayName"):
            value = str(profile.get(key) or "").strip()
            if value:
                return value
        email = str(profile.get("email") or "").strip()
        if email:
            return email
        return ("uid…" + uid_tail(self.uid)) if self.uid else ""

    @property
    def access_token(self):
        """网关别名：token。"""
        return self.token

    @access_token.setter
    def access_token(self, value):
        self.token = str(value or "")

    @property
    def expires_at(self):
        """网关别名：expired_at（epoch 秒）。"""
        return self.expired_at

    @expires_at.setter
    def expires_at(self, value):
        self.expired_at = normalize_epoch(value)

    @property
    def domain(self):
        """网络域（显示用）：账号 host 的主机名；缺省按 realm 的账号出口。

        cn -> api.trae.com.cn，intl -> grow-normal.traeapi.us。
        """
        host = str(self.host or "").strip()
        if host:
            parsed = urllib.parse.urlsplit(host if "://" in host
                                           else "http://" + host)
            if parsed.hostname:
                return parsed.hostname
            return host
        cfg = get_realm_config(self.realm)
        return urllib.parse.urlsplit(cfg["account"]).hostname or cfg["domain"]

    @property
    def platform(self):
        return "trae"

    @property
    def user_type(self):
        return str((self.account or {}).get("userType") or "")

    @property
    def credits(self):
        """配额视图：entitlement > usage（由 trae_tasks 回填；无数据 None）。"""
        return self.entitlement or self.usage

    @credits.setter
    def credits(self, value):
        if isinstance(value, dict):
            self.entitlement = dict(value)
        elif value is None:
            self.entitlement = None

    @property
    def plan(self):
        source = self.entitlement or {}
        return str(source.get("plan") or source.get("plan_name") or "")

    # -- 失败治理兼容（网关沿用的方法名）---------------------------------
    def note_failure(self, message=None, cooldown=None, model=None, **kwargs):
        return self.note_error(message or "upstream failure",
                               code=kwargs.get("code"), model=model,
                               cooldown=cooldown)

    def note_unknown_failure(self, message=None, cooldown=None, **kwargs):
        return self.note_error(message or "unknown upstream failure",
                               model=kwargs.get("model"), cooldown=cooldown)

    def note_soft_rate(self, message=None, cooldown=COOLDOWN_RATE, **kwargs):
        return self.note_error(message or "upstream rate limited", code=429,
                               model=kwargs.get("model"), cooldown=cooldown)

    # -- 配额查询（不发网络请求：数据由 trae_tasks 回填）------------------
    def fetch_credits(self, *args, **kwargs):
        data = self.credits or {}
        message = "" if data else "尚无用量数据（等待 trae_tasks 回填）"
        return {"ok": bool(data), "credits": dict(data), "usage": self.usage,
                "updated_at": self.usage_updated_at, "source": "local",
                "error": message, "message": message}

    def fetch_plan(self, *args, **kwargs):
        return {"ok": bool(self.plan), "plan": self.plan,
                "entitlement": dict(self.entitlement or {})}

    # -- dict 协议（trae_client 与网关都能 account.get(...)、acc["uid"]）--
    def get(self, key, default=None):
        key = str(key or "")
        if key == "nickname":
            return self.nickname
        if key in ("token", "access_token", "accessToken", "ide_token", "userJwt"):
            return self.token
        if key in ("refresh_token", "refreshToken"):
            return self.refresh_token
        if key in ("expired_at", "expires_at"):
            return self.expired_at
        if key == "expiresAt":
            return iso_utc(self.expired_at)
        if key in ("uid", "userId", "user_id", "user_unique_id"):
            return self.uid
        if key == "realm":
            return self.realm
        if key in ("host", "domain"):
            return self.host
        if key in ("proxy", "egress"):
            return self.proxy
        if key == "plan":
            return self.plan
        if key == "enabled":
            return self.enabled
        if key == "weight":
            return self.weight
        if key == "userRegion":
            return dict(self.user_region)
        if key == "account":
            return dict(self.account)
        return self.to_dict().get(key, default)

    def to_mapping(self):
        """整套字段（含网关别名），供不需要 Account 对象的调用方使用。"""
        data = self.to_dict()
        data.update({"nickname": self.nickname, "access_token": self.token,
                     "accessToken": self.token, "expires_at": self.expired_at,
                     "expiresAt": iso_utc(self.expired_at),
                     "refreshToken": self.refresh_token, "userId": self.uid,
                     "domain": self.host, "egress": self.proxy,
                     "plan": self.plan})
        return data

    def __getitem__(self, key):
        value = self.get(key, _MISSING)
        if value is _MISSING:
            raise KeyError(key)
        return value

    def __contains__(self, key):
        return self.get(key, _MISSING) is not _MISSING

    def keys(self):
        return list(self.to_mapping().keys())

    def items(self):
        return list(self.to_mapping().items())

    def save(self, directory=None):
        """原子落盘（tmp -> fsync -> 0600 -> os.replace）。"""
        target_dir = directory or self.directory or accounts_dir()
        if not self.uid:
            raise AccountError("cannot save account without uid")
        base = os.path.abspath(str(target_dir))
        os.makedirs(base, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", self.uid).strip("._ ") or "account"
        if safe in ("..", "."):
            raise AccountError("invalid uid for file name")
        name = safe + ".json"
        path = os.path.join(base, name)
        if not os.path.abspath(path).startswith(base + os.sep):
            raise AccountError("refusing to write outside accounts dir")
        tmp = path + ".tmp"
        self.updated_at = int(_now())
        self.directory = base
        with _SAVE_LOCK:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, ensure_ascii=False, indent=2)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, path)
        self.path = path
        return path

    def delete(self):
        path = self.path
        if path and os.path.exists(path):
            os.remove(path)
            return True
        return False

    # -- 状态 ------------------------------------------------------------
    def masked_uid(self):
        return mask_uid(self.uid)

    def token_expired(self, skew=0, now=None):
        if not self.expired_at:
            return False
        return self.expired_at <= (now or _now()) + skew

    def refresh_expired(self, now=None):
        if not self.refresh_expired_at:
            return False
        return self.refresh_expired_at <= (now or _now())

    def model_disabled(self, model):
        if not model:
            return False
        return str(model) in self.disabled_models

    def model_cooling(self, model, now=None):
        if not model:
            return False
        return self.model_cooldowns.get(str(model), 0.0) > (now or _now())

    def in_cooldown(self, now=None):
        now = now or _now()
        return self.cooldown_until > now or self.breaker_until > now

    def status(self, now=None):
        now = now or _now()
        if not self.enabled:
            return "disabled"
        if self.breaker_until > now:
            return "breaker"
        if self.cooldown_until > now:
            return "cooldown"
        if self.token_expired(now=now) and not self.refresh_token:
            return "expired"
        return "ready"

    def ready(self, model=None, now=None):
        """可用性判定（纯内存读，不做网络请求）。

        过期但**有 refresh_token** 的账号仍算可用：真正取号后由调用方
        ensure_fresh() 触发刷新（避免在选号循环里打网络）。
        """
        now = now or _now()
        if not self.enabled or not self.token:
            return False
        if self.model_disabled(model):
            return False
        if self.model_cooling(model, now=now):
            return False
        if self.breaker_until > now or self.cooldown_until > now:
            return False
        if self.token_expired(now=now) and not self.refresh_token:
            return False
        if self.refresh_expired(now=now):
            return False
        return True

    # -- 失败治理 --------------------------------------------------------
    def note_success(self, model=None):
        changed = bool(self.fails or self.last_error or self.cooldown_until
                       or self.breaker_until or self.last_error_at)
        self.fails = 0
        self.last_error = ""
        self.last_error_at = 0
        self.cooldown_until = 0.0
        self.breaker_until = 0.0
        self.last_ok_at = int(_now())
        if model:
            self.model_cooldowns.pop(str(model), None)
        if changed:
            self.save()
        return True

    def note_error(self, message, code=None, model=None, cooldown=None,
                   breaker=None, persist=True):
        """记一次失败并给出冷却/熔断窗口（返回本次冷却秒数）。

        code 约定（.team/PROTOCOL.md 第六节）：1001 鉴权 / 4015 上游拒绝 /
        4019 风控 / 4023 模型未知 / 429 限速。
        """
        now = _now()
        msg = _scrub_secrets(message, self)[:500]
        self.fails += 1
        self.last_error = msg
        self.last_error_at = int(now)
        code = int(code) if str(code or "").strip().isdigit() else code

        if code in (1001, 401, 403):
            window = float(breaker if breaker is not None else BREAKER_AUTH)
            self.breaker_until = max(self.breaker_until, now + window)
            seconds = window
        elif code in (4019, 4015):
            window = float(cooldown if cooldown is not None else (
                BREAKER_RISK if code == 4019 else COOLDOWN_RATE * 3))
            self.cooldown_until = max(self.cooldown_until, now + window)
            seconds = window
        elif code == 429:
            window = float(cooldown if cooldown is not None else COOLDOWN_RATE)
            self.cooldown_until = max(self.cooldown_until, now + window)
            seconds = window
        elif code == 4023:
            if model:
                self.model_cooldowns[str(model)] = now + float(cooldown or 300)
            seconds = float(cooldown or 0)
        else:
            if cooldown is not None:
                window = float(cooldown)
            else:
                window = min(COOLDOWN_CAP, COOLDOWN_BASE * (2 ** min(self.fails - 1, 5)))
            if window > 0:          # cooldown=0：只记错误时间（刷新退避用），不冻结
                self.cooldown_until = max(self.cooldown_until, now + window)
            seconds = window
        if persist:
            self.save()
        return seconds

    def clear_error(self):
        self.last_error = ""
        self.last_error_at = 0
        self.fails = 0
        self.cooldown_until = 0.0
        self.breaker_until = 0.0
        self.model_cooldowns = {}
        self.save()

    # -- 刷新（委托 trae_client，轮换原子回写）----------------------------
    def refresh_due(self, now=None, ahead=REFRESH_AHEAD):
        """是否进入刷新窗口：距 expires_at 不足 ahead（默认 24 小时）。

        无 refresh_token / 无 expires_at 一律视为「不需要刷新」——避免没有
        过期信息的账号被反复打 ExchangeToken（轮换式令牌，成本高）。
        """
        if not self.refresh_token or not self.expired_at:
            return False
        return self.expired_at <= (now or _now()) + max(0.0, float(ahead))

    def refresh_backoff_left(self, now=None):
        """刷新失败后的剩余退避秒数：10 分钟起，按连续失败加倍，最多 1 小时。"""
        now = now or _now()
        if not self.last_error_at:
            return 0.0
        exponent = min(max(int(self.fails or 1) - 1, 0), 4)
        window = min(REFRESH_FAIL_BACKOFF_MAX,
                     REFRESH_FAIL_BACKOFF * (2 ** exponent))
        return max(0.0, float(self.last_error_at) + window - now)

    def apply_refresh_result(self, result):
        """把归一后的刷新结果写回对象并原子落盘；失败不落盘。"""
        token = str(result.get("token") or "")
        if not token:
            raise AccountError("refresh result has no token")
        rotated = bool(result.get("refresh_token")) and \
            result["refresh_token"] != self.refresh_token
        self.token = token
        if result.get("refresh_token"):
            self.refresh_token = str(result["refresh_token"])
        if result.get("expired_at"):
            self.expired_at = int(result["expired_at"])
        if result.get("refresh_expired_at"):
            self.refresh_expired_at = int(result["refresh_expired_at"])
        self.fails = 0
        self.last_error = ""
        self.last_error_at = 0
        self.cooldown_until = 0.0
        self.breaker_until = 0.0
        self.last_ok_at = int(_now())
        self.save()
        return RefreshSummary({
            "uid": mask_uid(self.uid),
            "uidHash": uid_digest(self.uid),
            "realm": self.realm,
            "rotated": rotated,
            "expiresAt": self.expired_at,
            "expiresIn": human_delta(self.expired_at - _now()) if self.expired_at else None,
            "hasRefreshToken": bool(self.refresh_token),
            "file": os.path.basename(self.path or ""),
        })

    def refresh(self, force=False, client=None):
        """刷新 token（refreshToken 轮换式）。

        force=False 且 token 尚未进入刷新窗口时直接返回 skipped。
        返回脱敏摘要；任何失败都不触碰已有文件。
        """
        with self._lock:
            now = _now()
            if not self.refresh_token:
                raise AccountError("账号无 refreshToken，需重新导入：%s"
                                   % mask_uid(self.uid))
            if self.refresh_expired(now=now):
                raise AccountError("refreshToken 已过期（%s），需重新导入：%s"
                                   % (iso_utc(self.refresh_expired_at),
                                      mask_uid(self.uid)))
            if not force:
                left = self.refresh_backoff_left(now=now)
                if left:
                    return RefreshSummary({
                        "uid": mask_uid(self.uid), "realm": self.realm,
                        "skipped": True, "backoff": left,
                        "reason": "刷新失败退避中（剩 %d 秒）" % left})
                if not self.refresh_due(now=now):
                    return RefreshSummary({
                        "uid": mask_uid(self.uid), "realm": self.realm,
                        "skipped": True,
                        "reason": "token 未进入刷新窗口（距过期仍 > 24h）",
                        "expiresIn": human_delta(self.expired_at - now)
                        if self.expired_at else None})
            policy = (os.environ.get("TRAE_REFRESH_POLICY") or "rotate").strip().lower()
            if policy in ("readonly", "read-only", "none", "off"):
                # 只读策略：不调用 ExchangeToken，先跟桌面端 storage.json 同步；
                # 桌面端也没更新则明确报错，避免静默轮换掉桌面端 refreshToken。
                client = client or _load_client()
                fresh = None
                if client is not None and hasattr(client, "reload_desktop_auth"):
                    try:
                        fresh = client.reload_desktop_auth(self.to_dict(), self.realm)
                    except Exception:
                        fresh = None
                if fresh:
                    normalized = normalize_refresh_result(fresh)
                    if normalized.get("token") and normalized["token"] != self.token:
                        summary = self.apply_refresh_result(normalized)
                        summary["source"] = "desktop-reload"
                        return summary
                raise AccountError(
                    "刷新已禁用（TRAE_REFRESH_POLICY=readonly）：请先在 Trae 桌面端刷新，"
                    "或改为 rotate 策略/重新导入凭证")
            try:
                result = _call_client_refresh(self, client=client)
            except Exception as exc:
                # 记录失败时间（刷新退避的时钟）；cooldown=0 不额外冻结账号
                self.note_error(str(exc) or "refresh failed", cooldown=0)
                raise
            summary = self.apply_refresh_result(result)
            # 轮换式 refreshToken：默认把新值同步回桌面端，避免桌面端下次刷新 401。
            if (os.environ.get("TRAE_SYNC_DESKTOP") or "1").strip() != "0":
                try:
                    client = client or _load_client()
                    if client is not None and hasattr(client, "sync_desktop_auth"):
                        synced = client.sync_desktop_auth(self.to_dict(), self.realm)
                        summary["desktopSync"] = bool(synced.get("ok"))
                        if not synced.get("ok"):
                            summary["desktopSyncError"] = synced.get("error")
                except Exception as exc:
                    summary["desktopSyncError"] = type(exc).__name__
            return summary

    def ensure_fresh(self, skew=None, client=None, respect_backoff=True):
        """用前保鲜：距过期 <= 24h（或显式 skew）才刷新，失败后按 last_error_at 退避。

        默认（skew=None）用 REFRESH_AHEAD=24h 窗口：token 还有一天以上时直接
        跳过，不再每次 model discovery / 选号都打 ExchangeToken。
        """
        now = _now()
        ahead = REFRESH_AHEAD if skew is None else float(skew)
        if not self.refresh_token:
            return RefreshSummary({
                "uid": mask_uid(self.uid), "realm": self.realm,
                "skipped": True, "reason": "无 refreshToken"})
        if not self.refresh_due(now=now, ahead=ahead):
            return RefreshSummary({
                "uid": mask_uid(self.uid), "realm": self.realm,
                "skipped": True, "reason": "token 未进入刷新窗口",
                "expiresIn": human_delta(self.expired_at - now)
                if self.expired_at else None})
        if respect_backoff:
            left = self.refresh_backoff_left(now=now)
            if left:
                return RefreshSummary({
                    "uid": mask_uid(self.uid), "realm": self.realm,
                    "skipped": True, "backoff": left,
                    "reason": "刷新失败退避中（剩 %d 秒）" % left})
        return self.refresh(force=True, client=client)

    # -- 配额字段（由 trae_tasks 填充）-----------------------------------
    def set_usage(self, usage=None, entitlement=None, persist=True):
        if isinstance(usage, dict):
            self.usage = dict(usage)
            self.usage_updated_at = int(_now())
        if isinstance(entitlement, dict):
            self.entitlement = dict(entitlement)
            self.usage_updated_at = int(_now())
        if persist:
            self.save()
        return self.public()

    # -- 并发闸门 --------------------------------------------------------
    def add_inflight(self):
        self.inflight += 1

    def release_inflight(self):
        self.inflight = max(0, self.inflight - 1)

    # -- 脱敏视图 --------------------------------------------------------
    @staticmethod
    def _credit_view(account):
        ent = getattr(account, "entitlement", None) or {}
        usage = ent.get("ent_usage") if isinstance(ent.get("ent_usage"), dict) else {}
        packs = usage.get("user_entitlement_pack_list") or []
        pack = next((x for x in packs if isinstance(x, dict)), {}) if isinstance(packs, list) else {}
        quota = pack.get("quota") if isinstance(pack.get("quota"), dict) else {}
        used = pack.get("usage") if isinstance(pack.get("usage"), dict) else {}
        try:
            limit = int(quota.get("advanced_model_request_limit") or 0)
            consumed = int(used.get("advanced_model_request_usage") or 0)
        except (TypeError, ValueError):
            limit, consumed = 0, 0
        checkin = (getattr(account, "extra", {}) or {}).get("checkin") or {}
        try:
            credits = int(checkin.get("credits") or 0)
        except (TypeError, ValueError):
            credits = 0
        return {
            "checkin": credits,
            "checkin_at": checkin.get("at") or "",
            "checked_in": bool(checkin.get("checked_in")),
            "plan": str(pack.get("display_desc") or ""),
            "remain": max(0, limit - consumed),
            "limit": limit,
            "used": consumed,
            "updated_at": getattr(account, "usage_updated_at", 0) or 0,
        }

    @staticmethod
    def _intl_quota_state(quota):
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
        if any(v <= 10 for v in vals):
            return "low"
        return "ok"

    def public(self, now=None):
        now = now or _now()
        token_info = redact_token(self.token)
        refresh_info = redact_token(self.refresh_token)
        profile = self.account or {}
        return {
            # uid 只露后 4 位；uidHash 供接口定位，不可逆
            "uid": mask_uid(self.uid),
            "uidTail": uid_tail(self.uid),
            "uidHash": uid_digest(self.uid),
            "realm": self.realm,
            "realmName": get_realm_config(self.realm)["name"],
            "host": self.host,
            "proxy": mask_proxy(self.proxy),
            "proxyConfigured": bool(self.proxy),
            "proxySource": self.proxy_source,
            "enabled": bool(self.enabled),
            "status": self.status(now=now),
            "weight": self.weight,
            "disabledModels": list(self.disabled_models),
            "token": token_info,
            "refreshToken": refresh_info,
            "hasRefreshToken": bool(self.refresh_token),
            "expiresAt": self.expired_at,
            "expiresIso": iso_utc(self.expired_at),
            "expiresIn": human_delta(self.expired_at - now) if self.expired_at else None,
            "refreshExpiresAt": self.refresh_expired_at,
            "refreshExpiresIn": (human_delta(self.refresh_expired_at - now)
                                 if self.refresh_expired_at else None),
            "userRegion": dict(self.user_region),
            "account": {
                "username": mask_name(profile.get("username")),
                "email": mask_email(profile.get("email")),
                "avatar_url": str(profile.get("avatar_url") or ""),
                "scope": profile.get("scope"),
                "loginScope": profile.get("loginScope"),
                "storeRegion": profile.get("storeRegion"),
                "userTag": profile.get("userTag"),
                "storeCountryCode": profile.get("storeCountryCode"),
            },
            "userType": profile.get("userType"),
            "lastError": _scrub_secrets(self.last_error, self),
            "lastErrorAt": self.last_error_at or None,
            "lastOkAt": self.last_ok_at or None,
            "cooldownFor": round(max(0.0, self.cooldown_until - now)) or None,
            "breakerFor": round(max(0.0, self.breaker_until - now)) or None,
            "fails": int(self.fails),
            "inflight": int(self.inflight),
            "source": self.source,
            "addedAt": self.added_at,
            "updatedAt": self.updated_at,
            "usage": self.usage,
            "entitlement": self.entitlement,
            "credits": self._credit_view(self),
            "intlQuota": (self.extra or {}).get("intl_quota"),
            "intlQuotaState": self._intl_quota_state(
                (self.extra or {}).get("intl_quota")),
            "usageUpdatedAt": self.usage_updated_at or None,
            "file": os.path.basename(self.path or ""),
        }

    # -- 构造 ------------------------------------------------------------
    @classmethod
    def from_desktop(cls, row, realm=None, directory=None):
        """从桌面结构（PROTOCOL 第三节）构造 Account。"""
        if not isinstance(row, dict):
            raise ValueError("desktop row is not an object")
        data = dict(row)
        if realm:
            data["realm"] = realm
        raw_source = str(data.get("source") or "")
        if re.search(r"[\\/]", raw_source) or raw_source.endswith(".json"):
            extra = dict(data.get("extra") or {})
            extra.setdefault("desktopSource", raw_source)
            data["extra"] = extra
            data["source"] = "desktop"
        else:
            data["source"] = raw_source or "desktop"
        account = cls(data, directory=directory)
        if not account.uid:
            raise ValueError("desktop row has no userId")
        if not account.token:
            raise ValueError("desktop row has no token")
        return account


# ---------------------------------------------------------------------------
# 会话粘性
# ---------------------------------------------------------------------------
class SessionAffinity(object):
    """session_key -> uid 的短期绑定（同一对话固定落到同一账号）。"""

    def __init__(self, ttl=7200, max_entries=5000):
        self.ttl = ttl
        self.max_entries = max_entries
        self.bindings = {}
        self._lock = threading.Lock()

    def get(self, key):
        if not key:
            return None
        with self._lock:
            entry = self.bindings.get(key)
            if not entry:
                return None
            uid, exp = entry
            if time.time() > exp:
                self.bindings.pop(key, None)
                return None
            self.bindings[key] = (uid, time.time() + self.ttl)
            return uid

    def bind(self, key, uid):
        if not key or not uid:
            return
        with self._lock:
            if len(self.bindings) >= self.max_entries:
                now = time.time()
                self.bindings = {k: v for k, v in self.bindings.items()
                                 if v[1] > now}
            self.bindings[key] = (uid, time.time() + self.ttl)

    def unbind(self, key):
        if not key:
            return
        with self._lock:
            self.bindings.pop(key, None)

    def size(self):
        with self._lock:
            return len(self.bindings)


# ---------------------------------------------------------------------------
# AccountPool
# ---------------------------------------------------------------------------
def _default_log(message, level=None):
    try:
        import sys
        prefix = "[accounts]"
        if level:
            prefix += "[%s]" % level
        print("%s %s" % (prefix, message), file=sys.stderr)
    except Exception:
        pass


class AccountPool(object):
    """双区账号池：realm 选号 / 会话粘性 / 加权轮转 / 冷却熔断 / 并发闸门。"""

    SKIP_FILES = ("settings.json", "active_realm.json", "machine_identity.json")

    def __init__(self, directory=None, log=None, max_inflight=None, proxies=None):
        global _ACTIVE_POOL
        self.dir = os.path.abspath(directory or accounts_dir())
        self.log = log or _default_log
        self.accounts = []
        self._lock = threading.RLock()
        self.affinity = SessionAffinity()
        self._weights = {}
        # 区域出口覆盖（运行期）：{"cn": "...", "intl": "...", "global": "..."}
        self.proxies = {}
        self._settings_doc = None
        self._load_proxy_config(proxies)
        # 每日限额（三级作用域）与本地日账
        self.limits = {scope: {} for scope in LIMIT_SCOPES}
        self.free_models = frozenset()
        self._limits_lock = threading.RLock()
        self._ledger_lock = threading.Lock()
        self._ledger_cache = {}
        self._mem_usage = {}        # (day, uid[, model]) -> tokens
        self.ledger_reader = None   # 可注入：reader(uid, model) -> 当日 tokens
        try:
            self.max_inflight = int(max_inflight if max_inflight is not None
                                    else (os.environ.get("TRAE_MAX_INFLIGHT") or 8))
        except (TypeError, ValueError):
            self.max_inflight = 8
        if self.max_inflight < 0:
            self.max_inflight = 0
        _ACTIVE_POOL = self

    # -- 装载 ------------------------------------------------------------
    def load(self):
        with self._lock:
            self.accounts = []
            if not os.path.isdir(self.dir):
                return self.accounts
            for name in sorted(os.listdir(self.dir)):
                if not name.endswith(".json") or name in self.SKIP_FILES:
                    continue
                path = os.path.join(self.dir, name)
                try:
                    with open(path, encoding="utf-8") as fh:
                        data = json.load(fh)
                except Exception as exc:
                    self.log("账号文件不可读 %s: %s" % (name, exc), level="WARN")
                    continue
                if not isinstance(data, dict) or not data.get("uid"):
                    self.log("账号文件缺少 uid，已跳过 %s" % name, level="WARN")
                    continue
                try:
                    account = Account(data, path=path, directory=self.dir)
                except Exception as exc:
                    self.log("账号构造失败 %s: %s" % (name, exc), level="WARN")
                    continue
                self.accounts.append(account)
                self._apply_egress(account)
            self.log("已装载 %d 个账号（%s）" % (len(self.accounts), self.dir))
            return self.accounts

    # -- 查询 ------------------------------------------------------------
    def get(self, key):
        """按完整 uid / uidHash / 脱敏 uid 定位账号。"""
        key = str(key or "").strip()
        if not key:
            return None
        with self._lock:
            for account in self.accounts:
                if account.uid == key:
                    return account
            for account in self.accounts:
                if uid_digest(account.uid) == key or uid_digest(account.uid).startswith(key):
                    return account
            tail = key.lstrip("….")
            for account in self.accounts:
                if tail and uid_tail(account.uid) == tail:
                    return account
        return None

    resolve = get

    def by_realm(self, realm=None):
        with self._lock:
            if not realm or str(realm).lower() == "all":
                return list(self.accounts)
            realm = str(realm).lower()
            return [a for a in self.accounts if a.realm == realm]

    def list_public(self, realm=None, now=None):
        now = now or _now()
        return [self._apply_egress(a).public(now=now) for a in self.by_realm(realm)]

    @staticmethod
    def _health_bucket():
        return {"total": 0, "available": 0, "ready": 0, "cooldown": 0,
                "breaker": 0, "expired": 0, "refreshExpired": 0,
                "disabled": 0, "families": {}}

    @staticmethod
    def _count_account(bucket, account, now):
        """把一个账号计入健康桶（available / 冷却 / 熔断 / 过期 / 停用）。"""
        bucket["total"] += 1
        if account.ready(now=now):
            bucket["available"] += 1
            bucket["ready"] += 1
        if account.cooldown_until > now:
            bucket["cooldown"] += 1
        if account.breaker_until > now:
            bucket["breaker"] += 1
        if account.token_expired(now=now):
            bucket["expired"] += 1
        if account.refresh_expired(now=now):
            bucket["refreshExpired"] += 1
        if not account.enabled:
            bucket["disabled"] += 1
        status = account.status(now=now)
        bucket["families"][status] = bucket["families"].get(status, 0) + 1

    def summary(self, now=None):
        """双区健康摘要：available / cooldown / breaker / expired / refreshExpired。

        供 /health 与看板直接用：realms.<realm>.* 与顶层同名聚合计数。
        （ready 与 available 同义，保留 ready 兼容旧调用。）
        """
        now = now or _now()
        out = self._health_bucket()
        out.update({"dir": self.dir, "maxInflight": self.max_inflight,
                    "realms": {}})
        for account in self.by_realm():
            bucket = out["realms"].setdefault(account.realm, self._health_bucket())
            self._count_account(bucket, account, now)
            self._count_account(out, account, now)
        out["ok"] = out["available"] > 0
        return out

    def health(self, now=None):
        """summary 的语义别名（/health 直接返回）。"""
        return self.summary(now=now)

    def count_ready(self, realm=None, model=None):
        return sum(1 for a in self.by_realm(realm) if a.ready(model=model))

    def representative(self, realm=None):
        for account in self.by_realm(realm):
            if account.ready():
                return self._apply_egress(account)
        accounts = self.by_realm(realm)
        return self._apply_egress(accounts[0]) if accounts else None

    # -- 增删改 ----------------------------------------------------------
    def add(self, account):
        if not isinstance(account, Account):
            raise TypeError("add() expects Account")
        with self._lock:
            existing = self.get(account.uid)
            if existing is not None:
                account.added_at = existing.added_at or account.added_at
                if not account.usage and existing.usage:
                    account.usage = existing.usage
                if not account.entitlement and existing.entitlement:
                    account.entitlement = existing.entitlement
                self.accounts[self.accounts.index(existing)] = account
            else:
                self.accounts.append(account)
            account.directory = self.dir
            account.save(self.dir)
        return self._apply_egress(account)

    def remove(self, uid):
        with self._lock:
            account = self.get(uid)
            if account is None:
                return False
            account.delete()
            self.accounts.remove(account)
            self._weights.pop(account.uid, None)
        self.log("已删除账号 %s（%s）" % (mask_uid(account.uid), account.realm))
        return True

    def set_enabled(self, uid, enabled):
        account = self.get(uid)
        if account is None:
            return None
        with account._lock:
            account.enabled = bool(enabled)
            if enabled:
                account.clear_error()
            else:
                account.save()
        self.log("账号 %s（%s）已%s" % (mask_uid(account.uid), account.realm,
                                       "启用" if enabled else "停用"))
        return account.public()

    def set_all_enabled(self, enabled, realm=None):
        changed = 0
        for account in self.by_realm(realm):
            with account._lock:
                account.enabled = bool(enabled)
                if enabled:
                    account.clear_error()
                else:
                    account.save()
            changed += 1
        return changed

    def set_disabled_models(self, uid, models):
        account = self.get(uid)
        if account is None:
            return None
        with account._lock:
            account.disabled_models = [str(m) for m in (models or []) if str(m).strip()]
            account.save()
        return account.public()

    def set_weight(self, uid, weight):
        account = self.get(uid)
        if account is None:
            return None
        try:
            value = float(weight)
        except (TypeError, ValueError):
            raise AccountError("weight 必须是数字")
        with account._lock:
            account.weight = value if value > 0 else 1.0
            account.save()
        return account.public()

    def note_usage(self, uid, usage=None, model=None, realm=None,
                   entitlement=None):
        """登记一次用量（可选）：写内存日账 + 更新账号的 usage/entitlement。

        - 网关已把同一行写进 usage.jsonl；guard 优先读文件，**不会重复计数**
          （只有 usage 文件不存在时才用内存日账）。
        - 兼容旧调用 POOL.note_usage(account_uid)（只有 uid，没有 usage）。
        """
        tokens = _usage_tokens(usage)
        day = local_day()
        key_uid = str(uid or "")
        with self._ledger_lock:
            if tokens and key_uid:
                self._mem_usage[(day, key_uid)] = \
                    self._mem_usage.get((day, key_uid), 0) + tokens
                if model:
                    mkey = (day, key_uid, str(model))
                    self._mem_usage[mkey] = self._mem_usage.get(mkey, 0) + tokens
            if len(self._mem_usage) > 4096:
                self._mem_usage = {k: v for k, v in self._mem_usage.items()
                                   if k[0] == day}
        account = self.get(uid)
        if account is None:
            return {"uid": mask_uid(uid), "tokens": tokens,
                    "todayTokens": self._memory_ledger(day, key_uid)}
        with account._lock:
            if isinstance(usage, dict) or isinstance(entitlement, dict):
                return account.set_usage(
                    usage=usage if isinstance(usage, dict) else None,
                    entitlement=entitlement if isinstance(entitlement, dict)
                    else None)
        return account.public()

    # -- 并发闸门 --------------------------------------------------------
    def _saturated(self, account):
        return self.max_inflight > 0 and account.inflight >= self.max_inflight

    @contextlib.contextmanager
    def slot(self, account):
        """占用一个并发槽（异常安全）。"""
        if account is None:
            raise AccountError("slot() 需要账号对象")
        account.add_inflight()
        try:
            yield account
        finally:
            account.release_inflight()

    # -- 出口代理 --------------------------------------------------------
    def _load_proxy_config(self, proxies):
        if proxies is None:
            return
        if isinstance(proxies, str):
            proxies = {"global": proxies}
        if not isinstance(proxies, dict):
            return
        for key, value in proxies.items():
            try:
                normalized = normalize_proxy(value)
            except ValueError as exc:
                self.log("忽略非法代理配置 %s: %s" % (key, exc), level="WARN")
                continue
            if normalized:
                self.proxies[str(key or "global").lower()] = normalized

    def reload_settings(self):
        """丢弃 settings 缓存并重算出口（设置页保存后调用）。"""
        self._settings_doc = None
        for account in self.by_realm():
            self._apply_egress(account)
        return self

    def realm_proxy(self, realm=None):
        """区域兜底出口：显式构造/运行期覆盖 > settings.proxy > ''（直连）。"""
        realm = str(realm or "").strip().lower()
        if self.proxies:
            if self.proxies.get(realm):
                return self.proxies[realm]
            if self.proxies.get("global"):
                return self.proxies["global"]
        if self._settings_doc is None:
            self._settings_doc = _load_settings(self.dir)
        try:
            return proxy_from_settings(self._settings_doc, realm)
        except Exception:
            return ""

    def effective_proxy(self, account):
        """账号实际出口：账号级 > 区域兜底 > 空 = 直连。"""
        if account is None:
            return ""
        return account.proxy_own or self.realm_proxy(account.realm)

    def _apply_egress(self, account):
        """把区域兜底注入账号（只在账号级为空时生效）。"""
        if account is not None:
            account.set_egress(self.realm_proxy(account.realm))
        return account

    def set_realm_proxy(self, realm, proxy):
        """运行期设置区域出口（proxy 为空 = 清除，回落到 settings）。"""
        key = str(realm or "global").strip().lower()
        value = normalize_proxy(proxy) if proxy else ""
        if value:
            self.proxies[key] = value
        else:
            self.proxies.pop(key, None)
        for account in self.by_realm(None if key == "global" else key):
            self._apply_egress(account)
        return self.realm_proxy(realm)

    def set_proxy(self, uid, proxy):
        """账号级出口（持久化）。空 = 回落到区域兜底 / 直连。"""
        account = self.get(uid)
        if account is None:
            return None
        with account._lock:
            account.proxy = proxy or ""
            account.save()
            self._apply_egress(account)
        self.log("账号 %s（%s）出口=%s"
                 % (mask_uid(account.uid), account.realm,
                    mask_proxy(account.proxy) or "直连"))
        return account.public()

    # -- 选号 ------------------------------------------------------------
    def _weighted_pick(self, candidates):
        """平滑加权轮转（nginx smooth WRR）：等权时退化为严格轮转。"""
        if not candidates:
            return None
        weights = [max(0.0001, float(a.weight or 1.0)) for a in candidates]
        total = sum(weights) or 1.0
        with self._lock:
            best_i, best_cur = 0, None
            for i, account in enumerate(candidates):
                cur = self._weights.get(account.uid, 0.0) + weights[i]
                if best_cur is None or cur > best_cur:
                    best_i, best_cur = i, cur
            winner = candidates[best_i]
            self._weights[winner.uid] = best_cur - total
            if len(self._weights) > 256:
                keep = {a.uid for a in candidates}
                for uid in [u for u in self._weights if u not in keep]:
                    self._weights.pop(uid, None)
        return winner

    def pick(self, realm=None, exclude=None, model=None, session_key=None,
             now=None, ignore_inflight=False):
        """选一个可用账号。

        优先级：会话粘性 > 未饱和（并发上限）> 加权轮转。
        全部饱和时返回 None（并发上限是硬闸门：调用方据此返回 429/503，
        或在已知会立刻占用 slot 的场景传 ignore_inflight=True 自行把关）。
        """
        now = now or _now()
        exclude = set(exclude or ())
        if session_key:
            bound = self.affinity.get(session_key)
            if bound and bound not in exclude:
                account = self.get(bound)
                if account and account.ready(model=model, now=now) \
                        and (not realm or account.realm == realm):
                    if ignore_inflight or not self._saturated(account):
                        return self._apply_egress(account)
                    # 粘性账号已饱和：解绑，交给正常路由（避免死锁在同一号）
                    self.affinity.unbind(session_key)

        pool = [a for a in self.by_realm(realm)
                if a.uid not in exclude and a.ready(model=model, now=now)]
        if not pool:
            return None
        if not ignore_inflight:
            pool = [a for a in pool if not self._saturated(a)]
        chosen = self._weighted_pick(pool)
        if chosen is not None and session_key:
            self.affinity.bind(session_key, chosen.uid)
        return self._apply_egress(chosen)

    def pick_for_session(self, realm=None, session_key=None, exclude=None,
                         model=None):
        return self.pick(realm=realm, exclude=exclude, model=model,
                         session_key=session_key)

    # -- 刷新 ------------------------------------------------------------
    def refresh_account(self, uid, client=None, force=True):
        account = self.get(uid)
        if account is None:
            raise AccountError("账号不存在：%s" % mask_uid(uid))
        summary = account.refresh(force=force, client=client)
        if summary.get("skipped"):
            self.log("刷新跳过 %s（%s）：%s" % (mask_uid(account.uid),
                                              account.realm, summary.get("reason")))
        else:
            self.log("刷新成功 %s（%s）rotated=%s expiresIn=%s"
                     % (mask_uid(account.uid), account.realm,
                        summary.get("rotated"), summary.get("expiresIn")))
        return summary

    def refresh_due(self, realm=None, client=None, skew=None, now=None,
                    ahead=None, force=False):
        """刷新进入窗口的账号（默认距过期 <= 24h），返回逐条脱敏摘要。

        两条纪律（修 INTL 号被每 1-2 秒刷一次的抖动）：
          1. 只有 refresh_due()（24h 窗口）才刷；**冷却中的号不再触发刷新**；
          2. 上次刷新失败（last_error_at）后按 10min→1h 退避，force=True 才绕过。
        """
        now = now or _now()
        window = REFRESH_AHEAD if ahead is None else ahead
        if skew is not None:            # 兼容旧调用参数
            window = skew
        results = []
        for account in self.by_realm(realm):
            if not account.refresh_due(now=now, ahead=window):
                continue
            if not force:
                left = account.refresh_backoff_left(now=now)
                if left:
                    results.append({"uid": mask_uid(account.uid),
                                    "realm": account.realm, "skipped": True,
                                    "backoff": left,
                                    "reason": "刷新失败退避中（剩 %d 秒）" % left})
                    continue
            try:
                results.append(self.refresh_account(account.uid, client=client,
                                                    force=True))
            except AccountError as exc:
                self.log("刷新失败 %s（%s）：%s"
                         % (mask_uid(account.uid), account.realm, exc),
                         level="WARN")
                results.append({"uid": mask_uid(account.uid),
                                "realm": account.realm, "error": str(exc)})
        return results

    # -- 粘贴 refreshToken 导入 -------------------------------------------
    def add_from_refresh(self, refresh_token, realm=None, uid=None, proxy=None,
                         overwrite=False, client=None):
        """粘贴 refreshToken 换 access token 并入库。

        区域必须显式指定（refreshToken 本身不含区域信息，不做猜测）。
        换出来的 refreshToken 已轮换，必须立即落盘 —— 落盘失败等于该令牌作废。
        返回脱敏视图 + uidSynthetic（uid 由令牌摘要推导时为 True）。
        """
        token_in = str(refresh_token or "").strip().strip('"').strip("'")
        if token_in.lower().startswith("bearer "):
            token_in = token_in[7:].strip()
        if not token_in:
            raise AccountError("refreshToken 不能为空")
        realm_key_value = realm_key(realm)
        if not realm_key_value:
            raise AccountError("请显式指定 realm（cn 或 intl）：refreshToken 不携带"
                               "区域信息，无法推断，也不做猜测")

        seed = hashlib.sha256(token_in.encode("utf-8")).hexdigest()[:20]
        explicit_uid = str(uid or "").strip()
        if not explicit_uid:
            # 去重：存的是轮换后的 refreshToken，所以还要认「首次粘贴令牌」的指纹
            same = next((a for a in self.accounts
                         if a.refresh_token == token_in
                         or (a.extra or {}).get("refreshTokenOrigin") == seed),
                        None)
            if same is not None:
                explicit_uid = same.uid

        result = _refresh_with_token(token_in, realm_key_value, client=client,
                                     uid=explicit_uid)
        derived_uid = ""
        if not explicit_uid:
            derived_uid = "rt-" + seed
            explicit_uid = derived_uid
        account_uid = _safe_uid(explicit_uid)

        existing = self.get(account_uid)
        if existing is not None and not overwrite:
            return {"uid": mask_uid(existing.uid),
                    "uidHash": uid_digest(existing.uid),
                    "realm": existing.realm,
                    "skipped": True,
                    "reason": "该 refreshToken 已属于池内账号（overwrite=False 不覆盖）"}

        cfg = get_realm_config(realm_key_value)
        if existing is not None:
            with existing._lock:
                existing.token = result["token"]
                if result.get("refresh_token"):
                    existing.refresh_token = result["refresh_token"]
                if result.get("expired_at"):
                    existing.expired_at = int(result["expired_at"])
                if result.get("refresh_expired_at"):
                    existing.refresh_expired_at = int(result["refresh_expired_at"])
                existing.realm = realm_key_value
                existing.host = existing.host or cfg["account"]
                existing.fails = 0
                existing.last_error = ""
                existing.cooldown_until = 0.0
                existing.breaker_until = 0.0
                existing.last_ok_at = int(_now())
                existing.source = "refresh-token"
                existing.extra = dict(existing.extra or {})
                existing.extra["refreshTokenOrigin"] = seed
                if proxy is not None:
                    existing.proxy = proxy
                existing.save(self.dir)
            self._apply_egress(existing)
            self.log("refreshToken 导入：更新 %s（%s）"
                     % (mask_uid(existing.uid), existing.realm))
            view = dict(existing.public(), uidSynthetic=bool(derived_uid),
                        updated=True)
            return view

        account = Account({
            "uid": account_uid,
            "realm": realm_key_value,
            "token": result["token"],
            "refresh_token": result.get("refresh_token") or token_in,
            "expired_at": result.get("expired_at") or int(_now()) + 3600,
            "refresh_expired_at": result.get("refresh_expired_at") or 0,
            "host": cfg["account"],
            "user_region": {"region": cfg["region"],
                            "_aiRegion": cfg["ai_region"]},
            "proxy": proxy or "",
            "enabled": True,
            "source": "refresh-token",
            "extra": {"refreshTokenOrigin": seed},
        }, directory=self.dir)
        self.add(account)
        self.log("refreshToken 导入：新增 %s（%s）"
                 % (mask_uid(account.uid), account.realm))
        return dict(account.public(), uidSynthetic=bool(derived_uid), created=True)

    # -- 旧登录路由的明确回答（Trae 没有设备授权流程）--------------------
    def start_login(self, realm=None, platform=None):
        return {"status": "unsupported", "realm": realm_key(realm) or "",
                "message": "Trae 没有设备授权流程：请用 Desktop 导入，或粘贴 refreshToken"}

    def poll_login(self, state=None):
        return {"status": "unsupported",
                "message": "Trae 没有设备授权流程：请用 Desktop 导入，或粘贴 refreshToken"}

    def cancel_login(self, state=None):
        return False

    # -- PAT 导入（Trae 的 PAT 就是 refreshToken）-------------------------
    def import_pat(self, pat, realm=None, name=None, client=None):
        """导入一个 PAT：Trae 里 PAT = refreshToken，内部走 add_from_refresh。

        返回 Account 对象（/accounts/import/pat 直接 .uid / .public()）。
        失败抛 AccountError，消息里带原因（realm 缺失 / 令牌为空 / 上游拒绝）。
        """
        token_in = str(pat or "").strip().strip('"').strip("'")
        if token_in.lower().startswith("bearer "):
            token_in = token_in[7:].strip()
        if not token_in:
            raise AccountError("PAT/refreshToken 不能为空")
        view = self.add_from_refresh(token_in, realm=realm, client=client)
        account = self.get(view.get("uidHash") or view.get("uid") or "")
        if account is None:
            raise AccountError("导入成功但未能定位账号（uidHash=%s）"
                               % view.get("uidHash"))
        if name:
            account.account = dict(account.account or {})
            account.account["username"] = str(name)
            account.save(self.dir)
        return account

    # -- 导入 / 导出 -----------------------------------------------------
    def preview_import_rows(self, rows, realm=None, overwrite=False):
        rows, error = _coerce_account_rows(rows)
        if error:
            return {"error": error, "accounts": []}
        out, errors = [], []
        existing = {a.uid for a in self.accounts}
        for index, row in enumerate(rows, start=1):
            try:
                data = normalise_import_row(row, realm=realm)
                account = Account(data, directory=self.dir)
            except Exception as exc:
                errors.append("#%d: %s" % (index, exc))
                continue
            account.uid = _safe_uid(account.uid)
            preview = account.public()
            preview["action"] = ("update" if account.uid in existing else "add") \
                if overwrite or account.uid not in existing else "skip"
            out.append(preview)
        return {"total": len(rows), "accounts": out, "errors": errors,
                "overwrite": bool(overwrite)}

    def import_rows(self, rows, realm=None, overwrite=False):
        rows, error = _coerce_account_rows(rows)
        if error:
            return {"imported": 0, "updated": 0, "skipped": 0, "errors": [error]}
        imported = updated = skipped = 0
        errors = []
        for index, row in enumerate(rows, start=1):
            try:
                data = normalise_import_row(row, realm=realm)
                account = Account(data, directory=self.dir)
                account.uid = _safe_uid(account.uid)
            except Exception as exc:
                errors.append("#%d: %s" % (index, exc))
                continue
            existing = self.get(account.uid)
            if existing is not None and not overwrite:
                skipped += 1
                continue
            if existing is not None:
                project = ("token", "refresh_token", "expired_at",
                           "refresh_expired_at", "host", "user_region", "account",
                           "disabled_models", "weight", "usage", "entitlement",
                           "usage_updated_at", "extra")
                for field in project:
                    value = getattr(account, field)
                    if value not in (None, "", [], {}):
                        setattr(existing, field, value)
                existing.save(self.dir)
                updated += 1
            else:
                self.add(account)
                imported += 1
        if errors:
            for line in errors[:5]:
                self.log("导入错误 %s" % line, level="WARN")
        return {"imported": imported, "updated": updated,
                "skipped": skipped, "errors": errors}

    def export_document(self, realm=None, include_secrets=True, uids=None):
        return build_export_document(self.by_realm(realm), realm=None,
                                     include_secrets=include_secrets, uids=uids)

    # -- Desktop 导入（CN + INTL）----------------------------------------
    def import_desktop(self, preview_only=True, realms=None, overwrite=False,
                       client=None):
        """读取本机 Desktop 凭证 -> 规整 -> 脱敏预览 / 真正入库。

        preview_only=True（默认）只返回脱敏预览，不写盘 —— 看板必须先展示
        「将导入哪些账号（uid 后 4 位 + realm + 邮箱掩码）」再让用户确认。
        """
        rows, error = scan_desktop_accounts(client=client, realms=realms)
        result = {"found": len(rows), "preview": bool(preview_only),
                  "accounts": [], "errors": [], "error": error}
        if error:
            return result
        staged = []
        for index, row in enumerate(rows, start=1):
            try:
                account = Account.from_desktop(row, directory=self.dir)
                account.uid = _safe_uid(account.uid)
            except Exception as exc:
                result["errors"].append("#%d: %s" % (index, exc))
                continue
            staged.append(account)
        result["accounts"] = [a.public() for a in staged]
        if preview_only:
            return result
        imported = updated = 0
        for account in staged:
            existing = self.get(account.uid)
            if existing is not None:
                if not overwrite:
                    continue
                account.added_at = existing.added_at
                account.usage = existing.usage or account.usage
                account.entitlement = existing.entitlement or account.entitlement
                account.enabled = existing.enabled
                account.weight = existing.weight
                account.disabled_models = existing.disabled_models
                self.accounts[self.accounts.index(existing)] = account
                account.save(self.dir)
                updated += 1
            else:
                self.add(account)
                imported += 1
        result.update({"imported": imported, "updated": updated})
        self.log("Desktop 导入完成：新增 %d，更新 %d（%s）"
                 % (imported, updated, self.dir))
        return result

    # -- 每日限额护栏（token / 模型 token / 临期；credit 类在 Trae 无口径）--
    def apply_settings(self, limits_data=None, free_models=None):
        """保存三级限额（global / intl / cn），线程安全；返回翻转列表（兼容旧签名）。

        limits_data 兼容两种形态：
          A) {key: {"global": n, "intl": n|None, "cn": n|None}}   ← trae_settings
          B) {"global": {key: n}, "cn": {key: n}, "intl": {key: n}}
        具体 scope 优先、缺省回落 global；<=0 = 关闭该护栏。
        """
        normalized = {scope: {} for scope in LIMIT_SCOPES}
        data = limits_data if isinstance(limits_data, dict) else {}
        for key in LIMIT_KEYS:
            entry = data.get(key)
            if isinstance(entry, dict):
                for scope in LIMIT_SCOPES:
                    raw = entry.get(scope)
                    if raw is not None:
                        normalized[scope][key] = _coerce_limit(raw)
            elif entry is not None:
                normalized["global"][key] = _coerce_limit(entry)
        for scope in LIMIT_SCOPES:
            values = data.get(scope)
            if isinstance(values, dict):
                for key, raw in values.items():
                    if key in LIMIT_KEYS:
                        normalized[scope][key] = _coerce_limit(raw)
        with self._limits_lock:
            self.limits = normalized
            if free_models is not None:
                self.free_models = frozenset(str(m) for m in free_models if m)
        return []

    def limit_for(self, key, realm=None):
        """某区域某护栏的生效值：具体 scope > global > 0（关闭）。"""
        realm = str(realm or "").strip().lower()
        with self._limits_lock:
            if realm in REALMS:
                value = self.limits.get(realm, {}).get(key)
                if value is not None:
                    return value
            return self.limits.get("global", {}).get(key, 0)

    def limits_snapshot(self):
        """看板/诊断用：当前三级限额副本。"""
        with self._limits_lock:
            return {scope: dict(values) for scope, values in self.limits.items()}

    def guard(self, account, model=None, realm=None, tokens=0,
              ledger_reader=None):
        """每日限额护栏：返回 (ok, code, message)。

        数据源：usage/usage.jsonl 当天该账号（+模型）token 合计，文件不存在
        视为 0；也可注入 ledger_reader(uid, model) -> int（测试/自定义账本）。
        规则：
          daily_token_limit>0        且 今日+本次 > 上限 -> 拦截
          model_daily_token_limit>0  且 该模型今日+本次 > 上限 -> 拦截
          expiring_window_days>0     且 access token 剩余天数 < N -> 拦截（提示续期）
        daily_credit_limit / reserve_credits 在 Trae 无积分口径，恒 0（关闭）。
        """
        if account is None:
            return True, "", ""
        realm = str(realm or getattr(account, "realm", "") or "").lower()
        uid = str(getattr(account, "uid", "") or "")
        try:
            tokens = max(0, int(tokens or 0))
        except (TypeError, ValueError):
            tokens = 0

        daily = self.limit_for("daily_token_limit", realm)
        model_daily = self.limit_for("model_daily_token_limit", realm)
        window_days = self.limit_for("expiring_window_days", realm)

        if daily > 0:
            used = self._ledger_tokens(uid, None, ledger_reader)
            if used + tokens > daily:
                return False, "daily_token_limit", (
                    "账号 %s 今日 token 已用 %d / 上限 %d（本次 +%d）"
                    % (mask_uid(uid), used, daily, tokens))
        if model_daily > 0 and model:
            used_model = self._ledger_tokens(uid, model, ledger_reader)
            if used_model + tokens > model_daily:
                return False, "model_daily_token_limit", (
                    "账号 %s 今日模型 %s 已用 %d / 上限 %d（本次 +%d）"
                    % (mask_uid(uid), model, used_model, model_daily, tokens))
        if window_days > 0 and getattr(account, "expired_at", 0):
            remaining = (float(account.expired_at) - _now()) / 86400.0
            if remaining < float(window_days):
                return False, "expiring_soon", (
                    "账号 %s 的 access token 仅剩 %.1f 天（阈值 %d 天），请续期"
                    % (mask_uid(uid), max(0.0, remaining), window_days))
        return True, "", ""

    def _ledger_tokens(self, uid, model=None, ledger_reader=None):
        """当日 token 合计：注入 reader > usage.jsonl > 内存日账。"""
        reader = ledger_reader if callable(ledger_reader) else self.ledger_reader
        if callable(reader):
            try:
                return max(0, int(reader(uid, model) or 0))
            except Exception:
                return 0
        day = local_day()
        path = usage_log_path()
        if os.path.isfile(path):
            return self._file_ledger(path, day, uid, model)
        return self._memory_ledger(day, uid, model)

    def _file_ledger(self, path, day, uid, model=None):
        """读 usage.jsonl 求和（按 mtime+size+day 做 5s 缓存，避免每请求扫全文件）。"""
        try:
            st = os.stat(path)
        except OSError:
            return 0
        stamp = (st.st_mtime, st.st_size, day)
        key = (path, day, str(uid), str(model or ""))
        now = _now()
        with self._ledger_lock:
            hit = self._ledger_cache.get(key)
            if hit and hit[0] == stamp and now - hit[1] < LEDGER_CACHE_TTL:
                return hit[2]
        total = 0
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(row, dict) or row.get("error"):
                        continue
                    if _row_day(row) != day:
                        continue
                    recorded = str(row.get("account") or row.get("uid") or "")
                    if recorded and not _uid_matches(uid, recorded):
                        continue
                    if model and str(row.get("model") or "") != str(model):
                        continue
                    try:
                        total += int(float(row.get("total_tokens") or 0))
                    except (TypeError, ValueError):
                        continue
        except OSError:
            return 0
        with self._ledger_lock:
            self._ledger_cache[key] = (stamp, now, total)
            if len(self._ledger_cache) > 256:
                self._ledger_cache.clear()
        return total

    def _memory_ledger(self, day, uid, model=None):
        with self._ledger_lock:
            if model:
                return int(self._mem_usage.get((day, str(uid), str(model)), 0))
            return int(self._mem_usage.get((day, str(uid)), 0))


def _safe_uid(uid):
    """uid 只保留安全字符（落到文件名用）。"""
    value = re.sub(r"[^A-Za-z0-9_-]", "_", str(uid or "")).strip("_ ")
    return value or ("acct-" + hashlib.sha256(str(uid).encode()).hexdigest()[:16])


# ---------------------------------------------------------------------------
# 导入 / 导出文档
# ---------------------------------------------------------------------------
EXPORT_FORMAT = "trae-accounts"
EXPORT_VERSION = 1
_RUNTIME_FIELDS = ("path", "model_cooldowns", "inflight")


def account_to_export(account):
    data = account.to_dict()
    for field in _RUNTIME_FIELDS:
        data.pop(field, None)
    return data


def build_export_document(accounts, realm=None, include_secrets=True, uids=None):
    wanted = {str(u) for u in uids} if uids is not None else None
    rows = []
    for account in accounts:
        if realm and account.realm != realm:
            continue
        if wanted is not None and account.uid not in wanted \
                and uid_digest(account.uid) not in wanted:
            continue
        row = account_to_export(account)
        if not include_secrets:
            row.pop("token", None)
            row.pop("refresh_token", None)
        rows.append(row)
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exportedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(rows),
        "accounts": rows,
    }


def _coerce_account_rows(blob):
    """把任意受支持的容器规整成账号 dict 列表。返回 (rows, error)。"""
    if isinstance(blob, list):
        rows = blob
    elif isinstance(blob, dict) and isinstance(blob.get("accounts"), list):
        rows = blob["accounts"]
    elif isinstance(blob, dict):
        looks_like_account = (blob.get("token") or blob.get("accessToken")
                              or blob.get("refreshToken")
                              or isinstance(blob.get("account"), dict))
        if not looks_like_account:
            keys = ", ".join(sorted(blob.keys())[:6]) or "none"
            return [], ("不是账号文档（期望 accounts 数组 / 列表 / 单个账号对象；"
                        "实际键：%s）" % keys)
        rows = [blob]
    else:
        return [], "期望对象或账号列表"
    out = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            return [], "#%d 不是对象" % (index + 1)
        out.append(row)
    if not out:
        return [], "文档中没有账号"
    return out, ""


def _import_proxy(row):
    """导入行里的出口代理（非法值按直连处理，不让整行导入失败）。"""
    try:
        return normalize_proxy(row.get("proxy") or row.get("egress"))
    except ValueError:
        return ""


def normalise_import_row(row, realm=None):
    """导入行 -> Account 构造用 dict（白名单，运行期状态一律重置）。"""
    if not isinstance(row, dict):
        raise ValueError("账号行不是对象")
    token = str(_first_present(row, "token", "accessToken", "access_token",
                               default="") or "").strip()
    if not token:
        raise ValueError("缺少 token")
    profile = row.get("account") if isinstance(row.get("account"), dict) else {}
    user_region = row.get("user_region") or row.get("userRegion") or {}
    if not isinstance(user_region, dict):
        user_region = {"region": str(user_region)}
    host = str(_first_present(row, "host", "domain", default="") or "")
    detected = str(realm or row.get("realm") or "").strip().lower()
    if detected not in REALMS:
        detected = detect_realm(host=host, user_region=user_region,
                                store_region=str(profile.get("storeRegion") or ""))
    cfg = get_realm_config(detected)
    uid = str(_first_present(row, "uid", "userId", "user_id", default="") or "").strip()
    if not uid:
        uid = "import-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:20]
    expired_at = normalize_epoch(_first_present(row, "expired_at", "expiredAt",
                                               "expire_time"))
    if not expired_at:
        expired_at = int(_now()) + 3600
    disabled = row.get("disabled_models", row.get("disabledModels")) or []
    try:
        weight = float(row.get("weight", 1.0) or 1.0)
    except (TypeError, ValueError):
        weight = 1.0
    return {
        "uid": uid,
        "realm": detected,
        "token": token,
        "refresh_token": str(_first_present(row, "refresh_token", "refreshToken",
                                            default="") or ""),
        "expired_at": expired_at,
        "refresh_expired_at": normalize_epoch(_first_present(
            row, "refresh_expired_at", "refreshExpiredAt", "refreshExpireAt")),
        "host": host or cfg["account"],
        "user_region": dict(user_region) or {"region": cfg["region"],
                                             "_aiRegion": cfg["ai_region"]},
        "account": dict(profile),
        "enabled": _truthy(row.get("enabled"), True),
        "proxy": _import_proxy(row),
        "disabled_models": [str(m) for m in disabled if str(m).strip()],
        "weight": weight if weight > 0 else 1.0,
        "source": str(row.get("source") or "import"),
        "usage": row.get("usage") if isinstance(row.get("usage"), dict) else None,
        "entitlement": (row.get("entitlement")
                        if isinstance(row.get("entitlement"), dict) else None),
        "extra": row.get("extra") if isinstance(row.get("extra"), dict) else {},
    }


# ---------------------------------------------------------------------------
# 模块级便捷入口
# ---------------------------------------------------------------------------
def add_to_pool(account):
    """写入当前活动账号池（AccountPool 构造时自注册）。"""
    if _ACTIVE_POOL is None:
        raise AccountError("账号池未初始化（先构造 AccountPool）")
    return _ACTIVE_POOL.add(account)


def get_pool():
    return _ACTIVE_POOL


def import_desktop_credential(path=None, realm=None, client=None):
    """兼容入口：导入本机 Desktop 凭证（path 参数保留但由 trae_client 决定）。"""
    if _ACTIVE_POOL is None:
        raise AccountError("账号池未初始化（先构造 AccountPool）")
    result = _ACTIVE_POOL.import_desktop(preview_only=False,
                                        realms=[realm] if realm else None,
                                        overwrite=True, client=client)
    if result.get("error"):
        raise AccountError(result["error"])
    return result


def add_from_refresh(refresh_token, realm=None, uid=None, proxy=None,
                     overwrite=False, client=None):
    """模块级入口：把粘贴的 refreshToken 导入当前活动账号池（没有池则新建并装载）。"""
    pool = _ACTIVE_POOL
    if pool is None:
        pool = AccountPool()
        pool.load()
    return pool.add_from_refresh(refresh_token, realm=realm, uid=uid,
                                 proxy=proxy, overwrite=overwrite, client=client)


def scan_desktop_credentials(client=None):
    """兼容入口：脱敏预览本机双区凭证（不写盘）。"""
    pool = _ACTIVE_POOL or AccountPool()
    return pool.import_desktop(preview_only=True, client=client).get("accounts", [])


# ---------------------------------------------------------------------------
# 自检 CLI
# ---------------------------------------------------------------------------
def _main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Trae 账号池自检（只输出脱敏信息）")
    parser.add_argument("--dir", default="", help="账号目录（默认 ACCOUNTS_DIR / ./accounts）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    pool = AccountPool(args.dir or accounts_dir())
    pool.load()
    data = {"summary": pool.summary(),
            "accounts": pool.list_public(),
            "client": client_status()}
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    summary = data["summary"]
    print("账号目录：%s" % summary["dir"])
    print("账号总数：%d（并发上限 %s/号）" % (summary["total"], summary["maxInflight"]))
    for realm, bucket in sorted(summary["realms"].items()):
        print("  %-4s 共 %d，可用 %d，状态 %s"
              % (realm, bucket["total"], bucket["ready"], bucket["families"]))
    for row in data["accounts"]:
        print("  uid=%s realm=%s host=%s enabled=%s status=%s expires=%s"
              % (row["uid"], row["realm"], row["host"], row["enabled"],
                 row["status"], row["expiresIn"]))
    client = data["client"]
    print("trae_client：%s%s" % ("可用" if client["available"] else "不可用",
                                 "" if client["available"] else "（%s）" % client["error"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
