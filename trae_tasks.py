# -*- coding: utf-8 -*-
"""trae_tasks.py —— Trae 维护任务引擎（Token 保活 / 权益用量 / 模型目录 / 到期提醒）

Trae 没有 Qoder 那种「每日签到领积分」的任务体系，原骨架里的签到/活动领取逻辑
在本仓库已不适用。本模块改为**官方真实能力**的运维任务引擎，只做四件事：

  1. token_keepalive  access token 到期前 24 小时用 ExchangeToken 轮换刷新
  2. usage_refresh    权益 / 用量快照（优先 trae_client.fetch_usage /
                      fetch_entitlement；模块未就绪时回退 trae_accounts 账本）
  3. catalog_refresh  模型目录刷新（优先 trae_client.fetch_model_list，并核对
                      trae_catalog 的双区快照）
  4. expiry_reminder  access / refresh token、权益包、会话状态的到期提醒

所有任务结果原子落盘到 <usage>/tasks.json（**不写任何 token 值**），供看板、
调度器与 _diag_campaign.py 读取；手动触发与历史查询都由 run_task / run_all_tasks
统一入口完成。

兼容层（网关现有路由仍在调用，签名与返回键保持不变）：
  fetch_tasks_view(pool, realm=None, uid=None)
  fetch_task_view(account)
  run_batch_checkin(targets, gap=1.0, inter_gap=1.5)
  run_batch_pro_claim(targets, gap=1.0, inter_gap=1.5)
  run_checkin(account, gap=1.0, only_daily=False, claim_gap=None)
  run_keepalive(pool, force=False, threshold_seconds=24*3600)
  invalidate_panel_cache(uid=None) / set_logger(fn)
"""
import inspect
import json
import os
import re
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))

try:                                    # 账号层是运行期依赖；缺失也不影响 import
    import trae_accounts
except Exception:                       # pragma: no cover - 防御半成品仓库
    trae_accounts = None

# ---------------------------------------------------------------------------
# 常量与落盘位置
# ---------------------------------------------------------------------------
DEFAULT_KEEPALIVE_THRESHOLD = 24 * 3600      # 到期前 24 小时保活（需求口径）
STATE_VERSION = 2
TASKS_FILE_NAME = "tasks.json"
HISTORY_LIMIT = 200
PANEL_CACHE_TTL = 20                          # 兼容旧接口；新实现不做上游缓存
DEFAULT_USAGE_DIR = os.path.join(HERE, "usage")

TASK_ORDER = ("daily_checkin", "token_keepalive", "usage_refresh",
              "catalog_refresh", "model_probe", "expiry_reminder")
TASK_DEFS = (
    {"code": "daily_checkin", "name": "每日签到",
     "desc": "国内版每日签到领取积分（/trae/api/v2/ug/checkin_credits/*）；国际版无此接口"},
    {"code": "token_keepalive", "name": "Token 保活刷新",
     "desc": "access token 到期前 24 小时轮换刷新（ExchangeToken，refreshToken 同步回写）"},
    {"code": "usage_refresh", "name": "权益 / 用量刷新",
     "desc": "拉取账号权益包与会话用量（trae_client.fetch_usage / fetch_entitlement）"},
    {"code": "catalog_refresh", "name": "模型目录刷新",
     "desc": "刷新双区模型清单，并核对 trae_catalog 本地快照"},
    {"code": "model_probe", "name": "模型自动探测",
     "desc": "用最小请求验证模型真实可用性（6h 内成功结果跳过，单轮最多 6 个）"},
    {"code": "expiry_reminder", "name": "凭证到期提醒",
     "desc": "检查 access / refresh token、权益包与会话状态，输出到期风险"},
)
TASK_NAMES = {d["code"]: d["name"] for d in TASK_DEFS}

_log = lambda msg: None
_panel_cache = {}
_panel_lock = threading.Lock()
_STATE_LOCK = threading.RLock()
_TOKENISH_RE = re.compile(r"[A-Za-z0-9_\-]{32,}")


def set_logger(fn):
    """把任务诊断路由到调用方的日志器（端点吞错时依然可见）。"""
    global _log
    _log = fn or (lambda msg: None)


def invalidate_panel_cache(uid=None):
    """兼容旧接口：新实现的任务视图直接读 tasks.json，无上游短缓存。"""
    with _panel_lock:
        if uid:
            for key in [k for k in _panel_cache if k[0] == uid]:
                _panel_cache.pop(key, None)
        else:
            _panel_cache.clear()


def usage_dir():
    """用量目录：TRAE_PROXY_USAGE_DIR > USAGE_DIR > 已加载网关的 USAGE_DIR > 仓库/usage。"""
    value = (os.environ.get("TRAE_PROXY_USAGE_DIR")
             or os.environ.get("USAGE_DIR"))
    if value:
        return value
    # 网关用 --usage-dir 启动时只改模块全局；这里跟随它，避免两处状态分叉
    proxy = sys.modules.get("trae_proxy")
    if proxy is not None:
        proxy_dir = getattr(proxy, "USAGE_DIR", None)
        if proxy_dir:
            return str(proxy_dir)
    return DEFAULT_USAGE_DIR


def tasks_file_path():
    return os.path.join(usage_dir(), TASKS_FILE_NAME)


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _iso(ts=None):
    return time.strftime("%Y-%m-%d %H:%M:%S",
                         time.localtime(time.time() if ts is None else ts))


def _fmt_eta(seconds):
    """剩余寿命的人话表达；负数=已过期。"""
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "未知"
    if seconds <= 0:
        return "已过期"
    if seconds >= 86400:
        return "%.1f 天" % (seconds / 86400)
    if seconds >= 3600:
        return "%.1f 小时" % (seconds / 3600)
    return "%d 分钟" % int(seconds / 60)


def _scrub(text, limit=400):
    """日志/状态脱敏：把疑似 token 的长串替换成长度标记。"""
    if text is None:
        return ""
    text = str(text)
    text = _TOKENISH_RE.sub(lambda m: "<脱敏:%d>" % len(m.group(0)), text)
    return text[:limit]


def _jsonable(obj):
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    return _scrub(obj, 200)


def _normalize_epoch(value):
    """epoch 秒/毫秒/ISO 字符串统一成秒；无法解析返回 0。"""
    if not value:
        return 0
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        val = float(value)
        return val / 1000.0 if val > 1e11 else val
    text = str(value).strip()
    try:
        return _normalize_epoch(float(text))
    except (TypeError, ValueError):
        pass
    try:
        from datetime import datetime, timezone
        iso = text[:-1] + "+00:00" if text.endswith("Z") else text
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0


def _uid_of(account):
    return str(getattr(account, "uid", "") or "")


def _name_of(account):
    """展示名：nickname → 账号资料里的 username/email（脱敏）→ uid 前 8 位。"""
    uid = _uid_of(account)
    name = str(getattr(account, "nickname", "") or "").strip()
    if name:
        return name
    profile = getattr(account, "account", None)
    if isinstance(profile, dict):
        value = str(profile.get("username") or profile.get("email") or "").strip()
        if value:
            masker = getattr(trae_accounts, "mask_name", None)
            if callable(masker):
                try:
                    masked = str(masker(value) or "").strip()
                    if masked:
                        return masked
                except Exception:
                    pass
            return value[:2] + "***"
    return uid[:8] or "?"


# 账号层有两代形状：旧 Qoder 骨架（access_token/expires_at/credits）与
# 新 Trae 账号层（token/expired_at/refresh_expired_at/usage/entitlement）。
# 所有任务只通过这些访问器取字段，两种形状都能跑。
def _access_token(account):
    return str(getattr(account, "access_token", None)
               or getattr(account, "token", "") or "")


def _refresh_token(account):
    return str(getattr(account, "refresh_token", "") or "")


def _expires_at(account):
    return float(getattr(account, "expires_at", 0)
                 or getattr(account, "expired_at", 0) or 0)


def _refresh_expires_at(account):
    return float(getattr(account, "refresh_expired_at", 0)
                 or getattr(account, "refresh_expires_at", 0) or 0)


def _plan_of(account):
    """套餐名：新账号层从 entitlement / account profile 里取。"""
    plan = getattr(account, "plan", "") or ""
    if plan:
        return str(plan)
    for source in (getattr(account, "entitlement", None),
                   getattr(account, "usage", None)):
        if isinstance(source, dict):
            value = _first_value([source], {"plan", "planname", "productname",
                                            "tier", "subscription"})
            if isinstance(value, (str, int, float)) and str(value):
                return str(value)
    entitlement = getattr(account, "entitlement", None)
    if isinstance(entitlement, dict) and entitlement:
        digest = _digest_entitlement(entitlement, "account.entitlement")
        if digest.get("plan"):
            return str(digest["plan"])
    profile = getattr(account, "account", None)
    if isinstance(profile, dict):
        for key in ("plan", "planName", "productName"):
            if profile.get(key):
                return str(profile[key])
    return ""


def _do_refresh(account):
    """调用账号层刷新，兼容旧 bool 返回与新脱敏摘要 dict。

    新账号层 refresh(force=True) 会无条件轮换（我们已在外层按 24h 阈值判定）；
    旧账号层 refresh() 没有 force 参数，按原样调用。
    """
    refresh = getattr(account, "refresh", None)
    if not callable(refresh):
        raise RuntimeError("账号缺少 refresh() 方法")
    try:
        signature = inspect.signature(refresh)
        result = refresh(force=True) if "force" in signature.parameters else refresh()
    except (TypeError, ValueError):
        result = refresh()
    if isinstance(result, dict):
        if result.get("skipped"):
            return {"ok": True, "skipped": True,
                    "detail": str(result.get("reason") or "未到刷新窗口")}
        return {"ok": True, "skipped": False, "detail": "已刷新"}
    return {"ok": bool(result), "skipped": False,
            "detail": "已刷新" if result else "刷新失败"}


def _iter_accounts(pool=None, accounts=None, realm=None, include_disabled=False):
    """统一账号遍历：显式 accounts 优先，其次 pool.accounts。"""
    if accounts is not None:
        source = list(accounts)
    elif pool is not None:
        source = list(getattr(pool, "accounts", []) or [])
    else:
        source = []
    for account in source:
        if account is None:
            continue
        if realm and getattr(account, "realm", None) != realm:
            continue
        if not include_disabled and not bool(getattr(account, "enabled", True)):
            continue
        yield account


def _effective_remain(credits):
    """余额口径与 trae_accounts.effective_remain 保持一致（缺失时本地兜底）。"""
    if not isinstance(credits, dict):
        return 0
    fn = getattr(trae_accounts, "effective_remain", None)
    if callable(fn):
        try:
            return int(fn(credits) or 0)
        except Exception:
            pass
    for key in ("remain", "remaining", "balance"):
        if credits.get(key) is not None:
            try:
                return int(credits[key])
            except (TypeError, ValueError):
                pass
    total = 0
    for pkg in credits.get("packages") or []:
        if isinstance(pkg, dict):
            try:
                total += int(pkg.get("remain") or 0)
            except (TypeError, ValueError):
                pass
    return total


LEDGER_NEVER_EPOCH = 253402214400


def ledger_is_unknown(credits):
    """True = 账本是「未知」而非「0」（上游退化响应，不能当 0 参与计算）。"""
    if not isinstance(credits, dict):
        return False
    if _effective_remain(credits) or credits.get("size"):
        return False
    if not credits.get("exceeded"):
        return False
    try:
        return int(credits.get("expires_at") or 0) >= LEDGER_NEVER_EPOCH
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# 状态落盘（usage/tasks.json）
# ---------------------------------------------------------------------------
def _empty_state():
    return {
        "version": STATE_VERSION,
        "updated_at": "",
        "updated_ts": 0,
        "tasks": {},
        "history": [],
        "accounts": {},
        "reminders": {"updated_at": "", "items": [], "accounts": {}},
        "last_cycle": {},
    }


def _read_state_file():
    path = tasks_file_path()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    state = _empty_state()
    state.update(data if isinstance(data, dict) else {})
    for key in ("tasks", "accounts"):
        if not isinstance(state.get(key), dict):
            state[key] = {}
    if not isinstance(state.get("history"), list):
        state["history"] = []
    if not isinstance(state.get("reminders"), dict):
        state["reminders"] = {"updated_at": "", "items": [], "accounts": {}}
    return state


def load_state():
    with _STATE_LOCK:
        return _read_state_file()


def _write_state_locked(state):
    path = tasks_file_path()
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_jsonable(state), fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return True
    except Exception as exc:
        try:
            sys.stderr.write("[tasks] 状态落盘失败: %s\n" % exc)
            sys.stderr.flush()
        except Exception:
            pass
        return False


def _mutate_state(fn):
    """读-改-写（进程内 RLock + 原子替换）。fn 不得再次调用 _mutate_state。"""
    with _STATE_LOCK:
        state = _read_state_file()
        fn(state)
        state["version"] = STATE_VERSION
        state["updated_ts"] = int(time.time())
        state["updated_at"] = _iso()
        _write_state_locked(state)
        return state


def _record_run(code, ok, started_at, finished_at, trigger, summary,
                stats=None, logs=None, error=""):
    """把一次任务执行写入 tasks[code] 与 history。"""
    duration_ms = int(max(0.0, finished_at - started_at) * 1000)
    record = {
        "code": code,
        "name": TASK_NAMES.get(code, code),
        "ok": bool(ok),
        "last_run": _iso(finished_at),
        "last_ts": int(finished_at),
        "duration_ms": duration_ms,
        "trigger": trigger or "manual",
        "summary": _scrub(summary or "", 400),
        "error": _scrub(error or "", 300),
        "stats": _jsonable(stats or {}),
        "logs": [_scrub(x, 300) for x in (logs or [])][-40:],
        "runs": 0,
    }

    def mutate(state):
        tasks = state.setdefault("tasks", {})
        old = tasks.get(code) or {}
        record["runs"] = int(old.get("runs") or 0) + 1
        tasks[code] = record
        history = state.setdefault("history", [])
        history.append({
            "run_id": "%s-%d" % (code, int(started_at)),
            "task": code,
            "name": record["name"],
            "ok": record["ok"],
            "trigger": record["trigger"],
            "started_at": _iso(started_at),
            "finished_at": record["last_run"],
            "duration_ms": duration_ms,
            "summary": record["summary"],
            "error": record["error"],
            "stats": record["stats"],
        })
        del history[:-HISTORY_LIMIT]

    _mutate_state(mutate)
    return record


# ---------------------------------------------------------------------------
# 账号快照（脱敏）
# ---------------------------------------------------------------------------
def _account_meta(account):
    """到期元数据；**不复制任何 token 字段**。兼容新旧账号文件字段名。"""
    meta = {
        "file": "",
        "refresh_expires_at": int(_refresh_expires_at(account)),
        "token_release_at": int(getattr(account, "token_release_at", 0) or 0),
        "store_region": "",
        "user_type": "",
    }
    profile = getattr(account, "account", None)
    if isinstance(profile, dict):
        meta["store_region"] = str(profile.get("storeRegion") or "")
        meta["user_type"] = str(profile.get("userType") or "")
    path = getattr(account, "path", None)
    if not path or not os.path.isfile(path):
        return meta
    meta["file"] = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return meta
    if not isinstance(raw, dict):
        return meta
    if not meta["refresh_expires_at"]:
        for key in ("refresh_expired_at", "refreshExpiresAt",
                    "refreshExpireAt", "refresh_expires_at"):
            if raw.get(key):
                meta["refresh_expires_at"] = int(_normalize_epoch(raw.get(key)) or 0)
                break
    if not meta["token_release_at"]:
        for key in ("token_release_at", "tokenReleaseAt"):
            if raw.get(key):
                meta["token_release_at"] = int(_normalize_epoch(raw.get(key)) or 0)
                break
    region = (raw.get("storeRegion")
              or (raw.get("account") or {}).get("storeRegion"))
    meta["store_region"] = meta["store_region"] or str(region or "")
    meta["user_type"] = meta["user_type"] or str(raw.get("userType") or "")
    return meta


def _benefits_from(source):
    """从 entitlement / usage / credits 里提取权益包列表。"""
    if not isinstance(source, dict):
        return []
    raw = _first_value([source], {"benefits", "packages", "entitlements",
                                  "items", "quotas", "benefitlist"})
    items = []
    if isinstance(raw, list):
        for item in raw[:12]:
            normalized = _normalize_benefit(item)
            if normalized:
                items.append(normalized)
    elif isinstance(raw, dict):
        for key, item in list(raw.items())[:12]:
            if isinstance(item, dict):
                normalized = _normalize_benefit(item)
                if normalized:
                    normalized["name"] = normalized["name"] or str(key)[:80]
                    items.append(normalized)
    return items


def _credits_from_ledger(credits):
    packages = []
    for pkg in (credits.get("packages") or [])[:8]:
        if not isinstance(pkg, dict):
            continue
        packages.append({
            "name": str(pkg.get("name") or pkg.get("title") or ""),
            "remain": _as_int(pkg.get("remain")),
            "size": _as_int(pkg.get("size") or pkg.get("total")),
            "expires_at": int(_normalize_epoch(
                pkg.get("expires_at") or pkg.get("expireAt")
                or pkg.get("expiresAt")) or 0),
        })
    return {
        "ok": True,
        "quota_known": True,
        "remain": _effective_remain(credits),
        "size": _as_int(credits.get("size")),
        "exceeded": bool(credits.get("exceeded")),
        "unknown": ledger_is_unknown(credits),
        "expires_at": int(_normalize_epoch(
            credits.get("expires_at") or credits.get("expiresAt")) or 0),
        "updated_at": str(credits.get("updated_iso")
                          or credits.get("updated_at") or ""),
        "packages": packages,
        "source": "credits",
    }


def _credits_from_entitlement(source, account):
    """把 entitlement 快照压成额度视图（新 Trae 账号层）。"""
    digest = _digest_entitlement(source, "account.entitlement")
    if not digest.get("ok"):
        return None
    updated = int(getattr(account, "usage_updated_at", 0) or 0)
    remain = int(digest.get("remain") or 0)
    total = int(digest.get("total") or 0)
    return {
        "ok": True,
        # 真实 pay 结构没有「余额」字段：不要把缺失当 0 展示/累加
        "quota_known": bool(remain or total),
        "remain": remain,
        "size": total,
        "exceeded": bool(digest.get("exceeded")),
        "unknown": False,
        "expires_at": int(digest.get("expires_at") or 0),
        "updated_at": _iso(updated) if updated else "",
        "packages": digest.get("benefits") or [],
        "source": "account.entitlement",
        "plan": digest.get("plan") or "",
        "trial": digest.get("trial") or {},
    }


def _credits_digest(account):
    """额度摘要：新 Trae 账号优先 entitlement / usage；旧骨架回退 credits。"""
    for name in ("entitlement", "usage"):
        source = getattr(account, name, None)
        if not isinstance(source, dict) or not source:
            continue
        if name == "entitlement":
            summary = _credits_from_entitlement(source, account)
            if summary is not None:
                return summary
        remain_raw = _first_value([source], ("remain", "remaining", "balance",
                                             "credits", "credit",
                                             "quota_remain", "left"))
        total_raw = _first_value([source], ("total", "size", "quota",
                                            "total_quota", "limit"))
        if remain_raw is None and total_raw is None:
            continue
        updated = int(getattr(account, "usage_updated_at", 0) or 0)
        return {
            "ok": True,
            "quota_known": True,
            "remain": _as_int(remain_raw),
            "size": _as_int(total_raw),
            "exceeded": _find_bool(source, {"exceeded", "isquotaexceeded",
                                            "overlimit"}),
            "unknown": False,
            "expires_at": int(_normalize_epoch(_first_value(
                [source], ("expiresat", "expireat", "expiredat",
                           "endtime", "enddate"))) or 0),
            "updated_at": _iso(updated) if updated else "",
            "packages": _benefits_from(source),
            "source": "account.%s" % name,
        }
    credits = getattr(account, "credits", None)
    if isinstance(credits, dict) and credits:
        # 新账号的 credits property 是 entitlement 的别名；按权益解析
        if "ent_usage" in credits or "pay_status" in credits:
            summary = _credits_from_entitlement(credits, account)
            if summary is not None:
                return summary
            return {"ok": False, "quota_known": False,
                    "reason": "权益接口失败，暂无可用额度快照"}
        return _credits_from_ledger(credits)
    return {"ok": False, "quota_known": False,
            "reason": "账号尚无额度/权益快照"}


def _as_int(value):
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return 0


def _account_brief(account, snapshot=None):
    snapshot = snapshot or {}
    now = time.time()
    expires = _expires_at(account)
    refresh_expires = _refresh_expires_at(account)
    credits = snapshot.get("credits") or _credits_digest(account)
    usage = snapshot.get("usage") or None
    if not usage:
        stored_usage = getattr(account, "usage", None)
        if isinstance(stored_usage, dict) and stored_usage:
            usage = _digest_usage(stored_usage, "account.usage")
    entitlement = snapshot.get("entitlement") or None
    if not entitlement:
        stored_ent = getattr(account, "entitlement", None)
        if isinstance(stored_ent, dict) and stored_ent:
            entitlement = _digest_entitlement(stored_ent, "account.entitlement")
    brief = {
        "uid": _uid_of(account),
        "nickname": _name_of(account),
        "realm": str(getattr(account, "realm", "") or ""),
        "enabled": bool(getattr(account, "enabled", True)),
        "plan": str(_plan_of(account) or ""),
        "hasToken": bool(_access_token(account)),
        "hasRefreshToken": bool(_refresh_token(account)),
        "tokenExpiresAt": int(expires) if expires else 0,
        "tokenExpiresIn": int(expires - now) if expires else None,
        "tokenExpiresInText": _fmt_eta(expires - now) if expires else "未知",
        "refreshExpiresAt": int(refresh_expires) if refresh_expires else 0,
        "refreshExpiresIn": (int(refresh_expires - now)
                             if refresh_expires else None),
        "refreshExpiresInText": (_fmt_eta(refresh_expires - now)
                                 if refresh_expires else "未知"),
        "lastError": _scrub(getattr(account, "last_error", "") or "", 200),
        "credits": credits,
        "usage": usage,
        "entitlement": entitlement,
        "alerts": snapshot.get("alerts") or [],
        "lastRefreshAt": snapshot.get("updated_at") or "",
    }
    if not brief["alerts"]:
        brief["alerts"] = _collect_alerts(account, snapshot)
    return brief


# ---------------------------------------------------------------------------
# 上游取数（trae_client 优先，trae_accounts 兜底）
# ---------------------------------------------------------------------------
def _client_module():
    try:
        import trae_client
        return trae_client
    except Exception:
        return None


def _catalog_module():
    try:
        import trae_catalog
        return trae_catalog
    except Exception:
        return None


def _call_with_account(fn, account):
    """按 trae_client 的协议签名 fetch_usage(account, realm) 调用，兼容旧签名。"""
    realm = str(getattr(account, "realm", "cn") or "cn")
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(account, realm)
    positional = [p for p in sig.parameters.values()
                  if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    if len(positional) >= 2:
        return fn(account, realm)
    if len(positional) == 1:
        return fn(account)
    return fn()


def _norm_key(key):
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _find_key(obj, names, depth=3):
    """递归找第一个键名（归一化后）匹配的值；names 为归一化键集合。"""
    if depth < 0 or obj is None:
        return None
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _norm_key(key) in names:
                return value
        for value in obj.values():
            found = _find_key(value, names, depth - 1)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for value in obj[:20]:
            found = _find_key(value, names, depth - 1)
            if found is not None:
                return found
    return None


def _find_number(obj, names):
    return _as_int(_find_key(obj, names))


def _find_bool(obj, names):
    value = _find_key(obj, names)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y")
    return bool(value) if value is not None else False


def _flatten_numbers(obj, prefix="", out=None, depth=0):
    if out is None:
        out = {}
    if depth > 3 or len(out) >= 60:
        return out
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = ("%s.%s" % (prefix, key)).strip(".")
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                out[path] = value
            elif isinstance(value, (dict, list)):
                _flatten_numbers(value, path, out, depth + 1)
    elif isinstance(obj, list):
        for index, value in enumerate(obj[:20]):
            path = "%s[%d]" % (prefix, index) if prefix else "[%d]" % index
            _flatten_numbers(value, path, out, depth + 1)
    return out


def _pick_number(numbers, aliases):
    wanted = {_norm_key(a) for a in aliases}
    for path, value in numbers.items():
        leaf = _norm_key(re.split(r"[.\[]", path)[-1].rstrip("]"))
        if leaf in wanted:
            return int(value) if isinstance(value, (int, float)) else _as_int(value)
    return 0


def _digest_usage(payload, source=""):
    if not isinstance(payload, (dict, list)):
        return {"ok": False, "source": source,
                "error": "上游返回结构不是 JSON 对象"}
    if isinstance(payload, dict) and payload.get("ok") is False:
        return {"ok": False, "source": source,
                "error": _scrub(payload.get("error") or "上游返回 ok=false", 200)}
    numbers = _flatten_numbers(payload)
    usage = {
        "ok": True,
        "kind": "tokens",
        "source": source,
        "input_tokens": _pick_number(numbers, (
            "input_tokens", "prompt_tokens", "inputtokens", "prompttokens",
            "input_token", "inputtoken")),
        "output_tokens": _pick_number(numbers, (
            "output_tokens", "completion_tokens", "outputtokens",
            "completiontokens", "output_token", "outputtoken")),
        "total_tokens": _pick_number(numbers, (
            "total_tokens", "totaltokens", "tokens", "total_token",
            "totaltoken")),
        "cache_read_tokens": _pick_number(numbers, (
            "cache_read_input_tokens", "cachereadinputtokens",
            "cache_read_tokens", "cached_tokens", "cachedtokens",
            "cache_read_token", "cachereadtoken")),
        "cache_write_tokens": _pick_number(numbers, (
            "cache_creation_input_tokens", "cachecreationinputtokens",
            "cache_write_tokens", "cachewritetokens",
            "cache_write_token", "cachewritetoken")),
        "requests": _pick_number(numbers, ("request_count", "requestcount",
                                           "requests", "call_count",
                                           "callcount")),
        "remaining": _pick_number(numbers, ("remaining", "remain",
                                             "quota_remain", "quota_remaining",
                                             "balance", "left")),
        "used": _pick_number(numbers, ("used", "usage", "consumed",
                                       "quota_used", "amount_float",
                                       "amountfloat", "amount")),
        "limit": _pick_number(numbers, ("limit", "quota", "total_quota",
                                        "totalquota", "size")),
        "fields": sorted({re.split(r"[.\[]", p)[-1].rstrip("]")
                          for p in numbers})[:30],
        "numbers": dict(list(numbers.items())[:40]),
    }
    if not usage["total_tokens"]:
        usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    return usage


def _normalize_benefit(item):
    """兼容两种权益包形状：

    · 通用扁平结构（name/remain/total/expires_at）；
    · Trae 真实 pay 结构：display_desc + entitlement_base_info.quota/end_time。
      真实结构没有「剩余」字段，remain 记 0（不代表 0 余额，仅表示未提供），
      quota 原样带出供看板展示。
    """
    if not isinstance(item, dict):
        return None
    base = item.get("entitlement_base_info")
    if not isinstance(base, dict):
        base = {}
    quota = item.get("quota")
    if not isinstance(quota, dict):
        quota = base.get("quota") if isinstance(base.get("quota"), dict) else {}
    name = (item.get("display_desc") or item.get("name") or item.get("title")
            or item.get("productName") or item.get("packageName")
            or item.get("description") or "")
    total_raw = item.get("total") or item.get("size")
    if not isinstance(item.get("quota"), dict):
        total_raw = total_raw or item.get("quota")
    benefit = {
        "name": str(name)[:80],
        "remain": _as_int(item.get("remain") or item.get("remaining")
                          or item.get("balance")),
        "total": _as_int(total_raw),
        "expires_at": int(_normalize_epoch(
            item.get("expire_time") or item.get("expireTime")
            or item.get("end_time") or item.get("endTime")
            or item.get("expires_at") or item.get("expireAt")
            or item.get("expiresAt") or base.get("end_time")) or 0),
        "status": str(item.get("ent_status", item.get("status")
                              or item.get("state") or ""))[:40],
    }
    if quota:
        benefit["quota"] = {str(key): value
                            for key, value in list(quota.items())[:12]
                            if isinstance(value, (bool, int, float, str))}
        if not benefit["total"]:
            benefit["total"] = _as_int(
                quota.get("advanced_model_request_limit")
                or quota.get("premium_model_fast_request_limit")
                or quota.get("basic_usage_limit"))
    return benefit


def _errors_summary(errors):
    """把 trae_client.fetch_entitlement 的 errors 列表压缩成一句中文。"""
    parts = []
    if isinstance(errors, list):
        for item in errors[:4]:
            if isinstance(item, dict):
                parts.append("%s: %s"
                             % (item.get("endpoint") or item.get("code") or "?",
                                _scrub(item.get("message") or "", 120)))
            else:
                parts.append(_scrub(item, 120))
    elif errors:
        parts.append(_scrub(errors, 120))
    return "；".join([p for p in parts if p])


def _first_value(roots, names):
    for root in roots:
        if root is None:
            continue
        value = _find_key(root, names)
        if value not in (None, "", [], {}):
            return value
    return None


def _first_number(roots, names):
    for root in roots:
        if root is None:
            continue
        value = _find_number(root, names)
        if value:
            return value
    return 0


def _digest_entitlement(payload, source=""):
    """归一化权益 payload。

    兼容两种形状：
      · trae_client.fetch_entitlement 的封装 {realm, ent_usage, pay_status, errors}
      · 上游原始 JSON（含 plan/remain/expiresAt/benefits 等字段）
    两个 pay 接口都失败时返回 ok=False，供调用方回退账号层账本。
    """
    if not isinstance(payload, (dict, list)):
        return {"ok": False, "source": source,
                "error": "上游返回结构不是 JSON 对象"}
    if isinstance(payload, dict) and payload.get("ok") is False:
        return {"ok": False, "source": source,
                "error": _scrub(payload.get("error") or "上游返回 ok=false", 200)}
    errors = payload.get("errors") if isinstance(payload, dict) else None
    ent_usage = pay_status = None
    if isinstance(payload, dict):
        ent_usage = payload.get("ent_usage", payload.get("entUsage"))
        pay_status = payload.get("pay_status", payload.get("payStatus"))
    if ent_usage is None and pay_status is None and errors:
        summary = _errors_summary(errors) or "权益接口全部失败"
        return {"ok": False, "source": source, "error": summary,
                "errors": summary,
                "fields": sorted({_norm_key(k) for k in _all_keys(payload)})[:30]}
    roots = [root for root in (ent_usage, pay_status, payload)
             if root is not None]
    plan = _first_value(roots, {"plan", "planname", "plantype", "productname",
                                "subscription", "tier", "packagename"})
    benefits_raw = _first_value(roots, {
        "benefits", "packages", "entitlements", "items", "quotas",
        "benefitlist", "userentitlementpacklist", "entitlementpacklist",
        "packlist"})
    benefits = []
    if isinstance(benefits_raw, list):
        for item in benefits_raw[:12]:
            normalized = _normalize_benefit(item)
            if normalized:
                benefits.append(normalized)
    elif isinstance(benefits_raw, dict):
        for key, item in list(benefits_raw.items())[:12]:
            if isinstance(item, dict):
                normalized = _normalize_benefit(item)
                if normalized:
                    normalized["name"] = normalized["name"] or str(key)[:80]
                    benefits.append(normalized)
    remain = _first_number(roots, ("remain", "remaining", "balance",
                                   "credits", "credit", "quota_remain"))
    total = _first_number(roots, ("total", "size", "quota", "total_quota",
                                  "limit"))
    if not remain and benefits:
        remain = sum(b["remain"] for b in benefits)
    if not total and benefits:
        total = sum(b["total"] for b in benefits)
    expires_raw = _first_value(roots, ("expiresat", "expireat", "expiredat",
                                       "expires", "endtime", "enddate"))
    expires_at = int(_normalize_epoch(expires_raw) or 0)
    if not expires_at:
        for benefit in benefits:
            stamp = int(benefit.get("expires_at") or 0)
            if stamp and (not expires_at or stamp < expires_at):
                expires_at = stamp
    if not plan and benefits:
        plan = benefits[0].get("name") or ""
    status = _first_value(roots, ("status", "state", "entstatus"))
    trial_raw = _first_value(roots, {"trialstatus"})
    trial = {}
    if isinstance(trial_raw, dict):
        trial = {
            "eligible": bool(trial_raw.get("is_eligible_for_trial")),
            "in_trial": bool(trial_raw.get("is_in_trial")),
            "end_time": int(_normalize_epoch(
                trial_raw.get("trial_end_time")) or 0),
        }
    return {
        "ok": True,
        "source": source,
        "plan": str(plan)[:80] if isinstance(plan, (str, int, float)) else "",
        "remain": remain,
        "total": total,
        "expires_at": expires_at,
        "exceeded": _find_bool(ent_usage if ent_usage is not None else payload,
                               {"exceeded", "isquotaexceeded",
                                "overlimit", "quotaexceeded"}),
        "status": str(status or "")[:40],
        "benefits": benefits,
        "trial": trial,
        "partial": bool(errors),
        "errors": _errors_summary(errors),
        "fields": sorted({_norm_key(k) for k in _all_keys(payload)})[:30],
    }


def _all_keys(obj, depth=3, out=None):
    if out is None:
        out = set()
    if depth < 0:
        return out
    if isinstance(obj, dict):
        for key, value in obj.items():
            out.add(str(key))
            if isinstance(value, (dict, list)):
                _all_keys(value, depth - 1, out)
    elif isinstance(obj, list):
        for value in obj[:10]:
            _all_keys(value, depth - 1, out)
    return out


def _fetch_account_usage(account):
    """取账号权益/用量。

    返回 (usage, entitlement, errors, raw_usage, raw_entitlement)：
      · 优先 trae_client.fetch_usage / fetch_entitlement（原始 payload 一并带回，
        以便写回新版 Account.usage / Account.entitlement）；
      · 上游失败时回退账号层已有快照（account.usage / account.entitlement）；
      · 再回退旧骨架的 fetch_credits / fetch_plan。
    """
    errors = []
    usage = entitlement = None
    raw_usage = raw_entitlement = None
    client = _client_module()
    if client is not None:
        fetch_usage = getattr(client, "fetch_usage", None)
        if callable(fetch_usage):
            try:
                raw_usage = _call_with_account(fetch_usage, account)
                usage = _digest_usage(raw_usage, "trae_client.fetch_usage")
            except Exception as exc:
                errors.append("fetch_usage: %s" % _scrub(exc, 160))
        else:
            errors.append("trae_client 缺少 fetch_usage")
        fetch_ent = getattr(client, "fetch_entitlement", None)
        if callable(fetch_ent):
            try:
                raw_entitlement = _call_with_account(fetch_ent, account)
                entitlement = _digest_entitlement(
                    raw_entitlement, "trae_client.fetch_entitlement")
            except Exception as exc:
                errors.append("fetch_entitlement: %s" % _scrub(exc, 160))
        else:
            errors.append("trae_client 缺少 fetch_entitlement")
    else:
        errors.append("trae_client 未就绪（使用账号层快照兜底）")

    # 回退 1：新版账号层已落盘的快照
    if usage is None or not usage.get("ok"):
        stored_usage = getattr(account, "usage", None)
        if isinstance(stored_usage, dict) and stored_usage:
            usage = _digest_usage(stored_usage, "account.usage")
    if entitlement is None or not entitlement.get("ok"):
        stored_ent = getattr(account, "entitlement", None)
        if isinstance(stored_ent, dict) and stored_ent:
            entitlement = _digest_entitlement(stored_ent, "account.entitlement")

    # 回退 2：旧骨架账本
    credits = _credits_digest(account)
    if usage is None or not usage.get("ok"):
        fresh = {}
        try:
            if hasattr(account, "fetch_credits"):
                fresh = account.fetch_credits() or {}
        except Exception as exc:
            errors.append("fetch_credits: %s" % _scrub(exc, 160))
        if isinstance(fresh, dict) and fresh.get("ok") is False:
            errors.append("fetch_credits: %s"
                          % _scrub(fresh.get("error") or "失败", 160))
        credits = _credits_digest(account)
        if credits.get("ok"):
            usage = {
                "ok": True,
                "kind": "ledger",
                "source": credits.get("source") or "account.credits",
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "requests": 0,
                "remaining": credits.get("remain") or 0,
                "used": 0,
                "limit": credits.get("size") or 0,
                "fields": ["remain", "size", "exceeded"],
                "numbers": {},
            }
        else:
            usage = {"ok": False, "source": "account.ledger",
                     "error": "额度快照不可用"}
    if entitlement is None or not entitlement.get("ok"):
        plan = _plan_of(account)
        try:
            if hasattr(account, "fetch_plan"):
                plan_result = account.fetch_plan()
                if isinstance(plan_result, dict):
                    plan = str(plan_result.get("plan") or plan)
                else:
                    plan = str(plan_result or plan)
        except Exception as exc:
            errors.append("fetch_plan: %s" % _scrub(exc, 160))
        entitlement = {
            "ok": bool(credits.get("ok") or plan),
            "source": "account.plan+credits",
            "plan": plan,
            "remain": credits.get("remain") or 0,
            "total": credits.get("size") or 0,
            "expires_at": credits.get("expires_at") or 0,
            "exceeded": bool(credits.get("exceeded")),
            "status": "",
            "benefits": credits.get("packages") or [],
            "fields": ["plan", "remain", "size", "expires_at"],
        }
    return usage, entitlement, errors, raw_usage, raw_entitlement


# ---------------------------------------------------------------------------
# 到期提醒（纯本地计算，不产生网络请求）
# ---------------------------------------------------------------------------
_ALERT_ORDER = {"critical": 0, "warn": 1, "info": 2}


def _collect_alerts(account, snapshot=None):
    snapshot = snapshot or {}
    now = time.time()
    alerts = []

    def add(level, code, message):
        alerts.append({"level": level, "code": code,
                       "message": _scrub(message, 220)})

    if not _access_token(account):
        add("critical", "no_access_token", "缺少 access token，需重新导入账号")
    else:
        expires = _expires_at(account)
        if not expires:
            add("info", "no_access_expiry", "账号未记录 access token 到期时间")
        else:
            remain = expires - now
            if remain <= 0:
                add("critical", "access_expired",
                    "access token 已过期（%s）" % _fmt_eta(remain))
            elif remain <= 6 * 3600:
                add("critical", "access_expiring",
                    "access token 将在 %s 后过期，建议立即保活"
                    % _fmt_eta(remain))
            elif remain <= DEFAULT_KEEPALIVE_THRESHOLD:
                add("warn", "access_expiring_24h",
                    "access token 将在 %s 后过期，下一轮保活会自动刷新"
                    % _fmt_eta(remain))
            elif remain <= 72 * 3600:
                add("info", "access_expiring_72h",
                    "access token 将在 %s 后过期" % _fmt_eta(remain))
    if not _refresh_token(account):
        add("critical", "no_refresh_token",
            "缺少 refreshToken，access token 过期后无法自动续期")
    meta = snapshot.get("meta") or {}
    refresh_exp = int(meta.get("refresh_expires_at")
                      or _refresh_expires_at(account) or 0)
    if refresh_exp:
        remain = refresh_exp - now
        if remain <= 0:
            add("critical", "refresh_expired",
                "refreshToken 已过期，必须重新登录并在看板重新导入账号")
        elif remain <= 7 * 86400:
            add("warn", "refresh_expiring",
                "refreshToken 将在 %s 后过期，请重新登录桌面端并导入"
                % _fmt_eta(remain))
    credits = snapshot.get("credits") or {}
    credit_exp = int(credits.get("expires_at") or 0)
    # 新 Trae 账号的 credits 视图来自 entitlement；到期只在下面报一次，避免重复
    if credit_exp and str(credits.get("source") or "") == "credits":
        remain = credit_exp - now
        if 0 < remain <= 7 * 86400:
            add("info", "credits_expiring",
                "额度包将在 %s 后到期（剩余 %s）"
                % (_fmt_eta(remain), credits.get("remain") or 0))
    entitlement = snapshot.get("entitlement") or {}
    ent_exp = int(entitlement.get("expires_at") or 0)
    if ent_exp:
        remain = ent_exp - now
        if remain <= 0:
            add("warn", "entitlement_expired", "权益包已到期")
        elif remain <= 7 * 86400:
            add("info", "entitlement_expiring",
                "权益包将在 %s 后到期" % _fmt_eta(remain))
    last_error = str(getattr(account, "last_error", "") or "")
    if last_error:
        lower = last_error.lower()
        dead = False
        session_dead = getattr(trae_accounts, "session_dead", None)
        if callable(session_dead):
            try:
                dead = bool(session_dead(last_error))
            except Exception:
                dead = False
        if dead or "session dead" in lower or "token_expire" in lower:
            add("critical", "session_dead",
                "会话已失效（需重新登录）：%s" % _scrub(last_error, 120))
        elif "refresh failed" in lower:
            add("warn", "refresh_failed",
                "上次刷新失败：%s" % _scrub(last_error, 120))
    if not bool(getattr(account, "enabled", True)):
        add("warn", "account_disabled", "账号已禁用，不会被调度")
    if credits.get("unknown"):
        add("warn", "credits_unknown",
            "额度为未知（上游退化响应，不等于 0）")
    alerts.sort(key=lambda a: _ALERT_ORDER.get(a.get("level"), 9))
    return alerts


def _reminder_counts(alerts):
    counts = {"critical": 0, "warn": 0, "info": 0}
    for item in alerts or []:
        level = item.get("level") or "info"
        counts[level] = counts.get(level, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# 任务 1：Token 保活
# ---------------------------------------------------------------------------
def task_daily_checkin(pool=None, accounts=None, trigger="manual", **kwargs):
    """每日签到（仅 CN 真实可用）。

    调用 trae_client.claim_checkin：先查 status，已签到则幂等返回；未签到才
    POST claim，再查一次 status 用 credits 差额计算真实到账。INTL 没有该接口，
    如实记「跳过」而不是伪造成功。
    """
    started = time.time()
    client = _client_module()
    targets = _iter_accounts(pool=pool, accounts=accounts)
    logs = []
    checked = already = failed = skipped = 0
    earned_total = 0
    snapshot = {}
    if client is None:
        return {"ok": False, "logs": ["! trae_client 不可用，无法签到"],
                "stats": {"checked": 0, "already": 0, "failed": 0,
                          "skipped": 0, "earned_credit": 0}, "accounts": {}}
    for account in targets:
        uid = _uid_of(account)
        name = _name_of(account)
        realm = getattr(account, "realm", "cn")
        if realm != "cn":
            skipped += 1
            logs.append("— [%s] 国际版没有每日签到接口，跳过" % name)
            snapshot[uid] = {"ok": False, "skipped": True,
                             "reason": "intl_no_checkin", "earned_credit": 0}
            continue
        try:
            res = client.claim_checkin(account, realm="cn")
        except Exception as exc:                       # noqa: BLE001
            failed += 1
            msg = _scrub(str(exc), 200)
            logs.append("! [%s] 签到失败：%s" % (name, msg))
            snapshot[uid] = {"ok": False, "error": msg, "earned_credit": 0}
            continue
        if res.get("ok"):
            if res.get("already"):
                already += 1
                logs.append("✓ [%s] 今日已签到（积分 %s）"
                            % (name, res.get("credits")))
            else:
                checked += 1
                earned_total += int(res.get("earned_credit") or 0)
                logs.append("✓ [%s] 签到成功，到账 +%s（积分 %s）"
                            % (name, res.get("earned_credit") or 0,
                               res.get("credits") or 0))
        else:
            failed += 1
            logs.append("! [%s] 签到未生效：%s"
                        % (name, res.get("message") or "未知原因"))
        snapshot[uid] = dict(res)
        try:
            account.extra = dict(getattr(account, "extra", {}) or {})
            account.extra["checkin"] = {
                "at": _iso(), "checked_in": bool(res.get("checked_in")),
                "credits": res.get("credits"), "earned_credit": res.get("earned_credit") or 0,
            }
        except Exception:
            pass
    ok = failed == 0
    finished = time.time()
    summary = ("每日签到：新签 %d，已签 %d，跳过 %d，失败 %d，到账 %s"
               % (checked, already, skipped, failed, earned_total))
    stats = {"checked": checked, "already": already, "failed": failed,
             "skipped": skipped, "earned_credit": earned_total,
             "partial": failed > 0}
    record = _record_run("daily_checkin", ok, started, finished, trigger,
                         summary, stats, logs)
    for line in [summary] + [l for l in logs if l.startswith(("✓", "!", "—"))]:
        _log(line)
    return {"ok": ok, "task": "daily_checkin", "summary": summary,
            "stats": stats, "logs": logs, "record": record,
            "accounts": snapshot,
            "duration_ms": int((finished - started) * 1000)}


def task_token_keepalive(pool=None, accounts=None, trigger="manual",
                         force=False, threshold_seconds=DEFAULT_KEEPALIVE_THRESHOLD):
    """到期前 threshold_seconds（默认 24h）刷新 access token；force=True 全量。

    refresh 是轮换式的（旧 refreshToken 立即失效），account.refresh() 内部会
    原子回写账号文件，因此这里不做二次保存。
    """
    started = time.time()
    logs = []
    checked = refreshed = failed = skipped = 0
    refreshed_uids, failed_uids = [], []
    for account in _iter_accounts(pool, accounts):
        name = _name_of(account)
        if not _access_token(account):
            skipped += 1
            logs.append("— [%s] 缺少 access token，跳过保活" % name)
            continue
        remain = _expires_at(account) - time.time()
        if not force and remain > float(threshold_seconds):
            skipped += 1
            continue
        checked += 1
        logs.append("[%s] Token 剩余 %s，执行保活刷新..."
                    % (name, _fmt_eta(remain)))
        outcome = {"ok": False, "skipped": False, "detail": ""}
        try:
            outcome = _do_refresh(account)
        except Exception as exc:
            outcome = {"ok": False, "skipped": False,
                       "detail": _scrub(exc, 160)}
            try:
                account.last_error = outcome["detail"]
            except Exception:
                pass
        if outcome.get("ok") and outcome.get("skipped"):
            skipped += 1
            logs.append("— [%s] 未到刷新窗口（%s）"
                        % (name, outcome.get("detail") or "token 仍有效"))
        elif outcome.get("ok"):
            refreshed += 1
            refreshed_uids.append(_uid_of(account))
            logs.append("✓ [%s] 保活成功，新到期时间 %s"
                        % (name, _fmt_eta(_expires_at(account)
                                          - time.time())))
        else:
            failed += 1
            failed_uids.append(_uid_of(account))
            logs.append("! [%s] 保活失败：%s"
                        % (name, _scrub(outcome.get("detail")
                                        or getattr(account, "last_error", "")
                                        or "未知错误", 160)))
        time.sleep(0.2)
    if not logs:
        logs.append("所有账号 Token 剩余均超过 24 小时，无需刷新")
    summary = ("Token 保活：检查 %d，刷新 %d，跳过 %d，失败 %d"
               % (checked, refreshed, skipped, failed))
    finished = time.time()
    # 单个账号刷新失败不把整轮任务判死：任务完成 + stats.failed 呈现异常，
    # 看板行标 attention；只有「全员失败且无人可跳过」才算任务失败。
    task_ok = failed == 0 or refreshed > 0 or skipped > 0
    stats = {"checked": checked, "refreshed": refreshed, "failed": failed,
             "skipped": skipped, "partial": failed > 0,
             "threshold_seconds": int(threshold_seconds),
             "force": bool(force), "refreshed_uids": [_uid8(u) for u in refreshed_uids],
             "failed_uids": [_uid8(u) for u in failed_uids]}
    record = _record_run("token_keepalive", task_ok, started, finished,
                         trigger, summary, stats, logs)
    for line in [summary] + [l for l in logs if l.startswith(("✓", "!"))]:
        _log(line)
    return {"ok": task_ok, "task": "token_keepalive", "summary": summary,
            "stats": stats, "logs": logs, "record": record,
            "failed_uids": failed_uids, "refreshed_uids": refreshed_uids,
            "duration_ms": int((finished - started) * 1000)}


def _uid8(uid):
    uid = str(uid or "")
    return uid[:8]


# ---------------------------------------------------------------------------
# 任务 2：权益 / 用量刷新
# ---------------------------------------------------------------------------
def task_usage_refresh(pool=None, accounts=None, trigger="manual", realm=None):
    started = time.time()
    logs = []
    snapshots = {}
    refreshed = failed = skipped = 0
    for account in _iter_accounts(pool, accounts, realm):
        name = _name_of(account)
        uid = _uid_of(account) or name
        if not _access_token(account):
            skipped += 1
            logs.append("— [%s] 缺少 access token，跳过权益刷新" % name)
            continue
        (usage, entitlement, errors,
         raw_usage, raw_entitlement) = _fetch_account_usage(account)
        # 新 Trae 账号层：只回写**本次真实拉到**的原始快照；回退自账号旧快照
        # 时不重复覆盖（避免把原始 JSON 降级成归一化摘要）
        setter = getattr(account, "set_usage", None)
        persist_usage = (raw_usage
                         if isinstance(raw_usage, dict) and raw_usage else None)
        persist_ent = (raw_entitlement
                       if isinstance(raw_entitlement, dict) and raw_entitlement
                       else None)
        if callable(setter) and (persist_usage or persist_ent):
            try:
                setter(usage=persist_usage, entitlement=persist_ent,
                       persist=True)
            except Exception as exc:
                errors.append("set_usage: %s" % _scrub(exc, 160))
        snapshot = {
            "uid": _uid_of(account),
            "nickname": name,
            "realm": str(getattr(account, "realm", "") or ""),
            "plan": str(_plan_of(account) or ""),
            "usage": usage,
            "entitlement": entitlement,
            "credits": _credits_digest(account),
            "meta": _account_meta(account),
            "errors": errors[-8:],
            "updated_at": _iso(),
            "updated_ts": int(time.time()),
        }
        snapshot["alerts"] = _collect_alerts(account, snapshot)
        snapshots[uid] = snapshot
        if usage.get("ok") or entitlement.get("ok"):
            refreshed += 1
            if usage.get("ok"):
                logs.append("✓ [%s] 用量已刷新（来源 %s；输入 %s / 输出 %s）"
                            % (name, usage.get("source"),
                               usage.get("input_tokens"), usage.get("output_tokens")))
            if entitlement.get("ok"):
                logs.append("✓ [%s] 权益已刷新（%s；剩余 %s）"
                            % (name, entitlement.get("plan") or "未知套餐",
                               entitlement.get("remain")))
        else:
            failed += 1
            logs.append("! [%s] 权益/用量刷新失败：%s"
                        % (name, "；".join(errors[-3:]) or "上游无响应"))
        time.sleep(0.2)

    def merge(state):
        bucket = state.setdefault("accounts", {})
        for uid, new in snapshots.items():
            old = bucket.get(uid) or {}
            merged = dict(old)
            merged.update({k: v for k, v in new.items()
                           if k not in ("usage", "entitlement")})
            # 刷新失败不覆盖上一份健康快照（与账本“未知不覆盖 0”同一原则）
            if (new.get("usage") or {}).get("ok") or not old.get("usage"):
                merged["usage"] = new.get("usage")
            if (new.get("entitlement") or {}).get("ok") or not old.get("entitlement"):
                merged["entitlement"] = new.get("entitlement")
            bucket[uid] = merged

    _mutate_state(merge)
    total = refreshed + failed
    summary = ("权益/用量刷新：成功 %d / %d，跳过 %d，失败 %d"
               % (refreshed, total, skipped, failed))
    finished = time.time()
    stats = {"accounts": total, "refreshed": refreshed, "failed": failed,
             "skipped": skipped, "realm": realm or ""}
    partial = failed > 0 and refreshed > 0
    stats["partial"] = partial
    record = _record_run("usage_refresh", failed == 0 or refreshed > 0,
                         started, finished, trigger, summary, stats, logs)
    for line in [summary] + [l for l in logs if l.startswith(("✓", "!"))]:
        _log(line)
    return {"ok": failed == 0 or refreshed > 0, "task": "usage_refresh",
            "summary": summary,
            "stats": stats, "logs": logs, "record": record,
            "accounts": snapshots, "refreshed": refreshed, "failed": failed,
            "skipped": skipped, "duration_ms": int((finished - started) * 1000)}


# ---------------------------------------------------------------------------
# 模型自动探测
# ---------------------------------------------------------------------------
def task_model_probe(pool=None, accounts=None, trigger="manual", limit=6):
    """用最小请求探测模型真实可用性；只补测 6h 内没有成功记录的模型。"""
    import trae_probe
    started = time.time()
    targets = list(_iter_accounts(pool=pool, accounts=accounts))
    client = _client_module()
    catalog = _catalog_module()
    models = []
    seen = set()
    # 自动任务只探当前优先区域：CN 有账号就只探 CN，避免把 INTL 的
    # 4015 风控当成维护失败；双区全量探测留给面板手动按钮。
    available_realms = {str(getattr(a, "realm", "cn") or "cn")
                        for a in targets if getattr(a, "enabled", True)}
    auto_realm = "cn" if "cn" in available_realms else (
        sorted(available_realms)[0] if available_realms else "cn")
    for account in targets:
        realm = str(getattr(account, "realm", "cn") or "cn")
        if realm != auto_realm:
            continue
        rows = []
        fetch = getattr(client, "fetch_model_list", None) if client else None
        if callable(fetch):
            try:
                rows = _call_with_account(fetch, account) or []
            except Exception:
                rows = []
        if not rows and catalog is not None:
            try:
                rows = catalog.models_for_realm(realm) or []
            except Exception:
                rows = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            key = (item.get("name") or item.get("upstream_key")
                   or item.get("key") or item.get("id"))
            if not key or (realm, key) in seen:
                continue
            low = str(key).lower()
            if any(bad in low for bad in ("embed", "rerank", "image", "video", "tts", "asr")):
                continue
            seen.add((realm, key))
            models.append({"key": key, "realm": realm, "meta": item})
    if not models:
        finished = time.time()
        summary = "模型自动探测：没有可探测的模型"
        _record_run("model_probe", True, started, finished, trigger, summary,
                    {"total": 0}, [summary])
        return {"ok": True, "task": "model_probe", "summary": summary,
                "stats": {"total": 0}, "logs": [summary], "results": [],
                "duration_ms": int((finished - started) * 1000)}
    result = trae_probe.probe_models(targets, models, limit=limit,
                                     stale_seconds=6 * 3600)
    summary_data = result.get("summary") or {}
    ok = summary_data.get("failed", 0) == 0 or summary_data.get("ok", 0) > 0
    logs = []
    for row in result.get("results") or []:
        if row.get("cached"):
            continue
        if row.get("ok"):
            logs.append("✓ [%s] %s 可用（%sms）" % (row.get("realm"), row.get("model"),
                                                   row.get("elapsed_ms")))
        else:
            logs.append("! [%s] %s 探测失败：%s" % (row.get("realm"), row.get("model"),
                                                   _scrub(row.get("error"), 120)))
    summary = ("模型自动探测：成功 %d / 失败 %d / 跳过 %d"
               % (summary_data.get("ok", 0), summary_data.get("failed", 0),
                  summary_data.get("skipped", 0)))
    finished = time.time()
    record = _record_run("model_probe", ok, started, finished, trigger,
                         summary, summary_data, logs)
    for line in [summary] + logs[:20]:
        _log(line)
    return {"ok": ok, "task": "model_probe", "summary": summary,
            "stats": summary_data, "logs": logs, "record": record,
            "results": result.get("results") or [],
            "duration_ms": int((finished - started) * 1000)}


# ---------------------------------------------------------------------------
# 任务 3：模型目录刷新
# ---------------------------------------------------------------------------
def task_catalog_refresh(pool=None, accounts=None, trigger="manual"):
    started = time.time()
    accounts_list = list(_iter_accounts(pool, accounts))
    realms = sorted({str(getattr(a, "realm", "cn") or "cn")
                     for a in accounts_list}) or ["cn", "intl"]
    client = _client_module()
    catalog = _catalog_module()
    results = {}
    logs = []
    ok_all = True
    for realm in realms:
        account = next((a for a in accounts_list
                        if str(getattr(a, "realm", "cn") or "cn") == realm
                        and _access_token(a)), None)
        live_count = 0
        error = ""
        live_names = []
        fetch = getattr(client, "fetch_model_list", None) if client else None
        if callable(fetch) and account is not None:
            try:
                payload = _call_with_account(fetch, account)
                models = payload
                if isinstance(payload, dict):
                    models = payload.get("models") or payload.get("model_configs") \
                        or payload.get("data") or []
                if isinstance(models, list):
                    live_count = len(models)
                    for item in models[:20]:
                        if isinstance(item, dict):
                            live_names.append(str(item.get("name")
                                                   or item.get("model_name")
                                                   or item.get("id") or ""))
                else:
                    error = "上游模型清单结构异常"
            except Exception as exc:
                error = _scrub(exc, 160)
        elif client is None:
            error = "trae_client 未就绪"
        else:
            error = "该区域无可用账号，仅核对本地快照"
        snapshot_count = 0
        snapshot_source = ""
        if catalog is not None:
            try:
                snapshot_count = len(catalog.models_for_realm(realm) or [])
                source_fn = getattr(catalog, "snapshot_source", None)
                snapshot_source = str(source_fn(realm) if callable(source_fn) else "")
            except Exception as exc:
                error = error or ("trae_catalog: %s" % _scrub(exc, 120))
        ok = bool(live_count or snapshot_count)
        ok_all = ok_all and ok
        results[realm] = {
            "ok": ok,
            "live_count": live_count,
            "snapshot_count": snapshot_count,
            "snapshot_source": snapshot_source,
            "live_names": live_names,
            "error": error,
        }
        if live_count:
            logs.append("✓ [%s] 上游模型清单 %d 个（示例：%s）"
                        % (realm, live_count,
                           "、".join([n for n in live_names[:5] if n]) or "-"))
        if snapshot_count:
            logs.append("✓ [%s] 本地目录快照 %d 个（%s）"
                        % (realm, snapshot_count, snapshot_source or "内置"))
        if error and ok:
            logs.append("— [%s] 上游模型清单不可用，已用本地快照兜底：%s"
                        % (realm, error))
        if not ok:
            logs.append("! [%s] 模型目录刷新失败：%s" % (realm, error or "无数据"))
    summary_parts = ["%s：上游 %d / 快照 %d"
                     % (realm, item["live_count"], item["snapshot_count"])
                     for realm, item in sorted(results.items())]
    summary = "模型目录刷新 " + ("；".join(summary_parts) or "无区域")
    finished = time.time()
    stats = {"realms": results, "source": "trae_client"
             if client is not None else "trae_catalog(snapshot)"}
    record = _record_run("catalog_refresh", ok_all, started, finished, trigger,
                         summary, stats, logs)
    _log(summary)
    return {"ok": ok_all, "task": "catalog_refresh", "summary": summary,
            "stats": stats, "logs": logs, "record": record,
            "realms": results, "duration_ms": int((finished - started) * 1000)}


# ---------------------------------------------------------------------------
# 任务 4：到期提醒
# ---------------------------------------------------------------------------
def task_expiry_reminder(pool=None, accounts=None, trigger="manual", realm=None):
    started = time.time()
    state = load_state()
    snapshots = state.get("accounts") or {}
    items = []
    per_account = {}
    logs = []
    for account in _iter_accounts(pool, accounts, realm, include_disabled=True):
        uid = _uid_of(account) or _name_of(account)
        snapshot = snapshots.get(uid) or {}
        alerts = _collect_alerts(account, snapshot)
        per_account[uid] = alerts
        for alert in alerts:
            entry = dict(alert)
            entry.update({"uid": _uid_of(account),
                          "nickname": _name_of(account),
                          "realm": str(getattr(account, "realm", "") or "")})
            items.append(entry)
        if alerts:
            logs.append("[%s] %d 条提醒：%s"
                        % (_name_of(account), len(alerts),
                           "；".join(a["message"] for a in alerts[:2])))
        else:
            logs.append("✓ [%s] 无到期风险" % _name_of(account))
    items.sort(key=lambda a: _ALERT_ORDER.get(a.get("level"), 9))
    counts = _reminder_counts(items)
    critical = counts.get("critical", 0)
    warn = counts.get("warn", 0)
    if critical:
        summary = "到期提醒：%d 条严重 / %d 条警告，共影响 %d 个账号" % (
            critical, warn, len({i["uid"] for i in items if i.get("level") == "critical"}))
    elif warn:
        summary = "到期提醒：%d 条警告（共 %d 条）" % (warn, len(items))
    elif items:
        summary = "到期提醒：%d 条提示，无严重风险" % len(items)
    else:
        summary = "到期提醒：全部账号凭证与权益均在安全期内"

    def mutate(state):
        # 账号快照里的 alerts 也一并刷新，避免看板/体检读到上一轮旧提醒
        bucket = state.setdefault("accounts", {})
        for uid, alerts in per_account.items():
            snapshot = dict(bucket.get(uid) or {})
            snapshot["alerts"] = alerts
            snapshot["alerts_updated_at"] = _iso()
            bucket[uid] = snapshot
        state["reminders"] = {
            "updated_at": _iso(),
            "updated_ts": int(time.time()),
            "items": items[:100],
            "accounts": {uid: alerts for uid, alerts in per_account.items()},
            "counts": counts,
        }

    _mutate_state(mutate)
    finished = time.time()
    stats = {"total": len(items), "counts": counts,
             "accounts": len(per_account)}
    # 提醒任务是「扫描」：完成即成功；critical/warn 是发现，通过 stats 与
    # summary 呈现，不把任务本身标成失败（否则看板会长期飘红）
    record = _record_run("expiry_reminder", True, started, finished,
                         trigger, summary, stats, logs)
    _log(summary)
    return {"ok": True, "task": "expiry_reminder", "summary": summary,
            "stats": stats, "logs": logs, "record": record,
            "alerts": items, "counts": counts,
            "duration_ms": int((finished - started) * 1000)}


# ---------------------------------------------------------------------------
# 统一执行入口
# ---------------------------------------------------------------------------
_TASK_IMPLS = {
    "daily_checkin": task_daily_checkin,
    "model_probe": task_model_probe,
    "token_keepalive": task_token_keepalive,
    "usage_refresh": task_usage_refresh,
    "catalog_refresh": task_catalog_refresh,
    "expiry_reminder": task_expiry_reminder,
}


def run_task(code, pool=None, accounts=None, trigger="manual", **kwargs):
    """执行单个任务（手动/调度统一入口）。未知任务返回 ok=False。"""
    impl = _TASK_IMPLS.get(code)
    if impl is None:
        return {"ok": False, "task": code,
                "error": "未知任务：%s（可选：%s）"
                         % (code, "、".join(TASK_ORDER)),
                "logs": [], "stats": {}, "summary": "未知任务"}
    started = time.time()
    try:
        return impl(pool=pool, accounts=accounts, trigger=trigger, **kwargs)
    except Exception as exc:
        finished = time.time()
        summary = "任务执行异常：%s" % _scrub(exc, 160)
        _record_run(code, False, started, finished, trigger, summary,
                    {"exception": _scrub(exc, 200)}, [summary], error=str(exc))
        _log(summary)
        return {"ok": False, "task": code, "summary": summary,
                "error": _scrub(exc, 300), "logs": [summary], "stats": {},
                "duration_ms": int((finished - started) * 1000)}


def run_all_tasks(pool=None, accounts=None, trigger="manual", codes=None):
    """按固定顺序跑完维护任务（含每日签到），并把本轮摘要写入 last_cycle。"""
    started = time.time()
    results = {}
    logs = []
    ok = True
    for code in (codes or TASK_ORDER):
        result = run_task(code, pool=pool, accounts=accounts, trigger=trigger)
        results[code] = result
        ok = bool(result.get("ok")) and ok
        logs.append("—— %s：%s" % (TASK_NAMES.get(code, code),
                                  result.get("summary") or
                                  ("成功" if result.get("ok") else "失败")))
        logs.extend([l for l in (result.get("logs") or [])
                     if l.startswith(("✓", "!", "—"))][:20])
    finished = time.time()
    cycle = {
        "trigger": trigger or "manual",
        "started_at": _iso(started),
        "finished_at": _iso(finished),
        "duration_ms": int((finished - started) * 1000),
        "ok": ok,
        "tasks": {code: {"ok": bool(res.get("ok")),
                         "summary": res.get("summary") or ""}
                  for code, res in results.items()},
    }

    def mutate(state):
        state["last_cycle"] = cycle

    _mutate_state(mutate)
    summary = "维护巡检%s：%s" % (
        "完成" if ok else "部分失败",
        "；".join("%s=%s" % (TASK_NAMES.get(c, c),
                            "ok" if results[c].get("ok") else "fail")
                 for c in results))
    _log(summary)
    return {"ok": ok, "trigger": cycle["trigger"], "results": results,
            "logs": logs, "cycle": cycle, "summary": summary,
            "started_at": cycle["started_at"],
            "finished_at": cycle["finished_at"],
            "duration_ms": cycle["duration_ms"]}


def task_states():
    """调度器/看板用的任务状态摘要（不触发任何请求）。"""
    state = load_state()
    out = {}
    for definition in TASK_DEFS:
        code = definition["code"]
        record = (state.get("tasks") or {}).get(code) or {}
        out[code] = {
            "name": definition["name"],
            "state": _record_state(record, code),
            "ok": record.get("ok"),
            "last_run": record.get("last_run") or "",
            "summary": record.get("summary") or "",
            "runs": record.get("runs") or 0,
        }
    counts = ((state.get("reminders") or {}).get("counts") or {})
    out["reminders"] = {"counts": counts,
                        "updated_at": (state.get("reminders") or {}).get("updated_at") or ""}
    out["last_cycle"] = state.get("last_cycle") or {}
    out["updated_at"] = state.get("updated_at") or ""
    return out


def task_history(task=None, limit=20):
    """历史执行记录（最新在前）。"""
    state = load_state()
    rows = [row for row in (state.get("history") or [])
            if not task or row.get("task") == task]
    try:
        limit = max(1, int(limit))
    except (TypeError, ValueError):
        limit = 20
    return list(reversed(rows[-limit:]))


# ---------------------------------------------------------------------------
# 看板视图（兼容 dashboard 现有字段）
# ---------------------------------------------------------------------------
def _record_state(record, code=None):
    if not record:
        return "pending"
    if record.get("ok") is False:
        return "error"
    stats = record.get("stats") or {}
    if code in ("token_keepalive", "usage_refresh") and stats.get("failed"):
        return "attention"
    if code == "expiry_reminder":
        counts = stats.get("counts") or {}
        if counts.get("critical") or counts.get("warn"):
            return "attention"
    return "ok"


def _live_keepalive_stats(accounts):
    now = time.time()
    stats = {"checked": 0, "healthy": 0, "expiring": 0, "expired": 0,
             "missing": 0, "unknown": 0}
    for account in accounts:
        stats["checked"] += 1
        if not _access_token(account):
            stats["missing"] += 1
            continue
        expires = _expires_at(account)
        if not expires:
            stats["unknown"] += 1
        elif expires <= now:
            stats["expired"] += 1
        elif expires - now <= DEFAULT_KEEPALIVE_THRESHOLD:
            stats["expiring"] += 1
        else:
            stats["healthy"] += 1
    return stats


def _describe_keepalive(record, live):
    parts = []
    if live["expired"]:
        parts.append("%d 个账号 Token 已过期" % live["expired"])
    if live["expiring"]:
        parts.append("%d 个账号将在 24 小时内到期" % live["expiring"])
    if live["missing"]:
        parts.append("%d 个账号缺少 access token" % live["missing"])
    if not parts:
        parts.append("全部账号 Token 剩余超过 24 小时")
    if record:
        stats = record.get("stats") or {}
        parts.append("上次检查 %s：刷新 %s，跳过 %s，失败 %s"
                     % (record.get("last_run") or "-",
                        stats.get("refreshed", 0), stats.get("skipped", 0),
                        stats.get("failed", 0)))
    else:
        parts.append("尚未执行；点击「立即巡检保活」或等待每日 09:00 / 21:00 排程")
    return "；".join(parts)


def _describe_usage(record, accounts, snapshots):
    if record:
        stats = record.get("stats") or {}
        base = ("上次刷新 %s：成功 %s / %s，失败 %s"
                % (record.get("last_run") or "-",
                   stats.get("refreshed", 0), stats.get("accounts", 0),
                   stats.get("failed", 0)))
    else:
        base = "尚未刷新权益/用量"
    remain = 0
    unknown = 0
    tokens = 0
    for account in accounts:
        snapshot = snapshots.get(_uid_of(account)) or {}
        credits = snapshot.get("credits") or _credits_digest(account)
        if (credits.get("unknown") or credits.get("quota_known") is False
                or not credits.get("ok")):
            unknown += 1
        else:
            remain += int(credits.get("remain") or 0)
        usage = snapshot.get("usage") or {}
        if usage.get("ok"):
            tokens += int(usage.get("total_tokens") or 0)
    extra = "；余额合计 %s" % remain
    if tokens:
        extra += "；用量合计 %s tokens" % tokens
    if unknown:
        extra += "（%d 个账号额度未知）" % unknown
    return base + extra


def _describe_catalog(record):
    if not record:
        return "尚未刷新模型目录；等待排程或手动触发"
    realms = (record.get("stats") or {}).get("realms") or {}
    parts = ["%s 上游 %s / 快照 %s"
             % (realm, item.get("live_count", 0), item.get("snapshot_count", 0))
             for realm, item in sorted(realms.items())]
    return "上次刷新 %s：%s" % (record.get("last_run") or "-",
                               "；".join(parts) or "无区域数据")


def _describe_reminder(record, state):
    reminders = state.get("reminders") or {}
    counts = reminders.get("counts") or {}
    critical = counts.get("critical", 0)
    warn = counts.get("warn", 0)
    info = counts.get("info", 0)
    if critical or warn:
        first = ""
        for item in reminders.get("items") or []:
            if item.get("level") in ("critical", "warn"):
                first = "%s：%s" % (item.get("nickname") or "", item.get("message") or "")
                break
        return ("%d 条严重 / %d 条警告 / %d 条提示；最近检查 %s%s"
                % (critical, warn, info, record.get("last_run") or "-",
                   ("；" + first) if first else ""))
    if record:
        return ("无到期风险（%d 条提示）；上次检查 %s"
                % (info, record.get("last_run") or "-"))
    return "尚未检查；等待排程或手动触发"


def _task_row(definition, state, accounts, mode):
    code = definition["code"]
    record = (state.get("tasks") or {}).get(code) or {}
    snapshots = state.get("accounts") or {}
    state_label = _record_state(record, code)
    if code == "token_keepalive":
        live = _live_keepalive_stats(accounts)
        description = _describe_keepalive(record, live)
        if (record.get("stats") or {}).get("failed"):
            state_label = "attention"
        if live["expired"] or live["missing"]:
            state_label = "attention"
        elif live["expiring"]:
            state_label = "due" if not record else "attention"
        current = 1 if (record and record.get("ok") and
                        not (live["expired"] or live["missing"])) else 0
    elif code == "usage_refresh":
        description = _describe_usage(record, accounts, snapshots)
        stats = record.get("stats") or {}
        if record and record.get("ok") and stats.get("failed"):
            state_label = "attention"
        current = 1 if record and record.get("ok") else 0
    elif code == "catalog_refresh":
        description = _describe_catalog(record)
        current = 1 if record and record.get("ok") else 0
    else:
        description = _describe_reminder(record, state)
        counts = (state.get("reminders") or {}).get("counts") or {}
        if counts.get("critical"):
            state_label = "attention"
        current = 1 if record and record.get("ok") else 0
    status = {"pending": "not_accepted", "ok": "completed",
              "due": "accepted", "attention": "accepted",
              "error": "not_accepted"}.get(state_label, "not_accepted")
    row = {
        "task_code": code,
        "name": definition["name"],
        "description": description,
        "jump_url": "",
        "status": status,
        "state": state_label,
        "current": current,
        "target": 1,
        "reward_credit": 0,
        "reward_energy": 0,
        "ok": record.get("ok"),
        "last_run": record.get("last_run") or "",
        "last_run_ts": record.get("last_ts") or 0,
        "trigger": record.get("trigger") or "",
        "duration_ms": record.get("duration_ms") or 0,
        "summary": record.get("summary") or "",
        "stats": record.get("stats") or {},
        "runs": record.get("runs") or 0,
        "logs": (record.get("logs") or [])[-3:],
    }
    return row


def _travel_summary(accounts, snapshots):
    """把权益（entitlement）映射到旧 dashboard 的 travel 结构。"""
    now = time.time()
    remain = 0
    expires = 0
    ok_count = 0
    source = ""
    plan = ""
    benefits = []
    for account in accounts:
        snapshot = snapshots.get(_uid_of(account)) or {}
        ent = snapshot.get("entitlement") or {}
        if not ent:
            stored = getattr(account, "entitlement", None)
            if isinstance(stored, dict) and stored:
                ent = _digest_entitlement(stored, "account.entitlement")
        if not ent.get("ok"):
            continue
        ok_count += 1
        remain += int(ent.get("remain") or 0)
        ent_exp = int(ent.get("expires_at") or 0)
        if ent_exp and (not expires or ent_exp < expires):
            expires = ent_exp
        source = source or str(ent.get("source") or "")
        plan = plan or str(ent.get("plan") or "") or _plan_of(account)
        benefits.extend([b for b in (ent.get("benefits") or [])
                         if isinstance(b, dict)])
    if not ok_count:
        return {"state": "unknown", "detail": "尚未刷新权益",
                "label": "权益包"}
    if remain > 0 and (not expires or expires > now):
        return {"state": "arrived", "reward_credit": remain,
                "detail": "权益包剩余 %s（%s）" % (remain, plan or "未知套餐"),
                "expires_at": expires, "source": source, "label": "权益包"}
    active = [b for b in benefits
              if not b.get("expires_at") or int(b.get("expires_at") or 0) > now]
    if active:
        return {"state": "active", "active": True, "reward_credit": 0,
                "detail": "权益包有效（%s；%d 个权益项）"
                          % (plan or "未知套餐", len(active)),
                "plan": plan, "benefits": active[:8], "expires_at": expires,
                "source": source, "label": "权益包"}
    return {"state": "idle", "daily_limit_reached": True,
            "detail": "权益包无可用余额或已到期（%s）" % (plan or "未知套餐"),
            "expires_at": expires, "source": source, "label": "权益包"}


def _build_summary(accounts, state, mode=None, realm=None):
    snapshots = state.get("accounts") or {}
    now = time.time()
    energy = 0
    unknown_uids = []
    usage_total = {"input_tokens": 0, "output_tokens": 0,
                   "total_tokens": 0, "cache_read_tokens": 0,
                   "cache_write_tokens": 0, "requests": 0,
                   "remaining": 0, "accounts_ok": 0,
                   "source": ""}
    ent_total = {"ok": 0, "remain": 0, "total": 0, "expires_at": 0,
                 "source": "", "plan": ""}
    reminders = []
    for account in accounts:
        uid = _uid_of(account)
        snapshot = snapshots.get(uid) or {}
        credits = snapshot.get("credits") or _credits_digest(account)
        if (credits.get("unknown") or credits.get("quota_known") is False
                or not credits.get("ok")):
            unknown_uids.append(uid)
        else:
            energy += int(credits.get("remain") or 0)
        usage = snapshot.get("usage") or {}
        if not usage:
            stored_usage = getattr(account, "usage", None)
            if isinstance(stored_usage, dict) and stored_usage:
                usage = _digest_usage(stored_usage, "account.usage")
        if usage.get("ok"):
            usage_total["accounts_ok"] += 1
            for key in ("input_tokens", "output_tokens", "total_tokens",
                        "cache_read_tokens", "cache_write_tokens",
                        "requests", "remaining"):
                usage_total[key] += int(usage.get(key) or 0)
            usage_total["source"] = usage_total["source"] or str(
                usage.get("source") or "")
        ent = snapshot.get("entitlement") or {}
        if not ent:
            stored_ent = getattr(account, "entitlement", None)
            if isinstance(stored_ent, dict) and stored_ent:
                ent = _digest_entitlement(stored_ent, "account.entitlement")
        if ent.get("ok"):
            ent_total["ok"] += 1
            ent_total["remain"] += int(ent.get("remain") or 0)
            ent_total["total"] += int(ent.get("total") or 0)
            ent_exp = int(ent.get("expires_at") or 0)
            if ent_exp and (not ent_total["expires_at"]
                            or ent_exp < ent_total["expires_at"]):
                ent_total["expires_at"] = ent_exp
            ent_total["source"] = ent_total["source"] or str(ent.get("source") or "")
            ent_total["plan"] = ent_total["plan"] or str(ent.get("plan") or "")
        alerts = snapshot.get("alerts")
        if alerts is None:
            alerts = _collect_alerts(account, snapshot)
        reminders.extend([dict(a, uid=uid, nickname=_name_of(account),
                               realm=str(getattr(account, "realm", "") or ""))
                          for a in alerts])
    reminders.sort(key=lambda a: _ALERT_ORDER.get(a.get("level"), 9))
    summary = {
        "mode": mode,
        "realm": realm or "",
        "accounts_total": len(accounts),
        "energy": energy,
        "streak_days": 0,
        "plan": "全部账号" if mode == "all" else (
            str(getattr(accounts[0], "plan", "") or "-") if accounts else "-"),
        "credits": {"remain": energy},
        "codes": [],
        "travel": _travel_summary(accounts, snapshots),
        "usage": usage_total,
        "entitlement": ent_total,
        "reminders": reminders[:50],
        "reminder_counts": _reminder_counts(reminders),
        "tasks_file": tasks_file_path(),
        "updated_at": state.get("updated_at") or "",
        "last_cycle": state.get("last_cycle") or {},
        "task_states": {row["task_code"]: row["state"]
                        for row in (_task_row(d, state, accounts, mode)
                                    for d in TASK_DEFS)},
    }
    if unknown_uids:
        summary["credits_unknown_accounts"] = unknown_uids
        # 单账号视图沿用旧 dashboard 的「未知 ≠ 0」契约（energy=null + 说明）
        if mode != "all" and not energy:
            summary["energy"] = None
            summary["credits_unknown"] = True
            summary["energy_note"] = ("余额未知（上游未提供余额字段或刷新失败，"
                                      "等待下次成功刷新）")
    return summary


def fetch_tasks_view(pool=None, realm=None, uid=None):
    """看板 /tasks：读取落盘任务状态，返回与旧 dashboard 兼容的结构。"""
    accounts = [a for a in _iter_accounts(pool, realm=realm)
                if _access_token(a)]
    if not accounts:
        return {"tasks": [], "summary": {}, "accounts": [],
                "msg": "未找到可用账号（账号已禁用、缺少凭证或不属于该区域）"}
    state = load_state()
    snapshots = state.get("accounts") or {}
    account_list = [_account_brief(a, snapshots.get(_uid_of(a)))
                    for a in accounts]
    if not uid or uid == "all":
        targets = accounts
        mode = "all"
        account_public = None
    else:
        target = next((a for a in accounts if _uid_of(a) == uid), accounts[0])
        targets = [target]
        mode = None
        account_public = _account_brief(target, snapshots.get(_uid_of(target)))
    summary = _build_summary(targets, state, mode=mode, realm=realm)
    tasks = [_task_row(d, state, targets, mode) for d in TASK_DEFS]
    history = list(reversed((state.get("history") or [])[-10:]))
    return {"tasks": tasks, "summary": summary, "account": account_public,
            "accounts": account_list, "mode": mode,
            "history": history, "last_cycle": state.get("last_cycle") or {},
            "tasks_file": tasks_file_path()}


def fetch_task_view(account):
    """兼容旧接口：单账号视图 -> (tasks, summary)。"""
    state = load_state()
    accounts = [account] if account is not None else []
    summary = _build_summary(accounts, state, mode=None,
                             realm=getattr(account, "realm", None))
    tasks = [_task_row(d, state, accounts, None) for d in TASK_DEFS]
    return tasks, summary


# ---------------------------------------------------------------------------
# 兼容层：网关/看板现有路由（Trae 无签到，动作改为维护任务）
# ---------------------------------------------------------------------------
def run_checkin(account, gap=1.0, only_daily=False, claim_gap=None):
    """单账号每日签到（/accounts/checkin 兼容入口）。"""
    if account is None:
        return {"ok": False, "logs": ["! 未找到账号"], "earned_credit": 0,
                "error": "account not found", "message": "未找到账号",
                "claimed": [], "next_available_at": None,
                "next_available_note": "", "credits": {"ok": False}}
    realm = getattr(account, "realm", "cn")
    if realm != "cn":
        return {"ok": False, "logs": ["— [%s] 国际版没有每日签到接口，跳过"
                                     % _name_of(account)],
                "earned_credit": 0, "message": "国际版没有每日签到接口",
                "claimed": [], "credits": {"ok": False}, "skipped": True,
                "next_available_at": None, "next_available_note": ""}
    client = _client_module()
    try:
        res = client.claim_checkin(account, realm="cn")
    except Exception as exc:                           # noqa: BLE001
        msg = _scrub(str(exc), 300)
        return {"ok": False, "logs": ["! 签到失败：%s" % msg],
                "earned_credit": 0, "error": msg, "message": msg,
                "claimed": [], "credits": {"ok": False},
                "next_available_at": None, "next_available_note": ""}
    name = _name_of(account)
    logs = []
    if res.get("already"):
        logs.append("✓ [%s] 今日已签到（积分 %s）"
                    % (name, res.get("credits")))
    elif res.get("ok"):
        logs.append("✓ [%s] 签到成功，到账 +%s（积分 %s）"
                    % (name, res.get("earned_credit") or 0,
                       res.get("credits") or 0))
    else:
        logs.append("! [%s] 签到未生效：%s" % (name, res.get("message") or "未知原因"))
    return {
        "ok": bool(res.get("ok")),
        "logs": logs,
        "earned_credit": int(res.get("earned_credit") or 0),
        "credits": {"ok": True, "remain": res.get("credits") or 0,
                    "size": None},
        "campaign": None,
        "message": res.get("message") or "",
        "claimed": [] if res.get("already") else (["每日签到"] if res.get("ok") else []),
        "next_available_at": None,
        "next_available_note": "",
        "already": bool(res.get("already")),
        "checked_in": bool(res.get("checked_in")),
        "tasks": {"daily_checkin": bool(res.get("ok"))},
    }


def run_batch_daily_checkin(targets, gap=1.0, inter_gap=1.5):
    """批量签到：给 /accounts/checkin 返回 Qoder 看板兼容的 results 数组。"""
    targets = [a for a in (targets or []) if a is not None]
    results = []
    logs = []
    total = 0
    ok_all = True
    for account in targets:
        uid = _uid_of(account)
        name = _name_of(account)
        realm = getattr(account, "realm", "cn")
        if realm != "cn":
            results.append({"uid": uid, "nickname": name, "ok": False,
                            "claimed": [], "earned_credit": 0,
                            "message": "国际版没有每日签到接口",
                            "credits": None, "skipped": True})
            logs.append("— [%s] 国际版没有每日签到接口，跳过" % name)
            continue
        try:
            res = _client_module().claim_checkin(account, realm="cn")
        except Exception as exc:                       # noqa: BLE001
            ok_all = False
            msg = _scrub(str(exc), 200)
            results.append({"uid": uid, "nickname": name, "ok": False,
                            "claimed": [], "earned_credit": 0,
                            "message": msg, "credits": None})
            logs.append("! [%s] 签到失败：%s" % (name, msg))
            continue
        earned = int(res.get("earned_credit") or 0)
        total += earned
        ok = bool(res.get("ok"))
        ok_all = ok_all and ok
        results.append({
            "uid": uid, "nickname": name, "ok": ok,
            "claimed": [] if res.get("already") else (["每日签到"] if ok else []),
            "earned_credit": earned,
            "credits": res.get("credits"),
            "already": bool(res.get("already")),
            "checked_in": bool(res.get("checked_in")),
            "message": res.get("message") or "",
        })
        logs.append(("✓ [%s] 今日已签到（积分 %s）" if res.get("already")
                     else "✓ [%s] 签到成功，到账 +%s（积分 %s）")
                    % ((name, res.get("credits")) if res.get("already")
                       else (name, earned, res.get("credits"))))
    return {"ok": ok_all, "results": results, "logs": logs,
            "credit_added": total, "accounts_count": len(targets)}


def run_keepalive(pool=None, force=False,
                  threshold_seconds=DEFAULT_KEEPALIVE_THRESHOLD, accounts=None):
    """兼容旧调度器接口，返回 {refreshed, failed, failed_uids, logs}。"""
    result = task_token_keepalive(pool=pool, accounts=accounts, force=force,
                                  trigger="manual",
                                  threshold_seconds=threshold_seconds)
    stats = result.get("stats") or {}
    return {"ok": result.get("ok"), "refreshed": stats.get("refreshed", 0),
            "failed": stats.get("failed", 0),
            "failed_uids": result.get("failed_uids") or [],
            "logs": result.get("logs") or [], "stats": stats}


def run_batch_checkin(targets, gap=1.0, inter_gap=1.5):
    """兼容 /tasks/run：对目标账号执行一轮维护任务（保活/权益/目录/提醒）。"""
    targets = [a for a in (targets or []) if a is not None]
    started = time.time()
    result = run_all_tasks(accounts=targets, trigger="manual")
    logs = ["本次执行维护任务（每日签到 / Token 保活 / 权益用量 / 模型目录 / 到期提醒）"]
    for code in TASK_ORDER:
        item = (result.get("results") or {}).get(code) or {}
        logs.append("—— %s：%s" % (TASK_NAMES.get(code, code),
                                  "成功" if item.get("ok") else "失败"))
        logs.extend([l for l in (item.get("logs") or [])
                     if l.startswith(("✓", "!", "—"))][:20])
    logs.append("本轮用时 %.1f 秒；结果已落盘 %s"
                % (time.time() - started, tasks_file_path()))
    checkin_stats = ((result.get("results") or {}).get("daily_checkin") or {}).get("stats") or {}
    return {"ok": result.get("ok"), "logs": logs,
            "credit_added": int(checkin_stats.get("earned_credit") or 0),
            "accounts_count": len(targets),
            "tasks": {code: bool(((result.get("results") or {}).get(code) or {})
                                 .get("ok")) for code in TASK_ORDER},
            "results": result.get("results") or {},
            "duration_ms": result.get("duration_ms") or 0}


def run_batch_pro_claim(targets, gap=1.0, inter_gap=1.5):
    """兼容 /tasks/travel：Trae 无福利包可领，动作=刷新权益/用量。"""
    targets = [a for a in (targets or []) if a is not None]
    result = run_task("usage_refresh", accounts=targets, trigger="manual")
    snapshots = result.get("accounts") or {}
    results = []
    for account in targets:
        snapshot = snapshots.get(_uid_of(account)) or {}
        ent = snapshot.get("entitlement") or {}
        ok = bool(ent.get("ok"))
        results.append({
            "uid": _uid_of(account),
            "nickname": _name_of(account),
            "action": "usage_refresh",
            "ok": ok,
            "state": "refreshed" if ok else "error",
            "msg": ("权益已刷新（%s，剩余 %s）"
                    % (ent.get("plan") or "未知套餐", ent.get("remain") or 0))
                   if ok else "权益刷新失败",
            "reward_credit": 0,
            "already_claimed": False,
        })
    refreshed = sum(1 for row in results if row["ok"])
    msg = ("Trae 没有福利包领取：已刷新权益/用量（成功 %d / 共 %d）"
           % (refreshed, len(results)))
    logs = list(result.get("logs") or [])
    logs.append(msg)
    return {"ok": bool(result.get("ok")), "results": results, "msg": msg,
            "logs": logs, "accounts_count": len(targets)}
