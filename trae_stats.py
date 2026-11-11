
import os
import sys
import threading

PREFIX = "[trae_stats]"
_LOG_LOCK = threading.Lock()
_logger = None


def configure(usage_dir=None, log_path=None, summary_path=None,
              pool=None, log=None):
    """显式接线（由 trae_proxy 启动时调用；也可只传需要的项）。

    usage_dir      统计目录（与 proxy 的 USAGE_DIR 对齐）
    log_path       usage.jsonl 绝对路径；缺省按 usage_dir 推导
    summary_path   usage-summary.json 绝对路径；缺省按 usage_dir 推导
    pool           账号池（展示名/区属用，可为 None）
    log            日志函数 (msg, level=..., tag=...)；None = 保持当前
    返回生效后的路径字典。幂等：重复调用以最后一次为准。
    """
    global USAGE_DIR, USAGE_LOG, USAGE_SUMMARY, POOL, _logger
    global _USAGE_REPORT_CACHE
    if usage_dir:
        USAGE_DIR = os.path.abspath(str(usage_dir))
    if log_path:
        USAGE_LOG = os.path.abspath(str(log_path))
    elif usage_dir:
        USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
    if summary_path:
        USAGE_SUMMARY = os.path.abspath(str(summary_path))
    elif usage_dir:
        USAGE_SUMMARY = os.path.join(USAGE_DIR, "usage-summary.json")
    if pool is not None:
        POOL = pool
    if log is not None:
        _logger = log
    try:                      # 路径变了，报表缓存必须失效
        _USAGE_REPORT_CACHE = trae_cache.JsonResultCache()
    except Exception:
        pass
    return {"usage_dir": USAGE_DIR, "usage_log": USAGE_LOG,
            "usage_summary": USAGE_SUMMARY}


def log(msg, *args, **kwargs):
    """真实日志（绝不再静默 pass）：优先转发 trae_proxy.log，其次 stderr。"""
    text = str(msg)
    if args:
        try:
            text = text % args
        except Exception:
            pass
    level = kwargs.get("level") or ""
    tag = kwargs.get("tag") or "usage"
    fn = _logger
    if fn is None:
        try:                  # 懒解析，避免与 trae_proxy 形成导入环
            import trae_proxy
            fn = getattr(trae_proxy, "log", None)
        except Exception:
            fn = None
    if callable(fn):
        try:
            with _LOG_LOCK:
                if level:
                    fn(text, level=level, tag=tag)
                else:
                    fn(text, tag=tag)
            return
        except Exception:
            pass
    try:
        sys.stderr.write("%s %s %s\n" % (PREFIX, level or "INFO", text))
    except Exception:
        pass


POOL = None


def _local_day_start(ts=None):
    if ts is None:
        ts = time.time()
    t = time.localtime(ts)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1))

def _local_midnight(days_back=0):
    return _local_day_start(time.time() - days_back * 86400)

def range_window(value, since=None, until=None):
    v = str(value or "").strip().lower()
    if v in ("today", "day", "1d"):
        return _local_midnight(), None
    if v in ("week", "w", "7d"):
        return _local_midnight(days_back=6), None
    if v in ("month", "m", "30d"):
        return _local_midnight(days_back=29), None
    if v in ("all", ""):
        return None, None
    if v == "custom":
        try:
            s = float(since) if since else None
        except Exception:
            s = None
        try:
            u = float(until) if until else None
        except Exception:
            u = None
        return s, u
    return None, None

def _row_in_window(row, since, until):
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

import os
import json
import re
import time
import uuid

import trae_admin
import trae_routing
import trae_activity
import trae_pricing
import trae_cache

# 与 trae_proxy 完全同源：优先环境变量 TRAE_PROXY_USAGE_DIR，否则 <repo>/usage。
# 之前这里只写死 <repo>/usage，deployment 设了环境变量时面板会读错目录。
USAGE_DIR = os.environ.get("TRAE_PROXY_USAGE_DIR")     or os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage")
USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
USAGE_SUMMARY = os.path.join(USAGE_DIR, "usage-summary.json")
I18N_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "i18n")
I18N_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,31}\.json$")
FULL_PRICE_PROMPT_MIN = int(os.environ.get("TRAE_FULL_PRICE_PROMPT_MIN") or 100000)
_USAGE_REPORT_CACHE = trae_cache.JsonResultCache()
_ADMIN_JOBS = trae_admin.JobRegistry()

_PROVIDER_RULES = (
    ("claude", "Anthropic"), ("anthropic", "Anthropic"),
    ("gpt", "OpenAI"), ("o1", "OpenAI"), ("o3", "OpenAI"), ("dall-e", "OpenAI"),
    ("gemini", "Google"), ("deepseek", "DeepSeek"),
    ("glm", "智谱 GLM"), ("chatglm", "智谱 GLM"),
    ("kimi", "月之暗面"), ("moonshot", "月之暗面"),
    ("llama", "Meta"), ("mistral", "Mistral"), ("mixtral", "Mistral"),
    ("grok", "xAI"), ("doubao", "豆包"), ("ernie", "文心一言"), ("spark", "讯飞星火"),
    ("hunyuan", "腾讯混元"), ("minimax", "MiniMax"), ("abab", "MiniMax"),
)

def _account_label(account):
    """账号展示名（账号域已无 nickname）：display_name → profile → uid 尾。"""
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
    return str(getattr(account, "uid", "") or "")[:8]


def provider_of(model):
    m = str(model or "").lower()
    for key, name in _PROVIDER_RULES:
        if key in m:
            return name
    return "其他"

def _day_key(ts):
    try:
        return time.strftime("%Y-%m-%d", time.localtime(float(ts)))
    except Exception:
        return ""

def _usage_log_fingerprint():
    path = os.path.abspath(USAGE_LOG)
    try:
        st = os.stat(path)
        return (path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    except OSError:
        return (path, 0, 0, 0, 0, 0)

def _iter_usage_rows_forward(since, chunk=256 * 1024):
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

def compute_usage_stats(range_val=None, since=None, until=None, heatmap_days=365, top_n=5):
    now = time.time()
    lo, hi = range_window(range_val, since, until)
    today_start = _local_midnight()
    heat_lo = _local_midnight(days_back=max(1, int(heatmap_days)) - 1)

    tot = {"requests": 0, "errors": 0, "tokens": 0,
           "prompt": 0, "completion": 0, "cached": 0,
           # usage 缺失（上游没发 token_usage）但仍成功返回的请求数：
           # 它们计入 requests，但 token 量为未知（0），面板可据此提示。
           "usage_missing": 0}
    full_price = {"requests": 0, "prompt": 0, "credit": 0.0}
    total_credit = 0.0
    models = {}
    accounts = {}
    providers = {}
    heat = {}
    act_days = set()
    all_days = set()
    cache_win = {"10m": [0, 0], "1h": [0, 0], "24h": [0, 0], "7d": [0, 0]}
    hour_cached = [0] * 24
    hour_prompt = [0] * 24
    hour_tokens = [0] * 24

    def _bump(bucket, key, tokens, reqs=1):
        cell = bucket.get(key)
        if cell is None:
            cell = bucket[key] = {"tokens": 0, "requests": 0}
        cell["tokens"] += tokens
        cell["requests"] += reqs

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
                    at = r.get("at") or 0
                    try:
                        at = float(at)
                    except (TypeError, ValueError):
                        at = 0.0
                    prompt = int(r.get("prompt_tokens") or 0)
                    cached = int(r.get("cached_tokens") or 0)
                    tokens = int(r.get("total_tokens") or 0)
                    is_err = bool(r.get("error"))
                    dkey = _day_key(at)
                    if at >= heat_lo and dkey:
                        if not is_err and tokens:
                            heat[dkey] = heat.get(dkey, 0) + tokens
                        all_days.add(dkey)
                    # 缓存口径：cached_reported=False（上游没报 cache 字段 /
                    # usage 缺失）**不进分母也不进分子** —— 否则「不知道」会被
                    # 伪造成 0% 命中率。旧行没有该键（None）按历史语义视为已报。
                    _cache_known = (r.get("cached_reported") is not False
                                    and not r.get("usage_missing"))
                    if not is_err and prompt > 0 and _cache_known:
                        for _k, _secs in (("10m", 600), ("1h", 3600),
                                          ("24h", 86400), ("7d", 604800)):
                            if at >= now - _secs:
                                cache_win[_k][0] += cached
                                cache_win[_k][1] += prompt
                    if at >= now - 86400 and not is_err:
                        hour = time.localtime(at).tm_hour
                        if _cache_known:
                            hour_cached[hour] += cached
                            hour_prompt[hour] += prompt
                        hour_tokens[hour] += tokens
                    if not _row_in_window(r, lo, hi):
                        continue
                    if dkey:
                        act_days.add(dkey)
                    if is_err:
                        tot["errors"] += 1
                        continue
                    tot["requests"] += 1
                    if r.get("usage_missing"):
                        tot["usage_missing"] += 1
                    tot["tokens"] += tokens
                    tot["prompt"] += prompt
                    tot["completion"] += int(r.get("completion_tokens") or 0)
                    tot["cached"] += cached
                    _credit = r.get("credit") or 0
                    try:
                        _credit = float(_credit)
                    except (TypeError, ValueError):
                        _credit = 0.0
                    total_credit += _credit
                    _cached_known = r.get("cached_reported")
                    if _cached_known is None:
                        _cached_known = True
                    if (prompt >= FULL_PRICE_PROMPT_MIN and cached <= 0
                            and _cached_known):
                        full_price["requests"] += 1
                        full_price["prompt"] += prompt
                        full_price["credit"] += _credit
                    m = r.get("model") or "(unknown)"
                    _bump(models, m, tokens)
                    _bump(accounts, r.get("account") or "(unattributed)", tokens)
                    _bump(providers, provider_of(m), tokens)
        except Exception as exc:
            log("compute_usage_stats failed: %s" % exc, level="WARN", tag="usage")

    _nick = {}
    try:
        if POOL:
            for _a in POOL.accounts:
                _nick[_a.uid] = _account_label(_a)
    except Exception:
        _nick = {}

    def _rank(bucket, limit=None):
        rows = sorted(bucket.items(), key=lambda kv: kv[1]["tokens"], reverse=True)
        if limit:
            rows = rows[:limit]
        total = sum(v["tokens"] for _, v in rows) or 1
        return [{"name": _nick.get(k) or k, "key": k, "tokens": v["tokens"], "requests": v["requests"],
                 "share": round(v["tokens"] * 100.0 / total, 2)}
                for k, v in rows]

    streak = 0
    if all_days:
        probe = time.localtime()
        if _day_key(now) not in all_days:
            probe = time.localtime(now - 86400)
        while True:
            d = time.strftime("%Y-%m-%d", probe)
            if d not in all_days:
                break
            streak += 1
            probe = time.localtime(time.mktime(probe[:3] + (0, 0, 0, 0, 0, -1)) - 86400)

    top_models = _rank(models)
    hours = []
    for i in range(23, -1, -1):
        ts = now - i * 3600
        h = time.localtime(ts).tm_hour
        prompt = hour_prompt[h]
        cached = hour_cached[h]
        hours.append({
            "ts": int(ts),
            "label": time.strftime("%H:00", time.localtime(ts)),
            "pct": (round(cached * 100.0 / prompt, 2) if prompt else None),
            "tokens": hour_tokens[h],
        })

    cache_rows = []
    for _k, _label in (("10m", "近 10 分钟"), ("1h", "近 1 小时"),
                       ("24h", "近 24 小时"), ("7d", "近 7 天")):
        hit, inp = cache_win[_k]
        cache_rows.append({"key": _k, "label": _label, "hit": hit, "input": inp,
                           "pct": (round(hit * 100.0 / inp, 1) if inp else None)})

    heat_days = []
    start = time.localtime(heat_lo)
    cursor = time.mktime((start.tm_year, start.tm_mon, start.tm_mday,
                          0, 0, 0, 0, 0, -1))
    while cursor <= now:
        d = _day_key(cursor)
        heat_days.append({"date": d, "tokens": heat.get(d, 0)})
        cursor += 86400

    return {
        "window": {"from": lo, "to": hi, "range": str(range_val or "all")},
        "kpi": {
            "requests": tot["requests"],
            "success": tot["requests"],
            "errors": tot["errors"],
            "success_pct": (round(tot["requests"] * 100.0 /
                                  (tot["requests"] + tot["errors"]), 2)
                            if (tot["requests"] + tot["errors"]) else None),
            "tokens": tot["tokens"],
            "prompt": tot["prompt"],
            "completion": tot["completion"],
            "cached": tot["cached"],
            "usage_missing": tot["usage_missing"],
            "active_days": len(act_days),
            "streak_days": streak,
            "top_model": (top_models[0] if top_models else None),
        },
        "top_accounts": _rank(accounts, top_n),
        "top_providers": _rank(providers, top_n),
        "models": _rank(models, 10),
        "providers": _rank(providers, 10),
        "cache": {"windows": cache_rows},
        "full_price": {
            "requests": full_price["requests"],
            "prompt": full_price["prompt"],
            "credit": round(full_price["credit"], 2),
            "credit_share": (round(full_price["credit"] * 100.0 / total_credit, 1)
                             if total_credit > 0 else None),
            "threshold": FULL_PRICE_PROMPT_MIN,
        },
        "hourly": {"points": hours},
        "heatmap": {"days": heat_days},
    }

def cached_usage_report(kind, ttl=10, **params):
    builders = {
        "stats": lambda **kw: compute_usage_stats(
            range_val=kw.get("range"), since=kw.get("since"),
            until=kw.get("until")),
        "analytics": lambda **kw: compute_usage_stats(
            range_val=kw.get("range"), since=kw.get("since"),
            until=kw.get("until")),
    }
    builder = builders.get(str(kind or "stats"), builders["stats"])
    fingerprint = _usage_log_fingerprint()
    metadata = []
    for account in (POOL.accounts if POOL else []):
        row = [getattr(account, "uid", ""), _account_label(account),
               getattr(account, "realm", "")]
        if kind == "analytics":
            row.extend([getattr(account, "host", "")
                        or getattr(account, "domain", ""),
                        getattr(account, "credits", None)])
        metadata.append(row)
    meta = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
    day = time.strftime("%Y-%m-%d", time.localtime())
    key = (kind, tuple(sorted(params.items())), fingerprint, day,
           os.environ.get("TZ", ""), time.tzname, meta, FULL_PRICE_PROMPT_MIN)
    return _USAGE_REPORT_CACHE.get(
        key, lambda: builder(**params), ttl=ttl,
        valid=lambda: _usage_log_fingerprint() == fingerprint)
