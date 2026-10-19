
"""trae_pricing.py —— 公开 token 价格估算（OpenRouter 口径，零第三方依赖）

参考 WorkBuddy2API-Hub 的做法：用 OpenRouter 公开价格做「参考花费」，不冒充
Trae 官方账单。Trae 官方目录没有货币价格，所以：

  - 只有能在 OpenRouter 找到同名/同系列模型的条目才计价；
  - 找不到的模型 priced=False、cost=0，看板显示「未定价」，绝不猜；
  - 价格单位：USD / 1M tokens；同时按 usd_cny 折算人民币；
  - 长上下文 overrides 用 bands（min_prompt_tokens）表达；
  - 缓存命中率用 cached_tokens/prompt_tokens 计，未命中走 input_cache_miss。

数据文件：pricing/trae_pricing.json（_refresh_pricing.py 生成）。
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PRICING_PATH = os.path.join(HERE, "pricing", "trae_pricing.json")
_DEFAULT_USD_CNY = 7.1
_cache = {"mtime": None, "data": None}
_lock = __import__("threading").RLock()


def load_pricing(force=False):
    try:
        mtime = os.path.getmtime(PRICING_PATH)
    except OSError:
        mtime = None
    with _lock:
        if not force and _cache["data"] is not None and _cache["mtime"] == mtime:
            return _cache["data"]
        try:
            with open(PRICING_PATH, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            data = {"meta": {}, "models": {}}
        if not isinstance(data, dict):
            data = {"meta": {}, "models": {}}
        data.setdefault("models", {})
        data.setdefault("meta", {})
        _cache.update({"mtime": mtime, "data": data})
        return data


def usd_cny(pricing=None):
    pricing = pricing or load_pricing()
    try:
        value = float((pricing.get("meta") or {}).get("usd_cny") or _DEFAULT_USD_CNY)
    except (TypeError, ValueError):
        value = _DEFAULT_USD_CNY
    return value if value > 0 else _DEFAULT_USD_CNY


def _as_float(value, default=0.0):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _norm(value):
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def entry_for(model, pricing=None):
    """按 Trae 模型名查价；支持 upstream_key / 显示名 / 去标点归一。"""
    pricing = pricing or load_pricing()
    models = pricing.get("models") or {}
    if not model:
        return None
    name = str(model)
    for key in (name, name.lower()):
        if isinstance(models.get(key), dict):
            return models[key]
    target = _norm(name)
    for key, entry in models.items():
        if not isinstance(entry, dict):
            continue
        names = [key, entry.get("display"), entry.get("or_id")]
        names.extend(entry.get("aliases") or [])
        if any(_norm(candidate) == target for candidate in names if candidate):
            return entry
    return None


def _rate(entry, prompt_tokens):
    flat = entry.get("flat") or {}
    rate = dict(flat)
    bands = entry.get("bands") or []
    chosen = None
    for band in bands:
        try:
            minimum = int(band.get("min_prompt_tokens") or 0)
        except (TypeError, ValueError):
            continue
        if prompt_tokens >= minimum and (chosen is None or minimum >= chosen[0]):
            chosen = (minimum, band)
    if chosen:
        rate.update(chosen[1].get("flat") or {})
        return rate, chosen[0]
    return rate, None


def compute(model, prompt_tokens=0, completion_tokens=0, cached_tokens=0,
            pricing=None):
    """单次调用参考花费（USD / CNY）。返回 dict，未知模型 priced=False。"""
    pricing = pricing or load_pricing()
    entry = entry_for(model, pricing)
    if not entry:
        return {"usd": 0.0, "cny": 0.0, "priced": False,
                "band": None, "rates": None, "or_id": None}
    prompt = max(0, _as_float(prompt_tokens))
    completion = max(0, _as_float(completion_tokens))
    cached = min(max(0, _as_float(cached_tokens)), prompt)
    uncached = prompt - cached
    rate, band = _rate(entry, prompt)
    miss = _as_float(rate.get("input_cache_miss"), _as_float(rate.get("prompt")))
    hit = _as_float(rate.get("input_cache_hit"), miss)
    out = _as_float(rate.get("output"), _as_float(rate.get("completion")))
    unit = _as_float(entry.get("unit"), 1000000.0) or 1000000.0
    usd = (uncached * miss + cached * hit + completion * out) / unit
    return {"usd": round(usd, 8), "cny": round(usd * usd_cny(pricing), 6),
            "priced": True, "band": band, "rates": rate,
            "or_id": entry.get("or_id"), "exact": entry.get("exact", True)}


def compute_row(row, pricing=None):
    if not isinstance(row, dict):
        return {"usd": 0.0, "cny": 0.0, "priced": False, "band": None,
                "rates": None, "or_id": None}
    return compute(row.get("model"), row.get("prompt_tokens"),
                   row.get("completion_tokens"), row.get("cached_tokens"),
                   pricing=pricing)


def annotate_row(row, pricing=None):
    """给 usage 行补 cost_usd / cost_cny / priced / price_band（原地+返回）。"""
    cost = compute_row(row, pricing=pricing)
    row["cost_usd"] = cost["usd"]
    row["cost_cny"] = cost["cny"]
    row["priced"] = bool(cost["priced"])
    if cost.get("band") is not None:
        row["price_band"] = cost["band"]
    return row


def summarize(rows, pricing=None):
    """批量汇总：USD/CNY、已定价/未定价行数与未定价模型集合。"""
    total_usd = 0.0
    priced = 0
    missing = {}
    for row in rows or []:
        cost = compute_row(row, pricing=pricing)
        total_usd += cost["usd"]
        if cost["priced"]:
            priced += 1
        else:
            model = str((row or {}).get("model") or "?")
            missing[model] = missing.get(model, 0) + 1
    return {"usd": round(total_usd, 8),
            "cny": round(total_usd * usd_cny(pricing), 6),
            "priced_rows": priced,
            "total_rows": len(rows or []),
            "missing": missing}
