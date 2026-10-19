
"""_refresh_pricing.py —— 从 OpenRouter 生成 Trae 模型参考价快照。

用法：
    python _refresh_pricing.py            # 联网刷新 pricing/trae_pricing.json
    python _refresh_pricing.py --no-live  # 只打印当前快照覆盖

说明：Trae 没有官方货币价格；这里只做「参考花费」，找不到同名的模型留空，
绝不拿别的模型价格硬套（同系列近似会写 exact=false + note）。
"""
import argparse
import datetime
import json
import os
import re
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "pricing", "trae_pricing.json")
CATALOGS = ("trae_catalog_intl.json", "trae_catalog_cn.json")
OPENROUTER = "https://openrouter.ai/api/v1/models"

# 精确同名 / 官方 ID 映射（人工核对；exact=True）
MANUAL = {
    "aws_claude_4.7_opus": "anthropic/claude-opus-4.7",
    "aws_claude_4.6_sonnet": "anthropic/claude-sonnet-4.6",
    "gpt-6-astra": "openai/gpt-6-astra",
    "gpt-5.5": "openai/gpt-5.5",
    "gemini_3.1_pro": "google/gemini-3.1-pro-preview",
    "gemini_3_flash": "google/gemini-3-flash-preview",
    "gemini-2.5-pro-latest": "google/gemini-2.5-pro",
    "gemini_2.5_flash_premium": "google/gemini-2.5-flash",
    "kimi-k2": "moonshotai/kimi-k2-0905",
    "kimi-k3": "moonshotai/kimi-k3",
    "kimi-k2.7-code": "moonshotai/kimi-k2.7-code",
    "minimax-m3": "minimax/minimax-m3",
    "glm-5.3": "z-ai/glm-5.3",
    "glm-5.3-flash": "z-ai/glm-5.3-flash",
    "glm-5.3-flashx": "z-ai/glm-5.3-flashx",
    "glm-5.2": "z-ai/glm-5.2",
    "deepseek-v4.1-flash": "deepseek/deepseek-v4.1-flash",
    "DeepSeek-V4-Flash-Official": "deepseek/deepseek-v4-flash",
    "DeepSeek-V4-Pro-Official": "deepseek/deepseek-v4-pro",
    "deepseek-V3-0324": "deepseek/deepseek-chat-v3-0324",
    "deepseek-R1": "deepseek/deepseek-r1",
    "mimo-v2.6-flash": "xiaomi/mimo-v2.6-flash",
    "mimo-v2.6-pro": "xiaomi/mimo-v2.6-pro",
    "step-5-preview": "stepfun/step-5-preview",
    "qwen3.8-flash": "qwen/qwen3.8-flash",
    "qwen3.8-max": "qwen/qwen3.8-max-prime",
    "qwen-3.7-plus": "qwen/qwen3.7-plus",
    "Doubao-Seed-2.1-Turbo": "bytedance-seed/seed-2-1-turbo",
}

# 同系列近似（exact=False，note 说明；只在没有精确名时使用）
APPROX = {
    "deepseek-V3": ("deepseek/deepseek-chat-v3.1", "同系列 V3.1 参考价"),
    "Doubao-Seed-Code": ("bytedance-seed/seed-2.0-code", "同系列 Seed-2.0-Code 参考价"),
    "grok-4": ("x-ai/grok-4.3", "同系列 Grok-4.3 参考价"),
    "kimi-k2.8-preview": ("moonshotai/kimi-k2.7-code", "Kimi K2.7-Code 同系列参考价"),
}

USD_CNY = 7.1


def fetch():
    req = urllib.request.Request(OPENROUTER, headers={"User-Agent": "trae2api-hub"})
    with urllib.request.urlopen(req, timeout=40) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    out = {}
    for item in data.get("data") or []:
        if isinstance(item, dict) and item.get("id"):
            out[item["id"]] = item
    return out


EXTRA_MODELS = (
    ("deepseek-V3", "DeepSeek-V3"),
    ("deepseek-V3-0324", "DeepSeek-V3"),
    ("deepseek-R1", "DeepSeek-R1"),
    ("seed_m8", "Doubao-1.5-pro"),
    ("Doubao_1_5_thinking_pro", "Doubao-1.5-thinking-pro"),
)


def catalog_models():
    seen = {}
    for name in CATALOGS:
        path = os.path.join(HERE, name)
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        for item in data.get("models") or []:
            key = str(item.get("name") or item.get("upstream_key") or "").strip()
            if key and key not in seen:
                seen[key] = item
    for key, display in EXTRA_MODELS:
        if key not in seen:
            seen[key] = {"name": key, "display_name": display}
    return list(seen.values())


def norm(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def flat_of(pricing):
    if not isinstance(pricing, dict):
        return None
    def num(key, default=0.0):
        try:
            return float(pricing.get(key) or default) * 1000000.0
        except (TypeError, ValueError):
            return default
    prompt = num("prompt")
    out = num("completion")
    raw_hit = pricing.get("input_cache_read")
    hit = num("input_cache_read") if raw_hit not in (None, "") else prompt
    if prompt <= 0 and out <= 0:
        return None
    return {"input_cache_hit": round(hit, 8),
            "input_cache_miss": round(prompt, 8),
            "output": round(out, 8)}


def bands_of(pricing):
    bands = []
    for over in (pricing or {}).get("overrides") or []:
        try:
            minimum = int(over.get("min_prompt_tokens") or 0)
        except (TypeError, ValueError):
            continue
        flat = flat_of(over)
        if minimum and flat:
            bands.append({"min_prompt_tokens": minimum, "flat": flat})
    return bands


def build(or_models, models):
    by_norm = {}
    for oid in or_models:
        by_norm.setdefault(norm(oid.split("/")[-1]), []).append(oid)
    prices = {}
    for item in models:
        name = str(item.get("name") or "").strip()
        display = str(item.get("display_name") or name)
        if not name:
            continue
        oid = MANUAL.get(name)
        exact = True
        note = ""
        if oid not in or_models:
            approx = APPROX.get(name)
            if approx:
                oid, note = approx
                exact = False
            else:
                oid = None
        if not oid:
            # 模糊：模型名 / 显示名与 OpenRouter 后缀归一一致
            for candidate in (name, display):
                hits = by_norm.get(norm(candidate)) or []
                if len(hits) == 1:
                    oid, exact = hits[0], False
                    note = "按官方模型名匹配"
                    break
        if not oid or oid not in or_models:
            continue
        flat = flat_of(or_models[oid].get("pricing") or {})
        if not flat:
            continue
        entry = {
            "display": display,
            "source": "openrouter",
            "currency": "USD",
            "unit": 1000000,
            "or_id": oid,
            "exact": bool(exact),
            "flat": flat,
        }
        bands = bands_of(or_models[oid].get("pricing") or {})
        if bands:
            entry["bands"] = bands
        if note:
            entry["note"] = note
        prices[name] = entry
    return prices


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-live", action="store_true")
    args = ap.parse_args()
    models = catalog_models()
    if args.no_live:
        data = json.load(open(OUT, encoding="utf-8"))
        print("快照 %d 个模型，覆盖 %d 个目录模型"
              % (len(data.get("models") or {}), len(models)))
        return
    or_models = fetch()
    prices = build(or_models, models)
    data = {
        "meta": {
            "generated_at": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "base_currency": "USD",
            "usd_cny": USD_CNY,
            "source": OPENROUTER,
            "note": "参考价，不是 Trae 官方账单；exact=false 为同系列近似",
        },
        "models": prices,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)
    print("写入 %s：%d / %d 个模型有参考价"
          % (OUT, len(prices), len(models)))
    for name in sorted(prices)[:10]:
        print("  %-32s %s" % (name, prices[name]["or_id"]))


if __name__ == "__main__":
    main()
