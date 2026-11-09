"""费用估算（参考 OpenRouter 公布价，issue: 跟进 wb 的「等价 token 花费」）。

口径说明（与官方积分不是一回事）：
  · 输入按「缓存命中 / 未命中」两档单价拆分，输出单独单价；
  · 单价单位为 USD / 1M tokens；
  · 只用于「这些 token 放在 OpenRouter 上大概值多少钱」的参考估算，**不能用于结算**。

价格来源优先级：
  1. usage/pricing-overrides.json（用户手填，键为模型 key 或显示名）
  2. trae_catalog 的模型 key 静态表（本文件 DEFAULT_PRICES）
  3. 未知模型 -> 不计价（面板显示 —，绝不猜数字）
"""
import json
import os

# USD / 1M tokens: (输入未命中, 输入缓存命中, 输出)
DEFAULT_PRICES = {
    "dfmodel": (0.28, 0.028, 0.42),        # DeepSeek-V4-Flash
    "dmodel": (0.55, 0.14, 2.19),          # DeepSeek-V4-Pro
    "gmodel": (0.60, 0.15, 2.20),          # GLM-5.3
    "gfmodel": (0.06, 0.015, 0.40),        # GLM-5.3-Flash
    "kmodel": (0.60, 0.15, 2.50),          # Kimi-K2.8
    "kmodel_latest": (0.60, 0.15, 2.50),   # Kimi-K3（同族，先按此档）
    "qmodel": (0.40, 0.10, 1.20),          # Qwen3.7-Plus
    "qmodel_latest": (1.20, 0.30, 6.00),   # Qwen3.7-Max
    "qmodel_38max": (1.20, 0.30, 6.00),    # Qwen3.8-Max
    "qfmodel": (0.05, 0.012, 0.20),        # Qwen3.8-Flash
    "mmodel": (0.30, 0.075, 1.20),         # MiniMax-M3
    "cmodel": (3.00, 0.75, 15.00),         # Cantus
}

# 目录里的别名键 -> 计价键（agent 页/模型卡可能用这些名字）
ALIASES = {
    "deepseek": "dfmodel", "deepseek-flash": "dfmodel",
    "deepseek-v4-flash": "dfmodel", "deepseek-v4-pro": "dmodel",
    "glm": "gmodel", "glm-5.3": "gmodel", "glm-5.3-flash": "gfmodel",
    "kimi": "kmodel", "kimi-k2.8-preview": "kmodel", "kimi-k3": "kmodel_latest",
    "qwen3.7-plus": "qmodel", "qwen3.7-max": "qmodel_latest",
    "qwen3.8-max": "qmodel_38max", "qwen3.8-flash": "qfmodel",
    "minimax-m3": "mmodel", "cantus": "cmodel",
}


def _norm(name):
    return str(name or "").strip().lower()


def load_overrides(usage_dir):
    """读用户覆盖表（usage/pricing-overrides.json）；损坏时返回 {}。"""
    try:
        path = os.path.join(usage_dir or "", "pricing-overrides.json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return {}
    out = {}
    if not isinstance(data, dict):
        return out
    for key, val in data.items():
        try:
            if isinstance(val, dict):
                out[_norm(key)] = (float(val.get("in", 0)),
                                   float(val.get("cached", val.get("in", 0))),
                                   float(val.get("out", 0)))
            elif isinstance(val, (list, tuple)) and len(val) == 3:
                out[_norm(key)] = tuple(float(x) for x in val)
        except Exception:
            continue
    return out


def price_for(name, overrides=None):
    """返回 (in, cached_in, out) 或 None（未知模型不计价）。"""
    key = _norm(name)
    if not key:
        return None
    ov = overrides or {}
    if key in ov:
        return ov[key]
    if key in DEFAULT_PRICES:
        return DEFAULT_PRICES[key]
    if key in ALIASES:
        return DEFAULT_PRICES.get(ALIASES[key])
    # 前缀/后缀继承：deepseek-v4-flash-0731 -> deepseek-v4-flash
    for alias, target in ALIASES.items():
        if key.startswith(alias + "-") or key.startswith(alias + "_"):
            return DEFAULT_PRICES.get(target)
    return None


def cost_of(name, prompt_tokens=0, cached_tokens=0, completion_tokens=0,
            overrides=None):
    """按 tokens 折算 USD；未知模型返回 None。"""
    price = price_for(name, overrides)
    if price is None:
        return None
    pin, pcached, pout = price
    prompt = max(0, int(prompt_tokens or 0))
    cached = min(prompt, max(0, int(cached_tokens or 0)))
    out = max(0, int(completion_tokens or 0))
    return ((prompt - cached) * pin + cached * pcached + out * pout) / 1e6


def table(usage_dir=None):
    """对外输出：生效价格表 + 来源（含用户覆盖标记）。"""
    ov = load_overrides(usage_dir) if usage_dir else {}
    rows = {}
    for key, (pin, pcached, pout) in DEFAULT_PRICES.items():
        rows[key] = {"in": pin, "cached": pcached, "out": pout,
                     "source": "builtin"}
    for key, (pin, pcached, pout) in ov.items():
        rows[key] = {"in": pin, "cached": pcached, "out": pout,
                     "source": "override"}
    return rows