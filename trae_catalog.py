# -*- coding: utf-8 -*-
"""trae_catalog.py —— Trae 双区模型目录（运行时唯一入口）

一句话：目录是数据，不是代码。本模块只做四件事——读快照、建索引、
出 OpenAI /v1/models 条目、把客户端传来的模型名解析成上游 model_name。

数据来源（双区实测 · 见 .team/PROTOCOL.md 第八节）
--------------------------------------------------
trae_catalog_intl.json / trae_catalog_cn.json 由 _refresh_catalog.py 从本机
官方客户端 SQLite 缓存**只读**导出：

    国际版  %APPDATA%/Trae/User/globalStorage/state.vscdb
    国内版  %APPDATA%/Trae CN/User/globalStorage/state.vscdb

    ItemTable.key = "<uid>_AI.agent.model.model_list_map"
    value        = JSON: {分组 -> [模型对象, ...]}

实测分组：builder / builder_v3 / chat_v3 / code_reviewer /
code_review_summary / refactor / solo_agent。
"chat 面"按 CHAT_GROUPS_PRIORITY 逐组合并去重：

    国际版 10 个（chat_v3 / builder_v3 / builder 三组同集）
    国内版 20 个（chat_v3）

模型对象里**全是上游真字段**，本模块不造：
    name（上游 model_name）/ display_name / model_type / multimodal /
    context_window_size{max[],default} / context_window_tokens{dev,max} /
    max_tokens（上游自己的输出上限字段）/ is_default / is_new / status /
    selectable / reasoning_effort_config / features{...} / ...
官方目录**不含货币价格**：entry 的 price 恒为 None（缺失就留空，绝不编造）；
唯一与"钱"有关的是 features.consumption_rate.data.rate（信用消费倍率），
有就原样透传到 entry["consumption_rate"]，没有就是 None。

对外 API（网关只依赖这些，其余都是内部实现）
--------------------------------------------
    load_snapshot(realm)                读快照（按文件 mtime 缓存）
    models_for_realm(realm)             chat 面条目（/v1/models 用）
    all_models(realm)                   全部条目（含 solo_agent 等内部组）
    model_entry(model, realm=None)      OpenAI /v1/models 单条
    catalog_payload(realm)             {"object":"list","data":[...]}
    resolve_upstream_key(model, realm)  客户端名 -> 上游 model_name
    available_models(realm, ...)        CN 动态 model_list 优先，失败回落快照
    realm_exclusive_models(realm)       该区独占 key（另一区没有）
    key_realm_span(key) / model_realm(key)
    auto_realm_for_model(model, cur)    只在能明确判定时给区域（判不准就 None）
    snapshot_source(realm) / snapshot_report()
    set_account_provider(fn)            网关注入"按区取账号"回调（启用 CN 动态）

命名解析（resolve_upstream_key）——**精确优先，绝不"就近猜"**：
    1) raw 与社会上游真名完全相等（大小写敏感）          -> 原样返回
    2) 动态 model_list 登记的上游实名（大小写不敏感）      -> 返回实名
    3) 快照 name / display_name / 别名完全相等（大小写不敏感）
    4) 去掉 " (显示名)" 尾巴、"vendor/" 前缀后重做 1~3
    5) 整名规范化（slug / 去标点 compact / 语义 token 集合）完全相等
    6) 都不中 -> 原样返回（交给上游，4023 就 4023，绝不乱映射）

    **不做子集/超集猜测**：deepseek-V3 就是 deepseek-V3，不会被猜成
    deepseek-V3.1（后者在快照里，但上游 model_list 里没有，猜过去就是 4023）。
    同理 "gpt-6" 不再自动展开成 gpt-6-astra —— 想要就写全名。

可用性（available）
-------------------
available_models(realm) 返回的是**可用集视角**：
    · 动态 model_list 成功（source="dynamic"）：能调用的 key available=True；
      快照里多出来的模型仍然列出，但 available=False（展示用，别当能用）；
    · 拉取失败（source="snapshot:<原因>"）：没有实时信息，快照条目一律
      available=True（尽力而为），调用方按 source 自行判断可信度。
catalog_payload(realm, live=True) 就是这条口径的 /v1/models body。

区域独占判定
------------
raw 数据里两区几乎不重叠（只有 minimax-m3 这类同名 key 双区都有），
所以"独占"是**算出来的**，不是写死的：
    realm_exclusive_models("cn")    # -> {key: display_name}
    is_exclusive_to(key, "cn")      # -> True/False
网关可用 auto_realm_for_model 做双区自动路由；同名同型号一律不猜。

自检 / 导出
-----------
    python trae_catalog.py                 # 打印双区清单 + 验收断言（退出码 0/1）
    python trae_catalog.py --payload cn    # 打印 /v1/models 的 JSON body
"""

from __future__ import annotations

import json
import os
import re
import threading

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

REALMS = ("cn", "intl")

SNAPSHOT_FILES = {"intl": "trae_catalog_intl.json",
                  "cn": "trae_catalog_cn.json"}

#: chat 面分组优先级（前者优先；同 key 以先出现者为准）
CHAT_GROUPS_PRIORITY = ("chat_v3", "builder_v3", "builder")

#: 快照 schema 版本（结构变更时 +1，_refresh_catalog 会写入）
SNAPSHOT_SCHEMA = 1

#: 导出时丢弃的字段：客户端自定义模型可能带真实密钥，快照要进仓库，一律不落盘
DROP_FIELDS = ("sk", "ak", "base_url", "custom_model_id", "auth_type",
               "client_connect", "is_custom_base_url")

#: 语义匹配时视为"噪声"的 token（厂商/路由/状态词，不参与区分型号）
SOFT_TOKENS = frozenset((
    "aws", "azure", "vertex", "gcp", "google", "official", "latest",
    "preview", "beta", "trae", "api", "v1", "model",
))

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOKEN_RE = re.compile(r"[^a-z0-9]+")
_BUILD_NUM_RE = re.compile(r"^\d{4,}$")

_SNAPSHOT_CACHE = {}        # realm -> {"path","mtime","size","data"}
_INDEX_CACHE = {}           # realm -> _Index
_LOCK = threading.RLock()

_AVAIL_CACHE = {}           # "realm|account" -> {"ts","models","source","merge"}
_AVAIL_LAST = {}            # realm -> 最近一次用的 cache key
_AVAIL_LAST_SOURCE = {}     # realm -> 最近一次来源（注入 fetcher 时也记录）
_DYNAMIC_TTL = 600          # 动态 model_list 的默认缓存秒数

_account_provider = None    # 网关注入：realm -> account dict（可为 None）


def _warn(msg):
    try:
        print("[trae-catalog] WARNING: %s" % msg)
    except Exception:
        pass


def normalize_realm(realm):
    """把任意区域写法归一成 "cn" / "intl"（未知一律按 cn，与旧行为一致）。"""
    value = str(realm or "").strip().lower()
    if value in ("intl", "international", "global", "us", "sg", "trae"):
        return "intl"
    return "cn"


# ---------------------------------------------------------------------------
# 文本规范化（解析用）
# ---------------------------------------------------------------------------

def _tokens(text):
    return [t for t in _TOKEN_RE.split(str(text or "").lower()) if t]


def name_slug(text):
    """小写 + 非字母数字压成 "-"： "Claude-Opus-4.7" -> "claude-opus-4-7"。"""
    return "-".join(_tokens(text))


def name_compact(text):
    """只留字母数字： "Claude-Opus-4.7" -> "claudeopus47"。"""
    return "".join(_tokens(text))


def name_canon(text):
    """语义 token 集合（排序元组）：去软词 + 去 4 位以上构建号。"""
    return tuple(sorted(t for t in _tokens(text)
                        if t not in SOFT_TOKENS and not _BUILD_NUM_RE.match(t)))


# ---------------------------------------------------------------------------
# 快照读取
# ---------------------------------------------------------------------------

def _empty_snapshot(realm, reason):
    return {"schema": SNAPSHOT_SCHEMA, "realm": realm,
            "generated_at": None, "source": {"kind": "missing", "reason": reason},
            "chat_groups": list(CHAT_GROUPS_PRIORITY), "primary_group": None,
            "models": []}


def _normalize_snapshot(raw, realm, path):
    """把文件内容归一成快照 dict（兼容裸 list 的旧格式）。"""
    if isinstance(raw, list):
        return {"schema": 0, "realm": realm, "generated_at": None,
                "source": {"kind": "bare-list", "file": os.path.basename(path)},
                "chat_groups": list(CHAT_GROUPS_PRIORITY), "primary_group": None,
                "models": [m for m in raw if isinstance(m, dict)]}
    if not isinstance(raw, dict):
        raise ValueError("snapshot is neither dict nor list")
    models = raw.get("models")
    if not isinstance(models, list):
        raise ValueError("snapshot has no 'models' list")
    raw["realm"] = raw.get("realm") or realm
    raw.setdefault("chat_groups", list(CHAT_GROUPS_PRIORITY))
    raw.setdefault("source", {"kind": "file"})
    raw["models"] = [m for m in models if isinstance(m, dict)]
    return raw


def load_snapshot(realm, path=None, force=False):
    """读取该区域快照（文件 mtime 变化会自动重载）。缺失时返回空快照并告警。"""
    realm = normalize_realm(realm)
    path = path or os.path.join(_HERE, SNAPSHOT_FILES[realm])
    with _LOCK:
        try:
            stat = os.stat(path)
            stamp = (stat.st_mtime, stat.st_size)
        except OSError:
            stamp = None
        cached = _SNAPSHOT_CACHE.get(realm)
        if (not force and cached and cached["path"] == path
                and cached["stamp"] == stamp and stamp is not None):
            return cached["data"]
        if stamp is None:
            _warn("snapshot %s 不存在：该区 /v1/models 将为空（跑 _refresh_catalog.py）"
                  % os.path.basename(path))
            data = _empty_snapshot(realm, "file-missing")
        else:
            try:
                with open(path, encoding="utf-8") as fh:
                    raw = json.load(fh)
                data = _normalize_snapshot(raw, realm, path)
            except Exception as exc:                       # noqa: BLE001
                _warn("snapshot %s 读取失败(%s)：按空快照处理"
                      % (os.path.basename(path), exc.__class__.__name__))
                data = _empty_snapshot(realm, "unreadable")
        _SNAPSHOT_CACHE[realm] = {"path": path, "stamp": stamp, "data": data}
        _INDEX_CACHE.pop(realm, None)
        return data


def snapshot_source(realm):
    """该区快照的实际来源标签（只读，给 /v1/models 与诊断用）。"""
    src = load_snapshot(realm).get("source") or {}
    return str(src.get("kind") or "unknown")


def snapshot_report():
    """双区快照体检：来源 / 生成时间 / chat 条数 / 全量条数 / 分组。"""
    out = {}
    for realm in REALMS:
        snap = load_snapshot(realm)
        out[realm] = {
            "source": snapshot_source(realm),
            "generated_at": snap.get("generated_at"),
            "chat_models": len(models_for_realm(realm)),
            "all_models": len(all_models(realm)),
            "chat_groups": list(snap.get("chat_groups") or ()),
            "groups": sorted({g for m in all_models(realm)
                              for g in (m.get("groups") or ())}),
            "ambiguous_aliases": sorted(_index(realm).conflicts)[:20],
        }
    return out


# ---------------------------------------------------------------------------
# 条目整形（生成与运行时共用同一套逻辑）
# ---------------------------------------------------------------------------

def _as_int(value):
    return int(value) if isinstance(value, (int, float)) else None


def _max_of(values):
    nums = [int(v) for v in (values or ()) if isinstance(v, (int, float))]
    return max(nums) if nums else None


def _aliases_for(upstream_key, display_name):
    """显示名规范化别名 + 上游真名（去重，顺序：原样 -> slug -> compact）。"""
    out = []
    for candidate in (display_name, upstream_key):
        if not candidate:
            continue
        for form in (str(candidate).strip(), name_slug(candidate),
                     name_compact(candidate)):
            if form and form not in out:
                out.append(form)
    return out


def normalize_model(raw, groups=()):
    """把一个上游模型对象整成快照 entry（纯整形，不改语义、不补假值）。"""
    if not isinstance(raw, dict):
        raise TypeError("model entry must be a dict")
    entry = {k: v for k, v in raw.items() if k not in DROP_FIELDS}

    key = str(raw.get("name") or "").strip()
    display = str(raw.get("display_name") or "").strip()
    entry["upstream_key"] = key
    entry["key"] = key                      # 兼容旧调用（等价于 upstream_key）
    entry["name"] = key
    entry["display_name"] = display or key
    entry["groups"] = [g for g in groups]

    # 上下文窗口：官方同时给 context_window_size 与 context_window_tokens，取各自真值
    cws = raw.get("context_window_size") or {}
    toks = raw.get("context_window_tokens") or {}
    default_ctx = _as_int(cws.get("default")) or _as_int(toks.get("dev"))
    entry["context_window"] = default_ctx
    entry["context_window_max"] = _max_of(cws.get("max")) or _as_int(toks.get("max"))

    # 多模态 / 思考能力：优先 features（结构化），退回顶层布尔
    feats = raw.get("features") or {}
    mm = raw.get("multimodal")
    if mm is None:
        mm = bool((feats.get("multimodal") or {}).get("enable"))
    entry["multimodal"] = bool(mm)

    rec = raw.get("reasoning_effort_config") or {}
    supported = rec.get("support_thinking")
    if supported is None:
        supported = bool((feats.get("reasoning") or {}).get("enable"))
    entry["thinking"] = {
        "supported": bool(supported),
        "options": list(rec.get("options") or ()),
        "default_level": rec.get("default_level"),
    }

    rate = ((feats.get("consumption_rate") or {}).get("data") or {}).get("rate")
    entry["consumption_rate"] = rate if isinstance(rate, (int, float)) else None
    entry["price"] = None                   # 官方目录无货币价格 —— 留空
    entry["enabled"] = bool(raw.get("status")) and raw.get("selectable") is not False

    entry["model_type"] = raw.get("model_type")
    entry["is_default"] = bool(raw.get("is_default"))
    entry["is_new"] = bool(raw.get("is_new"))
    entry["status"] = bool(raw.get("status"))
    entry["aliases"] = _aliases_for(key, entry["display_name"])
    return entry


def build_snapshot(realm, groups_map, source=None, generated_at=None):
    """由「分组 -> 原始模型对象」生成快照 dict（_refresh_catalog.py 调用）。"""
    realm = normalize_realm(realm)
    if not isinstance(groups_map, dict):
        raise TypeError("groups_map must be {group: [model, ...]}")
    chat_groups = [g for g in CHAT_GROUPS_PRIORITY if groups_map.get(g)]
    chat_groups += [g for g in groups_map
                    if g not in CHAT_GROUPS_PRIORITY and groups_map.get(g)]

    seen = {}                                # key -> entry
    counts = {}
    for group in chat_groups:
        items = groups_map.get(group)
        if not isinstance(items, list):
            continue
        counts[group] = len(items)
        for raw in items:
            if not isinstance(raw, dict):
                continue
            key = str(raw.get("name") or "").strip()
            if not key:
                continue
            if key in seen:
                if group not in seen[key]["groups"]:
                    seen[key]["groups"].append(group)
                continue
            seen[key] = normalize_model(raw, [group])

    primary = chat_groups[0] if chat_groups else None
    for entry in seen.values():
        # chat 面 = **主 chat 组**的成员（实测：intl chat_v3/builder 同集 10，
        # cn chat_v3 = 20；builder_v3 另有 kimi-k2.6 等 4 个，仍留在 all_models
        # 里可解析、可点名，只是默认不进 /v1/models —— 口径与验收一致）。
        entry["chat"] = entry["groups"][:1] == [primary]
        entry["realm"] = realm

    models = list(seen.values())
    models.sort(key=lambda e: (0 if e["chat"] else 1,
                               0 if e["is_default"] else 1,
                               str(e["display_name"]).lower()))
    return {
        "schema": SNAPSHOT_SCHEMA,
        "realm": realm,
        "generated_at": generated_at,
        "source": dict(source or {}, groups=counts),
        "chat_groups": [g for g in chat_groups if g in CHAT_GROUPS_PRIORITY],
        "primary_group": primary,
        "models": models,
    }


# ---------------------------------------------------------------------------
# 索引与解析
# ---------------------------------------------------------------------------

class _Index(object):
    """一个区域的查表结构；冲突的别名不会被采用（记在 conflicts 里）。"""

    __slots__ = ("realm", "models", "by_key", "by_lower", "by_slug",
                 "by_compact", "by_canon", "conflicts")

    def __init__(self, realm, models):
        self.realm = realm
        self.models = models
        self.by_key = {}
        self.by_lower = {}
        self.by_slug = {}
        self.by_compact = {}
        self.by_canon = {}
        self.conflicts = set()

        chat_first = sorted(models, key=lambda m: (0 if m.get("chat") else 1,
                                                   0 if m.get("is_default") else 1))
        for entry in chat_first:
            key = entry.get("upstream_key")
            if not key:
                continue
            self.by_key[key] = entry
            names = [key, entry.get("display_name")] + list(entry.get("aliases") or ())
            for raw_name in names:
                if not raw_name:
                    continue
                self._put(self.by_lower, str(raw_name).strip().lower(), key)
                self._put(self.by_slug, name_slug(raw_name), key)
                self._put(self.by_compact, name_compact(raw_name), key)
            canon = name_canon(entry.get("display_name") or key)
            if canon:
                self._put(self.by_canon, canon, key)

    def _put(self, table, token, key):
        if not token:
            return
        current = table.get(token)
        if current is None:
            table[token] = key
        elif current != key:
            # 先到先得：插入顺序已经把 chat 面 + 默认模型排在前面，
            # 所以官方 UI 上真会看到的名字一定解析到主用模型；
            # 冲突只记录用于体检，不丢映射（丢了等于"官方名字点不动"）。
            self.conflicts.add(token if isinstance(token, str)
                               else "-".join(str(t) for t in token))

    def resolve(self, model, fuzzy=True):
        """返回该索引里命中的 upstream_key，未命中返回 None。"""
        raw = str(model or "").strip()
        if not raw:
            return None
        if raw in self.by_key:
            return raw

        name = raw
        if " (" in name and name.endswith(")"):
            head = name.rsplit(" (", 1)[0].strip()
            if head:
                name = head
        if name in self.by_key:
            return name

        low = name.lower()

        # 上游"此刻可用"的真名优先于任何模糊匹配：
        # 上游 model_list 说它叫 deepseek-V3，就别把它猜成快照里的 deepseek-V3.1。
        live = _LIVE_NAMES.get(self.realm) or ()
        if name in live:
            return name
        for live_name in live:
            if live_name.lower() == low:
                return live_name
        aliases = _LIVE_ALIASES.get(self.realm) or {}
        if low in aliases:
            return aliases[low]
        slug_hit = aliases.get("slug:" + name_slug(name))
        if slug_hit:
            return slug_hit
        compact_hit = aliases.get("compact:" + name_compact(name))
        if compact_hit:
            return compact_hit

        if low in self.by_lower:
            return self.by_lower[low]

        if "/" in name:
            tail = name.rsplit("/", 1)[-1].strip()
            if tail and tail != name:
                hit = self.resolve(tail, fuzzy)
                if hit:
                    return hit

        if not fuzzy:
            return None
        # 只有"整名规范化后仍不等"的情况下才用 slug/compact/canon ——
        # 一律不做子集/超集猜测（deepseek-V3 != deepseek-V3.1）。
        for table, token in ((self.by_slug, name_slug(name)),
                             (self.by_compact, name_compact(name))):
            hit = table.get(token) if token else None
            if hit:
                return hit
        canon = name_canon(name)
        if canon:
            return self.by_canon.get(canon)
        return None


def _index(realm):
    realm = normalize_realm(realm)
    with _LOCK:
        index = _INDEX_CACHE.get(realm)
        if index is None:
            index = _Index(realm, all_models(realm))
            _INDEX_CACHE[realm] = index
        return index


def _entry_by_key(realm, key):
    return _index(realm).by_key.get(key)


# ---------------------------------------------------------------------------
# 对外：清单
# ---------------------------------------------------------------------------

def all_models(realm):
    """该区全部条目（chat 面 + solo_agent / code_reviewer / refactor 等内部组）。"""
    return list(load_snapshot(realm).get("models") or ())


def models_for_realm(realm):
    """该区 **chat 面** 条目（/v1/models 用）：国际版 10 / 国内版 20（实测）。"""
    return [m for m in all_models(realm) if m.get("chat")]


def display_names(realm):
    return {m["upstream_key"]: m.get("display_name") or m["upstream_key"]
            for m in models_for_realm(realm)}


def model_entry(model, realm=None, id_style="display"):
    """OpenAI /v1/models 单条。

    model 可以是条目 dict，也可以是任意客户端叫法（会先 resolve 成上游 key）。
    id_style="display"（默认）时 id 用官方显示名，upstream_key 永远是真名；
    id_style="upstream" 时 id 直接是上游 model_name（两种写法都能被 resolve）。
    """
    realm_hint = normalize_realm(realm) if realm else None
    entry = model if isinstance(model, dict) else None
    if entry is None:
        name = str(model or "").strip()
        key = resolve_upstream_key(name, realm=realm) if name else ""
        entry = _entry_by_key(realm_hint, key) if realm_hint else None
        if entry is None:
            for candidate in (("cn", "intl") if realm_hint is None else (realm_hint,)):
                entry = _entry_by_key(candidate, key) or live_entry(candidate, key)
                if entry is not None:
                    realm_hint = candidate
                    break
        if entry is None:
            # 未知模型：如实给最小条目，不臆造能力
            return {"id": name, "object": "model", "created": 0,
                    "owned_by": "trae-%s" % (realm_hint or "cn"),
                    "upstream_key": key or name, "key": key or name,
                    "display_name": name, "aliases": [name],
                    "known": False, "enabled": None, "groups": [],
                    "model_type": None, "multimodal": None,
                    "context_window": None, "context_window_max": None,
                    "max_tokens": None, "is_default": None, "is_new": None,
                    "status": None,
                    "thinking": {"supported": None, "options": [],
                                 "default_level": None},
                    "consumption_rate": None, "price": None,
                    "available": None}

    owner_realm = normalize_realm(realm or entry.get("realm") or "cn")
    key = entry.get("upstream_key") or entry.get("key") or ""
    model_id = entry.get("display_name") or key
    if str(id_style).lower() == "upstream":
        model_id = key
    snap = load_snapshot(owner_realm)
    created = snap.get("generated_at")
    available = entry.get("available")
    if available is None:
        # 没有 available 标记时：该区已经拉过动态清单就按清单判断，
        # 没拉过就是"未知"（None），不假装能用也不假装不能用。
        names = _LIVE_NAMES.get(owner_realm) or set()
        if names:
            available = key in names
    return {
        "id": model_id,
        "object": "model",
        "created": created if isinstance(created, int) else 0,
        "owned_by": "trae-%s" % owner_realm,
        "upstream_key": key,
        "key": key,
        "display_name": entry.get("display_name") or key,
        "aliases": list(entry.get("aliases") or ()),
        "model_type": entry.get("model_type"),
        "multimodal": entry.get("multimodal"),
        "context_window": entry.get("context_window"),
        "context_window_max": entry.get("context_window_max"),
        "max_tokens": entry.get("max_tokens"),
        "is_default": entry.get("is_default"),
        "is_new": entry.get("is_new"),
        "status": entry.get("status"),
        "enabled": entry.get("enabled"),
        "groups": list(entry.get("groups") or ()),
        "thinking": dict(entry.get("thinking") or {"supported": None,
                                                   "options": [],
                                                   "default_level": None}),
        "consumption_rate": entry.get("consumption_rate"),
        "price": entry.get("price"),
        "realm": owner_realm,
        "available": available,
        "known": True,
    }


def catalog_payload(realm, id_style="display", live=False, account=None,
                   fetcher=None, refresh=False):
    """完整 /v1/models body（含来源标注，便于看板/诊断）。

    live=False（默认）：只列快照 chat 面 —— 离线、确定、验收口径（10 / 20）。
    live=True：列 available_models 的结果 —— 每条带 available 标记，
      上游 model_list 里没有的模型 available=False（展示但不算可用）；
      account / fetcher / refresh 透传给 available_models。
    """
    realm = normalize_realm(realm)
    entries = (available_models(realm, account=account, fetcher=fetcher,
                                refresh=refresh)
               if live else models_for_realm(realm))
    data = [model_entry(m, realm=realm, id_style=id_style) for m in entries]
    return {"object": "list", "data": data, "realm": realm,
            "count": len(data),
            "available_count": sum(1 for e in data if e.get("available") is True),
            "catalog_source": available_source(realm) if live
            else snapshot_source(realm)}


# ---------------------------------------------------------------------------
# 对外：名字解析
# ---------------------------------------------------------------------------

def resolve_upstream_key(model, realm=None):
    """客户端模型名 -> 上游 model_name。

    realm 给定时先查该区，再查另一区（跨区指名的模型仍按真名返回，
    是否允许由网关的独占校验决定）；解析不出就原样返回，交给上游判 4023。
    """
    if not model:
        return "auto"
    raw = str(model).strip()
    if not raw:
        return "auto"
    order = ((normalize_realm(realm),) if realm else ("cn", "intl"))
    for candidate in order:
        hit = _index(candidate).resolve(raw)
        if hit:
            return hit
    return raw


def aliases_for(key, realm=None):
    """该模型可被接受的全部写法（真名 / 显示名 / 规范化名）。"""
    realm = normalize_realm(realm) if realm else None
    entry = _entry_by_key(realm, key) if realm else None
    if entry is None:
        for candidate in REALMS:
            entry = _entry_by_key(candidate, key)
            if entry is not None:
                break
    return list(entry.get("aliases") or (key,)) if entry else [key]


def known_client_names(realm=None):
    """该区所有可被接受的写法（key / 显示名 / 别名 + 动态实名）。"""
    names = set()
    for entry in (models_for_realm(realm) if realm else
                  all_models("cn") + all_models("intl")):
        names.add(entry.get("upstream_key") or entry.get("key"))
        names.update(entry.get("aliases") or ())
    for candidate in (("cn", "intl") if realm is None else (normalize_realm(realm),)):
        names.update(_LIVE_NAMES.get(candidate) or ())
    names.discard(None)
    return names


# ---------------------------------------------------------------------------
# 对外：区域判定
# ---------------------------------------------------------------------------

def realm_keys(realm):
    return set(m.get("upstream_key") for m in models_for_realm(realm))


def key_realm_span(key):
    """该上游 key 出现在哪些区域的 chat 面： ('cn',) / ('intl',) / ('cn','intl')。"""
    return tuple(r for r in ("cn", "intl") if key in realm_keys(r))


def model_realm(key):
    """同 key_realm_span，名字更好读。"""
    return key_realm_span(key)


def realm_exclusive_models(realm):
    """该区独占的 chat 面模型 {key: display_name}（另一区没有同名 key）。"""
    realm = normalize_realm(realm)
    other = "intl" if realm == "cn" else "cn"
    theirs = realm_keys(other)
    return {m["upstream_key"]: m.get("display_name") or m["upstream_key"]
            for m in models_for_realm(realm) if m["upstream_key"] not in theirs}


def is_exclusive_to(key, realm):
    realm = normalize_realm(realm)
    other = "intl" if realm == "cn" else "cn"
    return key in realm_keys(realm) and key not in realm_keys(other)


def _exclusive(realm):
    return set(realm_exclusive_models(realm))


# 兼容旧名：惰性算好的独占集合（首次访问时按快照填充）
INTL_EXCLUSIVE = set()
CN_EXCLUSIVE = set()
INTL_EXCLUSIVE_PREFIXES = ("aws_", "gpt-", "gemini", "grok", "claude")
CN_EXCLUSIVE_PREFIXES = ("doubao-", "qwen", "glm-", "kimi", "mimo-", "step-",
                         "minimax", "deepseek")


def refresh_exclusive_sets():
    """重算并回填 INTL_EXCLUSIVE / CN_EXCLUSIVE（快照换文件后调用）。"""
    global INTL_EXCLUSIVE, CN_EXCLUSIVE
    INTL_EXCLUSIVE = _exclusive("intl")
    CN_EXCLUSIVE = _exclusive("cn")
    return INTL_EXCLUSIVE, CN_EXCLUSIVE


def exclusive_sets():
    """(intl 独占 key 集合, cn 独占 key 集合)，按当前快照实时计算。"""
    return refresh_exclusive_sets()


def auto_realm_for_model(model_id, current_realm):
    """只在能明确判定时给出目标区域，返回 (realm|None, reason)。

    规则：
      1) 名字只在某一个区能解析出来 -> 用该区；
      2) 两区都能解析 -> 若指向上游同一个 key，判为同名同型号，不路由；
         否则不猜（同名不同型号，猜错比不猜更糟）；
      3) 解析不出来 -> None。
    """
    if not model_id:
        return None, ""
    current = normalize_realm(current_realm)
    hits = {}
    for candidate in REALMS:
        hit = _index(candidate).resolve(str(model_id))
        if hit:
            hits[candidate] = hit
    if not hits:
        return None, ""
    if len(hits) == 1:
        only = next(iter(hits))
        if only != current:
            return only, "model '%s' 只在 %s 存在" % (model_id, only)
        return None, ""
    if len(set(hits.values())) == 1:
        return None, ""
    return None, ("'%s' 在两区指向不同上游（cn=%s / intl=%s）——不猜"
                  % (model_id, hits.get("cn"), hits.get("intl")))


# ---------------------------------------------------------------------------
# 对外：动态 model_list（CN 优先，失败回落快照）
# ---------------------------------------------------------------------------

class DynamicUnavailable(Exception):
    """动态 model_list 不可用（模块缺失 / 无账号 / 上游拒绝）。"""


def set_account_provider(fn):
    """网关注入「按区取账号」回调：fn(realm) -> account dict|None。"""
    global _account_provider
    _account_provider = fn


def _default_fetcher(realm, account=None):
    """默认取数：trae_client.fetch_model_list（协议层，零依赖 urllib）。"""
    try:
        import trae_client
    except Exception as exc:                              # noqa: BLE001
        raise DynamicUnavailable("trae_client 不可用(%s)"
                                 % exc.__class__.__name__)
    fetch = getattr(trae_client, "fetch_model_list", None)
    if fetch is None:
        raise DynamicUnavailable("trae_client.fetch_model_list 未实现")
    if account is None and _account_provider is not None:
        try:
            account = _account_provider(realm)
        except Exception:                                 # noqa: BLE001
            account = None
    try:
        payload = fetch(account, realm)
    except TypeError:
        payload = fetch(account)
    return _coerce_model_list(payload)


def _coerce_model_list(payload):
    """把协议层返回值归一成 list[dict]（list / {"model_configs": [...]} 都收）。"""
    if isinstance(payload, dict):
        for key in ("model_configs", "models", "data", "model_list"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            return []
    if not isinstance(payload, list):
        return []
    return [m for m in payload if isinstance(m, dict) and m.get("name")]


#: 公开别名（_refresh_catalog.py 生成侧与运行时共用同一套归一）
coerce_model_list = _coerce_model_list


def _merge_dynamic(realm, items, source_tag):
    """动态条目整形：**上游 name 原样作 key**，快照只补元数据。

    这里绝不对动态 name 做解析：上游说它叫 deepseek-V3，那就是 deepseek-V3；
    把它"归一"成快照里的 deepseek-V3.1 会让聊天请求直接 4023。
    """
    index = _index(realm)
    merged = []
    for raw in items:
        key = str(raw.get("name") or "").strip()
        if not key:
            continue
        base = index.by_key.get(key)
        if base is not None:
            entry = dict(base)
            entry["groups"] = list(base.get("groups") or ())
            entry["aliases"] = list(base.get("aliases") or ())
            entry["thinking"] = dict(base.get("thinking") or {})
        else:
            entry = {"upstream_key": key, "key": key, "name": key,
                     "display_name": str(raw.get("display_name") or key),
                     "aliases": [key], "groups": [], "chat": True,
                     "realm": realm, "price": None, "consumption_rate": None,
                     "thinking": {"supported": None, "options": [],
                                  "default_level": None},
                     "context_window": None, "context_window_max": None,
                     "max_tokens": None, "is_new": None, "is_beta": None,
                     "model_type": None, "multimodal": None,
                     "is_default": None, "status": None}
        for field in ("display_name", "model_type", "multimodal", "is_default",
                      "status", "is_new", "selectable", "max_tokens",
                      "context_window_size", "context_window_tokens"):
            if raw.get(field) is not None:
                entry[field] = raw[field]
        entry["chat"] = True
        entry["realm"] = realm
        entry["dynamic"] = True
        entry["dynamic_source"] = source_tag
        if raw.get("status") is not None:
            entry["enabled"] = (bool(raw.get("status"))
                                and raw.get("selectable") is not False)
        entry["aliases"] = _aliases_for(key, entry.get("display_name"))
        merged.append(entry)
    return merged


def _snapshot_copy(realm, available=True):
    """快照副本：没有动态信息时，快照条目就是"可用集"（尽力而为）。"""
    models = [dict(m) for m in models_for_realm(realm)]
    for m in models:
        m["dynamic"] = False
        m["available"] = available
    return models


# --- 动态可用名登记（解析与 model_entry 都要认"上游此刻的真名"）------------

_LIVE_NAMES = {"cn": set(), "intl": set()}
_LIVE_ENTRIES = {"cn": {}, "intl": {}}
_LIVE_ALIASES = {"cn": {}, "intl": {}}


def live_names(realm):
    """该区最近一次动态 model_list 的上游可用名（未拉取过返回空集）。"""
    return set(_LIVE_NAMES.get(normalize_realm(realm)) or ())


def live_entry(realm, key):
    """该区动态清单里该上游名的条目（没有返回 None）。"""
    return (_LIVE_ENTRIES.get(normalize_realm(realm)) or {}).get(key)


def note_live_models(realm, entries):
    """登记一次动态清单结果（供 resolve_upstream_key / model_entry 使用）。"""
    realm = normalize_realm(realm)
    names, table, aliases = set(), {}, {}
    for entry in entries or ():
        key = str(entry.get("upstream_key") or "")
        if not key:
            continue
        names.add(key)
        entry = dict(entry)
        entry["available"] = True        # 动态清单里的就是"能用"
        entry["dynamic"] = True
        table[key] = entry
        for raw in ([key, entry.get("display_name"), entry.get("name")]
                    + list(entry.get("aliases") or ())):
            if not raw:
                continue
            text = str(raw).strip()
            if not text:
                continue
            aliases[text.lower()] = key
            slug = name_slug(text)
            if slug:
                aliases["slug:" + slug] = key
            compact = name_compact(text)
            if compact:
                aliases["compact:" + compact] = key
    if names:
        _LIVE_NAMES[realm] = names
        _LIVE_ENTRIES[realm] = table
        _LIVE_ALIASES[realm] = aliases
    return _LIVE_NAMES[realm]


def _account_key(account):
    """缓存键里的账号标识（只取 uid，绝不拼 token）。"""
    if isinstance(account, dict):
        for field in ("userId", "uid", "user_id", "email"):
            value = account.get(field)
            if value:
                return str(value)
    return ""


def available_models(realm, account=None, fetcher=None, refresh=False,
                     ttl=None, merge=True, with_source=False):
    """该区"当前可用"模型条目。

    国内版优先上游 POST /api/ide/v1/model_list（body {"type":"chat"}）：
    那是账号**此刻真正能调用**的清单，字段优先于快照；拉取失败（模块缺失 /
    无账号 / 上游拒绝）回落本地快照。国际版该接口 403 no schema found
    （PROTOCOL §8），直接走快照。

    口径（merge=True，默认）——**动态清单才是"可用集"，快照只做展示/回退**：
      · 动态里有的 key      -> available=True，字段用动态值覆盖（快照补上下文）；
      · 动态里没有的快照条目 -> 保留展示，available=False（明确"不可用"）；
      · 动态里快照没有的 key -> 追加，available=True，缺的字段就是 None（不猜）。
    merge=False 时只返回动态清单（上游此刻能调用的全部）。
    source：成功 = "dynamic"；失败 = "snapshot:<原因>"。

    返回 list[entry]；with_source=True 时返回 (list, source)。
    """
    realm = normalize_realm(realm)
    ttl = _DYNAMIC_TTL if ttl is None else ttl
    import time as _time
    now = _time.time()
    cache_key = "%s|%s" % (realm, _account_key(account))
    cached = _AVAIL_CACHE.get(cache_key)
    if (not refresh and fetcher is None and cached
            and now - cached["ts"] < ttl and cached.get("merge") == merge):
        return (cached["models"], cached["source"]) if with_source else cached["models"]

    fetch = fetcher or _default_fetcher
    try:
        items = _coerce_model_list(fetch(realm, account))
        if not items:
            raise DynamicUnavailable("上游返回空清单")
        live = _merge_dynamic(realm, items, "model_list")
        note_live_models(realm, live)
        models = _surface_models(realm, live) if merge else [
            dict(m, available=True) for m in live]
        source = "dynamic"
    except DynamicUnavailable as exc:
        note_live_models(realm, ())
        models = _snapshot_copy(realm)
        source = "snapshot:%s" % exc
    except Exception as exc:                              # noqa: BLE001
        note_live_models(realm, ())
        models = _snapshot_copy(realm)
        source = "snapshot:error:%s" % exc.__class__.__name__

    if fetcher is None:
        _AVAIL_CACHE[cache_key] = {"ts": now, "models": models, "source": source,
                                   "merge": merge}
    _AVAIL_LAST[realm] = cache_key
    _AVAIL_LAST_SOURCE[realm] = source
    return (models, source) if with_source else models


def _surface_models(realm, live_entries):
    """把"上游可用集"铺开给 /v1/models：快照条目全留，但标 available。

    · 动态里有的 key       -> 字段用动态值覆盖（display_name/status/... 上游此刻为准）
    · 动态里没有的快照条目 -> 保留展示，available=False（不可用，但别让用户以为它消失了）
    · 动态里快照没有的 key -> 追加，available=True，缺的字段就是 None（不猜）
    """
    live = {str(m.get("upstream_key")): m for m in live_entries}
    out = []
    for base in models_for_realm(realm):
        entry = dict(base)
        found = live.pop(entry.get("upstream_key"), None)
        entry["available"] = found is not None
        entry["dynamic"] = found is not None
        if found is not None:
            for field, value in found.items():
                if field in ("groups", "aliases", "thinking"):
                    continue
                if value is not None:
                    entry[field] = value
            entry["groups"] = list(base.get("groups") or ())
            entry["aliases"] = list(base.get("aliases") or ())
            entry["thinking"] = dict(base.get("thinking") or {})
        out.append(entry)
    for entry in live.values():
        entry = dict(entry)
        entry["available"] = True
        entry["dynamic"] = True
        out.append(entry)
    return out


def available_source(realm):
    """最近一次 available_models 的来源标签（未拉取过则 pending）。"""
    realm = normalize_realm(realm)
    if realm in _AVAIL_LAST_SOURCE:
        return _AVAIL_LAST_SOURCE[realm]
    cached = _AVAIL_CACHE.get(_AVAIL_LAST.get(realm) or "")
    return cached["source"] if cached else "snapshot:pending"


# ---------------------------------------------------------------------------
# 兼容垫片（旧 Qoder 时代的调用点还在用这些名字；语义按 Trae 数据重定义）
# ---------------------------------------------------------------------------

def reload():
    """丢掉快照/索引/可用集缓存并重算（快照文件被 _refresh_catalog 重写后调用）。"""
    with _LOCK:
        _SNAPSHOT_CACHE.clear()
        _INDEX_CACHE.clear()
        _AVAIL_CACHE.clear()
        _AVAIL_LAST.clear()
        _AVAIL_LAST_SOURCE.clear()
        for realm in REALMS:
            _LIVE_NAMES[realm] = set()
            _LIVE_ENTRIES[realm] = {}
        _static_init()
        refresh_exclusive_sets()
    return snapshot_report()


def _static_init():
    global STATIC_CN_MODELS, STATIC_INTL_MODELS, STATIC_MODELS, MODEL_ALIASES
    STATIC_CN_MODELS = models_for_realm("cn")
    STATIC_INTL_MODELS = models_for_realm("intl")
    STATIC_MODELS = STATIC_CN_MODELS
    table = {}
    for entry in all_models("cn") + all_models("intl"):
        key = entry.get("upstream_key")
        for alias in entry.get("aliases") or ():
            table.setdefault(alias, key)
    MODEL_ALIASES = table
    return table


STATIC_CN_MODELS = []
STATIC_INTL_MODELS = []
STATIC_MODELS = []
MODEL_ALIASES = {}
_static_init()


def display_id(entry):
    """兼容旧接口：「上游真名 (显示名)」。"""
    key = entry.get("upstream_key") or entry.get("key") or ""
    name = entry.get("display_name") or ""
    return "%s (%s)" % (key, name) if name and name != key else key


def format_model_id(key, realm=None):
    entry = (_entry_by_key(normalize_realm(realm), key) if realm
             else _entry_by_key("cn", key) or _entry_by_key("intl", key))
    return display_id(entry) if entry else key


#: Trae 目录里没有"未开通原因"这类文案（Qoder 时代的常量保留为空串占位，
#: 让旧调用点不会 AttributeError；真需要提示文案请用 status/selectable 判断）。
OFFICIAL_DISABLED_REASON = ""


def official_description(key):
    """Trae 官方目录不含模型介绍文案 —— 返回空串（不编造）。"""
    return ""


def official_local_name(key):
    """Trae 官方目录不含本地化名 —— 返回空串（不编造）。"""
    return ""


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest(verbose=True):
    """返回 (通过数, 失败列表)；打印双区清单与验收断言。"""
    passed, failures = 0, []

    def check(label, ok, detail=""):
        nonlocal passed
        if ok:
            passed += 1
            if verbose:
                print("  [OK] %s" % label)
        else:
            failures.append("%s %s" % (label, detail))
            if verbose:
                print("  [FAIL] %s %s" % (label, detail))

    intl = models_for_realm("intl")
    cn = models_for_realm("cn")
    if verbose:
        print("=" * 72)
        print("快照来源: %s" % json.dumps(snapshot_report(), ensure_ascii=False))
        print("-" * 72)
        for realm, entries in (("intl", intl), ("cn", cn)):
            print("[%s] chat 面 %d 个：" % (realm, len(entries)))
            for m in entries:
                print("   %-28s %-26s %-15s ctx=%-8s multi=%s %s"
                      % (m["upstream_key"], m["display_name"],
                         m.get("model_type"), m.get("context_window"),
                         m.get("multimodal"),
                         "*default" if m.get("is_default") else ""))
        print("-" * 72)
        print("独占: intl=%d cn=%d" % (len(_exclusive("intl")), len(_exclusive("cn"))))

    check("INTL chat 面 = 10", len(intl) == 10, "实际 %d" % len(intl))
    check("CN chat 面 = 20", len(cn) == 20, "实际 %d" % len(cn))
    check("resolve('Claude-Opus-4.7') -> aws_claude_4.7_opus",
          resolve_upstream_key("Claude-Opus-4.7") == "aws_claude_4.7_opus",
          resolve_upstream_key("Claude-Opus-4.7"))
    check("resolve 忽略大小写/标点",
          resolve_upstream_key("claude-opus-4-7") == "aws_claude_4.7_opus",
          resolve_upstream_key("claude-opus-4-7"))
    check("resolve 上游真名原样",
          resolve_upstream_key("aws_claude_4.7_opus") == "aws_claude_4.7_opus")
    check("resolve vendor/ 前缀",
          resolve_upstream_key("trae/Claude-Opus-4.7") == "aws_claude_4.7_opus")
    check("resolve ' (显示名)' 尾巴",
          resolve_upstream_key("aws_claude_4.7_opus (Claude-Opus-4.7)")
          == "aws_claude_4.7_opus")
    check("CN resolve Kimi-K3", resolve_upstream_key("Kimi-K3", "cn") == "kimi-k3",
          resolve_upstream_key("Kimi-K3", "cn"))
    check("CN resolve DeepSeek-V4-Pro -> *-Official",
          resolve_upstream_key("DeepSeek-V4-Pro", "cn") == "DeepSeek-V4-Pro-Official",
          resolve_upstream_key("DeepSeek-V4-Pro", "cn"))
    check("CN resolve Seed-2.1-Turbo",
          resolve_upstream_key("Seed-2.1-Turbo", "cn") == "Doubao-Seed-2.1-Turbo",
          resolve_upstream_key("Seed-2.1-Turbo", "cn"))
    check("精确名优先: deepseek-V3 不被猜成 deepseek-V3.1",
          resolve_upstream_key("deepseek-V3", "cn") == "deepseek-V3",
          resolve_upstream_key("deepseek-V3", "cn"))
    check("精确名优先: deepseek-V3-0324 原样",
          resolve_upstream_key("deepseek-V3-0324", "cn") == "deepseek-V3-0324",
          resolve_upstream_key("deepseek-V3-0324", "cn"))
    check("精确名优先: seed_m8 原样",
          resolve_upstream_key("seed_m8", "cn") == "seed_m8",
          resolve_upstream_key("seed_m8", "cn"))
    check("精确名优先: deepseek-R1 原样",
          resolve_upstream_key("deepseek-R1", "cn") == "deepseek-R1",
          resolve_upstream_key("deepseek-R1", "cn"))
    check("未知模型原样返回",
          resolve_upstream_key("mystery-model-9000") == "mystery-model-9000")
    check("空模型 -> auto", resolve_upstream_key("") == "auto")

    entry = model_entry("Claude-Opus-4.7", realm="intl")
    check("model_entry id = display_name", entry["id"] == "Claude-Opus-4.7", entry["id"])
    check("model_entry upstream_key", entry["upstream_key"] == "aws_claude_4.7_opus")
    check("model_entry 不含货币价格", entry.get("price") is None)
    check("model_entry 有 aliases", len(entry["aliases"]) >= 2)

    realm, _why = auto_realm_for_model("Claude-Opus-4.7", "cn")
    check("auto_realm: Claude-Opus-4.7 -> intl", realm == "intl", str(realm))
    realm2, _why2 = auto_realm_for_model("Kimi-K3", "intl")
    check("auto_realm: Kimi-K3 -> cn", realm2 == "cn", str(realm2))
    realm3, _why3 = auto_realm_for_model("minimax-m3", "cn")
    check("auto_realm: 双区同名 minimax-m3 不猜", realm3 is None, str(realm3))

    check("INTL 独占无 CN 模型",
          not (_exclusive("intl") & realm_keys("cn")),
          sorted(_exclusive("intl") & realm_keys("cn")))
    check("CN 独占含 kimi-k3", "kimi-k3" in _exclusive("cn"))
    check("INTL 独占含 aws_claude_4.7_opus",
          "aws_claude_4.7_opus" in _exclusive("intl"))
    check("key_realm_span('aws_claude_4.7_opus') == ('intl',)",
          key_realm_span("aws_claude_4.7_opus") == ("intl",),
          str(key_realm_span("aws_claude_4.7_opus")))

    check("resolve 官方重名显示名仍可解析（先到先得）",
          resolve_upstream_key("Gemini-2.5-Flash", "intl") in realm_keys("intl"),
          resolve_upstream_key("Gemini-2.5-Flash", "intl"))

    payload = catalog_payload("cn")
    check("catalog_payload cn 20 条", payload["count"] == 20, str(payload["count"]))
    check("catalog_payload intl 10 条",
          catalog_payload("intl")["count"] == 10)
    check("catalog_payload 每条 id 都能 resolve 回 upstream_key",
          all(resolve_upstream_key(e["id"], e["realm"]) == e["upstream_key"]
              for e in payload["data"]),
          [e["id"] for e in payload["data"]
           if resolve_upstream_key(e["id"], e["realm"]) != e["upstream_key"]])

    # --- available_models：动态 model_list 优先 / 失败回落快照 ---
    _fake = lambda realm, account: fake_live            # noqa: E731
    fake_live = [{"name": "kimi-k3", "display_name": "Kimi-K3-Live",
                  "model_type": "chat_model", "multimodal": True,
                  "status": True, "is_default": True},
                 {"name": "seed_m8", "display_name": "Doubao-1.5-pro",
                  "model_type": "chat_model", "multimodal": False,
                  "status": True, "is_default": False}]
    live, live_src = available_models(
        "cn", fetcher=_fake, refresh=True, with_source=True)
    live_map = {m["upstream_key"]: m for m in live}
    check("available_models 动态优先: 来源标注 source=dynamic",
          live_src == "dynamic", live_src)
    check("available_models 动态优先: 快照条目不被收缩（仍列 20+）",
          len([m for m in live if m.get("chat")]) >= 20,
          str(len(live)))
    check("available_models 字段覆盖（display_name 以动态为准）",
          live_map["kimi-k3"]["display_name"] == "Kimi-K3-Live"
          and live_map["kimi-k3"]["dynamic"] is True,
          live_map["kimi-k3"]["display_name"])
    check("available_models 动态独有模型追加且 available=True",
          live_map.get("seed_m8", {}).get("available") is True
          and live_map.get("seed_m8", {}).get("context_window") is None,
          live_map.get("seed_m8"))
    check("available_models 快照多出来的模型 available=False",
          live_map["glm-5.3"]["available"] is False
          and live_map["kimi-k3"]["available"] is True,
          (live_map["glm-5.3"].get("available"),
           live_map["kimi-k3"].get("available")))
    check("model_entry 单查也认可用集（快照里但不在动态 = False）",
          model_entry("glm-5.3", realm="cn")["available"] is False,
          model_entry("glm-5.3", realm="cn")["available"])
    check("动态实名进入解析表（大小写不敏感）",
          resolve_upstream_key("deepseek-v3", "cn") == "deepseek-V3"
          or resolve_upstream_key("seed_M8", "cn") == "seed_m8",
          resolve_upstream_key("seed_M8", "cn"))
    payload_live = catalog_payload("cn", live=True, fetcher=_fake, refresh=True)
    check("catalog_payload(live=True) 标记可用数",
          payload_live["available_count"] == 2
          and payload_live["count"] >= 20,
          (payload_live["available_count"], payload_live["count"]))
    live_entry_v3 = model_entry("seed_m8", realm="cn")
    check("model_entry 认得动态独有模型",
          live_entry_v3["upstream_key"] == "seed_m8"
          and live_entry_v3["known"] is True,
          live_entry_v3["upstream_key"])


    fallback, fb_src = available_models(
        "cn", fetcher=lambda realm, account: (_ for _ in ()).throw(
            DynamicUnavailable("no-account")),
        refresh=True, with_source=True)
    check("available_models 失败回落快照",
          len(fallback) == 20 and fb_src.startswith("snapshot:"), fb_src)

    empty, empty_src = available_models(
        "intl", fetcher=lambda realm, account: [], refresh=True,
        with_source=True)
    check("available_models 空清单也回落快照（intl 10）",
          len(empty) == 10 and empty_src.startswith("snapshot:"), empty_src)

    unknown = model_entry("no-such-model", realm="cn")
    check("model_entry 未知模型 known=False 且不编造",
          unknown["known"] is False and unknown["price"] is None
          and unknown["context_window"] is None)

    if verbose:
        print("=" * 72)
        print("SELFTEST: PASS=%d FAIL=%d" % (passed, len(failures)))
        for item in failures:
            print("  - " + item)
    return passed, failures


def _main(argv):
    if "--payload" in argv:
        idx = argv.index("--payload")
        realm = argv[idx + 1] if len(argv) > idx + 1 else "cn"
        print(json.dumps(catalog_payload(realm), ensure_ascii=False, indent=2))
        return 0
    _passed, failures = selftest()
    return 0 if not failures else 1


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
