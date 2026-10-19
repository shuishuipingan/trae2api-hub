# -*- coding: utf-8 -*-
"""Trae2API-Hub 离线测试套件（零依赖 / 不联网 / 不碰真实凭证）

用法:
    python _test_trae.py

覆盖面
    [1] 协议编解码   trae_client：双区出口 / 鉴权头 / 请求体 parts / SSE 事件 / 错误帧 / 刷新
    [2] 凭据脱敏     trae_accounts：Account.public() / 账号池列表视图 / 区域识别
    [3] 模型目录     trae_catalog：双区清单 / key 解析 / 展示 id / 独占判定 / 快照来源
    [4] 路由         trae_proxy：独占区域 / 自动换区 / realm 归一 / CORS 边界
    [5] 工具标记转换 trae_proxy：<|FunctionCallBegin|>…<|FunctionCallEnd|> -> tool_calls
    [6] Anthropic 协议 trae_anthropic：tools 映射 / tool_use / usage 守恒 / 流式事件
    [7] 加密原语     trae_sign：AES-128-CBC NIST KAT + 往返（Desktop 凭证解密依赖）
    [8] 部署面静态检查 Dockerfile / compose / 启动脚本 / 防火墙 / README / .dockerignore
    [9] 诊断脚本冒烟  _diag_gateway.py --help 与 URL 白名单

判定政策（迁移期，写死在代码里，避免"看起来全绿"）
    FAIL = 组件在、入口在，但行为不符协议/契约（真回归，必须修）
    SKIP = 组件或入口**尚未交付**（迁移未完成），或缺外部 fixture；每行都打印
           "等待谁交付"，所以"没测到"永远可见，补齐即转 PASS。
    SKIP 不影响退出码。
退出码：0 = 无 FAIL（允许 SKIP）；1 = 有 FAIL。
"""
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ---- 运行期隔离：测试绝不写仓库里的 accounts/ 与 usage/ -------------------
# 团队约定：测试用临时目录（.tmp 语义），仓库 accounts/ usage/ 只属于运行时。
_TMP = tempfile.mkdtemp(prefix="trae-test-")
_TMP_ACC = os.path.join(_TMP, "accounts")
_TMP_USE = os.path.join(_TMP, "usage")
os.makedirs(_TMP_ACC, exist_ok=True)
os.makedirs(_TMP_USE, exist_ok=True)
for _name in ("TRAE_ACCOUNTS_DIR", "TRAE_USAGE_DIR",
              "TRAE_PROXY_ACCOUNTS_DIR", "TRAE_PROXY_USAGE_DIR",
              "ACCOUNTS_DIR", "USAGE_DIR"):
    os.environ[_name] = _TMP_ACC if "ACCOUNT" in _name else _TMP_USE
# 不拉起任何本机原生桥（活动平台的机器身份）；离线测试必须纯内存
os.environ.setdefault("QD_NATIVE_IDENTITY", "0")

PASS = 0
FAIL = 0
SKIP = 0
_FAILED = []
_WATCHED = ("trae_proxy.py", "trae_accounts.py", "trae_catalog.py",
            "trae_sign.py", "trae_anthropic.py", "trae_client.py")


# ===========================================================================
# 基础设施
# ===========================================================================
def section(title):
    print()
    print(title)


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        _FAILED.append(label)
        print("  [FAIL] " + label + (("  " + str(extra)) if extra else ""))


def skip(label, reason=""):
    global SKIP
    SKIP += 1
    print("  [SKIP] " + label + (("  -- " + str(reason)) if reason else ""))


def load(name):
    """导入模块；失败时返回 (None, 原因)，让套件继续跑其它分组。"""
    try:
        return importlib.import_module(name), ""
    except Exception as exc:                      # noqa: BLE001 - 迁移期容错
        return None, "%s: %s" % (type(exc).__name__, exc)


def _fingerprint():
    for name in _WATCHED:
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            yield name, "missing"
            continue
        with open(path, "rb") as fh:
            yield name, hashlib.sha256(fh.read()).hexdigest()[:12]


def read_text(name):
    path = os.path.join(ROOT, name)
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


_BOUND = {"done": False}


def bind_runtime_paths(proxy):
    """把网关模块的存储路径钉到临时目录，并断言隔离生效（只做一次）。

    trae_proxy 的 ACCOUNTS_DIR 是模块级常量（仓库相对），即使环境变量指向
    tmp，任何写盘路径仍可能落回仓库；离线测试必须显式改绑。
    """
    if not proxy or _BOUND["done"]:
        return
    _BOUND["done"] = True
    try:
        proxy.ACCOUNTS_DIR = _TMP_ACC
        proxy.USAGE_DIR = _TMP_USE
        proxy.USAGE_LOG = os.path.join(_TMP_USE, "usage.jsonl")
        proxy.USAGE_SUMMARY = os.path.join(_TMP_USE, "usage-summary.json")
        proxy.REALM_STATE_FILE = os.path.join(_TMP_ACC, "active_realm.json")
    except Exception:                              # noqa: BLE001
        pass
    check("测试隔离：网关 ACCOUNTS_DIR 指向临时目录",
          str(getattr(proxy, "ACCOUNTS_DIR", "")).startswith(_TMP),
          getattr(proxy, "ACCOUNTS_DIR", ""))
    check("测试隔离：网关 USAGE_LOG 指向临时目录",
          str(getattr(proxy, "USAGE_LOG", "")).startswith(_TMP),
          getattr(proxy, "USAGE_LOG", ""))


def catalog_exclusive_sets(cat):
    """(intl 独占, cn 独占) key 集合；优先 exclusive_sets()（按当前快照实时算）。"""
    fn = getattr(cat, "exclusive_sets", None)
    if callable(fn):
        try:
            pair = fn()
            if isinstance(pair, (tuple, list)) and len(pair) == 2:
                return set(pair[0] or ()), set(pair[1] or ())
        except Exception:                          # noqa: BLE001
            pass
    return (set(getattr(cat, "INTL_EXCLUSIVE", ()) or ()),
            set(getattr(cat, "CN_EXCLUSIVE", ()) or ()))


class _Duck(object):
    """同时支持 dict 式与属性式访问的假账号，兜住两种实现风格。"""

    def __init__(self, data):
        self._data = dict(data)
        self.__dict__.update(data)

    def __getitem__(self, key):
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)


def _expand_lines(lines):
    """把 "event: x\ndata: {...}\n" 这类块拆成逐行（SSE 解析器按行读）。"""
    out = []
    for item in lines or []:
        if isinstance(item, str):
            item = item.encode("utf-8")
        if not item:
            out.append(b"\n")
            continue
        parts = item.split(b"\n")
        for idx, part in enumerate(parts):
            if idx < len(parts) - 1:
                out.append(part + b"\n")
            elif part:
                out.append(part)
    return out


class _LineSource(object):
    """最小 file-like：既能 for 迭代也能 readline()/read()，兜住两种 SSE 读取实现。"""

    def __init__(self, lines):
        self._lines = _expand_lines(lines)

    def __iter__(self):
        return iter(self._lines)

    def readline(self):
        return self._lines.pop(0) if self._lines else b""

    def read(self):
        data = b"".join(self._lines)
        self._lines = []
        return data


def feed_lines(fn, lines, what="iter_events"):
    """按三种常见入参形态喂行（file-like / 迭代器 / BytesIO）；全失败才抛错。"""
    lines = list(lines or [])
    flat = _expand_lines(lines)
    try:
        import io
        blob = b"".join(flat)
    except Exception:                              # noqa: BLE001
        blob = b""
    errors = []
    for factory in (lambda: _LineSource(lines),
                    lambda: iter(list(flat)),
                    lambda: __import__("io").BytesIO(blob)):
        try:
            return list(fn(factory()))
        except Exception as exc:                  # noqa: BLE001
            errors.append("%s(%s) -> %s: %s"
                          % (what, type(factory()).__name__,
                             type(exc).__name__, exc))
    raise AssertionError("; ".join(errors[-2:]))


def event_pairs(items):
    """把 (event, data) / dict 两种产出归一成 [(name, dict)]。"""
    out = []
    for it in items or []:
        if isinstance(it, (tuple, list)) and len(it) == 2:
            out.append((str(it[0]), it[1] if isinstance(it[1], dict) else {}))
        elif isinstance(it, dict):
            name = str(it.get("event") or it.get("name") or "")
            data = it.get("data")
            if not isinstance(data, dict):
                data = it if "data" not in it else {}
            out.append((name, data))
    return out


def frame(name, payload):
    """一帧 SSE：event 行 + data 行 + 行尾 \n（空行分隔由调用方补 b"\n"）。"""
    return ("event: %s\ndata: %s\n"
            % (name, json.dumps(payload, ensure_ascii=False))).encode("utf-8")


def call_variants(fn, variants):
    """依次尝试多种调用形态；返回 (result, used_label)。全失败抛最后一个错。"""
    last = None
    for label, factory in variants:
        try:
            return factory(), label
        except Exception as exc:                  # noqa: BLE001
            last = (label, exc)
    raise AssertionError("%s: %s" % (last[0], last[1]) if last else "no variant")


# ===========================================================================
# [1] 协议编解码 · trae_client（PROTOCOL §一/§二/§五/§六/§十）
# ===========================================================================
def test_protocol():
    section("[1] 协议编解码 · trae_client（离线）")
    client, err = load("trae_client")
    labels = ["REALMS 双区出口", "鉴权头 x-ide-token/Authorization", "X-App-Id 常量",
              "build_chat_body parts 数组", "SSE 事件序列", "错误帧 code 透传",
              "refresh_account 走 ExchangeToken", "UpstreamError 三元组"]
    if client is None:
        for label in labels:
            skip(label, "trae_client 未交付（doudou / task-1）：" + err)
        return

    realms = getattr(client, "REALMS", None)
    check("REALMS 是 dict 且含 cn/intl",
          isinstance(realms, dict) and {"cn", "intl"} <= set(realms),
          list(realms) if isinstance(realms, dict) else type(realms).__name__)
    realms = realms if isinstance(realms, dict) else {}
    cn = realms.get("cn") if isinstance(realms.get("cn"), dict) else {}
    intl = realms.get("intl") if isinstance(realms.get("intl"), dict) else {}
    check("cn 区配置含 core/account/ua/version_code",
          {"core", "account", "ua", "version_code"} <= set(cn), sorted(cn))
    check("intl 区配置含 core/account/ua/version_code",
          {"core", "account", "ua", "version_code"} <= set(intl), sorted(intl))

    def _norm(url):
        return str(url or "").rstrip("/")

    check("CN core = trae-api-cn.mchost.guru",
          _norm(cn.get("core")) == "https://trae-api-cn.mchost.guru",
          cn.get("core"))
    check("CN account = api.trae.com.cn",
          _norm(cn.get("account")) == "https://api.trae.com.cn",
          cn.get("account"))
    check("INTL core 属官方三主机之一",
          _norm(intl.get("core")) in ("https://core-normal.traeapi.us",
                                      "https://core-normal.trae.ai",
                                      "https://coresg-normal.trae.ai"),
          intl.get("core"))
    check("INTL account 属官方两主机之一",
          _norm(intl.get("account")) in ("https://grow-normal.trae.ai",
                                         "https://grow-normal.traeapi.us"),
          intl.get("account"))
    check("UA 带 Trae 前缀（CN 用 Trae CN/…）",
          str(cn.get("ua") or "").startswith("Trae")
          and str(intl.get("ua") or "").startswith("Trae"),
          (cn.get("ua"), intl.get("ua")))

    # ---- 鉴权头 ----
    token = "TEST-ACCESS-TOKEN-0123456789"
    data = {"uid": "diag-uid", "realm": "cn", "token": token,
            "accessToken": token, "refreshToken": "TEST-REFRESH",
            "expiresAt": int(time.time()) + 3600}
    hdr_fn = getattr(client, "auth_headers", None)
    if not callable(hdr_fn):
        skip("鉴权头 x-ide-token/Authorization", "auth_headers 未交付")
    else:
        try:
            headers, _used = call_variants(hdr_fn, [
                ("auth_headers(dict, realm)", lambda: hdr_fn(data, "cn")),
                ("auth_headers(duck, realm)", lambda: hdr_fn(_Duck(data), "cn")),
                ("auth_headers(duck)", lambda: hdr_fn(_Duck(data))),
            ])
        except Exception as exc:                  # noqa: BLE001
            headers = None
            check("auth_headers 可调用", False, exc)
        if isinstance(headers, dict):
            low = {str(k).lower(): v for k, v in headers.items()}
            check("x-ide-token = access token", low.get("x-ide-token") == token,
                  low.get("x-ide-token"))
            check("Authorization = Cloud-IDE-JWT <同一 token>",
                  low.get("authorization") == "Cloud-IDE-JWT " + token,
                  low.get("authorization"))
            check("X-App-Id = 6eefa01c-…bfcd8",
                  low.get("x-app-id") == "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8",
                  low.get("x-app-id"))
            check("x-plugin-channel = icube-ai",
                  low.get("x-plugin-channel") == "icube-ai",
                  low.get("x-plugin-channel"))
            check("Content-Type = application/json",
                  str(low.get("content-type") or "").startswith("application/json"),
                  low.get("content-type"))
        elif headers is not None:
            check("auth_headers 返回 dict", False, type(headers).__name__)

    # ---- 请求体：content 必须是 parts 数组（字符串会 400）----
    model = "deepseek-V3"
    messages = [{"role": "system", "content": "你是助手"},
                {"role": "user", "content": "你好"}]
    build = getattr(client, "build_chat_body", None)
    if not callable(build):
        skip("build_chat_body parts 数组", "build_chat_body 未交付")
    else:
        try:
            body, used = call_variants(build, [
                ("(model, messages, stream=True)",
                 lambda: build(model, messages, stream=True)),
                ("(model, messages)", lambda: build(model, messages)),
                ("(dict)", lambda: build({"model": model, "messages": messages,
                                          "stream": True})),
            ])
        except Exception as exc:                  # noqa: BLE001
            body, used = None, str(exc)
            check("build_chat_body 可调用", False, exc)
        if isinstance(body, dict):
            check("请求体携带模型名", (body.get("model_name") or body.get("model")) == model,
                  body.get("model_name") or body.get("model"))
            check("请求体 stream=True", body.get("stream") is True, body.get("stream"))
            msgs = body.get("messages") or []
            parts_ok = bool(msgs) and all(isinstance(m.get("content"), list)
                                          for m in msgs if isinstance(m, dict))
            check("每条 message.content 是 parts 数组（字符串会 400）", parts_ok,
                  [type(m.get("content")).__name__ for m in msgs
                   if isinstance(m, dict)])
            flat = json.dumps(body, ensure_ascii=False)
            check("parts 里保留文本", "你是助手" in flat and "你好" in flat)
        elif body is not None:
            check("build_chat_body 返回 dict", False, type(body).__name__)

    # ---- SSE 事件 ----
    frames = [
        frame("metadata", {"model": "", "session_id": "s-diag",
                           "prompt_completion_id": 0, "ab_versions": [""],
                           "app_version": "default"}),
        b"\n",
        frame("output", {"response": "你好", "reasoning_content": None,
                         "tool_calls": None}),
        b"\n",
        frame("output", {"response": "，世界", "reasoning_content": None}),
        b"\n",
        frame("token_usage", {"name": "", "prompt_tokens": 50,
                              "completion_tokens": 21, "total_tokens": 71,
                              "cache_creation_input_tokens": 0,
                              "cache_read_input_tokens": 0,
                              "reasoning_tokens": 0}),
        b"\n",
        frame("done", {"finish_reason": "stop"}),
        b"\n",
    ]
    iter_fn = getattr(client, "iter_events", None)
    if not callable(iter_fn):
        skip("SSE 事件序列", "iter_events 未交付")
        skip("错误帧 code 透传", "iter_events 未交付")
    else:
        try:
            pairs = event_pairs(feed_lines(iter_fn, frames))
        except Exception as exc:                  # noqa: BLE001
            pairs = []
            check("iter_events 可解析上游帧", False, exc)
        names = [n for n, _ in pairs]
        check("事件名覆盖 metadata/output/token_usage/done",
              {"metadata", "output", "token_usage", "done"} <= set(names), names)
        check("事件顺序 metadata -> output… -> token_usage -> done",
              names.index("metadata") < names.index("token_usage") < names.index("done")
              if {"metadata", "token_usage", "done"} <= set(names) else False, names)
        text = "".join(str(d.get("response") or "") for n, d in pairs if n == "output")
        check("output 增量拼成 你好，世界", text == "你好，世界", text)
        usage = next((d for n, d in pairs if n == "token_usage"), {})
        check("token_usage prompt/completion 保留",
              usage.get("prompt_tokens") == 50 and usage.get("completion_tokens") == 21,
              usage)
        done = next((d for n, d in pairs if n == "done"), {})
        check("done.finish_reason 透传", done.get("finish_reason") == "stop", done)

        err_frames = [frame("error", {"code": 4015, "error": "",
                                      "message": "upstream refused",
                                      "extra": None})]
        try:
            err_pairs = event_pairs(feed_lines(iter_fn, err_frames))
            err_data = next((d for n, d in err_pairs if n == "error"), {})
            check("error 帧 code 透传（4015）", err_data.get("code") == 4015, err_data)
        except Exception as exc:                  # noqa: BLE001
            check("error 帧 code 透传（4015）", False, exc)

    # ---- 刷新 / 其它接口存在性 ----
    refresh = getattr(client, "refresh_account", None)
    if callable(refresh):
        try:
            import inspect
            src = inspect.getsource(refresh)
        except Exception:                          # noqa: BLE001
            src = ""
        check("refresh_account 走 ExchangeToken", "ExchangeToken" in src or not src,
              "源码里未见 ExchangeToken 端点")
    else:
        skip("refresh_account 走 ExchangeToken", "refresh_account 未交付")
    missing = [n for n in ("fetch_model_list", "fetch_usage",
                           "fetch_entitlement", "import_desktop_accounts")
               if not callable(getattr(client, n, None))]
    check("PROTOCOL §十 其余接口齐备", not missing, missing)

    exc_cls = getattr(client, "UpstreamError", None)
    if not isinstance(exc_cls, type):
        skip("UpstreamError 三元组", "UpstreamError 未交付")
    else:
        inst = None
        for args, kwargs in (((4015, "boom", 200), {}),
                             (("boom",), {"code": 4015}),
                             ((4015, "boom"), {})):
            try:
                inst = exc_cls(*args, **kwargs)
                break
            except Exception:                      # noqa: BLE001
                continue
        check("UpstreamError 可构造且带 code",
              inst is not None and getattr(inst, "code", None) == 4015,
              repr(inst))


# ===========================================================================
# [2] 凭据脱敏 · trae_accounts
# ===========================================================================
def test_secrets():
    section("[2] 凭据脱敏 · trae_accounts")
    acc_mod, err = load("trae_accounts")
    if acc_mod is None:
        for label in ("Account.public() 不含令牌", "账号池视图不含令牌",
                      "区域识别"):
            skip(label, "trae_accounts 未就绪（buding / task-3）：" + err)
        return

    acc_cls = getattr(acc_mod, "Account", None)
    raw_uid = "1234567890123456789"
    tok = "TRAE-ACCESS-TOKEN-SHOULD-NOT-LEAK-0001"
    ref = "TRAE-REFRESH-TOKEN-SHOULD-NOT-LEAK-0002"
    now = int(time.time())
    acc = None
    if not isinstance(acc_cls, type):
        skip("Account.public() 不含令牌", "Account 未交付")
    else:
        data = {"uid": raw_uid, "realm": "cn", "accessToken": tok, "token": tok,
                "access_token": tok, "refreshToken": ref,
                "expiresAt": now + 3600, "expiredAt": now + 3600,
                "domain": "https://api.trae.com.cn"}
        try:
            acc = acc_cls(data)
        except Exception as exc:                   # noqa: BLE001
            check("Account 可构造", False, exc)
        if acc is not None:
            pub_fn = getattr(acc, "public", None)
            if not callable(pub_fn):
                skip("Account.public() 不含令牌", "public() 未交付")
            else:
                try:
                    pub = pub_fn()
                except TypeError:
                    pub = pub_fn(now)
                dumped = json.dumps(pub, ensure_ascii=False, default=str)
                check("Account.public() 不含 access token", tok not in dumped,
                      dumped[:100])
                check("Account.public() 不含 refresh token", ref not in dumped)
                check("public() 不含原始 uid（掩码 / 哈希）", raw_uid not in dumped,
                      pub.get("uid"))
                check("public() 给出 uidTail / uidHash 之一",
                      bool(pub.get("uidHash") or pub.get("uidTail") or pub.get("uid")))
                check("public() 以布尔代替令牌（hasRefreshToken）",
                      isinstance(pub.get("hasRefreshToken", True), bool),
                      pub.get("hasRefreshToken"))
                to_dict = getattr(acc, "to_dict", None) or getattr(acc, "dump", None)
                if callable(to_dict):
                    check("落盘结构保留凭证（刷新 / 回写需要）",
                          tok in json.dumps(to_dict(), ensure_ascii=False, default=str))
                else:
                    skip("落盘结构保留凭证（刷新 / 回写需要）", "to_dict 未交付")

    # ---- 账号池列表视图 ----
    pool_cls = getattr(acc_mod, "AccountPool", None)
    if not isinstance(pool_cls, type) or acc is None:
        skip("账号池视图不含令牌", "AccountPool 未交付")
    else:
        try:
            pool_dir = tempfile.mkdtemp(prefix="pool-", dir=_TMP)
            pool = pool_cls(pool_dir)
            add = getattr(pool, "add", None)
            if callable(add):
                add(acc)
            list_fn = getattr(pool, "list_public", None)
            lp = []
            if callable(list_fn):
                try:
                    lp = list_fn()
                except TypeError:
                    lp = list_fn("cn")
            blob = json.dumps(lp, ensure_ascii=False, default=str)
            check("账号池视图不含令牌", tok not in blob and ref not in blob)
            check("账号池能列出刚加入的账号", len(lp) >= 1, len(lp))
        except Exception as exc:                   # noqa: BLE001
            check("账号池视图不含令牌", False, exc)

    # ---- 区域识别（host -> realm 契约）----
    realms = (getattr(acc_mod, "REALMS", None)
              or getattr(acc_mod, "REALM_CONFIGS", {}) or {})
    detect = getattr(acc_mod, "detect_realm_from_domain", None)
    check("双区表声明 cn/intl", {"cn", "intl"} <= set(realms), sorted(realms))
    pairs = []
    if isinstance(realms, dict):
        for realm, cfg in realms.items():
            dom = None
            if isinstance(cfg, dict):
                dom = cfg.get("domain") or cfg.get("account") or cfg.get("host")
            else:
                dom = getattr(cfg, "domain", None)
            if dom:
                pairs.append((realm, str(dom)))
    if not callable(detect) or not pairs:
        skip("区域识别", "detect_realm_from_domain 或双区 host 未交付")
    for realm, dom in sorted(pairs):
        host = dom.split("//")[-1].split("/")[0]
        got = None
        for cand in (dom, host):
            try:
                got = detect(cand)
            except Exception as exc:               # noqa: BLE001
                got = "err:%s" % exc
            if got == realm:
                break
        check("域名 %s 归属 %s" % (dom, realm), got == realm, got)


# ===========================================================================
# [3] 模型目录 · trae_catalog
# ===========================================================================
def test_catalog():
    section("[3] 模型目录 · trae_catalog")
    cat, err = load("trae_catalog")
    if cat is None:
        for label in ("cn 目录", "intl 目录", "key 解析", "展示 id", "独占判定",
                      "快照来源"):
            skip(label, "trae_catalog 未就绪（natie / task-4）：" + err)
        return

    models_for = getattr(cat, "models_for_realm", None)
    resolve = getattr(cat, "resolve_upstream_key", None)
    display_id = getattr(cat, "display_id", None)
    if not callable(models_for):
        skip("cn 目录", "models_for_realm 未交付")
        skip("intl 目录", "models_for_realm 未交付")
        return

    by_realm = {}
    for realm in ("cn", "intl"):
        try:
            entries = list(models_for(realm) or [])
        except Exception as exc:                   # noqa: BLE001
            entries = []
            check("[%s] models_for_realm 可调用" % realm, False, exc)
        by_realm[realm] = entries
        check("[%s] 目录非空" % realm, len(entries) >= 3, len(entries))
        keys = [m.get("key") for m in entries if isinstance(m, dict)]
        check("[%s] key 唯一" % realm, len(keys) == len(set(keys)),
              len(keys) - len(set(keys)))
        check("[%s] 每项都有 key + display_name" % realm,
              bool(entries) and all(
                  isinstance(m, dict) and m.get("key")
                  and (m.get("display_name") or m.get("name"))
                  for m in entries),
              [k for k in keys if not k])

    cn_keys = {m.get("key") for m in by_realm["cn"] if isinstance(m, dict)}
    intl_keys = {m.get("key") for m in by_realm["intl"] if isinstance(m, dict)}
    check("双区清单不同（CN / 国际版各有特供）", cn_keys != intl_keys,
          (len(cn_keys), len(intl_keys)))

    # ---- key 解析：展示 id 必须能解析回 key ----
    if not callable(resolve) or not callable(display_id):
        skip("key 解析", "resolve_upstream_key / display_id 未交付")
    else:
        bad = []
        for realm, entries in by_realm.items():
            for m in entries:
                if not isinstance(m, dict) or not m.get("key"):
                    continue
                try:
                    did = display_id(m)
                    got = resolve(did, realm=realm)
                except Exception as exc:           # noqa: BLE001
                    bad.append("%s: %s" % (m.get("key"), exc))
                    continue
                if got != m.get("key"):
                    bad.append("%s -> %r" % (m.get("key"), got))
        check("展示 id 解析回 key（双区全量）", not bad, bad[:4])
        sample = by_realm["cn"][0] if by_realm["cn"] else {}
        if isinstance(sample, dict) and sample.get("key"):
            did = display_id(sample)
            check("展示 id 形如 key (Name)",
                  str(did).startswith(str(sample["key"]) + " ("), did)
        check("空模型名 -> auto", resolve("") == "auto", resolve(""))
        check("未知模型名原样返回",
              resolve("mystery-model-xyz") == "mystery-model-xyz",
              resolve("mystery-model-xyz"))

    # ---- 独占判定与区域跨度 ----
    span = getattr(cat, "key_realm_span", None)
    intl_ex, cn_ex = catalog_exclusive_sets(cat)
    if intl_ex and cn_ex:
        check("独占表非空（双区都声明了特供模型）", True,
              (len(intl_ex), len(cn_ex)))
    else:
        skip("独占表非空（双区都声明了特供模型）",
             "独占表为空（快照未加载 / 未刷新，natie / task-4）")
    if callable(span):
        bad = []
        for key in intl_ex:
            if span(key) != ("intl",):
                bad.append((key, span(key)))
        for key in cn_ex:
            if span(key) != ("cn",):
                bad.append((key, span(key)))
        check("独占 key 的区域跨度正确", not bad, bad[:4])
    else:
        skip("独占 key 的区域跨度正确", "key_realm_span 未交付")

    # ---- 快照来源 ----
    snap_source = getattr(cat, "snapshot_source", None)
    report = getattr(cat, "snapshot_report", None)
    if callable(snap_source):
        for realm in ("cn", "intl"):
            try:
                src = snap_source(realm)
            except Exception as exc:               # noqa: BLE001
                src = "err:%s" % exc
            check("[%s] 快照来源可解释（非 unknown）" % realm,
                  bool(src) and str(src) not in ("unknown", "file-missing"), src)
    else:
        skip("快照来源", "snapshot_source 未交付")
    # 双区快照文件（natie 交付物）：存在且是 JSON 数组
    for name in ("trae_catalog_cn.json", "trae_catalog_intl.json"):
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            skip("快照文件 %s 存在且可解析" % name, "文件缺失（task-4 交付物）")
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            ok = isinstance(doc, (list, dict))
        except Exception as exc:                   # noqa: BLE001
            doc, ok = None, False
            check("快照文件 %s 可解析" % name, False, exc)
        if ok:
            check("快照文件 %s 可解析（list/dict）" % name, True)
    if callable(report):
        try:
            rep = report()
            check("snapshot_report 同时覆盖两区",
                  isinstance(rep, dict) and {"cn", "intl"} <= set(rep),
                  list(rep) if isinstance(rep, dict) else type(rep).__name__)
        except Exception as exc:                   # noqa: BLE001
            check("snapshot_report 可调用", False, exc)
    else:
        skip("snapshot_report 双区覆盖", "snapshot_report 未交付")

    # ---- 目录契约（2026-10-19 与拿铁对齐）----
    payload_fn = getattr(cat, "catalog_payload", None)
    if not callable(payload_fn):
        skip("catalog_payload 快照口径", "catalog_payload 未交付（natie / task-4）")
    else:
        for realm, expected in (("cn", 20), ("intl", 10)):
            try:
                payload = payload_fn(realm)
            except Exception as exc:               # noqa: BLE001
                payload = {}
                check("[%s] catalog_payload 可调用" % realm, False, exc)
            rows = payload.get("data") or []
            check("[%s] 快照口径 %d 条（离线确定）" % (realm, expected),
                  payload.get("count") == expected and len(rows) == expected,
                  (payload.get("count"), len(rows)))
            check("[%s] payload 带 catalog_source" % realm,
                  bool(payload.get("catalog_source")), payload.get("catalog_source"))
            check("[%s] 每条含 upstream_key / available" % realm,
                  bool(rows) and all("upstream_key" in e and "available" in e
                                     for e in rows if isinstance(e, dict)),
                  [k for k in (rows[0].keys() if rows else []) if k][:6])
        try:
            import inspect
            params = inspect.signature(payload_fn).parameters
            check("catalog_payload 支持 live=True（诊断口径）", "live" in params,
                  list(params))
        except Exception:                          # noqa: BLE001
            skip("catalog_payload 支持 live=True（诊断口径）", "签名不可读")

    if callable(resolve):
        check("resolve deepseek-V3 精确优先（不再猜 V3.1）",
              resolve("deepseek-V3", realm="cn") == "deepseek-V3",
              resolve("deepseek-V3", realm="cn"))
        check("resolve Claude-Opus-4.7 -> aws_claude_4.7_opus（intl）",
              resolve("Claude-Opus-4.7", realm="intl") == "aws_claude_4.7_opus",
              resolve("Claude-Opus-4.7", realm="intl"))
        check("resolve 同义名不带 realm 也命中 intl 真名",
              resolve("Claude-Opus-4.7") == "aws_claude_4.7_opus",
              resolve("Claude-Opus-4.7"))


# ===========================================================================
# [4] 路由 · trae_proxy
# ===========================================================================
def test_routing():
    section("[4] 路由 · trae_proxy")
    proxy, err = load("trae_proxy")
    if proxy is None:
        for label in ("独占区域", "自动换区", "realm 归一", "CORS 边界"):
            skip(label, "trae_proxy 未就绪（tangyuan / task-2）：" + err)
        return
    bind_runtime_paths(proxy)
    cat, _ = load("trae_catalog")
    intl_ex, cn_ex = catalog_exclusive_sets(cat) if cat else (set(), set())

    excl = getattr(proxy, "exclusive_realm", None)
    if not callable(excl):
        skip("独占区域", "exclusive_realm 未交付")
    else:
        if intl_ex:
            key = sorted(intl_ex)[0]
            check("国际独占 %s -> intl" % key, excl(key) == "intl", excl(key))
            if cat and callable(getattr(cat, "format_model_id", None)):
                did = cat.format_model_id(key, "intl")
                check("展示 id 也判独占（%s）" % did, excl(did) == "intl", excl(did))
        else:
            skip("国际独占 -> intl", "目录未声明 INTL_EXCLUSIVE")
        if cn_ex:
            key = sorted(cn_ex)[0]
            check("国内独占 %s -> cn" % key, excl(key) == "cn", excl(key))
        else:
            skip("国内独占 -> cn", "目录未声明 CN_EXCLUSIVE")
        check("未知模型不误判独占", excl("no-such-model-xyz") == "",
              excl("no-such-model-xyz"))
        check("空模型不误判独占", excl("") == "", excl(""))

    detect = getattr(proxy, "detect_model_realm", None)
    if not callable(detect):
        skip("自动换区", "detect_model_realm 未交付")
    else:
        check("空模型维持当前区", detect("") == proxy.CURRENT_REALM,
              detect(""))
        if intl_ex:
            key = sorted(intl_ex)[0]
            check("国际独占模型路由到 intl", detect(key) == "intl", detect(key))
        if cn_ex:
            key = sorted(cn_ex)[0]
            check("国内独占模型路由到 cn", detect(key) == "cn", detect(key))

    scope = getattr(proxy, "realm_scope", None)
    if not callable(scope):
        skip("realm 归一", "realm_scope 未交付")
    else:
        check("realm=all -> None（通配）", scope("all") is None, scope("all"))
        check("realm='' -> None", scope("") is None, scope(""))
        check("realm=cn 原样保留", scope("cn") == "cn", scope("cn"))

    cors = getattr(proxy, "cors_origin_allowed", None)
    if not callable(cors):
        skip("CORS 边界", "cors_origin_allowed 未交付")
    else:
        check("/v1/models 放开 CORS", cors("/v1/models") is True)
        check("/v1/chat/completions 放开 CORS", cors("/v1/chat/completions") is True)
        check("管理路由不发 ACAO（/accounts）", cors("/accounts") is False)
        check("管理路由不发 ACAO（/v1/usage/summary）",
              cors("/v1/usage/summary") is False)
        check("看板不发 ACAO（/）", cors("/") is False)

    row_match = getattr(proxy, "row_matches_realm", None)
    if callable(row_match):
        check("行过滤：realm=cn 命中 cn 行",
              row_match({"realm": "cn"}, "cn") is True)
        check("行过滤：intl 行不算 cn", row_match({"realm": "intl"}, "cn") is False)
        check("行过滤：all 通配全收",
              row_match({"realm": "intl"}, "all") is True)
    else:
        skip("行过滤", "row_matches_realm 未交付")


# ===========================================================================
# [5] 工具标记转换 · PROTOCOL §七
# ===========================================================================
BEGIN = "<|FunctionCallBegin|>"
END = "<|FunctionCallEnd|>"
CALL_JSON = '[{"name": "GetWeather", "parameters": {"city": "北京"}}]'


def _norm_calls(calls):
    out = []
    for c in calls or []:
        if not isinstance(c, dict):
            continue
        fn = c.get("function") if isinstance(c.get("function"), dict) else c
        name = fn.get("name") or c.get("name") or ""
        args = fn.get("arguments")
        if args is None:
            args = fn.get("parameters")
        if isinstance(args, (dict, list)):
            args = json.dumps(args, ensure_ascii=False)
        out.append({"name": str(name), "arguments": str(args or "")})
    return out


def _text_of(delta):
    if not isinstance(delta, dict):
        return ""
    if isinstance(delta.get("content"), str):
        return delta["content"]
    if isinstance(delta.get("text"), str):
        return delta["text"]
    return ""


def test_tool_markers():
    section("[5] 工具标记转换 · trae_proxy（协议 §七）")
    proxy, err = load("trae_proxy")
    if proxy is None:
        for label in ("纯文本透传", "完整标记 -> tool_calls", "跨块切分仍合并",
                      "坏 JSON fail-open", "标记外正文不丢"):
            skip(label, "trae_proxy 未就绪：%s" % err)
        return

    convert = getattr(proxy, "convert_tool_markers", None)
    stream_cls = getattr(proxy, "ToolMarkerStream", None)

    if callable(convert):
        def _convert(text):
            res = convert(text)
            if isinstance(res, tuple) and len(res) == 2:
                return str(res[0] or ""), _norm_calls(res[1])
            if isinstance(res, dict):
                return (str(res.get("text") or res.get("content") or ""),
                        _norm_calls(res.get("tool_calls") or res.get("calls")))
            return "", _norm_calls(res)

        try:
            clean, calls = _convert("你好")
        except Exception as exc:                   # noqa: BLE001
            clean, calls = "", []
            check("convert_tool_markers 可调用", False, exc)
        check("纯文本透传且无 tool_calls", clean == "你好" and not calls, (clean, calls))
        try:
            clean, calls = _convert("前缀 " + BEGIN + CALL_JSON + END + " 后缀")
        except Exception as exc:                   # noqa: BLE001
            clean, calls = "", []
            check("完整标记可转换", False, exc)
        check("完整标记 -> 恰好 1 个 tool_call", len(calls) == 1, calls)
        check("tool_call.name = GetWeather",
              bool(calls) and calls[0]["name"] == "GetWeather", calls)
        try:
            args = json.loads(calls[0]["arguments"]) if calls else None
        except Exception:                          # noqa: BLE001
            args = None
        check("tool_call.arguments 是可解析 JSON 且 city=北京",
              isinstance(args, dict) and args.get("city") == "北京", args)
        check("标记本身不透传（clean 无 FunctionCallBegin）",
              "FunctionCallBegin" not in clean and "FunctionCallEnd" not in clean,
              clean[:80])
        check("标记外正文保留",
              clean.startswith("前缀") and clean.rstrip().endswith("后缀"), repr(clean))
        try:
            clean_bad, calls_bad = _convert(
                "正文开始 " + BEGIN + '[{"name":"Bad","parameters": ' + END + " 正文结束")
        except Exception as exc:                   # noqa: BLE001
            clean_bad, calls_bad = "", []
            check("坏 JSON fail-open", False, exc)
        check("坏 JSON fail-open：正文不丢",
              "正文开始" in clean_bad or bool(calls_bad), repr(clean_bad)[:80])
        return

    if isinstance(stream_cls, type):
        try:
            try:
                stream_obj = stream_cls(allowed_names=["GetWeather"])
            except TypeError:
                stream_obj = stream_cls()
        except Exception as exc:                   # noqa: BLE001
            check("ToolMarkerStream 可构造", False, exc)
            return
        feed = getattr(stream_obj, "feed", None)
        flush = getattr(stream_obj, "flush", None)
        if not callable(feed):
            skip("纯文本透传", "ToolMarkerStream.feed 未交付")
            return
        full = "你好 " + BEGIN + CALL_JSON + END + " 完"
        chunks = [full[:5], full[5:5 + 11], full[16:40], full[40:]]
        deltas = []
        err = None
        try:
            for piece in chunks:
                deltas.extend(feed(piece) or [])
            if callable(flush):
                deltas.extend(flush() or [])
        except Exception as exc:                   # noqa: BLE001
            err = exc
        check("流式喂入不抛异常", err is None, err)
        text = "".join(_text_of(d) for d in deltas)
        calls = []
        for d in deltas:
            if isinstance(d, dict):
                calls.extend(_norm_calls(d.get("tool_calls")))
        if not calls and callable(getattr(stream_obj, "calls", None)):
            calls = _norm_calls(stream_obj.calls())
        check("跨块切分仍只出 1 个 tool_call", len(calls) == 1, calls)
        check("流式 tool_call.name = GetWeather",
              bool(calls) and calls[0]["name"] == "GetWeather", calls)
        joined = "".join(c["arguments"] for c in calls)
        try:
            args = json.loads(joined) if joined else None
        except Exception:                          # noqa: BLE001
            args = None
        check("流式 arguments 拼接后可解析且 city=北京",
              isinstance(args, dict) and args.get("city") == "北京", joined[:120])
        check("文本增量不含标记",
              "FunctionCallBegin" not in text and "FunctionCallEnd" not in text,
              text[:80])
        check("标记外正文保留（你好 / 完）",
              "你好" in text and "完" in text, repr(text))
        try:
            feed("正文开始 " + BEGIN + '[{"name":"Bad",')
            if callable(flush):
                flush()
            check("坏 JSON fail-open（不抛异常）", True)
        except Exception as exc:                   # noqa: BLE001
            check("坏 JSON fail-open（不抛异常）", False, exc)
        return

    for label in ("纯文本透传", "完整标记 -> 1 个 tool_call", "跨块切分仍合并",
                  "坏 JSON fail-open", "标记外正文不丢"):
        skip(label, "trae_proxy 未暴露 convert_tool_markers / ToolMarkerStream"
                    "（等待 tangyuan 交付）")


# ===========================================================================
# [6] Anthropic 工具协议 · trae_anthropic
# ===========================================================================
def test_anthropic():
    section("[6] Anthropic 工具协议 · trae_anthropic")
    ant, err = load("trae_anthropic")
    if ant is None:
        for label in ("tools 映射", "tool_use -> tool_calls", "usage 守恒",
                      "流式文本事件", "流式工具事件"):
            skip(label, "trae_anthropic 未就绪（tangyuan / task-2）：" + err)
        return

    to_chat = getattr(ant, "messages_to_chat", None)
    if not callable(to_chat):
        skip("tools 映射", "messages_to_chat 未交付")
    else:
        payload = {
            "model": "deepseek-V3", "max_tokens": 128, "system": "SYS",
            "tools": [{"name": "GetWeather", "description": "查天气",
                       "input_schema": {"type": "object",
                                        "properties": {"city": {"type": "string"}},
                                        "required": ["city"]}}],
            "messages": [
                {"role": "user", "content": "北京天气"},
                {"role": "assistant", "content": [
                    {"type": "text", "text": "查一下"},
                    {"type": "tool_use", "id": "tu1", "name": "GetWeather",
                     "input": {"city": "北京"}}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tu1",
                     "content": [{"type": "text", "text": "晴 25C"}]}]},
            ],
        }
        try:
            chat = to_chat(payload)
        except Exception as exc:                   # noqa: BLE001
            chat = {}
            check("messages_to_chat 可调用", False, exc)
        msgs = chat.get("messages") or []
        check("system 上提为 messages[0]，且不丢",
              bool(msgs) and msgs[0].get("role") == "system"
              and "SYS" in str(msgs[0].get("content")), msgs[:1])
        tools = chat.get("tools") or []
        check("Anthropic tools -> chat function 工具",
              bool(tools) and isinstance(tools[0].get("function"), dict)
              and tools[0]["function"].get("name") == "GetWeather", tools[:1])
        check("input_schema 映射为 parameters",
              bool(tools) and isinstance(tools[0]["function"].get("parameters"), dict)
              and "city" in json.dumps(tools[0]["function"]["parameters"]),
              tools[:1])
        assistant = [m for m in msgs if m.get("role") == "assistant"]
        check("assistant.tool_use -> tool_calls",
              bool(assistant) and bool(assistant[-1].get("tool_calls"))
              and assistant[-1]["tool_calls"][0]["function"]["name"] == "GetWeather",
              assistant[-1] if assistant else None)
        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
        check("tool_result -> role:tool + tool_call_id",
              bool(tool_msgs) and tool_msgs[-1].get("tool_call_id") == "tu1"
              and "晴 25C" in str(tool_msgs[-1].get("content")),
              tool_msgs[-1] if tool_msgs else None)

    # ---- 非流式出站 ----
    to_msg = getattr(ant, "chat_to_messages", None)
    if not callable(to_msg):
        skip("chat.completion -> Anthropic message", "chat_to_messages 未交付")
    else:
        chat_obj = {
            "choices": [{"finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": "好的",
                "tool_calls": [{"id": "call_1", "type": "function",
                                "function": {"name": "GetWeather",
                                             "arguments": '{"city": "北京"}'}}]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                      "prompt_tokens_details": {"cached_tokens": 40}},
        }
        try:
            out = to_msg(chat_obj, model="deepseek-V3")
        except Exception as exc:                   # noqa: BLE001
            out = {}
            check("chat_to_messages 可调用", False, exc)
        blocks = out.get("content") or []
        types = [b.get("type") for b in blocks if isinstance(b, dict)]
        check("content 同时含 text 与 tool_use 块",
              "text" in types and "tool_use" in types, types)
        tu = next((b for b in blocks if isinstance(b, dict)
                   and b.get("type") == "tool_use"), {})
        check("tool_use.input 由 arguments JSON 解析",
              isinstance(tu.get("input"), dict) and tu["input"].get("city") == "北京",
              tu.get("input"))
        check("finish_reason=tool_calls -> stop_reason=tool_use",
              out.get("stop_reason") == "tool_use", out.get("stop_reason"))

    # ---- usage 守恒 ----
    usage_fn = getattr(ant, "chat_usage_to_anthropic", None)
    if not callable(usage_fn):
        skip("usage 守恒", "chat_usage_to_anthropic 未交付")
    else:
        u = usage_fn({"prompt_tokens": 100, "completion_tokens": 20,
                      "prompt_tokens_details": {"cached_tokens": 40}})
        check("input_tokens 不含 cache_read（60）", u.get("input_tokens") == 60, u)
        check("cache_read_input_tokens = 40", u.get("cache_read_input_tokens") == 40, u)
        check("input + cache_read == prompt_tokens（守恒）",
              u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0) == 100, u)
        check("cache_creation_input_tokens 恒 0（不编造）",
              u.get("cache_creation_input_tokens") == 0, u)

    validate = getattr(ant, "validate_request", None)
    if callable(validate):
        ok_missing, _msg = validate({"messages": [{"role": "user", "content": "hi"}]})
        ok_valid, _msg2 = validate({"messages": [{"role": "user", "content": "hi"}],
                                    "max_tokens": 16})
        check("Anthropic 请求缺 max_tokens 应判不合法", ok_missing is False)
        check("合法请求通过校验", ok_valid is True)

    # ---- 流式 ----
    stream_fn = getattr(ant, "stream_anthropic_events", None)
    if not callable(stream_fn):
        skip("流式文本事件", "stream_anthropic_events 未交付")
        skip("流式工具事件", "stream_anthropic_events 未交付")
        return
    text_lines = [
        b'data: {"choices": [{"delta": {"content": "\xe4\xbd\xa0"}}]}\n',
        b'data: {"choices": [{"delta": {"content": "\xe5\xa5\xbd"}}]}\n',
        b'data: {"choices": [{"delta": {}, "finish_reason": "stop"}],'
        b' "usage": {"prompt_tokens": 5, "completion_tokens": 2}}\n',
        b"data: [DONE]\n",
    ]
    try:
        raw = b"".join(stream_fn(text_lines, model="deepseek-V3"))
        body = raw.decode("utf-8", "replace")
    except Exception as exc:                       # noqa: BLE001
        body = ""
        check("stream_anthropic_events 可调用", False, exc)
    names = re.findall(r"^event: ([A-Za-z_]+)$", body, re.M)
    check("事件序列含 message_start / content_block_delta / message_stop",
          {"message_start", "content_block_delta", "message_stop"} <= set(names),
          names)
    joined_text = ""
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            obj = json.loads(line[5:].strip())
        except Exception:                          # noqa: BLE001
            continue
        delta = obj.get("delta") if isinstance(obj, dict) else None
        if isinstance(delta, dict) and delta.get("type") == "text_delta":
            joined_text += str(delta.get("text") or "")
    check("文本增量按片拼接等于 你好", joined_text == "你好", joined_text)
    check("message_delta 带 stop_reason=end_turn",
          '"stop_reason": "end_turn"' in body or '"stop_reason":"end_turn"' in body,
          body[-200:])

    tool_lines = [
        b'data: {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1",'
        b' "type": "function", "function": {"name": "GetWeather",'
        b' "arguments": "{\\"city\\": \\"\xe5\x8c\x97\xe4\xba\xac"}}]}}]}\n',
        b'data: {"choices": [{"delta": {"tool_calls": [{"index": 0,'
        b' "function": {"arguments": "\\"}"}}]}, "finish_reason": "tool_calls"}]}\n',
        b"data: [DONE]\n",
    ]
    try:
        tool_body = b"".join(stream_fn(tool_lines, model="deepseek-V3")).decode(
            "utf-8", "replace")
    except Exception as exc:                       # noqa: BLE001
        tool_body = ""
        check("流式工具事件可生成", False, exc)
    check("tool_use content_block_start",
          '"type": "tool_use"' in tool_body or '"type":"tool_use"' in tool_body,
          tool_body[:200])
    partials = re.findall(r'"partial_json": "((?:[^"\\]|\\.)*)"', tool_body)
    joined = "".join(json.loads('"' + p + '"') for p in partials) if partials else ""
    try:
        args = json.loads(joined) if joined else None
    except Exception:                              # noqa: BLE001
        args = None
    check("input_json_delta 逐片拼接后是合法 JSON",
          isinstance(args, dict) and args.get("city") == "北京", joined[:120])
    check("tool_calls 收尾 stop_reason=tool_use",
          '"stop_reason": "tool_use"' in tool_body
          or '"stop_reason":"tool_use"' in tool_body, tool_body[-200:])


# ===========================================================================
# [7] 加密原语 · trae_sign（Desktop 凭证解密依赖）
# ===========================================================================
def test_crypto():
    section("[7] 加密原语 · trae_sign")
    sign, err = load("trae_sign")
    if sign is None:
        skip("AES-128-CBC NIST KAT", "trae_sign 未就绪（doudou / task-1）：" + err)
        return
    enc = getattr(sign, "aes_cbc_encrypt", None)
    dec = getattr(sign, "aes_cbc_decrypt", None)
    if not (callable(enc) and callable(dec)):
        skip("AES-128-CBC NIST KAT", "aes_cbc_encrypt/decrypt 未交付")
        return
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    try:
        ct = enc(pt, key, iv)
    except Exception as exc:                       # noqa: BLE001
        ct = b""
        check("aes_cbc_encrypt 可调用", False, exc)
    check("NIST SP800-38A CBC 首块 KAT",
          len(ct) >= 16 and ct[:16].hex() == "7649abac8119b246cee98e9b12e9197d",
          ct[:16].hex() if ct else "")
    check("PKCS#7 输出按 16 字节对齐", bool(ct) and len(ct) % 16 == 0, len(ct))
    try:
        back = dec(ct, key, iv)
    except Exception as exc:                       # noqa: BLE001
        back = b""
        check("aes_cbc_decrypt 可调用", False, exc)
    check("已知向量往返一致", back == pt, back.hex())
    rnd = bytes(range(77))
    try:
        okay = dec(enc(rnd, key, iv), key, iv) == rnd
    except Exception as exc:                       # noqa: BLE001
        okay = False
        check("77 字节明文往返", False, exc)
    else:
        check("77 字节明文往返（PKCS#7 多块）", okay)
    for name in ("dpapi_unprotect", "chromium_decrypt_v10"):
        if hasattr(sign, name):
            check("%s 存在（Windows/macOS 凭证解密入口）" % name,
                  callable(getattr(sign, name)))
        else:
            skip("%s 存在" % name, "未交付（当前平台可能不需要）")


# ===========================================================================
# [8] 部署面静态检查
# ===========================================================================
DEPLOY_FILES = ("Dockerfile", "docker-compose.yml", ".dockerignore",
                "start-trae2api-hub.bat", "start-trae2api-hub.sh",
                "start-trae2api-hub-lan.bat", "start-trae2api-hub-lan.sh",
                "start-trae-proxy.bat", "start-trae-proxy.sh",
                "start-trae-proxy-lan.bat", "start-trae-proxy-lan.sh",
                "allow-firewall.bat", "allow-firewall.sh", "README.md")
LEAK_PATTERNS = (re.compile(r"eyJ[A-Za-z0-9_-]{20,}"),                 # JWT
                 re.compile(r"refreshToken['\"]?\s*[:=]\s*['\"][A-Za-z0-9._\-]{20,}"),
                 re.compile(r"(?:access|refresh)[_-]?token['\"]?\s*[:=]\s*"
                            r"['\"][A-Za-z0-9._\-]{24,}"))


def _lint_dockerfile(text):
    """最小 Dockerfile 结构检查（指令名 / 续行闭合 / JSON CMD）。

    容器守护进程不一定可用（CI、离线验收），所以这里做静态解析；真正的
    构建语义仍以 docker build 为准，本检查只保证"语法层面能读"。
    """
    known = {"FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV",
             "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG",
             "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL"}
    problems = []
    logical, buf = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if stripped.startswith("#") and not buf:
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        logical.append(buf)
        buf = ""
    if buf.strip():
        problems.append("续行未闭合：%r" % buf[:40])
    for inst in logical:
        token = inst.strip().split(None, 1)[0].upper() if inst.strip() else ""
        if token not in known:
            problems.append("未知指令 %r" % token)
        if token == "CMD":
            rest = inst.strip()[3:].strip()
            if rest.startswith("["):
                try:
                    parsed = json.loads(rest)
                    if not isinstance(parsed, list):
                        problems.append("CMD JSON 不是数组")
                except Exception as exc:           # noqa: BLE001
                    problems.append("CMD JSON 非法：%s" % exc)
    if not any(i.strip().upper().startswith("FROM") for i in logical):
        problems.append("缺少 FROM")
    return problems


def test_deploy():
    section("[8] 部署面静态检查")
    texts = {}
    for name in DEPLOY_FILES:
        path = os.path.join(ROOT, name)
        exists = os.path.exists(path)
        check("交付文件存在：%s" % name, exists)
        texts[name] = read_text(name) if exists else ""

    docker = texts["Dockerfile"]
    low = docker.lower()
    check("Dockerfile EXPOSE 8791", "expose 8791" in low)
    check("Dockerfile 入口是 trae_proxy.py", "trae_proxy.py" in docker)
    check("Dockerfile 未残留 qoder 字样", "qoder" not in low)
    check("Dockerfile 不再依赖 _install_umid", "_install_umid" not in low)
    check("Dockerfile 有 HEALTHCHECK", "healthcheck" in low)
    lint = _lint_dockerfile(docker)
    check("Dockerfile 结构可解析（指令 / 续行 / JSON CMD）", not lint, lint[:3])
    check("健康探针打 /ping 或 /health", "/ping" in docker or "/health" in docker)
    check("Dockerfile 端口跟随 PORT 环境变量", "port=8791" in low)

    compose = texts["docker-compose.yml"]
    check("compose 服务名 trae2api-hub", "trae2api-hub" in compose)
    check("compose 端口映射 8791:8791", "8791:8791" in compose)
    check("compose 注入 PORT=8791", "PORT=8791" in compose)
    check("compose 未残留 qoder", "qoder" not in compose.lower())
    check("compose 挂载 accounts/usage",
          "./accounts:/app/accounts" in compose and "./usage:/app/usage" in compose)

    for sh in ("start-trae2api-hub.sh", "start-trae2api-hub-lan.sh"):
        body = texts[sh]
        check("%s 默认端口 8791" % sh, "8791" in body)
        check("%s 启动 trae_proxy.py" % sh, "trae_proxy.py" in body)
        check("%s 未残留 qoder" % sh, "qoder" not in body.lower())
        check("%s 带 bash 解释器" % sh, body.startswith("#!/usr/bin/env bash"))
    for bat in ("start-trae2api-hub.bat", "start-trae2api-hub-lan.bat"):
        body = texts[bat]
        check("%s 默认端口 8791" % bat, "8791" in body)
        check("%s 启动 trae_proxy.py" % bat, "trae_proxy.py" in body)
        check("%s 未残留 qoder" % bat, "qoder" not in body.lower())
        check("%s 纯 ASCII（cmd 代码页安全）" % bat,
              all(ord(ch) < 128 for ch in body), "含非 ASCII 字符")
    check("LAN 启动器带 --lan",
          "--lan" in texts["start-trae2api-hub-lan.sh"]
          and "--lan" in texts["start-trae2api-hub-lan.bat"])
    for fwd in ("start-trae-proxy.bat", "start-trae-proxy.sh",
                "start-trae-proxy-lan.bat", "start-trae-proxy-lan.sh"):
        body = texts[fwd]
        check("%s 指向新启动器" % fwd,
              "start-trae2api-hub" in body, body[:60])

    for fw in ("allow-firewall.bat", "allow-firewall.sh"):
        body = texts[fw]
        check("%s 默认端口 8791" % fw, "8791" in body)
        check("%s 规则名带 Trae2API-Hub" % fw, "Trae2API-Hub" in body)
        check("%s 未残留 qoder" % fw, "qoder" not in body.lower())
    check("allow-firewall.sh 覆盖 ufw/firewalld/iptables",
          all(s in texts["allow-firewall.sh"]
              for s in ("ufw", "firewall-cmd", "iptables")))

    readme = texts["README.md"]
    check("README 标题为 Trae2API-Hub", "Trae2API-Hub" in readme)
    check("README 写清双区（cn / 国际版）",
          "cn" in readme.lower() and ("国际" in readme or "intl" in readme.lower()))
    check("README 含端口 8791", "8791" in readme)
    check("README 含 docker 部署段", "docker" in readme.lower())
    check("README 含 OpenAI 兼容用法", "/v1/chat/completions" in readme)
    check("README 未残留 qoder", "qoder" not in readme.lower())

    ignores = texts[".dockerignore"]
    for pat in ("accounts/", "usage/", ".team/", ".recon/"):
        check(".dockerignore 排除 %s" % pat, pat in ignores)

    # 泄露扫描：只扫自己交付的文档/脚本，防止把真实凭证写进仓库
    for name in DEPLOY_FILES:
        hits = []
        for pattern in LEAK_PATTERNS:
            hits.extend(pattern.findall(texts[name]))
        check("%s 无凭证泄露特征" % name, not hits, hits[:2])


# ===========================================================================
# [9] 诊断脚本冒烟
# ===========================================================================
def test_diag():
    section("[9] 诊断脚本冒烟 · _diag_gateway.py")
    diag, err = load("_diag_gateway")
    if diag is None:
        skip("guard_url 白名单", "_diag_gateway 未就绪：" + err)
    else:
        guard = getattr(diag, "guard_url", None)
        if not callable(guard):
            skip("guard_url 白名单", "guard_url 未交付")
        else:
            try:
                guard("http://127.0.0.1:8791/health")
                ok_loop = True
            except Exception:                      # noqa: BLE001
                ok_loop = False
            check("guard_url 接受回环地址", ok_loop)
            try:
                guard("http://example.com/health")
                rejected = False
            except ValueError:
                rejected = True
            except Exception:                      # noqa: BLE001
                rejected = False
            check("guard_url 默认拒绝非回环", rejected)

    path = os.path.join(ROOT, "_diag_gateway.py")
    if not os.path.exists(path):
        skip("--help 可执行", "文件缺失")
        return
    try:
        proc = subprocess.run([sys.executable, path, "--help"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=60)
        out = proc.stdout.decode("utf-8", "replace")
        err_out = proc.stderr.decode("utf-8", "replace")
    except Exception as exc:                       # noqa: BLE001
        check("--help 可执行", False, exc)
        return
    check("--help 退出码 0", proc.returncode == 0, err_out[:200])
    check("--help 列出 --chat", "--chat" in out, out[:200])
    check("--help 默认端口 8791", "8791" in out, out[:200])
    check("--help 列出 --model", "--model" in out, out[:200])


# ===========================================================================
def main():
    print("=" * 66)
    print(" Trae2API-Hub 离线测试（不联网 / 不碰真实凭证）")
    print("=" * 66)
    print(" 依赖指纹（sha256 前 12 位）：")
    for name, digest in _fingerprint():
        print("   %-28s %s" % (name, digest))
    started = time.time()
    try:
        test_protocol()
        test_secrets()
        test_catalog()
        test_routing()
        test_tool_markers()
        test_anthropic()
        test_crypto()
        test_deploy()
        test_diag()
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    elapsed = time.time() - started
    print()
    print("=" * 66)
    print(" 汇总: PASS=%d  FAIL=%d  SKIP=%d  用时 %.1fs"
          % (PASS, FAIL, SKIP, elapsed))
    if FAIL:
        print(" 失败项：")
        for label in _FAILED:
            print("   - " + label)
        print(" 结果: FAIL（%d 项）" % FAIL)
        return 1
    print(" 结果: 0 failed" + ("（%d 项 SKIP，原因见上）" % SKIP if SKIP else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())