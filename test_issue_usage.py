#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_issue_usage.py —— 流式 usage 记账回归（usage=None 不记账 / 去重 / 缓存口径）

约束（与 lead 的接线约定一致）：
  · 只用 tempfile 临时目录与内存假账号池，**绝不读取真实凭证/真实 usage 日志**；
  · 去重**只认显式 request_id**，不按 model/account/指纹/耗时猜；
  · 上游真实给出的全 0 usage 属于「已知 0」，不当缺失；
  · stats 与 proxy 必须读同一份文件（configure 显式接线）。

跑法：python test_issue_usage.py    （全 PASS 退出码 0）
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import trae_proxy as P          # noqa: E402
import trae_stats as S          # noqa: E402

FAILS = []
CHECKS = [0]

# 在改动任何全局之前先记录两个模块的默认路径（同源断言用）
DEFAULT_PROXY_DIR = P.USAGE_DIR
DEFAULT_STATS_DIR = S.USAGE_DIR


def check(name, cond, extra=""):
    CHECKS[0] += 1
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  << " + str(extra)))
    if not cond:
        FAILS.append(name)


class FakeAccount(object):
    def __init__(self, uid, realm="cn"):
        self.uid = uid
        self.realm = realm
        self.display_name = "fake-" + uid[-2:]
        self.enabled = True
        self.token = "x" * 8          # 假 token：仅长度语义


class FakePool(object):
    def __init__(self, accounts):
        self.accounts = accounts

    def get(self, uid):
        for a in self.accounts:
            if a.uid == uid:
                return a
        return None

    def pick(self, realm=None, exclude=None, model=None, session_key=None,
             **kwargs):
        for a in self.accounts:
            if realm and getattr(a, "realm", "") != realm:
                continue
            if exclude and a.uid in exclude:
                continue
            return a
        return None

    def note_usage(self, uid, usage=None, entitlement=None):
        return None


TMP = tempfile.mkdtemp(prefix="trae-usage-test-")
LOG_PATH = os.path.join(TMP, "usage.jsonl")
SUMMARY_PATH = os.path.join(TMP, "usage-summary.json")


def reset():
    """重置到干净的临时夹具（proxy 直接改全局，stats 走 configure 以覆盖 API）。"""
    for path in (LOG_PATH, SUMMARY_PATH):
        if os.path.exists(path):
            os.remove(path)
    P.USAGE_DIR = TMP
    P.USAGE_LOG = LOG_PATH
    P.USAGE_SUMMARY = SUMMARY_PATH
    P._usage = P._empty_stats()
    with P._USAGE_DEDUPE_LOCK:
        P._USAGE_DEDUPE_SEEN.clear()
    P.POOL = FakePool([FakeAccount("1001"), FakeAccount("2002", "intl")])
    S.configure(usage_dir=TMP, log_path=LOG_PATH, summary_path=SUMMARY_PATH,
                pool=P.POOL, log=lambda *a, **k: None)
    return LOG_PATH


def rows(log_path=None):
    log_path = log_path or LOG_PATH
    if not os.path.exists(log_path):
        return []
    out = []
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def fresh_stats(range_val="all"):
    S.configure(usage_dir=TMP, log_path=LOG_PATH, summary_path=SUMMARY_PATH)
    return S.compute_usage_stats(range_val=range_val)


# ---------------------------------------------------------------------------
# 0) 路径同源：默认值与 TRAE_PROXY_USAGE_DIR 覆盖下都必须一致
# ---------------------------------------------------------------------------
check("0 默认 USAGE_DIR 两模块同源", DEFAULT_PROXY_DIR == DEFAULT_STATS_DIR,
      (DEFAULT_PROXY_DIR, DEFAULT_STATS_DIR))

env = dict(os.environ)
env["TRAE_PROXY_USAGE_DIR"] = os.path.join(TMP, "logs", "runtime", "usage")
proc = subprocess.run(
    [sys.executable, "-c",
     "import trae_proxy as p, trae_stats as s;"
     "print(p.USAGE_DIR); print(s.USAGE_DIR);"
     "print(p.USAGE_DIR == s.USAGE_DIR)"],
    cwd=HERE, env=env, capture_output=True, text=True, timeout=120)
lines = [ln.strip() for ln in (proc.stdout or "").strip().splitlines()]
check("0 环境变量覆盖后两模块同源",
      len(lines) == 3 and lines[2] == "True"
      and lines[0].endswith(os.path.join("logs", "runtime", "usage")),
      (proc.stdout, proc.stderr[-300:]))

# ---------------------------------------------------------------------------
# 1) 上游 usage 完整：正常记账
# ---------------------------------------------------------------------------
reset()
P.record_usage("deepseek-V3", {
    "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
    "prompt_tokens_details": {"cached_tokens": 40},
}, stream=True, elapsed_ms=800, ttft_ms=200, gen_ms=600,
    account="1001", fp={"msgs_sha": "abc"})
r = rows()
check("1 完整 usage 记一行", len(r) == 1, r)
check("1 usage_missing=False", r and r[0]["usage_missing"] is False, r[:1])
check("1 cached_reported=True", r and r[0]["cached_reported"] is True, r[:1])
check("1 token 落盘", r and r[0]["prompt_tokens"] == 100
      and r[0]["total_tokens"] == 120, r[:1])
check("1 cache_hit_pct=40", r and r[0].get("cache_hit_pct") == 40.0, r[:1])
check("1 汇总 requests=1", P._usage["requests"] == 1, P._usage["requests"])

# ---------------------------------------------------------------------------
# 2) usage=None（上游没发 token_usage）：仍记一次请求，未知就是未知
# ---------------------------------------------------------------------------
reset()
P.record_usage("deepseek-V3", None, stream=True, elapsed_ms=900,
               ttft_ms=120, gen_ms=780, account="1001",
               fp={"msgs_sha": "abc"})
r = rows()
check("2 usage=None 仍记一行", len(r) == 1, r)
check("2 usage_missing=True", r and r[0]["usage_missing"] is True, r[:1])
check("2 usage_source=missing", r and r[0]["usage_source"] == "missing", r[:1])
check("2 cached_reported=False", r and r[0]["cached_reported"] is False, r[:1])
check("2 不伪造 cache_hit_pct", r and "cache_hit_pct" not in r[0], r[:1])
check("2 不伪造 tokens_per_sec", r and "tokens_per_sec" not in r[0], r[:1])
check("2 token 未知记 0", r and r[0].get("prompt_tokens", 0) == 0
      and r[0].get("total_tokens", 0) == 0, r[:1])
check("2 汇总 requests=1/tokens=0", P._usage["requests"] == 1
      and P._usage["total_tokens"] == 0, P._usage)

# ---------------------------------------------------------------------------
# 3) 有 token 但没报 cache 字段：不能伪造成 0% 命中
# ---------------------------------------------------------------------------
reset()
P.record_usage("claude-x", {"prompt_tokens": 50, "completion_tokens": 5,
                            "total_tokens": 55}, stream=False, elapsed_ms=300,
               account="2002")
r = rows()
check("3 usage_missing=False", r and r[0]["usage_missing"] is False, r[:1])
check("3 无 cache 字段 -> cached_reported=False",
      r and r[0]["cached_reported"] is False, r[:1])
check("3 不产出 cache_hit_pct", r and "cache_hit_pct" not in r[0], r[:1])

# ---------------------------------------------------------------------------
# 4) 上游真实给出全 0 usage：已知 0，不是缺失
# ---------------------------------------------------------------------------
reset()
P.record_usage("m-zero", {"prompt_tokens": 0, "completion_tokens": 0,
                          "total_tokens": 0}, stream=True, elapsed_ms=42)
r = rows()
check("4 全 0 usage 记一行", len(r) == 1, r)
check("4 usage_missing=False（已知 0）",
      r and r[0]["usage_missing"] is False, r[:1])
check("4 usage_source=upstream", r and r[0]["usage_source"] == "upstream", r[:1])
check("4 token 记为 0 而非缺失", r and r[0]["total_tokens"] == 0
      and r[0]["prompt_tokens"] == 0, r[:1])
check("4 cached_reported=False（没报 cache）",
      r and r[0]["cached_reported"] is False, r[:1])

# ---------------------------------------------------------------------------
# 5) 去重只认 request_id：同提示同毫秒也必须记两次
# ---------------------------------------------------------------------------
reset()
same = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
P.record_usage("m", same, stream=True, elapsed_ms=10,
               fp={"msgs_sha": "identical"}, account="1001")
P.record_usage("m", same, stream=True, elapsed_ms=10,
               fp={"msgs_sha": "identical"}, account="1001")
check("5 无 request_id 的相同请求各记一行（不猜重复）", len(rows()) == 2, rows())
check("5 汇总 requests=2", P._usage["requests"] == 2, P._usage["requests"])

reset()
P.record_usage("m", same, stream=True, elapsed_ms=10, request_id="req-1")
P.record_usage("m", same, stream=True, elapsed_ms=11, request_id="req-1")
check("5 同 request_id 只记一行", len(rows()) == 1, rows())
check("5 汇总 requests 只加一次", P._usage["requests"] == 1, P._usage["requests"])
P.record_usage("m", same, stream=True, elapsed_ms=12, request_id="req-2")
check("5 新 request_id 再记一行", len(rows()) == 2, rows())
check("5 空 request_id 不去重", P._usage_dedupe_key("") is None, None)
expired_key = P._usage_dedupe_key("expired-request")
P._USAGE_DEDUPE_SEEN[expired_key] = time.time() - P._USAGE_DEDUPE_TTL - 1
check("5 TTL 过期可重新记账（小表也过期）", P._claim_usage_record(expired_key), None)

# ---------------------------------------------------------------------------
# 6) 统计层：range 生效、缺失行计入 requests、缓存口径跳过未知行
# ---------------------------------------------------------------------------
reset()
P.record_usage("m1", {"prompt_tokens": 200, "completion_tokens": 10,
                      "total_tokens": 210,
                      "prompt_tokens_details": {"cached_tokens": 100}},
               stream=True, elapsed_ms=100, account="1001")
P.record_usage("m2", None, stream=True, elapsed_ms=200, account="1001")
P.record_usage("m3", {"prompt_tokens": 80, "completion_tokens": 4,
                      "total_tokens": 84}, stream=True, elapsed_ms=300,
               account="2002")
P.record_usage("m4", {"prompt_tokens": 0, "completion_tokens": 0,
                      "total_tokens": 0}, stream=True, elapsed_ms=400,
               account="1001")

st = fresh_stats()
check("6 range 参数未被内置 range 覆盖", st["window"]["range"] == "all",
      st["window"]["range"])
check("6 requests=4（含缺失行与已知 0 行）", st["kpi"]["requests"] == 4,
      st["kpi"])
check("6 usage_missing=1", st["kpi"].get("usage_missing") == 1, st["kpi"])
check("6 tokens 只算已知值 210+84", st["kpi"]["tokens"] == 294,
      st["kpi"]["tokens"])
w = {row["key"]: row for row in st["cache"]["windows"]}
check("6 缓存分母只含已报 cache 的行（200）", w["24h"]["input"] == 200, w)
check("6 缓存命中=100", w["24h"]["hit"] == 100, w)
check("6 缓存命中率=50%", w["24h"]["pct"] == 50.0, w)
st_today = S.compute_usage_stats(range_val="today")
check("6 today 窗口可用", st_today["window"]["from"] is not None,
      st_today["window"])

# ---------------------------------------------------------------------------
# 7) configure()：显式接线后 stats 读的就是这份文件；无 nickname 也不炸
# ---------------------------------------------------------------------------
reset()
P.record_usage("m", {"prompt_tokens": 7, "completion_tokens": 3,
                     "total_tokens": 10}, stream=True, elapsed_ms=5,
               account="1001")
rep = {}
err = ""
try:
    rep = S.cached_usage_report("stats", ttl=0, range="all") or {}
    ok = isinstance(rep, dict) and rep.get("kpi", {}).get("requests") == 1
except Exception as exc:                      # noqa: BLE001
    ok, err = False, repr(exc)
check("7 configure 后报表读到同一文件", ok, (err, rep.get("kpi")))
check("7 账号排行带展示名",
      any(row.get("name") for row in (rep.get("top_accounts") or [])),
      rep.get("top_accounts"))
check("7 configure 返回生效路径",
      (S.configure(usage_dir=TMP) or {}).get("usage_log") == LOG_PATH,
      S.configure(usage_dir=TMP))

# ---------------------------------------------------------------------------
# 8) 缺失行不污染缓存/售价判定（cached_reported=False 的语义）
# ---------------------------------------------------------------------------
reset()
P.record_usage("m", None, stream=True, elapsed_ms=1)
r = rows()
check("8 缺失行 cached_reported=False", r and r[0]["cached_reported"] is False, r[:1])
st = fresh_stats()
check("8 缺失行不计入缓存分母", st["cache"]["windows"][0]["input"] == 0, st["cache"])
check("8 full_price 不因缺失行触发", st["full_price"]["requests"] == 0,
      st["full_price"])

# ---------------------------------------------------------------------------
# 8.5) 账号查询容错：池子没有 get()（baseline SOLO 桩池就是这种）也不能阻断记账
# ---------------------------------------------------------------------------
class FakePoolNoGet(object):
    """只有 accounts + pick，没有 get：模拟 baseline 的 _FakePool。"""
    def __init__(self, accounts):
        self.accounts = accounts

    def pick(self, realm=None, **kwargs):
        return self.accounts[0] if self.accounts else None


reset()
P.POOL = FakePoolNoGet([FakeAccount("1001")])
P.record_usage("m-noget", {"prompt_tokens": 3, "completion_tokens": 1,
                           "total_tokens": 4}, stream=False, elapsed_ms=2,
               account="1001")
r = rows()
check("8.5 池子无 get() 仍能记账", len(r) == 1 and r[0]["total_tokens"] == 4,
      r[:1])
check("8.5 realm 回退到当前区", bool(r) and r[0].get("realm") == P.CURRENT_REALM,
      r[:1])
check("8.5 未知 uid 不抛", P.pool_account(P.POOL, "missing") is None, None)
check("8.5 空池不抛", P.pool_account(None, "x") is None
      and P.pool_account(object(), "x") is None, None)

# ---------------------------------------------------------------------------
# 9) 真实 HTTP SOLO：/v1/agent/chat stream，上游 usage=None（成功必记一行）
# 10) SOLO 失败路径：502 + 一行 error，且不产生 usage 行
#
# 背景：_handle_agent_solo 曾完全没有 record_usage（漏记第二根因）；接线后
# 失败路径又因为给 record_error 多传 stream= 抛 TypeError（客户端拿到 500）。
# 本用例走真实 HTTP + 真 SSE 写回，只把上游 trae_solo_chat 换成假实现，
# 两个分支都是**硬断言**（不再 SKIP）。
# ---------------------------------------------------------------------------
import http.server as _http_server      # noqa: E402
import inspect as _inspect              # noqa: E402
import threading as _threading          # noqa: E402
import urllib.request as _urlreq        # noqa: E402

_solo_src = _inspect.getsource(P.Handler._handle_agent_solo)
check("9 SOLO 已接线 record_usage", "record_usage(" in _solo_src, "未接线")

_orig_banned = P.is_model_banned
P.is_model_banned = lambda model: False    # 不读真实 settings


def _serve():
    """起一个临时 HTTP 服务（真 Handler），返回 (base_url, httpd, thread)。"""
    P.Handler._key_ok = lambda self: True          # 跳过 API key/面板鉴权
    httpd = _http_server.ThreadingHTTPServer(("127.0.0.1", 0), P.Handler)
    th = _threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    return "http://127.0.0.1:%d" % httpd.server_address[1], httpd, th


def _post(url, body, timeout=20):
    data = json.dumps(body).encode("utf-8")
    req = _urlreq.Request(url, data=data, method="POST",
                          headers={"Content-Type": "application/json"})
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except _urlreq.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


_orig_solo = getattr(P, "trae_solo_chat", None)

# ---- 9) 成功：usage=None ----
reset()
P.trae_solo_chat = lambda account, payload: {
    "content": "solo-ok", "reasoning": "", "tool_calls": [],
    "finish_reason": "stop", "usage": None,      # 关键：上游没给 usage
}
base, httpd, th = _serve()
try:
    status, text = _post(base + "/v1/agent/chat", {
        "model": "deepseek-v4.1-flash",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
    })
finally:
    httpd.shutdown()
    httpd.server_close()

r = rows()
check("9 SOLO 流式 HTTP 200", status == 200, (status, text[:300]))
check("9 SOLO 流式真的走了 SSE", "data: " in text and "[DONE]" in text,
      text[:300])
check("9 SOLO 成功只记一行", len(r) == 1, r)
check("9 SOLO usage=None -> usage_missing",
      bool(r) and r[0].get("usage_missing") is True, r[:1])
check("9 SOLO 行 model 正确",
      bool(r) and r[0].get("model") == "deepseek-v4.1-flash", r[:1])
check("9 SOLO 行 stream=True", bool(r) and r[0].get("stream") is True, r[:1])
check("9 SOLO 行带 request_id", bool(r) and len(str(r[0].get("request_id") or "")) >= 8,
      r[:1])
check("9 SOLO token 记 0（未知）",
      bool(r) and r[0].get("total_tokens", 0) == 0, r[:1])

# ---- 10) 失败：上游抛错 ----
reset()
def _boom(account, payload):
    raise RuntimeError("solo upstream down")
P.trae_solo_chat = _boom
base, httpd, th = _serve()
try:
    status2, text2 = _post(base + "/v1/agent/chat", {
        "model": "deepseek-v4.1-flash",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
    })
finally:
    httpd.shutdown()
    httpd.server_close()

r2 = rows()
check("10 SOLO 失败 HTTP 502（不是 500）", status2 == 502, (status2, text2[:400]))
check("10 SOLO 失败记 error 行",
      len(r2) == 1 and r2[0].get("error") is True, r2)
check("10 SOLO 失败没有 usage 行",
      all(row.get("error") for row in r2), r2)
check("10 error 行 status=502 且有 message",
      bool(r2) and r2[0].get("status") == 502
      and bool(str(r2[0].get("message") or "").strip()), r2[:1])

# record_error 的签名兼容性（SOLO 曾因多传 stream= 抛 TypeError -> 客户端 500）
reset()
P.record_error("m-direct", 502, "boom", elapsed_ms=3, stream=True,
               account="1001", key_id="panel-1")
rd = rows()
check("10 record_error 兼容 stream/account/key_id",
      len(rd) == 1 and rd[0].get("stream") is True
      and rd[0].get("account") == "1001" and rd[0].get("key_id") == "panel-1",
      rd[:1])
_t = None
try:
    P.record_error("m-direct", 502, "boom", bogus_kw=1)
except TypeError as exc:
    _t = exc
check("10 record_error 未知关键字仍报错（不静默吞）", isinstance(_t, TypeError), _t)

P.is_model_banned = _orig_banned
if _orig_solo is not None:
    P.trae_solo_chat = _orig_solo

print("")
print("CHECKS=%d FAILS=%d" % (CHECKS[0], len(FAILS)))
if FAILS:
    print("FAILED: " + ", ".join(FAILS))
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAILS else 0)
