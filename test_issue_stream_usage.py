# -*- coding: utf-8 -*-
"""issue: SOLO 流式响应必须把 usage 帧发给客户端

覆盖 1.7.0 引入、1.7.1 仍在的回归：`_handle_agent_solo()` 的流式回放分支
（1.6.0 L10649-10653）原本在 finish 帧与 `[DONE]` 之间补一帧
`{"choices": [], "usage": {...}}`，1.7.0 起这一帧被删掉，客户端再也拿不到
本次请求的 token 数。

为什么要钉住它：按 usage 计算上下文占用的客户端（例如 DSH，`CHARS_PER_TOKEN
= 3.5`）在拿不到 usage 时会退回「整段按字符估算」。中文里上游真实约 0.6
token/字，估算是 1/3.5 ≈ 0.29 token/字，上下文显示虚低约一半，自动压缩
（compact）因此触发太晚。

本套件只钉「帧在不在 / 值对不对 / 位置对不对」，不碰真实账号与真实上游：
账号与用量全部 tempfile，`trae_solo_chat` 被 mock，不联网。

用法：python test_issue_stream_usage.py；退出码 0 = 全通过。
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0
SKIP = 0
_FAILED = []

MODEL = "deepseek-v4.1-flash"
# 上游真实给过的一组数（本机实测 290 汉字 prompt 的非流式 usage）
USAGE = {"prompt_tokens": 174, "completion_tokens": 23, "total_tokens": 197}


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


class Http(object):
    def __init__(self, base):
        self.base = base

    def post(self, path, payload, timeout=15):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except (http.client.RemoteDisconnected, ConnectionResetError,
                urllib.error.URLError) as exc:
            return 0, "connection closed before response: %r" % (exc,)


def parse_sse(body):
    """把 SSE 文本拆成 [(kind, obj)]；kind 为 'data'/'done'/其它。"""
    frames = []
    for raw in body.split("\n"):
        line = raw.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            frames.append(("done", None))
            continue
        try:
            frames.append(("data", json.loads(payload)))
        except Exception:                              # noqa: BLE001
            frames.append(("bad", payload))
    return frames


def usage_frames(frames):
    return [obj for kind, obj in frames
            if kind == "data" and isinstance(obj, dict)
            and isinstance(obj.get("usage"), dict) and obj.get("usage")]


def main():
    global MODEL
    print("=" * 66)
    print(" SOLO 流式 usage 帧回归（真实 HTTPServer / 临时目录 / mock SOLO 上游）")
    print("=" * 66)

    try:
        import trae_proxy as P
        import trae_accounts as A
    except Exception as exc:                           # noqa: BLE001
        check("导入 trae_proxy / trae_accounts", False, exc)
        return 1

    tmp = tempfile.mkdtemp(prefix="issue-stream-usage-")
    acc_dir = os.path.join(tmp, "accounts")
    use_dir = os.path.join(tmp, "usage")
    os.makedirs(acc_dir, exist_ok=True)
    os.makedirs(use_dir, exist_ok=True)

    saved = {}
    for name, value in (
            ("ACCOUNTS_DIR", acc_dir),
            ("USAGE_DIR", use_dir),
            ("USAGE_LOG", os.path.join(use_dir, "usage.jsonl")),
            ("USAGE_SUMMARY", os.path.join(use_dir, "usage-summary.json")),
            ("REALM_STATE_FILE", os.path.join(acc_dir, "active_realm.json")),
    ):
        saved[name] = getattr(P, name, None)
        setattr(P, name, value)

    if MODEL not in P.SOLO_AGENT_MODELS:
        solo = sorted(P.SOLO_AGENT_MODELS)
        if not solo:
            check("找一个 SOLO 模型", False, "SOLO_AGENT_MODELS 为空")
            return 1
        MODEL = solo[0]
    print("  model: %s" % MODEL)

    now = time.time()

    def mk_account(uid):
        return A.Account({"uid": uid, "realm": "cn",
                          "token": "TEST-TOKEN-" + uid,
                          "refresh_token": "TEST-REFRESH-" + uid,
                          "refreshToken": "TEST-REFRESH-" + uid,
                          "expired_at": now + 3600,
                          "enabled": True})

    pool = A.AccountPool(acc_dir)
    pool.load()
    pool.add(mk_account("stream-usage-1"))
    saved["POOL"] = P.POOL
    P.POOL = pool

    # ---- mock SOLO 上游：usage 可切换为 None（模拟上游真的不给） ----
    state = {"usage": dict(USAGE)}

    def fake_solo(account, payload):
        return {"content": "solo-ok", "reasoning": "", "tool_calls": [],
                "finish_reason": "stop",
                "usage": dict(state["usage"]) if state["usage"] else None}

    saved_solo = P.trae_solo_chat
    P.trae_solo_chat = fake_solo

    class QuietHandler(P.Handler):
        def log_message(self, *args, **kwargs):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    http = Http("http://127.0.0.1:%d" % port)
    print("  server: http://127.0.0.1:%d" % port)

    base = {"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}

    try:
        # ---------------------------------------------------------------
        section("[1] 非流式：usage 在 body 里（对照组）")
        code, body = http.post("/v1/agent/chat", dict(base, stream=False))
        check("非流式 -> 200", code == 200, code)
        try:
            obj = json.loads(body)
        except Exception:                              # noqa: BLE001
            obj = {}
        check("非流式 usage.prompt_tokens == 174",
              (obj.get("usage") or {}).get("prompt_tokens") == 174,
              obj.get("usage"))

        # ---------------------------------------------------------------
        section("[2] 流式：必须有 usage 帧，且值与非流式一致")
        code, body = http.post("/v1/agent/chat", dict(base, stream=True))
        check("流式 -> 200", code == 200, code)
        frames = parse_sse(body)
        check("SSE 收尾 [DONE]", any(k == "done" for k, _ in frames),
              body[-120:])
        uf = usage_frames(frames)
        check("流式响应里存在 usage 帧", len(uf) >= 1,
              "没有 choices=[] + usage 的帧；帧数=%d" % len(frames))
        first = uf[0] if uf else {}
        check("usage 帧 choices 为空数组", first.get("choices") == [],
              first.get("choices"))
        check("usage.prompt_tokens == 174",
              (first.get("usage") or {}).get("prompt_tokens") == 174,
              first.get("usage"))
        check("usage.completion_tokens == 23",
              (first.get("usage") or {}).get("completion_tokens") == 23,
              first.get("usage"))

        # ---------------------------------------------------------------
        section("[3] 位置：finish 帧之后、[DONE] 之前")
        idx_finish = idx_usage = idx_done = -1
        for i, (kind, obj) in enumerate(frames):
            if kind == "done":
                idx_done = i
                break
            if kind != "data" or not isinstance(obj, dict):
                continue
            if usage_frames([(kind, obj)]):
                idx_usage = idx_usage if idx_usage >= 0 else i
            for ch in obj.get("choices") or []:
                if isinstance(ch, dict) and ch.get("finish_reason"):
                    idx_finish = i
        check("finish 帧存在", idx_finish >= 0, frames[:4])
        check("usage 帧在 finish 帧之后", idx_usage > idx_finish,
              (idx_finish, idx_usage))
        check("usage 帧在 [DONE] 之前", 0 <= idx_usage < idx_done,
              (idx_usage, idx_done))

        # ---------------------------------------------------------------
        section("[4] 上游不给 usage 时不伪造（usage=None）")
        state["usage"] = None
        code, body = http.post("/v1/agent/chat", dict(base, stream=True))
        check("usage=None 流式 -> 200", code == 200, code)
        frames = parse_sse(body)
        check("usage=None 时不发 usage 帧（不伪造 0）",
              len(usage_frames(frames)) == 0,
              usage_frames(frames))
        check("usage=None 仍正常收尾 [DONE]",
              any(k == "done" for k, _ in frames), body[-80:])
        state["usage"] = dict(USAGE)
    finally:
        httpd.shutdown()
        P.trae_solo_chat = saved_solo
        P.POOL = saved["POOL"]
        for name, value in saved.items():
            if name == "POOL":
                continue
            if value is None:
                continue
            setattr(P, name, value)
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("=" * 66)
    print(" %d passed, %d failed, %d skipped" % (PASS, FAIL, SKIP))
    if _FAILED:
        print(" failed: " + "; ".join(_FAILED[:8]))
    print("=" * 66)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())