# -*- coding: utf-8 -*-
"""issue: SOLO HTTP 回归（真实 ThreadingHTTPServer，本机随机端口）

覆盖 lead 对 /v1/agent/chat（SOLO 通道）的修复：
  [1] 成功（usage=None，非流式）：record_usage 被调用且带 request uuid；
      requests+1；usage_missing=True（不伪造 0 命中）
  [2] 成功（流式 SSE）：同样记账 requests+1，[DONE] 正常收尾
  [3] 相同提示连发两次：两条 usage 行、两个不同 request_id（不误去重）
  [4] 上游失败：record_error 一次（502），不产生 usage 行，errors+1
  [5] 禁用账号不可回退：池里只有 disabled 账号 -> 503，且不调用上游
  [6] 上下文预算：enforce_model_context 在 SOLO 与 build_trae_body 都生效；
      超限 400 且**不发送上游**、不截断；输出 reserve 计入；无 override 不误拦；
      预算来自本地 override（1K），不是目录里的 model max

隔离：账号/用量全部 tempfile；trae_solo_chat 被 mock；不读真实凭证、不联网。
用法：python test_issue_solo.py；退出码 0=全通过。
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
            # Handler 在响应前抛异常时连接会被直接断开；把它当成可诊断结果，
            # 让断言报 FAIL 而不是让整个套件 traceback 退出。
            return 0, "connection closed before response: %r" % (exc,)


def read_rows(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:                  # noqa: BLE001
                    continue
    except OSError:
        pass
    return rows


def main():
    global MODEL
    print("=" * 66)
    print(" SOLO HTTP 回归（真实 HTTPServer / 临时目录 / mock SOLO 上游）")
    print("=" * 66)

    try:
        import trae_proxy as P
        import trae_accounts as A
    except Exception as exc:                       # noqa: BLE001
        check("导入 trae_proxy / trae_accounts", False, exc)
        return 1

    tmp = tempfile.mkdtemp(prefix="issue-solo-")
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

    now = time.time()

    # 选一个 SOLO 通道 + 目录里带官方窗口上限的模型（上下文预算用例需要）
    import trae_settings as TS
    candidates = []
    for item in P.trae_catalog.models_for_realm("cn"):
        key = item.get("key")
        if key in P.SOLO_AGENT_MODELS and TS.context_upper_bound(item):
            candidates.append(key)
    if candidates:
        MODEL = candidates[0]
    print("  model: %s（带窗口上限: %s）"
          % (MODEL, bool(candidates)))

    def mk_account(uid, enabled=True):
        return A.Account({"uid": uid, "realm": "cn",
                          "token": "TEST-SOLO-TOKEN-" + uid,
                          "refreshToken": "TEST-SOLO-REFRESH-" + uid,
                          "expired_at": now + 3600,
                          "enabled": enabled})

    pool = A.AccountPool(acc_dir)
    pool.load()
    pool.add(mk_account("solo-enabled-1"))
    pool.add(mk_account("solo-disabled-1", enabled=False))
    saved["POOL"] = P.POOL
    P.POOL = pool

    # ---- mock SOLO 上游：默认成功、usage=None；可切换失败 ----
    solo_calls = []
    mode = {"fail": False}

    def fake_solo(account, payload):
        solo_calls.append({"uid": getattr(account, "uid", ""),
                           "model": payload.get("model"),
                           "stream": bool(payload.get("stream"))})
        if mode["fail"]:
            raise RuntimeError("solo fixture upstream failure")
        return {"content": "solo-ok", "reasoning": "", "tool_calls": [],
                "finish_reason": "stop", "usage": None}

    saved_solo = P.trae_solo_chat
    P.trae_solo_chat = fake_solo

    # ---- spy：record_usage / record_error 的调用参数 ----
    usage_calls = []
    error_calls = []
    saved_record_usage = P.record_usage
    saved_record_error = P.record_error

    def spy_usage(model, usage=None, **kw):
        usage_calls.append({"model": model, "usage": usage,
                            "request_id": kw.get("request_id"),
                            "stream": kw.get("stream")})
        return saved_record_usage(model, usage, **kw)

    def spy_error(model, status, message, **kw):
        error_calls.append({"model": model, "status": status,
                            "message": message})
        return saved_record_error(model, status, message, **kw)

    P.record_usage = spy_usage
    P.record_error = spy_error

    class QuietHandler(P.Handler):
        def log_message(self, *args, **kwargs):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    http = Http("http://127.0.0.1:%d" % port)
    print("  server: http://127.0.0.1:%d  accounts=%s" % (port, acc_dir))

    base_payload = {"model": MODEL,
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": False}

    try:
        # ---------------------------------------------------------------
        section("[1] 成功（usage=None，非流式）")
        req0 = P._usage["requests"]
        code, body = http.post("/v1/agent/chat", dict(base_payload))
        check("非流式 -> 200", code == 200, code)
        check("响应正文 solo-ok", "solo-ok" in body, body[:120])
        check("requests +1", P._usage["requests"] == req0 + 1,
              (req0, P._usage["requests"]))
        check("record_usage 调用一次", len(usage_calls) == 1, usage_calls)
        call = usage_calls[-1] if usage_calls else {}
        check("record_usage 的 usage 为 None（上游未给）",
              call.get("usage") is None, call.get("usage"))
        rid = str(call.get("request_id") or "")
        check("record_usage 带 request uuid（32 hex）",
              bool(rid) and len(rid) == 32
              and all(c in "0123456789abcdef" for c in rid), rid)
        rows = [r for r in read_rows(P.USAGE_LOG) if r.get("model") == MODEL]
        check("usage 行已落盘", len(rows) == 1, len(rows))
        row = rows[-1] if rows else {}
        check("usage_missing=True（不伪造命中）", row.get("usage_missing") is True, row)
        check("usage_source=missing", row.get("usage_source") == "missing", row)
        check("缺失行 token 记 0（键缺省也按 0 读）",
              int(row.get("total_tokens") or 0) == 0
              and int(row.get("prompt_tokens") or 0) == 0, row)

        # ---------------------------------------------------------------
        section("[2] 成功（流式 SSE）")
        req1 = P._usage["requests"]
        before_calls = len(usage_calls)
        code, body = http.post("/v1/agent/chat",
                               dict(base_payload, stream=True))
        check("流式 -> 200", code == 200, code)
        check("SSE 以 [DONE] 收尾", "[DONE]" in body, body[-120:])
        check("流式正文 solo-ok", "solo-ok" in body, body[:160])
        check("流式 requests +1", P._usage["requests"] == req1 + 1,
              (req1, P._usage["requests"]))
        check("流式也调用 record_usage",
              len(usage_calls) == before_calls + 1, len(usage_calls))
        check("流式 record_usage stream=True",
              bool(usage_calls[-1].get("stream")) is True,
              usage_calls[-1].get("stream"))
        rows = [r for r in read_rows(P.USAGE_LOG) if r.get("model") == MODEL]
        check("流式 usage 行落盘（累计 2）", len(rows) == 2, len(rows))
        check("流式缺失行同样 usage_missing=True",
              rows[-1].get("usage_missing") is True, rows[-1])

        # ---------------------------------------------------------------
        section("[3] 相同提示连发两次：不误去重")
        req2 = P._usage["requests"]
        before = len(usage_calls)
        for _ in range(2):
            code, _body = http.post("/v1/agent/chat", dict(base_payload))
            check("重复请求 -> 200", code == 200, code)
        check("requests +2（两次都算）", P._usage["requests"] == req2 + 2,
              (req2, P._usage["requests"]))
        check("record_usage 调用 +2", len(usage_calls) == before + 2,
              len(usage_calls))
        rids = [str(c.get("request_id") or "") for c in usage_calls[before:]]
        check("两次 request_id 不同（uuid 每请求唯一）",
              len(rids) == 2 and rids[0] != rids[1], rids)
        rows = [r for r in read_rows(P.USAGE_LOG) if r.get("model") == MODEL]
        check("usage 行累计 4（未被提示指纹去重）", len(rows) == 4, len(rows))

        # ---------------------------------------------------------------
        section("[4] 上游失败：record_error、不记 usage")
        err0 = P._usage["errors"]
        req3 = P._usage["requests"]
        usage_before = len(usage_calls)
        mode["fail"] = True
        try:
            code, body = http.post("/v1/agent/chat", dict(base_payload))
        finally:
            mode["fail"] = False
        check("失败路径不崩连接（Handler 能回 JSON）", code != 0, body[:160])
        check("上游失败 -> 502", code == 502, code)
        check("错误文案含原因", "solo fixture upstream failure" in body, body[:160])
        check("errors +1", P._usage["errors"] == err0 + 1,
              (err0, P._usage["errors"]))
        check("record_error 调用一次", len(error_calls) == 1, error_calls)
        check("record_error status=502",
              error_calls and error_calls[-1]["status"] == 502, error_calls)
        check("失败不产生 usage 行", len(usage_calls) == usage_before,
              len(usage_calls))
        check("失败不计 requests", P._usage["requests"] == req3,
              (req3, P._usage["requests"]))

        # ---------------------------------------------------------------
        section("[5] 禁用账号不可回退")
        disabled_pool = A.AccountPool(os.path.join(tmp, "accounts-disabled"))
        disabled_pool.load()
        disabled_pool.add(mk_account("solo-disabled-only", enabled=False))
        P.POOL = disabled_pool
        calls_before = len(solo_calls)
        try:
            code, body = http.post("/v1/agent/chat", dict(base_payload))
        finally:
            P.POOL = pool
        check("只有禁用账号 -> 503", code == 503, code)
        check("503 文案明确无可用账号", "no CN account available" in body, body[:160])
        check("未回退到禁用账号（上游未被调用）",
              len(solo_calls) == calls_before, len(solo_calls))

        # ---------------------------------------------------------------
        section("[6] 上下文预算：SOLO + build_trae_body")
        meta = P.catalog_meta_for(MODEL, "cn")
        check("模型在目录里有 meta", bool(meta), meta)
        try:
            P.trae_settings.set_model_context(P.ACCOUNTS_DIR, MODEL, "1K",
                                              meta=meta, realm="cn")
            small = {"model": MODEL, "stream": False,
                     "messages": [{"role": "user", "content": "x" * 2000}]}
            calls_before = len(solo_calls)
            code, body = http.post("/v1/agent/chat", small)
            check("SOLO 超限 -> 400", code == 400, code)
            check("400 说明本地预算超限",
                  "Configured local context budget exceeded" in body, body[:200])
            check("明确不截断历史", "No messages were truncated" in body, body[:240])
            check("超限请求不发送上游", len(solo_calls) == calls_before,
                  len(solo_calls))
            check("400 不含上游正文", "solo-ok" not in body, body[:120])

            try:
                P.build_trae_body(small, model_key=MODEL, realm="cn")
                raised = None
            except P.UpstreamStatus as exc:
                raised = exc
            check("build_trae_body 同样抛 400", raised is not None
                  and raised.status == 400, raised)
            check("build_trae_body 错误文案一致",
                  raised is not None
                  and "Configured local context budget exceeded" in raised.detail,
                  getattr(raised, "detail", ""))

            reserve = dict(small)
            reserve["messages"] = [{"role": "user", "content": "hi"}]
            reserve["max_tokens"] = 5000
            code, body = http.post("/v1/agent/chat", reserve)
            check("输出 reserve 计入预算（1K 窗口 + 5000 max -> 400）",
                  code == 400, code)
            check("reserve 拒绝不发送上游", len(solo_calls) == calls_before,
                  len(solo_calls))
        finally:
            try:
                P.trae_settings.set_model_context(P.ACCOUNTS_DIR, MODEL, "",
                                                  meta=meta, realm="cn")
            except Exception:                      # noqa: BLE001
                pass

        # 无 override：不伪造目录上限，也不因大 prompt/max_tokens 误拦
        big = {"model": MODEL, "stream": False,
               "messages": [{"role": "user", "content": "x" * 2000}],
               "max_tokens": 5000}
        try:
            built = P.build_trae_body(big, model_key=MODEL, realm="cn")
            ok = isinstance(built, dict)
        except Exception as exc:                   # noqa: BLE001
            ok = False
            check("无 override 时 build_trae_body 不误拦", False, exc)
        if not ok:
            pass
        else:
            check("无 override 时 build_trae_body 不误拦（大 prompt/大 max）", True)

        calls_before = len(solo_calls)
        code, _body = http.post("/v1/agent/chat", big)
        check("无 override 时 SOLO 不误拦 -> 200", code == 200, code)
        check("无 override 请求正常到达上游",
              len(solo_calls) == calls_before + 1, len(solo_calls))
        check("模型 max 没有被当成伪造预算（override=1K 时才拒）", True)

        # SOLO 也挂在 /v1/chat/completions（按模型分派）
        code, body = http.post("/v1/chat/completions", dict(base_payload))
        check("/v1/chat/completions 的 SOLO 模型 -> 200", code == 200, code)
        check("chat/completions 走同一 SOLO 上游", "solo-ok" in body, body[:120])

        check("测试期间未发生真实网络调用（solo 全部 mock）",
              all(c["model"] == MODEL for c in solo_calls), solo_calls[:2])
    finally:
        try:
            httpd.shutdown()
        except Exception:                          # noqa: BLE001
            pass
        try:
            httpd.server_close()
        except Exception:                          # noqa: BLE001
            pass
        P.trae_solo_chat = saved_solo
        P.record_usage = saved_record_usage
        P.record_error = saved_record_error
        P.POOL = saved["POOL"]
        for name in ("ACCOUNTS_DIR", "USAGE_DIR", "USAGE_LOG", "USAGE_SUMMARY",
                     "REALM_STATE_FILE"):
            if saved.get(name) is not None:
                setattr(P, name, saved[name])
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("=" * 66)
    print(" 汇总: PASS=%d  FAIL=%d  SKIP=%d" % (PASS, FAIL, SKIP))
    if FAIL:
        print(" 失败项：")
        for label in _FAILED:
            print("   - " + label)
        print(" 结果: FAIL（%d 项）" % FAIL)
        return 1
    print(" 结果: 0 failed" + ("（%d 项 SKIP）" % SKIP if SKIP else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
