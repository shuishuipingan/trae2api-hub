#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_issue_context.py —— 模型上下文覆盖（settings.model_context）单元测试。

issue #106：面板给每个模型选上下文档位（200K / 1M ...）-> 存进
accounts/settings.json 的 model_context -> 网关热路径读取。

被测对象：trae_settings.py 的
    model_context / get_model_context / set_model_context / clear_model_context
    validate_model_context / parse_context_tokens / format_context_label
    official_context_tiers / official_context_max / official_context_default
    model_context_tokens / model_context_view

**全部写在 tempfile 临时目录**，不碰仓库里的 accounts/settings.json。
标准库 unittest，零依赖：

    python test_issue_context.py            # 安静模式，只打结果
    python test_issue_context.py -v         # 逐条
退出码：0 全过；1 有失败。

回归（并发/存量文件）：
  · 8 线程并发读改写、真实 HTTP 并发 POST，全部放**子进程 + 硬超时**里跑：
    真死锁时测试失败并打印子进程栈，而不是把整个测试套件挂住；
  · 真实存量 settings.json（api_keys/limits/secret/auto_degrade + 旧数字型
    model_context）在多次覆盖写入后一个键都不能丢、临时文件不残留；
  · save() 是 RLock 下的**同步**写：返回即落盘，不存在"失败但后台还在写"。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import trae_settings as S


# --- 官方 meta 样本（字段取自 trae_catalog 快照的真实形状）-------------------
KIMI = {                       # 默认 200K / 最大 1M，两个档位
    "upstream_key": "kimi-k3",
    "context_window": 200000,
    "context_window_max": 1000000,
    "context_window_size": {"max": [1000000], "default": 200000},
    "context_window_tokens": {"dev": 200000, "max": 1000000},
}
SEED = {                       # 默认 256K，官方没给上限（max:null）
    "upstream_key": "Doubao-Seed-Code",
    "context_window": 256000,
    "context_window_max": None,
    "context_window_size": {"max": None, "default": 256000},
    "context_window_tokens": {"dev": 256000},
}
BARE = {"upstream_key": "seed_m8", "model_type": "chat_model"}   # 动态清单里没有窗口


class TempSettings(unittest.TestCase):
    """每个用例一个空临时目录。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="trae-ctx-")
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def stored(self):
        with open(S.settings_path(self.dir), encoding="utf-8") as fh:
            return json.load(fh)

    def write_raw(self, payload):
        path = S.settings_path(self.dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            if isinstance(payload, str):
                fh.write(payload)
            else:
                json.dump(payload, fh)

    # -- 基础读写 --------------------------------------------------------
    def test_fresh_install_has_no_override(self):
        self.assertEqual(S.model_context(self.dir), {})
        self.assertIsNone(S.get_model_context(self.dir, "kimi-k3"))
        self.assertIsNone(S.model_context_tokens(self.dir, "kimi-k3", meta=KIMI))

    def test_set_official_tier_then_read(self):
        saved = S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        self.assertEqual(saved, {"kimi-k3": "1M"})
        self.assertEqual(S.get_model_context(self.dir, "kimi-k3"), "1M")
        self.assertEqual(S.model_context_tokens(self.dir, "kimi-k3", meta=KIMI),
                         1000000)

    def test_tier_label_case_insensitive_and_normalized(self):
        S.set_model_context(self.dir, "kimi-k3", " 1m ", meta=KIMI)
        self.assertEqual(S.get_model_context(self.dir, "kimi-k3"), "1M")
        S.set_model_context(self.dir, "kimi-k3", "200k", meta=KIMI)
        self.assertEqual(S.get_model_context(self.dir, "kimi-k3"), "200K")

    def test_numeric_value_within_window(self):
        S.set_model_context(self.dir, "kimi-k3", 64000, meta=KIMI)
        self.assertEqual(S.get_model_context(self.dir, "kimi-k3"), "64K")
        self.assertEqual(S.model_context_tokens(self.dir, "kimi-k3", meta=KIMI),
                         64000)

    def test_non_round_numeric_kept_verbatim(self):
        # 981504 是 MiMo 的真实窗口；不是 1000 的整数倍，标签必须原样
        S.set_model_context(self.dir, "mimo-v2.6-pro", "981504",
                            meta={"context_window_max": 981504})
        self.assertEqual(S.get_model_context(self.dir, "mimo-v2.6-pro"), "981504")
        self.assertEqual(
            S.model_context_tokens(self.dir, "mimo-v2.6-pro"),
            981504)

    def test_non_official_but_safe_custom_value(self):
        # 300K 不是官方档位，但 <= 最大窗口 -> 允许（自定义值）
        verdict = S.validate_model_context("300K", meta=KIMI)
        self.assertTrue(verdict["ok"])
        self.assertFalse(verdict.get("exact_tier"))
        S.set_model_context(self.dir, "kimi-k3", "300K", meta=KIMI)
        self.assertEqual(S.get_model_context(self.dir, "kimi-k3"), "300K")

    # -- 校验 ------------------------------------------------------------
    def test_reject_over_max_window(self):
        with self.assertRaises(ValueError) as ctx:
            S.set_model_context(self.dir, "kimi-k3", "2M", meta=KIMI)
        self.assertIn("1M", str(ctx.exception))
        self.assertEqual(S.model_context(self.dir), {})     # 没写进去

    def test_reject_over_max_keeps_previous_value(self):
        S.set_model_context(self.dir, "kimi-k3", "400K", meta=KIMI)
        with self.assertRaises(ValueError):
            S.set_model_context(self.dir, "kimi-k3", "9M", meta=KIMI)
        self.assertEqual(S.get_model_context(self.dir, "kimi-k3"), "400K")

    def test_reject_garbage_label(self):
        with self.assertRaises(ValueError):
            S.set_model_context(self.dir, "kimi-k3", "超大", meta=KIMI)
        self.assertEqual(S.model_context(self.dir), {})

    def test_reject_zero_and_negative(self):
        for bad in (0, -1, "0", "-5"):
            with self.assertRaises(ValueError):
                S.set_model_context(self.dir, "kimi-k3", bad, meta=KIMI)

    def test_reject_bool(self):
        with self.assertRaises(ValueError):
            S.set_model_context(self.dir, "kimi-k3", True, meta=KIMI)

    def test_missing_max_falls_back_to_default_window(self):
        # 官方只给了默认 256K、没有最大窗口：<= 默认可以，超出拒绝
        self.assertTrue(S.validate_model_context("256K", meta=SEED)["ok"])
        verdict = S.validate_model_context("300K", meta=SEED)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["reason"], "exceeds_window")

    def test_unknown_window_rejects_nowhere_to_validate(self):
        verdict = S.validate_model_context("128K", meta=BARE)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["reason"], "unknown_window")
        with self.assertRaises(ValueError):
            S.set_model_context(self.dir, "seed_m8", "128K", meta=BARE)

    def test_explicit_max_tokens_override(self):
        verdict = S.validate_model_context("128K", max_tokens=200000)
        self.assertTrue(verdict["ok"])
        verdict2 = S.validate_model_context("400K", max_tokens=200000)
        self.assertFalse(verdict2["ok"])

    # -- 清除 ------------------------------------------------------------
    def test_clear_single_model(self):
        S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        S.set_model_context(self.dir, "glm-5.3", "128K", meta=KIMI)
        ctx = S.set_model_context(self.dir, "kimi-k3", "", meta=KIMI)
        self.assertEqual(ctx, {"glm-5.3": "128K"})
        self.assertIsNone(S.get_model_context(self.dir, "kimi-k3"))
        # 清掉最后一个也把键抹掉，不留下空的 model_context: {}
        S.set_model_context(self.dir, "glm-5.3", "", meta=KIMI)
        self.assertNotIn(S.MODEL_CONTEXT_KEY, self.stored())

    def test_clear_words(self):
        for word in ("default", "DEFAULT", "默认", "  ", None):
            S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
            S.set_model_context(self.dir, "kimi-k3", word, meta=KIMI)
            self.assertEqual(S.model_context(self.dir), {}, repr(word))

    def test_clear_all(self):
        S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        S.set_model_context(self.dir, "glm-5.3", "128K", meta=KIMI)
        self.assertEqual(S.clear_model_context(self.dir), {})
        self.assertEqual(S.model_context(self.dir), {})
        self.assertNotIn(S.MODEL_CONTEXT_KEY, self.stored())

    # -- 键匹配 ----------------------------------------------------------
    def test_model_lookup_ignores_case(self):
        S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        self.assertEqual(S.get_model_context(self.dir, "KIMI-K3"), "1M")
        S.set_model_context(self.dir, "KIMI-K3", "", meta=KIMI)
        self.assertEqual(S.model_context(self.dir), {})

    def test_alias_lookup_uses_injected_resolver(self):
        original = S._resolve_model_name
        aliases = {"Claude-Opus-4.7": "aws_claude_4.7_opus",
                   "aws_claude_4.7_opus": "aws_claude_4.7_opus"}
        S._resolve_model_name = lambda name, realm=None: aliases.get(
            str(name or "").strip(), str(name or "").strip())
        try:
            S.set_model_context(self.dir, "Claude-Opus-4.7", "1M", meta=KIMI)
            self.assertEqual(
                S.get_model_context(self.dir, "aws_claude_4.7_opus"), "1M")
        finally:
            S._resolve_model_name = original

    def test_alias_lookup_with_real_catalog(self):
        try:
            import trae_catalog
        except Exception:
            self.skipTest("trae_catalog 不可用")
        if not trae_catalog.models_for_realm("intl"):
            self.skipTest("目录快照为空")
        meta = {"context_window_max": 1000000}
        S.set_model_context(self.dir, "Claude-Opus-4.7", "1M", meta=meta)
        self.assertEqual(
            S.get_model_context(self.dir, "aws_claude_4.7_opus"), "1M")
        self.assertEqual(
            S.model_context_tokens(self.dir, "aws_claude_4.7_opus", meta=meta),
            1000000)

    # -- 持久化 / 安全性 --------------------------------------------------
    def test_persisted_to_settings_json(self):
        S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        raw = self.stored()
        self.assertEqual(raw[S.MODEL_CONTEXT_KEY], {"kimi-k3": "1M"})
        # 只存标签字符串，不存换算后的数字
        self.assertIsInstance(raw[S.MODEL_CONTEXT_KEY]["kimi-k3"], str)

    def test_does_not_disturb_other_settings(self):
        self.write_raw({"panel_password_hash": "abc", "api_keys": [{"key": "k"}],
                        "limits": {"reserve_credits": {"global": 3}}})
        S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        raw = self.stored()
        self.assertEqual(raw["panel_password_hash"], "abc")
        self.assertEqual(raw["api_keys"], [{"key": "k"}])
        self.assertEqual(raw["limits"]["reserve_credits"]["global"], 3)

    def test_corrupt_settings_refuses_write(self):
        self.write_raw("{ not json")
        self.assertEqual(S.model_context(self.dir), {})      # 读：fail-open
        with self.assertRaises(OSError):
            S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        with open(S.settings_path(self.dir), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "{ not json")        # 原样没动

    def test_dirty_values_are_dropped_on_read(self):
        self.write_raw({S.MODEL_CONTEXT_KEY: {
            "good": "1M",
            "junk": "超大",
            "zero": 0,
            "cleared": "default",
            "bool": True,
            "": "1M",
        }})
        self.assertEqual(S.model_context(self.dir), {"good": "1M"})

    def test_numeric_legacy_value_normalized(self):
        # 老版本/手改写成数字也要能读出来
        self.write_raw({S.MODEL_CONTEXT_KEY: {"kimi-k3": 1000000}})
        self.assertEqual(S.get_model_context(self.dir, "kimi-k3"), "1M")

    def test_tokens_clamped_when_hand_edited_over_max(self):
        self.write_raw({S.MODEL_CONTEXT_KEY: {"kimi-k3": "4M"}})
        self.assertEqual(
            S.model_context_tokens(self.dir, "kimi-k3", meta=KIMI), 1000000)
        self.assertEqual(
            S.model_context_tokens(self.dir, "kimi-k3", meta=KIMI, clamp=False),
            4000000)

    # -- 官方档位/视图 ----------------------------------------------------
    def test_official_tiers_from_catalog_meta(self):
        self.assertEqual(S.official_context_tiers(KIMI),
                         [("200K", 200000), ("1M", 1000000)])
        self.assertEqual(S.official_context_tiers(BARE), [])
        self.assertEqual(S.official_context_max(KIMI), 1000000)
        self.assertIsNone(S.official_context_max(SEED))
        self.assertEqual(S.official_context_default(SEED), 256000)

    def test_view_shape_for_panel(self):
        S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        view = S.model_context_view(self.dir, {"kimi-k3": KIMI})
        item = view["kimi-k3"]
        self.assertEqual(item["label"], "1M")
        self.assertEqual(item["tokens"], 1000000)
        self.assertEqual(item["max"], 1000000)
        self.assertTrue(item["valid"])
        self.assertEqual([t["label"] for t in item["tiers"]], ["200K", "1M"])

    def test_parse_and_format_roundtrip(self):
        for label, tokens in (("1M", 1000000), ("200K", 200000),
                              ("128k", 128000), ("981504", 981504),
                              ("1.5M", 1500000)):
            self.assertEqual(S.parse_context_tokens(label), tokens, label)
        self.assertEqual(S.parse_context_tokens(""), None)
        self.assertEqual(S.parse_context_tokens(None), None)
        self.assertEqual(S.format_context_label(1000000), "1M")
        self.assertEqual(S.format_context_label(200000), "200K")
        self.assertEqual(S.format_context_label(981504), "981504")
        with self.assertRaises(ValueError):
            S.parse_context_tokens("abc")


# --------------------------------------------------------------- 回归组
# panel POST /settings/model-context 观测到"请求挂住 -> ConnectionAborted"后
# 的针对性回归：所有可能死锁的路径都放子进程 + 硬超时，挂住 = 测试失败。

ROOT = os.path.dirname(os.path.abspath(__file__))

_CHILD_PRELUDE = """
import faulthandler, json, os, sys, tempfile, threading, time
faulthandler.dump_traceback_later(15, exit=True)   # 卡住就打印栈并退出
sys.path.insert(0, %r)
import trae_settings as S
tmp = tempfile.mkdtemp(prefix="ctx-child-")
META = {"context_window": 200000, "context_window_max": 1000000,
        "context_window_size": {"max": [1000000], "default": 200000}}
"""


class NoDeadlockRegression(unittest.TestCase):
    """子进程 + 超时：并发路径若真的卡住，必须表现为测试失败而不是挂住套件。"""

    def child(self, body, timeout=30):
        code = (_CHILD_PRELUDE % ROOT) + body
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        try:
            proc = subprocess.run([sys.executable, "-c", code],
                                  capture_output=True, timeout=timeout,
                                  env=env, encoding="utf-8",
                                  errors="replace")
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or "") + (exc.stderr or "")
            self.fail("子进程 %.0fs 未退出（疑似死锁）:\n%s" % (timeout, out))
        self.assertEqual(proc.returncode, 0,
                         "子进程失败:\nSTDOUT:\n%s\nSTDERR:\n%s"
                         % (proc.stdout, proc.stderr))
        return proc.stdout

    def test_save_is_reentrant_under_module_lock(self):
        """setter 持 _lock 调 save()：RLock 重入必须直接通过且**落盘已完成**。"""
        out = self.child("""
with S._lock:                       # 模拟 setter 的持锁段
    S.save(tmp, {"probe": 1})
data = json.load(open(os.path.join(tmp, "settings.json"), encoding="utf-8"))
assert data == {"probe": 1}, data       # 返回即落盘，没有后台补写
print("ok")
""")
        self.assertIn("ok", out)

    def test_concurrent_readers_and_writers(self):
        out = self.child("""
errors = []
def worker(idx):
    try:
        for i in range(80):
            S.set_model_context(tmp, "m%d" % (i % 5), "1M", meta=META)
            S.model_context(tmp)
            S.get_model_context(tmp, "m%d" % (i % 5))
            S.limits_data(tmp)
            S.api_keys(tmp)
    except BaseException as exc:
        errors.append(repr(exc))
ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
for t in ts: t.start()
for t in ts:
    t.join(15)
    assert not t.is_alive(), "thread still alive -> deadlock"
assert not errors, errors[:3]
raw = json.load(open(os.path.join(tmp, "settings.json"), encoding="utf-8"))
assert set(raw) <= {"model_context"}, raw
print("ok", len(S.model_context(tmp)))
""")
        self.assertIn("ok", out)

    def test_http_post_burst_no_hang(self):
        """真实 HTTP：10 并发 POST /settings/model-context，必须全部 200。"""
        out = self.child("""
import http.server, socketserver, urllib.request

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        ctx = S.set_model_context(tmp, body.get("model"), body.get("label"),
                                  meta=META)
        payload = json.dumps({"ok": True, "model_context": ctx}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
srv.daemon_threads = True
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = "http://127.0.0.1:%d/settings/model-context" % port
bad = []
def post(i):
    try:
        data = json.dumps({"model": "h%d" % (i % 3), "label": "1M"}).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.status == 200
            json.loads(r.read())
    except BaseException as exc:
        bad.append("%s:%r" % (i, exc))
t0 = time.time()
ts = [threading.Thread(target=post, args=(i,)) for i in range(10)]
for t in ts: t.start()
for t in ts: t.join(20)
elapsed = time.time() - t0
srv.shutdown()
assert not bad, bad[:3]
assert elapsed < 15, "too slow: %.1fs" % elapsed
print("ok %.2fs" % elapsed)
""")
        self.assertIn("ok", out)

class RealisticSettingsFile(unittest.TestCase):
    """存量 settings.json（真机形状）上的读写：一个键都不能丢。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="trae-ctx-real-")
        self.dir = self._tmp.name
        self.seed = {
            "panel_session_secret": "s" * 64,
            "api_keys": [
                {"id": "k1", "name": "默认", "key": "sk-" + "a" * 24,
                 "realm": "", "enabled": True, "models": [],
                 "daily_requests": 0, "daily_tokens": 0,
                 "created_at": "2026/01/01 00:00"},
                {"id": "k2", "name": "CN", "key": "sk-" + "b" * 24,
                 "realm": "cn", "enabled": True, "models": ["kimi*"],
                 "daily_requests": 10, "daily_tokens": 1000,
                 "created_at": "2026/01/02 00:00"},
            ],
            "limits": {"reserve_credits": {"global": 3, "intl": None, "cn": 5}},
            "auto_degrade": {"enabled": True, "fallback_model": "kimi-k3",
                             "fallback_realm": "cn", "on_quota": True,
                             "on_upgrade": True, "warn_below": 10},
            # 旧版本手改留下的数字型覆盖
            "model_context": {"glm-5.3": 128000},
        }
        with open(S.settings_path(self.dir), "w", encoding="utf-8") as fh:
            json.dump(self.seed, fh, ensure_ascii=False, indent=2)

    def tearDown(self):
        self._tmp.cleanup()

    def read(self):
        with open(S.settings_path(self.dir), encoding="utf-8") as fh:
            return json.load(fh)

    def test_existing_keys_survive_repeated_writes(self):
        for i in range(5):
            S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
            S.set_model_context(self.dir, "glm-5.3", "200K", meta=KIMI)
            S.clear_model_context(self.dir, "glm-5.3")
        raw = self.read()
        for key in ("panel_session_secret", "api_keys", "limits",
                    "auto_degrade"):
            self.assertIn(key, raw)
        self.assertEqual(raw["panel_session_secret"], "s" * 64)
        self.assertEqual(len(raw["api_keys"]), 2)
        self.assertEqual(raw["limits"]["reserve_credits"]["cn"], 5)
        self.assertEqual(raw["auto_degrade"]["fallback_model"], "kimi-k3")
        self.assertEqual(raw["model_context"], {"kimi-k3": "1M"})

    def test_legacy_numeric_override_normalized(self):
        self.assertEqual(S.get_model_context(self.dir, "glm-5.3"), "128K")
        S.set_model_context(self.dir, "glm-5.3", "200K", meta=KIMI)
        self.assertEqual(self.read()["model_context"]["glm-5.3"], "200K")

    def test_no_tmp_leftovers(self):
        for i in range(5):
            S.set_model_context(self.dir, "kimi-k3", "1M", meta=KIMI)
        leftovers = [n for n in os.listdir(self.dir) if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1)
