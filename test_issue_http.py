# -*- coding: utf-8 -*-
"""issue: HTTP 管理层回归测试（真实 ThreadingHTTPServer，本机随机端口）

覆盖 Lead 修复的 Handler 边界：
  [1] POST 面板鉴权：未授权 POST 必须 401 且**不落盘**
  [2] /accounts/login/start：设备登录不支持时返回 501 JSON（ok=false / type）
  [3] /accounts/import：JSON 导入 dry-run 不写盘；实际导入写 1 个账号并回报 result
  [4] /accounts/import/desktop：{"path":...} / {"all":true} 接受 dict 报告；
      path= 时只导入该路径；非 dict 返回 502 而不是崩连接
  [5] /accounts/import/pat：add_from_refresh 返回 dict 时正确包成 {"imported":[dict]}
  [6] GET /v1/models：每条模型带 aliases（且含 id / upstream_key 形态）

隔离与安全
  · 账号 / 用量全部指向临时目录（tempfile.mkdtemp），不碰仓库 accounts/usage
  · 不读真实凭证：desktop 扫描 / 导入全部 monkeypatch 成 fixture
  · 全程 mock network：open_upstream 被替换成“一调用就失败”的哨兵，
    fetch_models / add_from_refresh 用本地 fixture
  · 不修改 trae_proxy.py；测试结束 shutdown server + 还原模块全局

用法:
    python test_issue_http.py
退出码：0 = 全通过（允许 SKIP）；1 = 有 FAIL。
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

    def request(self, method, path, payload=None, token=None, timeout=15,
                retry_abort=None):
        """发一个请求；连接被本机 RST（WinError 10053）时按需重试。

        Windows 上 loopback 偶发 "software caused connection abort"：若 Handler
        在读取请求体之前就返回 401 并关连接，客户端可能收不到响应。GET 与
        未授权探测都是幂等的，重试一次；有副作用的 POST 默认不重试，直接
        返回 code=0 让断言报 FAIL，而不是整个套件 traceback。
        """
        if retry_abort is None:
            retry_abort = method.upper() == "GET"
        attempts = 2 if retry_abort else 1
        last_exc = None
        for attempt in range(attempts):
            url = self.base + path
            data = None
            headers = {"Accept": "application/json"}
            if payload is not None:
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                headers["Content-Type"] = "application/json"
            if token:
                headers["X-Panel-Token"] = token
            req = urllib.request.Request(url, data=data, method=method,
                                         headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", "replace")
                    ctype = resp.headers.get("Content-Type", "")
                    code = resp.status
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")
                ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
                code = exc.code
            except (ConnectionAbortedError, ConnectionResetError,
                    http.client.RemoteDisconnected) as exc:
                last_exc = exc
                if attempt + 1 < attempts:
                    time.sleep(0.1)
                    continue
                return 0, "connection aborted before response: %r" % (exc,), ""
            try:
                doc = json.loads(body) if body else None
            except Exception:                      # noqa: BLE001
                doc = body
            return code, doc, ctype
        return 0, "connection aborted before response: %r" % (last_exc,), ""


def listing(directory):
    try:
        return sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except OSError:
        return []


def main():
    global PASS, FAIL, SKIP

    print("=" * 66)
    print(" issue HTTP 管理层回归（真实 HTTPServer / 临时目录 / mock 网络）")
    print("=" * 66)

    try:
        import trae_proxy as P
        import trae_accounts as A
    except Exception as exc:                       # noqa: BLE001
        check("导入 trae_proxy / trae_accounts", False, exc)
        return 1

    tmp = tempfile.mkdtemp(prefix="issue-http-")
    acc_dir = os.path.join(tmp, "accounts")
    use_dir = os.path.join(tmp, "usage")
    os.makedirs(acc_dir, exist_ok=True)
    os.makedirs(use_dir, exist_ok=True)

    # ---- 模块全局钉到临时目录（绝不写仓库）----
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

    pool = A.AccountPool(acc_dir)
    pool.load()
    saved["POOL"] = P.POOL
    P.POOL = pool

    # ---- mock network：任何上游调用都应立即失败（测试内不该发生）----
    sentinel = {"calls": 0}
    saved_open = getattr(P, "open_upstream", None)

    def _no_network(*a, **kw):
        sentinel["calls"] += 1
        raise AssertionError("unexpected upstream call in http tests")

    if saved_open is not None:
        P.open_upstream = _no_network

    # ---- mock desktop 扫描 / 导入（绝不读真实凭证）----
    saved_scan = getattr(A, "scan_desktop_credentials", None)
    saved_import = getattr(A, "import_desktop_credential", None)

    SCAN_FIXTURE = [{
        "kind": "app", "path": "C:/fixture/auth.v1.dat", "file": "auth.v1.dat",
        "realm": "cn", "realmName": "国内版", "domain": "api.trae.com.cn",
        "valid": True, "readable": True, "uid": "…0001", "uidTail": "0001",
        "uidHash": "f" * 32, "nickname": "fixture", "email": "f***@example.com",
        "hasRefreshToken": True, "expiresAt": int(time.time()) + 3600,
        "expiresIn": "1h", "error": "", "key": "iCubeAuthInfo://icube.cloudide",
        "accountsInFile": 1,
    }]
    A.scan_desktop_credentials = lambda *a, **kw: list(SCAN_FIXTURE)

    desktop_calls = []

    def fake_import_desktop(path=None, realm=None, client=None):
        desktop_calls.append({"path": path, "realm": realm})
        return {"imported": 1, "updated": 0, "errors": [],
                "accounts": [{"uid": "desk-0001", "uidHash": "a" * 32,
                              "realm": realm or "cn"}]}

    A.import_desktop_credential = fake_import_desktop

    class QuietHandler(P.Handler):
        def log_message(self, *args, **kwargs):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    http = Http("http://127.0.0.1:%d" % port)
    print("  server: http://127.0.0.1:%d  accounts=%s" % (port, acc_dir))

    try:
        token = P.PANEL.create()
        check("面板会话 token 可创建", bool(token))

        # ---------------------------------------------------------------
        section("[1] 未授权 POST：401 且不落盘")
        row = {"uid": "http-uid-1", "realm": "cn",
               "token": "TEST-ACCESS-TOKEN-NOT-REAL",
               "refreshToken": "TEST-REFRESH-NOT-REAL",
               "expiredAt": int(time.time()) + 3600}
        before = listing(acc_dir)
        code, doc, ctype = http.request("POST", "/accounts/import",
                                        {"accounts": [row]},
                                        retry_abort=True)
        check("无 X-Panel-Token -> 401", code == 401, code)
        check("401 响应是 JSON", "application/json" in ctype, ctype)
        check("401 响应带 error 字段", isinstance(doc, dict) and "error" in doc, doc)
        check("未授权导入不落盘", listing(acc_dir) == before, listing(acc_dir))

        code2, _doc2, _ = http.request("POST", "/accounts/import/pat",
                                       {"refresh_token": "x", "realm": "cn"},
                                       retry_abort=True)
        check("未授权 /accounts/import/pat -> 401", code2 == 401, code2)
        check("未授权 PAT 导入不落盘", listing(acc_dir) == before, listing(acc_dir))

        # ---------------------------------------------------------------
        section("[2] /accounts/login/start：浏览器 OAuth pending JSON")
        code, doc, ctype = http.request("POST", "/accounts/login/start",
                                        {"realm": "cn"}, token=token)
        check("login/start -> 200", code == 200, code)
        check("login/start 返回 JSON", "application/json" in ctype, ctype)
        check("body 包含随机 state", isinstance(doc, dict) and len(doc.get("state") or "") >= 32, doc)
        check("body.status = pending",
              isinstance(doc, dict) and doc.get("status") == "pending", doc)
        check("body 包含官方授权地址",
              isinstance(doc, dict) and (doc.get("authorization_url") or "").startswith("https://www.trae.cn/authorization?"), doc)
        if isinstance(doc, dict) and doc.get("state"):
            pool.cancel_login(doc["state"], owner=token)

        # ---------------------------------------------------------------
        section("[3] /accounts/import：dry-run 与真实导入")
        code, doc, _ = http.request("POST", "/accounts/import",
                                    {"accounts": [row], "dryRun": True},
                                    token=token)
        check("dry-run -> 200", code == 200, code)
        check("dry-run 标记 dryRun=true",
              isinstance(doc, dict) and doc.get("dryRun") is True, doc)
        check("dry-run count=1", isinstance(doc, dict) and doc.get("count") == 1, doc)
        result = (doc or {}).get("result") or {}
        check("dry-run 预演到 1 条 add",
              result.get("total") == 1 and len(result.get("accounts") or []) == 1,
              result)
        check("dry-run 不落盘", listing(acc_dir) == before, listing(acc_dir))

        code, doc, _ = http.request("POST", "/accounts/import",
                                    {"accounts": [row]}, token=token)
        check("真实导入 -> 200", code == 200, code)
        result = (doc or {}).get("result") or {}
        check("导入报告 imported=1", result.get("imported") == 1, result)
        after = listing(acc_dir)
        check("真实导入落盘 1 个账号文件", len(after) == len(before) + 1, after)
        check("落盘文件名含 uid", any("http-uid-1" in n for n in after), after)

        # ---------------------------------------------------------------
        section("[4] /accounts/import/desktop：path / all 的 dict 报告")
        code, doc, _ = http.request("POST", "/accounts/import/desktop", {},
                                    token=token)
        check("空 body 扫描 -> 200", code == 200, code)
        check("扫描返回 detected 列表",
              isinstance(doc, dict) and isinstance(doc.get("detected"), list)
              and len(doc["detected"]) == 1, doc)

        desktop_calls[:] = []
        code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                    {"path": "C:/fixture/auth.v1.dat",
                                     "realm": "cn"}, token=token)
        check("path 导入 -> 200", code == 200, code)
        check("path 导入 body.ok=true",
              isinstance(doc, dict) and doc.get("ok") is True, doc)
        check("path 导入 result 是 dict",
              isinstance(doc, dict) and isinstance(doc.get("result"), dict), doc)
        check("path 导入把 path 透传给账号层",
              bool(desktop_calls) and desktop_calls[-1]["path"] == "C:/fixture/auth.v1.dat",
              desktop_calls)
        check("path 导入 imported 列表来自账号层 dict",
              isinstance(doc, dict) and len(doc.get("imported") or []) == 1, doc)

        code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                    {"all": True}, token=token)
        check("all 导入 -> 200", code == 200, code)
        check("all 导入 path=None（由账号层枚举全部）",
              bool(desktop_calls) and desktop_calls[-1]["path"] is None,
              desktop_calls)

        def fake_bad_desktop(path=None, realm=None, client=None):
            return object()          # 非 dict：Handler 必须 502，不能断连接

        A.import_desktop_credential = fake_bad_desktop
        code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                    {"path": "C:/fixture/bad.dat"}, token=token)
        check("非 dict 返回值 -> 502", code == 502, code)
        check("502 响应仍是 JSON",
              isinstance(doc, dict) and "error" in doc, doc)
        A.import_desktop_credential = fake_import_desktop

        # ---------------------------------------------------------------
        section("[5] /accounts/import/pat：add_from_refresh 返回 dict")
        calls = {"n": 0}

        def fake_add_from_refresh(refresh_token, realm=None, **kw):
            calls["n"] += 1
            return {"uid": "pat-uid-1", "uidHash": "b" * 32, "realm": realm,
                    "uidSynthetic": False, "created": True}

        original_add = pool.add_from_refresh
        pool.add_from_refresh = fake_add_from_refresh
        try:
            code, doc, _ = http.request(
                "POST", "/accounts/import/pat",
                {"refresh_token": "TEST-REFRESH-NOT-REAL", "realm": "cn"},
                token=token)
        finally:
            pool.add_from_refresh = original_add
        check("PAT 导入 -> 200", code == 200, code)
        check("PAT 导入调用 add_from_refresh 一次", calls["n"] == 1, calls)
        check("PAT 返回 imported 列表",
              isinstance(doc, dict) and isinstance(doc.get("imported"), list)
              and len(doc["imported"]) == 1, doc)
        first = (doc or {}).get("imported", [{}])[0] if isinstance(doc, dict) else {}
        check("PAT imported[0] 是 dict 且保留 uid",
              isinstance(first, dict) and first.get("uid") == "pat-uid-1", first)

        # ---------------------------------------------------------------
        section("[6] GET /v1/models：aliases")
        fixture_models = [("deepseek-v4.1-flash",
                           {"display_name": "DeepSeek-V4.1-Flash",
                            "is_default": True})]
        original_fetch = P.fetch_models
        P.fetch_models = lambda realm=None: list(fixture_models)
        try:
            code, doc, _ = http.request("GET", "/v1/models")
        finally:
            P.fetch_models = original_fetch
        check("GET /v1/models -> 200", code == 200, code)
        data = (doc or {}).get("data") or []
        check("返回 1 条模型", len(data) == 1, data)
        entry = data[0] if data else {}
        aliases = entry.get("aliases") or []
        check("模型带 aliases 列表", isinstance(aliases, list) and bool(aliases),
              aliases)
        check("aliases 含 upstream_key", "deepseek-v4.1-flash" in aliases, aliases)
        check("aliases 含显示名", "DeepSeek-V4.1-Flash" in aliases, aliases)
        check("entry.id = 显示名",
              entry.get("id") == "DeepSeek-V4.1-Flash", entry.get("id"))
        check("entry.upstream_key 保留",
              entry.get("upstream_key") == "deepseek-v4.1-flash",
              entry.get("upstream_key"))

        # ---------------------------------------------------------------
        section("[7] 真实 helper + Handler 整合（统一 dict 契约）")
        # 恢复真实 import_desktop_credential；用 fake pool 挡住真实凭证/网络。
        A.import_desktop_credential = saved_import

        class _FakeAccount(object):
            uid = "desk-uid-1"

            def public(self):
                return {"uid": "…0001", "uidHash": "a" * 32, "realm": "cn",
                        "nickname": "fixture"}

        class _FakePool(object):
            def __init__(self, payload):
                self.payload = payload
                self.calls = []

            def import_desktop(self, **kw):
                self.calls.append(kw)
                return dict(self.payload)

            def get(self, key):
                return _FakeAccount() if key else None

        saved_active = getattr(A, "_ACTIVE_POOL", None)
        ok_payload = {"imported": 1, "updated": 0, "errors": [],
                      "accounts": [{"uid": "…0001", "uidHash": "a" * 32,
                                    "realm": "cn"}]}
        fake_pool = _FakePool(ok_payload)
        A._ACTIVE_POOL = fake_pool
        try:
            direct = saved_import(path="C:/fixture/auth.v1.dat", realm="cn") \
                if saved_import else None
            check("真实 helper(path=) 返回 dict（统一契约）",
                  isinstance(direct, dict), type(direct).__name__)
            check("真实 helper(path=) dict 带 accounts 列表",
                  isinstance(direct, dict)
                  and isinstance(direct.get("accounts"), list), direct)

            direct_all = saved_import(path=None, realm="cn") \
                if saved_import else None
            check("真实 helper(all) 返回 dict（统一契约）",
                  isinstance(direct_all, dict), type(direct_all).__name__)
            check("真实 helper(all) dict 带 accounts 列表",
                  isinstance(direct_all, dict)
                  and isinstance(direct_all.get("accounts"), list), direct_all)
        except Exception as exc:                   # noqa: BLE001
            check("真实 helper 可调用", False, exc)

        # Handler 调真实 helper（不再 monkeypatch）：契约不一致时必须暴露
        code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                    {"path": "C:/fixture/auth.v1.dat",
                                     "realm": "cn"}, token=token)
        check("Handler + 真实 helper -> 200（不再 502）", code == 200, code)
        check("Handler result 是 dict",
              isinstance(doc, dict) and isinstance(doc.get("result"), dict), doc)

        # 错误路径：helper 抛 AccountError -> Handler 400（400 而非断连接）
        A._ACTIVE_POOL = _FakePool({"error": "fixture boom",
                                    "errors": ["fixture boom"],
                                    "accounts": [], "imported": 0,
                                    "updated": 0})
        try:
            code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                        {"path": "C:/fixture/bad.dat"}, token=token)
            check("真实 helper 抛错 -> Handler 400", code == 400, code)
            check("400 文案带原因",
                  "fixture boom" in json.dumps(doc, ensure_ascii=False), doc)
        finally:
            A._ACTIVE_POOL = saved_active
            A.import_desktop_credential = fake_import_desktop

        # ---------------------------------------------------------------
        section("[8] 上下文设置：POST/GET、持久化、超窗 400、清除回默认")
        import trae_catalog as C
        import trae_settings as TS

        ctx_path = "/settings/model-context"
        settings_file = os.path.join(acc_dir, "settings.json")

        def _settings_bytes():
            try:
                with open(settings_file, "rb") as fh:
                    return fh.read()
            except OSError:
                return b""

        mid = meta = None
        upper = 0
        for cand in C.models_for_realm("cn"):
            if not P.is_chat_model(cand.get("key")):
                continue
            bound = TS.context_upper_bound(cand)
            if bound:
                mid, meta, upper = cand["key"], cand, bound
                break
        check("找到带官方窗口上限的 CN chat 模型", bool(mid), None)

        if mid:
            label = TS.format_context_label(upper)
            snap = _settings_bytes()
            code, _doc, _ = http.request("GET", ctx_path)
            check("无面板 GET /settings/model-context -> 401", code == 401, code)
            code, _doc, _ = http.request("POST", ctx_path,
                                         {"model": mid, "realm": "cn",
                                          "label": label},
                                         retry_abort=True)
            check("无面板 POST /settings/model-context -> 401", code == 401, code)
            check("未授权 POST 不写 settings.json", _settings_bytes() == snap)

            code, doc, _ = http.request("GET", ctx_path, token=token)
            check("有面板 GET model-context -> 200",
                  code == 200 and isinstance(doc, dict)
                  and isinstance(doc.get("model_context"), dict), doc)

            code, doc, _ = http.request("POST", ctx_path,
                                        {"model": mid, "realm": "cn",
                                         "label": label}, token=token)
            check("POST 设置上下文 -> 200", code == 200, code)
            ctx_map = (doc or {}).get("model_context") or {}
            check("POST 返回 map 含该模型",
                  any(k.lower() == mid.lower() for k in ctx_map), ctx_map)

            code, doc, _ = http.request("GET", ctx_path, token=token)
            ctx_map = (doc or {}).get("model_context") or {}
            check("GET 读到持久化值",
                  any(k.lower() == mid.lower() for k in ctx_map), ctx_map)

            try:
                with open(settings_file, encoding="utf-8") as fh:
                    disk = json.load(fh)
            except Exception:                      # noqa: BLE001
                disk = {}
            check("settings.json 落盘 model_context",
                  isinstance(disk.get("model_context"), dict)
                  and any(k.lower() == mid.lower()
                          for k in disk["model_context"]), list(disk)[:8])

            original_fetch = P.fetch_models
            P.fetch_models = lambda realm=None: [(mid, meta)]
            try:
                code, doc, _ = http.request("GET", "/v1/models")
            finally:
                P.fetch_models = original_fetch
            entry = ((doc or {}).get("data") or [{}])[0]
            check("模型条目带 context_window_override",
                  entry.get("context_window_override") == upper,
                  entry.get("context_window_override"))
            check("模型条目 context_window 生效为 override",
                  entry.get("context_window") == upper, entry.get("context_window"))

            code, doc, _ = http.request("POST", ctx_path,
                                        {"model": mid, "realm": "cn",
                                         "label": str(upper + 100000)},
                                        token=token)
            check("超窗 -> 400", code == 400, code)
            check("400 文案说明超出窗口",
                  "超出" in json.dumps(doc, ensure_ascii=False), doc)

            code, doc, _ = http.request("POST", ctx_path,
                                        {"model": mid, "realm": "cn",
                                         "label": "default"}, token=token)
            check("清除 -> 200", code == 200, code)
            check("清除后 map 不再含该模型",
                  not any(k.lower() == mid.lower()
                          for k in ((doc or {}).get("model_context") or {})),
                  (doc or {}).get("model_context"))
            code, doc, _ = http.request("GET", ctx_path, token=token)
            check("GET 确认已回默认",
                  not any(k.lower() == mid.lower()
                          for k in ((doc or {}).get("model_context") or {})))

        code, doc, _ = http.request("GET", "/settings", token=token)
        check("面板 GET /settings -> 200",
              code == 200 and isinstance(doc, dict), code)

        original_fetch = P.fetch_models
        P.fetch_models = lambda realm=None: [("http-fixture-model",
                                              {"display_name": "HTTP-Fixture"})]
        try:
            for ep in ("/models/available", "/admin/models"):
                code, doc, _ = http.request("GET", ep, token=token)
                check("面板 GET %s 非 404" % ep, code == 200, code)
                check("%s 返回 data 列表" % ep,
                      isinstance(doc, dict) and isinstance(doc.get("data"), list),
                      doc)
        finally:
            P.fetch_models = original_fetch

        # ---------------------------------------------------------------
        section("[9] Desktop 加密 fixture 穿过真实 helper + Handler")
        import trae_client as TC

        fixture_body = {
            "token": "TEST-DESK-TOKEN-NOT-REAL",
            "refreshToken": "TEST-DESK-REFRESH-NOT-REAL",
            "expiredAt": "2026-12-31T00:00:00.000Z",
            "refreshExpiredAt": "2027-12-31T00:00:00.000Z",
            "userId": "9999000111222",
            "host": "https://api.trae.com.cn",
            "userRegion": {"region": "CN", "_aiRegion": "CN"},
            "account": {"username": "fixture", "email": "fixture@example.com",
                        "storeCountryCode": "cn"},
        }
        desk_root = os.path.join(tmp, "Trae CN")
        storage_dir = os.path.join(desk_root, "User", "globalStorage")
        os.makedirs(storage_dir, exist_ok=True)
        storage_path = os.path.join(storage_dir, "storage.json")
        with open(storage_path, "w", encoding="utf-8") as fh:
            json.dump({"iCubeAuthInfo://icube.cloudide":
                       TC.build_icube_blob(fixture_body)}, fh)

        A.import_desktop_credential = saved_import      # 真实 helper
        A._ACTIVE_POOL = pool
        try:
            A._load_client(force=True)
        except Exception:                          # noqa: BLE001
            pass

        before_files = listing(acc_dir)
        result = saved_import(path=storage_path, realm=None) if saved_import else None
        check("真实 helper(path=fixture) -> dict",
              isinstance(result, dict), type(result).__name__)
        if isinstance(result, dict):
            check("fixture 导入 imported=1",
                  result.get("imported") == 1, result.get("imported"))
            check("fixture result.accounts 只有本次 1 条",
                  len(result.get("accounts") or []) == 1,
                  result.get("accounts"))
            check("fixture result.path 回填传入路径",
                  result.get("path") == storage_path, result.get("path"))
            check("fixture 导入不泄露明文 token",
                  "TEST-DESK-TOKEN" not in json.dumps(result, ensure_ascii=False))
        after_files = listing(acc_dir)
        check("fixture 导入落盘 1 个账号文件",
              len(after_files) == len(before_files) + 1,
              (before_files, after_files))

        code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                    {"path": storage_path}, token=token)
        check("Handler + 真实 helper(path=fixture) -> 200", code == 200, code)
        hresult = (doc or {}).get("result") or {}
        check("Handler result 的 imported+updated=1（重复导入不新增）",
              int(hresult.get("imported") or 0)
              + int(hresult.get("updated") or 0) == 1, hresult)
        check("Handler 响应不泄露明文 token",
              "TEST-DESK-TOKEN" not in json.dumps(doc, ensure_ascii=False))

        # 坏 blob / 路径不存在：统一 dict 的 9 键齐全 + imported=0 + error 同步 errors
        bad_storage = os.path.join(tmp, "bad-storage.json")
        with open(bad_storage, "w", encoding="utf-8") as fh:
            json.dump({"iCubeAuthInfo://icube.cloudide": "bm90LWEtYmxvYg=="}, fh)
        for label, bad_path in (("路径不存在", os.path.join(tmp, "missing.json")),
                                ("坏 blob", bad_storage)):
            bad_res = saved_import(path=bad_path, realm=None) if saved_import else {}
            keys = {"found", "preview", "path", "accounts", "errors", "error",
                    "imported", "updated", "skipped"}
            check("%s：返回 dict 且 9 键齐全" % label,
                  isinstance(bad_res, dict) and keys <= set(bad_res), bad_res)
            check("%s：imported/updated/skipped 恒为 0" % label,
                  int(bad_res.get("imported") or 0) == 0
                  and int(bad_res.get("updated") or 0) == 0
                  and int(bad_res.get("skipped") or 0) == 0, bad_res)
            check("%s：error 同步进 errors（Handler 400 分支可命中）" % label,
                  bool(bad_res.get("error"))
                  and bad_res["error"] in (bad_res.get("errors") or []), bad_res)
            code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                        {"path": bad_path}, token=token)
            check("%s：Handler -> 400（不是 200/502）" % label, code == 400, code)
            check("%s：400 响应带 result.errors" % label,
                  isinstance(doc, dict)
                  and isinstance((doc.get("result") or {}).get("errors"), list),
                  doc)

        old_env = os.environ.get("TRAE_DESKTOP_DIRS")
        os.environ["TRAE_DESKTOP_DIRS"] = desk_root
        try:
            all_result = saved_import(path=None, realm=None) if saved_import else None
            check("真实 helper(all, fixture env) -> dict",
                  isinstance(all_result, dict), type(all_result).__name__)
            if isinstance(all_result, dict):
                changed = (int(all_result.get("imported") or 0)
                           + int(all_result.get("updated") or 0))
                check("all 分支 accounts 只含本次涉及行",
                      len(all_result.get("accounts") or []) == changed,
                      all_result)
            code, doc, _ = http.request("POST", "/accounts/import/desktop",
                                        {"all": True}, token=token)
            check("Handler + 真实 helper(all fixture) -> 200", code == 200, code)
        finally:
            if old_env is None:
                os.environ.pop("TRAE_DESKTOP_DIRS", None)
            else:
                os.environ["TRAE_DESKTOP_DIRS"] = old_env
            A.import_desktop_credential = fake_import_desktop
            A._ACTIVE_POOL = saved_active

        check("测试全程没有触发上游网络调用", sentinel["calls"] == 0,
              sentinel["calls"])
    finally:
        try:
            httpd.shutdown()
        except Exception:                          # noqa: BLE001
            pass
        try:
            httpd.server_close()
        except Exception:                          # noqa: BLE001
            pass
        if saved_open is not None:
            P.open_upstream = saved_open
        if saved_scan is not None:
            A.scan_desktop_credentials = saved_scan
        if saved_import is not None:
            A.import_desktop_credential = saved_import
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
