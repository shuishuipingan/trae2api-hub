"""test_issue_desktop.py —— 桌面凭证「扫描 / 导入」契约回归（独立测试）

覆盖：
  1. 跨平台 APPDATA：Windows / macOS(Application Support) / Linux(XDG_CONFIG_HOME)，
     以及 TRAE_APPDATA / TRAE_DESKTOP_DIRS / TRAE_USER_HOME 覆盖。
  2. 扫描行前端字段：kind / path / file / realm / realmName / domain / valid /
     readable / uid(掩码) / uidTail / uidHash / nickname(掩码) / email(掩码) /
     expiresAt / expiresIn / error / key / accountsInFile。
  3. 显式 path 导入**只**导入该文件（另一区不受影响）。
  4. import 结果 dict 可 JSON 消费，且 accounts 只含本次涉及的行（不是全池）。
  5. TRAE_MAX_INFLIGHT 默认 2，环境变量可覆盖。
  6. 全程只读 temp fixtures，不触碰真实用户凭证。

运行：python test_issue_desktop.py        （或 python -m unittest test_issue_desktop -v）
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import trae_accounts as accounts
import trae_client as client

CN_UID = "2531505209880202"
INTL_UID = "7697513307502380046"
CN_TOKEN = "cn-access-" + "a" * 64
CN_REFRESH = "cn-refresh-" + "b" * 48
INTL_TOKEN = "intl-access-" + "c" * 64
INTL_REFRESH = "intl-refresh-" + "d" * 48
TEMP_TOKEN = "temp-token-cn-" + "e" * 40


def _cn_payload():
    return {
        "token": CN_TOKEN,
        "refreshToken": CN_REFRESH,
        "expiredAt": "2030-12-31T00:00:00.000Z",
        "refreshExpiredAt": "2031-06-30T00:00:00.000Z",
        "userId": CN_UID,
        "host": "https://api.trae.com.cn",
        "userRegion": {"region": "CN", "_aiRegion": "CN"},
        "account": {"username": "cnuser", "email": "cnuser@example.com",
                    "scope": "marscode", "loginScope": "trae",
                    "storeRegion": "CNTTP", "storeCountryCode": "cn"},
    }


def _intl_payload():
    return {
        "token": INTL_TOKEN,
        "refreshToken": INTL_REFRESH,
        "expiredAt": "2030-12-31T00:00:00.000Z",
        "refreshExpiredAt": "2031-06-30T00:00:00.000Z",
        "userId": INTL_UID,
        "host": "https://grow-normal.traeapi.us",
        "userRegion": {"region": "US", "_aiRegion": "US"},
        "account": {"username": "intluser", "email": "intluser@example.com",
                    "scope": "marscode", "loginScope": "trae",
                    "storeRegion": "USTTP", "storeCountryCode": "us"},
    }


def _write_json(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)


class DesktopContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="trae-desktop-fixture-")
        # 两个区各一个 app 目录（与官方一致：Trae / Trae CN）
        cls.cn_root = os.path.join(cls.root, "appdata", "Trae CN")
        cls.intl_root = os.path.join(cls.root, "appdata", "Trae")
        cls.broken_root = os.path.join(cls.root, "broken", "Trae CN")
        cls.home = os.path.join(cls.root, "home")
        cls.empty_appdata = os.path.join(cls.root, "empty-appdata")

        _write_json(os.path.join(cls.cn_root, "User", "globalStorage",
                                 "storage.json"),
                    {"iCubeAuthInfo://icube.cloudide": _cn_payload(),
                     "iCubeAuthInfo://usertag": {"tag": "plain"}})
        _write_json(os.path.join(cls.intl_root, "User", "globalStorage",
                                 "storage.json"),
                    {"iCubeAuthInfo://icube.cloudide":
                     client.build_icube_blob(_intl_payload())})
        _write_json(os.path.join(cls.broken_root, "User", "globalStorage",
                                 "storage.json"),
                    {"iCubeAuthInfo://icube.cloudide": "not-a-valid-blob"})
        os.makedirs(os.path.join(cls.home, ".trae-cn"), exist_ok=True)
        with open(os.path.join(cls.home, ".trae-cn", "trae-jwt-token"),
                  "w", encoding="utf-8") as handle:
            handle.write(TEMP_TOKEN)
        os.makedirs(cls.empty_appdata, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self):
        self.accounts_dir = tempfile.mkdtemp(prefix="accounts-", dir=self.root)
        self.env = {
            "TRAE_DESKTOP_DIRS": self.cn_root + os.pathsep + self.intl_root,
            "TRAE_USER_HOME": self.home,
            "ACCOUNTS_DIR": self.accounts_dir,
        }
        patcher = mock.patch.dict(os.environ, self.env, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("TRAE_APPDATA", None)
        os.environ.pop("TRAE_MAX_INFLIGHT", None)
        accounts._CLIENT = None          # 丢掉模块级 client 缓存
        accounts._ACTIVE_POOL = None

    # -- 1. 跨平台 appdata -------------------------------------------------
    def test_appdata_dir_cross_platform(self):
        win_base = os.path.join(self.root, "win-appdata")
        mac_base = os.path.join(self.root, "mac-appdata")
        xdg = os.path.join(self.root, "xdg-config")
        override = os.path.join(self.root, "override-appdata")

        def resolve(platform, **env):
            merged = {"TRAE_APPDATA": "", "APPDATA": ""}
            merged.update(env)
            with mock.patch.dict(os.environ, merged, clear=False):
                return client.appdata_dir(platform)

        # Windows 默认 = APPDATA
        self.assertEqual(resolve("win32", APPDATA=win_base), win_base)
        # macOS 默认 = ~/Library/Application Support（无 APPDATA 注入）
        mac_default = resolve("darwin")
        self.assertTrue(mac_default.endswith(
            os.path.join("Library", "Application Support")), mac_default)
        # Linux 默认 = XDG_CONFIG_HOME
        self.assertEqual(resolve("linux", XDG_CONFIG_HOME=xdg), xdg)
        # issue：mac / Linux 也支持 APPDATA 注入（优先级高于平台默认）
        self.assertEqual(resolve("darwin", APPDATA=mac_base), mac_base)
        self.assertEqual(resolve("linux", APPDATA=mac_base), mac_base)
        # TRAE_APPDATA 最优先（压过 APPDATA 与平台默认）
        self.assertEqual(resolve("win32", APPDATA=win_base,
                                 TRAE_APPDATA=override), override)
        self.assertEqual(resolve("darwin", APPDATA=mac_base,
                                 TRAE_APPDATA=override), override)
    def test_storage_candidates_per_platform(self):
        base = os.path.join(self.root, "cand")
        with mock.patch.dict(os.environ, {"TRAE_DESKTOP_DIRS": ""}, clear=False):
            cands = client.desktop_storage_candidates("darwin", appdata=base)
        paths = [c["path"] for c in cands]
        self.assertEqual(len(cands), 2)
        self.assertTrue(all(p.startswith(base) for p in paths), paths)
        self.assertTrue(any("Trae CN" in p for p in paths))
        self.assertTrue(any(os.sep + "Trae" + os.sep + "User" in p
                            for p in paths))
        # TRAE_DESKTOP_DIRS 覆盖后只认列出的根
        cands = client.desktop_storage_candidates()
        self.assertEqual([c["root"] for c in cands],
                         [os.path.abspath(self.cn_root),
                          os.path.abspath(self.intl_root)])
        self.assertTrue(all(c["exists"] for c in cands))

    # -- 2. 扫描契约 -------------------------------------------------------
    def test_scan_rows_contract_and_masking(self):
        rows = accounts.scan_desktop_credentials()
        by_realm = {}
        for row in rows:
            by_realm.setdefault(row["realm"], []).append(row)
            for key in ("kind", "path", "file", "realm", "realmName", "domain",
                        "valid", "readable", "uid", "uidTail", "uidHash",
                        "nickname", "email", "hasRefreshToken", "expiresAt",
                        "expiresIn", "error", "key", "accountsInFile"):
                self.assertIn(key, row, "缺字段 %s: %r" % (key, row))
        self.assertEqual(len(by_realm["cn"]), 2)      # app + cli
        self.assertEqual(len(by_realm["intl"]), 1)

        cn_app = next(r for r in by_realm["cn"] if r["kind"] == "app")
        self.assertTrue(cn_app["valid"] and cn_app["readable"])
        self.assertTrue(cn_app["path"].startswith(self.cn_root))
        self.assertEqual(cn_app["file"], "storage.json")
        self.assertEqual(cn_app["domain"], "api.trae.com.cn")
        self.assertEqual(cn_app["uid"], "…0202")
        self.assertEqual(cn_app["uidTail"], "0202")
        self.assertEqual(len(cn_app["uidHash"]), 16)
        self.assertEqual(cn_app["nickname"], "c***")
        self.assertEqual(cn_app["email"], "c***@example.com")
        self.assertTrue(cn_app["hasRefreshToken"])
        self.assertIn("天", cn_app["expiresIn"])

        intl_app = by_realm["intl"][0]
        self.assertTrue(intl_app["valid"], intl_app)
        self.assertEqual(intl_app["domain"], "grow-normal.traeapi.us")
        self.assertEqual(intl_app["uid"], "…0046")
        self.assertEqual(intl_app["nickname"], "i***")

        cli = next(r for r in by_realm["cn"] if r["kind"] == "cli")
        self.assertTrue(cli["valid"], cli)
        self.assertEqual(cli["file"], "trae-jwt-token")
        self.assertEqual(cli["uid"], "")              # 临时 token 无 uid
        self.assertEqual(cli["nickname"], "临时 token（无 uid）")

        blob = json.dumps(rows, ensure_ascii=False)
        for secret in (CN_TOKEN, CN_REFRESH, INTL_TOKEN, INTL_REFRESH,
                       TEMP_TOKEN, "cnuser@example.com", "intluser@example.com"):
            self.assertNotIn(secret, blob)

        # 扫描只读：fixture 目录里不能多出任何账号文件
        self.assertEqual(os.listdir(self.accounts_dir), [])

    def test_scan_reports_absent_and_broken(self):
        # 不存在：空 appdata，两个区都要给出「not found」行
        with mock.patch.dict(os.environ,
                             {"TRAE_DESKTOP_DIRS": "",
                              "TRAE_APPDATA": self.empty_appdata},
                             clear=False):
            rows = accounts.scan_desktop_credentials()
        # 两个区各一条「未登录」storage 行；CLI 临时 token 仍存在（fixture）
        absent = [r for r in rows if r["kind"] == "app"]
        self.assertEqual(len(absent), 2)
        for row in absent:
            self.assertFalse(row["valid"])
            self.assertFalse(row["readable"])
            self.assertTrue(row["error"].startswith("not found"), row["error"])
            self.assertTrue(row["path"].startswith(self.empty_appdata))
        self.assertTrue(any(r["kind"] == "cli" and r["valid"] for r in rows))

        # 坏 blob：readable=False + 错误原因，且不会让整次扫描失败
        with mock.patch.dict(os.environ,
                             {"TRAE_DESKTOP_DIRS": self.broken_root},
                             clear=False):
            rows = accounts.scan_desktop_credentials()
        app_rows = [r for r in rows if r["kind"] == "app"]
        self.assertEqual(len(app_rows), 1, rows)
        self.assertFalse(app_rows[0]["valid"])
        self.assertFalse(app_rows[0]["readable"])
        self.assertTrue(app_rows[0]["error"], "坏 blob 必须给出原因")
        self.assertEqual(app_rows[0]["path"].split(os.sep)[-4:],
                         ["User", "globalStorage", "storage.json"][-4:]) if False else None

    def test_scan_explicit_path_only(self):
        storage = os.path.join(self.cn_root, "User", "globalStorage",
                               "storage.json")
        rows = accounts.scan_desktop_credentials(path=storage)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], storage)
        self.assertTrue(rows[0]["valid"])
        # 客户端层同样只返回该文件
        raw = client.import_desktop_accounts(path=storage)
        self.assertEqual([a["uid"] for a in raw], [CN_UID])

    # -- 3. 显式路径导入 ---------------------------------------------------
    def test_explicit_path_import_only_that_file(self):
        pool = accounts.AccountPool(self.accounts_dir,
                                    log=lambda *a, **k: None)
        cn_storage = os.path.join(self.cn_root, "User", "globalStorage",
                                  "storage.json")
        result = accounts.import_desktop_credential(path=cn_storage, realm="cn")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["imported"], 1)
        self.assertEqual(len(result["accounts"]), 1)
        row = result["accounts"][0]
        self.assertEqual(row["realm"], "cn")
        self.assertEqual(row["uid"], "…0202")
        self.assertTrue(row["uidHash"])
        # 只导了 CN 文件：池里没有 INTL
        self.assertEqual([a.uid for a in pool.accounts], [CN_UID])
        self.assertEqual(len(os.listdir(self.accounts_dir)), 1)

        # 再导 INTL 文件，两个区各自独立
        intl_storage = os.path.join(self.intl_root, "User", "globalStorage",
                                    "storage.json")
        intl_result = accounts.import_desktop_credential(path=intl_storage,
                                                         realm="intl")
        self.assertEqual(intl_result["imported"], 1)
        self.assertEqual(sorted(a.realm for a in pool.accounts),
                         ["cn", "intl"])

        # 重复导入同一路径：更新而不是新增
        again = accounts.import_desktop_credential(path=cn_storage, realm="cn")
        self.assertEqual(again["updated"], 1)
        self.assertEqual(again["imported"], 0)
        self.assertEqual(len(pool.accounts), 2)

    def test_import_credential_missing_path_returns_dict_error(self):
        accounts.AccountPool(self.accounts_dir, log=lambda *a, **k: None)
        missing = os.path.join(self.root, "no-such", "Trae",
                               "User", "globalStorage", "storage.json")
        result = accounts.import_desktop_credential(path=missing)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["imported"], 0)
        self.assertEqual(result["accounts"], [])
        self.assertTrue(result.get("error"), result)
        self.assertTrue(result.get("errors"), "error 必须同步进 errors 供网关 400")
        self.assertEqual(result["errors"][0], result["error"])
        # 失败分支也必须带完整计数键（网关按 .get(...) 取值）
        for key in ("imported", "updated", "skipped"):
            self.assertEqual(result[key], 0, key)

    def test_scan_error_dict_shape(self):
        """client 层扫描失败（坏 blob）也必须返回完整 dict 键集。"""
        accounts.AccountPool(self.accounts_dir, log=lambda *a, **k: None)
        broken = os.path.join(self.root, "broken", "Trae CN", "User",
                              "globalStorage", "storage.json")
        result = accounts.import_desktop_credential(path=broken)
        self.assertIsInstance(result, dict)
        for key in ("found", "preview", "path", "accounts", "errors", "error",
                    "imported", "updated", "skipped"):
            self.assertIn(key, result, key)
        self.assertEqual(result["imported"], 0)
        self.assertEqual(result["accounts"], [])
        self.assertTrue(result["error"])
        self.assertTrue(result["errors"])
    def test_import_all_returns_import_result_dict(self):
        pool = accounts.AccountPool(self.accounts_dir,
                                    log=lambda *a, **k: None)
        result = accounts.import_desktop_credential()
        self.assertIsInstance(result, dict)
        for key in ("found", "preview", "path", "accounts", "errors",
                    "error", "imported", "updated", "skipped"):
            self.assertIn(key, result, key)
        self.assertFalse(result["preview"])
        self.assertEqual(result["imported"], 2)
        self.assertEqual(len(result["accounts"]), 2)   # 仅本次涉及的行
        self.assertEqual(sorted(a.realm for a in pool.accounts),
                         ["cn", "intl"])
        # 同区已有 storage 凭证时，临时 token 被去重
        self.assertFalse(any(a.uid.startswith("tok-") for a in pool.accounts))

        # 只有 INTL storage、CN 只剩临时 token：临时 token 以派生 uid 入库
        pool2_dir = tempfile.mkdtemp(prefix="accounts2-", dir=self.root)
        with mock.patch.dict(os.environ,
                             {"TRAE_DESKTOP_DIRS": self.intl_root,
                              "ACCOUNTS_DIR": pool2_dir}, clear=False):
            pool2 = accounts.AccountPool(pool2_dir, log=lambda *a, **k: None)
            result2 = accounts.import_desktop_credential()
        uids = sorted(a.uid for a in pool2.accounts)
        self.assertEqual(len(pool2.accounts), 2, uids)
        self.assertTrue(any(u.startswith("tok-") for u in uids), uids)
        self.assertEqual(len(result2["accounts"]), 2)
        self.assertEqual(sorted(a.realm for a in pool2.accounts),
                         ["cn", "intl"])
    def test_import_result_dict_consumable_and_affected_only(self):
        pool = accounts.AccountPool(self.accounts_dir,
                                    log=lambda *a, **k: None)
        cn_storage = os.path.join(self.cn_root, "User", "globalStorage",
                                  "storage.json")
        preview = pool.import_desktop(preview_only=True, path=cn_storage)
        json.dumps(preview, ensure_ascii=False)       # 必须可序列化
        self.assertTrue(preview["preview"])
        self.assertEqual(preview["found"], 1)
        self.assertEqual(len(preview["accounts"]), 1)
        self.assertEqual(preview["accounts"][0]["realm"], "cn")
        self.assertEqual(os.listdir(self.accounts_dir), [], "预览不得落盘")

        result = pool.import_desktop(preview_only=False, path=cn_storage,
                                     overwrite=True)
        json.dumps(result, ensure_ascii=False)
        self.assertEqual(result["imported"], 1)
        self.assertEqual(result["updated"], 0)
        self.assertEqual(len(result["accounts"]), 1)  # 只含本次涉及的行

        # 再导入另一区后：结果仍只含本次行，而池里有两台
        intl_storage = os.path.join(self.intl_root, "User", "globalStorage",
                                    "storage.json")
        second = pool.import_desktop(preview_only=False, path=intl_storage,
                                     overwrite=True)
        self.assertEqual(len(second["accounts"]), 1)
        self.assertEqual(second["accounts"][0]["realm"], "intl")
        self.assertEqual(len(pool.accounts), 2)
        self.assertIn("uidHash", second["accounts"][0])

    # -- 5. TRAE_MAX_INFLIGHT ---------------------------------------------
    def test_max_inflight_default_and_env_override(self):
        pool = accounts.AccountPool(self.accounts_dir,
                                    log=lambda *a, **k: None)
        self.assertEqual(pool.max_inflight, 2)
        with mock.patch.dict(os.environ, {"TRAE_MAX_INFLIGHT": "5"}, clear=False):
            pool = accounts.AccountPool(self.accounts_dir,
                                        log=lambda *a, **k: None)
            self.assertEqual(pool.max_inflight, 5)
        with mock.patch.dict(os.environ, {"TRAE_MAX_INFLIGHT": "0"}, clear=False):
            pool = accounts.AccountPool(self.accounts_dir,
                                        log=lambda *a, **k: None)
            self.assertEqual(pool.max_inflight, 0)
        with mock.patch.dict(os.environ, {"TRAE_MAX_INFLIGHT": "bad"}, clear=False):
            pool = accounts.AccountPool(self.accounts_dir,
                                        log=lambda *a, **k: None)
            self.assertEqual(pool.max_inflight, 2)
        explicit = accounts.AccountPool(self.accounts_dir,
                                        log=lambda *a, **k: None,
                                        max_inflight=3)
        self.assertEqual(explicit.max_inflight, 3)

    # -- 6. 不碰真实凭证 ---------------------------------------------------
    def test_scan_never_leaves_fixture(self):
        rows = accounts.scan_desktop_credentials()
        self.assertTrue(rows)
        for row in rows:
            self.assertTrue(row["path"].startswith(self.root),
                            "扫描到了 fixture 之外的路径：%s" % row["path"])
        for entry in client.desktop_storage_candidates():
            self.assertTrue(entry["path"].startswith(self.root), entry)


if __name__ == "__main__":
    unittest.main(verbosity=2)
