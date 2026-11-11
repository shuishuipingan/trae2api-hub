"""Browser OAuth HTTP integration: ephemeral loopback servers and fake upstream only."""
import contextlib
import copy
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

import trae_accounts as A
import trae_client as C
import trae_proxy as P
import trae_settings as S
import trae_oauth as O


class OAuthHTTP(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oauth-http-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = self.tmp.name
        self.pool = A.AccountPool(self.directory, log=lambda *a, **k: None)
        self.calls = []
        self.upstream_failure = False
        def transport(url, payload, headers):
            self.calls.append((url, copy.deepcopy(payload), dict(headers)))
            if self.upstream_failure:
                raise RuntimeError("DO-NOT-LEAK-ACCESS-REFRESH-SECRET")
            if url.endswith("/ExchangeToken"):
                return {"Result": {"Token": "TEST-OAUTH-ACCESS-SECRET", "RefreshToken": "TEST-OAUTH-REFRESH-SECRET",
                                   "TokenExpireAt": int((time.time()+3600)*1000), "UserID": "oauth-fixture-1234"}}
            if url.endswith("/GetUserInfo"):
                return {"Result": {"UserID": "oauth-fixture-1234", "ScreenName": "fixture"}}
            raise AssertionError("unexpected upstream route")
        self.pool._oauth_manager = O.OAuthManager(self.pool._complete_oauth_account, transport=transport)
        self.addCleanup(self.pool.close_logins)
        self.panel = S.PanelSessions(self.directory)
        self.token = self.panel.create()
        self.other = self.panel.create()
        self.patch = mock.patch.multiple(P, POOL=self.pool, PANEL=self.panel, ACCOUNTS_DIR=self.directory)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        class Quiet(P.Handler):
            def log_message(self, *a):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.server.server_port
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, path, body=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Panel-Token"] = token
        request = urllib.request.Request(self.base+path,
                   data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read()), response.headers

    def start(self, realm="cn"):
        status, doc, headers = self.request("/accounts/login/start", {"realm": realm}, self.token)
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["status"], "pending")
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(self.calls, [])
        self.assertGreaterEqual(len(doc["state"]), 32)
        return doc

    def callback(self, start, **extra):
        query = {"loginTraceID": start["state"], "authCodeInfo": json.dumps({"AuthCode": "FIXTURE-CODE"}),
                 "host": "https://api.trae.cn", "userInfo": json.dumps({"UserID": "UNTRUSTED-UID"})}
        query.update(extra)
        return start["redirect_uri"]+"?"+urllib.parse.urlencode(query)

    def test_start_requires_panel_no_disk_no_network(self):
        status, _, _ = self.request("/accounts/login/start", {"realm": "cn"})
        self.assertEqual(status, 401)
        self.assertEqual(self.calls, [])
        status, _, _ = self.request("/accounts/login/start", {"realm": "invalid"}, self.token)
        self.assertEqual(status, 400)
        start = self.start()
        self.assertNotIn("code_verifier", json.dumps(start))
        status, _, _ = self.request("/accounts/login/poll?state="+start["state"])
        self.assertEqual(status, 401)
        _, view, _ = self.request("/accounts/login/poll?state="+start["state"], token=self.other)
        self.assertEqual(view["status"], "not_found")
        status, _, _ = self.request("/accounts/login/poll?state=x&state=y", token=self.token)
        self.assertEqual(status, 400)

    def test_native_callback_exchanges_once_and_persists(self):
        start = self.start()
        with urllib.request.urlopen(self.callback(start), timeout=8) as response:
            self.assertIn(response.status, (200, 202))
            self.assertEqual(response.headers.get("Cache-Control"), "no-store")
            self.assertNotIn(b"TEST-OAUTH-ACCESS-SECRET", response.read())
        _, view, _ = self.request("/accounts/login/poll?state="+start["state"], token=self.token)
        self.assertEqual(view["status"], "success", view)
        self.assertEqual(len(self.pool.accounts), 1)
        self.assertEqual(self.pool.accounts[0].uid, "oauth-fixture-1234")
        saved = self.pool.accounts[0]
        payload = saved.to_desktop_dict()
        self.assertTrue(payload.get("privateKeyPEM"))
        auth = C.auth_headers(payload, "cn")
        self.assertEqual(auth["X-Device-Id"], saved.extra["device_id"])
        self.assertEqual(auth["X-Machine-Id"], saved.extra["machine_id"])
        serialized = json.dumps(view)
        for secret in ("TEST-OAUTH-ACCESS-SECRET", "TEST-OAUTH-REFRESH-SECRET", "PRIVATE KEY", "CodeVerifier"):
            self.assertNotIn(secret, serialized)
        calls = len(self.calls)
        with contextlib.suppress(urllib.error.URLError, ConnectionError):
            urllib.request.urlopen(self.callback(start), timeout=4).close()
        self.assertEqual(len(self.calls), calls)
        reloaded = A.AccountPool(self.directory, log=lambda *a, **k: None)
        reloaded.load()
        self.assertEqual(reloaded.accounts[0].extra["device_id"], saved.extra["device_id"])

    def test_manual_callback_is_owner_bound(self):
        start = self.start()
        url = self.callback(start)
        status, _, _ = self.request("/accounts/login/callback", {"callback_url": url, "state":start["state"]}, self.other)
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])
        status, view, _ = self.request("/accounts/login/callback", {"callback_url": url, "state":start["state"]}, self.token)
        self.assertEqual(status, 200, view)
        self.assertEqual(view["status"], "success")
        status, _, _ = self.request("/accounts/login/callback", {"callback_url": url, "state":start["state"]}, self.token)
        self.assertEqual(status, 400)

    def test_intl_identity_lookup_uses_verified_callback_account_host(self):
        start = self.start("intl")
        url = self.callback(start, host="https://growsg-normal.trae.ai", userRegion=json.dumps({"region":"SG","AIRegion":"SG"}))
        original = self.pool._oauth_manager._transport
        def transport(*args):
            data = original(*args)
            if args[0].endswith("/ExchangeToken"):
                data["Result"].pop("UserID")
            return data
        self.pool._oauth_manager._transport = transport
        status, doc, _ = self.request("/accounts/login/callback", {"callback_url":url,"state":start["state"]}, self.token)
        self.assertEqual(status,200,doc)
        self.assertEqual(len(self.calls),2)
        self.assertEqual(self.calls[1][0],"https://growsg-normal.trae.ai/cloudide/api/v3/trae/GetUserInfo")
        self.assertEqual(self.calls[1][1]["ReqSource"],"IDE")
        self.assertEqual(self.pool.accounts[0].user_region["_aiRegion"],"SG")
        proof = C.build_device_proof(self.pool.accounts[0].to_desktop_dict(), refresh_token="TEST-REFRESH")
        self.assertEqual(proof["DeviceInfo"]["DeviceID"],self.pool.accounts[0].extra["device_id"])

    def test_provider_error_envelope_cannot_persist_success_shaped_payload(self):
        start = self.start()
        original = self.pool._oauth_manager._transport
        def transport(*args):
            data = original(*args)
            data["ResponseMetadata"] = {"Error":{"Code":"Denied","Message":"DO-NOT-LEAK"}}
            return data
        self.pool._oauth_manager._transport = transport
        status,doc,_=self.request("/accounts/login/callback", {"callback_url":self.callback(start),"state":start["state"]}, self.token)
        self.assertEqual(status,400)
        self.assertNotIn("DO-NOT-LEAK",json.dumps(doc))
        self.assertFalse(self.pool.accounts)

    def test_listener_is_bound_to_its_own_session(self):
        first = self.start()
        second = self.start()
        query = urllib.parse.urlsplit(self.callback(second)).query
        wrong = first["redirect_uri"] + "?" + query
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(wrong, timeout=4)
        self.assertEqual(caught.exception.code, 400)
        self.assertFalse(self.calls)
        self.assertFalse(self.pool.accounts)

    def test_cancel_releases_listener_and_verifier(self):
        start = self.start()
        manager = self.pool._oauth_manager
        session = manager._sessions[start["state"]]
        self.assertTrue(manager.cancel(start["state"], owner=self.token))
        session.thread.join(timeout=3)
        self.assertFalse(session.thread.is_alive())
        self.assertEqual(session.verifier, "")
        self.assertEqual(session.private_key_pem, "")

    def test_unobserved_expiry_releases_listener(self):
        start = self.start()
        manager = self.pool._oauth_manager
        session = manager._sessions[start["state"]]
        with manager._lock:
            session.expires_at = time.time() - 1
        session.thread.join(timeout=3)
        self.assertFalse(session.thread.is_alive())
        self.assertEqual(manager.poll(start["state"], owner=self.token)["status"], "expired")

    def test_exchange_crossing_expiry_does_not_persist(self):
        start = self.start()
        manager = self.pool._oauth_manager
        original = manager._transport
        def expire_during_request(*args):
            result = original(*args)
            manager._sessions[start["state"]].expires_at = time.time() - 1
            return result
        manager._transport = expire_during_request
        status, doc, _ = self.request("/accounts/login/callback", {"callback_url":self.callback(start),"state":start["state"]}, self.token)
        self.assertEqual(status, 400)
        self.assertEqual(doc["status"], "expired")
        self.assertFalse(self.pool.accounts)

    def test_cancel_prevents_exchange(self):
        start = self.start()
        _, doc, _ = self.request("/accounts/login/cancel", {"state":start["state"]}, self.other)
        self.assertFalse(doc["cancelled"])
        _, doc, _ = self.request("/accounts/login/cancel", {"state":start["state"]}, self.token)
        self.assertTrue(doc["cancelled"])
        status, _, _ = self.request("/accounts/login/callback", {"callback_url":self.callback(start),"state":start["state"]}, self.token)
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.pool.accounts)

    def test_untrusted_callback_host_no_exchange(self):
        start = self.start()
        status, _, _ = self.request("/accounts/login/callback", {"callback_url":self.callback(start, host="https://example.invalid"), "state":start["state"]}, self.token)
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.pool.accounts)

    def test_duplicate_trace_no_exchange(self):
        start = self.start()
        url = self.callback(start)+"&loginTraceID="+start["state"]
        status, _, _ = self.request("/accounts/login/callback", {"callback_url":url,"state":start["state"]}, self.token)
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])

    def test_exchange_error_does_not_leak(self):
        start = self.start()
        self.upstream_failure = True
        status, doc, _ = self.request("/accounts/login/callback", {"callback_url":self.callback(start),"state":start["state"]}, self.token)
        self.assertEqual(status, 400)
        self.assertNotIn("DO-NOT-LEAK", json.dumps(doc))
        self.assertFalse(self.pool.accounts)

    def test_persistence_failure_no_memory_mutation(self):
        row = {"uid":"save-failure", "realm":"cn", "token":"TEST-ACCESS", "refresh_token":"TEST-REFRESH"}
        with mock.patch.object(A.Account, "save", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                self.pool._complete_oauth_account(row)
        self.assertFalse(self.pool.accounts)

    def test_relogin_preserves_settings_and_object_identity(self):
        account = A.Account({"uid":"oauth-fixture-1234", "realm":"cn", "token":"old", "enabled":False,
                             "weight":7, "disabled_models":["example"], "extra":{"custom":"preserved"}}, directory=self.directory)
        self.pool.add(account)
        with mock.patch.object(A.Account, "save", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                self.pool._complete_oauth_account({"uid":account.uid,"realm":"cn","token":"new"})
        self.assertEqual(account.token,"old")
        self.pool._complete_oauth_account({"uid":account.uid,"realm":"cn","token":"new","extra":{"device_id":"123"}})
        self.assertIs(self.pool.accounts[0], account)
        self.assertEqual(account.token,"new")
        self.assertFalse(account.enabled)
        self.assertEqual(account.weight,7)
        self.assertEqual(account.extra["custom"],"preserved")


if __name__ == "__main__":
    unittest.main()
