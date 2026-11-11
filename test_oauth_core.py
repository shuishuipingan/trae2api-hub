#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline regression tests for trae_oauth.

No real Trae login or upstream request is made.  The manager receives a fake
transport and the only HTTP server is a short-lived loopback callback listener.
"""
import base64
import hashlib
import json
import re
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

import trae_client
import trae_oauth
from trae_oauth import OAuthManager


class Clock:
    def __init__(self, value=1_700_000_000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


class Recorder:
    def __init__(self, public=None, error=None, delay=0.0):
        self.rows = []
        self.public = public
        self.error = error
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()

    def __call__(self, row):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                time.sleep(self.delay)
            if self.error:
                raise self.error
            self.rows.append(row)
            if self.public is not None:
                return self.public
            return {
                "uid": row.get("uid"),
                "realm": row.get("realm"),
                "host": row.get("host"),
                "source": row.get("source"),
                "account": {"username": row.get("account", {}).get("username")},
                "token": "must-not-leak",
                "refresh_token": "must-not-leak",
                "extra": {"privateKeyPEM": "must-not-leak"},
            }
        finally:
            with self.lock:
                self.active -= 1


class Transport:
    def __init__(self, exchange=None, userinfo=None, block=None,
                 error=None, userinfo_error=None):
        self.calls = []
        self.exchange = exchange
        self.userinfo = userinfo
        self.block = block
        self.error = error
        self.userinfo_error = userinfo_error
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self, url, payload, headers):
        self.calls.append({"url": url, "payload": payload, "headers": headers})
        if "ExchangeToken" in url:
            if self.block:
                self.entered.set()
                self.release.wait(5)
            if self.error:
                raise self.error
            if self.exchange is not None:
                return self.exchange
            return {"Result": {
                "Token": "access-1",
                "RefreshToken": "refresh-1",
                "UserID": "user-1",
                "ExpiredAt": int(time.time()) + 3600,
                "RefreshExpireAt": int(time.time()) + 86400,
            }}
        if self.userinfo_error:
            raise self.userinfo_error
        if self.userinfo is not None:
            return self.userinfo
        return {"Result": {"UserID": "user-1", "ScreenName": "Alice"}}


def callback_params(state, clock=None, **extra):
    now = clock.value if clock is not None else time.time()
    params = {
        "authCodeInfo": json.dumps({
            "AuthCode": "code-1",
            "ExpireAt": int(now + 300),
            "ExpireDuration": 300,
        }),
        "userInfo": json.dumps({"UserID": "user-1", "ScreenName": "Alice"}),
        "loginTraceID": state,
        "host": "api.trae.cn",
        "userRegion": "CN",
    }
    params.update(extra)
    return params


def http_get(url, headers=None):
    request = urllib.request.Request(url, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def callback_url(start):
    return start["redirect_uri"] + "?" + urllib.parse.urlencode(
        callback_params(start["state"]))


class ManagerCase(unittest.TestCase):
    def make(self, transport=None, recorder=None, clock=None):
        clock = clock or Clock()
        recorder = recorder or Recorder()
        manager = OAuthManager(recorder, clock=clock, transport=transport)
        self.addCleanup(manager.close)
        return manager, recorder, clock

    def start_manual(self, manager, **kwargs):
        return manager.start(redirect_uri="https://example.test/callback",
                             **kwargs)


class TestStart(ManagerCase):
    def test_cn_start_shape_and_authorization_parameters(self):
        manager, _recorder, clock = self.make()
        started = manager.start(realm="cn", platform="windows", owner="panel")
        self.assertEqual(started["status"], "pending")
        self.assertRegex(started["state"], r"^[0-9a-f]{32}$")
        self.assertEqual(started["interval"], 2)
        self.assertEqual(started["realm"], "cn")
        self.assertEqual(started["expires_at"], int(clock.value) + 600)
        self.assertEqual(started["verification_uri"],
                         started["authorization_url"])
        self.assertTrue(started["redirect_uri"].startswith(
            "http://127.0.0.1:"))
        self.assertTrue(started["redirect_uri"].endswith("/authorize"))

        parsed = urllib.parse.urlsplit(started["authorization_url"])
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "www.trae.cn")
        self.assertEqual(parsed.path, "/authorization")
        query = urllib.parse.parse_qs(parsed.query)
        expected = {
            "client_id": "ono9krqynydwx5",
            "login_version": "1",
            "auth_from": "trae",
            "login_channel": "native_ide",
            "plugin_version": "2.3.83560",
            "auth_type": "local",
            "redirect": "0",
            "login_trace_id": started["state"],
            "auth_callback_url": started["redirect_uri"],
            "x_device_type": "windows",
            "x_app_version": "3.3.100",
            "x_app_type": "stable",
            "code_challenge_method": "S256",
            "channel_name": "common",
        }
        for key, value in expected.items():
            self.assertEqual(query.get(key), [value], key)
        self.assertRegex(query["machine_id"][0], r"^[0-9a-f]{32}$")
        self.assertEqual(query["x_machine_id"][0], query["machine_id"][0])
        self.assertRegex(query["device_id"][0], r"^[1-9][0-9]{15}$")
        self.assertEqual(query["x_device_id"][0], query["device_id"][0])
        self.assertRegex(query["code_challenge"][0], r"^[A-Za-z0-9_-]{43}$")
        session = manager._sessions[started["state"]]
        digest = hashlib.sha256(session.verifier.encode("ascii")).digest()
        self.assertEqual(query["code_challenge"][0],
                         base64.urlsafe_b64encode(digest).rstrip(b"=").decode())

    def test_intl_start_uses_intl_hosts_and_19_digit_device(self):
        manager, _recorder, _clock = self.make()
        started = manager.start(realm="intl", platform="macos")
        parsed = urllib.parse.urlsplit(started["authorization_url"])
        self.assertEqual(parsed.netloc, "www.trae.ai")
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query["x_device_type"], ["macos"])
        self.assertEqual(query["x_app_version"], ["3.5.51"])
        self.assertRegex(query["device_id"][0], r"^[1-9][0-9]{18}$")

    def test_invalid_arguments_return_safe_errors(self):
        manager, _recorder, _clock = self.make()
        self.assertEqual(manager.start(realm="moon")["error"]["code"],
                         "invalid_realm")
        self.assertEqual(manager.start(platform="solaris")["error"]["code"],
                         "invalid_platform")
        self.assertEqual(
            manager.start(redirect_uri="http://example.com/cb")["error"]["code"],
            "invalid_redirect_uri")
        self.assertEqual(
            manager.start(redirect_uri="https://user:pass@example.com/cb")["error"]["code"],
            "invalid_redirect_uri")

    def test_explicit_redirect_does_not_start_listener(self):
        manager, _recorder, _clock = self.make()
        started = self.start_manual(manager)
        self.assertEqual(started["redirect_uri"],
                         "https://example.test/callback")
        self.assertIsNone(manager._sessions[started["state"]].server)

    def test_max_pending_sessions_and_reuse_after_cancel(self):
        manager, _recorder, _clock = self.make()
        states = []
        for _ in range(trae_oauth.MAX_PENDING):
            started = self.start_manual(manager)
            self.assertEqual(started["status"], "pending")
            states.append(started["state"])
        overflow = self.start_manual(manager)
        self.assertEqual(overflow["error"]["code"], "too_many_sessions")
        self.assertTrue(manager.cancel(states[0]))
        again = self.start_manual(manager)
        self.assertEqual(again["status"], "pending")

    def test_closed_manager_refuses_start(self):
        manager, _recorder, _clock = self.make()
        manager.close()
        self.assertEqual(manager.start()["error"]["code"], "manager_closed")


class TestPrimaryCallback(ManagerCase):
    def test_http_callback_completes_and_never_leaks_secrets(self):
        transport = Transport()
        recorder = Recorder()
        manager, recorder, clock = self.make(transport, recorder)
        started = manager.start(realm="cn", platform="windows", owner="panel")
        status, headers, body = http_get(callback_url(started))
        self.assertEqual(status, 200)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertNotIn(started["state"].encode(), body)
        self.assertNotIn(b"code-1", body)
        self.assertEqual(len(recorder.rows), 1)

        row = recorder.rows[0]
        self.assertEqual(row["uid"], "user-1")
        self.assertEqual(row["token"], "access-1")
        self.assertEqual(row["refresh_token"], "refresh-1")
        self.assertEqual(row["realm"], "cn")
        self.assertEqual(row["host"], "https://api.trae.cn")
        self.assertEqual(row["user_region"], {"region": "CN", "_aiRegion": "CN"})
        self.assertEqual(row["source"], "oauth")
        # Display name may come from the authenticated GetUserInfo response;
        # identity itself is asserted by uid below and never taken from callback.
        self.assertIn(row["account"]["username"], ("", "Alice"))
        self.assertGreater(row["expired_at"], int(time.time()))
        self.assertGreater(row["refresh_expired_at"], row["expired_at"])
        self.assertRegex(row["extra"]["device_id"], r"^[1-9][0-9]{15}$")
        self.assertRegex(row["extra"]["machine_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(row["extra"]["deviceInfo"]["PlatformCode"], "IDE_PC")
        self.assertEqual(row["extra"]["deviceInfo"]["DeviceType"], "PC")
        self.assertEqual(row["extra"]["deviceInfo"]["ClientVersion"], "3.3.100")
        self.assertEqual(row["extra"]["deviceInfo"]["DeviceID"],
                         row["extra"]["device_id"])
        self.assertEqual(row["extra"]["deviceInfo"]["MachineID"],
                         row["extra"]["machine_id"])
        self.assertIn("BEGIN EC PRIVATE KEY",
                      row["extra"]["privateKeyPEM"])
        self.assertIn("BEGIN PUBLIC KEY",
                      row["extra"]["deviceInfo"]["DevicePublicKey"])
        scalar = trae_client.ec_private_key_from_pem(
            row["extra"]["privateKeyPEM"])
        point = trae_client.ec_public_key_from_pem(
            row["extra"]["deviceInfo"]["DevicePublicKey"])
        self.assertEqual(trae_client.p256_public_point(scalar), point)

        self.assertEqual(len(transport.calls), 1)
        call = transport.calls[0]
        self.assertEqual(call["url"],
                         "https://api.trae.cn/trae/api/v3/oauth/ExchangeToken")
        self.assertEqual(call["headers"].get("x-cloudide-token"), "")
        self.assertEqual(call["payload"]["ClientID"], "ono9krqynydwx5")
        self.assertEqual(call["payload"]["AuthCode"], "code-1")
        self.assertEqual(call["payload"]["IDEVersion"], "3.3.100")
        self.assertEqual(call["payload"]["DeviceInfo"],
                         row["extra"]["deviceInfo"])

        polled = manager.poll(started["state"], owner="panel")
        self.assertEqual(polled["status"], "success")
        account = polled["account"]
        self.assertEqual(account["uid"], "user-1")
        self.assertNotIn("token", account)
        self.assertNotIn("refresh_token", account)
        self.assertNotIn("extra", account)
        self.assertNotIn("must-not-leak", json.dumps(polled))
        self.assertIn(account["account"].get("username"), ("", "Alice"))

        replay = manager.complete_callback(callback_params(started["state"]),
                                           owner="panel")
        self.assertEqual(replay["error"]["code"], "state_used")
        self.assertEqual(len(recorder.rows), 1)

    def test_callback_requires_matching_single_use_trace(self):
        transport = Transport()
        manager, recorder, clock = self.make(transport)
        started = self.start_manual(manager)
        cases = [
            {"authCodeInfo": json.dumps({"AuthCode": "c"})},
            callback_params(started["state"], loginTraceID="0" * 32),
            dict(callback_params(started["state"]), state="f" * 32),
            dict(callback_params(started["state"]), loginTraceID=""),
        ]
        for params in cases:
            result = manager.complete_callback(params)
            self.assertIn(result["status"], ("failed", "not_found"))
            if result["status"] == "failed":
                self.assertIn(result["error"]["code"],
                              ("invalid_callback", "unknown_state"))
        self.assertEqual(transport.calls, [])
        self.assertEqual(recorder.rows, [])

    def test_callback_uid_never_overrides_exchange_identity(self):
        transport = Transport(exchange={"Result": {
            "Token": "access-verified", "RefreshToken": "refresh-verified",
            "UserID": "verified-user"}})
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        params = callback_params(started["state"])
        params["userInfo"] = json.dumps({"UserID": "attacker-user"})
        result = manager.complete_callback(params)
        self.assertEqual(result["status"], "success")
        self.assertEqual(recorder.rows[0]["uid"], "verified-user")
        self.assertEqual(len(transport.calls), 1)

    def test_login_trace_id_alias_must_agree_with_login_trace_id(self):
        transport = Transport()
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        params = callback_params(started["state"], login_trace_id="0" * 32)
        result = manager.complete_callback(params)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "invalid_callback")
        self.assertEqual(transport.calls, [])
        self.assertEqual(recorder.rows, [])

    def test_duplicate_parameters_are_rejected(self):
        transport = Transport()
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        params = callback_params(started["state"])
        params["loginTraceID"] = [started["state"], started["state"]]
        result = manager.complete_callback(params)
        self.assertEqual(result["error"]["code"], "invalid_callback")
        self.assertEqual(transport.calls, [])
        self.assertEqual(recorder.rows, [])

    def test_authorization_error_and_expired_code_fail_without_exchange(self):
        transport = Transport()
        manager, recorder, clock = self.make(transport)
        denied = self.start_manual(manager)
        result = manager.complete_callback({
            "loginTraceID": denied["state"],
            "error": "access_denied",
            "error_description": "user said no",
        })
        self.assertEqual(result["error"]["code"], "authorization_denied")
        self.assertEqual(recorder.rows, [])

        expired = self.start_manual(manager)
        params = callback_params(expired["state"], clock=clock)
        params["authCodeInfo"] = json.dumps({
            "AuthCode": "old", "ExpireAt": int(clock.value - 1)})
        result = manager.complete_callback(params)
        self.assertEqual(result["error"]["code"], "authorization_expired")
        self.assertEqual(transport.calls, [])

    def test_owner_binding_for_poll_cancel_and_manual_complete(self):
        transport = Transport()
        manager, recorder, _clock = self.make(transport)
        started = manager.start(redirect_uri="https://example.test/cb",
                                owner="alice")
        state = started["state"]
        self.assertEqual(manager.poll(state, owner="bob")["status"],
                         "not_found")
        self.assertFalse(manager.cancel(state, owner="bob"))
        self.assertEqual(manager.complete_callback(
            callback_params(state), owner="bob")["status"], "not_found")
        self.assertEqual(transport.calls, [])
        result = manager.complete_callback(callback_params(state),
                                           owner="alice")
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(recorder.rows), 1)

    def test_cancel_before_callback_wins_and_blocks_storage(self):
        transport = Transport()
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager, owner="alice")
        self.assertTrue(manager.cancel(started["state"], owner="alice"))
        self.assertFalse(manager.cancel(started["state"], owner="alice"))
        self.assertEqual(manager.poll(started["state"], owner="alice")["status"],
                         "cancelled")
        result = manager.complete_callback(callback_params(started["state"]),
                                           owner="alice")
        self.assertEqual(result["error"]["code"], "state_cancelled")
        self.assertEqual(transport.calls, [])
        self.assertEqual(recorder.rows, [])

    def test_cancel_during_exchange_wins(self):
        transport = Transport(block=True)
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager, owner="alice")
        box = {}

        def run():
            box["result"] = manager.complete_callback(
                callback_params(started["state"]), owner="alice")

        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(transport.entered.wait(3))
        self.assertTrue(manager.cancel(started["state"], owner="alice"))
        transport.release.set()
        thread.join(5)
        self.assertEqual(box["result"]["status"], "cancelled")
        self.assertEqual(recorder.rows, [])

    def test_ttl_expiry_and_terminal_retention(self):
        transport = Transport()
        clock = Clock()
        manager, recorder, _clock = self.make(transport, clock=clock)
        started = self.start_manual(manager)
        clock.advance(trae_oauth.SESSION_TTL + 1)
        self.assertEqual(manager.poll(started["state"])["status"], "expired")
        result = manager.complete_callback(callback_params(
            started["state"], clock=clock))
        self.assertEqual(result["error"]["code"], "state_expired")
        self.assertEqual(transport.calls, [])

        fresh = self.start_manual(manager)
        self.assertEqual(manager.complete_callback(
            callback_params(fresh["state"], clock=clock),
            owner="")["status"], "success")
        clock.advance(trae_oauth.TERMINAL_TTL + 1)
        self.assertEqual(manager.poll(fresh["state"])["status"], "not_found")

    def test_on_complete_failure_is_not_success(self):
        for recorder in (Recorder(error=RuntimeError("disk full")),
                         Recorder(public=["not", "a", "dict"])):
            transport = Transport()
            manager, recorder, _clock = self.make(transport, recorder)
            started = self.start_manual(manager)
            result = manager.complete_callback(callback_params(started["state"]))
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"]["code"], "storage_failed")
            self.assertEqual(manager.poll(started["state"])["status"], "failed")

    def test_on_complete_is_serial_across_sessions(self):
        transport = Transport()
        recorder = Recorder(delay=0.05)
        manager, recorder, _clock = self.make(transport, recorder)
        first = self.start_manual(manager)
        second = self.start_manual(manager)
        threads = [
            threading.Thread(target=manager.complete_callback,
                             args=(callback_params(first["state"]),)),
            threading.Thread(target=manager.complete_callback,
                             args=(callback_params(second["state"]),)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(len(recorder.rows), 2)
        self.assertEqual(recorder.max_active, 1)

    def test_concurrent_replay_only_claims_once(self):
        transport = Transport(block=True)
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        box = {}

        def run():
            box["result"] = manager.complete_callback(
                callback_params(started["state"]))

        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(transport.entered.wait(3))
        replay = manager.complete_callback(callback_params(started["state"]))
        self.assertEqual(replay["error"]["code"], "state_used")
        transport.release.set()
        thread.join(5)
        self.assertEqual(box["result"]["status"], "success")
        self.assertEqual(len(recorder.rows), 1)


class TestFallbackAndIdentity(ManagerCase):
    def test_fallback_token_is_verified_by_get_user_info_without_rotation(self):
        transport = Transport(userinfo={"Result": {
            "UserID": "user-fallback", "ScreenName": "Bob"}})
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        params = {
            "loginTraceID": started["state"],
            "userJwt": "jwt-untrusted",
            "refreshToken": "refresh-fallback",
            "host": "api.trae.com.cn",
            "userInfo": json.dumps({"UserID": "user-fallback",
                                    "ScreenName": "Bob"}),
        }
        result = manager.complete_callback(params)
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(transport.calls), 1)
        self.assertIn("/cloudide/api/v3/trae/GetUserInfo",
                      transport.calls[0]["url"])
        self.assertEqual(transport.calls[0]["headers"]["x-cloudide-token"],
                         "jwt-untrusted")
        self.assertEqual(recorder.rows[0]["uid"], "user-fallback")
        self.assertEqual(recorder.rows[0]["token"], "jwt-untrusted")
        self.assertEqual(recorder.rows[0]["refresh_token"],
                         "refresh-fallback")

    def test_fallback_query_uid_cannot_override_verified_identity(self):
        transport = Transport(userinfo={"Result": {"UserID": "real-user"}})
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        result = manager.complete_callback({
            "loginTraceID": started["state"],
            "accessToken": "token",
            "refreshToken": "refresh",
            "userInfo": json.dumps({"UserID": "claimed-user"}),
        })
        # The query uid is never trusted: the verified GetUserInfo identity wins.
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(recorder.rows), 1)
        self.assertEqual(recorder.rows[0]["uid"], "real-user")

    def test_missing_exchange_uid_uses_get_user_info(self):
        transport = Transport(
            exchange={"Result": {"Token": "t", "RefreshToken": "r"}},
            userinfo={"Result": {"UserID": "from-userinfo",
                                 "ScreenName": "Carol"}})
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        params = callback_params(started["state"])
        params.pop("userInfo", None)       # identity must come from GetUserInfo
        result = manager.complete_callback(params)
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(recorder.rows[0]["uid"], "from-userinfo")
        self.assertEqual(recorder.rows[0]["account"]["username"], "Carol")

    def test_missing_uid_everywhere_is_rejected(self):
        transport = Transport(
            exchange={"Result": {"Token": "t", "RefreshToken": "r"}},
            userinfo={"Result": {}})
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        result = manager.complete_callback(callback_params(started["state"]))
        self.assertEqual(result["error"]["code"], "identity_mismatch")
        self.assertEqual(recorder.rows, [])

    def test_cross_realm_callback_host_is_rejected_before_transport(self):
        transport = Transport()
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        result = manager.complete_callback(callback_params(
            started["state"], host="api.trae.ai"))
        self.assertEqual(result["error"]["code"], "invalid_callback")
        self.assertEqual(transport.calls, [])

    def test_unapproved_host_and_transport_exception_do_not_leak(self):
        transport = Transport(error=RuntimeError("secret upstream token=abc"))
        manager, recorder, _clock = self.make(transport)
        started = self.start_manual(manager)
        result = manager.complete_callback(callback_params(started["state"]))
        self.assertEqual(result["error"]["code"], "exchange_failed")
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("abc", json.dumps(result))
        self.assertEqual(recorder.rows, [])


class TestListenerSecurity(ManagerCase):
    def test_host_origin_and_cors_are_strict(self):
        transport = Transport()
        manager, recorder, _clock = self.make(transport)
        started = manager.start(realm="cn", platform="linux")
        url = callback_url(started)
        status, _headers, _body = http_get(
            url, {"Host": "evil.test"})
        self.assertEqual(status, 421)
        status, _headers, _body = http_get(
            url, {"Origin": "https://evil.test"})
        self.assertEqual(status, 403)
        status, headers, _body = http_get(
            url, {"Origin": "https://www.trae.cn"})
        self.assertEqual(status, 200)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(len(recorder.rows), 1)

    def test_options_and_unknown_path_have_no_cors(self):
        manager, _recorder, _clock = self.make()
        started = manager.start()
        parsed = urllib.parse.urlsplit(started["redirect_uri"])
        base = "http://%s" % parsed.netloc
        status, headers, _body = http_get(base + "/authorize", {})
        # A GET without params is rejected, but must not advertise CORS.
        self.assertEqual(status, 400)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        request = urllib.request.Request(base + "/authorize", method="OPTIONS")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                status = response.status
                headers = dict(response.headers)
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = dict(exc.headers)
        self.assertEqual(status, 405)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_close_stops_listener(self):
        manager, _recorder, _clock = self.make()
        started = manager.start()
        parsed = urllib.parse.urlsplit(started["redirect_uri"])
        manager.close()
        with self.assertRaises(Exception):
            urllib.request.urlopen("http://%s/authorize" % parsed.netloc,
                                   timeout=3)
        manager.close()


class TestTransportPolicy(unittest.TestCase):
    def test_endpoint_whitelist_is_exact_and_realm_bound(self):
        manager = OAuthManager(lambda row: {})
        self.addCleanup(manager.close)
        manager._validate_endpoint(
            "https://api.trae.cn" + trae_oauth.EXCHANGE_PATH, "cn")
        manager._validate_endpoint(
            "https://grow-normal.trae.ai" + trae_oauth.USER_INFO_PATH, "intl")
        with self.assertRaises(trae_oauth.OAuthError):
            manager._validate_endpoint(
                "https://api.trae.ai" + trae_oauth.EXCHANGE_PATH, "cn")
        with self.assertRaises(trae_oauth.OAuthError):
            manager._validate_endpoint(
                "https://api.trae.cn:8443" + trae_oauth.EXCHANGE_PATH, "cn")
        with self.assertRaises(trae_oauth.OAuthError):
            manager._validate_endpoint(
                "https://api.trae.cn" + trae_oauth.EXCHANGE_PATH + "?x=1",
                "cn")
        with self.assertRaises(trae_oauth.OAuthError):
            manager._validate_endpoint(
                "http://api.trae.cn" + trae_oauth.EXCHANGE_PATH, "cn")

    def test_default_transport_contract_is_bounded_and_no_redirect(self):
        self.assertEqual(trae_oauth.HTTP_TIMEOUT, 30)
        self.assertEqual(trae_oauth.MAX_RESPONSE_BYTES, 1024 * 1024)
        handler = trae_oauth._NoRedirect()
        self.assertIsNone(handler.redirect_request(
            None, None, 302, "Found", {}, "https://evil.test/"))


class TestDeviceKey(unittest.TestCase):
    def test_sec1_and_spki_round_trip(self):
        scalar, private_pem, public_pem, point = (
            trae_oauth.generate_device_key())
        self.assertIn("BEGIN EC PRIVATE KEY", private_pem)
        self.assertIn("BEGIN PUBLIC KEY", public_pem)
        self.assertEqual(trae_client.ec_private_key_from_pem(private_pem),
                         scalar)
        self.assertEqual(trae_client.ec_public_key_from_pem(public_pem),
                         (point["x"], point["y"]))
        self.assertEqual(trae_client.p256_public_point(scalar),
                         (point["x"], point["y"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
