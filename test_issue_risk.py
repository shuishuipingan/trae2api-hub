# -*- coding: utf-8 -*-
"""Provider refusal regression tests; no sockets or real accounts."""
import io
import json
import tempfile
import time
import unittest
from contextlib import ExitStack
from email.message import Message
from unittest.mock import patch
from urllib.error import HTTPError

import trae_proxy as P


MODEL = "gpt-4o"
MESSAGES = [{"role": "user", "content": "fixture"}]
PAYLOAD = {"model": MODEL, "messages": MESSAGES}
SECRET = "fixture sensitive data: session expired; exceeded the quota"
PATHS = ("/v1/chat/completions", "/v1/responses", "/v1/messages")


def event(name, **payload):
    prefix = "event: " + name + "\n" if name else ""
    return (prefix + "data: " + json.dumps(payload) + "\n\n").encode()


def http_error(status, payload):
    body = json.dumps(payload).encode() if isinstance(payload, dict) else payload.encode()
    return HTTPError("https://fixture.invalid/", status, "fixture", {}, io.BytesIO(body))


class FixturePool:
    def __init__(self, first, second):
        self.accounts = [first, second]
        self.picked = []
        self.guard_result = (True, "", "")
        self.affinity = P.trae_accounts.SessionAffinity()

    def count_ready(self, realm, model=None):
        return sum(a.ready(model) for a in self.accounts)

    def pick_for_session(self, realm, session_key, exclude, model):
        order = sorted(self.accounts, key=lambda a: a.uid != self.affinity.get(session_key))
        for account in order:
            if account.uid not in exclude and account.ready(model):
                self.picked.append(account.uid)
                return account
        return None

    def guard(self, *args, **kwargs):
        return self.guard_result


class MemoryHandler(P.Handler):
    def __init__(self, path, payload):
        self.path = path
        self.payload = payload
        self.headers = Message()
        self.frames = []
        self.result = None
        self.status = None
        self.ended = False

    def _authorized(self):
        return True

    def _payload_or_error(self, **kwargs):
        return self.payload

    def _effective_realm(self, *args):
        return "intl"

    def _prepare_degrade(self, *args):
        return None

    def _model_precheck(self, *args):
        return None

    def _json(self, status, obj):
        self.status, self.result = status, obj

    def _sse_begin(self):
        self.status = 200

    def _sse_write(self, frame):
        self.frames.append(frame)

    def _sse_end(self):
        self.ended = True

    def stream_data(self):
        return [json.loads(line[6:]) for frame in self.frames
                for line in frame.decode().splitlines()
                if line.startswith("data: ") and line != "data: [DONE]"]


class ProviderRiskTests(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        self.directory = stack.enter_context(tempfile.TemporaryDirectory())
        def mock(obj, name, **kwargs):
            return stack.enter_context(patch.object(obj, name, **kwargs))
        mock(P, "ACCOUNTS_DIR", new=self.directory)
        mock(P.trae_accounts, "_now", return_value=int(time.time()))
        self.now = P.trae_accounts._now()
        mock(P, "log")
        mock(P, "record_usage")
        self.record_error = mock(P, "record_error")
        self.sleep = mock(P.time, "sleep")
        self.refresh = mock(P, "trae_refresh_account", return_value=False)
        self.client = P._trae_client
        self.transport = mock(self.client, "_open", side_effect=AssertionError("unmocked client"))
        self.legacy = mock(P.urllib.request, "urlopen", side_effect=AssertionError("unmocked legacy"))
        mock(P, "build_trae_body", return_value={"messages": MESSAGES})
        mock(P, "qoder_model_name", return_value=None)
        self.reset_pool()

    def reset_pool(self):
        def account(uid):
            return P.trae_accounts.Account({"uid": uid, "realm": "intl",
                "token": "fixture-token", "usage": {"remaining": 10},
                "extra": {"intl_quota": {"remain_usage": {"free": 10}}}},
                directory=self.directory)
        self.first, self.second = account("fixture-first"), account("fixture-second")
        self.pool = FixturePool(self.first, self.second)
        self.pool.affinity.bind("fixture-session", self.first.uid)
        self.enterContext(patch.object(P, "POOL", self.pool))
        self.enterContext(patch.object(P, "extract_session_key", return_value="fixture-session"))
        self.first_before, self.second_before = self.first.to_dict(), self.second.to_dict()
        self.transport.reset_mock()
        self.legacy.reset_mock()
        self.refresh.reset_mock()
        self.sleep.reset_mock()
        self.record_error.reset_mock()

    def open(self):
        return P.open_upstream(PAYLOAD, session_key="fixture-session", target_realm="intl")

    def request(self, path, stream):
        payload = dict(PAYLOAD, stream=stream, max_tokens=32)
        if path.endswith("/responses"):
            payload = {"model": MODEL, "input": "fixture", "stream": stream}
        handler = MemoryHandler(path, payload)
        handler.do_POST()
        return handler

    def assert_risk(self, code, account):
        self.assertTrue(account.enabled)
        self.assertEqual(account.fails, 1)
        self.assertEqual(account.breaker_until, 0)
        window = P.trae_accounts.COOLDOWN_RATE * 3 if code == 4015 else P.trae_accounts.BREAKER_RISK
        self.assertEqual(account.cooldown_until, self.now + window)
        self.assertIn(str(code), account.last_error)
        self.assertNotIn(SECRET, account.last_error)
        self.assertEqual(account.usage, {"remaining": 10})
        self.assertEqual(account.extra["intl_quota"]["remain_usage"], {"free": 10})

    def assert_first_only(self, code):
        self.assertEqual(self.pool.picked, [self.first.uid])
        self.assert_risk(code, self.first)
        self.assertEqual(self.second.to_dict(), self.second_before)
        self.assertEqual(self.pool.affinity.get("fixture-session"), self.first.uid)
        self.refresh.assert_not_called()
        self.sleep.assert_not_called()

    def assert_terminal(self, handler, path, code, sse):
        if not sse:
            self.assertEqual(handler.status, 403)
            self.assertEqual(handler.result["error"]["code"], code)
            self.assertEqual(handler.result["error"]["type"], "risk_control")
            message = handler.result["error"]["message"]
        else:
            self.assertEqual(handler.status, 200)
            self.assertTrue(handler.ended)
            data = handler.stream_data()
            if path.endswith("/responses"):
                self.assertEqual(data[0]["type"], "response.created")
                self.assertEqual(data[-1]["type"], "response.failed")
                self.assertEqual(data[-1]["response"]["error"]["code"], str(code))
                message = data[-1]["response"]["error"]["message"]
            elif path.endswith("/messages"):
                self.assertEqual(data[0]["type"], "message_start")
                self.assertEqual(data[-1]["type"], "error")
                self.assertEqual(data[-1]["error"]["type"], "api_error")
                message = data[-1]["error"]["message"]
            else:
                self.assertEqual(data[-1]["error"]["code"], code)
                self.assertEqual(data[-1]["error"]["type"], "risk_control")
                self.assertEqual(handler.frames[-1], b"data: [DONE]\n\n")
                message = data[-1]["error"]["message"]
        self.assertIn("Trae %d" % code, message)
        self.assertNotIn(SECRET, message)
        self.record_error.assert_called_once()
        self.assertNotIn(SECRET, self.record_error.call_args.args[2])

    def test_raw_client_4015_and_4019_before_refresh_or_transient_retry(self):
        for code, status, body in (
            (4015, 403, {"code": 4015, "message": SECRET}),
            (4019, 503, {"error": {"code": "4019", "message": SECRET}}),
        ):
            with self.subTest(code=code):
                self.reset_pool()
                self.transport.side_effect = http_error(status, body)
                with self.assertRaises(P.ProviderRisk) as ctx:
                    self.open()
                self.assertEqual((ctx.exception.status, ctx.exception.provider_code), (403, code))
                self.assertNotIn(SECRET, ctx.exception.detail)
                self.transport.assert_called_once()
                self.assert_first_only(code)

    def test_legacy_urllib_nested_code_past_diagnostic_limit(self):
        error = http_error(401, {"padding": "x" * 1000,
                                 "error": {"code": "4019"}})
        self.legacy.side_effect = error
        with patch.object(P, "_trae_client", None), \
                patch.object(P, "validate_public_http_url", side_effect=lambda url: url):
            with self.assertRaises(P.ProviderRisk) as ctx:
                self.open()
        self.assertEqual(ctx.exception.provider_code, 4019)
        self.legacy.assert_called_once()
        self.assertTrue(error.fp.closed)
        self.assert_first_only(4019)

    def test_auth_false_positives_still_refresh_and_rotate(self):
        for status, body in (
            (401, {"code": 1001, "message": "reference 4019 and risk_control"}),
            (403, {"code": "40150", "message": "unusual activity, reference 14019"}),
            (403, "Plain text: unusual activity risk_control 4015 4019"),
        ):
            with self.subTest(body=body):
                self.reset_pool()
                self.refresh.return_value = True
                self.transport.side_effect = [http_error(status, body), http_error(status, body),
                                              io.BytesIO(event("done"))]
                response, account, _ = self.open()
                response.close()
                self.assertIs(account, self.second)
                self.assertEqual(self.transport.call_count, 3)
                self.refresh.assert_called_once_with(self.first, "intl", force=True)
                self.assertEqual(self.pool.picked, [self.first.uid, self.second.uid])
                self.assertTrue(self.first.enabled)
                self.assertEqual(self.first.breaker_until, self.now + P.trae_accounts.BREAKER_AUTH)
                self.assertEqual(self.first.cooldown_until, 0)

    def test_raw_and_sse_first_event_reach_matching_terminal_protocol(self):
        for path in PATHS:
            for streaming in (False, True):
                for raw in (False, True):
                    with self.subTest(path=path, streaming=streaming, raw=raw):
                        self.reset_pool()
                        code = 4015 if raw else 4019
                        if raw:
                            response = http_error(403, {"code": code, "message": SECRET})
                        else:
                            response = io.BytesIO(event("error", code=str(code), message=SECRET)
                                                  + event("output", response="must not be emitted"))
                        self.transport.side_effect = [response]
                        handler = self.request(path, streaming)
                        self.assert_terminal(handler, path, code, sse=streaming and not raw)
                        self.transport.assert_called_once()
                        self.assert_first_only(code)
                        self.assertNotIn("must not be emitted", str(handler.frames))
                        if not raw:
                            self.assertTrue(response.closed)

    def test_nested_sse_error_and_ordinary_output_with_id(self):
        response = io.BytesIO(event("metadata", session_id="fixture-4019")
                              + event("output", response="record 4015", code=4019)
                              + event(None, statusCodeValue=403,
                                      error={"code": "4015", "message": SECRET}))
        self.transport.side_effect = [response]
        handler = self.request(PATHS[0], True)
        self.assertIn("record 4015", str(handler.frames))
        self.assert_terminal(handler, PATHS[0], 4015, sse=True)
        self.transport.assert_called_once()
        self.assert_first_only(4015)

    def test_terminal_raw_refusal_on_reopen_supersedes_initial_auth_error(self):
        for path, streaming in [(p, False) for p in PATHS] + [(p, True) for p in PATHS[:2]]:
            with self.subTest(path=path, streaming=streaming):
                self.reset_pool()
                initial = io.BytesIO(event("error", code=1001, message="authentication expired"))
                self.transport.side_effect = [initial, http_error(403, {"code": "4019"})]
                handler = self.request(path, streaming)
                self.assert_terminal(handler, path, 4019, sse=streaming)
                self.assertEqual(self.transport.call_count, 2)
                self.assertEqual(self.pool.picked, [self.first.uid, self.second.uid])
                self.refresh.assert_called_once_with(self.first, "intl", force=True)
                self.assertEqual(self.first.breaker_until, self.now + P.trae_accounts.BREAKER_AUTH)
                self.assert_risk(4019, self.second)
                self.assertTrue(initial.closed)

    def test_non_stream_transport_reopen_preserves_risk(self):
        class Broken(io.BytesIO):
            def __iter__(self):
                raise ConnectionResetError("fixture upstream reset")
        self.transport.side_effect = [Broken(), http_error(403, {"code": 4015})]
        handler = self.request(PATHS[0], False)
        self.assert_terminal(handler, PATHS[0], 4015, sse=False)
        self.assertEqual(self.transport.call_count, 2)
        self.assert_risk(4015, self.first)
        self.assertEqual(self.second.to_dict(), self.second_before)
        self.refresh.assert_not_called()

    def test_quota_4008_mapping_and_account_state_are_unchanged(self):
        self.transport.side_effect = [http_error(429, {"code": 4008,
                                                      "message": "exceeded the quota"})]
        with self.assertRaises(P.UpstreamStatus) as raw:
            self.open()
        self.assertEqual(raw.exception.status, 429)
        self.assertNotIsInstance(raw.exception, P.ProviderRisk)
        self.transport.assert_called_once()

        with self.assertRaises(P.UpstreamStatus) as sse:
            list(P.iter_inner_sse(io.BytesIO(event("error", code=4008))))
        self.assertEqual(sse.exception.status, 429)
        self.assertNotIsInstance(sse.exception, P.ProviderRisk)
        P._handle_envelope_account_cooldown(self.first, sse.exception,
                                            model=MODEL, session_key="fixture-session")
        self.assertEqual(P._upstream_status_message(sse.exception)[1], "quota_exceeded")
        self.assertEqual(self.first.to_dict(), self.first_before)
        self.assertEqual(self.second.to_dict(), self.second_before)
        self.refresh.assert_not_called()
        self.assertEqual(self.pool.affinity.get("fixture-session"), self.first.uid)

    def test_local_quota_guard_still_blocks_before_transport(self):
        self.pool.guard_result = (False, "quota_exceeded", "fixture quota guard")
        with self.assertRaises(P.QuotaBlocked):
            self.open()
        self.transport.assert_not_called()
        self.assertEqual(self.first.to_dict(), self.first_before)
        self.assertEqual(self.second.to_dict(), self.second_before)


if __name__ == "__main__":
    unittest.main()
