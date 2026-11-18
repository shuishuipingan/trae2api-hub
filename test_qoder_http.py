"""Qoder Chat HTTP contract: real loopback HTTP, temporary stores, fake providers.

Run: python -B -m unittest test_qoder_http -v
No real account pool is initialized; no credential or external network is used.
Only explicit qoder/<key> models belong to this provider.
"""
import contextlib
import copy
import http.client
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer

import trae_proxy as P
import trae_accounts as A
import trae_settings as S

Q = P.trae_qoder
MODEL = "qoder/gmodel"
USAGE = {"prompt_tokens": 17, "completion_tokens": 5, "total_tokens": 22,
         "prompt_tokens_details": {"cached_tokens": 3}}
CATALOG = [{"key": "gmodel", "display_name": "GLM-5.3", "enabled": True,
            "available": True},
           {"key": "other", "display_name": "Other", "enabled": True,
            "available": True}]


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.finished.set()


class _Quiet(P.Handler):
    def log_message(self, *args):
        pass


class _Iterator:
    """Observable close() even when a caller retains a reference to the iterator."""
    def __init__(self, mode):
        self.mode = mode
        self.step = 0
        self.closed = threading.Event()
        self.release = threading.Event()

    def __iter__(self):
        return self

    def __next__(self):
        step = self.step
        self.step += 1
        if step == 0 and self.mode == "prefirst":
            raise Q.QoderError("fixture pre-first failure", status=503)
        if step == 0:
            return {"object": "chat.completion.chunk", "model": "gmodel",
                    "choices": [{"index": 0, "delta": {"content": "fixture"},
                                 "finish_reason": None}]}
        if self.mode == "disconnect":
            if not self.release.wait(4):
                raise RuntimeError("disconnect fixture was not released")
            if step > 32:
                raise RuntimeError("disconnect was not observed")
            return {"choices": [{"index": 0, "delta": {"content": "x" * 1048576},
                                 "finish_reason": None}]}
        if self.mode == "midstream":
            raise Q.QoderError("fixture mid-stream failure", status=502)
        if step == 1:
            return {"object": "chat.completion.chunk", "model": "gmodel",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "usage": copy.deepcopy(USAGE)}
        raise StopIteration

    def close(self):
        self.closed.set()
        self.release.set()


class QoderHTTP(unittest.TestCase):
    real_stream_chat = staticmethod(Q.stream_chat)
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="qoder-http-")
        self.addCleanup(self.tmp.cleanup)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.accounts = os.path.join(self.tmp.name, "accounts")
        self.usage_dir = os.path.join(self.tmp.name, "usage")
        os.makedirs(self.accounts)
        os.makedirs(self.usage_dir)
        # The pool sees only this empty fixture directory, never desktop state.
        self.pool = A.AccountPool(self.accounts, log=lambda *a, **k: None)
        self.addCleanup(self.pool.close_logins)
        self.usage_log = os.path.join(self.usage_dir, "usage.jsonl")
        self.stack.enter_context(mock.patch.multiple(
            P, POOL=self.pool, ACCOUNTS_DIR=self.accounts,
            USAGE_DIR=self.usage_dir, USAGE_LOG=self.usage_log,
            USAGE_SUMMARY=os.path.join(self.usage_dir, "usage-summary.json"),
            REALM_STATE_FILE=os.path.join(self.accounts, "active_realm.json"),
            CURRENT_REALM="cn", API_KEY=None,
            PANEL=S.PanelSessions(self.accounts), _usage=P._empty_stats(),
            _USAGE_DEDUPE_SEEN={}, _bykey_cache={}))
        # Some reporting helpers live in trae_stats; point both modules at temp.
        self.stack.enter_context(mock.patch.multiple(
            P.trae_stats, POOL=self.pool, USAGE_DIR=self.usage_dir,
            USAGE_LOG=self.usage_log,
            USAGE_SUMMARY=os.path.join(self.usage_dir, "usage-summary.json")))
        self.stack.enter_context(mock.patch.dict(os.environ, {
            "QODER_CN_TOKEN": "dt-FIXTURE-ONLY", "QODER_CN_UID": "fixture",
            "QODER_CN_MACHINE_ID": "fixture-machine", "QODER_DISABLE": "0"}))
        self.patch(P, "log", return_value=None)
        # A hard guard below the mocked provider catches accidental live I/O.
        self.patch(Q, "_open", side_effect=AssertionError("real Qoder network forbidden"))
        self.real_credential = Q.load_credential
        self.real_available = Q.credential_available
        self.credential = self.patch(Q, "load_credential", side_effect=AssertionError(
            "real credentials forbidden"))
        self.directory_probe = self.patch(Q, "qoder_dir", side_effect=AssertionError(
            "personal Qoder directory forbidden"))
        self.available = self.patch(Q, "credential_available", return_value=True)
        self.catalog = self.patch(Q, "model_list", return_value=copy.deepcopy(CATALOG))
        self.resolve = self.patch(Q, "resolve_model", side_effect=lambda value:
                                  {"GLM-5.3": "gmodel"}.get(value, value))
        self.complete = self.patch(Q, "complete_chat", side_effect=self.fake_complete)
        self.stream = self.patch(Q, "stream_chat", side_effect=self.fake_stream)
        self.trae = self.patch(P, "open_upstream", side_effect=RuntimeError(
            "fixture Trae provider reached"))
        self.patch(P, "fetch_models", return_value=[("trae-fixture", {})])
        self.patch(P, "fetch_models_merged", return_value=[("trae-fixture", {}, "cn")])
        self.patch(P, "model_entry", side_effect=lambda mid, meta, realm=None:
                   {"id": mid, "object": "model", "realm": realm, "available": True})
        self.mode = "ok"
        self.iterators = []
        self.server = _Server(("127.0.0.1", 0), _Quiet)
        self.server.finished = threading.Event()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        original_connect = socket.socket.connect

        def loopback_only(sock, address):
            if not isinstance(address, tuple) or address[0] not in ("127.0.0.1", "::1"):
                raise AssertionError("external network forbidden: %r" % (address,))
            return original_connect(sock, address)

        self.patch(socket.socket, "connect", new=loopback_only)

    def patch(self, obj, name, **kwargs):
        return self.stack.enter_context(mock.patch.object(obj, name, **kwargs))

    def stop_server(self):
        for iterator in self.iterators:
            iterator.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def fake_complete(self, model, messages, request=None, **kwargs):
        if self.mode == "error":
            raise Q.QoderError("fixture provider failure", status=502)
        return {"object": "chat.completion", "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                             "finish_reason": "stop"}], "usage": copy.deepcopy(USAGE)}

    def fake_stream(self, *args, **kwargs):
        iterator = _Iterator(self.mode)
        self.iterators.append(iterator)
        return iterator

    def keys(self, **overrides):
        entry = {"id": "fixture-key-id", "name": "fixture", "key": "sk-FIXTURE-ONLY",
                 "realm": "cn", "enabled": True}
        entry.update(overrides)
        S.set_api_keys(self.accounts, [entry])
        return entry["key"]

    def request(self, path="/v1/chat/completions", model=MODEL, stream=False,
                key=None, body=None, method="POST"):
        payload = {"model": model, "messages": [{"role": "user", "content": "ping"}],
                   "stream": stream} if body is None else body
        headers = {"Content-Type": "application/json", "Connection": "close"}
        if key:
            headers["Authorization"] = "Bearer " + key
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=6)
        self.server.finished.clear()
        try:
            conn.request(method, path, None if method == "GET" else json.dumps(payload), headers)
            response = conn.getresponse()
            result = response.status, response.read().decode("utf-8"), dict(response.getheaders())
        finally:
            conn.close()
        self.assertTrue(self.server.finished.wait(3), "HTTP handler did not finish")
        return result

    def rows(self):
        if not os.path.exists(self.usage_log):
            return []
        return [json.loads(line) for line in Path(self.usage_log).read_text(encoding="utf-8").splitlines()
                if line.strip()]

    def assert_zero_provider(self):
        self.complete.assert_not_called()
        self.stream.assert_not_called()
        self.trae.assert_not_called()

    def assert_accounting(self, row, error=False):
        self.assertEqual(row["model"], MODEL, row)
        self.assertEqual(row.get("provider"), "qoder", row)
        self.assertEqual(row.get("realm"), "cn", row)
        self.assertEqual(row.get("key_id"), "fixture-key-id", row)
        self.assertTrue(row.get("request_id"), row)
        self.assertEqual(bool(row.get("error")), error, row)
        self.assertNotIn("sk-FIXTURE-ONLY", json.dumps(row))

    def test_bare_models_never_route_or_probe_qoder(self):
        for model in ("gmodel", "GLM-5.3", "trae-fixture"):
            with self.subTest(model=model):
                for spy in (self.available, self.catalog, self.resolve):
                    spy.reset_mock()
                status, text, _ = self.request(model=model)
                self.assertNotEqual(status, 200, text)  # mock Trae upstream deliberately fails
                self.complete.assert_not_called()
                self.stream.assert_not_called()
                self.available.assert_not_called()
                self.catalog.assert_not_called()
                self.resolve.assert_not_called()
                self.directory_probe.assert_not_called()
                self.credential.assert_not_called()

    def test_disabled_explicit_qoder_never_calls_provider(self):
        with mock.patch.dict(os.environ, {"QODER_DISABLE": "1"}):
            for stream in (False, True):
                for model in (MODEL, "qoder/unknown"):
                    with self.subTest(stream=stream, model=model):
                        status, text, _ = self.request(model=model, stream=stream)
                        self.assertIn(status, (400, 503), text)
                        self.assert_zero_provider()
        self.available.assert_not_called()
        self.catalog.assert_not_called()
        self.resolve.assert_not_called()

    def test_no_configuration_does_not_probe_personal_state(self):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("QODER_")}
        # Exercise the actual opt-in gate; only its personal-state sink remains
        # guarded. Mocking credential_available=True would mask that gate.
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(Q, "credential_available", wraps=self.real_available), \
                mock.patch.object(Q, "load_credential", wraps=self.real_credential):
            self.assertFalse(P.qoder_enabled())
            status, text, _ = self.request()
            self.assertIn(status, (400, 503), text)
            self.request(path="/v1/models", method="GET")
        self.directory_probe.assert_not_called()
        self.catalog.assert_not_called()
        self.assert_zero_provider()

    def test_cn_and_unbound_key_allow_qoder(self):
        for realm in ("cn", ""):
            with self.subTest(realm=realm):
                key = self.keys(realm=realm)
                status, text, _ = self.request(key=key)
                self.assertEqual(status, 200, text)
        self.assertEqual(self.complete.call_count, 2)
        self.trae.assert_not_called()

    def test_fixed_intl_key_rejected_before_provider(self):
        key = self.keys(realm="intl")
        for stream in (False, True):
            with self.subTest(stream=stream):
                status, text, _ = self.request(key=key, stream=stream)
                self.assertEqual(status, 400, text)
                self.assert_zero_provider()

    def test_global_ban_prechecked_for_stream_and_nonstream(self):
        S.set_banned_models(self.accounts, [MODEL])
        for stream in (False, True):
            with self.subTest(stream=stream):
                status, text, _ = self.request(stream=stream)
                self.assertEqual(status, 400, text)
                self.assert_zero_provider()

    def test_key_whitelist_prechecked_for_stream_and_nonstream(self):
        key = self.keys(models=["trae-*"])
        for stream in (False, True):
            with self.subTest(stream=stream):
                status, text, _ = self.request(stream=stream, key=key)
                self.assertEqual(status, 400, text)
                self.assert_zero_provider()

    def test_whitelist_matches_canonical_qoder_model(self):
        key = self.keys(models=[MODEL])
        status, text, _ = self.request(key=key)
        self.assertEqual(status, 200, text)
        self.assertEqual(self.complete.call_args.args[0], "gmodel")

    def test_request_quota_rechecked_on_each_request(self):
        key = self.keys(daily_requests=1)
        status, text, _ = self.request(key=key)
        self.assertEqual(status, 200, text)
        status, text, _ = self.request(key=key)
        self.assertEqual(status, 429, text)
        self.assertEqual(self.complete.call_count, 1)
        self.assertEqual(len([r for r in self.rows() if not r.get("error")]), 1)

    def test_token_quota_blocks_before_stream_provider(self):
        key = self.keys(daily_tokens=22)
        status, text, _ = self.request(key=key)
        self.assertEqual(status, 200, text)
        status, text, _ = self.request(key=key, stream=True)
        self.assertEqual(status, 429, text)
        self.stream.assert_not_called()
        self.assertEqual(self.complete.call_count, 1)

    def test_nonstream_usage_is_canonical_and_request_ids_unique(self):
        key = self.keys(realm="")
        with mock.patch.object(P, "CURRENT_REALM", "intl"):
            for _ in range(2):
                status, text, _ = self.request(key=key)
                self.assertEqual(status, 200, text)
        rows = self.rows()
        self.assertEqual(len(rows), 2, rows)
        for row in rows:
            self.assert_accounting(row)
            self.assertEqual(row["total_tokens"], 22)
            self.assertFalse(row["usage_missing"])
        self.assertNotEqual(rows[0]["request_id"], rows[1]["request_id"])

    def test_nonstream_error_is_accounted_without_success(self):
        self.mode = "error"
        status, text, _ = self.request(key=self.keys())
        self.assertEqual(status, 502, text)
        self.assertIn("error", json.loads(text))
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        self.assert_accounting(rows[0], error=True)
        self.assertEqual(P._usage["requests"], 0)
        self.assertEqual(P._usage["errors"], 1)

    def test_stream_saves_real_usage_and_closes_iterator(self):
        status, text, _ = self.request(stream=True, key=self.keys())
        self.assertEqual(status, 200, text)
        self.assertIn("data: [DONE]", text)
        frames = [json.loads(line[6:]) for line in text.splitlines()
                  if line.startswith("data: ") and line != "data: [DONE]"]
        self.assertTrue(any(frame.get("usage") == USAGE for frame in frames), frames)
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        self.assert_accounting(rows[0])
        self.assertEqual(rows[0]["prompt_tokens"], 17)
        self.assertEqual(rows[0]["completion_tokens"], 5)
        self.assertEqual(rows[0]["total_tokens"], 22)
        self.assertFalse(rows[0]["usage_missing"])
        self.assertTrue(self.iterators[0].closed.is_set(), "stream iterator not closed")

    def test_prefirst_failure_is_http_error_not_200(self):
        self.mode = "prefirst"
        status, text, headers = self.request(stream=True, key=self.keys())
        self.assertEqual(status, 503, text)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        self.assertIn("error", json.loads(text))
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        self.assert_accounting(rows[0], error=True)
        self.assertEqual(P._usage["requests"], 0)
        self.assertTrue(self.iterators[0].closed.is_set())

    def test_midstream_error_is_sse_error_not_success_usage(self):
        self.mode = "midstream"
        status, text, _ = self.request(stream=True, key=self.keys())
        self.assertEqual(status, 200, text)
        frames = [json.loads(line[6:]) for line in text.splitlines()
                  if line.startswith("data: ") and line != "data: [DONE]"]
        self.assertTrue(any("error" in frame for frame in frames), frames)
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        self.assert_accounting(rows[0], error=True)
        self.assertEqual(P._usage["requests"], 0)
        self.assertEqual(P._usage["errors"], 1)
        self.assertTrue(self.iterators[0].closed.is_set())

    def test_client_disconnect_closes_provider_iterator(self):
        self.mode = "disconnect"
        key = self.keys()
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=6)
        self.server.finished.clear()
        conn.request("POST", "/v1/chat/completions", json.dumps({"model": MODEL,
                     "messages": [{"role": "user", "content": "ping"}], "stream": True}),
                     {"Content-Type": "application/json", "Authorization": "Bearer " + key})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertTrue(response.readline().startswith(b"data: "))
        iterator = self.iterators[0]
        # Closing the actual local TCP peer, not mocking the Handler write path.
        peer = response.fp.raw._sock
        with contextlib.suppress(OSError):
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
        with contextlib.suppress(OSError):
            peer.shutdown(socket.SHUT_RDWR)
        response.close()
        conn.close()
        iterator.release.set()
        self.assertTrue(self.server.finished.wait(5), "disconnect handler did not finish")
        self.assertTrue(iterator.closed.is_set(), "client disconnect leaked provider iterator")
        self.assertEqual(P._usage["requests"], 0, "disconnect counted as completed success")

    def test_real_adapter_invalid_tool_stream_is_error_not_success(self):
        class Response(io.BytesIO):
            headers={"Content-Type":"text/event-stream"}
        for fragment in (None, {"index":0,"id":"call_fixture","type":"function","function":{"name":"f","arguments":"{"}}):
            with self.subTest(fragment=fragment):
                self.mode="ok"
                data={"choices":[{"index":0,"delta":{"tool_calls":[fragment]},"finish_reason":None}]}
                end={"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}
                raw=("data: "+json.dumps(data)+"\n\ndata: "+json.dumps(end)+"\n\ndata: [DONE]\n\n").encode()
                response=Response(raw)
                # Restore the actual parser, with only its transport mocked.
                with mock.patch.object(Q,"stream_chat",new=QoderHTTP.real_stream_chat), \
                     mock.patch.object(Q,"load_credential",return_value={"token":"fixture","userID":"fixture","machineID":"fixture"}), \
                     mock.patch.object(Q,"_open",return_value=response):
                    code,text,_=self.request(stream=True)
                    self.assertIn(code,(200,502),text)
                    self.assertIn('"error"',text)
                    self.assertNotIn('"finish_reason": "tool_calls"',text)
                    self.assertTrue(response.closed)
        self.assertEqual(P._usage["requests"],0)
        self.assertEqual(P._usage["errors"],2)

    def test_other_protocols_explicitly_reject_qoder(self):
        for path, extra in (("/v1/responses", {"input": "ping"}),
                            ("/v1/messages", {"max_tokens": 8}),
                            ("/v1/messages/count_tokens", {})):
            with self.subTest(path=path):
                status, text, _ = self.request(path=path, body={"model": MODEL,
                    "messages": [{"role": "user", "content": "ping"}], **extra})
                self.assertEqual(status, 400, text)
                error = json.loads(text)["error"]
                self.assertIn("unsupported", json.dumps(error).lower())
                self.assert_zero_provider()

    def model_ids(self, merge=False, key=None, realm="cn"):
        path = "/v1/models?realm=" + realm + ("&merge_realms=1" if merge else "")
        status, text, _ = self.request(path=path, method="GET", key=key)
        self.assertEqual(status, 200, text)
        doc = json.loads(text)
        return {row["id"] for row in doc["data"]}

    def test_models_single_and_merged_include_allowed_qoder(self):
        for merge in (False, True):
            with self.subTest(merge=merge):
                self.assertIn(MODEL, self.model_ids(merge=merge))

    def test_models_intl_key_never_leaks_qoder_even_merged(self):
        key = self.keys(realm="intl")
        for merge in (False, True):
            with self.subTest(merge=merge):
                self.assertFalse(any(mid.startswith("qoder/") for mid in
                                     self.model_ids(merge=merge, key=key, realm="intl")))

    def test_models_hide_banned_or_key_disallowed_qoder(self):
        S.set_banned_models(self.accounts, ["qoder/other"])
        key = self.keys(models=[MODEL])
        for merge in (False, True):
            with self.subTest(merge=merge):
                ids = self.model_ids(merge=merge, key=key)
                self.assertIn(MODEL, ids)
                self.assertNotIn("qoder/other", ids)

    def test_model_ban_and_whitelist_changes_apply_next_request(self):
        key = self.keys()
        status, text, _ = self.request(key=key)
        self.assertEqual(status, 200, text)
        S.set_banned_models(self.accounts, [MODEL])
        status, text, _ = self.request(key=key, stream=True)
        self.assertEqual(status, 400, text)
        S.set_banned_models(self.accounts, [])
        self.keys(models=["trae-*"])
        status, text, _ = self.request(key=key)
        self.assertEqual(status, 400, text)
        self.assertEqual(self.complete.call_count, 1)
        self.stream.assert_not_called()

    def test_models_global_ban_hidden_without_key_whitelist(self):
        S.set_banned_models(self.accounts, ["qoder/other"])
        for merge in (False, True):
            with self.subTest(merge=merge):
                ids = self.model_ids(merge=merge)
                self.assertIn(MODEL, ids)
                self.assertNotIn("qoder/other", ids)

    def test_context_budget_blocks_before_provider_without_truncation(self):
        S.set_model_context(self.accounts, MODEL, "1K", realm="cn", max_tokens=4096)
        for stream in (False, True):
            with self.subTest(stream=stream):
                payload = {"model": MODEL, "messages": [{"role": "user", "content": "x" * 2048}],
                           "max_tokens": 8, "stream": stream}
                before = copy.deepcopy(payload)
                status, text, _ = self.request(body=payload)
                self.assertEqual(status, 400, text)
                self.assertIn("context", text.lower())
                self.assertEqual(payload, before)
                self.assert_zero_provider()

    def test_invalid_messages_rejected_before_provider(self):
        for messages in (None, [], "ping", ["ping"]):
            with self.subTest(messages=messages):
                status, text, _ = self.request(body={"model": MODEL, "messages": messages})
                self.assertEqual(status, 400, text)
                self.assert_zero_provider()

    def test_unknown_or_unavailable_model_has_no_trae_fallback(self):
        status, text, _ = self.request(model="qoder/unknown")
        self.assertEqual(status, 400, text)
        for flag in ("enabled", "available"):
            with self.subTest(flag=flag):
                self.catalog.return_value = [{**CATALOG[0], flag: False}]
                status, text, _ = self.request()
                self.assertEqual(status, 400, text)
        self.assert_zero_provider()

    def test_provider_runtime_error_is_http_error_and_accounted(self):
        self.complete.side_effect = RuntimeError("fixture secret must not escape")
        status, text, _ = self.request(key=self.keys())
        self.assertEqual(status, 502, text)
        self.assertNotIn("fixture secret", text)
        rows = self.rows()
        self.assertEqual(len(rows), 1, rows)
        self.assert_accounting(rows[0], error=True)
        self.assertEqual(P._usage["requests"], 0)

    def test_models_disabled_provider_not_listed(self):
        with mock.patch.dict(os.environ, {"QODER_DISABLE": "1"}):
            for merge in (False, True):
                with self.subTest(merge=merge):
                    self.assertFalse(any(mid.startswith("qoder/") for mid in self.model_ids(merge)))
        self.catalog.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
