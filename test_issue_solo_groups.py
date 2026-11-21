# -*- coding: utf-8 -*-
"""Offline SOLO routing fixtures; run with python -m unittest test_issue_solo_groups."""
import http.client
from http.server import ThreadingHTTPServer
import io
import json
import os
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import trae_proxy as P


AGENT = "solo_agent_remote"
WORK = "solo_work_lite"
ENDPOINT = "https://trae-api-cn.mchost.guru/api/agent/v3/llm_utils_chat"
SEED = "Doubao-Seed-Code"
QWEN = "qwen3.8-flash"
# Fixed expectations, not computed from the production resolver or alias table.
CASES = (
    (SEED, SEED), ("Seed-Code", SEED), ("seedcode", SEED),
    ("Seed-Code-solo", SEED), ("Doubao-Seed-Code-solo", SEED),
    (QWEN, QWEN), ("Qwen3.8-Flash", QWEN), ("qwen3-8-flash", QWEN),
    ("Qwen3.8-Flash-solo", QWEN), ("qwen3.8-flash-solo", QWEN),
)
MESSAGES = [{"role": "user", "content": "hi"}]
USAGE = {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
ACCOUNT = SimpleNamespace(realm="cn", uid="fixture-uid", token="fixture-token",
                          extra={"device_id": "fixture-device", "machine_id": "fixture-machine"})
SUCCESS = (
    b'event:progress_notice\n'
    b'data:{"response":"fixture "}\n'
    b'data:{"response":"reply","finish_reason":"stop","prompt_tokens":3,'
    b'"completion_tokens":2,"total_tokens":5}\n'
    b'data:[DONE]\n'
)


class _TransportFixture:
    def setUp(self):
        self.requests = []
        self.responses = []
        self.frames = SUCCESS
        upstream = mock.patch.object(P.urllib.request, "urlopen", side_effect=self.fixture)
        self.addCleanup(upstream.stop)
        upstream.start()

    def fixture(self, request, timeout=None):
        self.requests.append(request)
        response = io.BytesIO(self.frames)
        self.responses.append(response)
        return response

    def assert_request(self, key, function):
        req = self.requests[-1]
        self.assertEqual(req.full_url, ENDPOINT)
        self.assertEqual(req.get_method(), "POST")
        body = json.loads(req.data)
        self.assertEqual((body["function"], body["model"], body["config_name"]),
                         (function, key, key))
        self.assertTrue(body["stream"])
        self.assertTrue(self.responses[-1].closed)


class SoloTransport(_TransportFixture, unittest.TestCase):
    def test_catalog_groups_and_all_work_models(self):
        self.assertEqual(P.SOLO_AGENT_ONLY, {SEED, QWEN})
        canonical = set(P.SOLO_MODEL_ALIASES.values())
        cn_agent_keys = {m["key"] for m in P.trae_catalog.all_models("cn")
                         if "solo_agent" in m.get("groups", ())}
        self.assertEqual(len(canonical), 20)
        self.assertEqual(canonical, cn_agent_keys)
        for key in canonical:
            with self.subTest(key=key):
                self.assertIn(key, P.SOLO_AGENT_MODELS)
                self.assertEqual(P.solo_function_for(key), AGENT if key in {SEED, QWEN} else WORK)
        for alias, key in CASES:
            with self.subTest(alias=alias):
                self.assertEqual(P._solo_agent_only_key(alias), key)
        for alias in ("glm-5.3", "GLM-5.3-solo", "provider/Seed-Code", "qoder/Qwen3.8-Flash"):
            with self.subTest(alias=alias):
                self.assertIsNone(P._solo_agent_only_key(alias))

    def test_real_request_and_successful_sse_parse(self):
        for alias, key in (*CASES, ("GLM-5.3", "glm-5.3"), ("glm-5.3-solo", "glm-5.3")):
            with self.subTest(alias=alias):
                result = P.trae_solo_chat(ACCOUNT, {"model": alias, "messages": MESSAGES})
                self.assert_request(key, AGENT if key in {SEED, QWEN} else WORK)
                self.assertEqual(result["model"], key)
                self.assertEqual(result["content"], "fixture reply")
                self.assertEqual(result["finish_reason"], "stop")
                self.assertEqual(result["usage"], USAGE)
        self.assertEqual(len(self.requests), len(CASES) + 2)

    def test_business_error_closes_response_and_is_reported(self):
        self.frames = b'data:{"code":4001,"message":"fixture error"}\n'
        with self.assertRaisesRegex(RuntimeError, "solo error 4001: fixture error"):
            P.trae_solo_chat(ACCOUNT, {"model": "Seed-Code", "messages": MESSAGES})
        self.assert_request(SEED, AGENT)


class SoloHTTP(_TransportFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory(prefix="solo-routing-")
        self.addCleanup(directory.cleanup)
        self.pool = mock.Mock()
        self.pool.pick.return_value = ACCOUNT
        self.raw = mock.Mock(side_effect=RuntimeError("raw fixture intentionally stopped"))
        self.qoder = mock.Mock(side_effect=AssertionError("unexpected Qoder route"))
        self.entry = {}
        config = mock.patch.multiple(P, POOL=self.pool, ACCOUNTS_DIR=directory.name,
                                     open_upstream=self.raw, record_usage=mock.Mock(),
                                     record_error=mock.Mock(), identify_key=lambda _: self.entry,
                                     auth_required=lambda: False)
        self.addCleanup(config.stop)
        config.start()
        qoder = mock.patch.object(P.Handler, "_handle_qoder_chat", self.qoder)
        self.addCleanup(qoder.stop)
        qoder.start()
        fallback = mock.patch.dict(os.environ, {"TRAE_AGENT_UI_FALLBACK": "0"})
        self.addCleanup(fallback.stop)
        fallback.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def post(self, path, model, stream=False, **fields):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            body = json.dumps({"model": model, "messages": MESSAGES, "stream": stream, **fields})
            conn.request("POST", path, body, {"Content-Type": "application/json"})
            with conn.getresponse() as response:
                return response.status, response.read().decode("utf-8")
        finally:
            conn.close()

    def test_aliases_and_versioned_endpoints_reach_same_transport(self):
        for path in ("/v1/chat/completions", "/chat/completions", "/v1/agent/chat", "/agent/chat"):
            for alias, key in CASES:
                with self.subTest(path=path, alias=alias):
                    before = len(self.requests)
                    status, body = self.post(path, alias)
                    self.assertEqual(status, 200, body)
                    result = json.loads(body)
                    self.assertEqual(result["model"], alias)
                    self.assertEqual(result["choices"][0]["message"]["content"], "fixture reply")
                    self.assertEqual(result["usage"], USAGE)
                    self.assertEqual(len(self.requests), before + 1)
                    self.assert_request(key, AGENT)
        self.raw.assert_not_called()
        self.qoder.assert_not_called()

    def test_client_stream_finishes(self):
        status, body = self.post("/v1/chat/completions", "Qwen3.8-Flash-solo", stream=True)
        self.assertEqual(status, 200, body)
        chunks = [line.removeprefix("data: ") for line in body.splitlines() if line.startswith("data: ")]
        self.assertEqual(chunks[-1], "[DONE]")
        message, finish = (json.loads(row)["choices"][0] for row in chunks[:-1])
        self.assertEqual(message["delta"]["content"], "fixture reply")
        self.assertEqual(finish["finish_reason"], "stop")
        self.assert_request(QWEN, AGENT)

    def test_other_raw_chat_aliases_are_unchanged(self):
        for model in ("glm53", "glm-5.3-solo"):
            with self.subTest(model=model):
                self.raw.reset_mock()
                status, body = self.post("/v1/chat/completions", model)
                self.assertEqual(status, 502, body)
                self.raw.assert_called_once()
                self.assertEqual(self.raw.call_args.args[0]["model"], model)
        self.assertEqual(self.requests, [])

    def test_responses_and_anthropic_keep_raw_transport(self):
        for path, payload in (("/v1/responses", {"input": "hi"}),
                              ("/v1/messages", {"max_tokens": 32})):
            with self.subTest(path=path):
                self.raw.reset_mock()
                status, body = self.post(path, SEED, **payload)
                self.assertEqual(status, 502, body)
                self.raw.assert_called_once()
                self.assertEqual(self.raw.call_args.args[0]["model"], SEED)
        self.assertEqual(self.requests, [])

    def test_banned_alias_and_canonical_model_block_all_spellings(self):
        for banned in ("Doubao-Seed-Code", "Seed-Code"):
            with mock.patch.object(P.trae_settings, "banned_models", return_value=[banned.lower()]):
                for path in ("/v1/chat/completions", "/v1/agent/chat"):
                    for model in ("Seed-Code-solo", "Doubao-Seed-Code"):
                        with self.subTest(path=path, banned=banned, model=model):
                            status, body = self.post(path, model)
                            self.assertEqual(status, 400, body)
                            self.assertIn("封禁", body)
        self.pool.pick.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_allowlist_only_matches_client_supplied_model(self):
        for permitted in ("Seed-Code", "Doubao-Seed-Code", "Seed-Code-solo"):
            self.entry["models"] = [permitted]
            status, body = self.post("/v1/chat/completions", permitted)
            self.assertEqual(status, 200, body)
            self.assert_request(SEED, AGENT)
            for model in ({"Seed-Code", "Doubao-Seed-Code", "Seed-Code-solo", QWEN} - {permitted}):
                with self.subTest(model=model, permitted=permitted):
                    status, body = self.post("/v1/agent/chat", model)
                    self.assertEqual(status, 400, body)
                    self.assertIn("模型限制不允许", body)
        self.assertEqual(len(self.requests), 3)

    def test_context_budget_keeps_requested_and_canonical_overrides(self):
        alias = "Seed-Code-solo"
        for configured in (alias, SEED):
            with self.subTest(configured=configured), mock.patch.object(
                    P.trae_settings, "model_context", return_value={configured: "1"}):
                status, body = self.post("/v1/chat/completions", alias)
                self.assertEqual(status, 400, body)
                self.assertIn("Configured local context budget exceeded", body)
        self.pool.pick.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_intl_realm_binding_stops_cn_transport(self):
        self.entry["realm"] = "intl"
        for path in ("/v1/chat/completions", "/v1/agent/chat"):
            with self.subTest(path=path):
                status, body = self.post(path, "Qwen3.8-Flash-solo")
                self.assertEqual(status, 400, body)
                self.assertIn("国内版", body)
        self.pool.pick.assert_not_called()
        self.assertEqual(self.requests, [])


class QuietHandler(P.Handler):
    def log_message(self, *args):
        pass


if __name__ == "__main__":
    unittest.main()
