# -*- coding: utf-8 -*-
"""SOLO usage on the wire: real gateway and parser, synthetic provider SSE."""
import json
import unittest
from unittest.mock import patch

import trae_proxy as P
import test_issue_solo_groups as fixture


class SoloStreamUsage(unittest.TestCase):
    def setUp(self):
        # Reuse the real loopback server and capture only the transport boundary.
        self.http = fixture.SoloHTTP("runTest")
        self.addCleanup(self.http.doCleanups)
        self.http.setUp()

    def wire(self, path, model):
        status, body = self.http.post(path, model, stream=True)
        self.assertEqual(status, 200, body)
        data = [line.removeprefix("data: ") for line in body.splitlines()
                if line.startswith("data: ")]
        self.assertEqual(data[-1], "[DONE]")
        return [json.loads(item) for item in data[:-1]]

    def test_usage_is_final_chunk_with_same_identity_and_nonstream_totals(self):
        for path in ("/v1/chat/completions", "/v1/agent/chat"):
            for model, key, group in (("glm-5.3", "glm-5.3", fixture.WORK),
                                      ("Seed-Code", fixture.SEED, fixture.AGENT)):
                with self.subTest(path=path, model=model):
                    status, body = self.http.post(path, model)
                    self.assertEqual(status, 200, body)
                    delta, finish, usage = self.wire(path, model)
                    self.http.assert_request(key, group)
                    self.assertEqual(usage["choices"], [])
                    self.assertEqual(usage["usage"], fixture.USAGE)
                    self.assertEqual(usage["usage"], json.loads(body)["usage"])
                    self.assertEqual(finish["choices"][0]["finish_reason"], "stop")
                    for field in ("id", "object", "model", "created"):
                        self.assertEqual(delta[field], finish[field])
                        self.assertEqual(finish[field], usage[field])

    def test_missing_usage_does_not_create_a_synthetic_frame(self):
        self.http.frames = (b'data:{"response":"fixture","finish_reason":"stop"}\n'
                            b'data:[DONE]\n')
        frames = self.wire("/v1/agent/chat", "Seed-Code")
        self.assertEqual(len(frames), 2)
        self.assertTrue(all("usage" not in frame for frame in frames))
        self.assertEqual(frames[-1]["choices"][0]["finish_reason"], "stop")

    def test_explicit_zero_upstream_counts_are_not_treated_as_missing(self):
        self.http.frames = (
            b'data:{"response":"fixture","finish_reason":"stop","prompt_tokens":0,'
            b'"completion_tokens":0,"total_tokens":0}\n'
            b'data:[DONE]\n'
        )
        usage = self.wire("/v1/chat/completions", "Seed-Code")[-1]
        self.assertEqual(usage["choices"], [])
        self.assertEqual(usage["usage"], {key: 0 for key in fixture.USAGE})

    def test_no_usage_objects_do_not_emit_a_tail(self):
        result = {"content": "fixture", "finish_reason": "stop", "tool_calls": []}
        for missing in (None, {}):
            with self.subTest(missing=missing), patch.object(
                    P, "trae_solo_chat", return_value={**result, "usage": missing}):
                frames = self.wire("/v1/agent/chat", "glm-5.3")
                self.assertEqual(len(frames), 2)
                self.assertTrue(all("usage" not in frame for frame in frames))


if __name__ == "__main__":
    unittest.main()
