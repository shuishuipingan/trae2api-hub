# -*- coding: utf-8 -*-
"""Verify only bounded inline SOLO image parts reach the mock transport."""
import http.client
import json
import unittest
from unittest.mock import patch

import trae_proxy as P
import test_issue_solo_groups as fixture


PNG = ("data:image/png;base64,"
       "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=")
TEXT = {"type": "text", "text": "Keep this text"}


def image(url):
    return {"type": "image_url", "image_url": {"url": url}}


class SoloImages(unittest.TestCase):
    def setUp(self):
        self.http = fixture.SoloHTTP("runTest")
        self.addCleanup(self.http.doCleanups)
        self.http.setUp()

    def post(self, content, *, role="user", path="/v1/chat/completions", model="Seed-Code", stream=False):
        conn = http.client.HTTPConnection(*self.http.server.server_address, timeout=5)
        try:
            payload = {"model": model, "stream": stream, "messages": [{"role": role, "content": content}]}
            conn.request("POST", path, json.dumps(payload), {"Content-Type": "application/json"})
            with conn.getresponse() as resp:
                return resp.status, resp.read().decode("utf-8")
        finally:
            conn.close()

    def test_image_only_and_mixed_messages_reach_the_actual_solo_request(self):
        for path, model, group in (("/v1/chat/completions", "Seed-Code", fixture.AGENT),
                                    ("/v1/agent/chat", "glm-5.3", fixture.WORK)):
            for content in ([image(PNG)], [TEXT, image(PNG), TEXT]):
                with self.subTest(path=path, parts=len(content)):
                    before = len(self.http.requests)
                    status, body = self.post(content, path=path, model=model)
                    self.assertEqual(status, 200, body)
                    self.assertEqual(len(self.http.requests), before + 1)
                    outbound = json.loads(self.http.requests[-1].data)
                    self.assertEqual(outbound["function"], group)
                    self.assertEqual(outbound["messages"], [{"role": "user", "content": content}])
                    self.assertTrue(self.http.responses[-1].closed)

    def assert_rejected(self, content, **kwargs):
        status, body = self.post(content, **kwargs)
        self.assertEqual(status, 400, body)
        self.assertEqual(json.loads(body)["error"]["type"], "invalid_request_error")
        self.assertNotIn("fixture-private-marker", body)
        self.assertEqual(self.http.requests, [])
        self.http.raw.assert_not_called()

    def test_malformed_and_remote_images_fail_before_the_upstream(self):
        cases = [image("https://example.invalid/fixture-private-marker"), image("data:image/png;base64,!!"),
                 image("data:image/png;base64,"), image("data:image/png;base64,汉字"),
                 image("data:image/svg+xml;base64,AAAA"), image(123),
                 {"type": "image_url"}, {"type": "input_image", "image_url": PNG}]
        for part in cases:
            with self.subTest(part=part):
                self.assert_rejected([TEXT, part], stream=True)
        self.assert_rejected([image(PNG)], role="assistant")

    def test_per_image_and_aggregate_decoded_byte_limits(self):
        tiny = image("data:image/png;base64,YWJj")  # size-only fixture: three bytes
        with patch.object(P, "_SOLO_IMAGE_LIMIT", 2):
            self.assert_rejected([tiny])
        with patch.object(P, "_SOLO_IMAGE_TOTAL_LIMIT", 5):
            self.assert_rejected([tiny, tiny])


if __name__ == "__main__":
    unittest.main()
