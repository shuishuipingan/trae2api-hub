"""Qoder adapter regression suite: synthetic env, temp desktop fixtures, no network.

Run: python -B -m unittest -v test_qoder_adapter
"""
import base64
import builtins
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

import trae_qoder as q


CRED = {"token": "fixture-secret-token", "userID": "fixture-user", "machineID": "fixture-machine"}
ENV = {"QODER_CN_TOKEN": CRED["token"], "QODER_CN_UID": CRED["userID"],
       "QODER_CN_MACHINE_ID": CRED["machineID"]}
SECRET = "PRIVATE_TOKEN_AND_RAW_BODY"


def choice(delta=None, finish=None):
    return {"choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish}]}


def frame(value, wrapped=False):
    if wrapped:
        value = {"body": json.dumps(value)}
    return ("data: " + json.dumps(value) + "\n\n").encode()


def tool(index=0, ident=None, name=None, arguments=None):
    item = {"index": index, "function": {}}
    if ident is not None:
        item["id"] = ident
    if name is not None:
        item["function"]["name"] = name
    if arguments is not None:
        item["function"]["arguments"] = arguments
    return item


class Response(io.BytesIO):
    def __init__(self, data=b"", content_type="text/event-stream", fail_read=False, fail_close=False):
        super().__init__(data)
        self.headers = {"Content-Type": content_type}
        self.read_sizes = []
        self.line_sizes = []
        self.close_count = 0
        self.fail_read = fail_read
        self.fail_close = fail_close

    def read(self, size=-1):
        self.read_sizes.append(size)
        if self.fail_read:
            raise OSError(SECRET)
        if size < 0:
            raise AssertionError("unbounded read")
        return super().read(size)

    def readline(self, size=-1):
        self.line_sizes.append(size)
        if self.fail_read:
            raise OSError(SECRET)
        if size < 0:
            raise AssertionError("unbounded readline")
        return super().readline(size)

    def close(self):
        self.close_count += 1
        super().close()
        if self.fail_close:
            raise OSError(SECRET)


class IsolatedCase(unittest.TestCase):
    def setUp(self):
        self.env = self.enterContext(patch.dict(os.environ, {}, clear=True))
        self.enterContext(patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")))
        self.enterContext(patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("network forbidden")))
        self.forbid_open = self.enterContext(patch("builtins.open", side_effect=AssertionError("personal reads forbidden")))
        self.enterContext(patch.object(q.os.path, "expanduser", side_effect=AssertionError("personal path forbidden")))
        q.invalidate_models()
        self.addCleanup(q.invalidate_models)

    def assert_qerror(self, action, kind=None, status=None):
        with self.assertRaises(q.QoderError) as caught:
            action()
        error = caught.exception
        self.assertNotIn(SECRET, str(error))
        self.assertNotIn(CRED["token"], str(error))
        if kind:
            self.assertEqual(error.kind, kind)
        if status:
            self.assertEqual(error.status, status)
        return error

    def stream(self, response):
        with patch.object(q, "load_credential", return_value=dict(CRED)), patch.object(q, "_open", return_value=response):
            return list(q.stream_chat("fixture-model", []))

    def complete(self, chunks):
        with patch.object(q, "stream_chat", return_value=iter(chunks)):
            return q.complete_chat("fixture-model", [])


class CredentialTests(IsolatedCase):
    def test_default_does_not_read_desktop(self):
        self.assert_qerror(q.load_credential, "no_credential", 401)
        self.forbid_open.assert_not_called()
        self.assertFalse(q.credential_available())

    def test_only_exact_optin_is_accepted(self):
        for value in ("true", "yes", "0", " 1", ""):
            with self.subTest(value=value), patch.dict(os.environ, {"QODER_DESKTOP_IMPORT": value}, clear=True):
                self.assert_qerror(q.load_credential, "no_credential")
        self.forbid_open.assert_not_called()

    def test_complete_env_precedes_desktop(self):
        with patch.dict(os.environ, dict(ENV, QODER_DESKTOP_IMPORT="1")), patch.object(q, "_master_key") as key:
            cred = q.load_credential()
            self.assertEqual({k: cred[k] for k in CRED}, CRED)
            self.assertEqual(cred["source"], "env")
            key.assert_not_called()
        self.forbid_open.assert_not_called()

    def test_all_partial_or_blank_env_combinations_never_fallback(self):
        keys = list(ENV)
        for mask in range(1, 8):
            values = {k: ENV[k] for i, k in enumerate(keys) if mask & (1 << i)}
            if mask == 7:
                values[keys[0]] = " "
            values["QODER_DESKTOP_IMPORT"] = "1"
            with self.subTest(mask=mask), patch.dict(os.environ, values, clear=True), patch.object(q, "_master_key") as key:
                self.assert_qerror(q.load_credential, "no_credential")
                key.assert_not_called()
        for key in keys:
            with patch.dict(os.environ, {key: "", "QODER_DESKTOP_IMPORT": "1"}, clear=True):
                self.assert_qerror(q.load_credential, "no_credential")
        self.forbid_open.assert_not_called()

    def test_env_strips_required_values(self):
        with patch.dict(os.environ, {k: " " + v + " " for k, v in ENV.items()}):
            cred = q.load_credential()
        self.assertEqual({k: cred[k] for k in CRED}, CRED)

    def test_nonwindows_optin_gives_env_diagnostic_without_reads(self):
        with patch.dict(os.environ, {"QODER_DESKTOP_IMPORT": "1"}), patch.object(q.sys, "platform", "linux"):
            error = self.assert_qerror(q.load_credential, "no_credential")
            self.assertIn("QODER_CN_MACHINE_ID", str(error))
        self.forbid_open.assert_not_called()

    def test_desktop_import_only_uses_temp_fixtures(self):
        # Opening is allowed only for the exact paths created below, never personal paths.
        real_open = io.open
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as directory:
            root = Path(directory)
            state = root / "Local State"
            auth = root / "auth.v1.dat"
            umid = root / "umid.json"
            state.write_text(json.dumps({"os_crypt": {"encrypted_key": base64.b64encode(b"DPAPIfake").decode()}}))
            auth.write_bytes(b"v10" + b"x" * 28)
            umid.write_text(json.dumps({"info": {"machineCode": CRED["machineID"]}}))
            def only_temp(path, *args, **kwargs):
                self.assertIn(Path(path), (state, auth, umid))
                self.assertNotIn("w", args[0] if args else "r")
                return real_open(path, *args, **kwargs)
            env = {"QODER_DESKTOP_IMPORT": "1", "QODER_CN_DATA_DIR": directory, "QODER_CN_UMID_CACHE": str(umid)}
            payload = json.dumps({"user": {"id": CRED["userID"]}, "token": CRED["token"]}).encode()
            with patch.dict(os.environ, env, clear=True), patch.object(q.sys, "platform", "win32"), patch("builtins.open", side_effect=only_temp), patch.object(q, "_dpapi_unprotect", return_value=b"key") as dpapi, patch.object(q, "_aes_gcm_decrypt", return_value=payload):
                cred = q.load_credential()
                self.assertEqual({k: cred[k] for k in CRED}, CRED)
                self.assertEqual(cred["source"], "desktop")
                dpapi.assert_called_once_with(b"fake")

    def test_desktop_errors_are_sanitized(self):
        with patch.dict(os.environ, {"QODER_DESKTOP_IMPORT": "1"}), patch.object(q.sys, "platform", "win32"), patch.object(q, "_master_key", side_effect=OSError(SECRET)):
            self.assert_qerror(q.load_credential, "credential_import", 401)

    def test_optional_gcm_dependency_diagnostic(self):
        with patch.dict(sys.modules, {"Crypto": None, "Crypto.Cipher": None}):
            error = self.assert_qerror(lambda: q._aes_gcm_decrypt(b"key", b"v10"), "credential_dependency", 503)
            self.assertIn("pycryptodome", str(error))
            self.assertIn("QODER_CN_UID", str(error))

    def test_gcm_validation_uses_mocked_crypto_only(self):
        cipher = Mock()
        cipher.decrypt_and_verify.return_value = b"fixture"
        aes = Mock(MODE_GCM=11)
        aes.new.return_value = cipher
        crypto = Mock(AES=aes)
        with patch.dict(sys.modules, {"Crypto": Mock(), "Crypto.Cipher": crypto}):
            self.assertEqual(q._aes_gcm_decrypt(b"k" * 32, b"v10" + b"n" * 12 + b"ct" + b"t" * 16), b"fixture")
            aes.new.assert_called_once_with(b"k" * 32, 11, nonce=b"n" * 12, mac_len=16)
            cipher.decrypt_and_verify.assert_called_once_with(b"ct", b"t" * 16)
            with self.assertRaises(ValueError):
                q._aes_gcm_decrypt(b"k", b"bad")


class TransportTests(IsolatedCase):
    def test_http_error_body_not_read_and_response_closed(self):
        raw = Response(SECRET.encode(), "text/plain")
        error = urllib.error.HTTPError("https://HOST/" + SECRET, 401, SECRET, {}, raw)
        with patch.object(q, "auth_headers", return_value={}), patch("urllib.request.build_opener", return_value=Mock(open=Mock(side_effect=error))):
            self.assert_qerror(lambda: q._open("https://HOST/", CRED), "upstream_http", 401)
        self.assertEqual(raw.read_sizes, [])
        self.assertTrue(raw.closed)

    def test_network_error_reason_not_exposed(self):
        for error in (urllib.error.URLError(SECRET), TimeoutError(SECRET), OSError(SECRET)):
            with self.subTest(error=type(error).__name__), patch.object(q, "auth_headers", return_value={}), patch("urllib.request.build_opener", return_value=Mock(open=Mock(side_effect=error))):
                self.assert_qerror(lambda: q._open("https://HOST/", CRED), "network", 502)

    def test_no_redirect_handler_rejects_every_3xx_and_closes_without_read(self):
        handler = q._NoRedirect()
        for status in range(300, 400):
            with self.subTest(status=status):
                response = Response(SECRET.encode())
                response.code = status
                response.headers["Location"] = "https://OTHER_HOST/" + SECRET
                self.assert_qerror(lambda: handler.https_response(Mock(), response), "upstream_redirect", 502)
                self.assertTrue(response.closed)
                self.assertEqual(response.read_sizes, [])

    def test_redirect_request_never_constructs_forwarded_request(self):
        handler = q._NoRedirect()
        request = urllib.request.Request("https://HOST/", headers={"Authorization": SECRET, "Cosy-User": SECRET})
        for destination in ("https://OTHER_HOST/", "https://HOST/next", "http://HOST/"):
            response = Response(SECRET.encode())
            self.assert_qerror(lambda: handler.redirect_request(request, response, 302, SECRET, {"Location": destination}, destination), "upstream_redirect")
            self.assertTrue(response.closed)
            self.assertEqual(response.read_sizes, [])

    def test_open_uses_private_no_redirect_opener_and_preserves_timeout(self):
        response = Response()
        opener = Mock(open=Mock(return_value=response))
        with patch.object(q, "auth_headers", return_value={"Authorization": SECRET}), patch("urllib.request.build_opener", return_value=opener) as build:
            self.assertIs(q._open("https://HOST/", CRED, timeout=7), response)
        self.assertIsInstance(build.call_args.args[0], q._NoRedirect)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 7)
        self.assertEqual(opener.open.call_count, 1)
        response.close()

    def test_redirect_httperror_is_fixed_and_closed(self):
        response = Response(SECRET.encode())
        error = urllib.error.HTTPError("https://HOST/", 302, SECRET, {"Location": "https://OTHER_HOST/"}, response)
        with patch.object(q, "auth_headers", return_value={}), patch("urllib.request.build_opener", return_value=Mock(open=Mock(side_effect=error))):
            self.assert_qerror(lambda: q._open("https://HOST/", CRED), "upstream_redirect", 502)
        self.assertTrue(response.closed)
        self.assertEqual(response.read_sizes, [])

    def test_control_char_credentials_rejected_before_signing(self):
        for key in (*CRED, "name", "email"):
            for control in ("\r", "\n", "\x00"):
                with self.subTest(key=key, control=repr(control)), patch.object(q, "auth_headers") as sign:
                    cred = dict(CRED, **{key: "fixture" + control + SECRET})
                    self.assert_qerror(lambda: q._open("https://HOST/", cred), "no_credential", 401)
                    sign.assert_not_called()

    def test_open_rejects_incomplete_credential_before_signing(self):
        with patch.object(q, "auth_headers") as sign:
            self.assert_qerror(lambda: q._open("https://HOST/", {"token": CRED["token"]}), "no_credential")
            sign.assert_not_called()

    def test_bounded_read_rejects_oversize(self):
        response = Response(b"x" * 17)
        with patch.object(q, "MAX_RESPONSE_BYTES", 16):
            self.assert_qerror(lambda: q._read_limited(response), "protocol_shape")
        self.assertEqual(response.read_sizes, [17])
        response.close()


class StreamTests(IsolatedCase):
    def test_wrapped_content_reasoning_usage_and_finish(self):
        response = Response(frame(choice({"role": "assistant"}), True) + frame(choice({"content": "ok", "reasoning_content": "why"}), True) + frame(choice(finish="stop"), True) + frame({"choices": [], "usage": {"total_tokens": 3}}) + b"data: [DONE]\n\n")
        chunks = self.stream(response)
        self.assertEqual(chunks[1]["choices"][0]["delta"]["content"], "ok")
        self.assertEqual(chunks[-1]["choices"][0]["finish_reason"], "stop")
        self.assertEqual(chunks[-1]["usage"]["total_tokens"], 3)
        self.assertTrue(response.closed)
        self.assertTrue(all(size == q.MAX_SSE_EVENT_BYTES + 1 for size in response.line_sizes))

    def test_explicit_finish_is_a_legal_terminator(self):
        response = Response(frame(choice({"content": "partial"}, "length")))
        self.assertEqual(self.stream(response)[-1]["choices"][0]["finish_reason"], "length")
        self.assertTrue(response.closed)

    def test_done_after_valid_choice_is_a_legal_terminator(self):
        response = Response(frame(choice({"content": "ok"})) + b"data: [DONE]\n\n")
        self.assertEqual(self.stream(response)[-1]["choices"][0]["finish_reason"], "stop")

    def test_empty_comment_and_done_only_are_errors(self):
        for data in (b"", b": ping\n\n", b"data: [DONE]\n\n", frame({"choices": [], "usage": {}})):
            with self.subTest(data=data):
                response = Response(data)
                self.assert_qerror(lambda: self.stream(response), "empty_stream")
                self.assertTrue(response.closed)

    def test_role_only_done_is_not_a_successful_answer(self):
        response = Response(frame(choice({"role": "assistant"})) + b"data: [DONE]\n\n")
        self.assert_qerror(lambda: self.stream(response), "empty_stream")
        self.assertTrue(response.closed)

    def test_plain_eof_never_fabricates_stop(self):
        response = Response(frame(choice({"content": "partial"})))
        self.assert_qerror(lambda: self.stream(response), "incomplete_stream")
        self.assertTrue(response.closed)

    def test_invalid_json_inner_and_nonobject_frames_fail(self):
        for data in (b"data: not-json\n\n", b"data: []\n\n", b"data: null\n\n", frame({"body": SECRET}), frame({"body": []}), frame({"body": "null"}), frame({}), b"data: {\"n\":NaN}\n\n", b"data: \xff\n\n", b"garbage\n\n"):
            with self.subTest(data=data):
                response = Response(data)
                self.assert_qerror(lambda: self.stream(response), "protocol_shape")
                self.assertTrue(response.closed)

    def test_unterminated_event_fails_even_with_finish_inside(self):
        response = Response(frame(choice(finish="stop")).rstrip(b"\n"))
        self.assert_qerror(lambda: self.stream(response), "incomplete_stream")
        self.assertTrue(response.closed)

    def test_multiline_data_and_comments(self):
        response = Response(b': heartbeat\r\nevent: message\r\nid: 1\r\ndata: {"choices":\r\ndata: [{"delta":{"content":"ok"},"finish_reason":"stop"}]}\r\n\r\n')
        self.assertEqual(self.stream(response)[0]["choices"][0]["delta"]["content"], "ok")

    def test_wrong_content_type_not_read_or_leaked(self):
        for content_type in ("application/json", "text/html", "", "text/plain"):
            with self.subTest(content_type=content_type):
                response = Response(SECRET.encode(), content_type)
                self.assert_qerror(lambda: self.stream(response), "protocol_shape")
                self.assertEqual(response.read_sizes, [])
                self.assertTrue(response.closed)

    def test_outer_and_nested_provider_errors_are_sanitized(self):
        errors = [{"code": 1210, "message": SECRET}, {"error": {"message": SECRET}}, {"details": json.dumps({"error": {"message": SECRET, "code": "secret"}})}, {"code": 401, "message": SECRET, "body": json.dumps(choice(finish="stop"))}, {"success": False, "message": SECRET}]
        for error in errors:
            with self.subTest(error=error):
                response = Response(frame(error))
                self.assert_qerror(lambda: self.stream(response), "provider_error")
                self.assertTrue(response.closed)

    def test_shape_drift_and_invalid_delta_fail(self):
        bad = [{"choices": "bad"}, {"choices": [None]}, {"choices": [{"delta": "bad"}]}, choice({"content": 8}), choice({"tool_calls": {}}), choice(finish="new-status"), {"choices": [{"index": 1, "delta": {}}]}, {"choices": [], "usage": []}]
        for payload in bad:
            with self.subTest(payload=payload):
                response = Response(frame(payload))
                self.assert_qerror(lambda: self.stream(response), "protocol_shape")
                self.assertTrue(response.closed)

    def test_event_and_line_sizes_are_bounded(self):
        for data in (b"data: " + b"x" * 100 + b"\n\n", b": " + b"x" * 20 + b"\n" + b": " + b"x" * 20 + b"\n\n"):
            response = Response(data)
            with patch.object(q, "MAX_SSE_EVENT_BYTES", 32):
                self.assert_qerror(lambda: self.stream(response), "protocol_shape")
            self.assertTrue(response.closed)

    def test_read_failure_is_sanitized_and_closed(self):
        response = Response(fail_read=True)
        self.assert_qerror(lambda: self.stream(response), "network")
        self.assertTrue(response.closed)

    def test_caller_cancellation_closes_response(self):
        response = Response(frame(choice({"content": "first"})) + frame(choice(finish="stop")))
        with patch.object(q, "load_credential", return_value=CRED), patch.object(q, "_open", return_value=response):
            generator = q.stream_chat("fixture-model", [])
            next(generator)
            generator.close()
        self.assertTrue(response.closed)

    def test_close_error_does_not_mask_completion(self):
        response = Response(frame(choice(finish="stop")), fail_close=True)
        self.assertEqual(self.stream(response)[-1]["choices"][0]["finish_reason"], "stop")

    def test_delta_after_finish_is_not_success(self):
        response = Response(frame(choice(finish="stop")) + frame(choice({"content": SECRET})))
        self.assert_qerror(lambda: self.stream(response), "protocol_shape")
        self.assertTrue(response.closed)

    def test_stream_invalid_tool_fragments_never_emit_success_tail(self):
        for fragment in (None, {}, {"index": -1}, {"index": True}, {"index": 0, "function": []}, {"index": 0, "id": 7}):
            with self.subTest(fragment=fragment):
                response = Response(frame(choice({"tool_calls": [fragment]}, "tool_calls")))
                emitted = []
                with patch.object(q, "load_credential", return_value=CRED), patch.object(q, "_open", return_value=response):
                    def consume():
                        for chunk in q.stream_chat("fixture-model", []):
                            emitted.append(chunk)
                    self.assert_qerror(consume, "protocol_shape")
                self.assertFalse(any(item["choices"][0]["finish_reason"] is not None for item in emitted))
                self.assertTrue(response.closed)

    def test_stream_tool_finish_requires_complete_object_and_identity(self):
        invalid = [tool(0, "id", "f", "{"), tool(0, "id", "f", "[]"), tool(0, "", "f", "{}"), tool(0, "id", "", "{}")]
        for call in invalid:
            with self.subTest(call=call):
                response = Response(frame(choice({"tool_calls": [call]}, "tool_calls")))
                self.assert_qerror(lambda: self.stream(response), "protocol_shape")
                self.assertTrue(response.closed)

    def test_stream_tool_finish_requires_at_least_one_call(self):
        for delta in ({}, {"tool_calls": []}):
            with self.subTest(delta=delta):
                response = Response(frame(choice(delta, "tool_calls")))
                self.assert_qerror(lambda: self.stream(response), "protocol_shape")
                self.assertTrue(response.closed)

    def test_stream_tools_cannot_finish_as_stop_or_done_synthesized_stop(self):
        for suffix in (frame(choice(finish="stop")), b"data: [DONE]\n\n"):
            with self.subTest(suffix=suffix):
                response = Response(frame(choice({"tool_calls": [tool(0, "id", "f", "{}")]})) + suffix)
                self.assert_qerror(lambda: self.stream(response), "protocol_shape")
                self.assertTrue(response.closed)

    def test_stream_truncated_tools_preserve_actual_finish(self):
        for reason in ("length", "content_filter"):
            with self.subTest(reason=reason):
                response = Response(frame(choice({"tool_calls": [tool(0, "id", "f", "{")]}, reason)))
                chunks = self.stream(response)
                self.assertEqual(chunks[-1]["choices"][0]["finish_reason"], reason)
                self.assertTrue(all(item["choices"][0]["finish_reason"] != "tool_calls" for item in chunks))
                self.assertTrue(response.closed)

    def test_stream_valid_interleaved_tool_fragments_are_preserved(self):
        first = {"tool_calls": [tool(1, "call_", "sec", '{"b":'), tool(0, "id_", "fir", '{"a":')]}
        second = {"tool_calls": [tool(0, "zero", "st", '1}'), tool(1, "one", "ond", '2}')]}
        response = Response(frame(choice(first)) + frame(choice(second, "tool_calls")) + b"data: [DONE]\n\n")
        chunks = self.stream(response)
        self.assertEqual(chunks[0]["choices"][0]["delta"], first)
        self.assertEqual(chunks[1]["choices"][0]["delta"], second)
        self.assertEqual(chunks[-1]["choices"][0]["finish_reason"], "tool_calls")
        self.assertTrue(response.closed)


class ToolCompletionTests(IsolatedCase):
    def test_interleaved_tools_aggregate_index_id_name_arguments(self):
        chunks = [choice({"tool_calls": [tool(2, "call_", "sec", '{"b":'), tool(0, "id_", "fir", '{"a":')]}), choice({"content": "before", "reasoning_content": "think", "tool_calls": [tool(0, "zero", "st", '1}'), tool(2, "two", "ond", '2}')]}), dict(choice(finish="tool_calls"), usage={"total_tokens": 9})]
        result = self.complete(chunks)
        answer = result["choices"][0]
        self.assertEqual(answer["finish_reason"], "tool_calls")
        self.assertEqual(answer["message"]["content"], "before")
        self.assertEqual(answer["message"]["reasoning_content"], "think")
        self.assertEqual(answer["message"]["tool_calls"], [{"id": "id_zero", "type": "function", "function": {"name": "first", "arguments": '{"a":1}'}}, {"id": "call_two", "type": "function", "function": {"name": "second", "arguments": '{"b":2}'}}])
        self.assertEqual(result["usage"]["total_tokens"], 9)

    def test_tools_only_content_is_null(self):
        answer = self.complete([choice({"tool_calls": [tool(0, "id", "f", "{}")]}, "tool_calls")])["choices"][0]
        self.assertIsNone(answer["message"]["content"])

    def test_arguments_must_be_one_complete_json_object(self):
        for args in ('{"a":', '{} trailing', '{}{}', '[]', 'null', '1', '"text"', '{"a":NaN}', ''):
            with self.subTest(args=args):
                self.assert_qerror(lambda: self.complete([choice({"tool_calls": [tool(0, "id", "f", args)]}, "tool_calls")]), "protocol_shape")

    def test_missing_id_name_duplicate_id_and_missing_calls_fail(self):
        for tools in ([], [tool(0, "", "f", "{}")], [tool(0, "id", "", "{}")], [tool(0, "id", "f", "{}"), tool(1, "id", "g", "{}")]):
            with self.subTest(tools=tools):
                self.assert_qerror(lambda: self.complete([choice({"tool_calls": tools}, "tool_calls")]), "protocol_shape")

    def test_invalid_tool_fragment_shapes_fail(self):
        fragments = [None, {}, {"index": -1}, {"index": True}, {"index": "0"}, {"index": 0, "id": 3}, {"index": 0, "function": []}, {"index": 0, "function": {"arguments": {}}}, {"index": 0, "type": "other"}]
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                self.assert_qerror(lambda: self.complete([choice({"tool_calls": [fragment]}, "tool_calls")]), "protocol_shape")

    def test_length_or_filtered_preserves_finish_without_executable_calls(self):
        for reason in ("length", "content_filter"):
            for args in ('{"unfinished":', '{}'):
                with self.subTest(reason=reason, args=args):
                    answer = self.complete([choice({"content": "partial", "tool_calls": [tool(0, "id", "f", args)]}, reason)])["choices"][0]
                    self.assertEqual(answer["finish_reason"], reason)
                    self.assertNotIn("tool_calls", answer["message"])
                    self.assertEqual(answer["message"]["content"], "partial")

    def test_stop_with_tools_does_not_forge_executable_finish(self):
        self.assert_qerror(lambda: self.complete([choice({"tool_calls": [tool(0, "id", "f", "{}")]}, "stop")]), "protocol_shape")

    def test_empty_aggregator_does_not_forge_stop(self):
        self.assert_qerror(lambda: self.complete([]), "incomplete_stream")

    def test_aggregation_failure_closes_upstream_generator(self):
        closed = []
        def chunks():
            try:
                yield choice({"tool_calls": [{"index": -1}]})
                yield choice(finish="stop")
            finally:
                closed.append(True)
        with patch.object(q, "stream_chat", return_value=chunks()):
            self.assert_qerror(lambda: q.complete_chat("fixture-model", []), "protocol_shape")
        self.assertEqual(closed, [True])

    def test_full_mock_transport_to_nonstream_tool_result(self):
        response = Response(frame(choice({"tool_calls": [tool(0, "id", "f", '{"a":')] }), True) + frame(choice({"tool_calls": [tool(0, arguments='1}')]}, "tool_calls"), True) + b"data: [DONE]\n\n")
        with patch.object(q, "load_credential", return_value=CRED), patch.object(q, "_open", return_value=response):
            answer = q.complete_chat("fixture-model", [])["choices"][0]
        self.assertEqual(answer["message"]["tool_calls"][0]["function"]["arguments"], '{"a":1}')
        self.assertTrue(response.closed)


class ModelCacheTests(IsolatedCase):
    def models_response(self, key="fixture-model", enabled=True):
        return Response(json.dumps({"chat": [{"key": key, "enable": enabled}]}).encode(), "application/json")

    def test_same_credential_cached_and_defensive_copied(self):
        response = self.models_response()
        with patch.object(q, "_open", return_value=response) as opening:
            first = q.model_list(CRED)
            first[0]["key"] = "mutated"
            first[0]["thinking"]["supported"] = "mutated"
            second = q.model_list(CRED)
            self.assertEqual(second[0]["key"], "fixture-model")
            self.assertIsNone(second[0]["thinking"]["supported"])
            opening.assert_called_once()
        self.assertTrue(response.closed)

    def test_token_uid_and_machine_each_isolate_cache(self):
        identities = [dict(CRED)] + [dict(CRED, **{key: value + "-other"}) for key, value in CRED.items()]
        responses = [self.models_response(str(i)) for i in range(len(identities))]
        with patch.object(q, "_open", side_effect=responses) as opening:
            for i, cred in enumerate(identities):
                self.assertEqual(q.model_list(cred)[0]["key"], str(i))
            self.assertEqual(q.model_list(CRED)[0]["key"], "0")
            self.assertEqual(opening.call_count, 4)
        self.assertNotIn(CRED["token"], repr(q._MODEL_CACHE))
        self.assertTrue(all(len(key) == 64 for key in q._MODEL_CACHE))

    def test_failed_other_identity_never_uses_warm_cache(self):
        with patch.object(q, "_open", return_value=self.models_response("account-a")):
            q.model_list(CRED)
        other = dict(CRED, token="other-token")
        with patch.object(q, "_open", side_effect=q.QoderError("Qoder 网络连接失败", kind="network")):
            self.assert_qerror(lambda: q.model_list(other), "network")
        self.assertNotIn(q._credential_fingerprint(other), q._MODEL_CACHE)
        self.assertEqual(len(q._MODEL_CACHE), 1)

    def test_missing_identity_never_receives_warm_cache(self):
        with patch.object(q, "_open", return_value=self.models_response()):
            q.model_list(CRED)
        self.assert_qerror(q.model_list, "no_credential")
        self.assert_qerror(lambda: q.model_list({}), "no_credential")

    def test_expiry_refresh_and_invalidate(self):
        with patch.object(q.time, "monotonic", return_value=0), patch.object(q, "_open", return_value=self.models_response("old")):
            q.model_list(CRED)
        with patch.object(q.time, "monotonic", return_value=q.MODEL_CACHE_TTL + 1), patch.object(q, "_open", return_value=self.models_response("new")):
            self.assertEqual(q.model_list(CRED)[0]["key"], "new")
        with patch.object(q, "_open", return_value=self.models_response("refresh")):
            self.assertEqual(q.model_list(CRED, refresh=True)[0]["key"], "refresh")
        q.invalidate_models()
        self.assertEqual(q._MODEL_CACHE, {})

    def test_failed_refresh_does_not_replace_cache(self):
        with patch.object(q, "_open", return_value=self.models_response("account-a")):
            q.model_list(CRED)
        with patch.object(q, "_open", return_value=Response(SECRET.encode(), "application/json")):
            self.assert_qerror(lambda: q.model_list(CRED, refresh=True), "protocol_shape")
        self.assertEqual(q.model_list(CRED)[0]["key"], "account-a")

    def test_model_shapes_errors_read_failure_and_oversize_close(self):
        payloads = [(b"[]", "protocol_shape"), (b"{}", "protocol_shape"), (SECRET.encode(), "protocol_shape"), (json.dumps({"code": 401, "message": SECRET}).encode(), "provider_error")]
        for raw, kind in payloads:
            response = Response(raw, "application/json")
            with self.subTest(raw=raw), patch.object(q, "_open", return_value=response):
                self.assert_qerror(lambda: q.model_list(CRED), kind)
                self.assertTrue(response.closed)
                self.assertEqual(response.read_sizes, [q.MAX_RESPONSE_BYTES + 1])
        response = Response(fail_read=True)
        with patch.object(q, "_open", return_value=response):
            self.assert_qerror(lambda: q.model_list(CRED), "network")
        self.assertTrue(response.closed)
        response = Response(b"x" * 50)
        with patch.object(q, "MAX_RESPONSE_BYTES", 32), patch.object(q, "_open", return_value=response):
            self.assert_qerror(lambda: q.model_list(CRED), "protocol_shape")
        self.assertTrue(response.closed)

    def test_disabled_model_is_retained_for_proxy_policy(self):
        with patch.object(q, "_open", return_value=self.models_response(enabled=False)):
            rows = q.model_list(CRED)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["enabled"])
        self.assertFalse(rows[0]["available"])

    def test_invalidated_inflight_response_cannot_repopulate_cache(self):
        def opening(*_args, **_kwargs):
            q.invalidate_models()
            return self.models_response()
        with patch.object(q, "_open", side_effect=opening):
            self.assertEqual(len(q.model_list(CRED)), 1)
        self.assertEqual(q._MODEL_CACHE, {})

    def test_cache_entry_limit(self):
        with patch.object(q, "_open", side_effect=lambda *_args, **_kwargs: self.models_response()):
            for index in range(35):
                q.model_list(dict(CRED, token="token-" + str(index)))
        self.assertLessEqual(len(q._MODEL_CACHE), 32)


class ProtocolRegressionTests(IsolatedCase):
    def test_thinking_constraints_and_tools_request_are_preserved(self):
        tools = [{"type": "function", "function": {"name": "fixture", "parameters": {"type": "object"}}}]
        body = q.build_chat_body("gmodel", [{"role": "user", "content": "fixture"}], {"tools": tools})
        self.assertEqual(body["tools"], tools)
        self.assertNotIn("enable_thinking", body["parameters"])
        self.assertNotIn("business", body)
        self.assertEqual(q._parameters("ordinary", {})["enable_thinking"], False)
        self.assertEqual(q._parameters("gmodel", {"enable_thinking": True, "reasoning_effort": "high"}), {"enable_thinking": True, "reasoning_effort": "high"})

    def test_encode_and_sign_helpers_remain_offline(self):
        encoded = q.encode_body(b"fixture")
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(q.signature_path("https://HOST/algo/api/v2/test?Encode=1"), "/api/v2/test")
        with patch.object(q, "_aes_cbc_base64", return_value="cipher"), patch.object(q, "rsa_encrypt_pkcs1v15", return_value="wrapped"):
            headers = q.auth_headers(encoded, "https://HOST/algo/api/v2/test", CRED)
        self.assertTrue(headers["Authorization"].startswith("Bearer COSY."))
        self.assertEqual(headers["Cosy-Bodylength"], str(len(encoded)))
        self.assertEqual(headers["Cosy-Machineid"], CRED["machineID"])


if __name__ == "__main__":
    unittest.main()
