"""Issue 9: explicit SaaS isolation, not enterprise protocol support. Offline only."""
import copy
import json
import os
import runpy
import sys
import tempfile
import time
import unittest
from unittest import mock

import trae_accounts as accounts
import trae_client as client


def personal():
    return {"uid": "fixture-user", "token": "fixture-access-secret",
            "refresh_token": "fixture-refresh-secret", "realm": "cn",
            "expired_at": int(time.time()) + 3600,
            "account": {"scope": "marscode", "loginScope": "trae"}}


def enterprise():
    row = personal()
    row["account"] = {"scope": "saas", "loginScope": "saas",
                      "tenant_id": "fixture-tenant",
                      "saasBootConfig": {"apiHost": "https://tenant.invalid"}}
    return row


class EnterpriseIsolationTest(unittest.TestCase):
    def assert_blocked(self, action):
        with self.assertRaises((client.UpstreamError, accounts.AccountError)) as caught:
            action()
        error = caught.exception
        self.assertEqual(error.code, "unsupported_enterprise_account")
        self.assertEqual(error.status, 400)
        self.assertEqual(getattr(error, "message", str(error)), client.ENTERPRISE_UNSUPPORTED_MESSAGE)
        self.assertNotIn("fixture-access", str(error))
        self.assertNotIn("fixture-refresh", str(error))
        self.assertNotIn("tenant.invalid", str(error))

    def test_explicit_metadata_locations(self):
        markers = [{"scope": "saas"}, {"loginScope": " SAAS "},
                   {"saasBootConfig": {"apiHost": "https://tenant.invalid"}}]
        for marker in markers:
            for key in (None, "account", "profile", "extra", "UserInfo"):
                row = marker if key is None else {key: marker}
                with self.subTest(key=key, marker=marker):
                    self.assertTrue(client.is_enterprise_account(row))
                    self.assert_blocked(lambda: client.ensure_personal_account(row))
        for wrapper in ("Data", "Result"):
            self.assertTrue(client.is_enterprise_account({wrapper: {"UserInfo": {"Scope": "saas"}}}))
            self.assertTrue(client.is_enterprise_account({wrapper: {"TenantInfoBase": {"ProductType": 102}}}))

    def test_personal_and_bare_token_are_unchanged(self):
        for row in (personal(), {"token": "opaque"}, {"account": {"scope": "personal"}},
                    {"extra": {"notes": {"scope": "saas"}}},
                    {"account": {"saasBootConfig": {}}}, {"tenant_id": "not-proof"}):
            self.assertFalse(client.is_enterprise_account(row))
            self.assertIs(client.ensure_personal_account(row), row)
        self.assertEqual(accounts.Account(personal()).realm, "cn")
        self.assertEqual(accounts.Account({"uid": "legacy", "token": "opaque", "realm": "intl"}).realm, "intl")
        self.assertEqual(client.normalize_realm("legacy-unknown"), "intl")

    def test_construction_normalisation_and_explicit_realm_block(self):
        row = enterprise()
        self.assert_blocked(lambda: accounts.Account(row))
        self.assert_blocked(lambda: accounts.normalise_import_row(row))
        self.assert_blocked(lambda: accounts.Account.from_desktop(row))
        self.assert_blocked(lambda: accounts.normalize_refresh_result(row))
        for realm in ("saas", "enterprise"):
            self.assert_blocked(lambda: client.normalize_realm(realm))
            self.assert_blocked(lambda: accounts.normalise_import_row(personal(), realm=realm))

    def test_all_client_network_entrypoints_block_without_outbound(self):
        row = enterprise()
        original = copy.deepcopy(row)
        calls = [lambda: client.open_chat(row, body={}),
                 lambda: client.refresh_account(row),
                 lambda: client._refresh_account_request(row),
                 lambda: client.request_json(row),
                 lambda: client.fetch_model_list(row),
                 lambda: client.fetch_usage(row),
                 lambda: client.fetch_activity(row),
                 lambda: client.fetch_entitlement(row),
                 lambda: client.checkin_status(row),
                 lambda: client.claim_checkin(row),
                 lambda: client.generate_temp_token(row),
                 lambda: client.ensure_token(row),
                 lambda: client.reload_desktop_auth(row),
                 lambda: client.sync_desktop_auth(row)]
        with mock.patch.object(client, "_open") as outbound, \
             mock.patch.object(client, "_post_no_auth") as post, \
             mock.patch.object(client, "_resolve_device_credentials") as device, \
             mock.patch.object(client, "desktop_auth_body") as desktop, \
             mock.patch.object(client, "_note_refresh_failure") as backoff:
            for action in calls:
                self.assert_blocked(action)
            for stub in (outbound, post, device, desktop, backoff):
                stub.assert_not_called()
        self.assertEqual(row, original)

    def test_pool_import_and_historical_load_do_not_mutate_files(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "fixture.json")
            raw = json.dumps(enterprise()).encode()
            with open(path, "wb") as handle:
                handle.write(raw)
            logs = []
            pool = accounts.AccountPool(directory=root, log=lambda message, level=None: logs.append((level, message)))
            with mock.patch.object(client, "_open") as outbound:
                self.assertEqual(pool.load(), [])
                self.assertIsNone(pool.pick())
                result = pool.import_rows([enterprise()])
                self.assertEqual(result["imported"], 0)
                self.assertTrue(result["errors"])
                self.assert_blocked(lambda: pool.add_from_refresh("opaque", realm="saas"))
                self.assert_blocked(lambda: pool.import_pat("opaque", realm="enterprise"))
                outbound.assert_not_called()
            self.assertTrue(any(level == "WARN" and "Enterprise/SaaS" in message for level, message in logs))
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), raw)
            self.assertEqual(os.listdir(root), ["fixture.json"])

    def test_dynamic_historical_account_never_selected_refreshed_or_saved(self):
        row = accounts.Account(personal())
        row.account = enterprise()["account"]
        with tempfile.TemporaryDirectory() as root:
            pool = accounts.AccountPool(directory=root, log=lambda *args, **kwargs: None)
            pool.accounts = [row]
            self.assertFalse(row.ready())
            self.assertFalse(row.refresh_due())
            self.assertIsNone(pool.pick())
            self.assertIsNone(pool.representative())
            with mock.patch.object(client, "refresh_account") as refresh:
                self.assert_blocked(lambda: row.refresh(force=True, client=client))
                self.assert_blocked(lambda: accounts._fallback_refresh(row))
                self.assert_blocked(lambda: row.save(root))
                self.assert_blocked(lambda: pool.add(row))
                refresh.assert_not_called()
            self.assertEqual(os.listdir(root), [])

    def test_refresh_response_cannot_strip_enterprise_metadata(self):
        response={"Result":{"Token":"new-fixture-token", "RefreshToken":"new-refresh", "UserInfo":{"Scope":"saas"}}}
        with mock.patch.object(client,"_post_no_auth",return_value=response) as post:
            row=personal()
            original=copy.deepcopy(row)
            self.assert_blocked(lambda:client._refresh_account_request(row))
            self.assertEqual(post.call_count,1)
            self.assertEqual(row,original)

    def test_accounts_still_imports_without_optional_client(self):
        with mock.patch.dict(sys.modules, {"trae_client": None}):
            module = runpy.run_path(accounts.__file__)
            self.assertIsNone(module["_load_client"]())
            row = module["Account"](personal())
            self.assertEqual(row.realm, "cn")
            with self.assertRaises(module["AccountError"]) as caught:
                module["Account"](enterprise())
            self.assertEqual(caught.exception.code, "unsupported_enterprise_account")
            self.assertEqual(caught.exception.status, 400)
            with tempfile.TemporaryDirectory() as root:
                pool = module["AccountPool"](directory=root, log=lambda *args, **kwargs: None)
                with mock.patch("urllib.request.urlopen") as outbound:
                    result = pool.import_rows([enterprise()])
                    self.assertEqual(result["imported"], 0)
                    self.assertIn("Enterprise/SaaS", result["errors"][0])
                    outbound.assert_not_called()
                self.assertEqual(os.listdir(root), [])

    def test_desktop_fixture_is_read_only_and_not_imported(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "storage.json")
            raw = json.dumps({"iCubeAuthInfo://icube.cloudide": enterprise()}).encode()
            with open(path, "wb") as handle:
                handle.write(raw)
            with mock.patch.object(client, "_open") as outbound:
                with self.assertRaises((client.UpstreamError, accounts.AccountError)) as caught:
                    client.import_desktop_accounts(path=path)
                self.assertIn("Enterprise/SaaS", str(caught.exception))
                outbound.assert_not_called()
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), raw)
            self.assertEqual(os.listdir(root), ["storage.json"])


if __name__ == "__main__":
    unittest.main()
