# -*- coding: utf-8 -*-
"""issue #6 并发/调度回归测试（只读假账号，不触碰真实凭证）。

覆盖：
  · 批量签到默认错峰 45~120s，sleep/rng 可注入，测试不真等待；
  · 保活/权益刷新沿用 0.2s 节流，同样可注入；
  · 调度器 09:00/21:00 加 0~25 分钟窗口抖动，clock/rng 可注入；
  · 抖动窗口跨重启保留、错过不补跑、异常不被吞成成功；
  · 既有返回键/签名兼容；调度器不修改账号池的每号并发上限。

运行：
    python -m unittest test_issue_scheduling -v
    python test_issue_scheduling.py
"""
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import trae_scheduler
import trae_tasks


def local_epoch(year, month, day, hour, minute=0, second=0):
    return time.mktime((year, month, day, hour, minute, second, 0, 0, -1))


class FakeClock(object):
    def __init__(self, ts):
        self.ts = float(ts)

    def __call__(self):
        return self.ts

    def set(self, ts):
        self.ts = float(ts)

    def advance(self, seconds):
        self.ts += float(seconds)


class FakeRng(object):
    """uniform() 返回区间内固定比例；默认 0.5 = 抖动中位。"""

    def __init__(self, ratio=0.5):
        self.ratio = float(ratio)
        self.calls = 0

    def uniform(self, low, high):
        self.calls += 1
        return float(low) + (float(high) - float(low)) * self.ratio


class FakeAccount(object):
    def __init__(self, uid, realm="cn", expires_in=3600,
                 access_token="test-token", refresh_token="test-refresh"):
        self.uid = uid
        self.nickname = uid
        self.realm = realm
        self.enabled = True
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = time.time() + float(expires_in)
        self.plan = ""
        self.last_error = ""
        self.path = None
        self.extra = {}
        self.usage = None
        self.entitlement = None
        self.usage_updated_at = 0

    def refresh(self, force=False):
        self.expires_at = time.time() + 7 * 86400
        return True

    def set_usage(self, usage=None, entitlement=None, persist=True):
        if usage:
            self.usage = usage
        if entitlement:
            self.entitlement = entitlement
        self.usage_updated_at = int(time.time())
        return {"ok": True}


class FakeClient(object):
    def __init__(self, result=None, exception_on=None, exception=None):
        self.calls = []
        self.result = result or {
            "ok": True, "already": False, "checked_in": True,
            "credits": 100, "earned_credit": 100, "message": "success",
        }
        self.exception_on = exception_on
        self.exception = exception or RuntimeError("upstream boom")

    def claim_checkin(self, account, realm=None):
        self.calls.append(account.uid)
        if self.exception_on and account.uid == self.exception_on:
            raise self.exception
        return dict(self.result)

    def fetch_usage(self, account, realm=None):
        return {"input_token": 3, "output_token": 2, "total_token": 5}

    def fetch_entitlement(self, account, realm=None):
        return {"plan": "Pro", "remain": 10, "total": 100}


class FakePool(object):
    def __init__(self, accounts=None, directory=None):
        self.accounts = list(accounts or [])
        self.dir = directory or tempfile.mkdtemp(prefix="issue6_pool_")
        self.max_inflight = 8


class Issue6TestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="issue6_test_")
        self.env_patch = mock.patch.dict(os.environ, {
            "TRAE_PROXY_USAGE_DIR": self.tmp,
            "USAGE_DIR": self.tmp,
        }, clear=False)
        self.env_patch.start()
        # 避免 scheduler.log 导入真实网关（重且有副作用）
        self.proxy_stub = types.SimpleNamespace(
            add_log_entry=lambda *args, **kwargs: None)
        self.sys_patch = mock.patch.dict(sys.modules,
                                         {"trae_proxy": self.proxy_stub})
        self.sys_patch.start()
        trae_tasks.set_logger(None)

    def tearDown(self):
        trae_tasks.set_logger(None)
        self.sys_patch.stop()
        self.env_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_pacing(self, kind="checkin", interval=10.0, jitter=5.0,
                    ratio=0.5, sleeps=None):
        sleeps = sleeps if sleeps is not None else []

        def _sleep(delay):
            sleeps.append(delay)

        pacing = trae_tasks.make_pacing(
            kind, interval=interval, jitter=jitter, sleep=_sleep,
            rng=FakeRng(ratio))
        return pacing, sleeps

    def make_scheduler(self, clock=None, ratio=0.5, jitter=1500.0,
                       accounts=None, pacing=None):
        clock = clock or FakeClock(local_epoch(2026, 11, 11, 8, 30, 0))
        pool = FakePool(accounts or [FakeAccount("acct-a")],
                        directory=os.path.join(self.tmp, "accounts"))
        os.makedirs(pool.dir, exist_ok=True)
        if pacing is None:
            pacing, _ = self.make_pacing(interval=10, jitter=5)
        return trae_scheduler.Scheduler(
            pool, state_dir=self.tmp, clock=clock, rng=FakeRng(ratio),
            schedule_jitter_seconds=jitter, checkin_pacing=pacing), clock, pool


class PacingConfigTests(Issue6TestBase):
    def test_defaults_are_conservative(self):
        with mock.patch.dict(os.environ, {
            "TRAE_CHECKIN_INTERVAL_SECONDS": "",
            "TRAE_CHECKIN_JITTER_SECONDS": "",
            "TRAE_TASK_INTERVAL_SECONDS": "",
            "TRAE_TASK_JITTER_SECONDS": "",
        }, clear=False):
            self.assertEqual(trae_tasks.pacing_defaults("checkin"),
                             {"interval": 45.0, "jitter": 75.0})
            self.assertEqual(trae_tasks.pacing_defaults("task"),
                             {"interval": 0.2, "jitter": 0.0})

    def test_env_overrides(self):
        with mock.patch.dict(os.environ, {
            "TRAE_CHECKIN_INTERVAL_SECONDS": "1.5",
            "TRAE_CHECKIN_JITTER_SECONDS": "2.5",
            "TRAE_TASK_INTERVAL_SECONDS": "0.7",
            "TRAE_TASK_JITTER_SECONDS": "0.3",
        }, clear=False):
            self.assertEqual(trae_tasks.pacing_defaults("checkin"),
                             {"interval": 1.5, "jitter": 2.5})
            self.assertEqual(trae_tasks.pacing_defaults("task"),
                             {"interval": 0.7, "jitter": 0.3})

    def test_invalid_and_negative_env_are_safe(self):
        with mock.patch.dict(os.environ, {
            "TRAE_CHECKIN_INTERVAL_SECONDS": "not-a-number",
            "TRAE_CHECKIN_JITTER_SECONDS": "-9",
        }, clear=False):
            values = trae_tasks.pacing_defaults("checkin")
            self.assertEqual(values["interval"], 45.0)
            self.assertEqual(values["jitter"], 0.0)

    def test_make_pacing_injection_does_not_sleep(self):
        sleeps = []
        pacing = trae_tasks.make_pacing(
            "checkin", interval=1.0, jitter=2.0,
            sleep=sleeps.append, rng=FakeRng(0.5))
        delay = trae_tasks._pace(pacing, 1)
        self.assertEqual(delay, 2.0)
        self.assertEqual(sleeps, [2.0])
        self.assertEqual(trae_tasks.pacing_view(pacing),
                         {"kind": "checkin", "interval": 1.0, "jitter": 2.0})


class DailyCheckinPacingTests(Issue6TestBase):
    def test_only_cn_accounts_are_paced_and_result_not_faked(self):
        accounts = [FakeAccount("cn1"), FakeAccount("cn2"),
                    FakeAccount("cn3"), FakeAccount("intl", realm="intl")]
        client = FakeClient(result={
            "ok": True, "already": True, "checked_in": True,
            "credits": 100, "earned_credit": 0, "message": "already",
        })
        pacing, sleeps = self.make_pacing()
        with mock.patch.object(trae_tasks, "_client_module", lambda: client):
            result = trae_tasks.task_daily_checkin(
                accounts=accounts, pacing=pacing, trigger="test")
        self.assertTrue(result["ok"])
        self.assertEqual(client.calls, ["cn1", "cn2", "cn3"])
        self.assertEqual(sleeps, [12.5, 12.5])
        self.assertEqual(result["stats"]["skipped"], 1)
        self.assertEqual(result["stats"]["paced_seconds"], 25.0)
        self.assertEqual(result["stats"]["waits"], [12.5, 12.5])
        self.assertEqual(result["stats"]["pacing"]["interval"], 10.0)
        self.assertEqual(result["stats"]["pacing"]["jitter"], 5.0)

    def test_cn_failure_is_reported_not_swallowed(self):
        accounts = [FakeAccount("cn1"), FakeAccount("cn2"), FakeAccount("cn3")]
        client = FakeClient(exception_on="cn2")
        pacing, sleeps = self.make_pacing()
        with mock.patch.object(trae_tasks, "_client_module", lambda: client):
            result = trae_tasks.task_daily_checkin(
                accounts=accounts, pacing=pacing, trigger="test")
        self.assertFalse(result["ok"])
        self.assertEqual(result["stats"]["failed"], 1)
        self.assertEqual(client.calls, ["cn1", "cn2", "cn3"])
        self.assertEqual(len(sleeps), 2)
        self.assertTrue(any("签到失败" in line for line in result["logs"]))
        record = trae_tasks.load_state()["tasks"]["daily_checkin"]
        self.assertFalse(record["ok"])
        self.assertNotEqual(result["stats"]["failed"], 0)

    def test_missing_client_is_failure(self):
        with mock.patch.object(trae_tasks, "_client_module", lambda: None):
            result = trae_tasks.task_daily_checkin(
                accounts=[FakeAccount("cn1")], trigger="test")
        self.assertFalse(result["ok"])
        self.assertTrue(any("trae_client" in line for line in result["logs"]))

    def test_batch_daily_checkin_uses_pacing(self):
        accounts = [FakeAccount("cn1"), FakeAccount("cn2"),
                    FakeAccount("cn3")]
        client = FakeClient()
        pacing, sleeps = self.make_pacing()
        with mock.patch.object(trae_tasks, "_client_module", lambda: client):
            result = trae_tasks.run_batch_daily_checkin(
                accounts, pacing=pacing)
        self.assertTrue(result["ok"])
        self.assertEqual(result["accounts_count"], 3)
        self.assertEqual(len(result["results"]), 3)
        self.assertEqual(sleeps, [12.5, 12.5])
        self.assertEqual(result["paced_seconds"], 25.0)

    def test_batch_checkin_wires_pacing_and_keeps_return_keys(self):
        fake = {
            "ok": True,
            "results": {"daily_checkin": {
                "ok": True, "stats": {"earned_credit": 7,
                                      "paced_seconds": 12.5}}},
            "duration_ms": 3,
        }
        pacing, _ = self.make_pacing(interval=7, jitter=3)
        with mock.patch.object(trae_tasks, "run_all_tasks",
                               return_value=fake) as run_all:
            result = trae_tasks.run_batch_checkin(
                [FakeAccount("cn1")], pacing=pacing)
        captured = run_all.call_args.kwargs["pacing"]
        captured_view = trae_tasks.pacing_view(captured)
        self.assertEqual(captured_view["interval"], 7.0)
        self.assertEqual(captured_view["jitter"], 3.0)
        self.assertEqual(captured_view["source"], "caller_pacing")
        self.assertIs(captured["sleep"], pacing["sleep"])
        self.assertIs(captured["rng"], pacing["rng"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["credit_added"], 7)
        self.assertEqual(result["accounts_count"], 1)
        for key in ("ok", "logs", "credit_added", "accounts_count",
                    "tasks", "results", "duration_ms", "pacing"):
            self.assertIn(key, result)

    def test_manual_explicit_gap_stays_short_and_is_reported(self):
        fake = {"ok": True, "results": {"daily_checkin": {
            "ok": True, "stats": {"earned_credit": 0}}}, "duration_ms": 1}
        with mock.patch.object(trae_tasks, "run_all_tasks",
                               return_value=fake) as run_all:
            result = trae_tasks.run_batch_checkin(
                [FakeAccount("cn1")], gap=1.0)
        pacing = run_all.call_args.kwargs["pacing"]
        self.assertEqual(trae_tasks.pacing_view(pacing)["interval"], 1.0)
        self.assertEqual(trae_tasks.pacing_view(pacing)["jitter"], 0.0)
        self.assertEqual(result["pacing"]["source"], "legacy_gap")
        self.assertEqual(result["pacing"]["interval"], 1.0)
        self.assertEqual(result["pacing"]["jitter"], 0.0)

    def test_manual_without_gap_uses_short_default(self):
        fake = {"ok": True, "results": {"daily_checkin": {
            "ok": True, "stats": {"earned_credit": 0}}}, "duration_ms": 1}
        with mock.patch.dict(os.environ, {
            "TRAE_MANUAL_CHECKIN_INTERVAL_SECONDS": "",
            "TRAE_MANUAL_CHECKIN_JITTER_SECONDS": "",
        }, clear=False), mock.patch.object(
                trae_tasks, "run_all_tasks", return_value=fake):
            result = trae_tasks.run_batch_checkin([FakeAccount("cn1")])
        self.assertEqual(result["pacing"]["interval"], 1.5)
        self.assertEqual(result["pacing"]["jitter"], 0.0)
        self.assertEqual(result["pacing"]["source"], "manual_default")

    def test_manual_env_can_enable_issue6_spacing(self):
        fake = {"ok": True, "results": {"daily_checkin": {
            "ok": True, "stats": {"earned_credit": 0}}}, "duration_ms": 1}
        with mock.patch.dict(os.environ, {
            "TRAE_MANUAL_CHECKIN_INTERVAL_SECONDS": "45",
            "TRAE_MANUAL_CHECKIN_JITTER_SECONDS": "75",
        }, clear=False), mock.patch.object(
                trae_tasks, "run_all_tasks", return_value=fake):
            result = trae_tasks.run_batch_checkin([FakeAccount("cn1")],
                                                  gap=1.0)
        self.assertEqual(result["pacing"]["interval"], 45.0)
        self.assertEqual(result["pacing"]["jitter"], 75.0)
        self.assertEqual(result["pacing"]["source"], "manual_env")

    def test_manual_interval_argument_can_enable_issue6_spacing(self):
        fake = {"ok": True, "results": {"daily_checkin": {
            "ok": True, "stats": {"earned_credit": 0}}}, "duration_ms": 1}
        with mock.patch.object(trae_tasks, "run_all_tasks",
                               return_value=fake):
            result = trae_tasks.run_batch_checkin(
                [FakeAccount("cn1")], interval=45, jitter=75)
        self.assertEqual(result["pacing"]["interval"], 45.0)
        self.assertEqual(result["pacing"]["jitter"], 75.0)
        self.assertEqual(result["pacing"]["source"], "explicit_interval")

    def test_manual_gap_pacing_waits_one_second_in_task(self):
        pacing, _ = trae_tasks.resolve_manual_checkin_pacing(gap=1.0)
        sleeps = []
        pacing["sleep"] = sleeps.append
        client = FakeClient()
        with mock.patch.object(trae_tasks, "_client_module", lambda: client):
            result = trae_tasks.task_daily_checkin(
                accounts=[FakeAccount("cn1"), FakeAccount("cn2")],
                pacing=pacing, trigger="test")
        self.assertTrue(result["ok"])
        self.assertEqual(sleeps, [1.0])
        self.assertEqual(result["stats"]["paced_seconds"], 1.0)
        self.assertEqual(result["stats"]["pacing"]["source"], "legacy_gap")

    def test_run_checkin_compat_keys(self):
        cn = FakeAccount("cn1")
        with mock.patch.object(trae_tasks, "_client_module",
                               lambda: FakeClient()):
            result = trae_tasks.run_checkin(cn)
        self.assertTrue(result["ok"])
        for key in ("message", "claimed", "next_available_at",
                    "next_available_note", "credits", "earned_credit"):
            self.assertIn(key, result)
        intl = FakeAccount("intl1", realm="intl")
        intl_result = trae_tasks.run_checkin(intl)
        self.assertFalse(intl_result["ok"])
        self.assertTrue(intl_result.get("skipped"))

    def test_run_task_exception_is_recorded_as_failure(self):
        def boom(**kwargs):
            raise RuntimeError("boom-for-test")

        with mock.patch.dict(trae_tasks._TASK_IMPLS,
                             {"daily_checkin": boom}):
            result = trae_tasks.run_task("daily_checkin",
                                         accounts=[FakeAccount("cn1")])
        self.assertFalse(result["ok"])
        self.assertIn("boom-for-test", result["error"])
        record = trae_tasks.load_state()["tasks"]["daily_checkin"]
        self.assertFalse(record["ok"])
        unknown = trae_tasks.run_task("does-not-exist")
        self.assertFalse(unknown["ok"])


class TaskPacingTests(Issue6TestBase):
    def test_keepalive_uses_injected_pacing(self):
        accounts = [FakeAccount("k1", expires_in=60),
                    FakeAccount("k2", expires_in=60)]
        pacing, sleeps = self.make_pacing(kind="task", interval=3, jitter=2)
        result = trae_tasks.task_token_keepalive(
            accounts=accounts, pacing=pacing, trigger="test")
        self.assertTrue(result["ok"])
        self.assertEqual(result["stats"]["refreshed"], 2)
        self.assertEqual(sleeps, [4.0])
        self.assertEqual(result["stats"]["paced_seconds"], 4.0)
        self.assertEqual(result["stats"]["pacing"]["kind"], "task")

    def test_run_all_tasks_only_paces_daily_checkin(self):
        pacing, _ = self.make_pacing()
        seen = {}

        def fake_run_task(code, **kwargs):
            seen[code] = kwargs.get("pacing")
            return {"ok": True, "task": code, "summary": "ok", "stats": {}}

        with mock.patch.object(trae_tasks, "run_task",
                               side_effect=fake_run_task):
            trae_tasks.run_all_tasks(accounts=[], pacing=pacing)
        self.assertIs(seen["daily_checkin"], pacing)
        self.assertIsNone(seen["token_keepalive"])
        self.assertIsNone(seen["usage_refresh"])

    def test_usage_refresh_uses_injected_pacing(self):
        accounts = [FakeAccount("u1"), FakeAccount("u2")]
        client = FakeClient()
        pacing, sleeps = self.make_pacing(kind="task", interval=3, jitter=2)
        with mock.patch.object(trae_tasks, "_client_module", lambda: client):
            result = trae_tasks.task_usage_refresh(
                accounts=accounts, pacing=pacing, trigger="test")
        self.assertTrue(result["ok"])
        self.assertEqual(result["stats"]["refreshed"], 2)
        self.assertEqual(sleeps, [4.0])
        self.assertEqual(result["stats"]["paced_seconds"], 4.0)
        self.assertEqual(len(result["accounts"]), 2)

    def test_no_real_time_sleep_for_paced_tasks(self):
        accounts = [FakeAccount("cn1"), FakeAccount("cn2")]
        client = FakeClient()
        pacing, _ = self.make_pacing()
        with mock.patch.object(trae_tasks, "_client_module", lambda: client), \
                mock.patch("trae_tasks.time.sleep",
                           side_effect=AssertionError("real sleep called")):
            result = trae_tasks.task_daily_checkin(
                accounts=accounts, pacing=pacing, trigger="test")
        self.assertTrue(result["ok"])


class SchedulerJitterTests(Issue6TestBase):
    def test_jittered_next_run_time_and_status(self):
        scheduler, clock, _ = self.make_scheduler(jitter=1500, ratio=0.5)
        self.assertEqual(scheduler.schedule_jitter_seconds, 1500.0)
        self.assertEqual(scheduler.next_run_slot,
                         local_epoch(2026, 11, 11, 9, 0, 0))
        self.assertEqual(scheduler.next_run_ts,
                         local_epoch(2026, 11, 11, 9, 12, 30))
        self.assertEqual(scheduler.next_run_time, "2026-11-11 09:12:30")
        status = scheduler.status()
        self.assertIn("抖动", status["mode"])
        self.assertEqual(status["schedule_jitter_seconds"], 1500.0)
        self.assertEqual(status["next_run_ts"],
                         int(local_epoch(2026, 11, 11, 9, 12, 30)))
        self.assertEqual(status["checkin_pacing"]["interval"], 10.0)
        self.assertEqual(status["hours"], [9, 21])

    def test_scheduler_background_keeps_conservative_default(self):
        clock = FakeClock(local_epoch(2026, 11, 11, 8, 30, 0))
        pool = FakePool([FakeAccount("a")],
                        directory=os.path.join(self.tmp, "accounts"))
        os.makedirs(pool.dir, exist_ok=True)
        with mock.patch.dict(os.environ, {
            "TRAE_CHECKIN_INTERVAL_SECONDS": "",
            "TRAE_CHECKIN_JITTER_SECONDS": "",
            "TRAE_MANUAL_CHECKIN_INTERVAL_SECONDS": "",
            "TRAE_MANUAL_CHECKIN_JITTER_SECONDS": "",
        }, clear=False):
            scheduler = trae_scheduler.Scheduler(
                pool, state_dir=self.tmp, clock=clock, rng=FakeRng(0.5),
                schedule_jitter_seconds=0)
        self.assertEqual(scheduler.checkin_pacing["interval"], 45.0)
        self.assertEqual(scheduler.checkin_pacing["jitter"], 75.0)
        self.assertEqual(scheduler.checkin_pacing["source"],
                         "scheduler_default")

    def test_env_jitter_zero_gives_exact_hour(self):
        clock = FakeClock(local_epoch(2026, 11, 11, 8, 30, 0))
        pool = FakePool([FakeAccount("a")],
                        directory=os.path.join(self.tmp, "accounts"))
        os.makedirs(pool.dir, exist_ok=True)
        pacing, _ = self.make_pacing()
        with mock.patch.dict(os.environ,
                             {"TRAE_SCHEDULE_JITTER_SECONDS": "0"},
                             clear=False):
            scheduler = trae_scheduler.Scheduler(
                pool, state_dir=self.tmp, clock=clock, rng=FakeRng(0.5),
                checkin_pacing=pacing)
        self.assertEqual(scheduler.schedule_jitter_seconds, 0.0)
        self.assertEqual(scheduler.next_run_time, "2026-11-11 09:00:00")

    def test_pending_jitter_window_survives_restart(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        scheduler._save_state()
        restarted, _, _ = self.make_scheduler(clock=clock, ratio=0.1)
        self.assertEqual(restarted.next_run_ts, scheduler.next_run_ts)
        self.assertEqual(restarted.next_run_time, scheduler.next_run_time)

    def test_tick_fires_once_at_target_and_reschedules(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        scheduler._execute_cycle = mock.Mock(return_value=None)
        self.assertFalse(scheduler._tick())
        clock.set(scheduler.next_run_ts)
        self.assertTrue(scheduler._tick())
        scheduler._execute_cycle.assert_called_once()
        _, kwargs = scheduler._execute_cycle.call_args
        self.assertEqual(kwargs, {})  # 位置参数形式，避免误传
        self.assertEqual(scheduler.next_run_ts,
                         local_epoch(2026, 11, 11, 21, 12, 30))
        self.assertFalse(scheduler._tick())
        self.assertEqual(scheduler._execute_cycle.call_count, 1)

    def test_stale_target_is_skipped_not_replayed(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        scheduler._execute_cycle = mock.Mock()
        target = scheduler.next_run_ts
        clock.set(target + trae_scheduler.MISSED_GRACE_SECONDS + 1)
        self.assertFalse(scheduler._tick())
        scheduler._execute_cycle.assert_not_called()
        self.assertGreater(scheduler.next_run_ts, clock.ts)

    def test_reenable_skips_missed_window(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        target = scheduler.next_run_ts
        scheduler.enabled = False
        clock.set(target + 60)
        scheduler.set_enabled(True)
        self.assertGreater(scheduler.next_run_ts, clock.ts)

    def test_old_state_without_jitter_fields_still_loads(self):
        old_state = {
            "version": 2, "kind": "scheduler_state", "enabled": False,
            "last_run_time": "2026-11-10 21:00:00",
            "next_run_time": "2026-11-11 09:00:00",
            "logs": ["old-state"],
        }
        with open(os.path.join(self.tmp, "scheduler.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(old_state, fh)
        scheduler, _, _ = self.make_scheduler(
            clock=FakeClock(local_epoch(2026, 11, 11, 8, 30, 0)), ratio=0.5)
        self.assertFalse(scheduler.enabled)
        self.assertEqual(scheduler.last_run_time, "2026-11-10 21:00:00")
        self.assertEqual(scheduler.schedule_jitter_seconds, 1500.0)
        self.assertEqual(scheduler.next_run_time, "2026-11-11 09:12:30")
        self.assertGreater(scheduler.next_run_ts, 0)

    def test_zero_jitter_does_not_refire_same_slot(self):
        scheduler, clock, _ = self.make_scheduler(
            clock=FakeClock(local_epoch(2026, 11, 11, 8, 59, 59)),
            ratio=0.0, jitter=0.0)
        scheduler._execute_cycle = mock.Mock()
        self.assertEqual(scheduler.next_run_time, "2026-11-11 09:00:00")
        clock.set(scheduler.next_run_ts)
        self.assertTrue(scheduler._tick())
        self.assertEqual(scheduler.next_run_time, "2026-11-11 21:00:00")
        self.assertFalse(scheduler._tick())
        self.assertEqual(scheduler._execute_cycle.call_count, 1)

    def test_boundary_085959_selects_0900_window(self):
        scheduler, _, _ = self.make_scheduler(
            clock=FakeClock(local_epoch(2026, 11, 11, 8, 59, 59)),
            ratio=0.0)
        self.assertEqual(scheduler.next_run_slot,
                         local_epoch(2026, 11, 11, 9, 0, 0))
        self.assertEqual(scheduler.next_run_time, "2026-11-11 09:00:00")

    def test_missed_window_is_not_replayed(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        scheduler._save_state()
        clock.set(local_epoch(2026, 11, 11, 10, 0, 0))
        restarted, _, _ = self.make_scheduler(clock=clock, ratio=0.5)
        self.assertGreater(restarted.next_run_ts, clock.ts)
        self.assertEqual(restarted.next_run_time, "2026-11-11 21:12:30")

    def test_disabled_scheduler_does_not_fire(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        scheduler.enabled = False
        scheduler._execute_cycle = mock.Mock()
        clock.set(scheduler.next_run_ts)
        self.assertFalse(scheduler._tick())
        scheduler._execute_cycle.assert_not_called()

    def test_enabled_and_last_run_persist(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        scheduler.enabled = False
        scheduler.last_run_time = "2026-11-11 09:12:30"
        scheduler.log("issue6 persistence")
        restarted, _, _ = self.make_scheduler(clock=clock, ratio=0.9)
        self.assertFalse(restarted.enabled)
        self.assertEqual(restarted.last_run_time, "2026-11-11 09:12:30")
        self.assertEqual(restarted._state_path(),
                         os.path.join(self.tmp, "scheduler.json"))
        self.assertFalse(os.path.exists(os.path.join(
            restarted.accounts_dir, "scheduler.json")))

    def test_startup_gate_uses_injected_clock(self):
        scheduler, clock, _ = self.make_scheduler(ratio=0.5)
        self.assertTrue(scheduler._allow_startup())
        self.assertFalse(scheduler._allow_startup())
        clock.advance(31 * 60)
        self.assertTrue(scheduler._allow_startup())

    def test_configure_updates_jitter_and_pacing(self):
        scheduler, _, _ = self.make_scheduler(ratio=0.5)
        status = scheduler.configure(schedule_jitter_seconds=0,
                                     checkin_interval=7,
                                     checkin_jitter=3)
        self.assertEqual(status["schedule_jitter_seconds"], 0.0)
        self.assertEqual(status["checkin_pacing"]["interval"], 7.0)
        self.assertEqual(status["checkin_pacing"]["jitter"], 3.0)
        self.assertEqual(status["next_run_time"], "2026-11-11 09:00:00")

    def test_cycle_passes_checkin_pacing_and_keeps_concurrency(self):
        scheduler, _, pool = self.make_scheduler(ratio=0.5)
        fake_result = {"ok": True, "results": {"daily_checkin": {
            "ok": True, "summary": "ok"}}, "duration_ms": 1}
        with mock.patch.object(trae_tasks, "run_all_tasks",
                               return_value=fake_result) as run_all:
            scheduler._run_cycle("test", "manual")
        self.assertIs(run_all.call_args.kwargs["pacing"],
                      scheduler.checkin_pacing)
        self.assertEqual(pool.max_inflight, 8)

    def test_account_default_inflight_is_accounts_layer_only(self):
        import inspect
        import re
        import trae_accounts
        source = inspect.getsource(trae_accounts.AccountPool.__init__)
        self.assertIn("TRAE_MAX_INFLIGHT", source)
        # issue #6 提到的默认并发定义在账号层；数值可能被账号负责人调整，
        # 本测试只锁定「位置」，不硬编码 8。
        self.assertRegex(source, r"or \d+")
        # 本任务只改调度/任务层，不直接改账号池默认并发
        self.assertNotIn("max_inflight", inspect.getsource(
            trae_scheduler.Scheduler.__init__))
        self.assertNotIn("max_inflight", inspect.getsource(
            trae_tasks.task_token_keepalive))


if __name__ == "__main__":
    unittest.main(verbosity=2)
