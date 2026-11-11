# -*- coding: utf-8 -*-
"""trae_scheduler.py —— Trae 维护巡检调度器

调度器的职责是**维护巡检**：
  每日 09:00 / 21:00 各加 0~25 分钟随机窗口抖动（issue #6），另加进程启动巡检；
  按 trae_tasks.TASK_ORDER 执行签到 / 保活 / 权益用量 / 目录 / 模型探测 / 到期提醒。
  签到账号之间默认 45~120 秒错峰，避免 5 个号在 5 秒内连打上游。

状态落盘：<usage>/scheduler.json（tmp + os.replace 原子写）
  · **不写 accounts/**：账号池会扫描该目录下所有 JSON，状态文件放进去会产生
    「缺少 uid，已跳过」告警与潜在误判；本文件与 tasks.json 一起放在 usage/；
  · 兼容迁移旧路径 <账号目录>/scheduler.json 与 <账号目录>/scheduler/state.json，
    迁移成功后只清理「无 uid 且像调度状态」的旧文件，绝不碰账号；
  · enabled / last_run_time / next_run_time / next_run_ts / 窗口抖动 / 签到节流
    重启后全部保留；未到点的抖动窗口不会重新掷骰子；
  · 启动巡检有 30 分钟去抖；错过排程窗口超过 5 分钟不补跑（保持旧行为）。

看板接口（trae_proxy.py 现有路由）保持不变：
  GET  /scheduler          -> status()
  POST /scheduler/trigger  -> trigger_now()
  POST /scheduler/toggle   -> 直接翻 enabled 后调用 log()（log 会落盘）
"""
import json
import os
import random
import sys
import threading
import time

import trae_tasks

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE_NAME = "scheduler.json"
LEGACY_STATE_SUBPATH = os.path.join("scheduler", "state.json")

CYCLE_STARTUP = "startup"
CYCLE_HOUR = "hour"
CYCLE_MANUAL = "manual"

SCHEDULE_HOURS = (9, 21)          # 每日 09:00 / 21:00（本地时区）
DEFAULT_SCHEDULE_JITTER_SECONDS = 25 * 60   # issue #6：0~25 分钟窗口抖动
MAX_SCHEDULE_JITTER_SECONDS = 60 * 60
ENV_SCHEDULE_JITTER = "TRAE_SCHEDULE_JITTER_SECONDS"
POLL_MAX_SECONDS = 20.0           # 运行期最长轮询间隔（不再是整点分钟判断）
POLL_MIN_SECONDS = 0.5
MISSED_GRACE_SECONDS = 5 * 60     # 错过窗口超过 5 分钟不补跑（保持旧行为）
STARTUP_DELAY = 10                # 启动后等主服务就绪
STARTUP_MIN_INTERVAL = 30 * 60    # 启动巡检去抖（秒）
LOG_LIMIT = 80
HISTORY_LIMIT = 60
STATE_VERSION = 3


def _coerce_jitter_seconds(value):
    """调度窗口抖动：0~1 小时；非法值回退默认 25 分钟。"""
    if value is None:
        return float(DEFAULT_SCHEDULE_JITTER_SECONDS)
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return float(DEFAULT_SCHEDULE_JITTER_SECONDS)
    return max(0.0, min(float(MAX_SCHEDULE_JITTER_SECONDS), seconds))


def _env_is_set(name):
    value = os.environ.get(name)
    return value is not None and str(value).strip() != ""


def _env_schedule_jitter():
    raw = os.environ.get(ENV_SCHEDULE_JITTER)
    if raw is None or str(raw).strip() == "":
        return float(DEFAULT_SCHEDULE_JITTER_SECONDS)
    return _coerce_jitter_seconds(raw)


class Scheduler(object):
    def __init__(self, pool, state_dir=None, clock=None, rng=None,
                 schedule_jitter_seconds=None, checkin_pacing=None):
        """调度器。

        clock/rng 可注入（测试传假时钟/假随机源，不真 sleep）；运行期默认
        time.time / random.Random。schedule_jitter_seconds 默认 25 分钟。
        """
        self.pool = pool
        self.hours = list(SCHEDULE_HOURS)
        self.all_hours = sorted(set(self.hours))
        self._stop_event = threading.Event()
        self._thread = None
        self._run_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._last_fired_key = None      # 兼容旧状态消费者；新逻辑按时间戳触发
        # clock=None 时动态取 time.time（便于测试 patch）；显式注入优先
        self._clock = clock if callable(clock) else None
        self._rng = rng if rng is not None else random.Random()
        self.accounts_dir = (getattr(pool, "dir", None)
                             or os.environ.get("ACCOUNTS_DIR")
                             or os.path.join(HERE, "accounts"))
        # 状态目录：显式传入（测试）→ usage 目录（与 tasks.json 同处）。
        # **不写 accounts/**：账号池会把该目录下所有 JSON 当账号扫描。
        self.state_dir = state_dir or trae_tasks.usage_dir()
        state, migrated, migrated_from = self._load_state_with_legacy()
        self.enabled = bool(state.get("enabled", True))
        self.last_run_time = state.get("last_run_time") or None
        self.next_run_time = state.get("next_run_time") or None
        self.logs = [str(x) for x in (state.get("logs") or [])][-LOG_LIMIT:]
        self.history = [row for row in (state.get("history") or [])
                        if isinstance(row, dict)][-HISTORY_LIMIT:]
        self.startup_claim_date = str(state.get("startup_claim_date") or "")
        self.startup_last_ts = float(state.get("startup_last_ts") or 0)
        self.last_cycle_date = str(state.get("last_cycle_date") or "")
        self.last_cycle_kind = str(state.get("last_cycle_kind") or "")
        self.last_cycle_stats = state.get("last_cycle_stats") or {}
        if schedule_jitter_seconds is not None:
            self.schedule_jitter_seconds = _coerce_jitter_seconds(
                schedule_jitter_seconds)
        elif _env_is_set(ENV_SCHEDULE_JITTER):
            # 环境变量显式设置时优先于旧状态，便于运维改配置
            self.schedule_jitter_seconds = _env_schedule_jitter()
        elif state.get("schedule_jitter_seconds") is not None:
            self.schedule_jitter_seconds = _coerce_jitter_seconds(
                state.get("schedule_jitter_seconds"))
        else:
            self.schedule_jitter_seconds = _env_schedule_jitter()
        self.next_run_ts = float(state.get("next_run_ts") or 0)
        self.next_run_slot = float(state.get("next_run_slot") or 0)
        persisted_pacing = state.get("checkin_pacing")
        env_pacing = (_env_is_set(trae_tasks.ENV_CHECKIN_INTERVAL)
                      or _env_is_set(trae_tasks.ENV_CHECKIN_JITTER))
        if checkin_pacing is not None:
            self.checkin_pacing = dict(checkin_pacing)
            self.checkin_pacing.setdefault("source", "scheduler_arg")
        elif env_pacing:
            self.checkin_pacing = trae_tasks.make_pacing("checkin")
            self.checkin_pacing["source"] = "scheduler_env"
        elif isinstance(persisted_pacing, dict):
            self.checkin_pacing = trae_tasks.make_pacing(
                "checkin", interval=persisted_pacing.get("interval"),
                jitter=persisted_pacing.get("jitter"))
            self.checkin_pacing["source"] = "scheduler_state"
        else:
            self.checkin_pacing = trae_tasks.make_pacing("checkin")
            self.checkin_pacing["source"] = "scheduler_default"
        if not self._restore_next_fire():
            self._calc_next_fire()
        # 任务层失败（死端点、上游结构变化）也打进看板日志
        trae_tasks.set_logger(self.log)
        if migrated:
            self._save_state()
            self.log("调度器状态已从旧路径 %s 迁移到 %s"
                     % (migrated_from, self._state_path()))
            if self._cleanup_legacy(migrated_from):
                self.log("已清理旧调度状态文件（不触碰账号）：%s" % migrated_from)
        # 无论是否迁移，都把 accounts/ 下遗留的调度状态清掉，避免账号池告警
        for legacy in self._legacy_state_paths():
            if os.path.exists(legacy) and self._cleanup_legacy(legacy):
                self.log("已清理旧调度状态文件（不触碰账号）：%s" % legacy)
        if state and not migrated:
            self.log("调度器状态已从 %s 恢复（enabled=%s，上次运行 %s）"
                     % (self._state_path(), self.enabled,
                        self.last_run_time or "-"))

    # -- 状态持久化 ---------------------------------------------------------
    def _state_path(self):
        return os.path.join(self.state_dir, STATE_FILE_NAME)

    def _legacy_state_paths(self):
        """旧位置：accounts/scheduler.json、accounts/scheduler/state.json，
        以及早期版本把 state_dir 指到 usage 时的 usage/scheduler/state.json。"""
        return [
            os.path.join(self.accounts_dir, STATE_FILE_NAME),
            os.path.join(self.accounts_dir, LEGACY_STATE_SUBPATH),
            os.path.join(self.state_dir, LEGACY_STATE_SUBPATH),
        ]

    def _load_state_with_legacy(self):
        """优先新路径；否则读旧位置并标记需要迁移。"""
        primary = os.path.abspath(self._state_path())
        for path in [self._state_path()] + self._legacy_state_paths():
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    return data, os.path.abspath(path) != primary, path
            except Exception:
                continue
        return {}, False, ""

    def _cleanup_legacy(self, path):
        """迁移成功后清理旧状态文件；只删「无 uid 且像调度状态」的文件。"""
        if not path:
            return False
        try:
            if os.path.abspath(path) == os.path.abspath(self._state_path()):
                return False
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return False
        if not isinstance(data, dict) or data.get("uid"):
            return False
        looks_like_state = (data.get("kind") == "scheduler_state"
                            or "last_run_time" in data
                            or "enabled" in data)
        if not looks_like_state:
            return False
        try:
            os.remove(path)
        except Exception:
            return False
        # 旧子目录空了就顺手删掉（rmdir 只对空目录成功，安全）
        parent = os.path.dirname(path)
        if os.path.basename(parent) == "scheduler":
            try:
                os.rmdir(parent)
            except OSError:
                pass
        return True

    def _save_state(self):
        """原子落盘。**不得**调用 self.log()（否则递归）。"""
        with self._state_lock:
            try:
                path = self._state_path()
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                tmp = path + ".tmp"
                data = {
                    "version": STATE_VERSION,
                    "kind": "scheduler_state",   # 显式标记：不是账号文件
                    "enabled": bool(self.enabled),
                    "last_run_time": self.last_run_time,
                    "next_run_time": self.next_run_time,
                    "next_run_ts": self.next_run_ts,
                    "next_run_slot": self.next_run_slot,
                    "schedule_jitter_seconds": self.schedule_jitter_seconds,
                    "checkin_pacing": trae_tasks.pacing_view(
                        self.checkin_pacing),
                    "startup_claim_date": self.startup_claim_date,
                    "startup_last_ts": self.startup_last_ts,
                    "last_cycle_date": self.last_cycle_date,
                    "last_cycle_kind": self.last_cycle_kind,
                    "last_cycle_stats": self.last_cycle_stats,
                    "hours": list(self.hours),
                    "history": self.history[-HISTORY_LIMIT:],
                    "logs": self.logs[-LOG_LIMIT:],
                    "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, indent=2)
                os.replace(tmp, path)
                return True
            except Exception as exc:
                try:
                    sys.stderr.write("[scheduler] 状态落盘失败: %s\n" % exc)
                    sys.stderr.flush()
                except Exception:
                    pass
                return False

    def log(self, msg):
        entry = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
        self.logs.append(entry)
        if len(self.logs) > LOG_LIMIT:
            self.logs = self.logs[-LOG_LIMIT:]
        # 日志即状态：顺带落盘，看板开关/上次运行时间在重启后仍然可见
        self._save_state()
        try:
            import trae_proxy
            trae_proxy.add_log_entry("[调度器] %s" % msg, tag="scheduler")
        except Exception:
            pass

    # -- 生命周期 -----------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self.log("后台维护调度器已启动（每日 09:00 / 21:00 + 0~%.0f 分钟抖动 + 启动巡检）"
                 % (self.schedule_jitter_seconds / 60.0))

    def stop(self):
        self._stop_event.set()
        self.log("后台维护调度器已暂停")

    def set_enabled(self, value):
        """看板开关：持久化 enabled 并立即生效。"""
        value = bool(value)
        if value == self.enabled:
            self._save_state()
            return self.status()
        self.enabled = value
        if value and self.next_run_ts and self.next_run_ts <= self._now():
            # 停用期间错过的窗口不补跑
            self._calc_next_fire()
        self.log("用户切换调度器状态为: %s" % ("启用" if value else "暂停"))
        return self.status()

    def enable(self):
        return self.set_enabled(True)

    def disable(self):
        return self.set_enabled(False)

    # -- 时钟 / 随机源（可注入，测试不真等待） -----------------------------
    def _now(self):
        return float((self._clock or time.time)())

    def _schedule_pacing_view(self):
        try:
            return trae_tasks.pacing_view(self.checkin_pacing)
        except Exception:
            return {"kind": "checkin", "interval": 0.0, "jitter": 0.0}

    def _next_nominal(self, now=None):
        now = self._now() if now is None else float(now)
        local = time.localtime(now)
        candidates = []
        for day_offset in (0, 1):
            for hour in self.all_hours:
                stamp = time.mktime((local.tm_year, local.tm_mon, local.tm_mday,
                                     hour, 0, 0, 0, 0, -1))
                stamp += day_offset * 86400
                # 边界：08:59:59 / 09:00:00 都应选 09:00 窗口；09:00:00.5 起
                # 视为已进入下一窗口（旧实现只在整点分钟内触发，错过不补）。
                if stamp >= now:
                    candidates.append(stamp)
        return float(min(candidates)) if candidates else 0.0

    def _jittered_ts(self, nominal):
        jitter = max(0.0, float(self.schedule_jitter_seconds or 0.0))
        if jitter <= 0 or not nominal:
            return float(nominal or 0.0)
        uniform = getattr(self._rng, "uniform", None)
        if callable(uniform):
            extra = float(uniform(0.0, jitter))
        else:
            extra = float(self._rng()) * jitter
        extra = max(0.0, min(jitter, extra))
        return float(nominal) + extra

    def _restore_next_fire(self):
        """重启时优先保留尚未到点的抖动窗口（不重复掷骰子）。"""
        now = self._now()
        saved_ts = float(self.next_run_ts or 0)
        saved_slot = float(self.next_run_slot or 0)
        if saved_ts <= now or saved_slot <= 0:
            return False
        local = time.localtime(saved_slot)
        if (local.tm_min != 0 or local.tm_sec != 0
                or local.tm_hour not in self.all_hours):
            return False
        if saved_ts - saved_slot > max(0.0, self.schedule_jitter_seconds) + 1:
            return False
        self.next_run_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                           time.localtime(saved_ts))
        return True

    def _calc_next_fire(self, now=None, after_ts=None):
        now = self._now() if now is None else float(now)
        if after_ts is not None:
            now = max(now, float(after_ts))
        nominal = self._next_nominal(now)
        if not nominal:
            self.next_run_slot = 0.0
            self.next_run_ts = 0.0
            self.next_run_time = ""
            return
        self.next_run_slot = float(nominal)
        self.next_run_ts = self._jittered_ts(nominal)
        self.next_run_time = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.next_run_ts))

    def _seconds_until_next(self, now=None):
        if not self.enabled or not self.next_run_ts:
            return POLL_MAX_SECONDS
        now = self._now() if now is None else float(now)
        remaining = float(self.next_run_ts) - now
        if remaining <= 0:
            return POLL_MIN_SECONDS
        return max(POLL_MIN_SECONDS, min(POLL_MAX_SECONDS, remaining))

    def _tick(self, now=None):
        """执行一次到点检查；返回是否触发了一轮巡检。

        触发后立即重算下一窗口；异常不在这里吞掉（由 _run_loop 记录日志），
        测试可直接断言触发次数/异常。
        """
        now = self._now() if now is None else float(now)
        if not self.enabled or not self.next_run_ts:
            return False
        if now < self.next_run_ts:
            return False
        if now - self.next_run_ts > MISSED_GRACE_SECONDS:
            # 进程暂停/看板停用跨过窗口：与旧实现一致，错过不补跑
            self._calc_next_fire(now)
            self._save_state()
            return False
        target = self.next_run_ts
        trigger = "定时窗口命中 (%s)" % time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(target))
        try:
            self._execute_cycle(trigger, CYCLE_HOUR)
        finally:
            # 跳过刚触发的窗口，避免 jitter=0 时在同一秒重复触发
            self._calc_next_fire(after_ts=target + 1.0)
            self._save_state()
        return True

    def _run_loop(self):
        # 启动后先等主服务就绪，再做一次启动巡检（30 分钟去抖）
        if self._stop_event.wait(STARTUP_DELAY):
            return
        if not self.enabled:
            self.log("调度器已暂停，跳过启动巡检")
        elif self._allow_startup():
            try:
                self._execute_cycle("启动巡检", CYCLE_STARTUP)
            except Exception as exc:
                self.log("启动巡检异常: %s" % exc)
            finally:
                # 启动巡检若跨过排程窗口，不补跑（与旧行为一致：错过不追）
                if self.next_run_ts and self.next_run_ts <= self._now():
                    self._calc_next_fire(after_ts=self._now() + 1.0)
        else:
            self.log("启动巡检跳过：%d 分钟内已执行过，避免重启重复打上游"
                     % (STARTUP_MIN_INTERVAL // 60))
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:
                # 不伪造成功：异常写日志并留待下一窗口；测试直接调 _tick
                self.log("排程执行异常: %s" % exc)
            self._stop_event.wait(self._seconds_until_next())

    def _allow_startup(self):
        """启动巡检去抖：同一天且 30 分钟内已跑过则跳过（先标记再动作）。"""
        now = self._now()
        today = time.strftime("%Y-%m-%d", time.localtime(now))
        if (self.startup_claim_date == today
                and now - self.startup_last_ts < STARTUP_MIN_INTERVAL):
            return False
        self.startup_claim_date = today
        self.startup_last_ts = now
        self._save_state()
        return True

    def configure(self, schedule_jitter_seconds=None, checkin_interval=None,
                  checkin_jitter=None):
        """运行期调整窗口抖动/签到节流（环境变量/看板后续可直接调用）。"""
        if schedule_jitter_seconds is not None:
            self.schedule_jitter_seconds = _coerce_jitter_seconds(
                schedule_jitter_seconds)
        if checkin_interval is not None or checkin_jitter is not None:
            current = self._schedule_pacing_view()
            self.checkin_pacing = trae_tasks.make_pacing(
                "checkin",
                interval=(current["interval"] if checkin_interval is None
                          else checkin_interval),
                jitter=(current["jitter"] if checkin_jitter is None
                        else checkin_jitter))
            self.checkin_pacing["source"] = "configure"
        self._calc_next_fire()
        self._save_state()
        pacing = self._schedule_pacing_view()
        self.log("调度配置已更新：窗口抖动 %.0fs，签到间隔 %.1fs + 抖动 %.1fs"
                 % (self.schedule_jitter_seconds, pacing["interval"],
                    pacing["jitter"]))
        return self.status()

    # -- 执行 ---------------------------------------------------------------
    def trigger_now(self):
        """手动立即触发一次维护巡检（不受 enabled 限制，由用户显式发起）。"""
        if self._run_lock.locked():
            return {"ok": False, "msg": "已有巡检正在执行，请稍候再试"}
        threading.Thread(target=self._execute_cycle,
                         args=("手动立即触发", CYCLE_MANUAL),
                         daemon=True).start()
        return {"ok": True, "msg": "已触发后台维护巡检（保活 / 权益用量 / 目录 / 提醒）",
                "enabled": self.enabled}

    def _execute_cycle(self, trigger_reason="周期巡检", cycle_kind=CYCLE_HOUR):
        if not self._run_lock.acquire(blocking=False):
            self.log("跳过本次巡检 (%s)：上一轮仍在执行" % trigger_reason)
            return
        try:
            self._run_cycle(trigger_reason, cycle_kind)
        finally:
            self._run_lock.release()

    def _run_cycle(self, trigger_reason="周期巡检", cycle_kind=CYCLE_HOUR):
        started = self._now()
        self.last_run_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                           time.localtime(started))
        self.last_cycle_date = time.strftime("%Y-%m-%d",
                                             time.localtime(started))
        self.last_cycle_kind = cycle_kind
        self.log("开始执行维护巡检 (%s)..." % trigger_reason)
        accounts = [a for a in (getattr(self.pool, "accounts", []) or [])
                    if getattr(a, "enabled", True)
                    and trae_tasks._access_token(a)]
        if not accounts:
            self.log("暂无可用的活跃账号，跳过本次巡检")
            self._save_state()
            return
        result = trae_tasks.run_all_tasks(
            accounts=accounts, trigger=cycle_kind,
            pacing=self.checkin_pacing)
        for code in trae_tasks.TASK_ORDER:
            item = (result.get("results") or {}).get(code) or {}
            self.log("%s：%s" % (trae_tasks.TASK_NAMES.get(code, code),
                                item.get("summary") or ("成功" if item.get("ok")
                                                        else "失败")))
        duration = self._now() - started
        stats = {
            "trigger": trigger_reason,
            "kind": cycle_kind,
            "ok": bool(result.get("ok")),
            "duration_ms": int(duration * 1000),
            "accounts": len(accounts),
            "schedule_jitter_seconds": self.schedule_jitter_seconds,
            "checkin_pacing": self._schedule_pacing_view(),
            "tasks": {code: {"ok": bool(((result.get("results") or {})
                                         .get(code) or {}).get("ok")),
                             "summary": (((result.get("results") or {})
                                          .get(code) or {}).get("summary") or "")}
                      for code in trae_tasks.TASK_ORDER},
        }
        self.last_cycle_stats = stats
        self.history.append({
            "at": self.last_run_time,
            "trigger": trigger_reason,
            "kind": cycle_kind,
            "ok": stats["ok"],
            "accounts": len(accounts),
            "duration_ms": stats["duration_ms"],
        })
        self.history = self.history[-HISTORY_LIMIT:]
        self.log("维护巡检完成：%s（用时 %.1f 秒）"
                 % ("全部成功" if stats["ok"] else "部分失败", duration))
        self._calc_next_fire()
        self._save_state()

    # -- 看板状态 -----------------------------------------------------------
    def status(self):
        try:
            tasks = trae_tasks.task_states()
        except Exception as exc:
            tasks = {"error": str(exc)}
        accounts = [a for a in (getattr(self.pool, "accounts", []) or [])
                    if getattr(a, "enabled", True)
                    and trae_tasks._access_token(a)]
        jitter_minutes = self.schedule_jitter_seconds / 60.0
        mode = ("每日 09:00 / 21:00 + 0~%.0f 分钟随机抖动 + 启动巡检"
                "（Token 保活 · 权益用量 · 模型目录 · 到期提醒）"
                % jitter_minutes)
        return {
            "enabled": self.enabled,
            "mode": mode,
            "mode_cn": mode,
            "mode_intl": mode,
            "hours": list(self.hours),
            "last_run_time": self.last_run_time or "尚未运行",
            "next_run_time": self.next_run_time or "待调度",
            "next_run_ts": int(self.next_run_ts) if self.next_run_ts else 0,
            "next_run_slot": int(self.next_run_slot) if self.next_run_slot else 0,
            "schedule_jitter_seconds": self.schedule_jitter_seconds,
            "schedule_jitter_minutes": round(jitter_minutes, 1),
            "checkin_pacing": self._schedule_pacing_view(),
            "startup_claim_date": self.startup_claim_date or "",
            "startup_last_ts": self.startup_last_ts,
            "last_cycle_date": self.last_cycle_date or "",
            "last_cycle_kind": self.last_cycle_kind or "",
            "last_cycle_stats": self.last_cycle_stats or {},
            "state_file": self._state_path(),
            "accounts_count": len(accounts),
            "running": self._run_lock.locked(),
            "tasks": tasks,
            "history": list(reversed(self.history[-10:])),
            "logs": self.logs[-20:],
        }
