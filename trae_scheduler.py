# -*- coding: utf-8 -*-
"""trae_scheduler.py —— Trae 维护巡检调度器

Trae 没有每日签到，调度器的职责改为**维护巡检**：
  每日 09:00 / 21:00 + 进程启动巡检，按顺序执行 trae_tasks 的四项任务：
    1. token_keepalive  access token 到期前 24 小时轮换刷新
    2. usage_refresh    权益 / 用量刷新
    3. catalog_refresh  模型目录刷新
    4. expiry_reminder  凭证与权益到期提醒

状态落盘：<usage>/scheduler.json（tmp + os.replace 原子写）
  · **不写 accounts/**：账号池会扫描该目录下所有 JSON，状态文件放进去会产生
    「缺少 uid，已跳过」告警与潜在误判；本文件与 tasks.json 一起放在 usage/；
  · 兼容迁移旧路径 <账号目录>/scheduler.json 与 <账号目录>/scheduler/state.json，
    迁移成功后只清理「无 uid 且像调度状态」的旧文件，绝不碰账号；
  · enabled / last_run_time / next_run_time / logs / history 重启后全部保留；
  · 启动巡检有 30 分钟去抖，避免重启风暴连续打上游；整点排程不受影响。

看板接口（trae_proxy.py 现有路由）保持不变：
  GET  /scheduler          -> status()
  POST /scheduler/trigger  -> trigger_now()
  POST /scheduler/toggle   -> 直接翻 enabled 后调用 log()（log 会落盘）
"""
import json
import os
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
STARTUP_DELAY = 10                # 启动后等主服务就绪
STARTUP_MIN_INTERVAL = 30 * 60    # 启动巡检去抖（秒）
LOG_LIMIT = 80
HISTORY_LIMIT = 60
STATE_VERSION = 2


class Scheduler(object):
    def __init__(self, pool, state_dir=None):
        self.pool = pool
        self.hours = list(SCHEDULE_HOURS)
        self.all_hours = sorted(set(self.hours))
        self._stop_event = threading.Event()
        self._thread = None
        self._run_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._last_fired_key = None
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
        self.log("后台维护调度器已启动（每日 09:00 / 21:00 + 启动巡检）")

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
        self.log("用户切换调度器状态为: %s" % ("启用" if value else "暂停"))
        return self.status()

    def enable(self):
        return self.set_enabled(True)

    def disable(self):
        return self.set_enabled(False)

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
        else:
            self.log("启动巡检跳过：%d 分钟内已执行过，避免重启重复打上游"
                     % (STARTUP_MIN_INTERVAL // 60))

        while not self._stop_event.is_set():
            self._calc_next_fire()
            now = time.localtime()
            fire_key = (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour)
            if (self.enabled and now.tm_min == 0
                    and now.tm_hour in self.all_hours
                    and fire_key != self._last_fired_key):
                self._last_fired_key = fire_key
                try:
                    self._execute_cycle("整点排程命中 (%02d:00)" % now.tm_hour,
                                        CYCLE_HOUR)
                except Exception as exc:
                    self.log("排程执行异常: %s" % exc)
                self._stop_event.wait(65)   # 避开当前这一分钟重复触发
                continue
            self._stop_event.wait(20)

    def _calc_next_fire(self):
        now = time.time()
        local = time.localtime(now)
        candidates = []
        for day_offset in (0, 1):
            for hour in self.all_hours:
                stamp = time.mktime((local.tm_year, local.tm_mon, local.tm_mday,
                                     hour, 0, 0, 0, 0, -1))
                stamp += day_offset * 86400
                if stamp > now + 5:
                    candidates.append(stamp)
        self.next_run_time = (time.strftime("%Y-%m-%d %H:%M:%S",
                                           time.localtime(min(candidates)))
                              if candidates else "")

    def _allow_startup(self):
        """启动巡检去抖：同一天且 30 分钟内已跑过则跳过（先标记再动作）。"""
        now = time.time()
        today = time.strftime("%Y-%m-%d")
        if (self.startup_claim_date == today
                and now - self.startup_last_ts < STARTUP_MIN_INTERVAL):
            return False
        self.startup_claim_date = today
        self.startup_last_ts = now
        self._save_state()
        return True

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
        started = time.time()
        self.last_run_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.last_cycle_date = time.strftime("%Y-%m-%d")
        self.last_cycle_kind = cycle_kind
        self.log("开始执行维护巡检 (%s)..." % trigger_reason)
        accounts = [a for a in (getattr(self.pool, "accounts", []) or [])
                    if getattr(a, "enabled", True)
                    and trae_tasks._access_token(a)]
        if not accounts:
            self.log("暂无可用的活跃账号，跳过本次巡检")
            self._save_state()
            return
        result = trae_tasks.run_all_tasks(accounts=accounts, trigger=cycle_kind)
        for code in trae_tasks.TASK_ORDER:
            item = (result.get("results") or {}).get(code) or {}
            self.log("%s：%s" % (trae_tasks.TASK_NAMES.get(code, code),
                                item.get("summary") or ("成功" if item.get("ok")
                                                        else "失败")))
        duration = time.time() - started
        stats = {
            "trigger": trigger_reason,
            "kind": cycle_kind,
            "ok": bool(result.get("ok")),
            "duration_ms": int(duration * 1000),
            "accounts": len(accounts),
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
        mode = ("每日 09:00 / 21:00 维护巡检 + 启动巡检"
                "（Token 保活 · 权益用量 · 模型目录 · 到期提醒）")
        return {
            "enabled": self.enabled,
            "mode": mode,
            "mode_cn": mode,
            "mode_intl": mode,
            "hours": list(self.hours),
            "last_run_time": self.last_run_time or "尚未运行",
            "next_run_time": self.next_run_time or "待调度",
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
