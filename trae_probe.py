
"""trae_probe.py —— 模型自动探测（最小请求验证可用性）

只做两件事：
  1) 用最小 chat 请求探测某个模型是否真的能出字（不是只看目录里的 enable）；
  2) 把结果按 模型+区域 持久化到 usage/model_health.json，供 /v1/models 与看板读取。

不参与路由、不刷新 token、不轮换账号；任何异常都记录为探测结果，不抛出到调度器。
"""
import json
import os
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HEALTH = os.path.join(HERE, "usage", "model_health.json")
_lock = threading.RLock()
_cache = {"mtime": None, "data": None}


def health_path():
    return os.environ.get("TRAE_MODEL_HEALTH") or DEFAULT_HEALTH


def set_health_path(path):
    """让 proxy 的 --usage-dir 与探测结果落盘位置保持一致。"""
    global DEFAULT_HEALTH
    if path:
        DEFAULT_HEALTH = path
        _cache["mtime"] = None
        _cache["data"] = None


def load_health(force=False):
    path = health_path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    with _lock:
        if not force and _cache["data"] is not None and _cache["mtime"] == mtime:
            return _cache["data"]
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            data = {"updated_at": 0, "models": {}}
        if not isinstance(data, dict):
            data = {"updated_at": 0, "models": {}}
        data.setdefault("models", {})
        _cache.update({"mtime": mtime, "data": data})
        return data


def save_health(data):
    path = health_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with _lock:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
        _cache["mtime"] = os.path.getmtime(path)
        _cache["data"] = data


def health_for(model, realm=None):
    data = load_health()
    realms = data.get("models") or {}
    if realm:
        return (realms.get(realm) or {}).get(model)
    for bucket in realms.values():
        if isinstance(bucket, dict) and model in bucket:
            return bucket[model]
    return None


def _bucket(data, realm):
    return data["models"].setdefault(realm, {})


def _status_from_error(exc):
    code = getattr(exc, "code", None)
    text = str(exc or "")
    if code in (4015, 4019) or "risk control" in text.lower():
        return "risk_control"
    if code in (4023, 4003) or "model" in text.lower() and "not" in text.lower():
        return "unavailable"
    if code in (401, 403):
        return "auth"
    if code in (429,):
        return "rate_limited"
    return "error"


def probe_one(account, model, realm, timeout=60):
    """探测单个模型；永远返回 dict，不抛异常。"""
    import trae_client as client
    started = time.time()
    result = {
        "model": model, "realm": realm, "ok": False, "status": "error",
        "at": started, "elapsed_ms": 0, "error": "", "reply": "",
        "prompt_tokens": 0, "completion_tokens": 0, "account": "",
    }
    try:
        result["account"] = str(getattr(account, "uid", "") or "")[-4:]
    except Exception:
        pass
    try:
        out = client.chat_once(
            account, realm=realm, model=model,
            messages=[{"role": "user", "content": "只回复 OK"}],
            stream=True, max_tokens=8, temperature=0, timeout=timeout)
        result["elapsed_ms"] = int((time.time() - started) * 1000)
        usage = out.get("usage") or {}
        result["prompt_tokens"] = int(usage.get("prompt_tokens") or 0)
        result["completion_tokens"] = int(usage.get("completion_tokens") or 0)
        errors = out.get("errors") or []
        text = str(out.get("text") or "").strip()
        result["reply"] = text[:80]
        if errors:
            err = errors[0] if isinstance(errors[0], dict) else {"message": str(errors[0])}
            code = err.get("code")
            result["status"] = "risk_control" if code in (4015, 4019) else "error"
            result["error"] = (err.get("message") or err.get("error") or
                               ("上游错误 %s" % code))[:300]
        else:
            result["ok"] = True
            result["status"] = "ok"
        return result
    except Exception as exc:                           # noqa: BLE001
        result["elapsed_ms"] = int((time.time() - started) * 1000)
        result["status"] = _status_from_error(exc)
        result["error"] = str(exc)[:300]
        return result


def probe_models(accounts, models, limit=None, force=False, stale_seconds=86400,
                 on_progress=None, stop_event=None):
    """按模型探测；accounts/models 由调用方提供（避免与 proxy 循环依赖）。

    models: [{"key":..., "realm":..., "meta":...}]
    accounts: Account 对象列表
    limit: 最多探测多少个（0/None 表示全部）
    force: 忽略 24h 内的旧成功结果
    返回 {results, summary, started_at, finished_at}
    """
    data = load_health()
    results = []
    skipped = 0
    ok = failed = 0
    started = time.time()
    accounts = list(accounts or [])
    models = list(models or [])
    # 先筛掉“新鲜且成功”的旧结果，再截 limit —— 否则前 N 个都健康时，
    # 单轮永远轮不到后面的失败/新模型。
    pending = []
    cached_rows = []
    for item in models:
        key = item.get("key") or item.get("model")
        realm = item.get("realm") or "cn"
        if not key:
            continue
        old = health_for(key, realm)
        if (not force and isinstance(old, dict) and old.get("ok")
                and time.time() - float(old.get("at") or 0) < stale_seconds):
            skipped += 1
            cached_rows.append((key, old))
            results.append(dict(old, cached=True))
        else:
            pending.append(item)
    if limit:
        pending = pending[:int(limit)]
    total = len(pending) + len(cached_rows)
    done = 0
    for key, old in cached_rows:
        done += 1
        if on_progress:
            on_progress(done, total, key, dict(old, cached=True))
    for index, item in enumerate(pending):
        if stop_event is not None and stop_event.is_set():
            break
        key = item.get("key") or item.get("model")
        realm = item.get("realm") or "cn"
        candidates = [a for a in accounts
                      if getattr(a, "enabled", True)
                      and getattr(a, "realm", realm) == realm]
        if not candidates:
            row = {"model": key, "realm": realm, "ok": False,
                   "status": "no_account", "at": time.time(),
                   "elapsed_ms": 0, "error": "该区域没有可用账号", "reply": ""}
            results.append(row)
            failed += 1
        else:
            account = candidates[(done) % len(candidates)]
            row = probe_one(account, key, realm)
            results.append(row)
            if row.get("ok"):
                ok += 1
            else:
                failed += 1
        with _lock:
            _bucket(data, realm)[key] = row
            data["updated_at"] = time.time()
            # 每探测完一个就落盘：中途被杀也能保留结果
            save_health(data)
        done += 1
        if on_progress:
            on_progress(done, total, key, row)
        # 轻间隔：避免探测本身触发上游频控
        if done < total:
            time.sleep(0.5)
    finished = time.time()
    summary = {"total": total, "ok": ok, "failed": failed, "skipped": skipped,
               "started_at": started, "finished_at": finished}
    return {"results": results, "summary": summary, "model_health": data}
