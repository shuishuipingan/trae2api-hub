"""Panel-only administration helpers: bounded batch jobs and group summaries."""
import copy
import threading
import time
import uuid
from collections import OrderedDict


def groups_view(accounts):
    groups = {}
    for account in accounts:
        name = getattr(account, "group", "")
        row = groups.setdefault(name, {"name": name, "total": 0, "enabled": 0,
                                       "ready": 0, "realms": set()})
        row["total"] += 1
        row["enabled"] += int(bool(account.enabled))
        row["ready"] += int(bool(account.enabled and account.access_token and account.ready()))
        row["realms"].add(account.realm)
    return [dict(row, realms=sorted(row["realms"]))
            for name, row in sorted(groups.items())]


def build_overview(rows, accounts, now=None, bucket_count=36, bucket_seconds=600):
    """Six-hour traffic, exact per-account attribution; never fabricate empty activity."""
    now = time.time() if now is None else float(now)
    end = int(now // bucket_seconds) * bucket_seconds + bucket_seconds
    start = end - bucket_count * bucket_seconds
    buckets = [{"at": start+i*bucket_seconds,
                "time": time.strftime("%H:%M", time.localtime(start+i*bucket_seconds)),
                "success": 0, "failed": 0} for i in range(bucket_count)]
    per_account = {}
    for account in accounts:
        per_account[account.uid] = {"uid": account.uid, "nickname": account.nickname,
            "group": getattr(account, "group", ""), "realm": account.realm,
            "enabled": bool(account.enabled),
            "ready": bool(account.enabled and account.access_token and account.ready()),
            "success": 0, "failed": 0, "tokens": 0,
            "buckets": [0]*bucket_count}
    total_success = total_failure = tokens = unattributed = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        at = row.get("at")
        if not isinstance(at, (int, float)) or at < start or at > now:
            continue
        index = int((at-start)//bucket_seconds)
        if not 0 <= index < bucket_count:
            continue
        failed = bool(row.get("error"))
        field = "failed" if failed else "success"
        buckets[index][field] += 1
        total_failure += int(failed)
        total_success += int(not failed)
        value = row.get("total_tokens") or 0
        value = max(0, value) if isinstance(value, (int,float)) else 0
        tokens += value
        item = per_account.get(str(row.get("account") or ""))
        if item is not None:
            item[field] += 1
            item["tokens"] += value
            item["buckets"][index] += 1
        else:
            unattributed += 1
    total = total_success + total_failure
    for item in per_account.values():
        item["total"] = item["success"]+item["failed"]
        item["success_rate"] = (item["success"]*100/item["total"]) if item["total"] else None
    return {"ok": True, "generated_at": now, "window": {"from": start, "to": now,
        "minutes": bucket_count*bucket_seconds//60, "bucket_seconds": bucket_seconds},
        "traffic": {"buckets": buckets, "success": total_success, "failed": total_failure,
                    "total": total, "tokens": tokens,
                    "success_rate": (100*total_success/total) if total else None},
        "accounts": sorted(per_account.values(), key=lambda a:(-a["total"],a["nickname"])),
        "unattributed": unattributed}


class JobRegistry:
    def __init__(self, max_active=2, retain=32):
        self.max_active = max_active
        self.retain = retain
        self.lock = threading.Lock()
        self.jobs = OrderedDict()

    def get(self, job_id):
        with self.lock:
            value = self.jobs.get(job_id)
            return copy.deepcopy(value) if value else None

    def submit(self, action, group, accounts, worker):
        snapshot = list(accounts)
        with self.lock:
            active = sum(j["status"] in ("pending", "running") for j in self.jobs.values())
            # Deduplicate repeated clicks rather than performing upstream writes twice.
            for value in self.jobs.values():
                if (value["status"] in ("pending", "running") and value["group"] == group
                        and value["action"] == action):
                    return value["id"]
            if active >= self.max_active:
                raise RuntimeError("已有批量任务正在运行，请等待完成")
            while len(self.jobs) >= self.retain:
                finished = next((k for k, j in self.jobs.items()
                                 if j["status"] not in ("pending", "running")), None)
                if finished is None:
                    break
                del self.jobs[finished]
            job_id = uuid.uuid4().hex
            self.jobs[job_id] = {"id": job_id, "status": "pending", "action": action,
                                 "group": group, "total": len(snapshot), "done": 0,
                                 "results": [], "created_at": time.time(), "ok": None}
        def run():
            with self.lock:
                self.jobs[job_id]["status"] = "running"
            try:
                for account in snapshot:
                    result = {"uid": account.uid, "nickname": account.nickname}
                    try:
                        response = worker(account)
                        result.update(response if isinstance(response, dict) else {"ok": bool(response)})
                    except Exception as error:
                        result.update(ok=False, error=str(error)[:300])
                    with self.lock:
                        value = self.jobs[job_id]
                        value["results"].append(result)
                        value["done"] += 1
                with self.lock:
                    value = self.jobs[job_id]
                    value.update(status="completed", finished_at=time.time(),
                                 ok=all(row.get("ok", False) for row in value["results"]))
            except Exception as error:
                with self.lock:
                    self.jobs[job_id].update(status="failed", error=str(error)[:200],
                                            ok=False, finished_at=time.time())
        threading.Thread(target=run, name="qd-admin-" + action, daemon=True).start()
        return job_id
