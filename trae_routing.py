"""Local route orchestration adapted to the CN/INTL account pool.

Rules never rewrite API keys or models, and cannot expand an API key's account
scope. Preview is side-effect free. A matching unavailable route fails closed.
"""
import fnmatch
import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path

_LOCK = threading.RLock()
_CACHE = {}
STRATEGIES = ("round-robin", "weighted-round-robin", "fill-first")
_SELECTOR_STATE = {}
DEFAULT_POLICY = {"strategy": "round-robin", "session_affinity": True,
                  "request_retry": 0, "max_retry_accounts": 0}


def _strings(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 256:
        raise ValueError(field + " must be a list of at most 256 strings")
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 160:
            raise ValueError(field + " contains an invalid value")
        text = item.strip()
        if (text or field == "groups") and text not in result:
            result.append(text)
    return result


def normalize_rules(rules):
    if not isinstance(rules, list) or len(rules) > 128:
        raise ValueError("rules must contain at most 128 entries")
    cleaned, ids = [], set()
    for index, item in enumerate(rules):
        if not isinstance(item, dict):
            raise ValueError("each routing rule must be an object")
        rule_id = str(item.get("id") or uuid.uuid4().hex).strip()[:80]
        if rule_id in ids:
            raise ValueError("duplicate routing rule id")
        ids.add(rule_id)
        model = str(item.get("model") or "*").strip()
        if not model or len(model) > 160:
            raise ValueError("invalid model pattern")
        realm = str(item.get("realm") or "").strip().lower()
        if realm not in ("", "cn", "intl"):
            raise ValueError("realm must be cn, intl or empty")
        strategy = str(item.get("strategy") or "round-robin")
        if strategy not in STRATEGIES:
            raise ValueError("unsupported routing strategy")
        try:
            priority = max(-10000, min(10000, int(item.get("priority", index))))
        except (ValueError, TypeError):
            raise ValueError("priority must be an integer")
        cleaned.append({"id": rule_id, "name": str(item.get("name") or "未命名规则").strip()[:100],
                        "enabled": item.get("enabled", True) is not False,
                        "model": model, "realm": realm, "strategy": strategy,
                        "groups": _strings(item.get("groups"), "groups"),
                        "accounts": _strings(item.get("accounts"), "accounts"),
                        "key_ids": _strings(item.get("key_ids"), "key_ids"),
                        "priority": priority})
    return sorted(cleaned, key=lambda r: r["priority"])


def rules_path(directory):
    # Subdirectory deliberately avoids collision with <account uid>.json files.
    return Path(directory) / "admin" / "routing.json"


def normalize_policy(value):
    if value is None:
        return dict(DEFAULT_POLICY)
    if not isinstance(value, dict):
        raise ValueError("policy must be an object")
    strategy = value.get("strategy", "round-robin")
    if strategy not in STRATEGIES:
        raise ValueError("unsupported routing strategy")
    affinity = value.get("session_affinity", True)
    if not isinstance(affinity, bool):
        raise ValueError("session_affinity must be boolean")
    result = {"strategy": strategy, "session_affinity": affinity}
    for name, maximum in (("request_retry", 3), ("max_retry_accounts", 256)):
        v = value.get(name, 0)
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= maximum:
            raise ValueError(name + " is outside supported range")
        result[name] = v
    return result


def normalize_tiers(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("tiers must be a list of at most 64 layers")
    result, seen, tier_ids = [], set(), set()
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError("each tier must be an object")
        uid = str(item.get("id") or uuid.uuid4().hex).strip()[:80]
        if uid in tier_ids:
            raise ValueError("duplicate tier id")
        tier_ids.add(uid)
        accounts = _strings(item.get("accounts"), "accounts")
        if seen.intersection(accounts):
            raise ValueError("an account may belong to only one tier")
        seen.update(accounts)
        weights = item.get("weights", {})
        if not isinstance(weights, dict):
            raise ValueError("weights must be an object")
        clean_weights = {}
        for account in accounts:
            weight = weights.get(account, 1)
            if isinstance(weight, bool) or not isinstance(weight, int) or not 0 <= weight <= 1000000:
                raise ValueError("account weight must be integer 0..1000000")
            clean_weights[account] = weight
        result.append({"id": uid, "name": str(item.get("name") or ("首选" if i == 0 else "备用层"))[:80],
                       "accounts": accounts, "weights": clean_weights})
    return result


def load_config(directory, _shared=False):
    """Stat-keyed immutable snapshot; only admin callers receive independent copies.

    Runtime resolves reuse parsed plans. Atomic saves invalidate immediately;
    external edits invalidate on inode/size/mtime/ctime (no TTL stale window).
    """
    path = rules_path(directory)
    cache_key = str(path)
    try:
        st = path.stat()
    except FileNotFoundError:
        with _LOCK:
            _CACHE.pop(cache_key, None)
        return {"rules": [], "tiers": [], "policy": dict(DEFAULT_POLICY),
                "configured": False, "board_enabled": False, "revision": "empty"}
    stamp = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    with _LOCK:
        cached = _CACHE.get(cache_key)
        if cached and cached[0] == stamp:
            return cached[1] if _shared else json.loads(cached[2])
    # fstat the descriptor read, not a possibly replaced pathname.
    with path.open("rb") as fh:
        fst = os.fstat(fh.fileno())
        raw = fh.read()
    latest = path.stat()
    # Windows stat(path).ctime is creation time while fstat.ctime may be change time.
    # Cache only when path still names the exact descriptor snapshot we read.
    stable = (latest.st_dev, latest.st_ino, latest.st_size, latest.st_mtime_ns) == (
        fst.st_dev, fst.st_ino, fst.st_size, fst.st_mtime_ns)
    stamp = (latest.st_dev, latest.st_ino, latest.st_size, latest.st_mtime_ns, latest.st_ctime_ns)
    revision = hashlib.sha256(raw).hexdigest()
    try:
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise ValueError("expected configuration object")
        result = {"rules": normalize_rules(body.get("rules", [])),
                  "tiers": normalize_tiers(body.get("tiers", [])),
                  "policy": normalize_policy(body.get("policy")),
                  "configured": "policy" in body or bool(body.get("tiers")),
                  "board_enabled": body.get("board_enabled", bool(body.get("tiers"))),
                  "revision": revision}
    except Exception as error:
        raise ValueError("routing configuration invalid: " + str(error)[:120])
    with _LOCK:
        if len(_CACHE) >= 16:
            _CACHE.clear()
        if stable:
            _CACHE[cache_key] = (stamp, result, json.dumps(result, ensure_ascii=False))
    return result if _shared else json.loads(json.dumps(result, ensure_ascii=False))


def load_rules(directory):
    return load_config(directory)["rules"]


def save_config(directory, rules=None, tiers=None, policy=None, expected_revision=None):
    path = rules_path(directory)
    with _LOCK:
        old = load_config(directory)
        if expected_revision is not None and expected_revision != old["revision"]:
            raise ValueError("routing_conflict: 配置已被其他窗口修改，请重新加载后再保存")
        cleaned = normalize_rules(rules) if rules is not None else old["rules"]
        layers = normalize_tiers(tiers) if tiers is not None else old["tiers"]
        settings = normalize_policy(policy) if policy is not None else old["policy"]
        document = {"rules": cleaned, "updated_at": time.time()}
        # Legacy rule-only saves must not opt old installations into new policy.
        if policy is not None or tiers is not None or old["configured"]:
            document.update(tiers=layers, policy=settings,
                            board_enabled=True if tiers is not None else old.get("board_enabled", False))
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name("routing.%s.tmp" % uuid.uuid4().hex)
        try:
            temp.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temp, path)
        finally:
            if temp.exists():
                temp.unlink()
        _CACHE.pop(str(path), None)
        return load_config(directory)


def save_rules(directory, rules):
    return save_config(directory, rules=rules)["rules"]


def scope_uids(accounts, ids=None, groups=None):
    ids, groups = set(ids or []), set(groups or [])
    if not ids and not groups:
        return None
    return {a.uid for a in accounts if a.uid in ids or getattr(a, "group", "") in groups}


def resolve(directory, accounts, model, key=None, explicit_realm=None, config=None):
    key = key or {}
    config = load_config(directory, _shared=True) if config is None else config
    key_realm = key.get("realm") or ""
    if key_realm and explicit_realm and key_realm != explicit_realm:
        raise ValueError("API Key realm conflicts with requested realm")
    forced = key_realm or explicit_realm or ""
    allowed = scope_uids(accounts, key.get("account_ids"), key.get("account_groups"))
    matched = None
    for rule in config["rules"]:
        if not rule["enabled"] or not fnmatch.fnmatchcase(str(model).lower(), rule["model"].lower()):
            continue
        if rule["key_ids"] and str(key.get("id") or "") not in rule["key_ids"]:
            continue
        if forced and rule["realm"] and forced != rule["realm"]:
            continue
        matched = rule
        scope = scope_uids(accounts, rule["accounts"], rule["groups"])
        if scope is not None:
            allowed = scope if allowed is None else allowed & scope
        break
    realm = forced or (matched or {}).get("realm") or ""
    if realm:
        within = {a.uid for a in accounts if a.realm == realm}
        allowed = within if allowed is None else allowed & within
    tiers = config.get("tiers", [])
    if tiers or config.get("board_enabled"):
        tier_scope = {uid for tier in tiers for uid in tier["accounts"]}
        allowed = tier_scope if allowed is None else allowed & tier_scope
    policy = dict(config.get("policy") or DEFAULT_POLICY)
    strategy = policy["strategy"] if tiers or config.get("configured") else (matched or {}).get("strategy") or "round-robin"
    return {"matched": matched, "realm": realm, "strategy": strategy,
            "allowed_uids": allowed, "tiers": tiers, "policy": policy,
            "configured": config.get("configured", False),
            "scope_id": str(directory)+":"+str(key.get("id") or "")+":"+(matched or {}).get("id", "")}


def _ready(account, model):
    return bool(account and account.enabled and account.access_token and account.ready(model=model))


def candidates(pool, decision, realm, model, exclude=None):
    allowed, excluded = decision.get("allowed_uids"), set(exclude or [])
    ready = {a.uid: a for a in list(pool.accounts) if a.realm == realm
             and a.uid not in excluded and (allowed is None or a.uid in allowed)
             and _ready(a, model)}
    tiers = decision.get("tiers") or []
    if not tiers:
        return list(ready.values()), None
    for tier in tiers:
        rows = [ready[uid] for uid in tier["accounts"] if uid in ready
                and (decision["strategy"] != "weighted-round-robin" or tier["weights"].get(uid, 1) > 0)]
        if rows:
            return rows, tier
    return [], None


def pick(pool, decision, realm, model, session_key=None, exclude=None):
    excluded, allowed = set(exclude or []), decision.get("allowed_uids")
    policy = decision.get("policy") or DEFAULT_POLICY
    affinity = bool(policy.get("session_affinity", True))
    tiers = decision.get("tiers") or []
    if affinity and session_key:
        uid = pool.affinity.get(session_key)
        bound = pool.get(uid) if uid else None
        weight_ok = not tiers or decision["strategy"] != "weighted-round-robin" or any(
            uid in t["accounts"] and t["weights"].get(uid, 1) > 0 for t in tiers)
        if (bound and bound.realm == realm and uid not in excluded
                and (allowed is None or uid in allowed) and weight_ok and _ready(bound, model)):
            return bound
    strategy = decision.get("strategy", "round-robin")
    if not tiers and strategy == "round-robin":
        options = {"allowed_uids": allowed} if allowed is not None else {}
        return pool.pick_for_session(realm=realm, session_key=session_key if affinity else None,
                                     exclude=excluded, model=model, **options)
    rows, tier = candidates(pool, decision, realm, model, excluded)
    if not rows:
        return None
    if strategy == "fill-first":
        chosen = rows[0]
    else:
        state_key = (decision.get("scope_id", ""), realm, model, (tier or {}).get("id", "all"), strategy,
                     tuple((a.uid, (tier or {}).get("weights", {}).get(a.uid, 1)) for a in rows))
        with _LOCK:
            if len(_SELECTOR_STATE) >= 512 and state_key not in _SELECTOR_STATE:
                _SELECTOR_STATE.pop(next(iter(_SELECTOR_STATE)))
            if strategy == "weighted-round-robin":
                state = _SELECTOR_STATE.setdefault(state_key, {})
                weights = {a.uid: (tier or {}).get("weights", {}).get(a.uid, 1) for a in rows}
                total = sum(weights.values())
                for a in rows:
                    state[a.uid] = state.get(a.uid, 0) + weights[a.uid]
                chosen = max(rows, key=lambda a: state[a.uid])
                state[chosen.uid] -= total
            else:
                cursor = _SELECTOR_STATE.get(state_key, 0)
                chosen = rows[cursor % len(rows)]
                _SELECTOR_STATE[state_key] = cursor+1
    if affinity and session_key:
        pool.affinity.bind(session_key, chosen.uid)
    return chosen


def preview(directory, accounts, model, key=None, realm=None, config=None, fallback_realm=None):
    decision = resolve(directory, accounts, model, key, realm, config=config)
    if not decision["realm"] and fallback_realm:
        decision["realm"] = fallback_realm
        within = {a.uid for a in accounts if a.realm == fallback_realm}
        decision["allowed_uids"] = within if decision["allowed_uids"] is None else decision["allowed_uids"] & within
    scope, tiers = decision["allowed_uids"], decision["tiers"]
    all_rows, tier_rows, active = [], [], None
    layers = tiers or [{"id": "default", "name": "默认层", "accounts": [a.uid for a in accounts], "weights": {}}]
    account_map = {a.uid:a for a in accounts}
    for tier in layers:
        members = []
        for uid in tier["accounts"]:
            a = account_map.get(uid)
            if a is None:
                continue
            allowed = (scope is None or uid in scope) and (not decision["realm"] or a.realm == decision["realm"])
            weight = tier.get("weights", {}).get(uid, 1)
            ready = allowed and _ready(a, model) and (decision["strategy"] != "weighted-round-robin" or weight > 0)
            members.append({"uid": uid, "nickname": a.nickname, "group": getattr(a, "group", ""),
                            "realm": a.realm, "ready": bool(ready), "allowed": bool(allowed), "weight": weight})
        serving = any(m["ready"] for m in members)
        state = "active" if serving and active is None else "standby" if serving else "skipped"
        if state == "active":
            active = tier["id"]
        ready_members = [m for m in members if m["ready"]]
        total_weight = sum(m["weight"] if decision["strategy"] == "weighted-round-robin" else 1 for m in ready_members)
        for i, m in enumerate(ready_members):
            m["share"] = (100.0 if i == 0 else 0.0) if decision["strategy"] == "fill-first" else (
                (m["weight"] if decision["strategy"] == "weighted-round-robin" else 1)*100/total_weight if total_weight else 0)
        tier_rows.append({"id": tier["id"], "name": tier["name"], "state": state, "members": members})
        all_rows.extend(m for m in members if m["allowed"])
    return {"ok": True, "matched": decision["matched"], "realm": decision["realm"],
            "strategy": decision["strategy"], "policy": decision["policy"], "tiers": tier_rows,
            "active_tier": active, "eligible_accounts": all_rows,
            "blocked_reason": "没有符合账号范围且可用的账号" if active is None else "",
            "note": "预览不包含会话粘性、进行中请求及动态模型限流；实际选号继续执行这些约束。"}
