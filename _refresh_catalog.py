# -*- coding: utf-8 -*-
"""_refresh_catalog.py —— 从本机 Trae 客户端重新导出双区模型快照（只读）

它做的只有三件事：读、整形、落盘。整形逻辑全在 trae_catalog.py 里
（normalize_model / build_snapshot），这里不重复实现，避免两套口径。

数据源 A（默认，最忠实）：本机客户端 SQLite 缓存
    国际版  %APPDATA%/Trae/User/globalStorage/state.vscdb
    国内版  %APPDATA%/Trae CN/User/globalStorage/state.vscdb
    ItemTable.key = "<uid>_AI.agent.model.model_list_map"
    value        = JSON: {分组 -> [模型对象, ...]}   （分组：chat_v3/builder/...）
  · 只读连接（file:...?mode=ro），不改客户端一个字节；
  · key 里的 uid 只打印长度与后缀，不落盘、不打印全文；
  · 快照里剔除 sk/ak/base_url/custom_model_id 等可能带密钥的字段（见 DROP_FIELDS）。

数据源 B（CN 兜底）：上游动态清单
    POST {core}/api/ide/v1/model_list  body {"type":"chat"}
  走 trae_client.fetch_model_list + trae_client.import_desktop_accounts
  （两者都由 doudou 的协议层提供）。这条路径只在没装/没登录客户端时用：
  动态条目没有 context_window 等字段，快照里这些位置留空，不猜。

用法：
    python _refresh_catalog.py                    # 双区从 state.vscdb 重导 + 打印差异
    python _refresh_catalog.py --dry-run          # 只看差异，不写文件
    python _refresh_catalog.py --realm cn         # 只刷国内版
    python _refresh_catalog.py --diff-detail      # 差异逐字段打印
    python _refresh_catalog.py --source cn-model-list --realm cn
    python _refresh_catalog.py --from-json X.json --realm intl   # 用已导出的 map 生成

退出码：0 = 至少一个区成功（含"无变化"）；1 = 全部失败。
"""

import argparse
import datetime
import io
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import trae_catalog as C  # noqa: E402

#: 区域 -> (客户端目录名, 快照文件名, 客户端显示名)
REALMS = {
    "intl": ("Trae", "trae_catalog_intl.json", "Trae（国际版）"),
    "cn": ("Trae CN", "trae_catalog_cn.json", "Trae CN（国内版）"),
}

KEY_SUFFIX = "_AI.agent.model.model_list_map"

COMPARE_FIELDS = ("display_name", "model_type", "multimodal", "context_window",
                  "context_window_max", "max_tokens", "is_default", "is_new",
                  "status", "enabled", "consumption_rate", "thinking", "chat")


# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------

def roaming_dir():
    """%APPDATA% 或 Linux/mac 等价位置。"""
    appdata = os.environ.get("APPDATA")
    if appdata:
        return appdata
    return os.path.join(os.path.expanduser("~"), "AppData", "Roaming")


def state_db(realm):
    """该区客户端的 state.vscdb 路径（不存在返回空串）。"""
    folder = REALMS[realm][0]
    path = os.path.join(roaming_dir(), folder, "User", "globalStorage",
                        "state.vscdb")
    return path if os.path.isfile(path) else ""


def portable_path(path):
    """仓库里只记可移植路径：把本机用户目录前缀换成 %APPDATA%。

    快照要进仓库，Windows 用户名不该跟着走；同时用 os.sep 归一，
    不在源码里写反斜杠字面量。
    """
    root = roaming_dir().replace(os.sep, "/")
    text = str(path or "").replace(os.sep, "/")
    if root and text.lower().startswith(root.lower()):
        return "%APPDATA%" + text[len(root):]
    return text


def mask_key(key):
    """只露后缀与 uid 长度：<uid:19>_AI.agent.model.model_list_map。"""
    text = str(key or "")
    if text.endswith(KEY_SUFFIX):
        return "<uid:%d>%s" % (len(text) - len(KEY_SUFFIX), KEY_SUFFIX)
    return "<key:%d>" % len(text)


# ---------------------------------------------------------------------------
# 读 SQLite（只读）
# ---------------------------------------------------------------------------

def read_model_list_map(db_path):
    """返回 (groups_map, meta)。多行命中时选模型总数最多的一行。"""
    con = sqlite3.connect("file:" + db_path + "?mode=ro", uri=True)
    try:
        rows = con.execute(
            "select key, value from ItemTable where key like ?",
            ("%" + KEY_SUFFIX,)).fetchall()
    finally:
        con.close()

    best = None
    for key, value in rows:
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        try:
            data = json.loads(text)
        except Exception:                                  # noqa: BLE001
            continue
        if not isinstance(data, dict):
            continue
        total = sum(len(v) for v in data.values() if isinstance(v, list))
        if best is None or total > best[0]:
            best = (total, key, data)

    if best is None:
        raise ValueError("state.vscdb 里没有可解析的 %s" % KEY_SUFFIX)
    _total, key, data = best
    groups = {g: [m for m in v if isinstance(m, dict)]
              for g, v in data.items() if isinstance(v, list)}
    meta = {
        "kind": "client-state-vscdb",
        "client": REALMS_META.get(db_path, ""),
        "db": portable_path(db_path),
        "db_mtime": datetime.datetime.fromtimestamp(
            os.path.getmtime(db_path)).isoformat(timespec="seconds"),
        "key": mask_key(key),
        "groups": {g: len(v) for g, v in groups.items()},
    }
    return groups, meta


#: 反查表：db 路径 -> 客户端显示名（read_model_list_map 里用）
REALMS_META = {}


def register_realm_paths():
    REALMS_META.clear()
    for realm, (_folder, _out, label) in REALMS.items():
        db = state_db(realm)
        if db:
            REALMS_META[db] = label


# ---------------------------------------------------------------------------
# 数据源 B：上游动态 model_list（CN 兜底）
# ---------------------------------------------------------------------------

def fetch_dynamic_groups(realm="cn"):
    """用协议层拉一次动态清单，整成 groups_map（只有 chat_v3 组）。"""
    import trae_client  # 延迟导入：协议层未就绪时给出可读错误

    accounts = []
    importer = getattr(trae_client, "import_desktop_accounts", None)
    if importer is not None:
        try:
            accounts = [a for a in importer()
                        if C.normalize_realm((a or {}).get("realm")
                                             or ((a or {}).get("userRegion") or {}
                                                 ).get("region")) == realm]
        except Exception as exc:                           # noqa: BLE001
            raise SystemExit("导入 Desktop 账号失败：%s" % exc)
    if not accounts:
        raise SystemExit("没有可用的 %s 账号（先在客户端登录，或让 trae_accounts 导入）"
                         % realm)
    payload = trae_client.fetch_model_list(accounts[0], realm)
    items = C.coerce_model_list(payload)                   # 与运行时同一套归一
    if not items:
        raise SystemExit("上游 model_list 返回空清单")
    meta = {"kind": "upstream-model_list", "client": REALMS[realm][2],
            "endpoint": "POST /api/ide/v1/model_list", "body": {"type": "chat"},
            "account": "<uid:%d>" % len(str(accounts[0].get("userId") or ""))}
    return {"chat_v3": items}, meta


# ---------------------------------------------------------------------------
# 差异摘要
# ---------------------------------------------------------------------------

def load_old(path):
    try:
        with io.open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:                                      # noqa: BLE001
        return {}
    models = data.get("models") if isinstance(data, dict) else data
    return {m.get("upstream_key") or m.get("key"): m
            for m in (models or []) if isinstance(m, dict)}


def summarize(old, new, detail=False):
    """打印差异；返回变化条数。"""
    changed = 0
    for key in sorted(set(old) | set(new)):
        before, after = old.get(key), new.get(key)
        if before is None:
            print("  + 新增 %s (%s)" % (key, after.get("display_name")))
            changed += 1
            continue
        if after is None:
            print("  - 下线 %s" % key)
            changed += 1
            continue
        diffs = [f for f in COMPARE_FIELDS
                 if before.get(f) != after.get(f)]
        if diffs:
            changed += 1
            print("  * %s" % key)
            for field in diffs:
                if detail or field in ("display_name", "status", "enabled"):
                    print("      %s: %r -> %r"
                          % (field, before.get(field), after.get(field)))
                else:
                    print("      %s" % field)
    if not changed:
        print("  （与现有快照一致）")
    return changed


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def write_snapshot(realm, snapshot, dry_run=False):
    path = os.path.join(HERE, REALMS[realm][1])
    if dry_run:
        print("  -> [dry-run] 不写 %s" % REALMS[realm][1])
        return
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(snapshot, ensure_ascii=False, indent=1) + "\n")
    print("  -> 写入 %s（%d 条，其中 chat 面 %d）"
          % (REALMS[realm][1], len(snapshot["models"]),
             sum(1 for m in snapshot["models"] if m.get("chat"))))


def refresh_realm(realm, args):
    """刷一个区；返回 True/False（成功与否）。"""
    print("=" * 70)
    print("[%s] %s" % (realm, REALMS[realm][2]))
    try:
        if args.from_json:
            with io.open(args.from_json, encoding="utf-8") as fh:
                groups = json.load(fh)
            meta = {"kind": "local-json", "client": REALMS[realm][2],
                    "file": os.path.basename(args.from_json)}
        elif args.source == "cn-model-list":
            groups, meta = fetch_dynamic_groups(realm)
        else:
            db = state_db(realm)
            if not db:
                print("  ! 未找到客户端数据库（该区客户端未安装/未登录）：%s"
                      % os.path.join(roaming_dir(), REALMS[realm][0]))
                return False
            groups, meta = read_model_list_map(db)
            print("  源: %s（本机绝对路径不落盘）" % meta["db"])
            print("  key: %s  分组: %s" % (meta["key"], meta["groups"]))
    except SystemExit as exc:
        print("  ! %s" % exc)
        return False
    except Exception as exc:                               # noqa: BLE001
        print("  ! 读取失败(%s): %s" % (exc.__class__.__name__, exc))
        return False

    snapshot = C.build_snapshot(realm, groups, source=meta,
                                generated_at=int(time.time()))
    chat_count = sum(1 for m in snapshot["models"] if m.get("chat"))
    print("  解析: 全量 %d 条 / chat 面 %d 条 / chat 分组 %s"
          % (len(snapshot["models"]), chat_count, snapshot["chat_groups"]))

    old = load_old(os.path.join(HERE, REALMS[realm][1]))
    summarize(old, {m["upstream_key"]: m for m in snapshot["models"]},
              detail=args.diff_detail)
    write_snapshot(realm, snapshot, dry_run=args.dry_run)
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="从本机 Trae 客户端重导双区模型快照（只读）")
    ap.add_argument("--realm", choices=("intl", "cn", "both"), default="both",
                    help="默认 both")
    ap.add_argument("--dry-run", action="store_true", help="只打印差异，不写文件")
    ap.add_argument("--diff-detail", action="store_true", help="差异逐字段打印")
    ap.add_argument("--source", choices=("cache", "cn-model-list"), default="cache",
                    help="cache=本机 state.vscdb（默认）；cn-model-list=上游动态清单")
    ap.add_argument("--from-json", default="",
                    help="从已导出的 model_list_map JSON 生成（离线）")
    args = ap.parse_args(argv)

    register_realm_paths()
    targets = ("intl", "cn") if args.realm == "both" else (args.realm,)
    ok = 0
    for realm in targets:
        if refresh_realm(realm, args):
            ok += 1

    if not args.dry_run and ok:
        # 写完立刻按运行时口径复算一遍，防止"生成了但读不出来"
        report = C.reload()
        print("=" * 70)
        for realm in ("intl", "cn"):
            info = report[realm]
            print("[%s] 运行时读取: source=%s chat=%d all=%d groups=%s"
                  % (realm, info["source"], info["chat_models"],
                     info["all_models"], ",".join(info["groups"])))
    print("=" * 70)
    print("刷新完成: %d/%d 区成功" % (ok, len(targets)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
