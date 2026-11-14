# -*- coding: utf-8 -*-
"""sync-upstream.py —— 让 fork 与上游保持一致

三件事，按顺序做，每步都可单独执行：

  1. `--check`    看上游有没有新提交、fork 落后多少
  2. `--sync`     把 fork 的 main 快进到上游最新，并推回 origin
  3. `--rebase`   把特性分支 rebase 到最新上游，冲突就停下让人处理

设计前提：**特性分支的改动是纯增量的**（trae_proxy.py +187/-0，其余是新文件），
所以 rebase 在绝大多数上游更新下都不会冲突。真冲突时脚本不做任何自动取舍，
直接停下并打印冲突文件——自动"帮你想办法"是这类脚本最容易埋雷的地方。

用法：
    python sync-upstream.py --check
    python sync-upstream.py --sync
    python sync-upstream.py --rebase
    python sync-upstream.py --all        # sync + rebase
"""

import argparse
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

REPO = os.path.dirname(os.path.abspath(__file__))
BRANCH = "feat/qoder-upstream"
UPSTREAM = "upstream"
ORIGIN = "origin"


def git(*args, check=True, capture=True):
    """跑一条 git 命令。capture=False 时直接透传输出（给交互/长输出用）。"""
    cmd = ["git"] + list(args)
    if capture:
        proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if check and proc.returncode != 0:
            raise RuntimeError("git %s 失败：%s" % (" ".join(args),
                                                   proc.stderr.strip()))
        return proc.stdout.strip()
    proc = subprocess.run(cmd, cwd=REPO)
    if check and proc.returncode != 0:
        raise RuntimeError("git %s 失败（exit=%d）" % (" ".join(args),
                                                     proc.returncode))
    return ""


def current_branch():
    return git("branch", "--show-current")


def require_clean():
    dirty = git("status", "--porcelain")
    if dirty:
        print("! 工作区不干净，先提交或 stash：")
        for line in dirty.splitlines():
            print("   ", line)
        return False
    return True


def do_check():
    print("=== 拉取上游 ===")
    git("fetch", UPSTREAM, "--tags", check=False)
    git("fetch", ORIGIN, check=False)

    upstream_head = git("rev-parse", "--short", UPSTREAM + "/main")
    upstream_subj = git("log", "-1", "--pretty=%s", UPSTREAM + "/main")
    origin_head = git("rev-parse", "--short", ORIGIN + "/main")

    behind = int(git("rev-list", "--count",
                     "%s/main..%s/main" % (ORIGIN, UPSTREAM)))
    ahead = int(git("rev-list", "--count",
                    "%s/main..%s/main" % (UPSTREAM, ORIGIN)))

    print("\n上游 main   : %s  %s" % (upstream_head, upstream_subj))
    print("fork  main  : %s" % origin_head)
    print("状态        : fork 领先 %d，落后 %d" % (ahead, behind))

    if git("rev-parse", "--verify", BRANCH, check=False):
        # `A..B` 数的是「B 有而 A 没有」的提交，两个方向别写反：
        #   upstream/main..BRANCH  -> 本分支自己的改动（ahead）
        #   BRANCH..upstream/main  -> 上游新增、本分支还没有（behind，需要 rebase）
        feat_ahead = int(git("rev-list", "--count",
                             "%s/main..%s" % (UPSTREAM, BRANCH)))
        feat_behind = int(git("rev-list", "--count",
                              "%s..%s/main" % (BRANCH, UPSTREAM)))
        print("特性分支    : %s 领先上游 %d，落后 %d"
              % (BRANCH, feat_ahead, feat_behind))
        if feat_behind:
            print("             → 需要 rebase 才能跟上上游")

    if behind:
        print("\n→ 建议执行：python sync-upstream.py --sync")
    else:
        print("\n✓ fork 的 main 已与上游一致")
    return 0


def do_sync():
    if not require_clean():
        return 1
    print("=== 同步 main 到上游 ===")
    git("fetch", UPSTREAM, "--tags", check=False)
    original = current_branch()
    try:
        git("checkout", "main")
        # --ff-only：宁可失败也不造出合并提交。fork 的 main 不应该有本地提交，
        # 一旦有就说明有人在 main 上直接干活了，那要人来判断，不是脚本该猜的。
        proc = subprocess.run(["git", "merge", "--ff-only",
                               UPSTREAM + "/main"], cwd=REPO,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            print("! 无法快进合并（main 上可能有本地提交）：")
            print(proc.stdout.strip() or proc.stderr.strip())
            return 1
        print(proc.stdout.strip())
        git("push", ORIGIN, "main")
        print("✓ main 已同步并推送")
    finally:
        if original and original != "main":
            git("checkout", original, check=False)
    return 0


def do_rebase():
    if not require_clean():
        return 1
    print("=== 把 %s rebase 到上游最新 ===" % BRANCH)
    git("fetch", UPSTREAM, "--tags", check=False)
    original = current_branch()
    try:
        git("checkout", BRANCH)
        proc = subprocess.run(["git", "rebase", UPSTREAM + "/main"], cwd=REPO,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            print("! rebase 冲突，已停下（不做自动取舍）")
            print(proc.stdout.strip())
            print(proc.stderr.strip())
            print("\n冲突文件：")
            for line in git("diff", "--name-only", "--diff-filter=U").splitlines():
                print("   ", line)
            print("\n处理完执行 `git rebase --continue`；"
                  "想放弃执行 `git rebase --abort`。")
            return 1
        print("✓ rebase 干净完成")
        # --force-with-lease：只在远端仍是我们上次看到的状态时才覆盖，
        # 避免把别人推到这条分支上的提交静默冲掉。
        git("push", "--force-with-lease", ORIGIN, BRANCH)
        print("✓ 已推送到 fork")
    finally:
        if original and original != BRANCH:
            git("checkout", original, check=False)
    return 0


def main():
    ap = argparse.ArgumentParser(description="让 fork 与上游保持一致")
    ap.add_argument("--check", action="store_true", help="只看差异")
    ap.add_argument("--sync", action="store_true", help="快进 main 到上游")
    ap.add_argument("--rebase", action="store_true", help="特性分支 rebase 到上游")
    ap.add_argument("--all", action="store_true", help="sync + rebase")
    args = ap.parse_args()

    if not (args.check or args.sync or args.rebase or args.all):
        ap.print_help()
        return 0

    if args.all:
        args.sync = True
        args.rebase = True

    rc = 0
    if args.sync:
        rc = do_sync() or rc
    if args.rebase:
        rc = do_rebase() or rc
    if args.check:
        rc = do_check() or rc
    return rc


if __name__ == "__main__":
    sys.exit(main())
