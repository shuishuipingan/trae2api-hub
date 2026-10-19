# -*- coding: utf-8 -*-
"""测试跑完后确认 checkout 没被套件弄脏（wb 同款检查）。

通过的测试必须证明自己待在临时目录里：往 checkout 里写东西的套件
不会红——只有后来发现散落文件的人才会注意到。CI 把这一步放在测试
之后（if: success()），红的测试仍然是报告的失败，这一步只是附加门。
本地也可以直接跑：

    python scripts/check_clean_checkout.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def git(args):
    return subprocess.run(
        ["git", "-C", ROOT] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def main():
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        print("not a git checkout; clean-check skipped")
        return 0
    # 未知文件（??）：套件散落的证据。已跟踪文件的修改（M）不算——
    # 那是开发者的工作，套件不该去改被跟踪文件。
    out = git(["status", "--porcelain", "--untracked-files=all"])
    if out.returncode != 0:
        print("git status failed: %s" % out.stderr.strip())
        return 1
    strays = []
    for line in out.stdout.splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        if line.startswith("?? "):
            strays.append(line[3:].strip())
    if strays:
        print("checkout has %d stray file(s) the suites left behind:" % len(strays))
        for p in strays:
            print("  %s" % p)
        return 1
    print("checkout clean: no untracked files left by the suites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
