# -*- coding: utf-8 -*-
"""issue4 静态打包 / 权限回归测试（离线、零依赖、不读任何凭证）

背景
  · 受版本控制的 *.sh 在 git 索引里是 100644 —— git clone / CI checkout 出来
    没有执行位，Linux/macOS 上 ./start-trae2api-hub.sh 直接 Permission denied。
  · Dockerfile 用 COPY . /app/ 整目录打包；新增的 i18n/、pricing/、前端静态
    资源一旦被 .dockerignore 误排除，构建仍然成功、运行时才 404。

本套件做四件事（全部静态，不联网、不启动网关、不读 accounts/）：
  [1] git 索引：所有 *.sh 必须是 100755，且 100755 只允许出现在 *.sh 上
  [2] 工作树：shebang 正确、行尾 LF、POSIX 上有执行位
  [3] Dockerfile：整目录 COPY、chmod +x /app/*.sh、构建期资源自检清单完整
  [4] .dockerignore：排除凭证/开发目录，但不得排除 i18n / pricing / 前端资源 /
      目录快照；并用同一套匹配规则模拟 docker build context 做全量校验

用法:
    python test_issue_packaging.py
退出码：0 = 全通过（允许 SKIP）；1 = 有 FAIL。
"""
import fnmatch
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

PASS = 0
FAIL = 0
SKIP = 0
_FAILED = []


def section(title):
    print()
    print(title)


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        _FAILED.append(label)
        print("  [FAIL] " + label + (("  " + str(extra)) if extra else ""))


def skip(label, reason=""):
    global SKIP
    SKIP += 1
    print("  [SKIP] " + label + (("  -- " + str(reason)) if reason else ""))


def rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


# ===========================================================================
# [1] git 索引里的文件模式
# ===========================================================================
def test_git_modes():
    section("[1] git 索引文件模式（受版本控制的 *.sh 必须 100755）")
    try:
        proc = subprocess.run(["git", "ls-files", "--stage"],
                              cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60)
    except Exception as exc:                       # noqa: BLE001
        skip("git 索引可读", "git 不可用：%s" % exc)
        return
    if proc.returncode != 0:
        skip("git 索引可读", proc.stderr.decode("utf-8", "replace")[:120])
        return

    rows = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) < 3 or not path:
            continue
        rows.append((parts[0], path))

    sh_rows = [(mode, path) for mode, path in rows if path.endswith(".sh")]
    check("索引里存在受版本控制的 .sh", bool(sh_rows), len(sh_rows))
    for mode, path in sorted(sh_rows, key=lambda r: r[1]):
        check("git 索引 %s = 100755" % path, mode == "100755", mode)

    wrong = [path for mode, path in rows
             if mode == "100755" and not path.endswith(".sh")]
    check("100755 只出现在 *.sh 上（没有误改其它文件）", not wrong, wrong[:5])


# ===========================================================================
# [2] 工作树脚本：shebang / 行尾 / 执行位
# ===========================================================================
def test_scripts():
    section("[2] 工作树脚本（shebang / LF / 执行位）")
    paths = sorted(glob.glob(os.path.join(ROOT, "*.sh")))
    check("工作树里能找到 .sh 脚本", bool(paths), len(paths))
    for path in paths:
        name = rel(path)
        with open(path, "rb") as fh:
            body = fh.read()
        first = body.split(b"\n", 1)[0]
        check("%s 有 bash shebang" % name, first.startswith(b"#!")
              and b"bash" in first, first[:40])
        check("%s 行尾为 LF（CRLF 会导致 bad interpreter）" % name,
              b"\r\n" not in body, body.count(b"\r\n"))
        if os.name == "nt":
            skip("%s 工作树执行位" % name, "Windows 无 POSIX 执行位（以 git 索引为准）")
        else:
            check("%s 工作树可执行" % name, os.access(path, os.X_OK))


# ===========================================================================
# [3] Dockerfile：整目录 COPY / chmod glob / 构建期资源自检
# ===========================================================================
CRITICAL_ASSETS = (
    "i18n/en.json",
    "pricing/trae_pricing.json",
    "dashboard.html",
    "dashboard-v3.css",
    "dashboard-v3.js",
    "dashboard-charts.js",
    "trae_catalog_cn.json",
    "trae_catalog_intl.json",
)


def test_dockerfile():
    section("[3] Dockerfile 打包面")
    if not os.path.exists(os.path.join(ROOT, "Dockerfile")):
        check("Dockerfile 存在", False)
        return
    text = read("Dockerfile")

    copy_all = re.search(r"(?m)^\s*COPY\s+\.\s+/app/?\s*$", text) is not None
    check("Dockerfile 使用整目录 COPY（新增资源自动进镜像）", copy_all)
    if not copy_all:
        sources = []
        for line in text.splitlines():
            m = re.match(r"\s*COPY\s+(.+?)\s+/app/?\s*$", line)
            if m:
                sources.extend(m.group(1).split())
        missing = [p for p in CRITICAL_ASSETS
                   if not any(p == s or p.startswith(s.rstrip("/") + "/")
                              for s in sources)]
        check("非整目录 COPY 时显式覆盖全部关键资源", not missing, missing)

    check("镜像内脚本用通配补执行位（chmod +x /app/*.sh，不硬编码）",
          re.search(r"chmod \+x /app/\*\.sh", text) is not None)

    m = re.search(r"req=\[(.*?)\]", text, re.S)
    declared = set(re.findall(r"'([^']+)'", m.group(1))) if m else set()
    check("Dockerfile 有构建期资源自检（req=[...]）", bool(declared))
    if declared:
        for asset in CRITICAL_ASSETS:
            check("构建期自检覆盖 %s" % asset, asset in declared,
                  sorted(declared)[:6])
        check("构建期自检在缺失时让构建失败（sys.exit(1)）",
              "sys.exit(1" in text and "missing" in text)

    check("EXPOSE 8791", "EXPOSE 8791" in text)
    check("CMD 启动 trae_proxy.py", "trae_proxy.py" in text)


# ===========================================================================
# [4] .dockerignore 匹配 + 模拟 build context
# ===========================================================================
def load_ignore(name=".dockerignore"):
    patterns = []
    if not os.path.exists(os.path.join(ROOT, name)):
        return patterns
    for line in read(name).splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        patterns.append(raw)
    return patterns


def _match(path, pattern):
    if "/" in pattern:
        return fnmatch.fnmatchcase(path, pattern)
    return any(fnmatch.fnmatchcase(part, pattern)
               for part in path.split("/") if part)


def is_ignored(path, patterns):
    """按出现顺序评估，支持 ! 取反（与 docker 的语义对齐到本仓用到的子集）。"""
    path = path.replace("\\", "/").strip("/")
    ignored = False
    for raw in patterns:
        neg = raw.startswith("!")
        pat = raw[1:] if neg else raw
        pat = pat.strip()
        if pat.startswith("./"):        # 只剥掉前缀 "./"，不能 lstrip("./")
            pat = pat[2:]
        pat = pat.rstrip("/")
        if not pat:
            continue
        if _match(path, pat) or path == pat or path.startswith(pat + "/"):
            ignored = not neg
    return ignored


def _runtime_manifest():
    """运行时/镜像必须存在的文件（动态发现，新增模块自动纳入）。"""
    files = sorted(rel(p) for p in glob.glob(os.path.join(ROOT, "trae_*.py")))
    for name in ("_test_trae.py", "_diag_gateway.py", "dashboard.html",
                 "dashboard-v3.css", "dashboard-v3.js", "dashboard-charts.js",
                 "trae_catalog_cn.json", "trae_catalog_intl.json"):
        if os.path.exists(os.path.join(ROOT, name)):
            files.append(name)
    for pattern in ("i18n/*.json", "pricing/*.json", "*.sh"):
        files.extend(sorted(rel(p) for p in glob.glob(os.path.join(ROOT, pattern))))
    return sorted(set(files))


def test_dockerignore():
    section("[4] .dockerignore 与构建上下文")
    patterns = load_ignore()
    check(".dockerignore 存在且非空", bool(patterns), len(patterns))

    # 4.1 必须排除的敏感 / 开发目录
    must_ignore = {
        "accounts/2531505209880202.json": "账号凭证",
        "usage/usage.jsonl": "用量流水",
        "update-backups/old.zip": "更新备份",
        "update.log": "更新日志",
        ".git/config": "版本库",
        "tools/ida_cipher_out.txt": "本机分析产物",
        ".github/workflows/tests.yml": "CI 配置",
        "__pycache__/trae_proxy.cpython-311.pyc": "字节码缓存",
        ".team/PROTOCOL.md": "团队文档",
        "tests/_test_i18n_core.js": "内部测试",
    }
    for path, label in sorted(must_ignore.items()):
        check("排除%s（%s）" % (label, path), is_ignored(path, patterns), path)

    # 4.2 绝不能排除的运行时资源
    for asset in CRITICAL_ASSETS:
        check("不排除运行时资源 %s" % asset,
              not is_ignored(asset, patterns), "被 .dockerignore 排除")

    # 4.3 模拟 build context：清单里每个文件都要真实存在且未被排除
    manifest = _runtime_manifest()
    check("运行时清单非空", len(manifest) >= 20, len(manifest))
    missing_disk = [p for p in manifest if not os.path.exists(os.path.join(ROOT, p))]
    check("清单文件在工作树中都存在", not missing_disk, missing_disk[:5])
    blocked = [p for p in manifest if is_ignored(p, patterns)]
    check("清单文件全部进入 docker build context（issue4 核心）",
          not blocked, blocked[:8])
    for asset in ("i18n/en.json", "pricing/trae_pricing.json",
                  "dashboard-v3.js", "dashboard-charts.js"):
        check("上下文中保留 %s" % asset,
              asset in manifest and not is_ignored(asset, patterns))

    # 4.4 反向用例：确认匹配器真的会命中（避免“永远返回 False”的假绿）
    check("匹配器自检：accounts/ 下文件被判排除",
          is_ignored("accounts/x.json", patterns))
    check("匹配器自检：i18n/en.json 不被误判",
          not is_ignored("i18n/en.json", patterns))


def test_compose():
    section("[5] docker-compose 构建上下文")
    if not os.path.exists(os.path.join(ROOT, "docker-compose.yml")):
        check("docker-compose.yml 存在", False)
        return
    text = read("docker-compose.yml")
    check("compose 从仓库根构建（context: .）",
          re.search(r"(?m)^\s{2,}context:\s*\.\s*$", text) is not None)
    check("compose 指向 Dockerfile",
          "dockerfile: Dockerfile" in text)
    check("compose 端口 8791:8791", "8791:8791" in text)


# ===========================================================================
def main():
    print("=" * 66)
    print(" issue4 静态打包 / 权限回归测试（离线，不读凭证）")
    print("=" * 66)
    test_git_modes()
    test_scripts()
    test_dockerfile()
    test_dockerignore()
    test_compose()
    print()
    print("=" * 66)
    print(" 汇总: PASS=%d  FAIL=%d  SKIP=%d" % (PASS, FAIL, SKIP))
    if FAIL:
        print(" 失败项：")
        for label in _FAILED:
            print("   - " + label)
        print(" 结果: FAIL（%d 项）" % FAIL)
        return 1
    print(" 结果: 0 failed" + ("（%d 项 SKIP）" % SKIP if SKIP else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
