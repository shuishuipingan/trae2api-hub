# -*- coding: utf-8 -*-
"""_diag_gateway.py —— Trae2API-Hub 网关体检（一条命令定位"为什么不出字"）

体检顺序（每项都打印中文结论 + 断点提示，任一环节失败即停在该环节）：
  [1/4] 端口     本机 TCP 是否能连上（默认 127.0.0.1:8791，IPv4/IPv6 都试）
  [2/4] /health  网关身份（service=trae2api-hub）、版本、当前区、账号数与可用数
  [3/4] /v1/models 鉴权是否通过、模型清单条数、待测模型是否在清单里
  [4/4] 真实流式（--chat）POST /v1/chat/completions，CN 账号，stream=true
        记录 TTFT / 帧数 / 首段正文 / 是否 [DONE]；上游 error 帧按错误码给中文处置

用法:
    python _diag_gateway.py                 # 只做 1-3（不消耗额度）
    python _diag_gateway.py --chat          # 追加真实流式（消耗极少量额度）
    python _diag_gateway.py --chat --model deepseek-v3 --realm cn
    python _diag_gateway.py --port 8791 --key <API_KEY>
    python _diag_gateway.py --host 127.0.0.1 --chat --timeout 300

退出码：0 = 全部通过；1 = 有环节失败。
"""
import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OK = "[ OK ]"
BAD = "[FAIL]"
WARN = "[WARN]"
INFO = "[ .. ]"
DEFAULT_PORT = 8791
DEFAULT_MODEL = "deepseek-v3"

# 上游错误码 -> 中文处置（.team/PROTOCOL.md §六 已实测）
ERROR_HINTS = {
    "1001": "鉴权失败：刷新 token 或换账号（看板 → 账号 → 刷新）",
    "4001": "参数非法：检查 messages 的 parts 数组与 model 名",
    "3003": "prompt pipeline 失败：/chat 专用接口，改用 llm_raw_chat 链路",
    "4015": "上游拒绝：换账号 / 降级模型（国际版账号风控或模型权限）",
    "4019": "风控命中：设备头 + 同区出口 + 冷却后再试",
    "4023": "模型未知：用 /v1/models 返回的 upstream_key（不是显示名）",
}


def guard_url(url, allow_remote=False):
    """出站 URL 白名单：默认只允许回环地址，避免自检脚本变成请求跳板。"""
    parsed = urllib.parse.urlsplit(str(url or ""))
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http/https URLs are allowed")
    host = (parsed.hostname or "").lower()
    if not allow_remote:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("host %r is not loopback; pass --allow-remote to "
                             "probe a remote gateway" % host)
        return url
    from trae_accounts import validate_public_http_url
    return validate_public_http_url(url)


def check_port(host, port, timeout=2.0):
    """TCP 可连接性（IPv4 优先，回退 IPv6）。返回 (ok, 描述)。"""
    last = ""
    for family, addr in ((socket.AF_INET, host), (socket.AF_INET6, "::1")):
        try:
            infos = socket.getaddrinfo(addr, port, family, socket.SOCK_STREAM)
        except Exception as exc:                   # noqa: BLE001
            last = "%s" % exc
            continue
        for af, stype, proto, _, sa in infos:
            sock = socket.socket(af, stype, proto)
            sock.settimeout(timeout)
            try:
                sock.connect(sa)
                sock.close()
                return True, "%s:%s" % (addr, port)
            except Exception as exc:               # noqa: BLE001
                last = "%s" % exc
                sock.close()
    return False, last or ("%s:%s" % (host, port))


def http_json(url, key=None, timeout=10, allow_remote=False):
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(guard_url(url, allow_remote), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8", "replace"))


def post_stream(url, payload, key=None, timeout=180, allow_remote=False):
    """返回 (status, 统计 dict)。逐帧解析 OpenAI 风格 SSE。"""
    headers = {"Accept": "text/event-stream", "Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(guard_url(url, allow_remote), data=body,
                                 method="POST", headers=headers)
    stats = {"status": None, "ttft_ms": None, "lines": 0, "frames": 0,
             "text": "", "reasoning": "", "done": False, "error": None,
             "usage": {}, "finish_reason": None, "content_type": ""}
    started = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        stats["status"] = resp.status
        stats["content_type"] = resp.headers.get("Content-Type", "")
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            stats["lines"] += 1
            if not line or line.startswith(":"):
                continue
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                stats["done"] = True
                continue
            try:
                obj = json.loads(data)
            except Exception:                      # noqa: BLE001
                continue
            stats["frames"] += 1
            if isinstance(obj.get("error"), dict):
                stats["error"] = obj["error"]
                continue
            for choice in obj.get("choices") or []:
                delta = choice.get("delta") or {}
                piece = delta.get("content")
                if isinstance(piece, str) and piece:
                    if stats["ttft_ms"] is None:
                        stats["ttft_ms"] = int((time.time() - started) * 1000)
                    stats["text"] += piece
                reason = delta.get("reasoning_content")
                if isinstance(reason, str) and reason:
                    stats["reasoning"] += reason
                if choice.get("finish_reason"):
                    stats["finish_reason"] = choice["finish_reason"]
            if isinstance(obj.get("usage"), dict):
                stats["usage"] = obj["usage"]
    return stats["status"], stats


def _err_hint(err):
    code = str((err or {}).get("code") or "")
    message = str((err or {}).get("message") or "")
    hint = ERROR_HINTS.get(code, "上游业务错误（非网关问题，按 message 处理）")
    return "code=%s %s -> %s" % (code or "?", message[:160], hint)


def step(n, title):
    print()
    print("[%s/4] %s" % (n, title))


def fail(text, tip=""):
    print(BAD, text)
    if tip:
        print("       断点：%s" % tip)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Trae2API-Hub 网关体检（端口 -> /health -> /v1/models -> 真实流式）")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="网关端口（默认 %d）" % DEFAULT_PORT)
    ap.add_argument("--host", default="127.0.0.1",
                    help="网关地址（默认 127.0.0.1）")
    ap.add_argument("--key", default=os.environ.get("TRAE_PROXY_KEY")
                    or os.environ.get("API_KEY") or None,
                    help="API Key（面板里那个；本机未启用鉴权时可省略）")
    ap.add_argument("--model", default=None,
                    help="流式自检用的模型（默认从 /v1/models 里挑 CN 可用项）")
    ap.add_argument("--realm", default="cn", choices=("cn", "intl", "all"),
                    help="期望的区域（默认 cn）")
    ap.add_argument("--chat", action="store_true",
                    help="追加真实流式对话自检（会消耗极少量额度）")
    ap.add_argument("--timeout", type=int, default=180,
                    help="流式读超时秒数（默认 180）")
    ap.add_argument("--allow-remote", action="store_true",
                    help="允许探测非本机网关（默认只允许回环地址）")
    args = ap.parse_args(argv)

    base = "http://%s:%d" % (args.host, args.port)
    failures = []
    print("=" * 66)
    print(" Trae2API-Hub 网关体检 @ %s" % base)
    print(" 区域期望=%s  鉴权=%s" % (args.realm, "带 Key" if args.key else "无 Key"))
    print("=" * 66)

    # ---------------- [1/4] 端口 ----------------
    step(1, "端口监听")
    up, where = check_port(args.host, args.port)
    if up:
        print(OK, "端口可连接（%s）" % where)
    else:
        fail("端口无人响应（%s）—— 网关进程没在跑" % where,
             "Windows 双击 start-trae2api-hub.bat；Linux/macOS 运行 "
             "./start-trae2api-hub.sh（窗口/终端必须保持开启）")
        if os.name == "nt":
            print("       查占用：netstat -ano | findstr :%d" % args.port)
        else:
            print("       查占用：ss -ltnp | grep :%d" % args.port)
        print("       客户端表现：一直「工作中」但不吐字")
        failures.append("port")
        return _summary(failures, False)

    # ---------------- [2/4] /health ----------------
    step(2, "/health 身份与账号")
    health = {}
    try:
        st, health = http_json(base + "/health", key=args.key,
                               allow_remote=args.allow_remote)
        service = health.get("service")
        print(OK, "/health 200 service=%s version=%s realm=%s"
              % (service, health.get("version"), health.get("realm")))
        print(INFO, "账号总数=%s 可用=%s api_key_required=%s"
              % (health.get("accounts"), health.get("accounts_ready"),
                 health.get("api_key_required")))
        if service not in (None, "trae2api-hub"):
            fail("/health 说自己是 %r，不是 trae2api-hub" % service,
                 "端口被别的服务占用；换端口或关掉那个进程")
            failures.append("health-service")
        if health.get("realm") and args.realm != "all" \
                and health.get("realm") != args.realm:
            print(WARN, "当前区=%s，与期望 %s 不同（自动路由会按模型换区，仅提示）"
                  % (health.get("realm"), args.realm))
        if health.get("accounts_ready") == 0:
            fail("没有可用账号 —— 上游一定会 401/1001",
                 "看板「账号」页导入 Desktop 凭证，或 OAuth 登录；"
                 "然后点一次「刷新」")
            failures.append("accounts")
        if health.get("uid"):
            print(INFO, "当前账号 uid=%s host=%s"
                  % (health.get("uid"), health.get("domain")))
    except urllib.error.HTTPError as exc:
        fail("/health HTTP %d" % exc.code,
             "网关在跑但路由异常；看网关窗口日志")
        failures.append("health")
    except Exception as exc:                       # noqa: BLE001
        fail("/health 失败：%s" % exc,
             "端口被非 HTTP 服务占用，或网关启动到一半退出")
        failures.append("health")

    # ---------------- [3/4] /v1/models ----------------
    step(3, "/v1/models 鉴权与模型清单")
    models = []
    if "health" not in failures:
        try:
            st, doc = http_json(base + "/v1/models?realm=" + args.realm
                                if args.realm != "all" else base + "/v1/models",
                                key=args.key, timeout=30,
                                allow_remote=args.allow_remote)
            models = doc.get("data") or []
            print(OK, "/v1/models 200 realm=%s models=%d catalog=%s"
                  % (doc.get("realm"), len(models), doc.get("catalog_source")))
            if not models:
                fail("模型清单为空",
                     "目录快照缺失：python _refresh_catalog.py，或看 trae_catalog_*.json")
                failures.append("models-empty")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                fail("/v1/models 401（鉴权）",
                     "用 --key 传入面板里的 API Key（docker logs 里 grep -i 'api key'）")
            else:
                fail("/v1/models HTTP %d" % exc.code,
                     "网关在跑但清单接口异常；看网关日志")
            failures.append("models")
        except Exception as exc:                   # noqa: BLE001
            fail("/v1/models 失败：%s" % exc)
            failures.append("models")

    # 选模型：显式 > 官方默认项(is_default) > 常见 CN 模型 > 第一个
    model = args.model
    if models:
        ids, keys, defaults = [], [], []
        for m in models:
            if not isinstance(m, dict):
                continue
            rid = str(m.get("id") or m.get("upstream_key") or "")
            rkey = str(m.get("upstream_key") or rid)
            ids.append(rid)
            keys.append(rkey)
            if m.get("is_default"):
                defaults.append(rkey)
        known = set(ids) | set(keys)
        if not model:
            for cand in defaults + [DEFAULT_MODEL, "deepseek-v3",
                                    "seed_m8", "deepseek-v4.1-flash"]:
                if cand in known:
                    model = cand
                    break
            if not model:
                model = keys[0] if keys else DEFAULT_MODEL
        if model not in known:
            print(WARN, "模型 %r 不在清单里（清单示例：%s）"
                  % (model, ", ".join(keys[:5])))
    if not model:
        model = DEFAULT_MODEL
    print(INFO, "流式待测模型=%s" % model)

    # ---------------- [4/4] 真实流式 ----------------
    if not args.chat:
        print()
        print(INFO, "跳过真实流式（加 --chat 才跑；会消耗极少量额度）")
        return _summary(failures, False)

    step(4, "真实流式（stream=true）")
    if failures:
        print(INFO, "前面有失败项，先修完再跑流式")
        return _summary(failures, False)
    payload = {"model": model, "stream": True,
               "messages": [{"role": "user", "content": "只回复两个字：收到"}]}
    try:
        status, stats = post_stream(base + "/v1/chat/completions", payload,
                                    key=args.key, timeout=args.timeout,
                                    allow_remote=args.allow_remote)
    except urllib.error.HTTPError as exc:
        detail = exc.read(600).decode("utf-8", "replace")
        fail("流式 HTTP %d：%s" % (exc.code, detail[:300]),
             "401=Key 不对；404=路径/端口不对；5xx=看网关日志")
        failures.append("stream-http")
        return _summary(failures, True)
    except Exception as exc:                       # noqa: BLE001
        fail("流式异常：%s" % exc,
             "网关到上游的链路断了（DNS/代理/TLS）；看网关窗口日志")
        failures.append("stream-exc")
        return _summary(failures, True)

    print(OK, "HTTP %s content-type=%s" % (stats["status"], stats["content_type"]))
    print(INFO, "TTFT=%sms 行数=%d 数据帧=%d"
          % (stats["ttft_ms"], stats["lines"], stats["frames"]))
    if stats["error"]:
        fail("上游 error 帧：" + _err_hint(stats["error"]),
             "这是上游业务错误，网关已如实透传")
        failures.append("upstream-error")
    if not stats["text"]:
        fail("没有正文（content 全空）",
             "有 reasoning 无正文=思考模型只回了思考；空流=上游被风控（看 error 帧）")
        failures.append("no-text")
    else:
        head = stats["text"][:60].replace("\n", " ")
        print(OK, "首段正文：%s" % head)
    if not stats["done"]:
        fail("未见 [DONE] 收尾（流被截断）",
             "网关或上游提前断流；看网关日志里的 stream 记录")
        failures.append("no-done")
    else:
        print(OK, "[DONE] 正常收尾")
    if stats["finish_reason"]:
        print(INFO, "finish_reason=%s" % stats["finish_reason"])
    if stats["usage"]:
        print(INFO, "usage: prompt=%s completion=%s total=%s"
              % (stats["usage"].get("prompt_tokens"),
                 stats["usage"].get("completion_tokens"),
                 stats["usage"].get("total_tokens")))
    else:
        print(WARN, "未收到 usage（部分上游在流末才给；不影响出字）")
    return _summary(failures, True)


def _summary(failures, chatted=False):
    print()
    print("=" * 66)
    if failures:
        print("结果：存在问题 -> %s" % ", ".join(failures))
        print("断点顺序：端口 -> /health -> /v1/models -> 流式；第一个失败项就是断点。")
        return 1
    print("结果：全部通过（网关在线、鉴权与模型清单正常"
          + ("、真实流式可出字" if chatted else "") + "）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
