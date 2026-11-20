# -*- coding: utf-8 -*-
"""issue: SOLO 通道按模型分组选 function（离线，不联网）

背景
----
上游 /api/agent/v3/llm_utils_chat 按 function 参数分组，两组模型集合不通用：

    solo_work_remote   18 个
    solo_agent_remote  20 个（多出 Doubao-Seed-Code / qwen3.8-flash）

旧实现里 trae_solo_chat 对所有模型都写死 `"function": "solo_work_lite"`，
所以 Seed-Code / qwen3.8-flash 必然被上游拒绝：

    4001: We're sorry, the param is invalid. Please try with a valid param.

这条错误信息很像 max_tokens / messages 的问题，实际是 function 和模型不匹配。
本用例锁住"模型 -> function"的映射，以及 trae_solo_chat 真的用了它。

用法：python test_issue_solo_groups.py；退出码 0=全通过。不读账号、不联网。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0
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


def main():
    import trae_proxy as P

    section("[1] agent 组专有模型 -> solo_agent_remote")
    for model in ("Doubao-Seed-Code", "qwen3.8-flash"):
        got = P.solo_function_for(model)
        check("%s -> solo_agent_remote" % model, got == "solo_agent_remote", got)

    section("[2] 其余 SOLO 模型保持 solo_work_lite")
    for model in ("Doubao-Seed-2.1-Turbo", "Doubao-Seed-2.1-Pro", "Doubao-Seed-Evolving",
                  "glm-5.3", "glm-5.3-flash", "deepseek-v4.1-flash",
                  "DeepSeek-V4-Pro-Official", "mimo-v2.6-flash", "minimax-m3",
                  "step-5-preview", "kimi-k3", "qwen3.8-max"):
        got = P.solo_function_for(model)
        check("%s -> solo_work_lite" % model, got == "solo_work_lite", got)

    section("[3] 映射表与别名表一致")
    unknown = sorted(P.SOLO_AGENT_ONLY - set(P.SOLO_MODEL_ALIASES.values()))
    check("SOLO_AGENT_ONLY 里的模型都在 SOLO_MODEL_ALIASES 里", not unknown, unknown)

    section("[4] trae_solo_chat 实际发的 function 跟映射一致")
    # 不联网：把 urlopen 换成假实现，抓请求体后就地报错退出。
    captured = {}

    class _FakeResp(object):
        def __iter__(self):
            return iter([b'data:{"code":4001,"message":"stop here"}\n'])

        def close(self):
            pass

    real_urlopen = P.urllib.request.urlopen

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResp()

    class _Account(object):
        token = "fake-token"
        uid = "fake-uid"
        realm = "cn"
        extra = {}

        def public(self, now=None):
            return {}

    real_ensure = P.trae_accounts.ensure_personal_account
    P.trae_accounts.ensure_personal_account = lambda acc: None
    P.urllib.request.urlopen = fake_urlopen
    try:
        for model, expected in (("Seed-Code", "solo_agent_remote"),
                                ("qwen3.8-flash", "solo_agent_remote"),
                                ("glm-5.3", "solo_work_lite")):
            captured.pop("body", None)
            try:
                P.trae_solo_chat(_Account(), {
                    "model": model,
                    "messages": [{"role": "user", "content": "hi"}],
                })
            except Exception:  # noqa: BLE001 - 假响应故意报错，忽略
                pass
            body = captured.get("body") or {}
            check("%s 请求体 function=%s" % (model, expected),
                  body.get("function") == expected,
                  "got=%r" % (body.get("function"),))
            check("%s 请求体 config_name 仍然是模型名" % model,
                  body.get("config_name") == P.SOLO_MODEL_ALIASES.get(model, model),
                  "got=%r" % (body.get("config_name"),))
    finally:
        P.urllib.request.urlopen = real_urlopen
        P.trae_accounts.ensure_personal_account = real_ensure

    print()
    print("PASS=%d FAIL=%d" % (PASS, FAIL))
    if FAIL:
        print("FAILED: " + ", ".join(_FAILED))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
