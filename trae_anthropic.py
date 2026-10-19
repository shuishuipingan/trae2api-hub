# -*- coding: utf-8 -*-
"""Anthropic Messages 协议 <-> Chat Completions 转换层（task-78）。

自包含：**零依赖、纯标准库**，不 import trae_proxy / trae_accounts（接线由调用方完成）。
设计依据：.team/72-ANTHROPIC-BRIDGE-DESIGN.md（三条原则见其 §0）。

边界（照设计文档 §0/§2）：
  1) 本模块**只做协议翻译、不做形态决策**：输出永远是标准 chat 形状
     （role:assistant + tool_calls / role:tool + tool_call_id）；「结构化直传 vs
     文本信封」由调用方的 structured_tool_history_enabled(...) 单点决定。
  2) **吞掉/回读守卫不在此重写**：stream_anthropic_events 的输入契约是
     「已被 recover_leaked_tool_calls 清洗过的 chat chunk」——本模块不做清洗。
  3) **不生成** Anthropic 的 thinking signature（见 §signature 说明）。

接线时最容易踩的三点（设计文档 §8 的 Top3）：
  · x-api-key 头（Anthropic 客户端不用 Authorization: Bearer）；
  · 不要在桥接层重复做形态决策；
  · input_json_delta 是**增量字符串**，逐片拼接、不要每片 json.loads。
"""
import json
import os
import time
import uuid

# ---------------------------------------------------------------------------
# 常量与开关
# ---------------------------------------------------------------------------
# 思考档位排序（与 trae_proxy.EFFORT_RANK 同表；**接线轮应统一为单一来源**：
# 建议让 trae_proxy 从本模块 import，依赖方向保持 proxy -> anthropic）。
EFFORT_RANK = {"none": 0, "minimal": 1, "low": 2, "medium": 3, "high": 4,
               "xhigh": 5, "max": 6}
_EFFORT_ORDER = tuple(sorted(EFFORT_RANK, key=lambda k: EFFORT_RANK[k]))
# budget_tokens 断点 -> 档位（设计文档 §4.2）
BUDGET_STEPS = ((1024, "minimal"), (4096, "low"), (16384, "medium"),
                (None, "high"))
_STOP_REASON = {"stop": "end_turn", "length": "max_tokens",
                "tool_calls": "tool_use", "function_call": "tool_use"}


def _new_id(prefix):
    return prefix + uuid.uuid4().hex[:24]


def thinking_mode():
    """TRAE_ANTHROPIC_THINKING（兼容旧名 QD_ANTHROPIC_THINKING）：
    off（默认，不发 thinking block）/ empty（发空签名）。

    设计文档 §5：我们生成不了 Anthropic 要求的 signature，默认降级为「不暴露思考」。
    伪造签名（raw）**不提供**。
    """
    raw = (os.environ.get("TRAE_ANTHROPIC_THINKING")
           or os.environ.get("QD_ANTHROPIC_THINKING") or "").strip().lower()
    return raw if raw in ("empty",) else "off"

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def _text_of_blocks(blocks):
    """Anthropic content blocks -> 纯文本（text 块拼接；其余块忽略）。"""
    if isinstance(blocks, str):
        return blocks
    if not isinstance(blocks, list):
        return ""
    parts = []
    for b in blocks:
        if isinstance(b, str):
            parts.append(b)
        elif isinstance(b, dict) and (b.get("type") in (None, "text")) \
                and isinstance(b.get("text"), str):
            parts.append(b["text"])
    return "\n".join(p for p in parts if p)


def _image_to_data_uri(block):
    """Anthropic image block -> chat 能吃的 URL（data URI 或原 URL）。"""
    src = block.get("source")
    if not isinstance(src, dict):
        return ""
    if src.get("type") == "base64":
        mt = str(src.get("media_type") or "image/png")
        data = str(src.get("data") or "")
        return ("data:%s;base64,%s" % (mt, data)) if data else ""
    if src.get("type") == "url":
        return str(src.get("url") or "")
    return ""


def _tool_result_text(block):
    """Anthropic tool_result -> 文本（图片等非文本块降级为占位）。"""
    c = block.get("content")
    if isinstance(c, str):
        return c
    if not isinstance(c, list):
        return "" if c is None else str(c)
    parts = []
    for b in c:
        if isinstance(b, str):
            parts.append(b)
        elif isinstance(b, dict) and b.get("type") in (None, "text"):
            parts.append(str(b.get("text") or ""))
        elif isinstance(b, dict):
            parts.append("[%s omitted]" % (b.get("type") or "block"))
    return "\n".join(p for p in parts if p)


def _tool_choice_to_chat(tc):
    """Anthropic tool_choice 四形态 -> chat 形态（auto/any/tool/none）。"""
    if isinstance(tc, str):
        return {"auto": "auto", "any": "required", "none": "none"}.get(tc, "auto")
    if isinstance(tc, dict):
        t = tc.get("type")
        if t == "any":
            return "required"
        if t == "none":
            return "none"
        if t == "tool" and tc.get("name"):
            return {"type": "function",
                    "function": {"name": str(tc.get("name"))}}
        if t == "auto":
            return "auto"
    return "auto"


def system_prompt_of(payload):
    """system 三形态合并（顶层字符串 / 顶层数组 / messages 内 system）。

    这是 wb v1.6.17 的 400 根因，也是本仓 flatten_messages「只取第一条 system、
    其余静默丢弃」的坑点（设计文档 §3.1 + §8 易错点 1）：三条来源必须**全部**合并且
    放在最前，顺序 = 顶层 system 在前、messages 内 system 按出现顺序追加。
    """
    parts = []
    sysv = payload.get("system")
    if isinstance(sysv, str):
        if sysv.strip():
            parts.append(sysv)
    elif isinstance(sysv, list):
        t = _text_of_blocks(sysv)
        if t.strip():
            parts.append(t)
    for m in payload.get("messages") or []:
        if isinstance(m, dict) and m.get("role") == "system":
            t = _text_of_blocks(m.get("content"))
            if t.strip():
                parts.append(t)
    return "\n\n".join(parts)


def _tools_to_chat(tools):
    """Anthropic tools（name/description/input_schema）-> chat function 工具。

    幂等：已是 chat 形态（含 function 子对象）的原样保留。
    """
    out = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        if isinstance(t.get("function"), dict):
            out.append(t)
            continue
        name = str(t.get("name") or "").strip()
        if not name:
            continue
        schema = t.get("input_schema")
        if not isinstance(schema, dict):
            schema = {"type": "object", "properties": {}}
        out.append({"type": "function", "function": {
            "name": name,
            "description": str(t.get("description") or ""),
            "parameters": schema}})
    return out


def effort_from_anthropic(payload, catalog_meta=None, supported=None):
    """thinking.budget_tokens -> reasoning_effort（设计文档 §4.2）。

    单调 + clamp：
      · thinking.type == "disabled" / budget 缺失 -> None（不下发）
      · 断点粗映射（<=1024 minimal / <=4096 low / <=16384 medium / >16384 high）
      · supported 给定时做 clamp（**接线时应显式传 trae_proxy.supported_efforts(meta)**）；
        未给时回退从 catalog_meta["thinking_config"] 读（避免与 proxy 重复决策）。
      · 档位表为空 -> None（保持「不猜测」语义）
    """
    th = payload.get("thinking")
    if not isinstance(th, dict):
        oc = payload.get("output_config")
        if isinstance(oc, dict) and oc.get("effort"):
            th = {"type": "enabled", "budget_tokens": None,
                  "effort": oc.get("effort")}
        else:
            return None
    if str(th.get("type") or "").lower() == "disabled":
        return None
    target = None
    if th.get("effort"):
        cand = str(th["effort"]).strip().lower()
        target = cand if cand in EFFORT_RANK else None
    if target is None:
        budget = th.get("budget_tokens")
        if budget is None:
            return None
        try:
            budget = float(budget)
        except (TypeError, ValueError):
            return None
        for limit, name in BUDGET_STEPS:
            if limit is None or budget <= limit:
                target = name
                break
    if not target:
        return None
    # 注意用 `is not None`：调用方**明确传空表**（= 该模型没有可用档位）时，
    # 不应该被 fallback 覆盖掉（falsy 判断会把 [] 当成"没传"）。
    allowed = supported if supported is not None else _efforts_from_meta(catalog_meta)
    if not allowed:
        return None                     # 无档位表 -> 不下发
    allowed = [str(x).strip().lower() for x in allowed
               if str(x).strip().lower() in EFFORT_RANK]
    if not allowed:
        return None
    if target in allowed:
        return target
    # clamp：取 rank 最接近且不超过的档；全超 -> 取最高档
    tr = EFFORT_RANK[target]
    lower = [x for x in allowed if EFFORT_RANK[x] <= tr]
    if lower:
        return max(lower, key=lambda x: EFFORT_RANK[x])
    return min(allowed, key=lambda x: EFFORT_RANK[x])


def _efforts_from_meta(meta):
    """从 catalog 元数据读档位（fallback；接线时应显式传 supported 以避免双实现）。

    ⚠️ 实测修正：本仓目录里的形状是 **dict**（"efforts": {"low": {...}, "high": {...}}），
    早期实现只认 list，导致这条 fallback 恒返回空（形同虚设）。两种形状都接受。
    """
    if not isinstance(meta, dict):
        return []
    tc = meta.get("thinking_config")
    if not isinstance(tc, dict):
        return []
    en = tc.get("enabled") if isinstance(tc.get("enabled"), dict) else {}
    for src in (en.get("efforts"), tc.get("efforts")):
        if isinstance(src, dict):
            return list(src)
        if isinstance(src, list):
            return src
    return []

# ---------------------------------------------------------------------------
# 入站：Anthropic -> Chat（设计文档 §3.1 的 14 行字段表）
# ---------------------------------------------------------------------------
def messages_to_chat(payload, catalog_meta=None, supported=None):
    """Anthropic /v1/messages 请求体 -> 标准 Chat Completions 请求体。"""
    payload = payload if isinstance(payload, dict) else {}
    messages = []
    for m in payload.get("messages") or []:
        if not isinstance(m, dict):
            continue
        role = str(m.get("role") or "user")
        if role == "system":
            continue                    # 已由 system_prompt_of 合并（不丢弃，只上提）
        content = m.get("content")
        if isinstance(content, str):
            blocks = [{"type": "text", "text": content}]
        elif isinstance(content, list):
            blocks = content
        elif isinstance(content, dict):
            # 单块形态（image/tool_use 单 dict 不套列表）：当单元素列表处理；
            # 旧写法把它压成 {"type":"text","text":""}，图像块被静默吞掉。
            blocks = [content]
        else:
            blocks = []
        texts, images, tool_calls, tool_results = [], [], [], []
        for b in blocks:
            if isinstance(b, str):
                texts.append(b)
                continue
            if not isinstance(b, dict):
                continue
            bt = b.get("type")
            if bt in (None, "text"):
                if isinstance(b.get("text"), str):
                    texts.append(b["text"])
            elif bt == "image":
                uri = _image_to_data_uri(b)
                if uri:
                    images.append(uri)
            elif bt == "tool_use":
                args = b.get("input")
                if not isinstance(args, str):
                    args = json.dumps(args if args is not None else {},
                                      ensure_ascii=False)
                tool_calls.append({"id": str(b.get("id") or ""),
                                   "type": "function",
                                   "function": {"name": str(b.get("name") or ""),
                                                "arguments": args}})
            elif bt == "tool_result":
                tool_results.append((str(b.get("tool_use_id") or ""),
                                     _tool_result_text(b)))
            elif bt == "thinking":
                continue                # 设计文档 §3.1：入站 thinking 一律丢弃
            # 其它未知 block：忽略（不静默改变语义：它们既不进文本也不进工具）
        # 顺序：tool_result 先落（紧跟其 tool_use 的 assistant）、再 assistant、再 user
        for cid, txt in tool_results:
            messages.append({"role": "tool", "tool_call_id": cid,
                             "content": txt})
        text = "".join(texts)
        if tool_calls:
            messages.append({"role": "assistant", "content": text,
                             "tool_calls": tool_calls})
        elif role == "assistant" and (text or images):
            messages.append({"role": "assistant", "content": text})
        elif images:
            parts = ([{"type": "text", "text": text}] if text else [])
            parts += [{"type": "image_url", "image_url": {"url": u}}
                      for u in images]
            messages.append({"role": role if role in ("user", "assistant")
                             else "user", "content": parts})
        elif text:
            messages.append({"role": role if role in ("user", "assistant")
                             else "user", "content": text})
        # else：该消息只承载 tool_result（已单独成 role:tool）或空内容 ->
        # **不追加空消息**（否则会在历史里留下 content:"" 的幽灵轮次）
    chat = {"messages": messages}
    sys_text = system_prompt_of(payload)
    if sys_text:
        chat["messages"] = [{"role": "system", "content": sys_text}] + messages
    if payload.get("model"):
        chat["model"] = payload["model"]
    if payload.get("max_tokens") is not None:
        chat["max_tokens"] = payload["max_tokens"]
    for key in ("temperature", "top_p"):
        if payload.get(key) is not None:
            chat[key] = payload[key]
    if payload.get("stop_sequences"):
        chat["stop"] = list(payload["stop_sequences"])
    tools = _tools_to_chat(payload.get("tools"))
    if tools:
        chat["tools"] = tools
    if payload.get("tool_choice") is not None:
        chat["tool_choice"] = _tool_choice_to_chat(payload["tool_choice"])
    effort = effort_from_anthropic(payload, catalog_meta=catalog_meta,
                                   supported=supported)
    if effort:
        chat["reasoning_effort"] = effort
    meta = payload.get("metadata")
    if isinstance(meta, dict) and meta.get("user_id"):
        # 设计文档 §8 易错点 8：接线时可据此生成会话亲和键
        chat["metadata"] = {"user_id": str(meta["user_id"])}
    return chat


def validate_request(payload):
    """Anthropic 必填项校验 -> (ok, message)。max_tokens 缺失应 400（与 chat 相反）。"""
    if not isinstance(payload, dict):
        return False, "request body must be a JSON object"
    if not payload.get("messages"):
        return False, "messages is required"
    if payload.get("max_tokens") is None:
        return False, "max_tokens is required"
    try:
        if int(payload["max_tokens"]) <= 0:
            return False, "max_tokens must be positive"
    except (TypeError, ValueError):
        return False, "max_tokens must be an integer"
    return True, ""

# ---------------------------------------------------------------------------
# 用量与出站（设计文档 §3.2 / §4.1 / §4.3）
# ---------------------------------------------------------------------------
def chat_usage_to_anthropic(usage):
    """chat usage -> Anthropic usage（§4.1）。

    口径（**规范口径**）：Anthropic 的 input_tokens 不含 cache_read；
      input_tokens + cache_read_input_tokens == prompt_tokens（守恒，判据 6）。
    cache_creation_input_tokens 恒 0：上游没有这个概念，不编造。
    """
    u = usage if isinstance(usage, dict) else {}
    details = u.get("completion_tokens_details")
    details = details if isinstance(details, dict) else {}
    pdet = u.get("prompt_tokens_details")
    pdet = pdet if isinstance(pdet, dict) else {}
    def _int(v):
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0
    prompt = max(0, _int(u.get("prompt_tokens")))
    cached = _int(u.get("prompt_cache_hit_tokens")) or _int(
        details.get("cached_tokens")) or _int(pdet.get("cached_tokens"))
    cached = max(0, min(cached, prompt))
    return {
        "input_tokens": max(0, prompt - cached),
        "cache_read_input_tokens": cached,
        "cache_creation_input_tokens": 0,
        "output_tokens": max(0, _int(u.get("completion_tokens"))),
        "output_tokens_details": {
            "reasoning_tokens": max(0, _int(details.get("reasoning_tokens")))},
    }


def _stop_reason(finish_reason):
    return _STOP_REASON.get(str(finish_reason or "stop"), "end_turn")


def chat_to_messages(chat_obj, model=None):
    """chat.completion -> Anthropic message（非流式出站，§3.2）。"""
    chat_obj = chat_obj if isinstance(chat_obj, dict) else {}
    choice = (chat_obj.get("choices") or [{}])[0]
    choice = choice if isinstance(choice, dict) else {}
    msg = choice.get("message")
    msg = msg if isinstance(msg, dict) else {}
    content = []
    text = msg.get("content")
    if isinstance(text, list):
        text = "".join(p.get("text", "") for p in text
                       if isinstance(p, dict))
    if isinstance(text, str) and text:
        content.append({"type": "text", "text": text})
    if thinking_mode() == "empty" and msg.get("reasoning_content"):
        content.append({"type": "thinking",
                        "thinking": str(msg["reasoning_content"]),
                        "signature": ""})
    for tc in msg.get("tool_calls") or []:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function")
        fn = fn if isinstance(fn, dict) else {}
        args = fn.get("arguments")
        try:
            inp = json.loads(args) if isinstance(args, str) and args.strip() else {}
        except Exception:
            inp = {}
        if not isinstance(inp, (dict, list)):
            inp = {"value": inp}
        content.append({"type": "tool_use",
                        "id": str(tc.get("id") or _new_id("toolu_")),
                        "name": str(fn.get("name") or ""),
                        "input": inp})
    return {
        "id": _new_id("msg_"),
        "type": "message",
        "role": "assistant",
        "model": str(model or chat_obj.get("model") or ""),
        "content": content,
        "stop_reason": _stop_reason(choice.get("finish_reason")),
        "stop_sequence": None,
        "usage": chat_usage_to_anthropic(chat_obj.get("usage")),
    }


def stream_anthropic_events(inner_lines, model="", holder=None):
    """把**已清洗**的 chat chunk 行翻译成 Anthropic SSE 事件（§4.3）。

    inner_lines 的契约：`data: {chat.chunk}` 行（bytes 或 str），**必须来自
    iter_inner_sse -> recover_leaked_tool_calls 之后**（本模块不做吞掉/回读）。
      · 以 ":" 开头的心跳注释行**原样透传**；
      · `[DONE]` 丢弃（Anthropic 客户端不认）；
      · arguments 是**增量字符串**，逐片 input_json_delta，不要逐片 json.loads。
    """
    msg_id = _new_id("msg_")
    next_index = 0
    text_index = None
    thinking_index = None
    tool_index = {}
    open_blocks = []
    finish = "stop"
    mode = thinking_mode()

    def ev(etype, obj):
        body = dict(obj)
        body["type"] = etype
        return ("event: " + etype + "\ndata: "
                + json.dumps(body, ensure_ascii=False) + "\n\n").encode("utf-8")

    start_usage = chat_usage_to_anthropic(
        holder.get("usage") if isinstance(holder, dict) else None)
    yield ev("message_start", {"message": {
        "id": msg_id, "type": "message", "role": "assistant",
        "model": model or "", "content": [], "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": start_usage["input_tokens"],
                  "cache_read_input_tokens": start_usage["cache_read_input_tokens"],
                  "cache_creation_input_tokens": 0,
                  "output_tokens": 0}}})
    for raw in inner_lines:
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(":"):
            yield (raw if isinstance(raw, bytes) else line.encode("utf-8"))
            continue
        if not stripped.startswith("data:"):
            continue
        body_txt = stripped[5:].strip()
        if not body_txt or body_txt == "[DONE]":
            continue
        try:
            chunk = json.loads(body_txt)
        except Exception:
            continue
        if not isinstance(chunk, dict):
            continue
        if isinstance(chunk.get("usage"), dict) and isinstance(holder, dict):
            holder["usage"] = chunk["usage"]
        for choice in chunk.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            delta = delta if isinstance(delta, dict) else {}
            piece = delta.get("reasoning_content")
            if piece and mode == "empty":
                if thinking_index is None:
                    thinking_index = next_index
                    next_index += 1
                    open_blocks.append(thinking_index)
                    yield ev("content_block_start", {
                        "index": thinking_index,
                        "content_block": {"type": "thinking", "thinking": "",
                                          "signature": ""}})
                yield ev("content_block_delta", {
                    "index": thinking_index,
                    "delta": {"type": "thinking_delta", "thinking": piece}})
            txt = delta.get("content")
            if isinstance(txt, str) and txt:
                if text_index is None:
                    text_index = next_index
                    next_index += 1
                    open_blocks.append(text_index)
                    yield ev("content_block_start", {
                        "index": text_index,
                        "content_block": {"type": "text", "text": ""}})
                yield ev("content_block_delta", {
                    "index": text_index,
                    "delta": {"type": "text_delta", "text": txt}})
            for tc in delta.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                ci = tc.get("index")
                if not isinstance(ci, int):
                    ci = len(tool_index)
                fn = tc.get("function")
                fn = fn if isinstance(fn, dict) else {}
                args = fn.get("arguments") or ""
                if ci not in tool_index:
                    ai = next_index
                    next_index += 1
                    tool_index[ci] = ai
                    open_blocks.append(ai)
                    yield ev("content_block_start", {
                        "index": ai,
                        "content_block": {"type": "tool_use",
                                          "id": str(tc.get("id")
                                                    or _new_id("toolu_")),
                                          "name": str(fn.get("name") or ""),
                                          "input": {}}})
                if args:
                    yield ev("content_block_delta", {
                        "index": tool_index[ci],
                        "delta": {"type": "input_json_delta",
                                  "partial_json": args}})
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
    for i in sorted(open_blocks):
        yield ev("content_block_stop", {"index": i})
    final = chat_usage_to_anthropic(
        holder.get("usage") if isinstance(holder, dict) else None)
    # issue #42：新版 Anthropic 语义里 message_delta.usage 是**累计完整用量**，
    # Claude Code / AI SDK 系客户端按它读取最终计量。此前只回 output_tokens，
    # 输入侧（input/cache_read/cache_creation）全部缺失 -> 客户端输入 token 恒 0。
    # 口径与非流式 chat_to_messages 完全一致（input + cache_read == prompt_tokens）。
    yield ev("message_delta", {
        "delta": {"stop_reason": _stop_reason(finish), "stop_sequence": None},
        "usage": {
            "input_tokens": final["input_tokens"],
            "cache_read_input_tokens": final["cache_read_input_tokens"],
            "cache_creation_input_tokens":
                final["cache_creation_input_tokens"],
            "output_tokens": final["output_tokens"],
            "output_tokens_details": final["output_tokens_details"],
        }})
    yield ev("message_stop", {})


def anthropic_error_frame(message, kind="api_error"):
    """Anthropic 流的终态错误事件（`event: error`）—— 规范里流的唯一错误出口。"""
    body = {"type": "error",
            "error": {"type": str(kind or "api_error"),
                      "message": str(message or "")}}
    return ("event: error\ndata: " + json.dumps(body, ensure_ascii=False)
            + "\n\n").encode("utf-8")


def estimate_anthropic_tokens(payload):
    """count_tokens 的本地估算（CJK 感知）—— **不联网**（判据 4）。"""
    payload = payload if isinstance(payload, dict) else {}
    chunks = [system_prompt_of(payload)]
    for m in payload.get("messages") or []:
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        chunks.append(_text_of_blocks(c) if not isinstance(c, str) else c)
    try:
        chunks.append(json.dumps(payload.get("tools") or [], ensure_ascii=False))
    except Exception:
        pass
    text = "\n".join(x for x in chunks if x)
    cjk = sum(1 for ch in text if ord(ch) > 0x2E80)
    other = len(text) - cjk
    return {"input_tokens": max(1, cjk + (other + 3) // 4)}