# -*- coding: utf-8 -*-
"""智能体一键配置（Trae 网关版，零第三方依赖）。

把本机 AI 客户端的配置指向本网关：改前自动备份、byte-exact 还原、
多文件客户端两阶段写入（任一失败整体回滚）。设计照 wb_agents.py 的
四条铁律：

1. **非侵入**：纯标准库实现的文本级 YAML / TOML / JSON 编辑器，只增量
   插入或更新 `trae2api-hub` 那一段，绝不重排或抹掉用户的注释、缩进
   与其它 provider 配置。
2. **可回滚**：写入前把原件字节备份到 accounts/agent-backups/（每文件
   保留最新 10 份），首次接入的原件永久保留；restore() byte-exact 回到
   接入前，网关新建的文件会被清理。
3. **密钥安全**：API Key 只写进客户端自己的本地配置目录，网关侧只在
   state 里存 sha256 指纹（不存明文）；单文件超过 8MB 拒绝编辑。
4. **plan 即 apply**：plan() 与 integrate() 共享同一构建器，dry-run 打印
   的就是真实写入的（面板预览与 CLI --dry-run 都走它）。

面板用法（/agents 系列端点，需面板会话）与独立 CLI 用法（客户端装在
别的机器时）见模块尾部 main()。

    python trae_agents.py list
    python trae_agents.py plan --client dsh --base-url http://192.168.1.5:8790 --key sk-...
    python trae_agents.py apply --client dsh --base-url ... --key ...
    python trae_agents.py restore --client dsh
"""
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request

PROVIDER_ID = "trae2api-hub"
PROVIDER_NAME = "Trae Gateway"
CREDENTIAL_REF = "TRAE_PROXY_API_KEY"
BACKUP_KEEP = 10
MAX_EDIT_BYTES = 8 * 1024 * 1024   # 8MB：单文件超过即拒绝编辑


class AgentConfigError(Exception):
    """用户可读的配置失败（面板与 CLI 都直接展示 str(exc)）。"""


# ---------------------------------------------------------------------------
# 文件原语：原子写 + 读
# ---------------------------------------------------------------------------

def _resolve_home(home=None):
    return str(home or os.path.expanduser("~"))


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _read_bytes(path):
    if not os.path.exists(path):
        raise AgentConfigError("file not found: %s" % path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise AgentConfigError("cannot read %s: %s" % (path, exc))
    if len(data) > MAX_EDIT_BYTES:
        raise AgentConfigError(
            "refusing to edit %s (%d bytes > %d limit)"
            % (path, len(data), MAX_EDIT_BYTES))
    return data


def _read_text(path):
    """读文本配置；缺失=空文档（从零建配置是合法场景，如 DSH 首次生成 settings.yaml）。"""
    if not os.path.exists(path):
        return ""
    data = _read_bytes(path)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise AgentConfigError("%s is not UTF-8 text" % path)


def _atomic_write_text(path, text):
    _atomic_write_bytes(path, text.encode("utf-8"))


def _atomic_write_bytes(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(directory, exist_ok=True)
        tmp = path + ".qagent.tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except OSError as exc:
        raise AgentConfigError("cannot write %s: %s" % (path, exc))


def _prune_empty_parents(path, home=None):
    """删除我们建空的父目录链（restore 后不留「幽灵安装」痕迹）。"""
    home = _resolve_home(home)
    directory = os.path.dirname(os.path.abspath(path))
    stop = os.path.abspath(home)
    while directory and directory != stop and len(directory) > len(stop):
        try:
            if os.listdir(directory):
                break
            os.rmdir(directory)
        except OSError:
            break
        directory = os.path.dirname(directory)


def _load_json(path, what):
    text = _read_text(path)
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise AgentConfigError("%s is not valid JSON (%s): %s" % (what, path, exc))
    if not isinstance(data, dict):
        raise AgentConfigError("%s must be a JSON object: %s" % (what, path))
    return data


def _dump_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def deep_merge(base, patch):
    """递归合并：patch 之外的兄弟键存活；输入不被改动。"""
    if not isinstance(base, dict) or not isinstance(patch, dict):
        return patch
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


# ---------------------------------------------------------------------------
# 文本级 YAML 编辑器（子集；纯标准库）
# ---------------------------------------------------------------------------

def _yaml_indent(line):
    return len(line) - len(line.lstrip(" "))


def _yaml_key(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
        return None
    m = re.match(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*:(?:\s|$)", line.lstrip(" "))
    if not m:
        return None
    return m.group(1)


def _yaml_block_end(lines, start, indent):
    idx = start + 1
    while idx < len(lines):
        line = lines[idx]
        if line.strip() and _yaml_indent(line) <= indent:
            break
        idx += 1
    return idx


def _yaml_insert_point(lines, start, end, indent):
    idx = end
    while idx > start and not lines[idx - 1].strip():
        idx -= 1
    return idx if idx > start else end


def _yaml_inline_to_block(lines, idx, key, inline_value):
    indent = _yaml_indent(lines[idx])
    value = inline_value.strip()
    if value.startswith("{") and value.endswith("}"):
        inner = value[1:-1].strip()
        out = [" " * indent + key + ":"]
        if inner:
            for part in inner.split(","):
                part = part.strip()
                if part:
                    out.append(" " * (indent + 2) + part)
        lines[idx:idx + 1] = out
        return
    if value == "":
        return
    raise AgentConfigError(
        "cannot nest keys under `%s: %s` - only an inline {..} mapping "
        "can be expanded" % (key, inline_value))


def yaml_upsert_inline(text, key_path, value):
    """Upsert 嵌套映射键（内联 JSON 值）。块外字节保持不变。"""
    keys = [part.strip() for part in str(key_path).split(".") if part.strip()]
    if not keys:
        raise AgentConfigError("yaml_upsert_inline: empty key path")
    lines = text.split("\n")
    lines = _yaml_upsert_at(lines, 0, len(lines), 0, keys,
                            json.dumps(value, ensure_ascii=False))
    return "\n".join(lines)


def _yaml_upsert_at(lines, start, end, indent, keys, value_json):
    key = keys[0]
    idx = start
    while idx < end:
        line = lines[idx]
        if line.strip() and not line.strip().startswith("#") \
                and _yaml_indent(line) == indent and _yaml_key(line) == key:
            after = line.split(":", 1)[1].strip()
            child_end = _yaml_block_end(lines, idx, indent)
            if len(keys) == 1:
                lines[idx] = " " * indent + key + ": " + value_json
                return lines
            if after:
                _yaml_inline_to_block(lines, idx, key, after)
                child_end = _yaml_block_end(lines, idx, indent)
                lines = _yaml_upsert_at(lines, idx + 1, child_end,
                                        indent + 2, keys[1:], value_json)
                return lines
            lines = _yaml_upsert_at(lines, idx + 1, child_end,
                                    indent + 2, keys[1:], value_json)
            return lines
        idx += 1
    insert = _yaml_insert_point(lines, start, end, indent)
    if len(keys) == 1:
        new_lines = [" " * indent + key + ": " + value_json]
    else:
        new_lines = [" " * indent + keys[0] + ":"]
        new_lines.extend(
            _yaml_upsert_at([], 0, 0, indent + 2, keys[1:], value_json))
    lines[insert:insert] = new_lines
    return lines


def yaml_refs_upsert(text, key, value):
    """Upsert 顶层 `refs:` 块内的键（DSH credentials.yaml 专用）。"""
    lines = text.split("\n")
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if line.strip() and not line.strip().startswith("#") \
                and _yaml_indent(line) == 0 and _yaml_key(line) == "refs":
            after = line.split(":", 1)[1].strip()
            if after:
                raise AgentConfigError(
                    "cannot upsert into `refs: %s` - only a block-style "
                    "refs: mapping is supported" % after)
            end = _yaml_block_end(lines, idx, 0)
            j = idx + 1
            while j < end:
                if lines[j].strip() and _yaml_indent(lines[j]) == 2 \
                        and _yaml_key(lines[j]) == key:
                    lines[j] = "  %s: %s" % (key, value)
                    return "\n".join(lines)
                j += 1
            insert = _yaml_insert_point(lines, idx + 1, end, 2)
            lines[insert:insert] = ["  %s: %s" % (key, value)]
            return "\n".join(lines)
        idx += 1
    while lines and not lines[-1].strip():
        lines.pop()
    lines.append("refs:")
    lines.append("  %s: %s" % (key, value))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 文本级 TOML 编辑器（子集；纯标准库）
# ---------------------------------------------------------------------------

_TOML_TABLE_RE = re.compile(r"^\s*\[([A-Za-z0-9_.-]+)\]\s*(?:#.*)?$")
_TOML_KEY_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=")


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def toml_upsert_top_key(text, key, value):
    """Upsert 顶层 `key = value`（写到第一个 [table] 前）。"""
    lines = text.split("\n")
    rendered = "%s = %s" % (key, _toml_value(value))
    idx = 0
    first_table = len(lines)
    while idx < len(lines):
        if _TOML_TABLE_RE.match(lines[idx]):
            first_table = idx
            break
        m = _TOML_KEY_RE.match(lines[idx])
        if m and m.group(1) == key:
            lines[idx] = rendered
            return "\n".join(lines)
        idx += 1
    # 找顶层段最后一个非空行插入
    insert = first_table
    while insert > 0 and not lines[insert - 1].strip():
        insert -= 1
    lines.insert(insert, rendered)
    return "\n".join(lines)


def toml_upsert_table(text, table, mapping):
    """Upsert `[table]` 下的键值（表不存在则建在文件末尾）。"""
    lines = text.split("\n")
    rendered = ["[%s]" % table]
    for k, v in mapping.items():
        rendered.append("%s = %s" % (k, _toml_value(v)))
    idx = 0
    while idx < len(lines):
        m = _TOML_TABLE_RE.match(lines[idx])
        if m and m.group(1) == table:
            end = idx + 1
            while end < len(lines) and not _TOML_TABLE_RE.match(lines[end]):
                end += 1
            body = dict(mapping)
            j = idx + 1
            while j < end:
                km = _TOML_KEY_RE.match(lines[j])
                if km and km.group(1) in body:
                    lines[j] = "%s = %s" % (km.group(1), _toml_value(body.pop(km.group(1))))
                j += 1
            if body:
                insert = end
                while insert > idx + 1 and not lines[insert - 1].strip():
                    insert -= 1
                extra = ["%s = %s" % (k, _toml_value(v)) for k, v in body.items()]
                lines[insert:insert] = extra
            return "\n".join(lines)
        idx += 1
    while lines and not lines[-1].strip():
        lines.pop()
    lines.append("")
    lines.extend(rendered)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 状态与备份（存网关侧 accounts/；CLI 模式存 ~/.trae-agent-config/）
# ---------------------------------------------------------------------------

def _state_path(accounts_dir):
    return os.path.join(accounts_dir, "agent-state.json")


def _load_state(accounts_dir):
    path = _state_path(accounts_dir)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(accounts_dir, state):
    path = _state_path(accounts_dir)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)


def _backup_dir(accounts_dir, client_id):
    return os.path.join(accounts_dir, "agent-backups", client_id)


def _backup_file(accounts_dir, client_id, path, original):
    directory = _backup_dir(accounts_dir, client_id)
    os.makedirs(directory, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = os.path.basename(path) + "." + stamp + ".bak"
    target = os.path.join(directory, name)
    with open(target, "wb") as fh:
        fh.write(original)
    _prune_backups(directory)
    return target


def _prune_backups(directory, keep=BACKUP_KEEP):
    """每文件只留最新 keep 份；首次接入的原件（.first.bak）永久保留。"""
    if not os.path.isdir(directory):
        return
    groups = {}
    for name in os.listdir(directory):
        if not name.endswith(".bak"):
            continue
        base = name.rsplit(".", 3)[0] if name.count(".") >= 3 else name
        groups.setdefault(base, []).append(name)
    for base, names in groups.items():
        if len(names) <= keep:
            continue
        ordered = sorted(names)   # 时间戳前缀 → 字典序即时间序
        for name in ordered[:len(names) - keep]:
            try:
                os.remove(os.path.join(directory, name))
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 各客户端 apply：输入 ctx，输出 {path: new_text}
# ---------------------------------------------------------------------------

def _claude_settings_path(home):
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return os.path.join(override, "settings.json")
    return os.path.join(home, ".claude", "settings.json")


def _apply_claude_code(paths, ctx):
    path = paths["settings"]
    data = _load_json(path, "claude settings")
    env = dict(data.get("env") or {})
    # Claude Code 自己拼 /v1：给它裸根地址（原生 Anthropic Messages 端点）。
    env["ANTHROPIC_BASE_URL"] = re.sub(r"/v1/?$", "", ctx["base_url"])
    env["ANTHROPIC_AUTH_TOKEN"] = ctx["api_key"]
    if ctx.get("model"):
        for name in ("ANTHROPIC_MODEL",
                     "ANTHROPIC_DEFAULT_SONNET_MODEL",
                     "ANTHROPIC_DEFAULT_OPUS_MODEL",
                     "ANTHROPIC_DEFAULT_HAIKU_MODEL"):
            env[name] = ctx["model"]
    data["env"] = env
    return {path: _dump_json(data)}


def _codex_home(home):
    return os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")


def _apply_codex(paths, ctx):
    config_path = paths["config"]
    text = _read_text(config_path)
    text = toml_upsert_top_key(text, "model_provider", PROVIDER_ID)
    if ctx.get("model"):
        text = toml_upsert_top_key(text, "model", ctx["model"])
    text = toml_upsert_table(text, "model_providers." + PROVIDER_ID, {
        "name": PROVIDER_NAME,
        "base_url": ctx["base_url_v1"],
        "wire_api": "responses",
        "env_key": "OPENAI_API_KEY",
    })
    auth_path = paths["auth"]
    auth = _load_json(auth_path, "codex auth")
    auth = deep_merge(auth, {"OPENAI_API_KEY": ctx["api_key"]})
    return {config_path: text, auth_path: _dump_json(auth)}


def _apply_opencode(paths, ctx):
    path = paths["config"]
    data = _load_json(path, "opencode config")
    models = []
    for entry in ctx.get("models") or []:
        mid = entry.get("id")
        if not mid:
            continue
        item = {"id": mid, "name": mid}
        if entry.get("context_window"):
            item["contextWindow"] = entry["context_window"]
        if entry.get("max_output"):
            item["limit"] = entry["max_output"]
        models.append(item)
    provider = {
        "npm": "@ai-sdk/openai-compatible",
        "name": PROVIDER_NAME,
        "options": {
            "baseURL": ctx["base_url_v1"],
            "apiKey": ctx["api_key"],
        },
        "models": models,
    }
    data = deep_merge(data, {"provider": {PROVIDER_ID: provider}})
    return {path: _dump_json(data)}


def _dsh_home(home):
    return os.environ.get("DSH_HOME") or os.path.join(home, ".dsh")


def _apply_dsh(paths, ctx):
    settings_path = paths["settings"]
    text = _read_text(settings_path)
    models = []
    for entry in ctx.get("models") or []:
        mid = entry.get("id")
        if not mid:
            continue
        item = {"id": mid}
        if entry.get("context_window"):
            item["contextWindow"] = entry["context_window"]
        models.append(item)
    provider = {
        "displayName": PROVIDER_NAME,
        "apiKeyEnv": CREDENTIAL_REF,
        "api": "openai-completions",
        "baseURL": ctx["base_url_v1"],
    }
    if models:
        provider["models"] = models
    text = yaml_upsert_inline(
        text, "llm-pi-ai.providers.%s" % PROVIDER_ID, provider)
    if ctx.get("model"):
        text = yaml_upsert_inline(
            text, "agent-default-model",
            {"provider": PROVIDER_ID, "model": ctx["model"]})
    credentials_path = paths["credentials"]
    cred_text = _read_text(credentials_path)
    cred_text = yaml_refs_upsert(cred_text, CREDENTIAL_REF, ctx["api_key"])
    return {settings_path: text, credentials_path: cred_text}


def _apply_crush(paths, ctx):
    path = paths["config"]
    data = _load_json(path, "crush config")
    models = []
    for entry in ctx.get("models") or []:
        mid = entry.get("id")
        if not mid:
            continue
        item = {"id": mid, "name": mid}
        if entry.get("context_window"):
            item["context_window"] = entry["context_window"]
        if entry.get("max_output"):
            item["default_max_tokens"] = entry["max_output"]
        models.append(item)
    provider = {
        "name": PROVIDER_NAME,
        "type": "openai",
        "base_url": ctx["base_url_v1"],
        "api_key": ctx["api_key"],
        "models": models,
    }
    data = deep_merge(data, {"providers": {PROVIDER_ID: provider}})
    return {path: _dump_json(data)}


# ---------------------------------------------------------------------------
# 客户端注册表
# ---------------------------------------------------------------------------

CLIENTS = {
    "claude-code": {
        "id": "claude-code",
        "label": "Claude Code",
        "desc": "Anthropic CLI；走网关原生 /v1/messages（ANTHROPIC_BASE_URL）。",
        "protocol": "anthropic",
        "files": lambda home: {
            "settings": _claude_settings_path(home),
        },
        "probe": lambda home: (
            os.path.isdir(os.environ.get("CLAUDE_CONFIG_DIR")
                         or os.path.join(home, ".claude"))
            or os.path.isfile(_claude_settings_path(home))
            or bool(shutil.which("claude"))
        ),
        "apply": _apply_claude_code,
    },
    "codex": {
        "id": "codex",
        "label": "Codex CLI",
        "desc": "OpenAI Codex CLI；注册 trae2api-hub Responses provider。",
        "protocol": "openai",
        "files": lambda home: {
            "config": os.path.join(_codex_home(home), "config.toml"),
            "auth": os.path.join(_codex_home(home), "auth.json"),
        },
        "probe": lambda home: (
            os.path.isdir(_codex_home(home))
            or os.path.isfile(os.path.join(_codex_home(home), "config.toml"))
            or bool(shutil.which("codex"))
        ),
        "apply": _apply_codex,
    },
    "opencode": {
        "id": "opencode",
        "label": "OpenCode",
        "desc": "OpenCode；注册 openai-compatible provider。",
        "protocol": "openai",
        "files": lambda home: {
            "config": os.path.join(home, ".config", "opencode", "opencode.json"),
        },
        "probe": lambda home: (
            os.path.isdir(os.path.join(home, ".config", "opencode"))
            or os.path.isfile(os.path.join(home, ".config", "opencode",
                                           "opencode.json"))
            or bool(shutil.which("opencode"))
        ),
        "apply": _apply_opencode,
    },
    "dsh": {
        "id": "dsh",
        "label": "DSH (DeepSeek Harness)",
        "desc": "DSH；llm-pi-ai 注册 trae2api-hub provider，Key 走 credentials refs。",
        "protocol": "openai",
        "files": lambda home: {
            "settings": os.path.join(_dsh_home(home), "settings.yaml"),
            "credentials": os.path.join(_dsh_home(home), ".credentials.yaml"),
        },
        "probe": lambda home: (
            os.path.isdir(_dsh_home(home))
            or os.path.isfile(os.path.join(_dsh_home(home), "settings.yaml"))
            or bool(shutil.which("dsh"))
        ),
        "apply": _apply_dsh,
    },
    "crush": {
        "id": "crush",
        "label": "Crush (Charm)",
        "desc": "Charm Crush；providers 注册 openai 型 trae2api-hub。",
        "protocol": "openai",
        "files": lambda home: {
            "config": os.path.join(home, ".config", "crush", "crush.json"),
        },
        "probe": lambda home: (
            os.path.isdir(os.path.join(home, ".config", "crush"))
            or os.path.isfile(os.path.join(home, ".config", "crush",
                                           "crush.json"))
            or bool(shutil.which("crush"))
        ),
        "apply": _apply_crush,
    },
}


def _client(client_id):
    client = CLIENTS.get(client_id)
    if not client:
        raise AgentConfigError("unknown client %r (have: %s)"
                               % (client_id, ", ".join(sorted(CLIENTS))))
    return client


# ---------------------------------------------------------------------------
# 三主入口：overview / plan / integrate / restore
# ---------------------------------------------------------------------------

def overview(accounts_dir, home=None):
    """本机探测：装了哪些客户端、各自的接入状态（只读，不碰任何文件）。"""
    home = _resolve_home(home)
    state = _load_state(accounts_dir)
    out = []
    for client_id in sorted(CLIENTS):
        client = CLIENTS[client_id]
        installed = bool(client["probe"](home))
        record = state.get(client_id) if installed else None
        out.append({
            "id": client_id,
            "label": client["label"],
            "desc": client["desc"],
            "protocol": client["protocol"],
            "installed": installed,
            "configured": bool(isinstance(record, dict)
                               and record.get("files")),
            "applied_at": (record or {}).get("applied_at"),
            "base_url": (record or {}).get("base_url"),
            "model": (record or {}).get("model"),
        })
    return {"clients": out}


def plan(client_id, base_url, api_key, model=None, models=None, home=None):
    """integrate() 会写的确切文件内容；不落盘。dry-run 与真实写入共享它。"""
    client = _client(client_id)
    home = _resolve_home(home)
    base_url = str(base_url or "").strip().rstrip("/")
    if not re.match(r"^https?://", base_url):
        raise AgentConfigError("base_url must start with http:// or https://")
    base_url_v1 = base_url if base_url.endswith("/v1") else base_url + "/v1"
    ctx = {
        "base_url": base_url,
        "base_url_v1": base_url_v1,
        "api_key": str(api_key or ""),
        "model": str(model or "").strip() or None,
        "models": list(models or []),
    }
    paths = client["files"](home)
    try:
        new_contents = client["apply"](paths, ctx)
    except AgentConfigError:
        raise
    except Exception as exc:
        raise AgentConfigError("failed to build %s config: %s"
                               % (client_id, exc))
    files = []
    for path in paths.values():
        content = new_contents.get(path)
        if content is None:
            continue
        files.append({
            "path": path,
            "content": content,
            "existed": os.path.exists(path),
        })
    return {
        "client": client_id,
        "label": client["label"],
        "base_url": base_url,
        "model": ctx["model"],
        "files": files,
    }


def integrate(accounts_dir, client_id, base_url, api_key, model=None,
              models=None, home=None):
    """把 client_id 指向本网关；返回写入明细。

    首次 apply 备份每个被碰文件的原件字节；后续 apply 保留最早那份备份
    （restore 永远回到**第一次接入前**）。多文件客户端两阶段写入：
    任一文件失败，已写文件整体回滚。
    """
    built = plan(client_id, base_url, api_key, model=model, models=models,
                 home=home)
    state = _load_state(accounts_dir)
    record = state.get(client_id) or {}
    previous_files = {entry.get("path"): entry
                      for entry in record.get("files") or []
                      if isinstance(entry, dict)}
    # Phase 1：先备份，后动手。
    staged = []
    for entry in built["files"]:
        path, content, existed = entry["path"], entry["content"], entry["existed"]
        prior = previous_files.get(path)
        if prior is not None and not prior.get("existed") and existed:
            # 上次 apply 我们建的文件：仍是原样就还是「我们的」，restore 删它
            # 而不是复活我们写的字节（可能含 Key）；被手改过才算用户的文件。
            try:
                if _sha256_bytes(_read_bytes(path)) == prior.get("sha256"):
                    existed = False
            except AgentConfigError:
                pass
        backup = None
        if existed and prior and prior.get("backup"):
            backup = prior.get("backup")
        elif existed:
            backup = _backup_file(accounts_dir, client_id, path,
                                  _read_bytes(path))
        staged.append((path, content, existed, backup))

    # Phase 2：事务式写入；失败回滚已写的。
    written = []
    entries = []
    try:
        for path, content, existed, backup in staged:
            _atomic_write_text(path, content)
            written.append((path, existed, backup))
            entries.append({
                "path": path,
                "existed": existed,
                "backup": backup,
                "sha256": _sha256_bytes(content.encode("utf-8")),
                "bytes": len(content.encode("utf-8")),
            })
    except Exception as exc:
        for w_path, w_existed, w_backup in written:
            try:
                if w_existed and w_backup:
                    _atomic_write_bytes(w_path, _read_bytes(w_backup))
                elif not w_existed and os.path.exists(w_path):
                    os.unlink(w_path)
            except Exception:
                pass
        raise AgentConfigError("failed to write %s files: %s" % (client_id, exc))

    state[client_id] = {
        "applied_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": built["base_url"],
        "model": built["model"],
        "files": entries,
    }
    _save_state(accounts_dir, state)
    return {
        "client": client_id,
        "label": built["label"],
        "applied_at": state[client_id]["applied_at"],
        "base_url": built["base_url"],
        "model": built["model"],
        "files": entries,
    }


def restore(accounts_dir, client_id, home=None):
    """撤销 integrate()：byte-exact 放回原件；我们建的文件删除。"""
    client = _client(client_id)
    home = _resolve_home(home)
    state = _load_state(accounts_dir)
    record = state.get(client_id)
    if not isinstance(record, dict) or not record.get("files"):
        raise AgentConfigError(
            "%s has no recorded integration to restore" % client["label"])
    restored = []
    for entry in record.get("files") or []:
        path = entry.get("path")
        if not path:
            continue
        if entry.get("existed") and entry.get("backup"):
            backup = entry["backup"]
            if not os.path.exists(backup):
                raise AgentConfigError(
                    "backup missing for %s: %s" % (path, backup))
            _atomic_write_bytes(path, _read_bytes(backup))
            restored.append({"path": path, "action": "restored"})
        else:
            try:
                os.remove(path)
                restored.append({"path": path, "action": "deleted"})
            except FileNotFoundError:
                restored.append({"path": path, "action": "already-absent"})
            _prune_empty_parents(path, home)
    state.pop(client_id, None)
    _save_state(accounts_dir, state)
    return {
        "client": client_id,
        "label": client["label"],
        "restored": restored,
    }


def fetch_models_from_gateway(base_url, api_key, timeout=10):
    """网关模型清单（顺带验证 Key：401 = Key 被拒）。"""
    base = str(base_url or "").strip().rstrip("/")
    if not re.match(r"^https?://", base):
        raise AgentConfigError("base_url must start with http:// or https://")
    if base.endswith("/v1"):
        base = base[:-3]
    request = urllib.request.Request(
        base + "/v1/models",
        headers={"Authorization": "Bearer " + str(api_key or "")})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise AgentConfigError(
                "the gateway rejected the API key (HTTP 401)")
        raise AgentConfigError("gateway /v1/models failed: HTTP %s" % exc.code)
    except ValueError as exc:
        raise AgentConfigError(
            "gateway /v1/models returned invalid JSON: %s" % exc)
    except Exception as exc:
        raise AgentConfigError(
            "cannot reach the gateway /v1/models: %s" % exc)
    models = []
    seen = set()
    for item in (payload.get("data") or []):
        if not isinstance(item, dict):
            continue
        mid = str(item.get("id") or "").strip()
        if not mid or mid in seen:
            continue
        seen.add(mid)
        entry = {"id": mid}
        context = item.get("context_length") or item.get("max_input_tokens")
        if context:
            try:
                entry["context_window"] = int(context)
            except (TypeError, ValueError):
                pass
        out_tokens = item.get("max_output_tokens")
        if out_tokens:
            try:
                entry["max_output"] = int(out_tokens)
            except (TypeError, ValueError):
                pass
        name = item.get("name")
        if name:
            entry["name"] = str(name)
        models.append(entry)
    return models[:80]


# ---------------------------------------------------------------------------
# 独立 CLI（客户端装在别的机器时：改**本机**配置，只从网关取模型表）
# ---------------------------------------------------------------------------

def _default_state_dir():
    return os.path.join(_resolve_home(), ".trae-agent-config")


def _mask_key(key):
    key = str(key or "")
    if len(key) <= 12:
        return "*" * len(key)
    return key[:6] + "..." + key[-4:]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[0]
    state_dir = os.environ.get("TRAE_AGENT_STATE") or _default_state_dir()
    if cmd == "list":
        info = overview(state_dir)
        for c in info["clients"]:
            mark = ("[configured]" if c["configured"]
                    else "[installed]" if c["installed"] else "[absent]")
            print("%-12s %-28s %s" % (c["id"], mark, c["label"]))
        return 0
    if cmd in ("plan", "apply", "restore"):
        args = dict(zip(argv[1::2], argv[2::2]))
        client_id = args.get("--client")
        if not client_id:
            print("usage: %s --client <id> [--base-url URL] [--key KEY] "
                  "[--model M] [--no-models]" % cmd)
            return 2
        if cmd == "restore":
            try:
                result = restore(state_dir, client_id)
            except AgentConfigError as exc:
                print("[ERROR] %s" % exc)
                return 1
            for r in result["restored"]:
                print("  %-40s %s" % (r["path"], r["action"]))
            print("restored %s" % result["label"])
            return 0
        base_url = args.get("--base-url") or os.environ.get("TRAE_BASE_URL")
        api_key = args.get("--key") or os.environ.get(CREDENTIAL_REF)
        model = args.get("--model")
        if not base_url or not api_key:
            print("[ERROR] --base-url and --key are required "
                  "(or env TRAE_BASE_URL / %s)" % CREDENTIAL_REF)
            return 2
        models = []
        if "--no-models" not in args:
            try:
                models = fetch_models_from_gateway(base_url, api_key)
                print("fetched %d models from the gateway" % len(models))
            except AgentConfigError as exc:
                print("[WARN] %s (continuing without model list; "
                      "use --no-models to silence)" % exc)
        if cmd == "plan":
            result = plan(client_id, base_url, api_key, model=model,
                          models=models)
            for f in result["files"]:
                print("=== %s (existed: %s) ===" % (f["path"], f["existed"]))
                print(f["content"])
            return 0
        result = integrate(state_dir, client_id, base_url, api_key,
                           model=model, models=models)
        print("applied %s at %s" % (result["label"], result["applied_at"]))
        for f in result["files"]:
            print("  %-40s %d bytes (existed: %s)"
                  % (f["path"], f["bytes"], f["existed"]))
        return 0
    print("unknown command %r (have: list, plan, apply, restore)" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main())