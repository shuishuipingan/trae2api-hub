# -*- coding: utf-8 -*-
"""trae_qoder.py —— 把 Qoder CN 接入本网关（第三个上游通道）

本模块只做三件事，不碰 trae_proxy 的任何既有逻辑：

  1. **凭据**：从 Qoder CN 桌面端读登录态（只读，绝不写回）
       %APPDATA%/com.qodercn.app.stable/Local State   -> os_crypt.encrypted_key（DPAPI）
       %APPDATA%/com.qodercn.app.stable/auth.v1.dat   -> v10 + nonce(12) + ct + tag(16)，AES-256-GCM
     机器指纹取 ~/.qoder-cn/umid-cache.json 的 info.machineCode。

  2. **协议**：Qoder 不是 OpenAI 兼容端点，必须复现三套机制
       a. COSY 签名头 —— Authorization: Bearer COSY.<payload>.<sig>，
          签名是 MD5(base64负载 \n RSA包裹的AES key \n 时间戳 \n 请求体 \n 签名路径)
       b. 置换 base64 请求体 —— 查询串带 Encode=1 时，JSON 先 base64、
          再按换过的字母表逐字符替换、最后按三分之一旋转
       c. 双层 SSE —— 每个 data: 帧是信封对象，body 字段本身又是 JSON 字符串，
          里面才是 OpenAI 风格的 chunk

  3. **接口**：model_list / stream_chat，输出统一成 OpenAI 词汇。

依赖：只用标准库 + trae_client 的纯 Python AES（`aes_cbc_encrypt`）。
RSA 用 pow() 手写 PKCS#1 v1.5 加密，不引入 pycryptodome——网关的零依赖是
刻意设计，加一个 C 扩展依赖等于让 Docker 镜像和裸机部署都多一道坑。

协议事实来源：Qoder CN 桌面端 0.5.11 客户端行为 + 社区还原（dsh-connect-qoder）。
上游随时可能改；改了这一层，聊天会回 `provider_error` 或形状漂移，不会静默出错。
"""

import base64
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

# ---------------------------------------------------------------------------
# 协议常量（客户端实测值，不是配置）
# ---------------------------------------------------------------------------

#: 网关用来包裹每次请求 AES key 的 RSA 公钥（1024 位）。
QODER_RSA_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc"
    "4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l"
    "6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17"
    "XcW+ML9FoCI6AOvOzwIDAQAB"
)

#: Encode=1 用的置换字母表（与标准 base64 位置一一对应）。
CUSTOM_ALPHABET = ('_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)'
                   'sUrthbf%Y^w.(kIQyXqWA!')
STD_ALPHABET = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                '0123456789+/')

COSY_VERSION = "1.1.38"
CLIENT_TYPE = "5"
MACHINE_TYPE = "5"
DATA_POLICY = "disagree"
LOGIN_VERSION = "v2"

#: 网关对 MachineOS 不做门控（实测 x86_64_linux / aarch64_darwin 等一律 200），
#: 所以这里如实上报宿主平台，而不是编一个"更安全"的值。
if sys.platform == "win32":
    MACHINE_OS = "aarch64_windows" if os.environ.get("PROCESSOR_ARCHITECTURE") == "ARM64" \
        else "x86_64_windows"
elif sys.platform == "darwin":
    MACHINE_OS = "aarch64_darwin" if os.uname().machine == "arm64" else "x86_64_darwin"
else:
    MACHINE_OS = "aarch64_linux" if os.uname().machine in ("aarch64", "arm64") \
        else "x86_64_linux"

#: 国内版主机。国际版是 api3.qoder.sh，本模块只接国内版（凭据来自 Qoder CN）。
OPENAPI_BASE = "https://openapi.qoder.com.cn"
GATEWAY_BASE = "https://gateway.qoder.com.cn"

PATH_MODEL_LIST = "/algo/api/v2/model/list?Encode=1"
PATH_CHAT = ("/algo/api/v2/service/pro/sse/agent_chat_generation"
             "?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1")

#: 拒绝 `enable_thinking:false` 的模型（回 1210 "API 调用参数有误"）。
#: 这些只能"正向请求思考"或干脆不提该字段；发 false 会让整轮失败。
#:
#: 实测（2026-11-14，Qoder CN 0.5.11）：GLM-5.3 在 `parameters={}` 与
#: `{enable_thinking:true}` 下都正常出流，唯独 `{enable_thinking:false}`
#: 回 1210。这不是"模型不支持思考"，而是"不接受被显式关闭"——所以对它们
#: 默认省略该字段，让上游用自己的默认档位。
ALWAYS_THINKING_KEYS = frozenset({"gmodel", "gfmodel"})

MODEL_CACHE_TTL = 300          # 模型列表缓存（秒）
REQUEST_TIMEOUT = 120          # 单次请求超时


# ---------------------------------------------------------------------------
# 凭据
# ---------------------------------------------------------------------------

def _appdata():
    return os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")


def qoder_dir():
    """Qoder CN 的用户数据目录。可用 QODER_CN_DATA_DIR 覆盖（容器/换机部署）。"""
    override = os.environ.get("QODER_CN_DATA_DIR")
    if override:
        return override
    return os.path.join(_appdata(), "com.qodercn.app.stable")


def umid_cache_path():
    override = os.environ.get("QODER_CN_UMID_CACHE")
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".qoder-cn", "umid-cache.json")


def _dpapi_unprotect(blob):
    """CryptUnprotectData（当前用户作用域）。Windows only。"""
    if sys.platform != "win32":
        raise RuntimeError("Qoder 桌面端凭据解密只在 Windows 上成立（DPAPI）")
    import ctypes
    import ctypes.wintypes as wt

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _mk(data):
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data),
                     ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    blobin, _keep = _mk(blob)
    blobout = _Blob()
    if not crypt32.CryptUnprotectData(ctypes.byref(blobin), None, None, None,
                                      None, 0, ctypes.byref(blobout)):
        raise OSError("CryptUnprotectData failed: %d" % ctypes.get_last_error())
    try:
        return ctypes.string_at(blobout.pbData, blobout.cbData)
    finally:
        kernel32.LocalFree(blobout.pbData)


def _aes_gcm_decrypt(key, blob):
    """v10 + nonce(12) + ct + tag(16) 的 AES-256-GCM 解密。

    AES-GCM 标准库没有，这里用 trae_client 的 AES 原语拼 CTR + GHASH 太重；
    桌面端凭据只在 Windows 上可读，而 Windows 上 Python 3.13 的 hashlib 不带
    GCM。退路：优先用 pycryptodome（如果装了），没有就报一条明确的错。
    """
    try:
        from Crypto.Cipher import AES as _AES
    except Exception:                                          # noqa: BLE001
        raise RuntimeError(
            "解密 Qoder 凭据需要 pycryptodome（pip install pycryptodome）；"
            "或设置 QODER_CN_TOKEN 直接给一个 dt- 令牌")
    if blob[:3] != b"v10":
        raise ValueError("auth.v1.dat 头不是 v10：%r" % blob[:3])
    body = blob[3:]
    cipher = _AES.new(key, _AES.MODE_GCM, nonce=body[:12], mac_len=16)
    return cipher.decrypt_and_verify(body[12:-16], body[-16:])


def _master_key():
    path = os.path.join(qoder_dir(), "Local State")
    with open(path, "r", encoding="utf-8") as handle:
        state = json.load(handle)
    raw = base64.b64decode(state["os_crypt"]["encrypted_key"])
    if raw[:5] != b"DPAPI":
        raise ValueError("encrypted_key 前缀不是 DPAPI：%r" % raw[:5])
    return _dpapi_unprotect(raw[5:])


def _machine_code():
    try:
        with open(umid_cache_path(), "r", encoding="utf-8") as handle:
            cache = json.load(handle)
        code = (cache.get("info") or {}).get("machineCode")
        if code:
            return str(code)
    except (OSError, ValueError):
        pass
    return ""


def load_credential():
    """读 Qoder CN 登录态。返回 dict，失败抛异常（由调用方决定怎么报）。

    优先级：
      1. 环境变量 QODER_CN_TOKEN（容器/无桌面端部署的唯一可行路径）
      2. 桌面端 auth.v1.dat
    """
    token = (os.environ.get("QODER_CN_TOKEN") or "").strip()
    uid = (os.environ.get("QODER_CN_UID") or "").strip()
    if token:
        return {
            "userID": uid,
            "token": token,
            "name": os.environ.get("QODER_CN_NAME") or "",
            "email": os.environ.get("QODER_CN_EMAIL") or "",
            "machineID": os.environ.get("QODER_CN_MACHINE_ID") or _machine_code(),
            "source": "env",
        }

    key = _master_key()
    with open(os.path.join(qoder_dir(), "auth.v1.dat"), "rb") as handle:
        blob = handle.read()
    auth = json.loads(_aes_gcm_decrypt(key, blob).decode("utf-8"))
    user = auth.get("user") or {}
    return {
        "userID": user.get("id") or "",
        "token": auth.get("token") or "",
        "name": user.get("name") or "",
        "email": user.get("email") or "",
        "machineID": _machine_code(),
        "source": "desktop",
        "expiresAt": auth.get("expiresAt") or "",
    }


def credential_available():
    """轻量探测：能不能拿到凭据（不抛异常，供 /v1/models 决定要不要列 Qoder）。"""
    try:
        cred = load_credential()
        return bool(cred.get("token"))
    except Exception:                                          # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Encode=1：置换 base64
# ---------------------------------------------------------------------------

def _build_encode_table():
    table = list(range(256))
    for index, char in enumerate(STD_ALPHABET):
        table[ord(char)] = ord(CUSTOM_ALPHABET[index])
    table[ord("=")] = ord("$")
    return table


_ENCODE_TABLE = _build_encode_table()


def encode_body(plaintext):
    """base64 → 置换字母表 → 按三分之一旋转（末三分之一提到最前）。

    三段顺序是 [n-third, n) + [third, n-third) + [0, third)，
    不是"每三分之一内部倒序"——顺序错了网关会回签名/解析错误。
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    std = base64.b64encode(plaintext).decode("ascii")
    total = len(std)
    third = total // 3
    out = []
    for i in range(total - third, total):
        out.append(chr(_ENCODE_TABLE[ord(std[i])]))
    for i in range(third, total - third):
        out.append(chr(_ENCODE_TABLE[ord(std[i])]))
    for i in range(0, third):
        out.append(chr(_ENCODE_TABLE[ord(std[i])]))
    return "".join(out).encode("ascii")


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5 加密（纯 Python，只依赖 pow）
# ---------------------------------------------------------------------------

def _der_read(buf, pos):
    """读一个 DER TLV，返回 (tag, value_bytes, next_pos)。"""
    tag = buf[pos]
    pos += 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    return tag, buf[pos:pos + length], pos + length


def _rsa_public_key():
    """把 SPKI base64 解成 (n, e)。只支持这一种固定的 1024 位 RSA 公钥。"""
    der = base64.b64decode(QODER_RSA_PUBLIC_KEY_B64)
    tag, spki, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError("SPKI 不是 SEQUENCE")
    pos = 0
    # AlgorithmIdentifier
    _, _alg, pos = _der_read(spki, pos)
    # BIT STRING 包着 RSAPublicKey
    tag, bits, _ = _der_read(spki, pos)
    if tag != 0x03:
        raise ValueError("SPKI 里没有 BIT STRING")
    inner = bits[1:]                      # 跳过 unused-bits 计数
    _, rsa_key, _ = _der_read(inner, 0)
    pos = 0
    _, modulus, pos = _der_read(rsa_key, pos)
    _, exponent, _ = _der_read(rsa_key, pos)
    return (int.from_bytes(modulus, "big"),
            int.from_bytes(exponent, "big"))


_RSA_KEY = None
_RSA_LOCK = threading.Lock()


def _rsa_key():
    global _RSA_KEY
    if _RSA_KEY is None:
        with _RSA_LOCK:
            if _RSA_KEY is None:
                _RSA_KEY = _rsa_public_key()
    return _RSA_KEY


def rsa_encrypt_pkcs1v15(message):
    """PKCS#1 v1.5 加密，输出 base64。

    填充：0x00 0x02 [非零随机字节...] 0x00 [明文]
    长度必须恰好 k-3-len(msg)，随机字节里不许出现 0x00。
    """
    modulus, exponent = _rsa_key()
    k = (modulus.bit_length() + 7) // 8
    if len(message) > k - 11:
        raise ValueError("明文超过 RSA 可加密长度")
    padding_len = k - 3 - len(message)
    padding = bytearray()
    while len(padding) < padding_len:
        chunk = os.urandom(padding_len - len(padding))
        padding.extend(b for b in chunk if b != 0)
    block = b"\x00\x02" + bytes(padding[:padding_len]) + b"\x00" + message
    cipher = pow(int.from_bytes(block, "big"), exponent, modulus)
    return base64.b64encode(cipher.to_bytes(k, "big")).decode("ascii")


# ---------------------------------------------------------------------------
# COSY 签名
# ---------------------------------------------------------------------------

def _aes_cbc_base64(plaintext, key_string):
    """AES-128-CBC（key 兼作 IV）+ PKCS#7，输出 base64。

    复用 trae_client 的纯 Python AES 实现，保持零第三方依赖。
    """
    import trae_client

    key = key_string.encode("utf-8")
    raw = trae_client.aes_cbc_encrypt(plaintext.encode("utf-8"), key, key)
    return base64.b64encode(raw).decode("ascii")


def signature_path(url):
    """签名覆盖的路径：去掉网关路由掉的 /algo 前缀。"""
    path = urllib.parse.urlparse(url).path
    if path.startswith("/algo"):
        path = path[len("/algo"):]
    return path


def auth_headers(body_bytes, url, cred):
    """组装一次请求的完整 COSY 头。

    每一步都是承重的：
      · info 块用 AES-128-CBC 加密（key 随请求随机生成，兼作 IV）
      · 该 AES key 再用网关 RSA 公钥包裹
      · payload 是 {version, requestId, info, cosyVersion, ideVersion} 的 base64
      · 签名 = MD5(payload_b64 \\n cosyKey \\n timestamp \\n body \\n path)
    少一个换行、少一段，网关回签名错误而不是 401，排查会很难。
    """
    aes_key = uuid.uuid4().hex[:16]
    info_b64 = _aes_cbc_base64(json.dumps({
        "uid": cred.get("userID") or "",
        "security_oauth_token": cred.get("token") or "",
        "name": cred.get("name") or "",
        "aid": "",
        "email": cred.get("email") or "",
    }, separators=(",", ":")), aes_key)
    cosy_key = rsa_encrypt_pkcs1v15(aes_key.encode("utf-8"))

    timestamp = str(int(time.time()))
    payload_b64 = base64.b64encode(json.dumps({
        "version": "v1",
        "requestId": str(uuid.uuid4()),
        "info": info_b64,
        "cosyVersion": COSY_VERSION,
        "ideVersion": "",
    }, separators=(",", ":")).encode("utf-8")).decode("ascii")

    path = signature_path(url)
    digest = hashlib.md5()
    digest.update(payload_b64.encode("ascii"))
    digest.update(b"\n")
    digest.update(cosy_key.encode("ascii"))
    digest.update(b"\n")
    digest.update(timestamp.encode("ascii"))
    digest.update(b"\n")
    digest.update(body_bytes)
    digest.update(b"\n")
    digest.update(path.encode("ascii"))

    machine_id = cred.get("machineID") or ""
    return {
        "Authorization": "Bearer COSY.%s.%s" % (payload_b64, digest.hexdigest()),
        "Cosy-Key": cosy_key,
        "Cosy-User": cred.get("userID") or "",
        "Cosy-Date": timestamp,
        "Cosy-Version": COSY_VERSION,
        "Cosy-Machineid": machine_id,
        "Cosy-Machinetoken": machine_id,
        "Cosy-Machinetype": MACHINE_TYPE,
        "Cosy-Machineos": MACHINE_OS,
        "Cosy-Clienttype": CLIENT_TYPE,
        "Cosy-Clientip": "127.0.0.1",
        "Cosy-Bodyhash": hashlib.md5(body_bytes).hexdigest(),
        "Cosy-Bodylength": str(len(body_bytes)),
        "Cosy-Sigpath": path,
        "Cosy-Data-Policy": DATA_POLICY,
        "Cosy-Organization-Id": "",
        "Cosy-Organization-Tags": "",
        "Login-Version": LOGIN_VERSION,
        "X-Request-Id": str(uuid.uuid4()),
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class QoderError(Exception):
    """上游/凭据类错误。带 status，便于网关映射成对应 HTTP 码。"""

    def __init__(self, message, status=502, kind="qoder_error"):
        Exception.__init__(self, message)
        self.message = message
        self.status = status
        self.kind = kind


def _open(url, cred, body=None, extra_headers=None, timeout=None, method=None):
    raw = b"" if body is None else json.dumps(
        body, separators=(",", ":")).encode("utf-8")
    # Encode=1 的接口：请求体要按置换字母表编码后再签名（签名覆盖的是编码后
    # 的字节，不是原文），顺序错了网关会认为 body 被篡改。
    payload = encode_body(raw) if body is not None and "Encode=1" in url else raw

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    headers.update(auth_headers(payload, url, cred))
    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(
        url,
        data=payload if body is not None else None,
        headers=headers,
        method=method or ("POST" if body is not None else "GET"),
    )
    try:
        return urllib.request.urlopen(request, timeout=timeout or REQUEST_TIMEOUT)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:500]
        except Exception:                                      # noqa: BLE001
            pass
        raise QoderError("Qoder HTTP %s: %s" % (exc.code, detail),
                         status=exc.code, kind="upstream_http")
    except urllib.error.URLError as exc:
        raise QoderError("Qoder 网络不可达: %s" % exc.reason,
                         status=502, kind="network")


# ---------------------------------------------------------------------------
# 模型目录
# ---------------------------------------------------------------------------

_MODEL_CACHE = {"at": 0.0, "rows": None}
_MODEL_LOCK = threading.Lock()


def _context_window(item):
    """从 context_config 取默认档位的 token 数（没有就退 max_input_tokens）。"""
    config = item.get("context_config")
    if isinstance(config, dict):
        for _name, entry in config.items():
            if isinstance(entry, dict) and entry.get("is_default"):
                value = entry.get("token_count")
                if isinstance(value, int) and value > 0:
                    return value
    value = item.get("max_input_tokens")
    return value if isinstance(value, int) and value > 0 else None


def _thinking_supported(item):
    """thinking_config.enabled 存在即支持；disabled 单独出现表示只能关。"""
    config = item.get("thinking_config")
    if not isinstance(config, dict):
        return None
    if "enabled" in config:
        return True
    if "disabled" in config:
        return False
    return None


def normalize_model(item):
    """把 Qoder 的模型对象整成本网关统一的行形状。"""
    key = str(item.get("key") or "").strip()
    if not key:
        return None
    return {
        "key": key,
        "upstream_key": key,
        "display_name": str(item.get("display_name") or key),
        "name": key,
        "model_type": "chat",
        "multimodal": bool(item.get("is_vl")),
        "context_window": _context_window(item),
        "context_window_max": None,
        "max_tokens": None,
        "is_default": bool(item.get("is_default")),
        "is_new": bool(item.get("is_new")),
        "thinking": {"supported": _thinking_supported(item),
                     "options": [], "default_level": None},
        "chat": True,
        "enabled": item.get("enable") is not False,
        "status": item.get("status"),
        "consumption_rate": item.get("price_factor"),
        "provider": "qoder",
        "realm": "qoder",
        "available": item.get("enable") is not False,
        "dynamic": True,
    }


def model_list(cred=None, refresh=False, timeout=None):
    """拉 Qoder 模型目录，返回统一行形状的 list。带 5 分钟缓存。"""
    with _MODEL_LOCK:
        cached = _MODEL_CACHE.get("rows")
        if (not refresh and cached is not None
                and time.time() - _MODEL_CACHE["at"] < MODEL_CACHE_TTL):
            return cached

    cred = cred or load_credential()
    if not cred.get("token"):
        raise QoderError("Qoder 凭据缺失", status=401, kind="no_credential")

    response = _open(GATEWAY_BASE + PATH_MODEL_LIST, cred, body=None,
                     timeout=timeout or 30)
    try:
        raw = response.read()
    finally:
        response.close()
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise QoderError("Qoder 模型目录不是合法 JSON", status=502,
                         kind="protocol_shape")

    groups = payload.get("chat")
    if not isinstance(groups, list):
        # 分组改名/缺失属于"协议形状变了"，不是"没有模型"——两者要分开报，
        # 否则账号被收窄会被误读成接口坏掉。
        raise QoderError("Qoder 模型目录缺少 chat 分组（协议形状可能已变）",
                         status=502, kind="protocol_shape")

    rows = []
    for item in groups:
        if not isinstance(item, dict):
            continue
        row = normalize_model(item)
        if row:
            rows.append(row)

    with _MODEL_LOCK:
        _MODEL_CACHE["at"] = time.time()
        _MODEL_CACHE["rows"] = rows
    return rows


def invalidate_models():
    with _MODEL_LOCK:
        _MODEL_CACHE["at"] = 0.0
        _MODEL_CACHE["rows"] = None


def model_keys():
    """{key, display_name} 都算可选中的名字，供路由判断"这是不是 Qoder 的模型"。"""
    try:
        rows = model_list()
    except Exception:                                          # noqa: BLE001
        return set()
    names = set()
    for row in rows:
        names.add(row["key"])
        names.add(row["display_name"])
    return names


def resolve_model(name):
    """客户端给的名字 -> Qoder 的 model key。命中不了返回 None。"""
    if not name:
        return None
    raw = str(name).strip()
    try:
        rows = model_list()
    except Exception:                                          # noqa: BLE001
        return None
    lowered = raw.lower()
    for row in rows:
        if raw == row["key"] or raw == row["display_name"]:
            return row["key"]
    for row in rows:
        if lowered == row["key"].lower() or lowered == row["display_name"].lower():
            return row["key"]
    return None


# ---------------------------------------------------------------------------
# 聊天
# ---------------------------------------------------------------------------

def _parameters(model_key, request):
    """构造 parameters 块。

    `enable_thinking: false` 会让"始终思考"的模型直接回 1210，所以那些模型
    要么正向请求思考，要么完全不提这个字段——绝不能发 false。
    """
    params = {}
    max_tokens = request.get("max_tokens")
    if isinstance(max_tokens, int) and max_tokens > 0:
        params["max_tokens"] = max_tokens
    if request.get("enable_thinking") is True:
        params["enable_thinking"] = True
        effort = request.get("reasoning_effort")
        if isinstance(effort, str) and effort:
            params["reasoning_effort"] = effort
    elif model_key not in ALWAYS_THINKING_KEYS:
        params["enable_thinking"] = False
    return params


def build_chat_body(model_key, messages, request=None):
    """构造 chat 请求体。每个 null / [] 都是网关要求存在的必填位。"""
    request = request or {}
    record_id = str(uuid.uuid4())
    last_text = ""
    for message in reversed(messages or []):
        if message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, str):
                last_text = content
            break

    enable_thinking = request.get("enable_thinking") is True
    return {
        "request_id": str(uuid.uuid4()),
        "request_set_id": record_id,
        "chat_record_id": record_id,
        "session_id": request.get("session_id") or ("qoder-%s" % uuid.uuid4()),
        "stream": True,
        "chat_task": "FREE_INPUT",
        "is_reply": True,
        "is_retry": False,
        "source": 1,
        "version": "3",
        "session_type": "qodercli",
        "agent_id": "agent_common",
        "task_id": "common",
        "code_language": "",
        "chat_prompt": "",
        "image_urls": None,
        "aliyun_user_type": "",
        # 上游忽略顶层 system，只认开头的 role:system 消息
        "system": "",
        "messages": messages or [],
        "tools": request.get("tools") or [],
        "parameters": _parameters(model_key, request),
        "chat_context": {
            "chatPrompt": "",
            "imageUrls": None,
            "extra": {
                "context": [],
                "modelConfig": {"key": model_key, "is_reasoning": enable_thinking},
                "originalContent": last_text,
            },
            "features": [],
            "text": last_text,
        },
        "model_config": {"key": model_key, "source": "system",
                         "is_reasoning": enable_thinking},
        # 刻意**不发** `business` 块：带上它上游回 1210（API 调用参数有误）。
        # 实测同一请求去掉该字段即正常出流，所以它不是"可选装饰"而是"发了就坏"。
    }


def _unwrap_envelope(payload_text):
    """双层 SSE：信封对象，body 字段本身又是 JSON 字符串。"""
    try:
        envelope = json.loads(payload_text)
    except ValueError:
        return None
    if not isinstance(envelope, dict):
        return None
    inner = envelope.get("body")
    if isinstance(inner, str):
        try:
            return json.loads(inner)
        except ValueError:
            return None
    if isinstance(inner, dict):
        return inner
    return envelope


def _failure_of(chunk):
    """把错误帧拆成 (code, message)。非错误返回 None。

    Qoder 把真正的错误码嵌在 message 字符串里的 JSON 中，只读第一层会得到
    一个没有信息量的 provider_error。这里往下走两层。
    """
    if not isinstance(chunk, dict):
        return None
    code = chunk.get("code") or chunk.get("errorCode")
    message = chunk.get("message") or chunk.get("errorMessage")
    details = chunk.get("details")
    if isinstance(details, str):
        try:
            nested = json.loads(details)
        except ValueError:
            nested = None
        if isinstance(nested, dict):
            error = nested.get("error")
            if isinstance(error, dict):
                inner_code = error.get("code")
                inner_msg = error.get("message")
                if inner_code:
                    code = inner_code
                if inner_msg:
                    message = inner_msg
    if code is None and not message:
        return None
    return (str(code or ""), str(message or ""))


def stream_chat(model_key, messages, request=None, timeout=None):
    """发一次流式对话，逐帧产出 OpenAI 形状的 chunk dict。

    产出的是 `{"choices":[{"delta":{...},"finish_reason":...}]}` 或带 usage 的帧，
    与 /v1/chat/completions 的流式格式一致，调用方可以直接转发。
    """
    cred = load_credential()
    if not cred.get("token"):
        raise QoderError("Qoder 凭据缺失", status=401, kind="no_credential")

    body = build_chat_body(model_key, messages, request)
    response = _open(
        GATEWAY_BASE + PATH_CHAT, cred, body=body,
        extra_headers={
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Model-Key": model_key,
            "X-Model-Source": "system",
        },
        timeout=timeout,
    )

    content_type = (response.headers.get("Content-Type") or "").lower()
    if "json" in content_type or "html" in content_type:
        # 200 但不是 SSE：多半是鉴权页/错误文档，说清楚比空回更省排查时间
        try:
            text = response.read().decode("utf-8", "replace")[:400]
        finally:
            response.close()
        raise QoderError("Qoder 回了 %s 而不是 SSE：%s" % (content_type, text),
                         status=502, kind="protocol_shape")

    created = int(time.time())
    finish_reason = None
    usage = None
    try:
        for raw_line in response:
            line = raw_line.decode("utf-8", "replace").strip()
            if not line or not line.startswith("data:"):
                continue
            payload_text = line[5:].strip()
            if not payload_text or payload_text == "[DONE]":
                if payload_text == "[DONE]":
                    break
                continue

            chunk = _unwrap_envelope(payload_text)
            if chunk is None:
                continue

            failure = _failure_of(chunk)
            if failure is not None and failure[0] not in ("", "0"):
                code, message = failure
                status = 429 if "limit" in message.lower() else 502
                raise QoderError("Qoder 上游错误 %s: %s" % (code, message),
                                 status=status, kind="provider_error")

            if isinstance(chunk.get("usage"), dict):
                usage = chunk["usage"]

            choices = chunk.get("choices")
            if not isinstance(choices, list) or not choices:
                continue
            first = choices[0] if isinstance(choices[0], dict) else {}
            delta = first.get("delta")
            if not isinstance(delta, dict):
                delta = {}
            if first.get("finish_reason"):
                finish_reason = first["finish_reason"]
            if delta.get("content") or delta.get("reasoning_content") \
                    or delta.get("tool_calls"):
                yield {
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model_key,
                    "choices": [{"index": 0, "delta": delta,
                                 "finish_reason": None}],
                }
    finally:
        try:
            response.close()
        except Exception:                                      # noqa: BLE001
            pass

    tail = {"object": "chat.completion.chunk", "created": created,
            "model": model_key,
            "choices": [{"index": 0, "delta": {},
                         "finish_reason": finish_reason or "stop"}]}
    if usage:
        tail["usage"] = usage
    yield tail


def complete_chat(model_key, messages, request=None, timeout=None):
    """非流式：把 stream_chat 收成一条完整回答。"""
    parts = []
    reasoning = []
    finish_reason = "stop"
    usage = None
    for chunk in stream_chat(model_key, messages, request, timeout=timeout):
        if chunk.get("usage"):
            usage = chunk["usage"]
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}
            if delta.get("content"):
                parts.append(delta["content"])
            if delta.get("reasoning_content"):
                reasoning.append(delta["reasoning_content"])
            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]

    message = {"role": "assistant", "content": "".join(parts)}
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    result = {
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model_key,
        "choices": [{"index": 0, "message": message,
                     "finish_reason": finish_reason}],
    }
    if usage:
        result["usage"] = usage
    return result


# ---------------------------------------------------------------------------
# 自检（直接跑本文件）
# ---------------------------------------------------------------------------

def _selfcheck():
    print("qoder dir      :", qoder_dir())
    print("machine os     :", MACHINE_OS)
    try:
        cred = load_credential()
        print("credential     : %s (%s), uid=%s, machineID=%s"
              % (cred.get("name"), cred.get("source"),
                 (cred.get("userID") or "")[:8], cred.get("machineID")))
    except Exception as exc:                                   # noqa: BLE001
        print("credential     : FAILED —", exc)
        return 1

    try:
        rows = model_list(cred, refresh=True)
        print("models         : %d" % len(rows))
        for row in rows:
            print("  %-22s %-24s ctx=%-8s vl=%-5s think=%s"
                  % (row["key"], row["display_name"], row["context_window"],
                     row["multimodal"], row["thinking"]["supported"]))
    except Exception as exc:                                   # noqa: BLE001
        print("models         : FAILED —", exc)
        return 1

    target = "gmodel" if any(r["key"] == "gmodel" for r in rows) else rows[0]["key"]
    print("\nchat           : %s" % target)
    try:
        answer = complete_chat(target, [{"role": "user", "content": "say ok"}])
        print("  ->", repr((answer["choices"][0]["message"].get("content") or "")[:60]))
    except Exception as exc:                                   # noqa: BLE001
        print("  -> FAILED —", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_selfcheck())
