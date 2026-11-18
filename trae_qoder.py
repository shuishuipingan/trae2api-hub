# -*- coding: utf-8 -*-
"""trae_qoder.py —— 把 Qoder CN 接入本网关（第三个上游通道）

本模块只做三件事，不碰 trae_proxy 的任何既有逻辑：

  1. **凭据**：优先使用完整环境变量；默认不读取桌面登录态。
     仅 QODER_DESKTOP_IMPORT=1 时在 Windows 只读导入：
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

环境变量模式：标准库 + trae_client 的纯 Python AES（`aes_cbc_encrypt`）。
RSA 用 pow() 实现 PKCS#1 v1.5。Windows 桌面导入还需要可选依赖
pycryptodome（Crypto.Cipher.AES）执行 AES-GCM；非 Windows 请使用环境变量。

协议事实来源：Qoder CN 桌面端 0.5.11 客户端行为 + 社区还原（dsh-connect-qoder）。
上游随时可能改；改了这一层，聊天会回 `provider_error` 或形状漂移，不会静默出错。
"""

import base64
import copy
import http.client
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
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_SSE_EVENT_BYTES = 1024 * 1024
_ENV_CREDENTIALS = ("QODER_CN_TOKEN", "QODER_CN_UID", "QODER_CN_MACHINE_ID")


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
    """Windows 桌面导入使用可选 pycryptodome，不属于标准库路径。"""
    try:
        from Crypto.Cipher import AES as _AES
    except ImportError:
        raise QoderError(
            "Qoder 桌面导入需要 pycryptodome（pip install pycryptodome）；"
            "或设置 QODER_CN_TOKEN、QODER_CN_UID、QODER_CN_MACHINE_ID",
            status=503, kind="credential_dependency") from None
    if blob[:3] != b"v10" or len(blob) < 31:
        raise ValueError("Qoder 桌面凭据格式无效")
    body = blob[3:]
    cipher = _AES.new(key, _AES.MODE_GCM, nonce=body[:12], mac_len=16)
    return cipher.decrypt_and_verify(body[12:-16], body[-16:])


def _master_key():
    path = os.path.join(qoder_dir(), "Local State")
    with open(path, "r", encoding="utf-8") as handle:
        state = json.loads(_read_limited(handle))
    raw = base64.b64decode(state["os_crypt"]["encrypted_key"], validate=True)
    if raw[:5] != b"DPAPI":
        raise ValueError("Qoder 桌面密钥格式无效")
    return _dpapi_unprotect(raw[5:])


def _machine_code():
    with open(umid_cache_path(), "r", encoding="utf-8") as handle:
        cache = json.loads(_read_limited(handle))
    code = (cache.get("info") or {}).get("machineCode")
    return str(code).strip() if code else ""


def _validate_credential(cred):
    if not isinstance(cred, dict) or any(
            not isinstance(cred.get(key), str) or not cred[key].strip()
            for key in ("token", "userID", "machineID")):
        raise QoderError(
            "Qoder 凭据不完整：请设置 QODER_CN_TOKEN、QODER_CN_UID、QODER_CN_MACHINE_ID",
            status=401, kind="no_credential")
    if any(isinstance(value, str) and any(char in value for char in ("\r", "\n", "\x00"))
           for value in cred.values()):
        raise QoderError("Qoder 凭据包含无效控制字符", 401, "no_credential")
    return cred


def load_credential():
    """完整 env 优先；任一认证变量存在即 env 模式，禁止混用个人缓存。

    默认不读桌面；QODER_DESKTOP_IMPORT=1 显式启用 Windows DPAPI/GCM 导入。
    非 Windows 使用 QODER_CN_TOKEN / QODER_CN_UID / QODER_CN_MACHINE_ID。
    """
    if any(key in os.environ for key in _ENV_CREDENTIALS):
        return _validate_credential({
            "token": (os.environ.get("QODER_CN_TOKEN") or "").strip(),
            "userID": (os.environ.get("QODER_CN_UID") or "").strip(),
            "machineID": (os.environ.get("QODER_CN_MACHINE_ID") or "").strip(),
            "name": os.environ.get("QODER_CN_NAME") or "",
            "email": os.environ.get("QODER_CN_EMAIL") or "",
            "source": "env",
        })
    if os.environ.get("QODER_DESKTOP_IMPORT") != "1":
        raise QoderError(
            "Qoder 桌面导入默认关闭；请设置 QODER_CN_TOKEN、QODER_CN_UID、QODER_CN_MACHINE_ID，"
            "或在 Windows 设置 QODER_DESKTOP_IMPORT=1",
            status=401, kind="no_credential")
    if sys.platform != "win32":
        raise QoderError(
            "Qoder 桌面导入仅支持 Windows；请设置 QODER_CN_TOKEN、QODER_CN_UID、QODER_CN_MACHINE_ID",
            status=401, kind="no_credential")
    try:
        key = _master_key()
        with open(os.path.join(qoder_dir(), "auth.v1.dat"), "rb") as handle:
            blob = _read_limited(handle)
        auth = json.loads(_aes_gcm_decrypt(key, blob).decode("utf-8"))
        user = auth.get("user") or {}
        return _validate_credential({
            "userID": str(user.get("id") or "").strip(),
            "token": auth.get("token") or "",
            "name": user.get("name") or "",
            "email": user.get("email") or "",
            "machineID": _machine_code(),
            "source": "desktop",
            "expiresAt": auth.get("expiresAt") or "",
        })
    except QoderError as exc:
        if exc.kind in ("credential_dependency", "no_credential"):
            raise
        raise QoderError("Qoder 桌面凭据读取或解密失败", 401, "credential_import") from None
    except Exception:
        raise QoderError("Qoder 桌面凭据读取或解密失败", 401, "credential_import") from None


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


def _close_response(response):
    try:
        response.close()
    except Exception:
        pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """签名及身份头不转发到重定向目的地；同主机重定向也拒绝。"""

    def http_response(self, request, response):
        if 300 <= response.code < 400:
            _close_response(response)
            raise QoderError("Qoder 上游重定向已拒绝", 502, "upstream_redirect")
        return response

    https_response = http_response

    def redirect_request(self, request, response, code, message, headers, newurl):
        _close_response(response)
        raise QoderError("Qoder 上游重定向已拒绝", 502, "upstream_redirect")


def _read_limited(handle):
    data = handle.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise QoderError("Qoder 响应超过大小限制", 502, "protocol_shape")
    return data


def _open(url, cred, body=None, extra_headers=None, timeout=None, method=None):
    _validate_credential(cred)
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
        opener = urllib.request.build_opener(_NoRedirect())
        return opener.open(request, timeout=timeout or REQUEST_TIMEOUT)
    except urllib.error.HTTPError as exc:
        _close_response(exc)
        if isinstance(exc.code, int) and 300 <= exc.code < 400:
            raise QoderError("Qoder 上游重定向已拒绝", 502, "upstream_redirect") from None
        status = exc.code if isinstance(exc.code, int) and 400 <= exc.code <= 599 else 502
        raise QoderError("Qoder 上游 HTTP 请求失败", status, "upstream_http") from None
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        raise QoderError("Qoder 网络连接失败", 502, "network") from None


# ---------------------------------------------------------------------------
# 模型目录
# ---------------------------------------------------------------------------

_MODEL_CACHE = {}  # sha256(完整认证身份) -> {at, rows}；不保存原始 token
_MODEL_CACHE_GENERATION = 0
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


def _credential_fingerprint(cred):
    identity = [cred[key] for key in ("token", "userID", "machineID")]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode("utf-8")).hexdigest()


def model_list(cred=None, refresh=False, timeout=None):
    """凭据指纹隔离的模型目录；失败不回退到其它账号的缓存。"""
    cred = dict(_validate_credential(load_credential() if cred is None else cred))
    fingerprint = _credential_fingerprint(cred)
    with _MODEL_LOCK:
        generation = _MODEL_CACHE_GENERATION
        cached = _MODEL_CACHE.get(fingerprint)
        if not refresh and cached and time.monotonic() - cached["at"] < MODEL_CACHE_TTL:
            return copy.deepcopy(cached["rows"])
    response = _open(GATEWAY_BASE + PATH_MODEL_LIST, cred, body=None,
                     timeout=timeout or 30)
    try:
        raw = _read_limited(response)
        payload = json.loads(raw)
    except QoderError:
        raise
    except (OSError, http.client.HTTPException):
        raise QoderError("Qoder 网络读取失败", 502, "network") from None
    except (ValueError, UnicodeError, RecursionError):
        raise QoderError("Qoder 模型目录不是合法 JSON", 502, "protocol_shape") from None
    finally:
        _close_response(response)
    if not isinstance(payload, dict):
        raise QoderError("Qoder 模型目录格式无效", 502, "protocol_shape")
    if _failure_of(payload):
        raise QoderError("Qoder 上游请求失败", 502, "provider_error")
    groups = payload.get("chat")
    if not isinstance(groups, list):
        raise QoderError("Qoder 模型目录缺少 chat 分组", 502, "protocol_shape")
    rows = []
    for item in groups:
        if isinstance(item, dict):
            row = normalize_model(item)
            if row:
                rows.append(row)
    with _MODEL_LOCK:
        if generation == _MODEL_CACHE_GENERATION:
            now = time.monotonic()
            for key in list(_MODEL_CACHE):
                if now - _MODEL_CACHE[key]["at"] >= MODEL_CACHE_TTL:
                    del _MODEL_CACHE[key]
            if len(_MODEL_CACHE) >= 32 and fingerprint not in _MODEL_CACHE:
                del _MODEL_CACHE[min(_MODEL_CACHE, key=lambda key: _MODEL_CACHE[key]["at"])]
            _MODEL_CACHE[fingerprint] = {"at": now, "rows": copy.deepcopy(rows)}
    return rows


def invalidate_models():
    global _MODEL_CACHE_GENERATION
    with _MODEL_LOCK:
        _MODEL_CACHE.clear()
        _MODEL_CACHE_GENERATION += 1


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


def _protocol_error():
    return QoderError("Qoder 流响应格式无效", 502, "protocol_shape")


def _strict_json(text):
    def reject_constant(_value):
        raise ValueError("non-finite JSON")
    return json.loads(text, parse_constant=reject_constant)


def _unwrap_envelope(payload_text):
    """严格解开双层 JSON；错误信封不能被 body 遮蔽。"""
    try:
        envelope = _strict_json(payload_text)
        if not isinstance(envelope, dict):
            raise ValueError("envelope")
        if _failure_of(envelope):
            raise QoderError("Qoder 上游请求失败", 502, "provider_error")
        if "body" not in envelope:
            return envelope
        inner = envelope["body"]
        if isinstance(inner, str):
            inner = _strict_json(inner)
        if not isinstance(inner, dict):
            raise ValueError("body")
        return inner
    except (ValueError, TypeError, RecursionError):
        raise _protocol_error() from None


def _failure_of(chunk):
    """仅判断错误标志；上游 code/message/details 永不放入公开消息。"""
    if not isinstance(chunk, dict):
        return False
    code = chunk.get("code", chunk.get("errorCode"))
    if code not in (None, "", 0, "0") or chunk.get("error") or chunk.get("success") is False:
        return True
    details = chunk.get("details")
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            details = None
    return isinstance(details, dict) and bool(details.get("error"))


def _sse_events(response):
    """按空行分隔事件，支持多行 data；行及事件均有大小上限。"""
    data = []
    size = 0
    while True:
        raw_line = response.readline(MAX_SSE_EVENT_BYTES + 1)
        if not raw_line:
            if data:
                raise QoderError("Qoder 流响应意外中断", 502, "incomplete_stream")
            return
        size += len(raw_line)
        if len(raw_line) > MAX_SSE_EVENT_BYTES or size > MAX_SSE_EVENT_BYTES:
            raise QoderError("Qoder 流事件超过大小限制", 502, "protocol_shape")
        try:
            line = raw_line.decode("utf-8").rstrip("\r\n")
        except UnicodeError:
            raise _protocol_error() from None
        if line == "":
            if data:
                yield "\n".join(data)
            data = []
            size = 0
        elif line.startswith(":"):
            continue
        else:
            field, sep, value = line.partition(":")
            if value.startswith(" "):
                value = value[1:]
            if field == "data":
                data.append(value if sep else "")
            elif field not in ("event", "id", "retry"):
                raise _protocol_error()


def stream_chat(model_key, messages, request=None, timeout=None):
    """透明转发 delta；必须有 choice 且观察到 finish_reason 或 [DONE] 才成功。"""
    cred = _validate_credential(load_credential())
    body = build_chat_body(model_key, messages, request)
    response = _open(
        GATEWAY_BASE + PATH_CHAT, cred, body=body,
        extra_headers={"Accept": "text/event-stream", "Cache-Control": "no-cache",
                       "X-Model-Key": model_key, "X-Model-Source": "system"},
        timeout=timeout)
    created = int(time.time())
    finish_reason = None
    usage = None
    seen_choice = False
    seen_payload = False
    calls = {}
    done = False
    try:
        content_type = (response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "text/event-stream":
            raise QoderError("Qoder 上游未返回 SSE 响应", 502, "protocol_shape")
        for payload_text in _sse_events(response):
            if payload_text == "[DONE]":
                done = True
                break
            chunk = _unwrap_envelope(payload_text)
            if _failure_of(chunk):
                raise QoderError("Qoder 上游请求失败", 502, "provider_error")
            if "usage" in chunk and chunk["usage"] is not None:
                if not isinstance(chunk["usage"], dict):
                    raise _protocol_error()
                usage = chunk["usage"]
            choices = chunk.get("choices")
            if choices == [] and isinstance(chunk.get("usage"), dict):
                continue
            if not isinstance(choices, list) or len(choices) != 1:
                raise _protocol_error()
            first = choices[0]
            if not isinstance(first, dict) or first.get("index", 0) != 0:
                raise _protocol_error()
            delta = first.get("delta")
            if delta is None:
                delta = {}
            if not isinstance(delta, dict):
                raise _protocol_error()
            for key in ("content", "reasoning_content"):
                if delta.get(key) is not None and not isinstance(delta[key], str):
                    raise _protocol_error()
            if "tool_calls" in delta:
                _merge_tool_delta(calls, delta["tool_calls"])
            reason = first.get("finish_reason")
            if reason is not None and reason not in ("stop", "length", "tool_calls", "content_filter", "function_call"):
                raise _protocol_error()
            if finish_reason is not None and (delta or reason not in (None, finish_reason)):
                raise _protocol_error()
            seen_choice = True
            if delta.get("content") or delta.get("reasoning_content") or delta.get("tool_calls"):
                seen_payload = True
            if reason is not None:
                finish_reason = reason
            if delta:
                yield {"object": "chat.completion.chunk", "created": created,
                       "model": model_key,
                       "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
        if not seen_choice or (not seen_payload and finish_reason is None):
            raise QoderError("Qoder 流响应为空", 502, "empty_stream")
        if not done and finish_reason is None:
            raise QoderError("Qoder 流响应意外中断", 502, "incomplete_stream")
        # 流式也验证聚合结果，防止 malformed 工具流被代理计为成功。
        # length/content_filter 保留真实终态，不补齐参数或伪造 tool_calls 终态。
        if finish_reason == "tool_calls":
            if not calls:
                raise _protocol_error()
            _validated_tool_calls(calls)
        elif calls and finish_reason not in ("length", "content_filter"):
            raise _protocol_error()
    except (OSError, http.client.HTTPException):
        raise QoderError("Qoder 网络读取失败", 502, "network") from None
    finally:
        _close_response(response)
    tail = {"object": "chat.completion.chunk", "created": created, "model": model_key,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason or "stop"}]}
    if usage is not None:
        tail["usage"] = usage
    yield tail


def _merge_tool_delta(calls, fragments):
    if not isinstance(fragments, list):
        raise _protocol_error()
    for fragment in fragments:
        if not isinstance(fragment, dict):
            raise _protocol_error()
        index = fragment.get("index")
        if type(index) is not int or index < 0:
            raise _protocol_error()
        call = calls.setdefault(index, {"id": "", "type": "function",
                                        "function": {"name": "", "arguments": ""}})
        if fragment.get("type", "function") != "function":
            raise _protocol_error()
        if "id" in fragment:
            if not isinstance(fragment["id"], str):
                raise _protocol_error()
            call["id"] += fragment["id"]
        function = fragment.get("function", {})
        if not isinstance(function, dict):
            raise _protocol_error()
        for key in ("name", "arguments"):
            if key in function:
                if not isinstance(function[key], str):
                    raise _protocol_error()
                call["function"][key] += function[key]


def _validated_tool_calls(calls):
    ordered = [calls[index] for index in sorted(calls)]
    ids = set()
    for call in ordered:
        function = call["function"]
        if not call["id"].strip() or not function["name"].strip() or call["id"] in ids:
            raise _protocol_error()
        ids.add(call["id"])
        try:
            arguments = _strict_json(function["arguments"])
        except (ValueError, TypeError, RecursionError):
            raise QoderError("Qoder 工具参数不是完整 JSON 对象", 502, "protocol_shape") from None
        if not isinstance(arguments, dict):
            raise QoderError("Qoder 工具参数不是完整 JSON 对象", 502, "protocol_shape")
    return ordered


def complete_chat(model_key, messages, request=None, timeout=None):
    """按工具 index 聚合分片；截断/过滤的工具不暴露为可执行 tool_calls。"""
    parts, reasoning, calls = [], [], {}
    finish_reason = None
    usage = None
    stream = stream_chat(model_key, messages, request, timeout=timeout)
    try:
        for chunk in stream:
            if chunk.get("usage") is not None:
                usage = chunk["usage"]
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                if delta.get("content"):
                    parts.append(delta["content"])
                if delta.get("reasoning_content"):
                    reasoning.append(delta["reasoning_content"])
                if "tool_calls" in delta:
                    _merge_tool_delta(calls, delta["tool_calls"])
                if choice.get("finish_reason") is not None:
                    finish_reason = choice["finish_reason"]
    finally:
        if hasattr(stream, "close"):
            _close_response(stream)
    if finish_reason is None:
        raise QoderError("Qoder 流响应意外中断", 502, "incomplete_stream")
    message = {"role": "assistant", "content": "".join(parts)}
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    if finish_reason == "tool_calls":
        if not calls:
            raise _protocol_error()
        message["tool_calls"] = _validated_tool_calls(calls)
        if not parts:
            message["content"] = None
    elif calls and finish_reason not in ("length", "content_filter"):
        raise _protocol_error()
    result = {"object": "chat.completion", "created": int(time.time()), "model": model_key,
              "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}]}
    if usage is not None:
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
