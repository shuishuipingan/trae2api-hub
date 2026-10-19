"""trae_sign.py —— 兼容垫片（Trae 数据面不再需要 COSY 签名）

Trae 的请求鉴权是 `x-ide-token` + `Cloud-IDE-JWT`（见 trae_client.auth_headers），
不存在 Qoder 那套 RSA/AES 会话密钥 + MD5 签名。本文件只保留两类被测试/历史代码
引用的密码学原语，实现统一来自 `trae_client`：

  - aes_cbc_encrypt / aes_cbc_decrypt   AES-128-CBC + PKCS#7（Desktop 凭证解密用）
  - dpapi_unprotect / chromium_decrypt_v10  可选平台入口（当前平台不需要，保留名字）

新代码请直接 `import trae_client`。
"""
from trae_client import aes_cbc_decrypt, aes_cbc_encrypt  # noqa: F401

__all__ = ["aes_cbc_encrypt", "aes_cbc_decrypt", "dpapi_unprotect",
           "chromium_decrypt_v10"]


def dpapi_unprotect(data):
    """可选：Windows DPAPI 解保护。Trae 凭证用 tc/AES-128-CBC，不走 DPAPI。"""
    raise NotImplementedError("Trae 凭证解密不需要 DPAPI；请用 trae_client.decrypt_icube_blob")


def chromium_decrypt_v10(blob, key):
    """可选：Chromium v10 cookie 解密。Trae 网关不使用浏览器 cookie。"""
    raise NotImplementedError("Trae 网关不读取浏览器 cookie")
