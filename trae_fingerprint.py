"""trae_fingerprint.py —— 统一设备指纹稳定派生模块 (derive_id)

无论是国内版 (api.trae.com.cn / trae-api-cn.mchost.guru) 还是国际版
(core-normal.traeapi.us / core-normal.trae.ai)，均通过本模块基于账号 UID 和
加盐哈希单向派生固定的伪物理设备特征 (machineId / deviceId / sessionId)，
确保每个账号长期来自同一台虚拟物理设备，且多账号之间天然隔离，阻断跨账号关联风控。

Trae 请求头会携带 X-Machine-Id / X-Device-Id / X-Device-Type 等设备字段
（见 trae_client.auth_headers）：
  - machineId  : 由 uid 稳定派生（同一账号永远相同）
  - deviceId   : 由 uid 稳定派生（账号级隔离）
  - sessionId  : 由 uid 稳定派生（会话隔离）
  - request id : 稳定前缀 + 微秒时间戳（防重放且可溯源）
"""
import functools
import hashlib
import os
import time


def derive_id(uid: str, salt: str) -> str:
    """由 uid + salt 稳定派生一个 32 位十六进制设备/会话标识。

    幂等：同一账号每次调用产生相同值，彻底避免随机机器码导致的上游风控。

    长度事实（勿"顺手修正"）：md5().hexdigest() 恒为 32 个十六进制字符，
    因此 [:36] 是防御性切片（对 32 长串为恒等），实际输出恒为 32 位；
    旧注释写作"36 位"属文档漂移，已在本轮与实现对齐。
    若要补齐到 36 位（UUID 形态），会改变所有已入池账号的 machineId /
    sessionId，属破坏性变更：必须 Lead 批准 + 全量账号回归，禁止单方面修改。
    """
    seed = f"{salt}:{uid or 'anonymous'}"
    # md5 hexdigest 恒为 32 字符；[:36] 是恒等切片（防御性保留，结果不变）
    return hashlib.md5(seed.encode("utf-8")).hexdigest()[:36]


def generate_request_id(uid: str) -> str:
    """生成带稳定前缀与微秒时间戳的防风控请求 ID。"""
    prefix = derive_id(uid, "req")
    suffix = str(time.time_ns() % 1000000).zfill(6)
    return f"{prefix}-{suffix}"


def derive_machine_type(uid: str) -> str:
    """稳定派生 18 位去横线的 machine_type（cosy-machinetoken 同形）。"""
    return derive_id(uid, "machinetype").replace("-", "")[:18]


def derive_machine_token(uid: str) -> str:
    """稳定派生 machine_token（base64url 风格的随机串外观）。"""
    raw = hashlib.sha512(f"machinetoken:{uid}".encode("utf-8")).digest()
    import base64
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")[:43]


# ---------------------------------------------------------------------------
# 本机虚拟化状态检测（中文输出）
# ---------------------------------------------------------------------------
# 用途：官方风控（runtime-info.exe）会返回 vmInfo（是否虚拟机 / 平台 / 评分），
# 活动和风控策略可能据此区别对待；看板与 _diag_campaign.py 都展示这份结果。
# 判定来源：
#   1) 官方风控桥 runtime-info.exe 的 vmInfo（最权威：官方客户端就是这么判的）
#   2) 本机交叉校验（CPU 型号字符串 / 系统制造商 / 常见虚拟化驱动文件）
VM_BRANDS_CN = {
    "hyper-v": "Hyper-V（微软）",
    "vmware": "VMware",
    "virtualbox": "Oracle VirtualBox",
    "vbox": "Oracle VirtualBox",
    "kvm": "KVM",
    "qemu": "QEMU",
    "xen": "Xen",
    "parallels": "Parallels",
    "virtual machine": "通用虚拟机",
    "bochs": "Bochs",
    "bhyve": "bhyve",
}

# 常见虚拟机/半虚拟化驱动（存在任一即强烈提示运行在虚拟机内）
_VM_DRIVER_FILES = (
    "vmbus.sys",          # Hyper-V
    "vmci.sys",           # VMware
    "vmhgfs.sys",         # VMware 共享目录
    "vboxguest.sys",      # VirtualBox
    "vboxmouse.sys",      # VirtualBox
    "vmmouse.sys",        # VMware
    "virtio_balloon.sys", # KVM/QEMU
    "viostor.sys",        # KVM/QEMU 存储
    "xenevtchn.sys",      # Xen
)


def vm_brand_cn(brand: str) -> str:
    """虚拟化平台中文名（未知品牌原样返回）。"""
    b = str(brand or "").strip()
    if not b:
        return ""
    low = b.lower()
    for key, cn in VM_BRANDS_CN.items():
        if key in low:
            return cn
    return b


def _vm_level_cn(score):
    """风控评分 -> 中文档位。"""
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "未知"
    if s >= 70:
        return "高"
    if s >= 40:
        return "中"
    if s > 0:
        return "低"
    return "无"


def _local_vm_evidence():
    """本机交叉校验：返回 (evidence 列表, 品牌提示 或 '')。全部中文描述。"""
    evidence, hint = [], ""
    # 1) CPU 型号字符串（注册表 / /proc/cpuinfo）
    cpu = ""
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                cpu = str(winreg.QueryValueEx(k, "ProcessorNameString")[0])
            with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\BIOS") as k:
                maker = str(winreg.QueryValueEx(k, "SystemManufacturer")[0])
                model = str(winreg.QueryValueEx(k, "SystemProductName")[0])
            if maker or model:
                evidence.append("系统制造商/型号：%s %s" % (maker, model))
                for token in ("VMware", "VirtualBox", "Virtual Machine",
                              "KVM", "QEMU", "Xen", "Parallels", "Hyper-V"):
                    if token.lower() in (maker + " " + model).lower():
                        hint = hint or token
                        break
        except Exception:
            pass
    else:
        try:
            with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for line in text.splitlines():
                if line.lower().startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
            if "hypervisor" in text.lower():
                evidence.append("CPU 标志含 hypervisor（运行在虚拟机监控程序之上）")
        except Exception:
            pass
    if cpu:
        evidence.append("处理器型号：%s" % cpu)
        for token in ("Virtual CPU", "VirtualBox", "VMware", "QEMU",
                      "KVM", "Xeon Platinum 8", "Virtual Machine"):
            if token.lower() in cpu.lower():
                hint = hint or token
                break
    # 2) 常见虚拟化驱动文件
    if os.name == "nt":
        drv = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows",
                           "System32", "drivers")
        found = [f for f in _VM_DRIVER_FILES
                 if os.path.isfile(os.path.join(drv, f))]
        if found:
            evidence.append("检测到虚拟化驱动：%s" % ", ".join(sorted(found)))
            if not hint:
                low = " ".join(found).lower()
                hint = ("Hyper-V" if "vmbus" in low else
                        "VMware" if "vmci" in low or "vmhgfs" in low or "vmmouse" in low else
                        "VirtualBox" if "vbox" in low else
                        "KVM/QEMU" if "virtio" in low or "viostor" in low else
                        "Xen" if "xen" in low else "")
    return evidence, hint


def vm_status(bridge_vm_info=None, bridge_available=None):
    """本机虚拟化状态（中文输出），供看板 / 体检脚本共用。

    bridge_vm_info：官方风控桥 runtime-info.exe 返回的 vmInfo（最权威）
    bridge_available：官方风控桥是否可用（None=未知）

    返回：
      {is_vm, level(高/中/低/无/未知), score, brand, brand_cn,
       vm_type_code, source(runtime-info/local/none), evidence[], summary}
    """
    evidence, hint = _local_vm_evidence()
    info = bridge_vm_info if isinstance(bridge_vm_info, dict) else {}
    is_vm = info.get("isVm")
    score = info.get("percentage")
    brand = str(info.get("brand") or "") or hint
    if is_vm is None:
        # 桥不可用/无结果：退化为本机交叉校验结论
        is_vm = bool(hint) or any("虚拟化驱动" in e or "hypervisor" in e
                                 for e in evidence)
        source = "local" if (evidence or bridge_available is None) else "runtime-info"
    else:
        source = "runtime-info"
    if info:
        evidence.insert(0, "官方风控判定：%s（评分 %s，类型码 %s）"
                        % ("是虚拟机" if is_vm else "不是虚拟机",
                           score if score is not None else "-",
                           info.get("vmTypeCode") if info.get("vmTypeCode") is not None else "-"))
    brand_cn = vm_brand_cn(brand)
    if is_vm and brand_cn:
        summary = "本机运行在虚拟机中（%s，风控评分 %s/100）" % (brand_cn, score if score is not None else "-")
    elif is_vm:
        summary = "本机疑似运行在虚拟机中（未识别虚拟化平台）"
    else:
        summary = "未检测到虚拟化运行环境（物理机）"
    if source == "local":
        summary += "；官方风控桥不可用，以上为本机交叉校验结果"
    return {
        "is_vm": bool(is_vm),
        "level": _vm_level_cn(score) if is_vm else "无",
        "score": score if score is not None else None,
        "brand": brand,
        "brand_cn": brand_cn,
        "vm_type_code": info.get("vmTypeCode"),
        "source": source,
        "evidence": evidence,
        "summary": summary,
    }


def get_desktop_fingerprint(uid: str, nickname: str = "", os_name: str = "win32") -> dict:
    """生成上报事件所需的标准完整桌面端指纹（行为事件上报用）。"""
    now = int(time.time() * 1000)
    return {
        "timezone": "Asia/Shanghai",
        "reportDelay": 2000,
        "userId": uid,
        "username": nickname,
        "userNickname": nickname,
        "product": "SaaS",
        "releaseDate": 1789036585355,
        "commit": "b014a3198565189578a96e6a525e9d92be107cab",
        "ideName": "Trae",
        "ideType": "Trae",
        "ideVersion": "3.6.2",
        "machineId": derive_id(uid, "machine"),
        "sessionId": derive_id(uid, "session"),
        "extName": "trae-desktop",
        "extVersion": "3.6.2",
        "os": os_name,
        "arch": "x64",
        "osVersion": "10.0.26220",
        "cpuCores": 20,
        "memorySize": 24,
        "timestamp": now,
        "presentAt": now,
    }

# ---------------------------------------------------------------------------
# Trae 客户端设备指纹（IDE 数据面 X-Device-* / X-Machine-Id 头）
# ---------------------------------------------------------------------------
# 事实来源：.team/PROTOCOL.md 第二节；本机 Desktop 3.6.2 / CN 3.4.3 实测抓包。
# 官方客户端在同一账号上长期复用同一组设备头，跨账号绝不共享（风控关联面）。
# 这里的派生全部是"由 uid 单向派生"的纯函数：同 uid 恒等，不同 uid 互异。
def trae_machine_id(uid: str) -> str:
    """64 位十六进制 machineId（与官方客户端同形；实测样例即 sha256 长度）。"""
    seed = "trae-machine:%s" % (str(uid or "").strip() or "anonymous")
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def trae_device_id(uid: str) -> str:
    """数值型 X-Device-Id。

    官方客户端直接复用账号 userId（19 位数字串）。uid 非纯数字时（导入的
    第三方账号）从 sha256 稳定取 19 位数字，避免退化成随机设备号。
    """
    raw = str(uid or "").strip()
    if raw.isdigit():
        return raw
    digest = int(hashlib.sha256(("trae-device:%s" % (raw or "anonymous")).encode("utf-8")).hexdigest()[:16], 16)
    return str(10 ** 18 + digest % (9 * 10 ** 18))


@functools.lru_cache(maxsize=1)
def _win_hardware_brand() -> str:
    """Windows: 厂商 + 机型（官方样例 'TX Gaming FX608JMR_FX608JMR'）。"""
    if os.name != "nt":
        return "unknown"
    try:
        import winreg  # 仅 Windows 可用
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            maker = str(winreg.QueryValueEx(key, "SystemManufacturer")[0] or "").strip()
            model = str(winreg.QueryValueEx(key, "SystemProductName")[0] or "").strip()
        brand = " ".join(x for x in (maker, model) if x).strip()
        return brand or "Default string"
    except Exception:
        return "Default string"


@functools.lru_cache(maxsize=1)
def _win_os_version() -> str:
    """Windows: 营销名 + 版本（官方样例 'Windows 11 Pro'）。"""
    if os.name != "nt":
        return "Linux"
    product, edition = "Windows", ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            product = str(winreg.QueryValueEx(key, "ProductName")[0] or "Windows").strip()
            try:
                edition = str(winreg.QueryValueEx(key, "EditionID")[0] or "").strip()
            except OSError:
                edition = ""
            try:
                build = int(str(winreg.QueryValueEx(key, "CurrentBuild")[0]))
            except (OSError, ValueError):
                build = 0
        if build >= 22000 and product.startswith("Windows 10"):
            product = product.replace("Windows 10", "Windows 11", 1)
        if edition and edition.lower() not in product.lower():
            product = "%s %s" % (product, edition)
    except Exception:
        pass
    return product or "Windows"


def trae_device_brand() -> str:
    """X-Device-Brand 原值（未编码）。"""
    return _win_hardware_brand()


def trae_os_version() -> str:
    """X-Os-Version 原值（未编码）。"""
    return _win_os_version()


def trae_device_headers(uid: str) -> dict:
    """IDE 数据面设备头（已按官方形态 URL 编码，可直接塞进 headers）。

    只含与"设备"相关的稳定字段；鉴权头由 trae_client.auth_headers 负责。
    """
    import urllib.parse
    return {
        "X-Device-Cpu": "Intel",
        "X-Device-Id": trae_device_id(uid),
        "X-Machine-Id": trae_machine_id(uid),
        "X-Device-Brand": urllib.parse.quote(trae_device_brand(), safe=""),
        "X-Device-Type": "windows",
        "X-Os-Version": urllib.parse.quote(trae_os_version(), safe=""),
    }


def trae_request_id() -> str:
    """X-Request-Id：每次请求唯一（uuid4），与账号设备指纹解耦。"""
    import uuid
    return str(uuid.uuid4())


def get_trae_fingerprint(uid: str) -> dict:
    """Trae 客户端指纹汇总（看板/诊断展示用，不含 token）。"""
    return {
        "ideName": "Trae",
        "userId": str(uid or ""),
        "machineId": trae_machine_id(uid),
        "deviceId": trae_device_id(uid),
        "deviceBrand": trae_device_brand(),
        "osVersion": trae_os_version(),
        "deviceType": "windows",
        "cpu": "Intel",
    }