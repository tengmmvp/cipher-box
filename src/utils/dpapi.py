"""Windows DPAPI 封装 — 用当前用户凭据封装敏感数据（MAINT-117 拆分自 file_security）。

用当前用户凭据封装敏感数据（如配置签名密钥），blob 即便被同权限进程读取也无法在别处
解密，收缩读取密钥文件后离线重算签名绕过完整性校验的攻击面。非 Windows 或失败回退 None，
调用方降级明文存储（靠文件权限保护），绝不阻断启动。唯一生产消费方是
``src/config_key_store.py`` 的签名密钥存储链（独立模块而非并入消费方：与 win_acl
同属 Win32 ctypes 原语层，config_key_store 保持存储链编排单一职责，且
tests/utils/test_dpapi.py 已有镜像测试）。
"""

import logging
from typing import Any

from ._platform import IS_WINDOWS

logger = logging.getLogger(__name__)


def protect_with_dpapi(data: bytes) -> bytes | None:
    """用 Windows DPAPI 封装数据，返回封装后的 blob；非 Windows 或失败返回 None。"""
    if not IS_WINDOWS:
        return None
    return _dpapi_crypt(data, protect=True)


def unprotect_with_dpapi(blob: bytes) -> bytes | None:
    """解封 DPAPI 封装的数据；非 Windows、非 DPAPI 格式或失败返回 None。

    返回 None 表示数据非 DPAPI 封装或解封失败，调用方据此尝试明文回退。
    """
    if not IS_WINDOWS:
        return None
    return _dpapi_crypt(blob, protect=False)


def _dpapi_crypt(data: bytes, *, protect: bool) -> bytes | None:
    """调用 CryptProtectData/CryptUnprotectData。返回 None 时调用方回退明文。

    异常分类告警，避免「敏感数据因 DPAPI 失败明文落盘」被静默掩盖：
    - 平台性失败（非 Windows 无 ``ctypes.WinDLL``）：静默回退，合法。
    - 调用性失败（crypt32 可用但 API 失败）：敏感数据明文落盘，ERROR 告警（安全降级须可见）。
    - 未预期异常（Structure/类型 bug）：ERROR 暴露而非掩盖。
    """
    try:
        import ctypes
        from ctypes import wintypes

        class _DataBlob(ctypes.Structure):
            """Windows CRYPT_DATA_BLOB 结构，DPAPI 输入/输出载体（长度 + 数据指针）。"""

            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        buffer = ctypes.create_string_buffer(data, len(data))
        blob_in = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DataBlob()
        # ctypes 在非 Windows 既无 windll 也无 WinDLL；经 Any 访问避免平台 attr-defined。Linux 运行时 ctypes.WinDLL 抛 AttributeError → 下方 except 回退明文。
        ctypes_any: Any = ctypes
        crypt32: Any = ctypes_any.WinDLL("crypt32")
        if protect:
            ok = crypt32.CryptProtectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(blob_out),
            )
        else:
            # ppszDataDescr 传 None 表示不接收描述字符串
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(blob_out),
            )
        if not ok:
            raise OSError("DPAPI 调用失败")
        try:
            result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32: Any = ctypes_any.WinDLL("kernel32")
            kernel32.LocalFree(blob_out.pbData)
            # 清零输入侧 buffer 副本（封装前 data 的明文拷贝 / 解封前 blob 拷贝），收缩残留面
            ctypes.memset(buffer, 0, ctypes.sizeof(buffer))
        return result
    except AttributeError:
        # 平台性：非 Windows 无 ctypes.WinDLL/wintypes，DPAPI 不可用合法，静默回退明文。
        return None
    except OSError:
        # 调用性：crypt32 可用但 API 失败，敏感数据明文落盘，ERROR 告警避免静默掩盖安全降级。
        logger.error("DPAPI %s 调用失败，敏感数据将以明文存储", "封装" if protect else "解封")
        return None
    except Exception:
        # 未预期异常（Structure/类型 bug），ERROR 暴露而非掩盖。
        logger.error(
            "DPAPI %s 未预期异常，敏感数据将以明文存储",
            "封装" if protect else "解封",
            exc_info=True,
        )
        return None
