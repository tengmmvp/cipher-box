"""安全内存操作工具。"""

import ctypes
import logging

logger = logging.getLogger(__name__)


def secure_zero_buffer(data: bytes | bytearray) -> None:
    """尽力清零缓冲区内存。

    bytes 不可变，传入 bytes 仅清零副本（假清零，无安全收益）；调用方**必须**传
    bytearray（如 MasterKeyManager 派生密钥）才能原地清零，误传 bytes 触发 warning。
    """
    if not data:
        return
    if isinstance(data, bytes):
        logger.warning(
            "secure_zero_buffer 收到不可变 bytes，仅清零副本，原对象未变"
            "（应传入 bytearray 以原地清零）"
        )
    try:
        mutable = bytearray(data) if isinstance(data, bytes) else data
        ctypes.memset((ctypes.c_char * len(mutable)).from_buffer(mutable), 0, len(mutable))
    except Exception:
        logger.warning("安全清零失败（CPython 限制），密钥可能未被清零", exc_info=True)


def mark_secret_discarded(value: str) -> None:
    """标记敏感字符串已弃用（语义占位，安全收益接近零）。

    CPython ``str`` 不可变，UI 持有的原串无法原地清零，此处仅清零 encode 临时副本。
    真正释放依赖调用方置空引用触发 GC；函数名避用 ``zero`` 以免误以为已原地擦除原串。
    """
    if not value:
        return
    try:
        buf = bytearray(value.encode("utf-16-le"))
        buf[:] = b"\x00" * len(buf)
        del buf
    except Exception:
        logger.warning("字符串副本清零失败（CPython 限制）", exc_info=True)
