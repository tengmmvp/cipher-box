"""安全内存操作工具。"""

import ctypes
import logging

logger = logging.getLogger(__name__)


def secure_zero_buffer(data: bytes | bytearray) -> None:
    """尽力将字节缓冲区的内存内容清零。

    CPython 的 bytes/string 对象不可变，此函数只能清零 bytearray 副本。
    调用方应先创建 bytearray 副本再调用本函数，随后 del 副本。
    """
    if not data:
        return
    try:
        mutable = bytearray(data) if isinstance(data, bytes) else data
        ctypes.memset(
            (ctypes.c_char * len(mutable)).from_buffer(mutable), 0, len(mutable)
        )
    except Exception:
        logger.debug("安全清零失败（CPython 限制）", exc_info=True)
