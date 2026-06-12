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


def secure_zero_str(value: str) -> None:
    """尽力零化字符串的 UTF-16 编码副本，作为纵深防御措施。

    WARNING: CPython 下 ``str`` 不可变，此函数仅零化 ``encode()`` 后的
    bytearray 副本，不影响原始字符串对象。真正的清理依赖置空所有引用
    触发 GC。方法名如实反映其能力，即零化副本而非清除原串。
    """
    if not value:
        return
    try:
        buf = bytearray(value.encode('utf-16-le'))
        for i in range(len(buf)):
            buf[i] = 0
        del buf
    except Exception:
        logger.debug("字符串副本清零失败（CPython 限制）", exc_info=True)
