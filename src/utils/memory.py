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
    """尽力零化字符串的 UTF-16 编码副本。

    WARNING: 此函数实际安全收益接近零，主要为调用方的语义占位。CPython 下
    ``str`` 不可变，UI 实际持有的原始字符串对象无法被原地清零，此处零化的
    只是 ``encode('utf-16-le')`` 生成的临时 bytearray 副本，随 ``del buf``
    立即丢弃。真正的明文释放依赖调用方置空所有引用触发 GC。保留此调用是为
    统一「敏感值不再需要」的代码语义，不应误以为已原地擦除原串。
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
