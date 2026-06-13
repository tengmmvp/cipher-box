"""安全内存操作工具。"""

import ctypes
import logging

logger = logging.getLogger(__name__)


def secure_zero_buffer(data: bytes | bytearray) -> None:
    """尽力将字节缓冲区的内存内容清零。

    CPython 的 bytes 对象不可变：传入 bytes 时只能清零其 bytearray 副本，
    原 bytes 内容不变（假清零，无实际安全收益）。调用方**必须**传入 bytearray
    （如 MasterKeyManager 派生密钥）以实现原地清零；误传 bytes 会触发 warning，
    使「安全清零实际空转」的隐患可见而非静默。
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
        ctypes.memset(
            (ctypes.c_char * len(mutable)).from_buffer(mutable), 0, len(mutable)
        )
    except Exception:
        logger.debug("安全清零失败（CPython 限制）", exc_info=True)


def mark_secret_discarded(value: str) -> None:
    """标记敏感字符串已不再需要（语义占位，非原地擦除）。

    WARNING: 此函数实际安全收益接近零，主要为调用方的语义占位。CPython 下
    ``str`` 不可变，UI 实际持有的原始字符串对象无法被原地清零，此处零化的
    只是 ``encode('utf-16-le')`` 生成的临时 bytearray 副本，随 ``del buf``
    立即丢弃。真正的明文释放依赖调用方置空所有引用触发 GC。函数名刻意避免
    ``zero`` 字样以防误以为已原地擦除原串；调用方须配合置空引用。
    """
    if not value:
        return
    try:
        buf = bytearray(value.encode('utf-16-le'))
        buf[:] = b'\x00' * len(buf)
        del buf
    except Exception:
        logger.debug("字符串副本清零失败（CPython 限制）", exc_info=True)
