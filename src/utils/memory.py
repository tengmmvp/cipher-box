"""安全内存操作工具 — 敏感数据（密钥/密码）的尽力清零与弃用标记。

``secure_zero_buffer`` 经 ``ctypes.memset`` 原地清零 ``bytearray``（CPython 下尽力，
非密码学保证）；``mark_secret_discarded`` 为不可变 ``str`` 提供语义标记（真正释放依赖
调用方置空引用 + GC）。属零上层依赖共享层。
"""

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
        # bytes 不可变：创建副本清零只擦除临时副本，原对象未动，无安全收益且短暂增加
        # 明文副本数（反效果）。告警后直接返回，真正的释放由调用方置空引用 + GC。
        logger.warning(
            "secure_zero_buffer 收到不可变 bytes，原对象无法原地清零（应传入 bytearray 以原地清零）"
        )
        return
    try:
        ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))
    except Exception:
        logger.warning("安全清零失败（CPython 限制），密钥可能未被清零", exc_info=True)


def mark_secret_discarded(value: str) -> None:
    """标记敏感字符串已弃用（语义占位，无原地擦除）。

    CPython ``str`` 不可变，UI 持有的原串无法原地清零。本函数为纯语义标记——真正
    的明文释放依赖调用方置空引用（如 ``self._x = ""``）触发 GC（调用点 detail_panel /
    custom_fields_renderer / password_history_widget 均在调用后 ``.clear()`` 或置空引用）。
    历史实现经 ``encode`` 创建临时 bytearray 再清零，只擦除了自身刚创建的副本而原串
    未动，反而短暂增加明文副本数（反效果），故移除编码逻辑。函数名避用 ``zero``
    以免误以为已原地擦除原串；保留函数供调用方统一表达「此 secret 已弃用」意图并
    提示读者真正的释放责任在置空引用。

    Args:
        value: 已弃用的敏感字符串（仅作语义标记，不会被修改或清零）。
    """
    # 无操作：CPython str 不可变，原地清零不可能；保留函数体仅为承载上述契约。
    # del 解除本栈帧对明文参数的引用（内容不可擦，但即时收缩驻留面）。
    del value
