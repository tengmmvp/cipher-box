"""主密钥与快照密钥的持有与安全清零。

从 VaultManager 提取的密钥生命周期管理职责，集中密钥材料的持有与清零，
便于审计密钥访问路径，并为未来引入更安全的密钥托管机制提供单一改造点，
例如 C 扩展级的密钥对象。

注：曾评估以匿名 mmap 持有主密钥以求更可靠清零，但 Python 标准库的
hmac.new 不接受 mmap，需先复制反而扩大明文暴露面；且 cryptography 的
AESGCM 构造时仍会将密钥复制到 OpenSSL C 层，mmap 无法清零该副本。
故当前仍以 bytearray 配合 secure_zero_buffer 持有，这是 CPython 下的最佳实践。
"""

import logging

from ...utils.memory import secure_zero_buffer

logger = logging.getLogger(__name__)


class KeyManager:
    """主密钥、快照密钥与密钥版本的集中持有与安全清零。"""

    def __init__(self) -> None:
        self._key: bytearray | None = None
        self._snapshot_key: bytearray | None = None
        self._key_epoch: str | None = None

    @property
    def key(self) -> bytes | None:
        """返回主密钥的 bytes 副本。

        返回副本而非内部 bytearray 引用，使调用方持有的密钥不受 lock() 时
        secure_zero_buffer 原地清零内部对象的影响，消除密钥身份暴露导致的
        并发清零风险。KeyManager 内部仍以 bytearray 持有，clear() 真正清零。
        """
        return bytes(self._key) if self._key is not None else None

    @property
    def snapshot_key(self) -> bytes | None:
        """返回快照密钥的 bytes 副本，理由同 key。"""
        return bytes(self._snapshot_key) if self._snapshot_key is not None else None

    @property
    def key_epoch(self) -> str | None:
        return self._key_epoch

    def _set_key(self, key: bytearray | bytes | None) -> None:
        """装入主密钥前先安全清零旧 bytearray，避免改密后旧密钥残留待 GC 回收。

        与 clear() 的清零语义对齐：旧密钥（bytearray）被新值覆盖前原地清零，
        收缩改密/恢复后旧密钥仍可被进程内存 dump 读取的窗口。
        old is not new 用于跳过“传入的正是当前持有的同一 bytearray”的情形
        （_to_bytearray 对 bytearray 直接返回、所有权转移），避免清零掉将要使用的值。
        """
        old = self._key
        new = self._to_bytearray(key)
        if old is not None and old is not new and isinstance(old, bytearray):
            secure_zero_buffer(old)
        self._key = new

    def _set_snapshot_key(self, snapshot_key: bytearray | bytes | None) -> None:
        """装入快照密钥前先安全清零旧 bytearray，理由同 _set_key。"""
        old = self._snapshot_key
        new = self._to_bytearray(snapshot_key)
        if old is not None and old is not new and isinstance(old, bytearray):
            secure_zero_buffer(old)
        self._snapshot_key = new

    def activate(
        self, key: bytearray | bytes, snapshot_key: bytearray | bytes, epoch: str,
    ) -> None:
        """解锁或改密成功后，一次性设置全部密钥材料与版本。"""
        self._set_key(key)
        self._set_snapshot_key(snapshot_key)
        self._key_epoch = epoch

    def update_key(self, key: bytearray | bytes) -> None:
        self._set_key(key)

    def update_snapshot_key(self, snapshot_key: bytearray | bytes) -> None:
        self._set_snapshot_key(snapshot_key)

    def update_epoch(self, epoch: str) -> None:
        self._key_epoch = epoch

    @staticmethod
    def _to_bytearray(value: bytearray | bytes | None) -> bytearray | None:
        """确保密钥以 bytearray 持有，使 secure_zero_buffer 能真正原地清零。

        所有权契约：传入的 bytearray 直接返回，所有权转移给 KeyManager——后续
        clear() 会原地清零该对象，调用方此后不得继续使用传入的引用（若需保留
        密钥应自行复制；key/snapshot_key property 读取始终返回 bytes 副本，不受
        清零影响，test_clear_zeroes_bytearray_key_content 据此验证传入对象被清零）。
        bytes 不可变，转为 bytearray 副本持有，清零作用于该副本。AESGCM 构造时
        仍会复制密钥到 OpenSSL C 层，该副本由 EncryptionEngine.clear_cache 间接管理。
        """
        if value is None:
            return None
        if isinstance(value, bytearray):
            return value
        return bytearray(value)

    def clear(self) -> None:
        """尽力清零密钥材料并释放引用。

        仅对 _key 与 _snapshot_key 调用 secure_zero_buffer 原地清零（二者以
        bytearray 持有）；_key_epoch 不是密钥材料，仅置 None 释放引用。
        CPython 下加密库内部仍持有密钥副本，依赖 GC 回收，此为固有限制。
        """
        try:
            # 直接遍历密钥属性而非 getattr(字符串名)：字段重命名时静态检查立即
            # 报错，避免 getattr 默认值掩盖重命名导致的静默空转清零（与避免
            # __getattr__ 全面委托破坏类型的教训同源）。
            for secret in (self._key, self._snapshot_key):
                if secret is not None:
                    secure_zero_buffer(secret)
        except Exception:
            logger.warning("密钥清零失败", exc_info=True)
        self._key = None
        self._snapshot_key = None
        self._key_epoch = None
