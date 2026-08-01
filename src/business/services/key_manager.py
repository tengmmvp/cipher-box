"""主密钥与快照密钥的持有与安全清零。

集中密钥材料的持有与清零，为未来引入更安全的密钥托管机制（如 C 扩展级密钥对象）
提供单一改造点。曾评估 mmap 持有以求更可靠清零，但 hmac.new 不接受 mmap 需先复制
反而扩大暴露面，且 AESGCM 仍复制密钥到 OpenSSL C 层无法清零；故当前以 bytearray
配合 secure_zero_buffer 持有，是 CPython 下的最佳实践。
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
        """返回主密钥的 bytes 副本，使调用方持有的密钥不受 lock() 清零内部对象影响。"""
        return bytes(self._key) if self._key is not None else None

    @property
    def snapshot_key(self) -> bytes | None:
        """返回快照密钥的 bytes 副本，理由同 key。"""
        return bytes(self._snapshot_key) if self._snapshot_key is not None else None

    @property
    def key_epoch(self) -> str | None:
        return self._key_epoch

    def _set_key(self, key: bytearray | bytes | None) -> None:
        """装入主密钥前先安全清零旧 bytearray，收缩改密/恢复后旧密钥残留窗口。"""
        self._key = self._set_secret(self._key, key)

    def _set_snapshot_key(self, snapshot_key: bytearray | bytes | None) -> None:
        """装入快照密钥前先安全清零旧 bytearray，理由同 _set_key。"""
        self._snapshot_key = self._set_secret(self._snapshot_key, snapshot_key)

    def _set_secret(
        self,
        current_value: bytearray | None,
        value: bytearray | bytes | None,
    ) -> bytearray | None:
        """归一新值为 bytearray 副本，并在装入前安全清零旧 bytearray（_set_key/_set_snapshot_key 共用）。

        ``current_value is not new`` 跳过「传入的正是当前持有的同一 bytearray」（防御性
        不变量），避免清零掉将要使用的值。current_value 来自 self._key/self._snapshot_key，
        非 None 时类型已由 :meth:`_to_bytearray` 保证为 bytearray，无需额外 isinstance
        守卫（QL-015）。
        """
        new = self._to_bytearray(value)
        if current_value is not None and current_value is not new:
            secure_zero_buffer(current_value)
        return new

    def activate(
        self,
        key: bytearray | bytes,
        snapshot_key: bytearray | bytes,
        epoch: str,
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
        """确保密钥以 bytearray 持有，使 secure_zero_buffer 能原地清零。

        总是复制：KeyManager 持有独立副本，与调用方解耦——双方各自收缩驻留面，
        避免「所有权转移致 finally 清零破坏激活态」陷阱。AESGCM 构造时仍复制密钥
        到 OpenSSL C 层，该副本由 EncryptionEngine.clear_cache 间接管理。
        """
        if value is None:
            return None
        return bytearray(value)

    def clear(self) -> None:
        """尽力清零密钥材料并释放引用。

        仅对 _key/_snapshot_key 调用 secure_zero_buffer 原地清零；_key_epoch 非
        密钥材料仅置 None。CPython 下加密库内部仍持副本依赖 GC 回收，为固有限制。
        """
        try:
            # 直接遍历密钥属性而非 getattr(字符串名)，字段重命名时静态检查立即报错，
            # 避免静默空转清零。
            for secret in (self._key, self._snapshot_key):
                if secret is not None:
                    secure_zero_buffer(secret)
        except Exception:
            logger.warning("密钥清零失败", exc_info=True)
        self._key = None
        self._snapshot_key = None
        self._key_epoch = None
