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

    def __init__(self):
        self._key = None
        self._snapshot_key = None
        self._key_epoch = None

    @property
    def key(self):
        return self._key

    @property
    def snapshot_key(self):
        return self._snapshot_key

    @property
    def key_epoch(self):
        return self._key_epoch

    def activate(self, key, snapshot_key, epoch) -> None:
        """解锁或改密成功后，一次性设置全部密钥材料与版本。"""
        self._key = self._to_bytearray(key)
        self._snapshot_key = self._to_bytearray(snapshot_key)
        self._key_epoch = epoch

    def update_key(self, key) -> None:
        self._key = self._to_bytearray(key)

    def update_snapshot_key(self, snapshot_key) -> None:
        self._snapshot_key = self._to_bytearray(snapshot_key)

    def update_epoch(self, epoch) -> None:
        self._key_epoch = epoch

    @staticmethod
    def _to_bytearray(value):
        """确保密钥以 bytearray 持有，使 secure_zero_buffer 能真正原地清零。

        bytearray 可变，直接持有，clear() 的 memset 可原地擦除；
        bytes 不可变，转为 bytearray 副本持有，清零作用于该副本。
        AESGCM 构造时仍会复制密钥到 OpenSSL C 层，该副本由
        EncryptionEngine.clear_cache 间接管理。
        """
        if value is None:
            return None
        if isinstance(value, bytearray):
            return value
        return bytearray(value)

    def clear(self) -> None:
        """尽力清零密钥材料并释放引用。

        CPython 下 bytes 不可变，secure_zero_buffer 仅清零可变副本，原始对象
        依赖 GC 回收，这是 CPython 固有限制。snapshot_key 与主密钥同理。
        """
        try:
            for attr in ('_key', '_snapshot_key'):
                secret = getattr(self, attr, None)
                if secret is not None:
                    secure_zero_buffer(secret)
        except Exception:
            logger.warning("密钥清零失败", exc_info=True)
        self._key = None
        self._snapshot_key = None
        self._key_epoch = None
