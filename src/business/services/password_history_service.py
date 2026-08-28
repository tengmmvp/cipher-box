"""密码历史服务：密码历史的读取与解密展示。

无状态编排 vault.db 读取与字段解密。条目更新写入历史仍由 EntryManager.update_entry
在事务内完成（涉及 epoch 复查与旧密钥保护），此处仅负责读取与解密展示。
"""

from __future__ import annotations

import logging
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ...database.types import VaultDataStore

from ...models import PasswordHistory
from ...utils.format import format_datetime
from .crypto_utils import KeyProvider, decrypt_field, require_vault_key

logger = logging.getLogger(__name__)


class PasswordHistoryVaultProtocol(KeyProvider, Protocol):
    """密码历史服务所需的最小保险库协议（ARCH-039「一删三协议」）。

    ``VaultManager`` 自然满足此协议。实际依赖面共 4 成员：取密钥两成员
    （:class:`crypto_utils.KeyProvider`，经 require_vault_key 消费）+ db
    （:class:`~...database.types.VaultDataStore` 数据库协议切片，本服务仅用其
    get_password_history/get_password_history_count）+ vault_write_lock（decrypt
    接触全量历史明文须与改密/备份串行化）。协议化后 services 子包不再
    TYPE_CHECKING 引用具体 manager 类，测试替身只需 4 成员。
    """

    @property
    def db(self) -> VaultDataStore: ...

    def vault_write_lock(self) -> AbstractContextManager[None]: ...


class PasswordHistoryService:
    """密码历史的数据库读取与解密展示。"""

    def __init__(self, vault: PasswordHistoryVaultProtocol):
        self._vault = vault

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def get(self, entry_id: int) -> list[PasswordHistory]:
        """读取条目的密码历史。委托 db.get_password_history。"""
        return self._vault.db.get_password_history(entry_id)

    def get_count(self, entry_id: int) -> int:
        """读取条目的密码历史记录数。委托 db.get_password_history_count。"""
        return self._vault.db.get_password_history_count(entry_id)

    def decrypt(self, history: list[PasswordHistory]) -> list[dict[str, str]]:
        """解密密码历史，返回字典列表，每个字典含 changed_at 与 password。

        持 ``vault_write_lock``（与 full_analysis 对齐）：本方法接触全量历史明文，
        持锁防 ``lock()`` 中途清零主密钥致用失效密钥解密，并使接触明文操作串行化。
        """
        result = []
        with self._vault.vault_write_lock():
            # 循环外提取主密钥一次（对齐 full_analysis）：self._key 经 property 链每轮新建
            # 32 字节副本，N 条历史会驻留 N 份主密钥副本，循环外取一份复用收缩驻留面。
            key = self._key
            for h in history:
                pwd = decrypt_field(h.old_password_enc, key, h.entry_crypto_id, "password")
                if pwd:
                    result.append(
                        {
                            "changed_at": format_datetime(h.changed_at),
                            "password": pwd,
                        }
                    )
                else:
                    # 解密失败（损坏记录）静默丢弃会掩盖数据问题，记录告警便于排查
                    logger.warning(
                        "密码历史解密失败 entry_crypto_id=%s，已跳过",
                        h.entry_crypto_id,
                    )
        return result
