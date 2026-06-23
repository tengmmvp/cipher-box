"""密码历史服务 — 从 EntryManager 抽离的密码历史读取与解密。

无状态编排 vault.db 读取与字段解密。条目更新写入历史的路径仍由
EntryManager.update_entry 在事务内完成（涉及 epoch 复查与旧密钥保护），
此处仅负责对外读取与解密展示。
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...models import PasswordHistory
from ...utils.format import format_datetime
from .crypto_utils import decrypt_field, require_vault_key

logger = logging.getLogger(__name__)


class PasswordHistoryService:
    """密码历史的数据库读取与解密展示。"""

    def __init__(self, vault: 'VaultManager'):
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

    def decrypt(self, history: list[PasswordHistory]) -> list[dict]:
        """解密密码历史，返回字典列表，每个字典含变更时间 changed_at 与密码 password。

        持 ``vault_write_lock`` 与 ``security_analyzer.full_analysis`` 对齐：本方法
        接触全量历史明文密码，持锁保证 ``lock()`` 不会在解密中途清零主密钥导致用
        失效密钥解密，也使「接触全量明文」的操作串行化。
        """
        result = []
        with self._vault.vault_write_lock():
            for h in history:
                pwd = decrypt_field(
                    h.old_password_enc, self._key, h.entry_crypto_id, 'password'
                )
                if pwd:
                    result.append({
                        'changed_at': format_datetime(h.changed_at),
                        'password': pwd,
                    })
                else:
                    # 解密失败（损坏记录）静默丢弃会掩盖数据问题，记录告警便于排查
                    logger.warning(
                        "密码历史解密失败 entry_crypto_id=%s，已跳过", h.entry_crypto_id,
                    )
        return result
