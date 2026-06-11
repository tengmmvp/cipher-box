"""密钥轮换（重加密）编排服务。

从 VaultManager 提取的职责：在主密码修改时，使用新密钥重新加密
所有条目的敏感字段和密码历史记录。本服务只负责纯粹的加解密计算，
事务管理和密钥状态更新仍然留在 VaultManager 中。
"""

import logging
from typing import NamedTuple

from ...exceptions import DecryptionError
from .crypto_utils import decrypt_field as _decrypt_field_impl
from .crypto_utils import encrypt_field as _encrypt_field_impl

logger = logging.getLogger(__name__)

_RE_ENCRYPT_BATCH_SIZE = 200
_ENCRYPTED_ENTRY_FIELDS = ('username', 'password', 'notes', 'totp_secret', 'custom_fields')


class ReEncryptedEntry(NamedTuple):
    """重加密后条目的批量更新 DTO。

    字段顺序与 ``EntryRepository._RE_ENCRYPT_BATCH_UPDATE_SQL`` 一一对应，
    消除了调用方需要了解 SQL 列布局的耦合。
    """
    crypto_id: str
    title: str
    username_enc: str
    password_enc: str
    url: str
    category_id: int | None
    tags: str
    notes_enc: str
    custom_fields_enc: str
    is_favorite: int  # 0 or 1
    password_strength: int
    entry_type: str
    totp_secret_enc: str
    updated_at: str
    password_changed_at: str
    metadata_mac: str
    id: int


class ReEncryptedHistory(NamedTuple):
    """重加密后密码历史的批量更新 DTO。"""
    ciphertext: str
    id: int


class KeyRotationService:
    """密钥轮换即重加密编排服务。

    在主密码修改时，将所有条目的加密字段和密码历史记录从旧密钥
    重新加密到新密钥。分批处理以控制内存峰值。

    本类只负责加解密计算，不涉及事务管理或密钥状态更新。
    调用方 VaultManager._re_encrypt_all 负责事务包裹和密钥轮换。
    """

    def __init__(self, db, metadata_signer):
        """初始化重加密服务。

        Args:
            db: DatabaseManager 实例，用于读取和更新条目/历史。
            metadata_signer: MetadataSigner 实例，用于对重加密后的条目重新签名。
        """
        self._db = db
        self._signer = metadata_signer

    def re_encrypt_entries(self, old_key: bytes, new_key: bytes):
        """分批重新加密所有条目的敏感字段。

        逐字段解密→加密，减少同时驻留内存的明文数量。
        不变量：raw_entry 来自 get_entries，_row_to_entry 将 custom_fields
        设为与 custom_fields_enc 相同的密文字符串，str 类型，因此 getattr
        读取的是密文字符串，setattr 写入的也是密文字符串。
        若 _row_to_entry 的行为改变，如改为解密后设为 list，此处会静默损坏。

        每批收集所有更新行，通过 executemany 一次性写入，将 N 次单独
        UPDATE 减少为 N/200 次 executemany 调用。
        """
        # 预计算域密钥，避免每条条目重复 HMAC 派生，每批 200 条可省 200 次 HMAC
        precomputed_domain_key = self._signer.compute_domain_key(new_key)
        last_id = 0
        while True:
            batch = self._db.get_entries(
                include_deleted=True, limit=_RE_ENCRYPT_BATCH_SIZE,
                after_id=last_id,
            )
            if not batch:
                break
            last_id = batch[-1].id
            rows = []
            for raw_entry in batch:
                try:
                    for field in _ENCRYPTED_ENTRY_FIELDS:
                        value = getattr(raw_entry, field)
                        if value:
                            plain = _decrypt_field_impl(
                                value, old_key, raw_entry.crypto_id, field,
                            )
                            setattr(raw_entry, field,
                                    _encrypt_field_impl(plain, new_key, raw_entry.crypto_id, field))
                            del plain
                except ValueError:
                    logger.error("重加密中止：条目 id=%s 解密失败", raw_entry.id)
                    raise DecryptionError(
                        "某条目解密失败，数据可能已损坏。中止改密以保护数据完整性。"
                    )

                mac = self._signer.sign_with_domain_key(raw_entry, precomputed_domain_key)
                rows.append(ReEncryptedEntry(
                    crypto_id=raw_entry.crypto_id,
                    title=raw_entry.title,
                    username_enc=raw_entry.username,
                    password_enc=raw_entry.password,
                    url=raw_entry.url,
                    category_id=raw_entry.category_id,
                    tags=raw_entry.tags,
                    notes_enc=raw_entry.notes,
                    custom_fields_enc=raw_entry.custom_fields_db_value,
                    is_favorite=1 if raw_entry.is_favorite else 0,
                    password_strength=raw_entry.password_strength,
                    entry_type=raw_entry.entry_type,
                    totp_secret_enc=raw_entry.totp_secret,
                    updated_at=raw_entry.updated_at,
                    password_changed_at=raw_entry.password_changed_at,
                    metadata_mac=mac,
                    id=raw_entry.id,
                ))
            self._db.update_entries_batch(rows)
            del batch, rows

    def re_encrypt_history(self, old_key: bytes, new_key: bytes):
        """分批重新加密密码历史记录。

        密码历史分批拉取，使用游标分页与条目批处理对齐，
        控制改密重加密时的内存峰值，复用 _RE_ENCRYPT_BATCH_SIZE。

        每批收集所有更新行，通过 update_password_history_batch 一次性写入，
        将 N 次单独 UPDATE 合并为 N/200 次 executemany 调用。
        """
        last_history_id = 0
        while True:
            history_batch = self._db.get_all_password_history_batch(
                last_history_id, _RE_ENCRYPT_BATCH_SIZE
            )
            if not history_batch:
                break
            last_history_id = history_batch[-1].id or 0
            rows: list[tuple] = []
            for history in history_batch:
                if history.id is None:
                    continue  # 跳过无 ID 的历史记录，不应出现，防御性编程
                try:
                    plaintext = _decrypt_field_impl(
                        history.old_password_enc, old_key,
                        history.entry_crypto_id, 'password',
                    )
                except ValueError as exc:
                    logger.error("重加密中止：密码历史 id=%s 解密失败", history.id)
                    raise DecryptionError(
                        "某密码历史记录解密失败，数据可能已损坏。"
                    ) from exc
                ciphertext = _encrypt_field_impl(
                    plaintext, new_key,
                    history.entry_crypto_id, 'password',
                )
                del plaintext
                rows.append(ReEncryptedHistory(
                    ciphertext=ciphertext,
                    id=history.id,
                ))
            if rows:
                self._db.update_password_history_batch(rows)
            del history_batch, rows
