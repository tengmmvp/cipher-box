"""重加密编排服务。

主密码修改时用新密钥重新加密所有条目的敏感字段和密码历史。本服务只负责纯粹的
加解密计算，事务管理与密钥状态更新留在 VaultManager 中。
"""

from __future__ import annotations

import logging
from dataclasses import replace
from threading import Event
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ...database.types import EntryQuery, ReEncryptedEntry, ReEncryptedHistory, VerifyMode
from ...exceptions import DecryptionError, VaultError
from ...models import Category, PasswordHistory, RawEntry
from ...utils.memory import secure_zero_buffer
from .crypto_utils import (
    SENSITIVE_ENCRYPTED_FIELDS,
    category_crypto_id,
    decrypt_field as _decrypt_field_impl,
    encrypt_field as _encrypt_field_impl,
)

if TYPE_CHECKING:
    from .metadata_signer import MetadataSigner

logger = logging.getLogger(__name__)


@runtime_checkable
class ReEncryptionDB(Protocol):
    """ReEncryptionService 所需的数据库接口协议（窄接口，仅含实际使用的方法）。

    独立窄接口声明，避免测试 mock 必须实现全部 CRUD。DatabaseManager 与 MockDB 均满足。
    """

    def get_entries(self, query: EntryQuery) -> list[RawEntry]: ...

    def update_entries_batch(self, rows: list[ReEncryptedEntry]) -> None: ...

    def get_all_password_history_batch(
        self,
        after_id: int = 0,
        limit: int = 200,
    ) -> list[PasswordHistory]: ...

    def update_password_history_batch(self, rows: list[ReEncryptedHistory]) -> None: ...

    def get_categories(self, *, verify: bool = True) -> list[Category]: ...

    def update_categories_batch(self, categories: list[Category]) -> None: ...


# 重加密分批大小：单批 executemany 一次性写入，控制内存峰值并将 N 次 UPDATE 压缩为 N/200 次。
_RE_ENCRYPT_BATCH_SIZE = 200
# 重加密的敏感字段集，与加解密字段集共用单一事实源，避免新增加密字段时漏列致改密后无法解密。
_ENCRYPTED_ENTRY_FIELDS = SENSITIVE_ENCRYPTED_FIELDS


class ReEncryptionService:
    """重加密编排服务。

    主密码修改时将所有条目与密码历史从旧密钥重加密到新密钥，分批处理控制内存峰值。
    本类只负责加解密计算，事务包裹与密钥轮换由调用方 VaultManager._re_encrypt_all 负责。
    """

    def __init__(self, db: ReEncryptionDB, metadata_signer: MetadataSigner):
        """初始化重加密服务。

        Args:
            db: DatabaseManager 实例。
            metadata_signer: 用于对重加密后的条目重新签名。
        """
        self._db = db
        self._signer = metadata_signer

    def re_encrypt_entries(
        self,
        old_key: bytes | bytearray,
        new_key: bytes | bytearray,
        *,
        cancel_event: Event | None = None,
    ) -> None:
        """分批重新加密所有条目的敏感字段。

        逐字段解密→加密减少驻留明文。不变量：raw_entry 来自 get_entries，
        custom_fields 恒为密文 str（RawEntry 类型保证）。每批经 executemany 写入，
        将 N 次 UPDATE 减为 N/200 次。

        Args:
            old_key: 改密前的旧 AES 密钥。
            new_key: 改密后的新 AES 密钥。
            cancel_event: 可选的 threading.Event，设置时提前终止循环。
        """
        # 预计算 domain_key 省「从主密钥派生域密钥」的那一次 HMAC；每条仍做的
        # 签名 HMAC 输入含明文无法预计算。每批 200 条省 200 次域密钥派生。
        precomputed_domain_key = self._signer.compute_domain_key(new_key)
        try:
            last_id = 0
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise VaultError("重加密已被取消，事务回滚以保持数据一致")
                batch = self._db.get_entries(
                    EntryQuery(
                        include_deleted=True,
                        limit=_RE_ENCRYPT_BATCH_SIZE,
                        after_id=last_id,
                        # 重加密重写全部密文并新域密钥重签，旧签名无意义（密文完整性
                        # 由 strict 解密的 GCM 标签兜底）；SKIP 避免冗余验签延长持锁。
                        verify=VerifyMode.SKIP,
                    )
                )
                if not batch:
                    break
                # 主键 id 非 None 守卫：避免 None 作游标致死循环或写空主键。
                last_raw = batch[-1]
                if last_raw.id is None:
                    raise VaultError("重加密分页遇到空主键，违反 RawEntry 主键非空契约")
                last_id = last_raw.id
                rows = []
                for raw_entry in batch:
                    # 主键非空守卫：兼作 Pyright 类型收窄，并非与外层游标守卫纯冗余。
                    if raw_entry.id is None:
                        raise VaultError("重加密遇到空主键条目，违反 RawEntry 主键非空契约")
                    try:
                        updates: dict[str, Any] = {}
                        for field in _ENCRYPTED_ENTRY_FIELDS:
                            # custom_fields 在 RawEntry 态为密文 str，显式取 db_value
                            # 与 _row_to_entry 状态机解耦，避免误读解密后的 list。
                            value = (
                                raw_entry.custom_fields_db_value
                                if field == "custom_fields"
                                else getattr(raw_entry, field)
                            )
                            if value:
                                # strict=True：解密失败立即抛异常被下方转为 DecryptionError
                                # 中止改密并回滚。默认 strict=False 会静默把损坏字段解密为
                                # 空串再用新密钥写入，致不可逆数据丢失。
                                plain = _decrypt_field_impl(
                                    value,
                                    old_key,
                                    raw_entry.crypto_id,
                                    field,
                                    strict=True,
                                )
                                updates[field] = _encrypt_field_impl(
                                    plain,
                                    new_key,
                                    raw_entry.crypto_id,
                                    field,
                                )
                                del plain
                        re_encrypted = replace(raw_entry, **updates) if updates else raw_entry
                    except DecryptionError as exc:
                        logger.error("重加密中止：条目 id=%s 解密失败", raw_entry.id)
                        raise DecryptionError(
                            "某条目解密失败，数据可能已损坏。中止改密以保护数据完整性。"
                        ) from exc

                    mac = self._signer.sign_with_domain_key(re_encrypted, precomputed_domain_key)
                    rows.append(
                        ReEncryptedEntry(
                            crypto_id=re_encrypted.crypto_id,
                            title_enc=re_encrypted.title,
                            username_enc=re_encrypted.username,
                            password_enc=re_encrypted.password,
                            url_enc=re_encrypted.url,
                            category_id=re_encrypted.category_id,
                            tags_enc=re_encrypted.tags,
                            notes_enc=re_encrypted.notes,
                            custom_fields_enc=re_encrypted.custom_fields_db_value,
                            is_favorite=int(re_encrypted.is_favorite),
                            password_strength=re_encrypted.password_strength,
                            entry_type=re_encrypted.entry_type,
                            totp_secret_enc=re_encrypted.totp_secret,
                            updated_at=re_encrypted.updated_at,
                            password_changed_at=re_encrypted.password_changed_at,
                            metadata_mac=mac,
                            id=raw_entry.id,
                        )
                    )
                self._db.update_entries_batch(rows)
                del batch, rows
        finally:
            # 域密钥（bytearray）全程持有（含分批与回滚窗口），结束后立即原地清零。
            secure_zero_buffer(precomputed_domain_key)

    def re_encrypt_categories(
        self,
        old_key: bytes | bytearray,
        new_key: bytes | bytearray,
        *,
        cancel_event: Event | None = None,
    ) -> None:
        """使用分类 ID 绑定的 AAD 重加密全部分类名称。

        读取分类 verify=False 跳过验签：改密产生新域密钥后旧 metadata_mac 在新域密钥
        下必然失败，此处只读原始数据重加密 name 并重签。

        本方法在改密事务内运行，此时 ``signer._domain_key`` 仍是旧值（vault_manager
        在事务提交后才 set_domain_key(new)，防后台线程用新域密钥验签未提交数据）。
        分类重签经 ``sign_category_with_domain_key`` 注入预计算新域密钥、不签名写，
        与条目重签对称——不临时切换 signer 全局 _domain_key，无「借全局状态」的隐含契约。

        Args:
            cancel_event: 可选的 threading.Event，设置时提前终止（ARCH-004，与条目/历史
                重加密循环一致）。分类通常很少，取消窗口小，但保持三者一致以便统一响应取消。
        """
        precomputed_domain_key = self._signer.compute_domain_key(new_key)
        try:
            # 一次性 executemany 写入（分类通常 <20，收益在一致性而非吞吐）。
            updated: list[Category] = []
            for category in self._db.get_categories(verify=False):
                if cancel_event is not None and cancel_event.is_set():
                    raise VaultError("重加密已被取消，事务回滚以保持数据一致")
                if category.id is None:
                    continue
                crypto_id = category_crypto_id(category.id)
                try:
                    plaintext = _decrypt_field_impl(
                        category.name,
                        old_key,
                        crypto_id,
                        "category_name",
                        strict=True,
                    )
                except DecryptionError as exc:
                    raise DecryptionError(f"分类 {category.id} 名称解密失败，已中止改密") from exc
                category = replace(
                    category,
                    name=_encrypt_field_impl(
                        plaintext,
                        new_key,
                        crypto_id,
                        "category_name",
                    ),
                )
                category = replace(
                    category,
                    metadata_mac=self._signer.sign_category_with_domain_key(
                        category,
                        precomputed_domain_key,
                    ),
                )
                updated.append(category)
            if updated:
                self._db.update_categories_batch(updated)
        finally:
            # 新域密钥副本全程持有，结束后立即原地清零。
            secure_zero_buffer(precomputed_domain_key)

    def re_encrypt_history(
        self,
        old_key: bytes | bytearray,
        new_key: bytes | bytearray,
        *,
        cancel_event: Event | None = None,
    ) -> None:
        """分批重新加密密码历史记录。

        游标分页与条目批处理对齐控制内存峰值。每批经 update_password_history_batch
        一次性写入，将 N 次 UPDATE 合并为 N/200 次 executemany。

        Args:
            old_key: 改密前的旧 AES 密钥。
            new_key: 改密后的新 AES 密钥。
            cancel_event: 可选的 threading.Event，设置时提前终止循环。
        """
        last_history_id = 0
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise VaultError("重加密已被取消，事务回滚以保持数据一致")
            history_batch = self._db.get_all_password_history_batch(
                last_history_id, _RE_ENCRYPT_BATCH_SIZE
            )
            if not history_batch:
                break
            # 主键 id 非 None 守卫：避免 None 作游标致死循环。
            last_history = history_batch[-1]
            if last_history.id is None:
                raise VaultError("重加密分页遇到空主键，违反 PasswordHistory 主键非空契约")
            last_history_id = last_history.id
            rows: list[ReEncryptedHistory] = []
            for history in history_batch:
                # 主键非空守卫：兼作 Pyright 类型收窄，并非与外层游标守卫纯冗余。
                if history.id is None:
                    raise VaultError("重加密遇到空主键密码历史，违反 PasswordHistory 主键非空契约")
                try:
                    plaintext = _decrypt_field_impl(
                        history.old_password_enc,
                        old_key,
                        history.entry_crypto_id,
                        "password",
                        strict=True,
                    )
                except DecryptionError as exc:
                    logger.error("重加密中止：密码历史 id=%s 解密失败", history.id)
                    raise DecryptionError("某密码历史记录解密失败，数据可能已损坏。") from exc
                ciphertext = _encrypt_field_impl(
                    plaintext,
                    new_key,
                    history.entry_crypto_id,
                    "password",
                )
                del plaintext
                rows.append(
                    ReEncryptedHistory(
                        ciphertext=ciphertext,
                        id=history.id,
                    )
                )
            if rows:
                self._db.update_password_history_batch(rows)
            del history_batch, rows
