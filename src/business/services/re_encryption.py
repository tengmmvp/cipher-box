"""重加密编排服务。

从 VaultManager 提取的职责：在主密码修改时，使用新密钥重新加密
所有条目的敏感字段和密码历史记录。本服务只负责纯粹的加解密计算，
事务管理和密钥状态更新仍然留在 VaultManager 中。

命名说明：原名 KeyRotationService 易与 KeyManager（持密钥）、crypto_utils
（加解密）混淆，其实际职责是「重加密编排」，故更名 ReEncryptionService。
"""

from __future__ import annotations

import logging
from threading import Event
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ...database.types import EntryQuery, ReEncryptedEntry, ReEncryptedHistory
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

    与 B3 的 EntryStore / CategoryStore（Business 层宽切片）平行但更窄——
    ReEncryptionService 只用 ``get_entries`` 的 keyword 子集与若干批量方法，故独立
    声明，避免测试 mock 必须实现全部 CRUD。DatabaseManager 与 MockDB 均满足。
    """

    def get_entries(self, query: EntryQuery) -> list[RawEntry]: ...

    def update_entries_batch(self, rows: list[ReEncryptedEntry]) -> None: ...

    def get_all_password_history_batch(
        self, after_id: int = 0, limit: int = 200,
    ) -> list[PasswordHistory]: ...

    def update_password_history_batch(self, rows: list[ReEncryptedHistory]) -> None: ...

    def get_categories(self, *, verify: bool = True) -> list[Category]: ...

    def update_category_reencrypted(self, category: Category) -> None: ...

    def update_categories_batch(self, categories: list[Category]) -> None: ...


_RE_ENCRYPT_BATCH_SIZE = 200
# 重加密的敏感字段集，与 crypto_utils 的加解密字段集共用单一事实来源，
# 避免两处独立列举导致新增加密字段时重加密漏列（该列保留旧密钥密文、改密后无法解密）。
_ENCRYPTED_ENTRY_FIELDS = SENSITIVE_ENCRYPTED_FIELDS


class ReEncryptionService:
    """重加密编排服务。

    在主密码修改时，将所有条目的加密字段和密码历史记录从旧密钥
    重新加密到新密钥。分批处理以控制内存峰值。

    本类只负责加解密计算，不涉及事务管理或密钥状态更新。
    调用方 VaultManager._re_encrypt_all 负责事务包裹和密钥轮换。
    """

    def __init__(self, db: ReEncryptionDB, metadata_signer: MetadataSigner):
        """初始化重加密服务。

        Args:
            db: DatabaseManager 实例，用于读取和更新条目/历史。
            metadata_signer: MetadataSigner 实例，用于对重加密后的条目重新签名。
        """
        self._db = db
        self._signer = metadata_signer

    def re_encrypt_entries(self, old_key: bytes | bytearray, new_key: bytes | bytearray, *,
                           cancel_event: Event | None = None) -> None:
        """分批重新加密所有条目的敏感字段。

        逐字段解密→加密，减少同时驻留内存的明文数量。
        不变量：raw_entry 来自 get_entries（RawEntry），custom_fields 为密文 str。
        RawEntry 类型保证 custom_fields 恒为密文，getattr/setattr 读写均为密文 str。

        每批收集所有更新行，通过 executemany 一次性写入，将 N 次单独
        UPDATE 减少为 N/200 次 executemany 调用。

        Args:
            old_key: 改密前的旧 AES 密钥。
            new_key: 改密后的新 AES 密钥。
            cancel_event: 可选的 threading.Event，设置时提前终止循环。
        """
        # 预计算 domain_key：省的是「从主密钥派生域密钥」的那一次 HMAC，
        # 不是 sign_with_domain_key 每条仍做的签名 HMAC——后者无法预计算，
        # 因其输入含每条目不同的字段明文。每批 200 条省 200 次域密钥派生 HMAC。
        precomputed_domain_key = self._signer.compute_domain_key(new_key)
        try:
            last_id = 0
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise VaultError('重加密已被取消，事务回滚以保持数据一致')
                batch = self._db.get_entries(
                    EntryQuery(
                        include_deleted=True, limit=_RE_ENCRYPT_BATCH_SIZE,
                        after_id=last_id,
                    )
                )
                if not batch:
                    break
                # batch 来自 DB get_entries，主键 id 必非 None；守卫锚定契约，避免
                # None 作分页游标导致死循环或写入空主键（运行时不应触发）。
                last_raw = batch[-1]
                if last_raw.id is None:
                    raise VaultError('重加密分页遇到空主键，违反 RawEntry 主键非空契约')
                last_id = last_raw.id
                rows = []
                for raw_entry in batch:
                    # 主键非空守卫：兼作 Pyright 类型收窄（raw_entry.id 类型为 int|None，
                    # 缺失会使构造 ReEncryptedEntry(id=raw_entry.id) 处类型不符），并在
                    # 运行时锚定 DB 主键非空契约，与外层分页游标守卫并非纯冗余。
                    if raw_entry.id is None:
                        raise VaultError('重加密遇到空主键条目，违反 RawEntry 主键非空契约')
                    try:
                        for field in _ENCRYPTED_ENTRY_FIELDS:
                            # custom_fields 在 RawEntry 态为密文字符串，显式取 db_value
                            # 与 _row_to_entry 的状态机解耦，避免误读解密后的 list；
                            # 写回 setattr 对 custom_fields 同样落入密文 str，
                            # 与 custom_fields_db_value 的读取一致。
                            value = (
                                raw_entry.custom_fields_db_value
                                if field == 'custom_fields'
                                else getattr(raw_entry, field)
                            )
                            if value:
                                # strict=True：任一字段解密失败立即抛 ValueError，被下方
                                # except 捕获转为 DecryptionError 中止改密并回滚事务。
                                # 若用默认 strict=False，损坏字段会被静默解密为空串再
                                # 用新密钥加密写入——不可逆的数据丢失。
                                plain = _decrypt_field_impl(
                                    value, old_key, raw_entry.crypto_id, field,
                                    strict=True,
                                )
                                new_cipher = _encrypt_field_impl(
                                    plain, new_key, raw_entry.crypto_id, field,
                                )
                                setattr(raw_entry, field, new_cipher)
                                del plain
                    except DecryptionError as exc:
                        logger.error("重加密中止：条目 id=%s 解密失败", raw_entry.id)
                        raise DecryptionError(
                            "某条目解密失败，数据可能已损坏。中止改密以保护数据完整性。"
                        ) from exc

                    mac = self._signer.sign_with_domain_key(raw_entry, precomputed_domain_key)
                    rows.append(ReEncryptedEntry(
                        crypto_id=raw_entry.crypto_id,
                        title_enc=raw_entry.title,
                        username_enc=raw_entry.username,
                        password_enc=raw_entry.password,
                        url_enc=raw_entry.url,
                        category_id=raw_entry.category_id,
                        tags_enc=raw_entry.tags,
                        notes_enc=raw_entry.notes,
                        custom_fields_enc=raw_entry.custom_fields_db_value,
                        is_favorite=int(raw_entry.is_favorite),
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
        finally:
            # 域密钥（bytearray）在重加密全程持有（含分批与取消回滚窗口），结束后
            # 立即原地清零，收缩驻留面，不依赖后续 KeyManager.clear() 间接回收。
            secure_zero_buffer(precomputed_domain_key)

    def re_encrypt_categories(self, old_key: bytes | bytearray, new_key: bytes | bytearray) -> None:
        """使用分类 ID 绑定的 AAD 重加密全部分类名称。

        读取分类时 verify=False 跳过完整性验签：改密产生新域密钥后，旧 metadata_mac
        在新域密钥下验证必然失败，此处只需读取原始数据重加密 name 并重签。

        域密钥对称（与 ``re_encrypt_entries`` 的 ``sign_with_domain_key(new)`` 一致）：
        本方法在改密事务内运行，此时 ``signer._domain_key`` 仍是旧值
        （``vault_manager._re_encrypt_all`` 在事务提交后才正式 ``set_domain_key(new)``，
        防后台线程在 commit 前用新域密钥验签未提交数据）。分类重签用
        ``sign_category_with_domain_key`` 注入预计算的新域密钥，再经不签名的
        ``update_category_reencrypted`` 写入——与条目一样自给自足（自己用新域密钥
        预签名 + 不签名写），不临时切换 signer 全局 ``_domain_key``。这消除「借全局
        状态」的隐含契约：任何新增的并发/重入读路径都不会在此窗口读到被切换的
        ``_domain_key``，也使分类重签与条目重签在抽象上一致。
        """
        precomputed_domain_key = self._signer.compute_domain_key(new_key)
        try:
            # 收集所有重加密+重签后的分类，一次性 executemany 写入，与条目/历史
            # 的批量重加密路径对称（分类通常 <20，收益在一致性而非吞吐）。
            updated: list[Category] = []
            for category in self._db.get_categories(verify=False):
                if category.id is None:
                    continue
                crypto_id = category_crypto_id(category.id)
                try:
                    plaintext = _decrypt_field_impl(
                        category.name, old_key, crypto_id, 'category_name', strict=True,
                    )
                except DecryptionError as exc:
                    raise DecryptionError(
                        f'分类 {category.id} 名称解密失败，已中止改密'
                    ) from exc
                category.name = _encrypt_field_impl(
                    plaintext, new_key, crypto_id, 'category_name',
                )
                category.metadata_mac = self._signer.sign_category_with_domain_key(
                    category, precomputed_domain_key,
                )
                updated.append(category)
            if updated:
                self._db.update_categories_batch(updated)
        finally:
            # 新域密钥派生副本（bytearray）在分类重加密全程持有，结束后立即原地
            # 清零收缩驻留，不依赖后续 KeyManager.clear() 间接回收。
            secure_zero_buffer(precomputed_domain_key)

    def re_encrypt_history(self, old_key: bytes | bytearray, new_key: bytes | bytearray, *,
                           cancel_event: Event | None = None) -> None:
        """分批重新加密密码历史记录。

        密码历史分批拉取，使用游标分页与条目批处理对齐，
        控制改密重加密时的内存峰值，复用 _RE_ENCRYPT_BATCH_SIZE。

        每批收集所有更新行，通过 update_password_history_batch 一次性写入，
        将 N 次单独 UPDATE 合并为 N/200 次 executemany 调用。

        Args:
            old_key: 改密前的旧 AES 密钥。
            new_key: 改密后的新 AES 密钥。
            cancel_event: 可选的 threading.Event，设置时提前终止循环。
        """
        last_history_id = 0
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise VaultError('重加密已被取消，事务回滚以保持数据一致')
            history_batch = self._db.get_all_password_history_batch(
                last_history_id, _RE_ENCRYPT_BATCH_SIZE
            )
            if not history_batch:
                break
            last_history_id = history_batch[-1].id or 0
            rows: list[ReEncryptedHistory] = []
            for history in history_batch:
                if history.id is None:
                    continue  # 跳过无 ID 的历史记录，不应出现，防御性编程
                try:
                    plaintext = _decrypt_field_impl(
                        history.old_password_enc, old_key,
                        history.entry_crypto_id, 'password',
                        strict=True,
                    )
                except DecryptionError as exc:
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
