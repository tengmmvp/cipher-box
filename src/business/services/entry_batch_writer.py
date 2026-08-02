"""导入批量写入的加密与落库编排（无状态纯函数）。

从 EntryManager 下沉的导入专用批量写入路径：新条目批量加密/写入、覆盖条目批量
预处理（验证+加密）/写入。仅服务 ImportExportManager，经 ``entry_mgr`` 参数注入
EntryManager 的加密/落库原语（包内协作，调其 ``_build_encrypted_entry`` 等私有），
使 EntryManager 聚焦单条 CRUD 与视图解密。

两阶段（MAINT-004）：CPU 密集的加密移出 db_lock（调用方先取 pre_epoch 快照→锁外
加密→epoch 守卫事务内裸写入），pre_epoch 守卫保证「加密后→写入前」改密则复查失败回滚。
"""

import uuid
from dataclasses import replace
from typing import TYPE_CHECKING, NamedTuple

from ...crypto.password_generator import PasswordGenerator
from ...exceptions import (
    DecryptionError,
    EntryError,
    EntryIntegrityError,
    VaultKeyEpochMismatchError,
)
from ...models import Entry, RawEntry
from ...utils.format import utc_now_iso
from .entry_validation import validate_plain_entry

if TYPE_CHECKING:
    from ..managers.entry_manager import EntryManager


class BatchUpdateItem(NamedTuple):
    """批量覆盖更新项（导入覆盖路径）：合并后条目、待覆盖条目密文 raw。

    old_password 为 None 表示未预解密，由 :func:`prepare_overwrite_updates` 在
    prepared 阶段逐条解密（PERF-006：不批量预解密致全部旧密码同刻驻留）；解密后经
    EntryManager._prepare_password_update 比对即 del，收敛明文驻留面。
    """

    entry: Entry
    raw: RawEntry
    old_password: str | None


class PreparedUpdate(NamedTuple):
    """覆盖项加密预处理结果（MAINT-004）：写阶段所需的最小密文载荷。

    由 :func:`prepare_overwrite_updates` 在锁外加密构建，供 :func:`write_overwrite_updates`
    在事务内逐条写入。raw 保留以取 ``raw.password`` 记录密码历史（旧密文，非明文）。
    """

    enc_entry: RawEntry
    raw: RawEntry
    password_changed: bool
    password_changed_at: str


def encrypt_new_entries(
    entry_mgr: "EntryManager", entries: list[Entry]
) -> tuple[list[RawEntry], bool]:
    """锁外加密构建新条目密文（MAINT-004），返回 ``(enc_entries, preserve_metadata)``。

    CPU 密集的加密循环移出 db_lock：调用方先取 ``pre_epoch`` 快照，调本函数加密，
    再于 ``epoch_guarded_transaction(pre_epoch=...)`` 内调 :func:`write_new_entries`
    裸写入。加密仅依赖 vault key（不触 db_lock），故可锁外；pre_epoch 守卫保证
    「加密后→写入前」若改密则复查失败回滚，旧密钥密文不落库。
    ``entries`` 须已由 ``Entry.from_dict`` 校验。
    """
    now = utc_now_iso()
    enc_entries: list[RawEntry] = []
    for entry in entries:
        entry = replace(
            entry,
            password_strength=PasswordGenerator.check_strength(entry.password).score,
        )
        crypto_id = entry.crypto_id or uuid.uuid4().hex
        enc_entries.append(
            entry_mgr._build_encrypted_entry(
                entry,
                crypto_id,
                now,
                created_at=entry.created_at or now,
                updated_at=entry.updated_at or now,
            )
        )
    preserve = any(e.created_at or e.updated_at for e in entries)
    return enc_entries, preserve


def write_new_entries(
    entry_mgr: "EntryManager",
    enc_entries: list[RawEntry],
    *,
    preserve: bool,
    notify: bool = True,
) -> None:
    """事务内裸写入已加密条目（MAINT-004），executemany 一次性 INSERT。

    写入须受 epoch 守卫保护：导入路径在 ``epoch_guarded_transaction`` 内调用；
    不含加密，仅 db 写，把 db_lock 持有收敛到 executemany 时长。
    """
    if not enc_entries:
        if notify:
            entry_mgr._change_bus.notify(clear_summaries=False)
        return
    entry_mgr._vault.db.add_entries_batch(enc_entries, preserve_metadata=preserve)
    if notify:
        # 与 add_entry 一致：新条目不改变既有摘要，clear_summaries=False 保留缓存。
        entry_mgr._change_bus.notify(clear_summaries=False)


def prepare_overwrite_updates(
    entry_mgr: "EntryManager",
    items: list[BatchUpdateItem],
    *,
    preserve_password_changed_at: bool = True,
) -> tuple[list[PreparedUpdate], list[tuple[int, Exception]]]:
    """锁外验证+加密覆盖项（MAINT-004），返回 ``(prepared, failures)``。

    验证/解密/加密预处理移出 db_lock：调用方先取 ``pre_epoch`` 快照，调本函数预处理，
    再于 ``epoch_guarded_transaction(pre_epoch=...)`` 内调 :func:`write_overwrite_updates`。

    failures 仅收集验证/解密阶段的 EntryError / EntryIntegrityError / DecryptionError
    （数据问题，逐条跳过）；写阶段错误由 :func:`write_overwrite_updates` 向上传播中止。
    pop_totp 在此阶段（加密前）失效缓存。
    """
    failures: list[tuple[int, Exception]] = []
    now = utc_now_iso()
    prepared: list[PreparedUpdate] = []
    for idx, item in enumerate(items):
        entry, raw, old_password = item.entry, item.raw, item.old_password
        try:
            validate_plain_entry(entry)
            if entry.integrity_error:
                raise EntryIntegrityError(
                    f"条目存在无法解密的字段（{entry.integrity_message}），为避免数据丢失已禁止保存"
                )
            if entry.id is None:
                raise EntryError("覆盖条目缺少 id")
            # 失效该条目的 TOTP secret 缓存，下次 TotpService 重新解密。
            entry_mgr._cache.pop_totp(entry.id)
            new_pwd_enc, password_changed = entry_mgr._prepare_password_update(
                entry,
                raw,
                old_password,
            )
            password_changed_at = entry_mgr._resolve_password_changed_at(
                entry,
                raw,
                password_changed,
                preserve_password_changed_at,
            )
            entry = replace(
                entry,
                password_strength=PasswordGenerator.check_strength(entry.password).score,
            )
            enc_entry = entry_mgr._build_encrypted_entry(
                entry,
                raw.crypto_id,
                now,
                created_at=raw.created_at,
                updated_at=now,
                password_override=new_pwd_enc,
                entry_id=entry.id,
            )
            enc_entry = replace(enc_entry, password_changed_at=password_changed_at)
            prepared.append(PreparedUpdate(enc_entry, raw, password_changed, password_changed_at))
        except (EntryError, EntryIntegrityError, DecryptionError) as exc:
            failures.append((idx, exc))
    return prepared, failures


def write_overwrite_updates(
    entry_mgr: "EntryManager",
    prepared: list[PreparedUpdate],
    pre_epoch: str | None,
) -> int:
    """锁内逐条 SAVEPOINT 写入已加密覆盖项（MAINT-004），复查 ``pre_epoch``。

    须在 ``epoch_guarded_transaction(pre_epoch=...)`` 内调用。``pre_epoch`` 由调用方
    在锁外加密前快照并传入，与本函数逐条复查共用同一快照——纵深防御「写入期间改密」，
    不匹配或写失败照原语义向上传播中止导入。
    """
    count = 0
    for item in prepared:
        with entry_mgr.db.transaction():
            if entry_mgr.key_epoch != pre_epoch:
                raise VaultKeyEpochMismatchError(
                    "更新期间检测到密钥变更（改密/锁定），已中止以防写入旧密钥密文"
                )
            if item.raw.password and item.password_changed and item.enc_entry.id is not None:
                # 用与条目一致的 password_changed_at 作为历史 changed_at，
                # 避免两次独立 utc_now_iso() 产生的微秒级时序倒置。
                entry_mgr.db.add_password_history(
                    item.enc_entry.id,
                    item.raw.password,
                    changed_at=item.password_changed_at,
                )
            entry_mgr.db.update_entry(item.enc_entry, preserve_updated_at=True)
        count += 1
    return count


__all__ = [
    "BatchUpdateItem",
    "PreparedUpdate",
    "encrypt_new_entries",
    "prepare_overwrite_updates",
    "write_new_entries",
    "write_overwrite_updates",
]
