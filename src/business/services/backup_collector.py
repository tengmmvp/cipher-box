"""备份载荷采集：解密全量明文并构建可移植字典。

从 :class:`..managers.backup_restore.BackupRestoreManager` 下沉的无状态采集逻辑：
原实例方法（``_collect_portable_*`` / ``_check_payload_limit``）迁移为模块级函数，
原先经由 ``self._key`` / ``self._vault.db`` / ``self._entry_mgr`` 访问的依赖改为
入参注入，使采集与 manager 状态解耦——便于在锁外 finalize 复用（A4）与单元测试。

``cancel_check`` 触发时经 :class:`_BackupCancelled` 中止采集，编排层捕获后返回 None
（不产出残缺备份）。payload 字节数增量估算超限抛 :class:`PayloadTooLargeError`。
"""

import json
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ...database.types import EntryQuery
from ...exceptions import BackupError, DecryptionError, PayloadTooLargeError
from ...models import PasswordHistory, RawEntry
from ...utils.format import utc_now_iso
from .backup_header_codec import BACKUP_FORMAT, BACKUP_VERSION, MAX_BACKUP_PAYLOAD_SIZE
from .backup_payload import (
    CATEGORY_OVERHEAD_BYTES,
    ENTRY_OVERHEAD_BYTES,
    HISTORY_OVERHEAD_BYTES,
)
from .backup_validator import MAX_BACKUP_ENTRIES, MAX_HISTORY_PER_ENTRY
from .crypto_utils import decrypt_entry_to_portable_dict, decrypt_field

if TYPE_CHECKING:
    from ...database.types import VaultDataStore
    from ..managers.entry_manager import EntryManager

logger = logging.getLogger(__name__)


class _BackupCancelled(Exception):
    """内部哨兵异常：cancel_check 触发时中止备份采集，编排层捕获后返回 None。

    用异常而非返回值传递「取消」，使采集子方法保持单一返回类型（tuple），
    编排层 ``collect_portable_data`` 统一在 try/except 中归一为 None。
    """


def check_payload_limit(estimated_size: int) -> None:
    """估算的 payload 字节数超限时抛 PayloadTooLargeError，供采集路径复用。"""
    if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
        raise PayloadTooLargeError('备份数据过大')


def collect_portable_data(
    key: bytes,
    db: 'VaultDataStore',
    entry_mgr: 'EntryManager',
    cancel_check: Callable[[], bool] | None = None,
    raw_entries: list[RawEntry] | None = None,
    history_rows: list[PasswordHistory] | None = None,
    categories: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """收集备份数据：解密所有字段为明文，构建可移植字典。

    编排条目与密码历史的采集：二者各自增量估算 payload 大小，超限抛
    :class:`PayloadTooLargeError`；``cancel_check`` 触发时经
    :class:`_BackupCancelled` 中止并整体返回 None（调用方据此不产出残缺备份）。

    A4 后本方法在 ``finalize_backup`` 锁外调用：``raw_entries``/``history_rows``/
    ``categories`` 由 ``prepare_backup_locked`` 在锁内预读并传入，本方法只负责
    解密（全量解密移出锁以缩短 ``lock()`` 阻塞，``cancel_check`` 在锁外解密循环
    中及时生效）。三者任一为 None 时回退到经 ``db``/``entry_mgr`` 自读 DB 的原行为，
    供持锁全流程路径（``_create_backup_locked``）复用。

    返回结构的嵌套 entries/categories/password_history 项值类型混合，故标注
    ``dict[str, Any]``（结构由 :func:`validate_restore_data` 校验）。
    """
    if categories is None:
        categories = [
            category.to_dict()
            for category in entry_mgr.categories.get_categories()
        ]
    # 基于字段原始字节长度的粗略估算，避免逐条 json.dumps 双重序列化开销
    estimated_size = sum(
        len(c.get('name', '').encode('utf-8')) + CATEGORY_OVERHEAD_BYTES
        for c in categories
    )
    try:
        entries, entry_count, estimated_size = collect_portable_entries(
            key, db, cancel_check, estimated_size, raw_entries,
        )
        history, _ = collect_portable_history(
            key, db, cancel_check, entry_count, estimated_size, history_rows,
        )
    except _BackupCancelled:
        return None
    return {
        'format': BACKUP_FORMAT,
        'version': BACKUP_VERSION,
        'created_at': utc_now_iso(),
        'categories': categories,
        'entries': entries,
        'password_history': history,
    }


def collect_portable_entries(
    key: bytes,
    db: 'VaultDataStore',
    cancel_check: Callable[[], bool] | None,
    estimated_size: int,
    raw_entries: list[RawEntry] | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    """采集并解密全部条目为可移植字典，增量估算 payload 大小。

    返回 ``(entries, entry_count, estimated_size)``。``cancel_check`` 触发时抛
    :class:`_BackupCancelled`（编排层捕获）；完整性失败抛 :class:`BackupError`；
    估算超限抛 :class:`PayloadTooLargeError`。

    A4：``raw_entries`` 由 ``prepare_backup_locked`` 锁内预读时，直接解密传入的
    raw（跳过 DB 读，保留数量校验、cancel_check、estimated_size 逻辑），使本方法
    的解密循环可在锁外运行、``cancel_check`` 得以及时中止。
    """
    if raw_entries is None:
        raw_entries = db.get_entries(EntryQuery(include_deleted=True))
    if len(raw_entries) > MAX_BACKUP_ENTRIES:
        raise PayloadTooLargeError('备份条目数量超出限制')
    entries: list[dict[str, Any]] = []
    for raw in raw_entries:
        if cancel_check and cancel_check():
            raise _BackupCancelled
        try:
            portable_item = decrypt_entry_to_portable_dict(raw, key, include_secrets=True)
        except (DecryptionError, json.JSONDecodeError) as exc:
            # decrypt_entry_to_portable_dict 失败抛异常（完整性/解密/JSON 损坏），
            # 此处转为 BackupError 中止备份（备份不容忍残缺条目）。
            raise BackupError(
                f'条目 {raw.id} 完整性校验或解密失败，备份已中止'
            ) from exc
        # 基于字段原始长度的粗略估算，每条目约 512 字节固定开销。估算覆盖全部
        # 将进入 JSON payload 的字段，以密文长度作上界（base64 密文 ≥ 明文），
        # 避免大 notes 或 custom_fields 场景下粗估漏判、直至序列化才产生内存峰值。
        estimated_size += (
            len(raw.title.encode('utf-8'))
            + len((raw.username or '').encode('utf-8'))
            + len((raw.url or '').encode('utf-8'))
            + len((raw.tags or '').encode('utf-8'))
            + len((raw.notes or '').encode('utf-8'))
            + len(raw.custom_fields_db_value.encode('utf-8'))
            + len((raw.totp_secret or '').encode('utf-8'))
            + ENTRY_OVERHEAD_BYTES
        )
        check_payload_limit(estimated_size)
        entries.append(portable_item)
    return entries, len(raw_entries), estimated_size


def collect_portable_history(
    key: bytes,
    db: 'VaultDataStore',
    cancel_check: Callable[[], bool] | None,
    entry_count: int,
    estimated_size: int,
    history_rows: list[PasswordHistory] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """采集并解密密码历史，增量估算 payload 大小。

    返回 ``(history, estimated_size)``。``entry_count`` 用于历史条数上限校验
    （每条目平均历史数不超过 :data:`MAX_HISTORY_PER_ENTRY`）。

    A4：``history_rows`` 由 ``prepare_backup_locked`` 锁内预读时直接解密传入
    （跳过 DB 读），使解密循环可在锁外运行。
    """
    if history_rows is None:
        history_rows = db.get_all_password_history()
    if len(history_rows) > entry_count * MAX_HISTORY_PER_ENTRY:
        raise PayloadTooLargeError('密码历史数量超出限制')
    history: list[dict[str, Any]] = []
    for history_row in history_rows:
        if cancel_check and cancel_check():
            raise _BackupCancelled
        try:
            pwd = decrypt_field(
                history_row.old_password_enc, key,
                history_row.entry_crypto_id, 'password', strict=True,
            )
        except DecryptionError:
            raise BackupError(
                f'条目 {history_row.entry_id} 的密码历史解密失败，备份已中止'
            ) from None
        history.append({
            'entry_id': history_row.entry_id,
            'password': pwd,
            'changed_at': history_row.changed_at,
        })
        estimated_size += (
            len(history_row.changed_at.encode('utf-8'))
            + len((history_row.old_password_enc or '').encode('utf-8'))
            + HISTORY_OVERHEAD_BYTES
        )
        check_payload_limit(estimated_size)
    return history, estimated_size
