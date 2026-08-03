"""备份载荷采集：解密全量明文并构建可移植字典。

无状态函数：全入参注入，与 manager 状态解耦，便于锁外 finalize 复用（A4）与单元测试。
``cancel_check`` 触发时经 :class:`_BackupCancelled` 中止采集，编排层捕获后返回 None
（不产出残缺备份）。payload 字节数增量估算超限抛 :class:`PayloadTooLargeError`。

A4 契约：raw_entries/history_rows/categories 须由 prepare_backup_locked 锁内预读传入，
全量解密移出锁以缩短 ``lock()`` 阻塞。三者原为可选参数、None 时锁外自读 DB 回退，
但唯一调用方（finalize_backup）恒传入预读数据，回退属死代码且锁外读 DB 与并发写有
竞态（读到部分提交状态），故改为必传并移除回退（M11）。
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from ....exceptions import BackupError, DecryptionError, PayloadTooLargeError
from ....models import PasswordHistory, RawEntry
from ....utils.format import utc_now_iso
from ..crypto_utils import decrypt_entry_to_portable_dict, decrypt_field
from .header_codec import BACKUP_FORMAT, BACKUP_VERSION, MAX_BACKUP_PAYLOAD_SIZE
from .payload import (
    CATEGORY_OVERHEAD_BYTES,
    ENTRY_OVERHEAD_BYTES,
    HISTORY_OVERHEAD_BYTES,
)
from .validator import MAX_BACKUP_ENTRIES, MAX_HISTORY_PER_ENTRY

logger = logging.getLogger(__name__)


class _BackupCancelled(Exception):
    """内部哨兵异常：cancel_check 触发时中止采集，编排层捕获后返回 None。

    用异常而非返回值传递「取消」，使采集子方法保持单一返回类型（tuple）。
    """


def check_payload_limit(estimated_size: int) -> None:
    """估算的 payload 字节数超限时抛 PayloadTooLargeError，供采集路径复用。"""
    if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
        raise PayloadTooLargeError("备份数据过大")


def collect_portable_data(
    key: bytes,
    cancel_check: Callable[[], bool] | None,
    raw_entries: list[RawEntry],
    history_rows: list[PasswordHistory],
    categories: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """收集备份数据：解密所有字段为明文，构建可移植字典。

    A4：本函数在 ``finalize_backup`` 锁外调用，``raw_entries``/``history_rows``/``categories``
    须由 prepare_backup_locked 锁内预读传入（必传，M11：移除原 None 锁外自读 DB 回退，
    避免与并发写竞态读到部分提交状态）。返回嵌套项值类型混合，故标注
    ``dict[str, Any]``（结构由 validate_restore_data 校验）。
    """
    # 基于字段原始字节长度的粗略估算，避免逐条 json.dumps 双重序列化开销
    estimated_size = sum(
        len(c.get("name", "").encode("utf-8")) + CATEGORY_OVERHEAD_BYTES for c in categories
    )
    try:
        entries, entry_count, estimated_size = collect_portable_entries(
            key,
            cancel_check,
            estimated_size,
            raw_entries,
        )
        history = collect_portable_history(
            key,
            cancel_check,
            entry_count,
            estimated_size,
            history_rows,
        )
    except _BackupCancelled:
        return None
    return {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "created_at": utc_now_iso(),
        "categories": categories,
        "entries": entries,
        "password_history": history,
    }


def collect_portable_entries(
    key: bytes,
    cancel_check: Callable[[], bool] | None,
    estimated_size: int,
    raw_entries: list[RawEntry],
) -> tuple[list[dict[str, Any]], int, int]:
    """采集并解密全部条目为可移植字典，增量估算 payload 大小。

    返回 ``(entries, entry_count, estimated_size)``（元素含义同参数名）。条目完整性失败
    抛 :class:`BackupError`；``raw_entries`` 锁内预读后必传（A4 + M11），解密循环锁外运行。
    """
    if len(raw_entries) > MAX_BACKUP_ENTRIES:
        raise PayloadTooLargeError("备份条目数量超出限制")
    entries: list[dict[str, Any]] = []
    for raw in raw_entries:
        if cancel_check and cancel_check():
            raise _BackupCancelled
        try:
            portable_item = decrypt_entry_to_portable_dict(raw, key, include_secrets=True)
        except (DecryptionError, json.JSONDecodeError) as exc:
            # 解密失败（完整性/解密/JSON 损坏）转 BackupError 中止，备份不容忍残缺条目。
            raise BackupError(f"条目 {raw.id} 完整性校验或解密失败，备份已中止") from exc
        # 以密文长度（≥ 明文）作上界估算，覆盖全部入 payload 字段，避免大字段
        # 粗估漏判至序列化才产生内存峰值。
        estimated_size += (
            len(raw.title.encode("utf-8"))
            + len((raw.username or "").encode("utf-8"))
            + len((raw.password or "").encode("utf-8"))
            + len((raw.url or "").encode("utf-8"))
            + len((raw.tags or "").encode("utf-8"))
            + len((raw.notes or "").encode("utf-8"))
            + len(raw.custom_fields_db_value.encode("utf-8"))
            + len((raw.totp_secret or "").encode("utf-8"))
            + ENTRY_OVERHEAD_BYTES
        )
        check_payload_limit(estimated_size)
        entries.append(portable_item)
    return entries, len(raw_entries), estimated_size


def collect_portable_history(
    key: bytes,
    cancel_check: Callable[[], bool] | None,
    entry_count: int,
    estimated_size: int,
    history_rows: list[PasswordHistory],
) -> list[dict[str, Any]]:
    """采集并解密密码历史，返回历史记录列表。

    ``estimated_size`` 入参参与 payload 上限校验，累计值不再返回（无调用方使用，QL-010）；
    ``entry_count`` 用于历史上限校验。``history_rows`` 锁内预读后必传（A4 + M11），解密循环锁外运行。
    """
    if len(history_rows) > entry_count * MAX_HISTORY_PER_ENTRY:
        raise PayloadTooLargeError("密码历史数量超出限制")
    history: list[dict[str, Any]] = []
    for history_row in history_rows:
        if cancel_check and cancel_check():
            raise _BackupCancelled
        try:
            pwd = decrypt_field(
                history_row.old_password_enc,
                key,
                history_row.entry_crypto_id,
                "password",
                strict=True,
            )
        except DecryptionError:
            raise BackupError(
                f"条目 {history_row.entry_id} 的密码历史解密失败，备份已中止"
            ) from None
        history.append(
            {
                "entry_id": history_row.entry_id,
                "password": pwd,
                "changed_at": history_row.changed_at,
            }
        )
        estimated_size += (
            len(history_row.changed_at.encode("utf-8"))
            + len((history_row.old_password_enc or "").encode("utf-8"))
            + HISTORY_OVERHEAD_BYTES
        )
        check_payload_limit(estimated_size)
    return history
