"""备份载荷采集：解密全量明文并构建可移植字典。

无状态函数：全入参注入，与 manager 状态解耦，便于锁外 finalize 复用（备份锁外
解密决策，见 backup_restore 的 :meth:`create_backup`）与单元测试。
``cancel_check`` 触发时经 :class:`_BackupCancelled` 中止采集，编排层捕获后返回 None
（不产出残缺备份）。payload 字节数增量估算超限抛 :class:`PayloadTooLargeError`。

备份锁外解密契约：raw_entries/history_rows/categories 须由 prepare_backup_locked
锁内预读传入，全量解密移出锁以缩短 ``lock()`` 阻塞。三者原为可选参数、None 时锁外
自读 DB 回退，但唯一调用方（finalize_backup）恒传入预读数据，回退属死代码且锁外读
DB 与并发写有竞态（读到部分提交状态），故改为必传并移除回退（MAINT-015 必传化原则
在数据参数上的同款应用：删除兜底回退，契约由可选约定升级为签名强制）。
"""

import json
from collections.abc import Callable
from typing import Any

from ....exceptions import BackupError, DecryptionError, PayloadTooLargeError
from ....models import PasswordHistory, RawEntry
from ....utils.format import utc_now_iso
from ..crypto_utils import STRING_ENCRYPTED_FIELDS, decrypt_field, decrypt_string_fields_strict
from ..entry_batch_writer import should_report_progress
from .header_codec import BACKUP_FORMAT, BACKUP_VERSION, MAX_BACKUP_PAYLOAD_SIZE
from .payload import (
    CATEGORY_OVERHEAD_BYTES,
    CUSTOM_FIELD_OVERHEAD_BYTES,
    ENTRY_OVERHEAD_BYTES,
    HISTORY_OVERHEAD_BYTES,
    PAYLOAD_TOP_OVERHEAD_BYTES,
)
from .validator import MAX_BACKUP_ENTRIES, MAX_HISTORY_PER_ENTRY

# portable dict 中的时间戳字段（模板以空串占位，估算按实际长度补齐）。
_ENTRY_TIMESTAMP_FIELDS = ("created_at", "updated_at", "deleted_at", "password_changed_at")


class _BackupCancelled(Exception):
    """内部哨兵异常：cancel_check 触发时中止采集，编排层捕获后返回 None。

    用异常而非返回值传递「取消」，使采集子方法保持单一返回类型（tuple）。
    """


def check_payload_limit(estimated_size: int) -> None:
    """估算的 payload 字节数超限时抛 PayloadTooLargeError，供采集路径复用。"""
    if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
        raise PayloadTooLargeError("备份数据过大")


def decrypt_entry_to_portable_dict(
    raw_entry: RawEntry,
    key: bytes | bytearray,
    *,
    include_secrets: bool = True,
) -> dict[str, Any]:
    """将原始 Entry 解密为明文字典，任一字段损坏抛异常。供备份/导出等整条解密场景。

    自 crypto_utils 迁入（MAINT-097）：本函数是备份可移植数据采集的专用原语
    （唯一生产消费方即本模块 collect_portable_data），归位消费域。

    字符串型加密字段经 :func:`crypto_utils.decrypt_string_fields_strict` 统一解密
    （QL-018 单一事实源），本函数仅组装 portable dict 并单独处理 custom_fields 的
    JSON 反序列化。

    Args:
        raw_entry: 数据库层原始 Entry，加密字段为密文字符串。
        key: AES-256 密钥。
        include_secrets: 是否包含密码和 TOTP 密钥等敏感字段。

    Raises:
        DecryptionError: 元数据完整性失败，或任一加密字段解密失败。
        json.JSONDecodeError: 自定义字段密文解密成功但 JSON 结构损坏。
    """
    if raw_entry.integrity_error:
        raise DecryptionError(f"条目 {raw_entry.crypto_id} 元数据完整性校验失败")
    # 全部加密字段统一 strict=True：任一字段损坏即抛 DecryptionError。实际触发极少，
    # 因 metadata_mac 已绑定全部加密字段密文（title/url/tags 直接入签，余者经 _enc_hash），
    # 损坏会先触发完整性失败。
    fields = decrypt_string_fields_strict(raw_entry, key, include_secrets=include_secrets)
    custom_json = decrypt_field(
        raw_entry.custom_fields_db_value,
        key,
        raw_entry.crypto_id,
        "custom_fields",
        strict=True,
    )
    custom_fields = json.loads(custom_json) if custom_json else []
    return {
        "id": raw_entry.id,
        "crypto_id": raw_entry.crypto_id,
        **fields,
        "custom_fields": custom_fields,
        "category_id": raw_entry.category_id,
        "password_strength": raw_entry.password_strength,
        "entry_type": raw_entry.entry_type,
        "is_favorite": raw_entry.is_favorite,
        "is_deleted": raw_entry.is_deleted,
        "created_at": raw_entry.created_at,
        "updated_at": raw_entry.updated_at,
        "deleted_at": raw_entry.deleted_at,
        "password_changed_at": raw_entry.password_changed_at,
    }


def _escape_inflation(value: str) -> int:
    """统计 value 中会被 JSON 转义成两字符的常见字符数（" \\ \\n \\t \\r）。

    PERF-068：明文估算须覆盖 JSON 转义膨胀（每个引号/反斜杠/控制符在序列化后
    占 2 字节）；罕见控制字符（\\u00XX 形态）不计，残余误差由 finalize 落盘前的
    ``len(payload) > MAX_BACKUP_PAYLOAD_SIZE`` 硬校验兜底。
    """
    return (
        value.count('"')
        + value.count("\\")
        + value.count("\n")
        + value.count("\t")
        + value.count("\r")
    )


def estimate_entry_payload_bytes(item: dict[str, Any]) -> int:
    """按已解密明文估算单条 portable entry 的 JSON 序列化字节数（PERF-068）。

    旧估算按密文长度累加（空串密文恒 44 字符 × 8 字段），对空字段系统性虚高，
    50k 全空库估算 43MB（实际 ~17MB），在旧 32MB 上限下数学上不可能备份通过。
    改用解密后的 portable_item 明文长度 + 按 ``json.dumps`` 实际输出校准的模板
    开销（payload.py 单一事实源），典型画像误差 ≤10%（校准测试守护）。
    ``item`` 键集由 decrypt_entry_to_portable_dict 保证。
    """
    estimated = ENTRY_OVERHEAD_BYTES
    # 模板以 id=0 单字符占位，实际 id 位数差补齐。
    estimated += len(str(item["id"])) - 1
    for field in STRING_ENCRYPTED_FIELDS:
        value = item[field]
        estimated += len(value.encode("utf-8")) + _escape_inflation(value)
    # 模板以空串占位的其余变长字段（crypto_id/entry_type/时间戳）：非空时的字节数
    # 补齐（模板已含各自引号与键名结构）。
    estimated += len(item["crypto_id"].encode("utf-8"))
    estimated += len(item["entry_type"].encode("utf-8"))
    for timestamp_field in _ENTRY_TIMESTAMP_FIELDS:
        estimated += len(item[timestamp_field].encode("utf-8"))
    fields = item["custom_fields"]
    if fields:
        estimated += CUSTOM_FIELD_OVERHEAD_BYTES * len(fields)
        for custom in fields:
            estimated += (
                len(custom["name"].encode("utf-8"))
                + len(custom["value"].encode("utf-8"))
                + _escape_inflation(custom["name"])
                + _escape_inflation(custom["value"])
            )
    return estimated


def collect_portable_data(
    key: bytes,
    cancel_check: Callable[[], bool] | None,
    raw_entries: list[RawEntry],
    history_rows: list[PasswordHistory],
    categories: list[dict[str, Any]],
    entries_progress: Callable[[int, int], None] | None = None,
    history_progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any] | None:
    """收集备份数据：解密所有字段为明文，构建可移植字典。

    备份锁外解密：本函数在 ``finalize_backup`` 锁外调用，``raw_entries``/``history_rows``/
    ``categories`` 须由 prepare_backup_locked 锁内预读传入（必传，已移除原 None 锁外
    自读 DB 回退以避免与并发写竞态读到部分提交状态——MAINT-015 必传化原则的同款
    应用）。返回嵌套项值类型混合，故标注
    ``dict[str, Any]``（结构由 validate_restore_data 校验）。
    ``entries_progress``（PERF-083，恢复点创建路径专用）：按已解密条目数上报原始
    ``(done, total)`` 计数，加权映射由调用方完成；``history_progress``（PERF-089）
    覆盖其后的历史解密段（此前整段无上报，进度在条目终值后冻结至序列化）。正式
    备份路径均不传（全程无进度 UI）。
    """
    # 基于明文长度的增量估算（PERF-068）：避免逐条 json.dumps 双重序列化开销，
    # 顶层结构开销常量一次性计入。
    estimated_size = PAYLOAD_TOP_OVERHEAD_BYTES + sum(
        len(c.get("name", "").encode("utf-8")) + CATEGORY_OVERHEAD_BYTES for c in categories
    )
    try:
        entries, entry_count, estimated_size = collect_portable_entries(
            key,
            cancel_check,
            estimated_size,
            raw_entries,
            entries_progress,
        )
        history = collect_portable_history(
            key,
            cancel_check,
            entry_count,
            estimated_size,
            history_rows,
            history_progress,
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
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    """采集并解密全部条目为可移植字典，增量估算 payload 大小。

    返回 ``(entries, entry_count, estimated_size)``（元素含义同参数名）。条目完整性失败
    抛 :class:`BackupError`；``raw_entries`` 锁内预读后必传（见模块头「备份锁外解密
    契约」），解密循环锁外运行。``progress`` 按已解密条目数每 ``PROGRESS_REPORT_EVERY``
    条节流上报、终值恒上报（PERF-083）。
    """
    if len(raw_entries) > MAX_BACKUP_ENTRIES:
        raise PayloadTooLargeError("备份条目数量超出限制")
    total = len(raw_entries)
    entries: list[dict[str, Any]] = []
    for done, raw in enumerate(raw_entries, start=1):
        if cancel_check and cancel_check():
            raise _BackupCancelled
        try:
            portable_item = decrypt_entry_to_portable_dict(raw, key, include_secrets=True)
        except (DecryptionError, json.JSONDecodeError) as exc:
            # 解密失败（完整性/解密/JSON 损坏）转 BackupError 中止，备份不容忍残缺条目。
            raise BackupError(f"条目 {raw.id} 完整性校验或解密失败，备份已中止") from exc
        # 以已解密明文长度估算（PERF-068）：与最终 json.dumps 的实际序列化内容一致，
        # 模板开销经 payload.py 校准；大字段的超限在序列化前即被拦截，残余转义
        # 膨胀误差由 finalize 落盘前的硬校验兜底。
        estimated_size += estimate_entry_payload_bytes(portable_item)
        check_payload_limit(estimated_size)
        entries.append(portable_item)
        if progress is not None and should_report_progress(done, total):
            progress(done, total)
    return entries, total, estimated_size


def collect_portable_history(
    key: bytes,
    cancel_check: Callable[[], bool] | None,
    entry_count: int,
    estimated_size: int,
    history_rows: list[PasswordHistory],
    progress: Callable[[int, int], None] | None = None,
) -> list[dict[str, Any]]:
    """采集并解密密码历史，返回历史记录列表。

    ``estimated_size`` 入参参与 payload 上限校验，累计值不再返回（无调用方使用，QL-010）；
    ``entry_count`` 用于历史上限校验。``history_rows`` 锁内预读后必传（见模块头
    「备份锁外解密契约」），解密循环锁外运行。``progress``（PERF-089）按已解密历史
    条数每 ``PROGRESS_REPORT_EVERY`` 条节流上报原始 ``(done, total)`` 计数、终值恒
    上报，加权映射由调用方完成。
    """
    if len(history_rows) > entry_count * MAX_HISTORY_PER_ENTRY:
        raise PayloadTooLargeError("密码历史数量超出限制")
    history: list[dict[str, Any]] = []
    total = len(history_rows)
    for done, history_row in enumerate(history_rows, start=1):
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
        # 明文长度估算（PERF-068，与条目路径一致）：旧版按密文长度（空密码也恒
        # 44 字符）虚高；模板开销已含 entry_id=0 占位，位数差补齐。
        estimated_size += (
            HISTORY_OVERHEAD_BYTES
            + len(str(history_row.entry_id))
            - 1
            + len(pwd.encode("utf-8"))
            + _escape_inflation(pwd)
            + len(history_row.changed_at.encode("utf-8"))
        )
        check_payload_limit(estimated_size)
        if progress is not None and should_report_progress(done, total):
            progress(done, total)
    return history
