"""导入批量写入的加密与落库编排（无状态纯函数）。

从 EntryManager 下沉的导入专用批量写入路径：新条目批量加密/写入、覆盖条目批量
预处理（验证+加密）/写入。仅服务 ImportExportManager，经 ``entry_mgr`` 参数注入
EntryManager 的加密/落库原语（``build_encrypted_entry`` 等公开协作 API），
使 EntryManager 聚焦单条 CRUD 与视图解密。

两阶段（MAINT-004）：CPU 密集的加密移出 db_lock（调用方先取 pre_epoch 快照→锁外
加密→epoch 守卫事务内裸写入），pre_epoch 守卫保证「加密后→写入前」改密则复查失败回滚。
"""

import uuid
from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING, NamedTuple, TypeVar

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
    # 对 EntryManager 维持 TYPE_CHECKING 具体类（ARCH-039 显式决策）：本模块对其
    # 依赖面 8 成员横跨加密原语/db/totp/epoch（build_encrypted_entry/
    # db.add_entries_batch/totp.evict/prepare_password_update/resolve_password_
    # changed_at/key_epoch/db.update_overwrite_batch/db.add_password_history_batch），
    # 协议化只会产出 EntryManager 的「影子类」——核心编排 API 抄一遍再让唯一实现
    # 满足，无测试替身或第二实现的净收益。
    from ..managers.entry_manager import EntryManager

# 进度上报节流间隔（PERF-065）：每 100 行上报一次，避免 50k 行导入产生 50k 次跨
# 线程信号发射（UI 侧 repaint 开销反超加密本身）；阶段终值恒上报，保证进度能到达
# 阶段终点。公开常量供 import_export 的 classify 阶段复用同一节流纪律（PERF-069）。
PROGRESS_REPORT_EVERY = 100

# 写入分块大小（PERF-065）：progress 提供时按此分块调用 add_entries_batch，供写入
# 阶段上报中间进度。分块间仍处调用方 epoch_guarded_transaction 内（_auto_commit 在
# 活动事务内为 no-op），全有或全无语义不变。PERF-089 随 backup/rebuilder 复用去掉
# 下划线前缀成为公开常量（跨模块消费的分块阈值不再是本模块私有细节）。
WRITE_PROGRESS_CHUNK = 500


def should_report_progress(done: int, total: int) -> bool:
    """进度上报节流谓词（单一事实源，MAINT-099）：每 ``PROGRESS_REPORT_EVERY`` 条一次、终值恒上报。

    ``done % PROGRESS_REPORT_EVERY == 0 or done == total`` 此前在加密/覆盖预处理/
    分类/解密/导出/备份采集/恢复重建等 10 处手抄——任一处漂移（漏终值、误改间隔）
    即该阶段进度冻结或过密。消费方统一改调本谓词。
    """
    return done % PROGRESS_REPORT_EVERY == 0 or done == total


def phase_progress(done: int, total: int, start: int, end: int) -> int:
    """把阶段内进度 ``(done/total)`` 线性映射到 ``[start, end]`` 的加权总进度值（MAINT-099）。

    ``total <= 0``（空阶段）与 ``done >= total``（阶段终值）均返回 ``end``，保持
    进度单调不减、空阶段不留悬挂；``done <= 0`` 钳制到 ``start``（防调用方传入
    非单调的越界值使映射越过阶段下界）。整数下取整使连续上报值单调不降。

    import_export（PERF-065/069/070）与 backup_restore（PERF-083）的加权刻度
    此前各持一份字节级相同的实现，收敛至本模块——它已是进度契约的家
    （``PROGRESS_REPORT_EVERY`` 的单一事实源）。
    """
    if total <= 0 or done >= total:
        return end
    if done <= 0:
        return start
    return start + (end - start) * done // total


_RowT = TypeVar("_RowT")
_ResultT = TypeVar("_ResultT")


def write_chunks(
    rows: list[_RowT],
    write_fn: Callable[[list[_RowT]], _ResultT],
    *,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[_ResultT]:
    """按 ``WRITE_PROGRESS_CHUNK`` 分块写入并逐块上报，返回各块的写入结果列表（MAINT-106）。

    write_new_entries / write_overwrite_updates / backup rebuilder.restore_entries
    三处逐字节相同的分块循环（仅 ``write_fn`` 与结果合并策略不同，后者由调用方
    对返回的各块结果自行合并）收敛为单一原语：``on_progress`` 提供时按块调用
    ``write_fn`` 并上报 ``(done, total)``；未提供时整批单次调用（既有调用方的
    原路径，不引入无进度场景的多余分块）。分块间仍处调用方事务/epoch 守卫内，
    全有或全无语义不变；``WRITE_PROGRESS_CHUNK`` 调用时从模块属性解析，保持
    测试 monkeypatch 该常量的可达性。
    """
    if on_progress is None:
        return [write_fn(rows)]
    total = len(rows)
    done = 0
    results: list[_ResultT] = []
    for start in range(0, total, WRITE_PROGRESS_CHUNK):
        chunk = rows[start : start + WRITE_PROGRESS_CHUNK]
        results.append(write_fn(chunk))
        done += len(chunk)
        on_progress(done, total)
    return results


class BatchUpdateItem(NamedTuple):
    """批量覆盖更新项（导入覆盖路径）：合并后条目、待覆盖条目密文 raw。

    old_password 为 None 表示未预解密，由 :func:`prepare_overwrite_updates` 在
    prepared 阶段逐条解密（PERF-006：不批量预解密致全部旧密码同刻驻留）；解密后经
    EntryManager.prepare_password_update 比对即 del，收敛明文驻留面。
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
    entry_mgr: "EntryManager",
    entries: list[Entry],
    *,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[RawEntry], bool]:
    """锁外加密构建新条目密文（MAINT-004），返回 ``(enc_entries, preserve_metadata)``。

    CPU 密集的加密循环移出 db_lock：调用方先取 ``pre_epoch`` 快照，调本函数加密，
    再于 ``epoch_guarded_transaction(pre_epoch=...)`` 内调 :func:`write_new_entries`
    裸写入。加密仅依赖 vault key（不触 db_lock），故可锁外；pre_epoch 守卫保证
    「加密后→写入前」若改密则复查失败回滚，旧密钥密文不落库。
    ``entries`` 须已由 ``Entry.from_dict`` 校验。

    ``progress``（PERF-065）：提供时按 ``(done, total)`` 上报加密进度，每
    ``PROGRESS_REPORT_EVERY`` 行节流一次、终值恒上报——加密逐字段是密码学契约，
    循环结构不变，仅插入上报点。
    """
    now = utc_now_iso()
    enc_entries: list[RawEntry] = []
    total = len(entries)
    for idx, entry in enumerate(entries, start=1):
        entry = replace(
            entry,
            password_strength=PasswordGenerator.check_strength(entry.password).score,
        )
        crypto_id = entry.crypto_id or uuid.uuid4().hex
        enc_entries.append(
            entry_mgr.build_encrypted_entry(
                entry,
                crypto_id,
                now,
                created_at=entry.created_at or now,
                updated_at=entry.updated_at or now,
            )
        )
        if progress is not None and should_report_progress(idx, total):
            progress(idx, total)
    preserve = any(e.created_at or e.updated_at for e in entries)
    return enc_entries, preserve


def write_new_entries(
    entry_mgr: "EntryManager",
    enc_entries: list[RawEntry],
    *,
    preserve: bool,
    progress: Callable[[int, int], None] | None = None,
) -> None:
    """事务内裸写入已加密条目（MAINT-004），executemany 批量 INSERT。

    写入须受 epoch 守卫保护：导入路径在 ``epoch_guarded_transaction`` 内调用；
    不含加密，仅 db 写，把 db_lock 持有收敛到 executemany 时长。不做任何通知——
    通知（含摘要缓存保留语义）由调用方 ImportExportManager 在全部写入完成后经
    ``notify_batch_change`` 统一发一次（PERF-022 移除已成死分支的 notify 参数：
    唯一生产调用方始终传 notify=False，逐条/空批次通知路径不再存在）。

    ``progress``（PERF-065）：提供时按 ``WRITE_PROGRESS_CHUNK`` 分块写入并逐块
    上报 ``(done, total)``，消除写入阶段（50k 库实测 2.85s）进度条冻结；分块间
    仍处调用方 epoch 守卫事务内，原子性与持久化语义不变。未提供时保持单次
    executemany 原路径（既有调用方零改动）。分块循环经 :func:`write_chunks`
    共享原语（MAINT-106，与覆盖写入/恢复重建共用同一份）。
    """
    if not enc_entries:
        return
    write_chunks(
        enc_entries,
        lambda chunk: entry_mgr.db.add_entries_batch(chunk, preserve_metadata=preserve),
        on_progress=progress,
    )


def prepare_overwrite_updates(
    entry_mgr: "EntryManager",
    items: list[BatchUpdateItem],
    *,
    preserve_password_changed_at: bool = True,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[PreparedUpdate], list[tuple[int, Exception]]]:
    """锁外验证+加密覆盖项（MAINT-004），返回 ``(prepared, failures)``。

    验证/解密/加密预处理移出 db_lock：调用方先取 ``pre_epoch`` 快照，调本函数预处理，
    再于 ``epoch_guarded_transaction(pre_epoch=...)`` 内调 :func:`write_overwrite_updates`。

    failures 仅收集验证/解密阶段的 EntryError / EntryIntegrityError / DecryptionError
    （数据问题，逐条跳过），元素为 ``(items 的 0 基索引, 异常)``（QL-062：消费方以其
    直接索引同序构建的覆盖计划列表）；写阶段错误由 :func:`write_overwrite_updates`
    向上传播中止。pop_totp 在此阶段（加密前）失效缓存。

    ``progress``（PERF-069）：提供时按已处理条目数（含失败项）上报 ``(done, total)``，
    每 ``PROGRESS_REPORT_EVERY`` 条节流、终值恒上报——纯覆盖导入（duplicate_action=
    overwrite 全命中）此前全程冻结在 15%，重导全量覆盖是典型场景，加密预处理是
    其耗时主导，须有可见进度。
    """
    failures: list[tuple[int, Exception]] = []
    now = utc_now_iso()
    prepared: list[PreparedUpdate] = []
    total = len(items)
    # 失败项索引 0 基对齐 items（QL-062）：消费方按其直接索引同序构建的覆盖计划列表，
    # 1 基索引在末项失败时越界（IndexError 中止整次导入）、非末项失败时报告错误的条目。
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
            entry_mgr.totp.evict(entry.id)
            new_pwd_enc, password_changed = entry_mgr.prepare_password_update(
                entry,
                raw,
                old_password,
            )
            password_changed_at = entry_mgr.resolve_password_changed_at(
                entry,
                raw,
                password_changed,
                preserve_password_changed_at,
            )
            entry = replace(
                entry,
                password_strength=PasswordGenerator.check_strength(entry.password).score,
            )
            enc_entry = entry_mgr.build_encrypted_entry(
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
        # 进度按「已处理条目数」1 基计数（done），与失败索引的 0 基语义解耦（QL-062）。
        done = idx + 1
        if progress is not None and should_report_progress(done, total):
            progress(done, total)
    return prepared, failures


def write_overwrite_updates(
    entry_mgr: "EntryManager",
    prepared: list[PreparedUpdate],
    pre_epoch: str | None,
    progress: Callable[[int, int], None] | None = None,
) -> int:
    """锁内批量写入已加密覆盖项（PERF-004 同族：executemany 批量写入替代逐条
    SAVEPOINT；MAINT-004）。

    须在 ``epoch_guarded_transaction(pre_epoch=...)`` 内调用。复查 ``pre_epoch`` 一次
    （db_lock 已串行化改密，批量写期间无并发改密），随后批量 UPDATE 条目 + 按条目分组
    批量写密码历史（每组一次 INSERT + 单次截断）。

    单事务全有或全无：任一写入失败由外层 ``epoch_guarded_transaction`` 统一回滚，避免
    逐条 SAVEPOINT 提交留下的部分成功不一致状态（导入可整体重试）。``pre_epoch`` 由
    调用方在锁外加密前快照并传入——纵深防御「写入期间改密」，不匹配则中止导入。

    ``progress``（PERF-069）：提供时按 ``WRITE_PROGRESS_CHUNK`` 分块调用
    update_overwrite_batch 并逐块上报 ``(done, total)``（与 write_new_entries 同款，
    分块仍处调用方事务内，原子性不变，循环体经 :func:`write_chunks` 共享——
    MAINT-106）；密码历史分组写入计入终值。
    """
    if not prepared:
        return 0
    if entry_mgr.key_epoch != pre_epoch:
        raise VaultKeyEpochMismatchError(
            "更新期间检测到密钥变更（改密/锁定），已中止以防写入旧密钥密文"
        )
    write_chunks(
        prepared,
        lambda chunk: entry_mgr.db.update_overwrite_batch([item.enc_entry for item in chunk]),
        on_progress=progress,
    )
    # 批量密码历史：按 entry_id 分组，每组一次 add_password_history_batch（INSERT + 单次
    # 截断），changed_at 用与条目一致的 password_changed_at 避免微秒级时序倒置。
    history_by_entry: dict[int, list[tuple[str, str]]] = {}
    for item in prepared:
        if item.raw.password and item.password_changed and item.enc_entry.id is not None:
            history_by_entry.setdefault(item.enc_entry.id, []).append(
                (item.raw.password, item.password_changed_at)
            )
    for entry_id, items in history_by_entry.items():
        entry_mgr.db.add_password_history_batch(entry_id, items)
    return len(prepared)


__all__ = [
    "BatchUpdateItem",
    "PreparedUpdate",
    "PROGRESS_REPORT_EVERY",
    "WRITE_PROGRESS_CHUNK",
    "encrypt_new_entries",
    "phase_progress",
    "prepare_overwrite_updates",
    "should_report_progress",
    "write_chunks",
    "write_new_entries",
    "write_overwrite_updates",
]
