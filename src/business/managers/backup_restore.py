"""CipherBox 固定格式的加密备份与恢复。

模块拆分后仅承载备份创建/恢复的核心编排逻辑：
- 头部编解码、检视、密钥派生 → :mod:`..services.backup.header_codec`
- 恢复前数据校验 → :mod:`..services.backup.validator`
- 命名常量 → :mod:`..services.backup.paths`
- 恢复点统计/清理 → :class:`.restore_point_manager.RestorePointManager`
"""

import json
import logging
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, NamedTuple, cast

if TYPE_CHECKING:
    from .entry_manager import EntryManager
    from .vault_manager import VaultManager

from ...config import (
    CFG_AUTO_BACKUP_ENABLED,
    CFG_AUTO_BACKUP_RETENTION,
    CFG_BACKUP_DIRECTORY,
    CFG_LAST_AUTO_BACKUP_AT,
    DEFAULT_CONFIG,
)
from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import DEFAULT_KDF_PARAMS, KEY_SIZE, KdfParams, MasterKeyManager
from ...database.types import EntryQuery
from ...exceptions import (
    BackupError,
    DecryptionError,
    PayloadTooLargeError,
    RestoreAbortedError,
)
from ...utils.file_security import (
    atomic_write,
    secure_directory,
    validate_file_path,
)
from ...utils.format import utc_now_iso
from ...utils.memory import secure_zero_buffer
from ..services.backup.auto_backup_policy import (
    is_auto_backup_due,
    purge_expired_auto_backups,
)
from ..services.backup.collector import collect_portable_data
from ..services.backup.header_codec import (
    BACKUP_SALT_SIZE,
    MAX_BACKUP_FILE_SIZE,
    MAX_BACKUP_PAYLOAD_SIZE,
    BackupFlag,
    derive_backup_key,
    enforce_kdf_ceiling,
    enforce_kdf_floor,
    header_aad,
    inspect_backup as _inspect_backup,
    read_backup_header,
    write_backup_header,
    zero_backup_key_if_owned,
)
from ..services.backup.paths import (
    BACKUP_EXT,
    BACKUPS_DIR_NAME,
    SNAPSHOT_PREFIX,
    build_backup_filename,
)
from ..services.backup.payload import PortableBackup, PreparedBackup
from ..services.backup.purge import purge_snapshot_backups
from ..services.backup.rebuilder import (
    restore_categories,
    restore_entries,
    restore_history,
)
from ..services.backup.validator import (
    MAX_BACKUP_ENTRIES,
    validate_restore_data,
)
from ..services.crypto_utils import require_vault_key
from ..services.entry_batch_writer import phase_progress
from ..services.error_messages import to_user_message
from ..services.metadata_signer import VAULT_META_SIGNED_KEYS, MetadataSigner
from ..services.password_service import PasswordService
from .restore_point_manager import RestorePointManager

logger = logging.getLogger(__name__)

# ======== 恢复加权总进度刻度（PERF-083，子段细化 PERF-089，段表收敛 MAINT-107）========
# 50k 库恢复实测 15-25s 全程模态无反馈，比照导入（PERF-065）/导出（PERF-070）的加权
# 刻度方法：按各阶段耗时画像映射到 [0,100]。两段 CPU 主导大头是「恢复点创建」（恢复
# 前全量库的逐条解密 collect_portable_data + 整体重加密落盘）与「逐表重建」
# （restore_entries 逐条多字段加密 + 批量写库），两者工作量对称于同一份条目集；重建
# 中条目（每条约 8 个加密字段）远重于密码历史（每条 1 个），区间按 35:15 分配；
# 头部+KDF 派生+解密为固定成本（Argon2id t3/m64MiB + GCM 解密 ~1-2s），收尾
# （WAL 截断 + 旧快照 purge）为快速 IO 段，合并占首尾 5+5。
# PERF-089 子段细化（消除段内长无上报冻结窗口）：
# - 恢复点创建段 5→45 按同款「条目远重于历史」7:3 比例拆条目解密 5→33 / 历史解密
#   33→45（历史解密此前整段无上报）；
# - 重建条目段 45→80 拆加密 45→62 / 批量写入 62→80（写入单次 executemany 50k 实测
#   ~2.85s，加密逐字段 CPU 同量级，近似各半）；
# - 重建历史段 80→95 拆加密 80→90 / 分组批量写入 90→95（加密逐条单字段为主导，
#   写入按 entry 分组批量、组数远小于历史行数）。
# MAINT-107：六段的 base/span 常量对（跨段相邻性 45+17==62 等纯手工维护）收敛为
# 结构化段表 + 启动期相邻性校验 + 单一闭包工厂（见 _segment_progress_reporter）。
_RESTORE_PROGRESS_TOTAL = 100
# 头部解析 + PASSWORD Argon2id 派生 + GCM 解密 + 结构校验完成（粗粒度单点上报）。
_RESTORE_DECRYPT_DONE = 5


class _ProgressSegment(NamedTuple):
    """恢复加权进度的一个子段刻度（``base → base+span``，段表行）。"""

    base: int
    span: int


class _RestoreSegments(NamedTuple):
    """恢复全部子段刻度的具名视图（调用点按语义名取段，替代魔法索引）。"""

    point_entries: _ProgressSegment
    point_history: _ProgressSegment
    entries_encrypt: _ProgressSegment
    entries_write: _ProgressSegment
    history_encrypt: _ProgressSegment
    history_write: _ProgressSegment


# 段表（次序即刻度次序，语义见上方 PERF-089 说明）：恢复点创建两段（条目/历史解密）、
# 重建条目两段（加密/分块写入）、重建历史两段（加密/分组写入）；95→100 的事务后收尾
# 段（WAL 截断/purge）由 _restore_current 的终值上报直接补足，不在表内。
_RESTORE_SEG = _RestoreSegments(
    point_entries=_ProgressSegment(5, 28),
    point_history=_ProgressSegment(33, 12),
    entries_encrypt=_ProgressSegment(45, 17),
    entries_write=_ProgressSegment(62, 18),
    history_encrypt=_ProgressSegment(80, 10),
    history_write=_ProgressSegment(90, 5),
)


# 启动期校验（if+RuntimeError，-O 存活，对齐 strings.py ARCH-040 形式）：段表相邻
# 无缝隙/无重叠——首段起点承接解密完成里程碑、每段 base+span == 下一段 base。
# 45+17==62 等相邻性此前散在 6 组常量对手工维护、无任何校验，一处手改即静默
# 留缝隙（进度条卡在缝隙点）或重叠（进度回退）；尾段终点（95）须小于总刻度，
# 给收尾段留出区间。段表契约另有可读失败定位的测试守护
# （TestRestoreProgressSegmentTable）。
def _validate_restore_segments(
    segments: _RestoreSegments,
    start: int,
    total: int,
) -> None:
    """校验段表相邻性：首段起点承接 ``start``、逐段无缝衔接、尾段终点 < ``total``。"""
    cursor = start
    for seg in segments:
        if seg.base != cursor:
            raise RuntimeError(f"恢复进度段表相邻刻度出现缝隙/重叠：{seg.base} != {cursor}")
        cursor = seg.base + seg.span
    if cursor >= total:
        raise RuntimeError("恢复进度段表尾段越过总刻度，收尾段无区间可用")


_validate_restore_segments(_RESTORE_SEG, _RESTORE_DECRYPT_DONE, _RESTORE_PROGRESS_TOTAL)


def _weighted_progress(base: int, span: int, done: int, total: int) -> int:
    """把阶段内进度 ``(done/total)`` 映射为恢复加权总进度百分比。

    薄委托 :func:`entry_batch_writer.phase_progress`（MAINT-099 共享单一事实源，
    base/span 形态适配 start/end 形态）：与 import_export 的导入/导出刻度共用
    同一映射语义（``total <= 0`` 空阶段取满、终值取满、整数下取整单调不降）。
    """
    return phase_progress(done, total, base, base + span)


def _segment_progress_reporter(
    progress: Callable[[int, int], None] | None,
    segment: _ProgressSegment,
) -> Callable[[int, int], None]:
    """构造把阶段内 ``(done, total)`` 映射到 ``segment`` 加权刻度的上报闭包（MAINT-107）。

    恢复点两段与重建四段的进度闭包 ~66 行复制体（仅 base/span 不同）收敛为
    partial over base/span 的单一工厂（import_export._offset_phase_reporter 同型）；
    ``progress`` 为 None 时闭包内跳过上报，与收敛前各闭包首行的 ``if progress
    is not None`` 守卫逐点等价（无进度路径的下游回调形态不变）。
    """
    base, span = segment

    def _report(done: int, total: int) -> None:
        if progress is not None:
            progress(_weighted_progress(base, span, done, total), _RESTORE_PROGRESS_TOTAL)

    return _report


@dataclass
class _DecryptedPayload:
    """恢复载荷解密结果（成功路径），供 _restore_current 阶段方法间传递明文与解析数据。

    有意非 frozen（SEC-027）：:meth:`_rebuild_with_restore_point_locked` 在 finally 中
    置空字段本身以释放调用方仍持有的明文引用——仅 del 局部别名不足以回收。
    """

    plaintext: bytes
    data: dict[str, Any]


class BackupRestoreManager:
    """创建可移植的加密备份并以事务方式恢复。"""

    # 备份文件扩展名（供 UI 文件过滤器/默认名经 manager 取用，不穿透 backup/paths）。
    BACKUP_EXT: str = BACKUP_EXT

    def __init__(
        self,
        vault_manager: "VaultManager",
        entry_manager: "EntryManager",
        restore_point_mgr: RestorePointManager,
    ) -> None:
        self._vault = vault_manager
        # 复用调用方持有的 EntryManager 单例，共享分类名缓存，避免重复解密与双份明文驻留。
        self._entry_mgr = entry_manager
        # 恢复点子服务经组合根/测试工厂显式注入（一等依赖；MAINT-015 移除兜底内部
        # 构造——可选注入使遗漏装配在运行期才暴露且与组合根实例不一致）。
        self._restore_points = restore_point_mgr
        # ARCH-006：恢复点创建/统计/清理统一由 RestorePointManager 承载。备份加密管线
        # （持锁 _create_backup_locked 薄包装）由本类在调用 create 时作为 creator 参数显式
        # 传入；恢复点复用与正式备份同一加密格式。

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    @property
    def restore_points(self) -> RestorePointManager:
        """恢复点统计/清理管理器，供 UI 与清理路径访问。"""
        return self._restore_points

    @staticmethod
    def inspect_backup(filepath: str) -> dict[str, Any]:
        """读取备份头判定是否需要密码等，不解密内容。

        供 UI 恢复对话框探测备份属性，不直接依赖 backup/header_codec 内部模块。
        """
        return _inspect_backup(filepath)

    def create_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
        use_snapshot_key: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[bool, str]:
        """创建加密备份；密码备份可跨安装恢复，快照使用稳定快照密钥。

        ``cancel_check`` 在全量解密循环中周期调用，返回真值时中止备份。

        备份锁外解密（导入路径 MAINT-004「CPU 密集加密移出锁」的对称决策）：
        ``vault_write_lock`` 仅持有快速 prepare 阶段（DB 读 +
        snapshot_key/master_key 副本采集 + 数量校验），全量解密与 PASSWORD 密钥派生
        （Argon2id）推迟到锁外 :meth:`_finalize_backup`。主线程 ``lock()`` 经
        ``_shutdown_workers`` → ``cancel_check`` 中止备份后才取锁清零密钥（worker 全程
        join 后方清零），故 finalize 锁外解密期间主密钥不会被并发清零；snapshot_key 与
        master_key 均取 bytes 副本（property 返回拷贝），锁外使用不受 KeyManager 内部
        bytearray 清零影响。master_key 与 raw_entries 在同一持锁阶段采集，锁外改密
        （轮换主密钥 + 重加密 DB）不会令 finalize 用新密钥解密旧密文而失败。

        ``_create_backup_locked`` 保留为持锁全流程入口，供 :meth:`RestorePointManager.create`
        经 ``creator`` 参数在已持锁上下文复用（恢复点快照体积小，无需锁外 finalize 拆分）。
        """
        try:
            filepath = str(validate_file_path(filepath))
            # 备份密码是离线攻击（窃取 .cbox 后暴力破解）的唯一屏障，须与主密码
            # 同等强度。UI 已校验，业务层兜底防止绕过 UI（如未来 CLI/自动化入口）
            # 直接调用 create_backup 设置极弱备份密码。强度校验在锁前完成。
            if backup_password:
                valid, error = PasswordService.validate_master_password(
                    backup_password,
                    label="备份密码",
                )
                if not valid:
                    return False, error
            # 锁内仅做快速 prepare（DB 读 + snapshot_key 副本采集），全量解密与密钥
            # 派生推迟到锁外 finalize，缩短 vault_write_lock 持有时间，使主线程 lock()
            # 经 cancel_check 及时中止备份而非等待全量解密。
            with self._vault.vault_write_lock():
                prepared = self._prepare_backup_locked(
                    filepath,
                    backup_password,
                    use_snapshot_key,
                )
            return self._finalize_backup(prepared, cancel_check)
        except Exception as exc:
            logger.error("备份失败: %s", exc, exc_info=True)
            return False, to_user_message(exc, default="操作失败，请检查文件和磁盘。")

    def _create_backup_locked(
        self,
        filepath: str,
        backup_password: str | None,
        use_snapshot_key: bool,
        cancel_check: Callable[[], bool] | None,
        entries_progress: Callable[[int, int], None] | None = None,
        history_progress: Callable[[int, int], None] | None = None,
    ) -> tuple[bool, str]:
        """备份全流程；调用方须已持有 ``vault_write_lock``。

        持锁顺序执行 prepare + finalize，供 :class:`RestorePointManager.create` 经
        ``creator`` 参数在已持锁上下文复用以创建恢复点。亦为测试 monkeypatch 拦截恢复点
        创建的桩点（见 test_restore_point_cleaned_on_creation_exception）。
        ``entries_progress``/``history_progress``（PERF-083/089）仅恢复点创建路径传入
        （经 collector 按条目/历史上报）；正式备份路径无进度 UI，恒 None。
        """
        prepared = self._prepare_backup_locked(filepath, backup_password, use_snapshot_key)
        return self._finalize_backup(prepared, cancel_check, entries_progress, history_progress)

    def _prepare_backup_locked(
        self,
        filepath: str,
        backup_password: str | None,
        use_snapshot_key: bool,
    ) -> PreparedBackup:
        """锁内快速采集 finalize 所需全部输入；调用方须已持有 ``vault_write_lock``。

        仅完成需持锁串行的快速操作——生成 salt、读 raw_entries/history_rows/
        categories、数量上限校验、确定 flags、SNAPSHOT 路径取 snapshot_key 副本。
        PASSWORD 密钥派生（Argon2id）与全量解密推迟到锁外 :meth:`_finalize_backup`，
        缩短 ``lock()`` 经 cancel_check 中止前的阻塞窗口。

        snapshot_key 经 property 取 bytes 副本，锁外 finalize 持此副本加密，
        不受 KeyManager 内部 bytearray 清零影响。
        """
        salt = os.urandom(BACKUP_SALT_SIZE)
        raw_entries = self._vault.db.get_entries(EntryQuery(include_deleted=True))
        # 数量上限在锁内预判（快速失败，避免锁外 finalize 才抛错白白多持锁时间）；
        # _collect_portable_entries 收到预读 raw 时仍保留同名校验作防御性冗余。
        if len(raw_entries) > MAX_BACKUP_ENTRIES:
            raise PayloadTooLargeError("备份条目数量超出限制")
        history_rows = self._vault.db.get_all_password_history()
        categories = [
            category.to_dict() for category in self._entry_mgr.categories.get_categories()
        ]
        snapshot_key: bytes | None
        if backup_password:
            flags = BackupFlag.PASSWORD
            snapshot_key = None
        elif use_snapshot_key:
            flags = BackupFlag.SNAPSHOT
            snapshot_key = self._vault.snapshot_key
        else:
            raise BackupError("必须指定备份密码或使用快照密钥")
        return PreparedBackup(
            filepath=filepath,
            salt=salt,
            flags=flags,
            backup_password=backup_password,
            snapshot_key=snapshot_key,
            raw_entries=raw_entries,
            history_rows=history_rows,
            categories=categories,
            # 锁内快照主密钥：与 raw_entries 同源采集，锁外 finalize 用它解密，
            # 不受锁外改密（轮换主密钥 + 重加密 DB）竞态影响。
            master_key=self._key,
        )

    def _finalize_backup(
        self,
        prepared: PreparedBackup,
        cancel_check: Callable[[], bool] | None,
        entries_progress: Callable[[int, int], None] | None = None,
        history_progress: Callable[[int, int], None] | None = None,
    ) -> tuple[bool, str]:
        """锁外完成密钥派生、全量解密、加密与落盘（缩短 vault_write_lock 持有，
        锁内 prepare → 锁外 finalize 拆分，见 :meth:`create_backup` 的决策说明）。

        PASSWORD 路径在此派生 backup_key；SNAPSHOT 路径用 prepared 锁内取的 snapshot_key
        副本。``cancel_check`` 在解密循环中及时中止。AAD、header 写入、payload/数量上限
        校验与持锁全流程路径（:meth:`_create_backup_locked`）一致，备份格式不变。backup_key
        的清零在 finally 完成，PASSWORD 路径派生密钥在所有退出路径均被清零；SNAPSHOT 路径
        借用 snapshot_key 不清零。``entries_progress``/``history_progress``
        （PERF-083/089）透传 collector 的条目/历史解密上报，正式备份路径恒 None。
        """
        t0 = time.monotonic()
        backup_key: bytes | bytearray
        if prepared.flags == BackupFlag.PASSWORD:
            password = prepared.backup_password
            # prepare 已保证 PASSWORD 路径 backup_password 非 None；此处显式检查替代
            # assert（python -O 下 assert 跳过），满足类型 narrow 与意外状态防御。
            if password is None:
                raise BackupError("备份密码不可用")
            backup_key = derive_backup_key(password, prepared.salt)
        else:
            snapshot_key = prepared.snapshot_key
            # prepare 已保证 SNAPSHOT 路径 snapshot_key 非 None；显式检查替代 assert
            # （python -O 跳过），满足类型 narrow 与意外状态防御（对称 PASSWORD 分支）。
            if snapshot_key is None:
                raise BackupError("快照密钥不可用")
            backup_key = snapshot_key
        try:
            data = collect_portable_data(
                prepared.master_key,
                cancel_check=cancel_check,
                raw_entries=prepared.raw_entries,
                history_rows=prepared.history_rows,
                categories=prepared.categories,
                entries_progress=entries_progress,
                history_progress=history_progress,
            )
            if data is None:
                return False, "备份已取消"
            payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
            del data
            if len(payload) > MAX_BACKUP_PAYLOAD_SIZE:
                raise PayloadTooLargeError("备份数据过大")
            encrypted = EncryptionEngine.encrypt_bytes(
                payload,
                backup_key,
                header_aad(prepared.flags, prepared.salt, DEFAULT_KDF_PARAMS),
                # 一次性备份密码派生密钥不入 cipher 缓存（SEC-046）：finally 清零 bytearray
                # 后 C 层密钥副本不再驻留至下次 lock，兑现「清零即收缩」的语义。
                cache_key=False,
            )
            del payload

            def _write_backup_file(file: IO[bytes]) -> bool:
                write_backup_header(
                    file,
                    prepared.flags,
                    prepared.salt,
                    DEFAULT_KDF_PARAMS,
                )
                file.write(encrypted)
                return True

            atomic_write(Path(prepared.filepath), _write_backup_file)
        finally:
            zero_backup_key_if_owned(prepared.flags, backup_key)
        logger.info("备份创建完成 (%.1fms)", (time.monotonic() - t0) * 1000)
        return True, ""

    def restore_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> tuple[bool, str]:
        """恢复备份；任何步骤失败都会回滚当前数据库。

        ``progress``（PERF-083，子段细化 PERF-089）按加权总进度上报 ``(current, 100)``，
        覆盖解密完成里程碑、恢复点创建（条目 5→33 / 历史 33→45）、逐表重建（条目加密
        45→62 / 条目写入 62→80 / 历史加密 80→90 / 历史写入 90→95）与终值 100；大库恢复
        实测 15-25s，此前全程模态无反馈。None 时不上报（调用方无进度 UI 的路径不变）。
        """
        try:
            t0 = time.monotonic()
            filepath = str(validate_file_path(filepath))
            if Path(filepath).stat().st_size > MAX_BACKUP_FILE_SIZE:
                return False, "备份文件过大"
            with open(filepath, "rb") as file:
                result = self._restore_current(file, backup_password, progress)
                if result[0]:
                    logger.info("备份恢复完成 (%.1fms)", (time.monotonic() - t0) * 1000)
                return result
        except Exception as exc:
            # 所有异常（validate_file_path 的 ValueError、BackupError、RestoreAbortedError、
            # OSError 等）统一经 to_user_message 翻译为用户友好消息，避免内部消息直接暴露。
            logger.error("恢复失败: %s", exc, exc_info=True)
            return False, to_user_message(exc, default="操作失败，请检查文件和磁盘。")

    def _restore_current(
        self,
        file: IO[bytes],
        backup_password: str | None,
        progress: Callable[[int, int], None] | None = None,
    ) -> tuple[bool, str]:
        """恢复备份当前实现：4 阶段编排（头部+密钥 → 解密校验 → 重建+恢复点 → 收尾）。

        各阶段拆为独立私有方法，本方法仅编排阶段顺序与贯穿全程的 try/finally（backup_key
        清零）。面向用户的中止（缺密码/未解锁/备份无效）统一由阶段方法抛
        :class:`RestoreAbortedError` 携带文案（ARCH-045），经外层 :meth:`restore_backup`
        的统一翻译兜底转为 ``(False, msg)``，调用方不再 isinstance 判别联合返回类型。
        事务边界（``epoch_guarded_transaction`` 在 :meth:`_restore_data` 内）、
        清零纪律（backup_key / new_snapshot_key / plaintext）、锁范围（``vault_write_lock``
        包裹解密到 WAL 截断）由各阶段方法与 try/finally 维护（MAINT-001）。
        """
        # 阶段 1：头部解析 + KDF 边界 + PASSWORD 密钥派生（锁外，缩短持锁与 UI 冻结）
        flags, salt, kdf_params = self._read_and_validate_header(file)
        backup_key: bytearray | bytes | None = self._derive_password_backup_key(
            flags,
            salt,
            kdf_params,
            backup_password,
        )
        # SNAPSHOT 路径此处为 None（密钥在锁内经 snapshot_key 解析）。
        checkpoint_ok = True
        try:
            # 持 vault 写锁串行化恢复与改密/备份：从解密全量明文到写库全程持锁。
            with self._vault.vault_write_lock():
                # SNAPSHOT 路径借用 snapshot_key，须在锁内读取（消除 is_unlocked 检查与
                # 读取间主线程 lock() 清零 snapshot_key 的竞态）。
                self._ensure_snapshot_key_locked(flags)
                if backup_key is None:
                    backup_key = self._vault.snapshot_key
                # 显式检查替代 assert（python -O 下 assert 跳过），满足类型 narrow 需求。
                if backup_key is None:
                    raise RuntimeError("备份密钥未初始化")
                # 阶段 2：TOCTOU 复核 + 解密 + 结构校验（锁内）
                payload = self._decrypt_and_validate_payload_locked(
                    file,
                    flags,
                    salt,
                    kdf_params,
                    backup_key,
                )
                if progress is not None:
                    progress(_RESTORE_DECRYPT_DONE, _RESTORE_PROGRESS_TOTAL)
                # 阶段 3：创建恢复点 + epoch 守卫事务内重建数据（锁内）。
                # restore_point_skipped：恢复点创建因载荷超限被降级跳过（QL-047），
                # 恢复本身继续，无回退快照的降级经阶段 4b 拼装为可见警告。
                new_epoch, new_snapshot_key, restore_point_skipped = (
                    self._rebuild_with_restore_point_locked(payload, progress)
                )
                # 阶段 4a：同步内存状态 + WAL 截断（锁内）
                checkpoint_ok = self._finalize_restored_state_locked(
                    new_epoch,
                    new_snapshot_key,
                )
            # 阶段 4b：清理旧 snapshot_key 加密的快照与恢复点 + 拼装降级警告（锁外）。
            # 仅 unlink 文件，不读取 snapshot_key property，故无需持锁，减少锁持有时间。
            result = self._assemble_restore_result(checkpoint_ok, restore_point_skipped)
            if progress is not None:
                # 终值恒上报（PERF-083，对齐导入/导出契约）：进度条不留悬挂。
                progress(_RESTORE_PROGRESS_TOTAL, _RESTORE_PROGRESS_TOTAL)
            return result
        finally:
            # 确保 PASSWORD 派生的 backup_key 在所有退出路径（含密钥派生失败、文件
            # 过大、解密异常）都清零；SNAPSHOT 路径借用 snapshot_key 不清零。
            zero_backup_key_if_owned(flags, backup_key)

    def _read_and_validate_header(
        self,
        file: IO[bytes],
    ) -> tuple[BackupFlag, bytes, KdfParams]:
        """读取备份头并强制 KDF 参数在合法区间（防降级/飙升）。"""
        flags, salt, kdf_params = read_backup_header(file)
        # 防 KDF 参数降级/飙升：在派生密钥前拒绝被篡改的参数。floor 拒绝弱化降级；
        # ceiling 拒绝社会工程下构造的内存耗尽参数（合法备份恒用 DEFAULT_KDF_PARAMS），
        # 避免在持锁派生时 UI 长冻结或 OOM。
        enforce_kdf_floor(kdf_params)
        enforce_kdf_ceiling(kdf_params)
        return flags, salt, kdf_params

    def _derive_password_backup_key(
        self,
        flags: BackupFlag,
        salt: bytes,
        kdf_params: KdfParams,
        backup_password: str | None,
    ) -> bytearray | None:
        """锁外派生 PASSWORD 备份密钥（Argon2id 耗时，移出 vault_write_lock 缩短持锁）。

        SNAPSHOT 路径返回 None（密钥在锁内经 snapshot_key 解析）。PASSWORD 缺密码时
        抛 :class:`RestoreAbortedError` 早期中止（ARCH-045）。派生密钥为本地
        bytearray，不涉及 snapshot_key 竞态。
        """
        if flags != BackupFlag.PASSWORD:
            return None
        if not backup_password:
            raise RestoreAbortedError("请输入创建备份时设置的备份密码")
        return MasterKeyManager.derive_backup_key(backup_password, salt, kdf_params)

    def _ensure_snapshot_key_locked(self, flags: BackupFlag) -> None:
        """锁内校验 SNAPSHOT 恢复的前置条件（已解锁），PASSWORD 直接放行。

        SNAPSHOT 借用 snapshot_key，须在锁内读取以消除与主线程 lock() 清零的竞态；
        未解锁时抛 :class:`RestoreAbortedError`（ARCH-045）。
        """
        if flags == BackupFlag.PASSWORD:
            return
        if not self._vault.is_unlocked:
            raise RestoreAbortedError("恢复快照备份需要先解锁保险库")

    def _decrypt_and_validate_payload_locked(
        self,
        file: IO[bytes],
        flags: BackupFlag,
        salt: bytes,
        kdf_params: KdfParams,
        backup_key: bytearray | bytes,
    ) -> _DecryptedPayload:
        """锁内 TOCTOU 复核 + 解密 + 结构校验，失败抛 :class:`RestoreAbortedError`。

        TOCTOU 防护（备份文件替换窗口）：header 锁外读取后，锁内读 payload 前重读
        header 比对——检测文件在「锁外读 header → 锁内读 payload」窗口内被替换。
        GCM-AAD 只绑定单次 header+payload，整个合法备份替换需此额外校验拦截。
        """
        try:
            file.seek(0)
            if read_backup_header(file) != (flags, salt, kdf_params):
                raise RestoreAbortedError("备份文件在读取期间已变更，请重试")
            # 内存特征：峰值约 3 倍载荷大小。encrypted 不超过 80MB，plaintext 不超过 40MB
            # （PERF-068 上限联动），外加 JSON 解析树，桌面应用可接受。GCM 认证加密要求
            # 完整密文可用，无法流式解密。
            encrypted = file.read(MAX_BACKUP_FILE_SIZE + 1)
            if len(encrypted) > MAX_BACKUP_FILE_SIZE:
                raise RestoreAbortedError("备份文件过大")
            plaintext = EncryptionEngine.decrypt_bytes(
                encrypted,
                backup_key,
                header_aad(flags, salt, kdf_params),
                # 一次性备份密钥不入缓存（SEC-046，与加密侧对称）。
                cache_key=False,
            )
            if len(plaintext) > MAX_BACKUP_PAYLOAD_SIZE:
                raise RestoreAbortedError("备份解密数据过大")
            data = json.loads(plaintext.decode("utf-8"))
        except (OSError, DecryptionError, json.JSONDecodeError):
            # 缩窄为预期的「读文件 / GCM 解密 / JSON 解析」失败，统一提示密码错误或损坏；
            # 编程错误（KeyError/TypeError 等）不在此列，冒泡由上层 restore_backup 的 except
            # 经 to_user_message 兜底，避免把真实 bug 静默归为「备份损坏」而掩盖根因。
            logger.debug("备份读取或解密失败", exc_info=True)
            raise RestoreAbortedError("备份密码错误或文件已损坏") from None
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            raise RestoreAbortedError("备份数据结构无效")
        validate_restore_data(data)
        return _DecryptedPayload(plaintext=plaintext, data=data)

    def _rebuild_with_restore_point_locked(
        self,
        payload: _DecryptedPayload,
        progress: Callable[[int, int], None] | None = None,
    ) -> tuple[str, bytearray, bool]:
        """锁内创建恢复点并在 epoch 守卫事务内重建全部数据。

        事务由 :meth:`_restore_data` 的 ``epoch_guarded_transaction`` 提供；失败时**保留**
        恢复点（含恢复前明文）作安全网——事务回滚本身失败（磁盘满/IO 错误）时它是唯一
        干净全量副本，删除会致灾难性数据丢失。MAX_RESTORE_POINTS 上限覆盖反复尝试占盘。
        无论成败均释放明文引用（SEC-027）。恢复点创建经 :class:`RestorePointManager`
        单一事实源（ARCH-006）。

        恢复点超限降级（QL-047）：恢复点体积取决于**当前库**（恢复前全量明文），与待
        恢复备份无关——旧实现中恢复点创建抛 :class:`PayloadTooLargeError` 会阻断整个
        恢复（把小备份恢复进大库也被拦）。现仅对 PayloadTooLargeError 降级：跳过恢复
        点继续恢复（用户显式要求的操作优先于可选安全网），返回第三元素
        ``restore_point_skipped=True`` 供结果拼装"本次恢复无回退快照"警告；其余异常
        （磁盘满/IO）仍向上中止——那类失败同样可能影响恢复写入本身，不宜带病继续。
        理想的「恢复点改文件级快照（vault.db 加密整库复制）」不受明文载荷上限约束，
        属数据安全架构变更，未实施（MAINT-086：原「见恢复流程未尽事项」指向不存在的
        文档/章节，悬空追溯点删除；如需跟踪，登记 docs/audit_codes.md 新编号承载）。
        """
        plaintext = payload.plaintext
        data = payload.data
        restore_point_skipped = False
        try:
            # 创建恢复点（注册到 _restore_points 单一事实源，路径经其管理）；失败时保留
            # 作安全网（见 docstring），不在此删除。creator 显式传入持锁备份入口（snapshot_key
            # 加密恢复前明文），消除延迟绑定的可变状态。创建步骤亦纳入 try：其异常路径
            # 同样须触发 finally 的明文释放，兑现 docstring「无论成败」契约。
            try:
                # 恢复点创建进度映射到 5→45 区间（PERF-083/089 拆条目/历史两个子段，
                # 闭包工厂收敛 MAINT-107）：collector 上报的原始计数经
                # _segment_progress_reporter 加权；恢复点被超限降级跳过时该段直接
                # 跳到重建阶段，进度单调不减。
                self._restore_points.create(
                    lambda path: self._create_backup_locked(
                        path,
                        backup_password=None,
                        use_snapshot_key=True,
                        cancel_check=None,
                        entries_progress=_segment_progress_reporter(
                            progress, _RESTORE_SEG.point_entries
                        ),
                        history_progress=_segment_progress_reporter(
                            progress, _RESTORE_SEG.point_history
                        ),
                    )
                )
            except PayloadTooLargeError:
                # 恢复点载荷超限（当前库过大）：降级跳过而非阻断恢复（QL-047，
                # 见 docstring）。RestorePointManager.create 的异常路径已安全删除
                # 半成品文件，无明文残留。
                restore_point_skipped = True
                logger.warning(
                    "恢复点创建因备份数据过大被跳过，本次恢复无回退快照（QL-047）",
                    exc_info=True,
                )
            new_epoch, new_snapshot_key = self._restore_data(data, progress)
        finally:
            # 释放明文引用（SEC-027）：调用方 _restore_current 的 payload 引用存活至其
            # 方法返回，仅 del 局部别名时最多 40MB 的全量明文 JSON（含所有密码）仍被
            # dataclass 字段钉住，在 WAL 截断、旧快照 purge 等收尾期间持续驻留。先直接
            # 置空字段本身（_DecryptedPayload 有意非 frozen），再 del 局部别名，使恢复点
            # 创建与数据重建的任一退出路径都不残留明文引用。
            payload.plaintext = b""
            payload.data = {}
            del plaintext
            del data
        return new_epoch, new_snapshot_key, restore_point_skipped

    def _finalize_restored_state_locked(
        self,
        new_epoch: str,
        new_snapshot_key: bytearray,
    ) -> bool:
        """锁内同步内存状态（key_epoch + snapshot_key）并截断 WAL，返回 checkpoint 是否成功。

        事务已提交，key_epoch 与 snapshot_key_enc 均已在同一事务内原子写入。在释放 vault
        锁前同步内存状态（不写库），既消除事务外写库的崩溃窗口，也消除旧 snapshot_key 仍
        可被并发读取（snapshot_key property）的窗口。new_snapshot_key 在 apply 后原地清零。
        """
        try:
            if new_epoch:
                self._vault.update_key_epoch(new_epoch)
            self._vault.apply_snapshot_key(new_snapshot_key)
        finally:
            secure_zero_buffer(new_snapshot_key)
            # 恢复轮换 snapshot_key 后清 cipher 缓存（SEC-046，对称改密路径
            # vault_lifecycle 的显式 clear_cache）：旧 snapshot 密钥在加密恢复点/快照时
            # 进入缓存的 AESGCM 副本不再驻留至下次锁定，收缩崩溃 dump 攻击面。
            EncryptionEngine.clear_cache()
        # 事务提交后截断 WAL：clear_vault_data 删除的是被恢复数据替换的旧条目/分类/历史
        # 密文，由当前主密钥加密（恢复不轮换主密钥，与改密路径残留旧密钥不同），持当前
        # 主密钥与 WAL 文件者可恢复这些旧明文。须在事务外显式截断（事务内
        # secure_checkpoint 会跳过）；失败非致命（数据已提交完整），纳入返回警告让降级可见。
        try:
            self._vault.db.secure_checkpoint()
            return True
        except Exception:
            logger.warning("恢复后 WAL 安全截断失败", exc_info=True)
            return False

    def _assemble_restore_result(
        self,
        checkpoint_ok: bool,
        restore_point_skipped: bool = False,
    ) -> tuple[bool, str]:
        """锁外清理旧 snapshot_key 加密的快照与恢复点，拼装降级警告。"""
        failed_purges = purge_snapshot_backups(self._vault.config)
        warnings: list[str] = []
        if restore_point_skipped:
            # 恢复点超限降级的可见反馈（QL-047）：恢复成功但无回退快照，用户应
            # 知晓当前库在本次恢复前未留安全网，建议立即手动备份一次。
            warnings.append(
                "恢复完成，但恢复点创建失败（数据过大），本次恢复无回退快照；"
                "建议立即手动创建一次备份作为安全网。"
            )
        if not checkpoint_ok:
            warnings.append(
                "恢复完成，但 WAL 安全截断失败，被替换的旧数据（当前主密钥加密）"
                "可能残留于 WAL；建议重启应用以完成清理。"
            )
        if failed_purges:
            warnings.append(self._format_purge_warning(failed_purges))
        if warnings:
            return True, " ".join(warnings)
        return True, ""

    def _format_purge_warning(self, failed_purges: list[Path]) -> str:
        """格式化 purge 失败警告：区分含明文的恢复点（严重泄漏面）与普通旧快照。

        恢复点（``pre_restore_*``，含恢复前全部条目明文）未能删除是更严重的明文
        泄漏面，需显著警告并指引重启清理；普通旧快照笼统提示手动清理即可。
        """
        restore_point_failed = any(p.name.startswith("pre_restore_") for p in failed_purges)
        if restore_point_failed:
            return (
                f"恢复完成，但 {len(failed_purges)} 个含恢复前明文的快照"
                "未能删除（可能被占用）。为避免明文泄漏，请关闭可能占用"
                "该文件的程序后重启应用以自动清理。"
            )
        return (
            f"恢复完成，但 {len(failed_purges)} 个旧快照未能删除"
            "（可能被占用），建议在备份对话框手动清理以收缩泄漏面。"
        )

    def _restore_data(
        self,
        data: dict[str, Any],
        progress: Callable[[int, int], None] | None = None,
    ) -> tuple[str, bytearray]:
        """在 epoch 守卫事务内用当前主密钥重建全部数据并轮换 key_epoch 与 snapshot_key。

        恢复不改主密码，故用 ``self._key`` 重新加密备份载荷。事务内清空库后重建
        分类/条目/密码历史，同事务写入新的 key_epoch 与 snapshot_key_enc（消除事务外
        崩溃的不一致窗口），并据新 epoch 重算 vault_meta_mac。
        ``progress``（PERF-083，子段细化 PERF-089）逐表重建映射到 45→95：条目段
        45→80（加密 45→62 每条约 8 个加密字段、批量写入 62→80 单次 executemany 50k
        实测 ~2.85s）、密码历史段 80→95（加密 80→90、分组批量写入 90→95）；分类表
        数量级小不细分。

        返回 ``(new_epoch, new_snapshot_key)``：调用方在事务提交后、释放锁前经
        :meth:`update_key_epoch` 与 :meth:`apply_snapshot_key` 同步内存状态。
        ``new_snapshot_key`` 为 bytearray 便于失败时原地清零。
        """
        db = self._vault.db
        key = self._key
        # validate_restore_data 已校验载荷结构，cast 为 PortableBackup 使后续 _restore_*
        # 经 TypedDict 直接索引（键集由 require_keys 精确匹配保证），消除 dict[str, Any]
        # 下 .get(default) 的死分支与字段拼写静默。
        backup = cast(PortableBackup, data)
        # snapshot_key 与 key_epoch 在同一事务内轮换：恢复整体替换数据后，旧 snapshot_key
        # 加密的快照含恢复前明文，轮换使其失效以收缩泄漏面，与改密路径语义一致。
        # 同事务写入消除事务外写库在崩溃时 epoch 已提交而
        # snapshot_key_enc 未写入的不一致窗口。
        # bytearray 持有以便原地清零：成功路径 return 交调用方，apply_snapshot_key
        # 总复制到 KeyManager 后由调用方清零自己的引用；失败路径在 finally 清零。
        new_snapshot_key = bytearray(os.urandom(KEY_SIZE))
        new_epoch = ""
        success = False
        try:
            with self._vault.epoch_guarded_transaction(operation="恢复"):
                db.clear_vault_data()
                category_map = restore_categories(
                    # ARCH-002：注入批量写回调，解耦 backup/rebuilder 与 EntryManager。
                    lambda cats: self._entry_mgr.categories.add_categories_batch(
                        cats,
                        notify=False,
                    ),
                    backup,
                )
                # 四个重建子段的上报闭包经 _segment_progress_reporter 工厂构造
                # （MAINT-107，替代四份仅 base/span 不同的复制体）。
                entry_map, crypto_id_map = restore_entries(
                    db,
                    backup,
                    key,
                    category_map,
                    _segment_progress_reporter(progress, _RESTORE_SEG.entries_encrypt),
                    _segment_progress_reporter(progress, _RESTORE_SEG.entries_write),
                )
                restore_history(
                    db,
                    backup,
                    key,
                    entry_map,
                    crypto_id_map,
                    _segment_progress_reporter(progress, _RESTORE_SEG.history_encrypt),
                    _segment_progress_reporter(progress, _RESTORE_SEG.history_write),
                )
                # 轮换 key_epoch 防止旧会话写入恢复后的数据
                new_epoch = uuid.uuid4().hex
                db.set_meta("key_epoch", new_epoch)
                db.set_meta("snapshot_key_enc", self._vault.encrypt_snapshot_key(new_snapshot_key))
                # key_epoch 轮换后重算 vault_meta_mac（签名含 key_epoch），保持 unlock
                # 校验一致；恢复不改凭据字段（salt/verify/KDF），故读回当前值重算即可。
                meta_snapshot = db.get_meta_batch(list(VAULT_META_SIGNED_KEYS))
                db.set_meta(
                    "vault_meta_mac",
                    MetadataSigner.compute_vault_meta_mac(meta_snapshot, key),
                )
            # WAL 截断由 :meth:`_finalize_restored_state_locked` 在事务提交后执行
            # （事务内 secure_checkpoint 会被跳过）；success 在 return 前置 True，保证
            # finally 不误清零已落库的 snapshot_key（调用方 apply_snapshot_key 复制后才
            # 清零自身引用）。
            success = True
            return new_epoch, new_snapshot_key
        finally:
            # 事务失败（success 未置 True）时局部 snapshot_key 未被 apply_snapshot_key
            # 接管，原地清零收缩崩溃 dump 窗口；成功路径由调用方在 apply 后清零自己的引用。
            if not success:
                secure_zero_buffer(new_snapshot_key)

    def maybe_auto_backup(
        self,
        force: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[bool, str]:
        """按配置创建当前保险库的本地快速快照。

        配置读取统一经 ``self._vault.config`` 单一通道（ARCH-048）：与同类
        ``create_backup`` 的 purge 清理（``purge_snapshot_backups(self._vault.config)``）
        一致，不留「调用方传参」的第二通道——vault 构造注入的 ConfigManager 即
        全类配置的唯一来源，参数传入的另一实例（即便当前恰好同对象）构成双源
        漂移面。

        Args:
            force: 是否强制创建，忽略时间间隔检查。
            cancel_check: 可选取消探针，透传给 create_backup，使后台快照
                在隐藏到托盘或锁定时能尽快退出。

        Returns:
            由是否成功与错误信息组成的二元组，成功时错误信息为空字符串。
        """
        config = self._vault.config
        if not force and not config.get(CFG_AUTO_BACKUP_ENABLED, False):
            return True, ""

        # 间隔判定下沉 auto_backup_policy.is_auto_backup_due（纯函数，可独立测试）；
        # 未到间隔时静默返回成功（与禁用跳过一致：非错误，只是无需备份）。
        if not is_auto_backup_due(config, force=force):
            return True, ""

        backup_dir = config.get(CFG_BACKUP_DIRECTORY, "")
        if backup_dir:
            try:
                # backup_directory 是用户自定义的高敏感路径——自动快照含全量明文，
                # 若攻击者把其某祖先目录替换为符号链接，可把写入重定向到攻击者位置。
                # 默认 validate_file_path 的 Unix 分支仅检测叶子（避开 macOS 系统
                # 符号链接误伤），此处追加 check_ancestors 逐级检测祖先符号链接
                # （系统规范链接放行），收缩该重定向威胁。
                backup_dir = str(validate_file_path(backup_dir, check_ancestors=True))
            except ValueError:
                return False, f"备份目录路径无效: {backup_dir}"

        directory = Path(backup_dir) if backup_dir else config.data_dir / BACKUPS_DIR_NAME
        # 创建并收紧权限（strict）：自动快照含全量明文，ACL 失败时宁可中止备份
        # 也不以宽松权限落盘，让用户经返回的错误感知权限问题。
        try:
            secure_directory(directory, strict=True)
        except OSError as exc:
            return False, f"无法收紧备份目录权限：{exc}"
        filename = build_backup_filename(SNAPSHOT_PREFIX)
        success, error = self.create_backup(
            str(directory / filename),
            use_snapshot_key=True,
            cancel_check=cancel_check,
        )
        if not success:
            return False, error

        config.set(CFG_LAST_AUTO_BACKUP_AT, utc_now_iso())
        try:
            # keep_integrity_warning=True（QL-064）：自动备份时间戳是后台自动写盘，
            # 不是用户驱动的配置修复——本会话检出过的篡改告警不得因此清零（与
            # register_security_sentinel 的哨兵登记写盘语义一致），否则抑制
            # MainWindow 的完整性用户通知。
            config.save(keep_integrity_warning=True)
        except OSError:
            # save 失败：备份已成功创建，未持久化的时间戳仅会让下次间隔检查失效而
            # 冗余备份，非致命；风格与 settings_dialog 的 config.save() 一致。
            logger.warning("无法写入配置文件，请检查磁盘空间和文件权限。", exc_info=True)

        retention = config.get(CFG_AUTO_BACKUP_RETENTION, DEFAULT_CONFIG[CFG_AUTO_BACKUP_RETENTION])
        # 过期快照清理下沉 auto_backup_policy.purge_expired_auto_backups（纯策略函数）。
        # PERF-002：清理异常就地捕获降级 warning，不漂移致「备份已成功却被误报失败」
        # （purge 内部 secure_purge 已对单文件删除告警，此处兜底 glob 等非预期 OSError）。
        try:
            purge_expired_auto_backups(directory, retention)
        except OSError:
            logger.warning("过期自动备份清理失败，已跳过", exc_info=True)

        return True, ""
