"""恢复前安全快照（pre_restore_*.cbox）的创建、统计与清理。

独立的 ``RestorePointManager`` 承载恢复点文件的完整生命周期：创建（pre_restore 快照
备份）、统计、清理，使恢复点成为单一事实源（ARCH-006）。备份加密管线经
:meth:`RestorePointManager.bind_backup_creator` 由 :class:`BackupRestoreManager` 延迟
注入（避免构造期循环依赖），复用同一加密格式。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from ...exceptions import BackupError
from ...utils.file_security import secure_delete_file, secure_directory
from ...utils.purge_files import count_files, secure_purge
from ..services.backup.paths import (
    BACKUPS_DIR_NAME,
    PRE_RESTORE_GLOB,
    PRE_RESTORE_PREFIX,
    build_backup_filename,
)
from ..services.backup.purge import backup_directories

if TYPE_CHECKING:
    from .vault_manager import VaultManager

logger = logging.getLogger(__name__)

# 按文件名降序保留最新恢复点数量上限。
MAX_RESTORE_POINTS = 10

# 恢复点创建所需备份加密管线类型：(目标路径) -> (是否成功, 错误信息)。
_RestorePointCreator = Callable[[str], tuple[bool, str]]


class RestorePointManager:
    """创建、统计与清理恢复前安全快照（pre_restore_*.cbox）。"""

    def __init__(self, vault: VaultManager) -> None:
        self._vault = vault
        # 备份加密管线由 BackupRestoreManager 延迟注入（避免构造期循环依赖）。
        self._backup_creator: _RestorePointCreator | None = None

    def bind_backup_creator(self, creator: _RestorePointCreator) -> None:
        """注入恢复点创建所需的备份加密管线。

        ``BackupRestoreManager`` 构造本管理器后立即调用，绑定其持锁全流程备份入口
        （``_create_backup_locked`` 的薄包装）作为恢复点加密管线。延迟绑定避免
        ``BackupRestoreManager`` ↔ ``RestorePointManager`` 构造期循环依赖。
        """
        self._backup_creator = creator

    def create(self) -> Path | None:
        """创建恢复前安全快照，返回快照路径用于失败时清理；创建失败返回 None。

        调用方须已持有 ``vault_write_lock``（恢复点创建复用持锁备份管线，避免经
        ``create_backup`` 再次获取 RLock 的嵌套重入）。
        """
        creator = self._backup_creator
        if creator is None:
            raise RuntimeError("恢复点备份管线未绑定（bind_backup_creator 未调用）")
        directory = self._vault.data_dir / BACKUPS_DIR_NAME
        # 恢复点是恢复失败回滚的安全网，优先于权限严格性：data_dir 已由 config
        # 以 strict 创建，backups 子目录继承收紧后的父权限；宁可保留安全网也
        # 不因 ACL 失败放弃恢复点（短期明文，恢复后即清理）。
        secure_directory(directory)
        filename = build_backup_filename(PRE_RESTORE_PREFIX)
        target_path = directory / filename
        try:
            success, error = creator(str(target_path))
        except Exception:
            # creator 的 atomic_write 在 os.replace 成功后若 secure_file 失败会抛异常；
            # 此时 target_path 可能已写出含恢复前全部明文的文件（atomic_write 仅清理
            # .tmp，不清理已 replace 到位的目标）。立即安全删除避免明文泄漏面扩大，
            # 再向上抛出原异常。
            self._safe_delete_restore_point(target_path)
            raise
        if not success:
            raise BackupError(f"无法创建恢复前安全快照：{error}")
        # 按文件名降序保留最新 MAX_RESTORE_POINTS 个恢复点，删除过期项；删除失败
        # 仅告警（恢复点含全量明文，残留由调用方据创建结果决定是否重试清理）。
        # PERF-002：retention 清理异常就地捕获降级 warning，不漂移致「恢复已成功却被
        # 误报失败」（secure_purge 的 collect_failures=False 已对单文件删除告警，
        # 此处仅兜底 glob 等非预期 OSError）。
        try:
            secure_purge(
                [directory],
                [PRE_RESTORE_GLOB],
                keep=MAX_RESTORE_POINTS,
                collect_failures=False,
            )
        except OSError:
            logger.warning("恢复点 retention 清理失败，已跳过", exc_info=True)
        return target_path

    @staticmethod
    def _safe_delete_restore_point(path: Path) -> None:
        """异常路径清理恢复点：删除失败仅告警，绝不掩盖向上抛出的原异常。

        恢复点含恢复前全部条目明文，删除失败意味着泄漏面未收缩，需可见日志；
        但调用方（如 :meth:`create`）的原异常更需向上传递，故此处吞掉删除异常仅记录。
        """
        try:
            secure_delete_file(path)
        except OSError:
            logger.warning("异常路径清理恢复点失败：%s", path, exc_info=True)

    def count(self) -> int:
        """统计恢复前安全快照数量（覆盖默认与自定义备份目录），供 UI 决策。"""
        return count_files(backup_directories(self._vault.config), [PRE_RESTORE_GLOB])

    def clear_all(self) -> int:
        """删除所有恢复前安全快照 pre_restore_*.cbox，返回删除数量。

        覆盖默认备份目录与用户自定义 backup_directory，避免用户改了备份目录后
        旧目录残留明文恢复点。供 UI 手动清理；改密时由 VaultManager 自动清理。
        恢复点含恢复前全部条目明文，定期清理可收缩泄漏面。

        Note:
            count_files + secure_purge 各 glob 一遍同目录同模式（PERF-007），但恢复点文件
            稀少（通常个位数），双重遍历开销可忽略，保持复用 purge 统一删除逻辑。
        """
        directories = backup_directories(self._vault.config)
        total = count_files(directories, [PRE_RESTORE_GLOB])
        failed = secure_purge(directories, [PRE_RESTORE_GLOB])
        if failed:
            # 恢复点含恢复前全部明文，删除失败意味着泄漏面未收缩，需可见日志（QL-002）。
            # secure_purge 默认 collect_failures=True 收集失败项，此处补 warning 上报。
            logger.warning(
                "清理 %d 个恢复点失败（含明文，需手动检查）：%s",
                len(failed),
                ", ".join(str(p) for p in failed),
            )
        return total - len(failed)
