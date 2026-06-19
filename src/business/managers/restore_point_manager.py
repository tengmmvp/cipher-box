"""恢复前安全快照（pre_restore_*.cbox）的统计与清理。

独立的 ``RestorePointManager`` 承载与恢复点文件相关的查询/清理职责，
``BackupRestoreManager`` 通过 ``restore_points`` 属性暴露。注意创建恢复点
（``_create_restore_point``）与 ``_create_backup_locked`` 强耦合，
仍保留在 ``BackupRestoreManager`` 主体。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...utils.purge_files import count_files, secure_purge
from ..services.backup_paths import PRE_RESTORE_GLOB

if TYPE_CHECKING:
    from .vault_manager import VaultManager

# 按文件名降序保留最新恢复点数量上限。
MAX_RESTORE_POINTS = 10


class RestorePointManager:
    """统计与清理恢复前安全快照（pre_restore_*.cbox）。"""

    def __init__(self, vault: VaultManager) -> None:
        self._vault = vault

    def count(self) -> int:
        """统计恢复前安全快照数量（覆盖默认与自定义备份目录），供 UI 决策。"""
        return count_files(self._vault.backup_directories, [PRE_RESTORE_GLOB])

    def clear_all(self) -> int:
        """删除所有恢复前安全快照 pre_restore_*.cbox，返回删除数量。

        覆盖默认备份目录与用户自定义 backup_directory，避免用户改了备份目录后
        旧目录残留明文恢复点。供 UI 手动清理；改密时由 VaultManager 自动清理。
        恢复点含恢复前全部条目明文，定期清理可收缩泄漏面。
        """
        directories = self._vault.backup_directories
        total = count_files(directories, [PRE_RESTORE_GLOB])
        failed = secure_purge(directories, [PRE_RESTORE_GLOB])
        return total - len(failed)
