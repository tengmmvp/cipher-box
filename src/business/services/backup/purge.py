"""备份文件清理纯函数 — 目录收集与 purge，下沉自 :class:`VaultManager`（SRP）。

备份目录策略（默认 + 用户自定义校验）与文件清理（snapshot/恢复点 purge）属备份域
逻辑，从安全边界核心 :class:`~src.business.managers.vault_manager.VaultManager` 下沉
至此无状态纯函数模块。调用方（app 启动重试、改密/恢复后清理、恢复点统计）各自传入
:class:`ConfigManager` 调用，使 VaultManager 不再承担备份域职责。
"""

from __future__ import annotations

import logging
from pathlib import Path

from ....config import CFG_BACKUP_DIRECTORY, ConfigManager
from ....utils.file_security import validate_file_path
from ....utils.purge_files import secure_purge
from .paths import BACKUPS_DIR_NAME, PRE_RESTORE_GLOB, SNAPSHOT_GLOB

logger = logging.getLogger(__name__)


def backup_directories(config: ConfigManager) -> list[Path]:
    """备份相关目录列表：默认目录 + 用户自定义 backup_directory（若配置且合法）。

    作为 purge/清理/统计的目录单一事实源，避免漏扫自定义目录导致含明文的恢复点/
    快照残留。用户配置的 ``backup_directory`` 经 ``validate_file_path(check_ancestors=True)``
    复核（与写入侧对齐），收缩符号链接重定向威胁；非法路径跳过并告警，避免 purge
    误删重定向位置文件（SEC-004）。
    """
    directories = [config.data_dir / BACKUPS_DIR_NAME]
    custom = config.get(CFG_BACKUP_DIRECTORY, "")
    if custom:
        try:
            validated = validate_file_path(custom, check_ancestors=True)
            directories.append(Path(str(validated)))
        except ValueError:
            logger.warning("自定义备份目录路径无效，已跳过清理：%s", custom)
    return directories


def purge_snapshot_backups(config: ConfigManager) -> list[Path]:
    """删除所有 snapshot_key 加密的快照与恢复前安全快照，返回未能删除的文件。

    改密/恢复时 snapshot_key 随主密钥轮换，旧 snapshot_key 加密的文件无法用新密钥
    解密且含历史明文，清理以收缩泄漏面。覆盖默认与自定义备份目录。
    """
    return secure_purge(
        backup_directories(config),
        [PRE_RESTORE_GLOB, SNAPSHOT_GLOB],
    )


def purge_restore_points(config: ConfigManager) -> list[Path]:
    """删除所有恢复前安全快照（pre_restore_*.cbox），返回未能删除的文件。

    恢复点为恢复前的临时全量明文快照，恢复成功后应删除；启动时重试清理之前 purge
    失败的残留。仅清理 pre_restore_*（一次性恢复点），不动 cipherbox_snapshot_*。
    """
    return secure_purge(backup_directories(config), [PRE_RESTORE_GLOB])
