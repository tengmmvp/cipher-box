"""自动备份的策略判定：间隔决策与过期快照清理。

从 :meth:`..managers.backup_restore.BackupRestoreManager.maybe_auto_backup` 下沉的
纯策略逻辑，使 manager 仅保留编排主体（路径解析、``create_backup`` 调用、配置持久化），
策略可独立测试。本模块不依赖 manager 实例状态。
"""

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ...config import DEFAULT_CONFIG
from ...utils.purge_files import secure_purge
from .backup_paths import SNAPSHOT_GLOB

logger = logging.getLogger(__name__)


def is_auto_backup_due(
    config: 'object',
    *,
    force: bool,
    now: datetime | None = None,
) -> bool:
    """间隔判定：``force`` 或距上次备份超过间隔（或无记录/记录损坏）时返回 True。

    仅做时间间隔判定。启用开关（``auto_backup_enabled``）的「禁用且非 force 时
    静默跳过」由调用方先行处理——本函数假定调用方已过启用检查（禁用且非 force
    时调用方直接返回成功，不进入间隔判定）。

    Args:
        config: ConfigManager 实例（读取 ``last_auto_backup_at`` 与
            ``auto_backup_interval_hours``）。
        force: 是否强制（忽略间隔）。
        now: 注入的当前时刻，供测试控制时间；默认 ``datetime.now(timezone.utc)``。
    """
    if force:
        return True
    last_text = config.get('last_auto_backup_at', '')  # type: ignore[attr-defined]
    if not last_text:
        return True
    current = now or datetime.now(timezone.utc)
    try:
        elapsed = current - datetime.fromisoformat(last_text)
    except ValueError:
        # last_auto_backup_at 解析失败（损坏的时间戳）会让间隔检查每次都
        # 重新备份；记录以便运维发现配置损坏，而非静默持续冗余备份。
        logger.warning('last_auto_backup_at 解析失败，跳过间隔检查：%s', last_text)
        return True
    interval = config.get(  # type: ignore[attr-defined]
        'auto_backup_interval_hours', DEFAULT_CONFIG['auto_backup_interval_hours'],
    )
    return elapsed >= timedelta(hours=interval)


def purge_expired_auto_backups(directory: Path, retention: int) -> None:
    """按文件名降序保留最新 ``retention`` 个自动快照，过期项安全删除。

    过期快照含全量明文，删除失败会扩大泄漏面，``secure_purge`` 的
    ``collect_failures=False`` 使失败仅告警（由 secure_purge 内部记录）而不中断
    调用方——自动备份已成功，清理失败不应让其看起来失败。
    """
    secure_purge([directory], [SNAPSHOT_GLOB], keep=retention, collect_failures=False)
