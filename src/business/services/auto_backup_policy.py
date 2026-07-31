"""自动备份的策略判定：间隔决策与过期快照清理。

纯策略逻辑，不依赖 manager 实例状态，可独立测试。
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

    仅做时间间隔判定，假定调用方已过启用开关检查（禁用且非 force 时由调用方直接返回）。

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
        # 时间戳损坏会让间隔检查每次都重新备份；记日志以便运维发现而非静默冗余备份。
        logger.warning('last_auto_backup_at 解析失败，跳过间隔检查：%s', last_text)
        return True
    interval = config.get(  # type: ignore[attr-defined]
        'auto_backup_interval_hours', DEFAULT_CONFIG['auto_backup_interval_hours'],
    )
    return elapsed >= timedelta(hours=interval)


def purge_expired_auto_backups(directory: Path, retention: int) -> None:
    """按文件名降序保留最新 ``retention`` 个自动快照，过期项安全删除。

    过期快照含全量明文，删除失败会扩大泄漏面。``collect_failures=False`` 使失败
    仅告警而不中断调用方——自动备份已成功，清理失败不应让其看起来失败。
    """
    secure_purge([directory], [SNAPSHOT_GLOB], keep=retention, collect_failures=False)
