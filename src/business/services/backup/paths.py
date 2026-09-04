"""备份/恢复点文件命名约定。

集中目录名、扩展名、glob 模式与文件名构造，避免漂移致 purge 找不到旧文件——
尤其 pre_restore_* 含恢复前全部条目明文，残留即放大泄漏面。
"""

from ....utils.format import timestamped_suffix

BACKUPS_DIR_NAME = "backups"
BACKUP_EXT = ".cbox"
PRE_RESTORE_PREFIX = "pre_restore_"
PRE_RESTORE_GLOB = f"{PRE_RESTORE_PREFIX}*{BACKUP_EXT}"
SNAPSHOT_PREFIX = "cipherbox_snapshot_"
SNAPSHOT_GLOB = f"{SNAPSHOT_PREFIX}*{BACKUP_EXT}"


def build_backup_filename(prefix: str) -> str:
    """构造带 UTC 时间戳与随机后缀的备份文件名。

    统一两类备份命名格式避免漂移；后缀干经共享
    :func:`src.utils.format.timestamped_suffix` 构造（QL-082）。
    """
    return f"{prefix}{timestamped_suffix()}{BACKUP_EXT}"
