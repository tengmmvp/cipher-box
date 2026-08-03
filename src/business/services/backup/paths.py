"""备份/恢复点文件命名约定。

集中目录名、扩展名、glob 模式与文件名构造，避免漂移致 purge 找不到旧文件——
尤其 pre_restore_* 含恢复前全部条目明文，残留即放大泄漏面。
"""

import uuid
from datetime import datetime, timezone

BACKUPS_DIR_NAME = "backups"
BACKUP_EXT = ".cbox"
PRE_RESTORE_PREFIX = "pre_restore_"
PRE_RESTORE_GLOB = f"{PRE_RESTORE_PREFIX}*{BACKUP_EXT}"
SNAPSHOT_PREFIX = "cipherbox_snapshot_"
SNAPSHOT_GLOB = f"{SNAPSHOT_PREFIX}*{BACKUP_EXT}"

# 备份文件名时间戳格式，单一事实源，供 build_backup_filename 与 glob/排序假设对齐。
_BACKUP_NAME_TS_FORMAT = "%Y%m%d_%H%M%S_%f"


def build_backup_filename(prefix: str) -> str:
    """构造带 UTC 时间戳与随机后缀的备份文件名。

    统一两类备份命名格式避免漂移；时间戳精确到微秒，uuid 取 8 位保证唯一性。
    """
    stamp = datetime.now(timezone.utc).strftime(_BACKUP_NAME_TS_FORMAT)
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}{stamp}_{suffix}{BACKUP_EXT}"
