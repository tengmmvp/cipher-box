"""备份/恢复点文件命名约定。

集中定义目录名、扩展名、glob 模式与文件名构造，供 ``BackupRestoreManager`` 与
``VaultManager`` 的清理/创建路径共用，避免目录名、glob 模式或文件名格式漂移导致
purge 找不到旧文件——尤其 pre_restore_* 含恢复前全部条目明文，残留即放大泄漏面。
"""

import uuid
from datetime import datetime, timezone

BACKUPS_DIR_NAME = 'backups'
BACKUP_EXT = '.cbox'
PRE_RESTORE_PREFIX = 'pre_restore_'
PRE_RESTORE_GLOB = f'{PRE_RESTORE_PREFIX}*{BACKUP_EXT}'
SNAPSHOT_PREFIX = 'cipherbox_snapshot_'
SNAPSHOT_GLOB = f'{SNAPSHOT_PREFIX}*{BACKUP_EXT}'

# 备份文件名时间戳格式，单一来源供 build_backup_filename 与 glob/排序假设对齐。
_BACKUP_NAME_TS_FORMAT = '%Y%m%d_%H%M%S_%f'


def build_backup_filename(prefix: str) -> str:
    """构造带 UTC 时间戳与随机后缀的备份文件名。

    统一 pre_restore_ 与 cipherbox_snapshot_ 两类备份的命名格式，避免调用方两处
    内联 f-string 漂移（时间戳精度或后缀长度不一致会使 glob/排序假设失效）。
    时间戳精确到微秒，uuid 取 8 位保证唯一性。
    """
    stamp = datetime.now(timezone.utc).strftime(_BACKUP_NAME_TS_FORMAT)
    suffix = uuid.uuid4().hex[:8]
    return f'{prefix}{stamp}_{suffix}{BACKUP_EXT}'
