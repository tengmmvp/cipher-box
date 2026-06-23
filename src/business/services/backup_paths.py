"""备份/恢复点文件命名约定。

集中定义目录名、扩展名与 glob 模式，供 ``BackupRestoreManager`` 与
``VaultManager`` 的清理路径共用，避免目录名或 glob 模式漂移导致 purge 找不到旧
文件——尤其 pre_restore_* 含恢复前全部条目明文，残留即放大泄漏面。
"""

BACKUPS_DIR_NAME = 'backups'
BACKUP_EXT = '.cbox'
PRE_RESTORE_PREFIX = 'pre_restore_'
PRE_RESTORE_GLOB = f'{PRE_RESTORE_PREFIX}*{BACKUP_EXT}'
SNAPSHOT_PREFIX = 'cipherbox_snapshot_'
SNAPSHOT_GLOB = f'{SNAPSHOT_PREFIX}*{BACKUP_EXT}'
