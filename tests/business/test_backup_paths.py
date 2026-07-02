"""备份/恢复点文件命名约定测试。

``build_backup_filename`` 的时间戳精度、后缀长度与 ``.cbox`` 扩展名是
``PRE_RESTORE_GLOB`` / ``SNAPSHOT_GLOB`` 匹配与排序假设的基础。命名格式漂移会使
glob 匹配失败，导致含恢复前全部条目明文的 ``pre_restore_*`` 恢复点 purge 不到，
放大泄漏面。此处守护命名格式与 glob 的一致性。
"""

import fnmatch
import re

from src.business.services.backup_paths import (
    BACKUP_EXT,
    PRE_RESTORE_GLOB,
    PRE_RESTORE_PREFIX,
    SNAPSHOT_GLOB,
    SNAPSHOT_PREFIX,
    build_backup_filename,
)


def test_build_backup_filename_uses_prefix_ext_and_suffix():
    """文件名须为 前缀 + UTC 时间戳(微秒) + 8 位 hex 后缀 + .cbox 扩展名。"""
    name = build_backup_filename(PRE_RESTORE_PREFIX)
    assert name.startswith(PRE_RESTORE_PREFIX)
    assert name.endswith(BACKUP_EXT)
    body = name[len(PRE_RESTORE_PREFIX):-len(BACKUP_EXT)]
    assert re.fullmatch(r'\d{8}_\d{6}_\d{6}_[0-9a-f]{8}', body), body


def test_backup_filename_matches_glob():
    """生成的恢复点/快照文件名须被对应 glob 捕获，确保 purge 能找到旧文件。"""
    pre_restore = build_backup_filename(PRE_RESTORE_PREFIX)
    snapshot = build_backup_filename(SNAPSHOT_PREFIX)
    assert fnmatch.fnmatch(pre_restore, PRE_RESTORE_GLOB)
    assert fnmatch.fnmatch(snapshot, SNAPSHOT_GLOB)


def test_backup_filenames_are_unique():
    """uuid 后缀保证并发/快速连续生成不重名，避免覆盖。"""
    names = {build_backup_filename(PRE_RESTORE_PREFIX) for _ in range(20)}
    assert len(names) == 20
