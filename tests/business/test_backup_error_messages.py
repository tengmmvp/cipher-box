"""``_friendly_error`` 错误文案映射测试。

覆盖此前 0 覆盖的分支：ENOSPC（磁盘满）→「磁盘空间不足」。现有 secure_delete_file
测试抛 ``OSError('disk full')`` 未设 ``errno``，不匹配 ``errno.ENOSPC``，故该文案
分支从未被触发；此处直接对 ``_friendly_error`` 做分支覆盖。
"""

import errno

from src.business.managers.backup_restore import _friendly_error

_DEFAULT = '操作失败，请检查文件和磁盘。'


def test_enospc_maps_to_disk_full_message():
    """OSError(errno=ENOSPC) 映射为「磁盘空间不足」而非通用「文件读写失败」。"""
    exc = OSError(errno.ENOSPC, 'No space left on device')
    assert _friendly_error(exc, _DEFAULT) == '磁盘空间不足。'


def test_generic_oserror_maps_to_io_failure_message():
    """非 ENOSPC 且非 PermissionError/FileNotFound 等子类的 OSError 回退为通用文案。"""
    # EIO 不映射到 PermissionError/FileNotFoundError/IsADirectoryError，走通用分支
    exc = OSError(errno.EIO, 'I/O error')
    assert _friendly_error(exc, _DEFAULT) == '文件读写失败，请检查路径和磁盘。'
