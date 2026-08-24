"""``to_user_message`` 错误文案映射测试。

补 ENOSPC（磁盘满）→「磁盘空间不足」分支：secure_delete_file 测试抛
``OSError('disk full')`` 未设 ``errno``，不匹配 ``errno.ENOSPC``，故此处直接对
统一翻译层 ``to_user_message`` 做分支覆盖。另覆盖 ShareError 的原文保留分支
（QL-043）。
"""

import errno

import pytest

from src.business.services.error_messages import to_user_message
from src.exceptions import ShareError

_DEFAULT = "操作失败，请检查文件和磁盘。"


def test_enospc_maps_to_disk_full_message():
    """OSError(errno=ENOSPC) 映射为「磁盘空间不足」而非通用「文件读写失败」。"""
    exc = OSError(errno.ENOSPC, "No space left on device")
    assert to_user_message(exc, default=_DEFAULT) == "磁盘空间不足。"


def test_generic_oserror_maps_to_io_failure_message():
    """非 ENOSPC 且非 PermissionError/FileNotFound 等子类的 OSError 回退为通用文案。"""
    # EIO 不映射到 PermissionError/FileNotFoundError/IsADirectoryError，走通用分支
    exc = OSError(errno.EIO, "I/O error")
    assert to_user_message(exc, default=_DEFAULT) == "文件读写失败，请检查路径和磁盘。"


@pytest.mark.parametrize(
    "message",
    [
        "无效的共享包文件格式",
        "共享包文件头已损坏",
        "不支持的共享包版本：2",
        "共享包 KDF 参数无效，可能已损坏",
    ],
)
def test_share_error_preserves_user_facing_message(message):
    """ShareError 的面向用户消息经统一翻译层保留原文（QL-043）。

    ShareError 非 ValueError 子类，无此分支会落入 default 兜底（「操作失败，请
    重试。」），丢失 share/header_codec 等抛出的具体可操作提示。
    """
    assert to_user_message(ShareError(message), default=_DEFAULT) == message


def test_empty_share_error_falls_back_to_share_default():
    """空消息 ShareError 回退到共享包场景兜底文案而非通用 default。"""
    assert to_user_message(ShareError(""), default=_DEFAULT) == "共享包操作失败，文件可能已损坏。"
