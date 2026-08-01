"""批量安全删除文件工具 — 统一备份/恢复点/快照的清理逻辑。

参数化目录、模式、保留数与失败策略；复用 :func:`secure_delete_file` 保持覆写删除强度，
确保含明文的恢复点/快照不被仅 unlink。
"""

import logging
from collections.abc import Iterable
from pathlib import Path

from .file_security import secure_delete_file

logger = logging.getLogger(__name__)


def secure_purge(
    directories: Iterable[Path],
    patterns: Iterable[str],
    *,
    keep: int | None = None,
    collect_failures: bool = True,
) -> list[Path]:
    """按 glob 模式安全删除目录下匹配文件，返回未能删除的文件列表。

    Args:
        directories: 待清理目录（不存在则跳过）。
        patterns: glob 模式集合（如 ``['pre_restore_*.cbox', ...]``）。
        keep: ``None`` 全删；``N`` 表示每个 ``(directory, pattern)`` 按文件名降序
            保留最新 N 个（与恢复点/快照 retention 语义一致，避开 ``st_mtime`` 秒级精度问题）。
        collect_failures: ``True`` 收集失败文件到返回列表供上报；``False`` 仅告警返回空。

    Returns:
        删除失败的 ``Path`` 列表；``collect_failures=False`` 时恒为空（残留文件含明文，需可见反馈）。
    """
    failed: list[Path] = []
    for directory in directories:
        if not directory.is_dir():
            continue
        for pattern in patterns:
            matches = sorted(directory.glob(pattern), key=lambda p: p.name, reverse=True)
            if keep is not None:
                matches = matches[keep:]
            for path in matches:
                try:
                    secure_delete_file(path)
                except OSError:
                    if collect_failures:
                        failed.append(path)
                    else:
                        logger.warning("安全删除失败：%s", path, exc_info=True)
    return failed


def count_files(directories: Iterable[Path], patterns: Iterable[str]) -> int:
    """统计目录下匹配 glob 模式的文件数（不删除），供 UI 计数场景复用。"""
    total = 0
    for directory in directories:
        if not directory.is_dir():
            continue
        for pattern in patterns:
            total += sum(1 for _ in directory.glob(pattern))
    return total
