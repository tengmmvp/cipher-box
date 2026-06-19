"""批量安全删除文件工具 — 统一备份/恢复点/快照的清理逻辑。

集中 ``backup_restore`` 与 ``vault_manager`` 中重复的「目录遍历 + glob +
secure_delete_file + 失败收集/告警」模式，参数化目录、模式、保留数与失败策略，
消除 6 处逐字重复实现。底层复用 :func:`secure_delete_file` 保持覆写删除强度，
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
        directories: 待清理的目录（不存在的目录跳过）。
        patterns: glob 模式集合（如 ``['pre_restore_*.cbox', 'cipherbox_snapshot_*.cbox']``）。
        keep: ``None`` 表示全部删除；``N`` 表示每个 ``(directory, pattern)`` 组合
            按文件名降序保留最新 N 个、删除其余。文件名降序比 ``st_mtime`` 更精确，
            与原恢复点/快照 retention 语义一致（避免秒级精度问题）。
        collect_failures: ``True`` 时删除失败的文件收集到返回列表供调用方上报；
            ``False`` 时失败仅记录告警、返回空列表。

    Returns:
        删除失败的 ``Path`` 列表；``collect_failures=False`` 时恒为空。调用方据此
        区分「全清成功」与「部分残留」（残留文件含明文，需可见反馈）。
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
                        logger.warning('安全删除失败：%s', path, exc_info=True)
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
