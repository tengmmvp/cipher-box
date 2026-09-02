"""异常到用户友好消息的统一翻译层（单一事实源）。

业务层与 UI 层共享此翻译，避免多入口各自维护异常→文案映射致同一异常呈现不一致。

设计原则：技术性/内部异常（``CipherBoxError`` 家族、IO/格式错误、解密/完整性失败）
归一为固定友好提示，不暴露 ``str(exc)`` 内部细节（列名/crypto_id/驱动信息）；用户
输入校验类 ``ValueError`` 保留其面向用户的可操作消息。``DecryptionError`` 虽是
``ValueError`` 子类，但在 ``ValueError`` 分支前已按 ``CipherBoxError`` 归一，不透传。
例外：携带面向用户文案的 ``RestoreAbortedError`` / ``ShareError`` / 纯 ``VaultError``
本体（系统错误包装通道，ARCH-042）保留原文——子类的罐头映射先于本体分支命中。
"""

from __future__ import annotations

import binascii
import errno
import json

from ...exceptions import (
    BackupError,
    DatabaseError,
    DecryptionError,
    EntryIntegrityError,
    ImportDataError,
    PayloadTooLargeError,
    RestoreAbortedError,
    SchemaError,
    ShareError,
    VaultError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)

__all__ = ["to_user_message"]


# 固定文案映射（顺序敏感）：技术性异常归一为固定友好消息，不透传 str(exc) 的内部
# 细节（crypto_id/列名/驱动信息）。子类异常须先于父类——DecryptionError 与
# EntryIntegrityError 是 ValueError 子类，列在前以先于下方 ValueError 分支归一。
# 映射表替代 if-elif 链归一异常文案，降 to_user_message 圈复杂度（QL-015）。
_FIXED_MESSAGES: tuple[tuple[type[BaseException], str], ...] = (
    (VaultLockedError, "保险库已锁定，请先解锁后重试。"),
    (VaultKeyEpochMismatchError, "操作期间检测到主密码已被修改，已中止并回滚，请重试。"),
    (PayloadTooLargeError, "数据或文件超出大小限制，请减少内容后重试。"),
    (VaultIntegrityError, "数据完整性校验失败，文件可能已损坏或被篡改。"),
    (EntryIntegrityError, "该条目数据完整性校验失败，可能已损坏。"),
    (DecryptionError, "解密失败，数据可能已损坏。"),
    (SchemaError, "数据库结构异常，可能已损坏或不兼容。"),
    (DatabaseError, "数据库操作失败，请稍后重试。"),
    (BackupError, "备份文件已损坏或格式无效，无法读取。"),
    (FileNotFoundError, "找不到指定的文件。"),
    (PermissionError, "没有文件访问权限。"),
    (IsADirectoryError, "所选路径是目录，请选择文件。"),
    (json.JSONDecodeError, "文件格式无效或已损坏。"),
    (binascii.Error, "数据格式错误，可能已损坏。"),
)


def to_user_message(exc: BaseException, *, default: str = "操作失败，请重试。") -> str:
    """将异常翻译为面向用户的中文提示（统一入口）。

    技术性异常（CipherBoxError 家族、IO/格式错误）经 ``_FIXED_MESSAGES`` 归一为固定
    友好消息；携带面向用户消息的异常（ImportDataError/ValueError）保留 str(exc) 作
    可操作文案。映射顺序敏感，子类先于父类（见 ``_FIXED_MESSAGES`` 注释）。

    Args:
        exc: 待翻译的异常。
        default: 未明确归类的异常兜底文案，调用方可按场景定制。
    """
    # RestoreAbortedError 是携带面向用户文案的 BackupError 子类（ARCH-045），须
    # 先于 _FIXED_MESSAGES 的 BackupError 归一分支拦截以保留原文——与 ImportDataError/
    # ShareError 的保留语义一致（如「请输入创建备份时设置的备份密码」）。
    if isinstance(exc, RestoreAbortedError):
        return str(exc).strip() or default
    for exc_type, message in _FIXED_MESSAGES:
        if isinstance(exc, exc_type):
            return message
    # 纯 VaultError 本体：携带面向用户文案的系统错误通道（ARCH-042——vault_lifecycle
    # 把系统错误经 to_user_message 翻译后以 VaultError 包装，子类（VaultLockedError 等）
    # 已在上方 _FIXED_MESSAGES 命中罐头映射，本体则保留原文），否则 worker error 通道
    # 的二次翻译会把磁盘满/IO 错误的准确文案覆盖为「操作失败，请重试。」。抛出方须
    # 保证 str 面向用户（不携内部细节），与 ImportDataError/ShareError 契约一致。
    if isinstance(exc, VaultError):
        return str(exc).strip() or default
    if isinstance(exc, OSError):
        if exc.errno == errno.ENOSPC:
            return "磁盘空间不足。"
        return "文件读写失败，请检查路径和磁盘。"
    # ImportDataError / ShareError / 纯 ValueError：str(exc) 本就是面向用户消息，保留
    # （空则兜底）。ShareError 非 ValueError 子类，不经统一翻译层会落入 default 兜底、
    # 丢失其面向用户的消息（QL-043）——share/header_codec 等抛出的消息本身面向用户
    # （如「无效的共享包文件格式」「共享包文件头已损坏」），与 ImportDataError 同款
    # 保留原文处理。
    if isinstance(exc, ImportDataError):
        return str(exc).strip() or "导入文件格式无效或已损坏。"
    if isinstance(exc, ShareError):
        return str(exc).strip() or "共享包操作失败，文件可能已损坏。"
    if isinstance(exc, ValueError):
        return str(exc).strip() or default
    return default
