"""异常到用户友好消息的统一翻译层（单一事实源）。

业务层与 UI 层共享此翻译，避免多入口各自维护异常→文案映射致同一异常呈现不一致。

设计原则：技术性/内部异常（``CipherBoxError`` 家族、IO/格式错误、解密/完整性失败）
归一为固定友好提示，不暴露 ``str(exc)`` 内部细节（列名/crypto_id/驱动信息）；用户
输入校验类 ``ValueError`` 保留其面向用户的可操作消息。``DecryptionError`` 虽是
``ValueError`` 子类，但在 ``ValueError`` 分支前已按 ``CipherBoxError`` 归一，不透传。
"""

from __future__ import annotations

import binascii
import errno
import json

from ...exceptions import (
    BackupError,
    DatabaseError,
    DecryptionError,
    ImportDataError,
    PayloadTooLargeError,
    SchemaError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)

__all__ = ['to_user_message']


def to_user_message(exc: BaseException, *, default: str = '操作失败，请重试。') -> str:
    """将异常翻译为面向用户的中文提示（统一入口）。

    匹配顺序按具体→一般（``DecryptionError`` 先于 ``ValueError``、
    ``PayloadTooLargeError`` 落入 ``BackupError``）。技术性异常返回固定友好消息不
    暴露内部细节；``BackupError``（含子类）携带结构校验消息保留诊断；``ValueError``
    保留可操作消息。

    Args:
        exc: 待翻译的异常。
        default: 未明确归类的异常兜底文案，调用方可按场景定制。
    """
    # ---- CipherBoxError 家族（技术性失败，归一为固定文案）----
    if isinstance(exc, VaultLockedError):
        return '保险库已锁定，请先解锁后重试。'
    if isinstance(exc, VaultKeyEpochMismatchError):
        # 并发改密/锁定致库内 key_epoch 与内存不一致时由 epoch 守卫抛出（ARCH-005），
        # 已中止并回滚。归一为固定重试提示，不透传 str(exc) 的「密钥/epoch」措辞。
        return '操作期间检测到主密码已被修改，已中止并回滚，请重试。'
    if isinstance(exc, PayloadTooLargeError):
        return '数据或文件超出大小限制，请减少内容后重试。'
    if isinstance(exc, VaultIntegrityError):
        return '数据完整性校验失败，文件可能已损坏或被篡改。'
    if isinstance(exc, DecryptionError):
        # DecryptionError 是 ValueError 子类，须在下方 ValueError 分支前归一，
        # 避免 str(exc) 透传 crypto_id 等技术细节。
        return '解密失败，数据可能已损坏。'
    if isinstance(exc, SchemaError):
        return '数据库结构异常，可能已损坏或不兼容。'
    if isinstance(exc, DatabaseError):
        return '数据库操作失败，请稍后重试。'
    if isinstance(exc, BackupError):
        # BackupError 归一为固定文案，不透传 str(exc)（校验消息可能含技术细节）。
        # 诊断信息已由调用方记日志。
        return '备份文件已损坏或格式无效，无法读取。'
    # ---- ImportDataError 域（导入解析/校验，携带面向用户的消息）----
    # 纯 CipherBoxError 不落入下方 ValueError 分支，str(exc) 本就是可操作消息，保留。
    if isinstance(exc, ImportDataError):
        msg = str(exc).strip()
        return msg or '导入文件格式无效或已损坏。'
    # ---- IO / 格式异常（驱动层，归一为固定文案）----
    if isinstance(exc, FileNotFoundError):
        return '找不到指定的文件。'
    if isinstance(exc, PermissionError):
        return '没有文件访问权限。'
    if isinstance(exc, IsADirectoryError):
        return '所选路径是目录，请选择文件。'
    if isinstance(exc, json.JSONDecodeError):
        return '文件格式无效或已损坏。'
    if isinstance(exc, binascii.Error):
        return '数据格式错误，可能已损坏。'
    if isinstance(exc, OSError):
        if exc.errno == errno.ENOSPC:
            return '磁盘空间不足。'
        return '文件读写失败，请检查路径和磁盘。'
    # ---- 用户输入校验类 ValueError（保留可操作消息）----
    # DecryptionError 已在上方按 CipherBoxError 归一不到此；此处仅纯校验类
    # ValueError，str(exc) 本就是面向用户消息。
    if isinstance(exc, ValueError):
        msg = str(exc).strip()
        return msg or default
    return default
