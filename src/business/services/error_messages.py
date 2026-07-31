"""异常到用户友好消息的统一翻译层（单一事实源）。

业务层（``backup_restore`` / ``vault_lifecycle``）与 UI 层（经
:mod:`src.ui.error_messages` re-export）共享此翻译，避免三处各自维护异常→文案
映射导致同一异常在不同入口呈现不一致文案——（重构前 ``DecryptionError`` 曾经经
``backup_restore._user_friendly_error`` 的 ``ValueError`` 分支透传内部 ``crypto_id``
等技术细节，而 UI 层归一为「解密失败」；现已统一委托 ``to_user_message``）。

设计原则：技术性/内部异常（``CipherBoxError`` 家族、IO 错误、格式错误、解密失败、
完整性校验失败）归一为固定友好提示，不暴露 ``str(exc)`` 的内部细节（数据库列名、
crypto_id、驱动层信息）；用户输入校验类 ``ValueError``（携带「标题过长」等可操作
消息）保留原消息——此类消息本就面向用户，归一会丢失可操作性。``DecryptionError``
虽是 ``ValueError`` 子类，但在 ``ValueError`` 分支前已按 ``CipherBoxError`` 归一，
不会透传 ``str(exc)``。
"""

from __future__ import annotations

import binascii
import errno
import json

from ...exceptions import (
    BackupError,
    DatabaseError,
    DecryptionError,
    ImportError,
    PayloadTooLargeError,
    SchemaError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)

__all__ = ['to_user_message']


def to_user_message(exc: BaseException, *, default: str = '操作失败，请重试。') -> str:
    """将异常翻译为面向用户的中文提示（统一入口）。

    匹配顺序按具体→一般：先匹配最具体的领域异常（``DecryptionError`` 先于
    ``ValueError``、``PayloadTooLargeError`` 落入 ``BackupError``）。技术性异常返回
    固定友好消息，不暴露 ``str(exc)`` 的内部细节；``BackupError``（含
    ``PayloadTooLargeError``）携带面向用户的结构校验消息（如「备份数据缺少必备
    字段」「备份条目数量超出限制」），保留以提供诊断；用户输入校验类 ``ValueError``
    保留其可操作消息。

    Args:
        exc: 待翻译的异常。
        default: 未明确归类的异常兜底文案，调用方可按场景定制（备份场景用
            「操作失败，请检查文件和磁盘」、初始化场景用「保险库初始化失败」）。
    """
    # ---- CipherBoxError 家族（技术性失败，归一为固定文案）----
    if isinstance(exc, VaultLockedError):
        return '保险库已锁定，请先解锁后重试。'
    if isinstance(exc, VaultKeyEpochMismatchError):
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
        # BackupError 归一为固定文案，不透传 str(exc)：校验路径抛出的 BackupError
        # 消息理论上有含技术细节（列名/crypto_id）风险，统一归一避免泄漏。诊断信息
        # 已由调用方记日志（exc_info），用户层只需友好提示。
        return '备份文件已损坏或格式无效，无法读取。'
    # ---- ImportError 域（导入解析/校验，携带面向用户的消息）----
    # ImportError 非 ValueError 子类（纯 CipherBoxError），不会落入下方 ValueError
    # 分支，须显式处理。其 str(exc) 本就是面向用户的可操作消息（如「不是 CipherBox
    # JSON 导出文件」「导入文件过大」），保留以提供诊断。
    if isinstance(exc, ImportError):
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
    # ---- 用户输入校验类 ValueError（非 CipherBoxError 子类，保留可操作消息）----
    # DecryptionError 虽是 ValueError 子类，但已在上方按 CipherBoxError 归一，
    # 不会到此分支；此处仅处理纯校验类 ValueError（密码强度、字段长度、路径非法等），
    # 其 str(exc) 本就是面向用户的可操作消息。
    if isinstance(exc, ValueError):
        msg = str(exc).strip()
        return msg or default
    return default
