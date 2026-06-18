"""异常到用户友好消息的统一翻译层。

UI 层所有面向用户的错误提示经 ``to_user_message`` 转换，避免把领域异常的内部
细节（数据库列名如 ``username_enc``、``entry_id``、``crypto_id`` 等技术标识，
或 sqlite3/InvalidTag 等驱动层信息）直接透传给终端用户。

设计原则：技术性/内部异常（备份损坏、数据库错误、解密失败、完整性校验失败）
归一为通用友好提示；用户输入校验类异常（``ValueError`` 携带的「标题过长」等
可操作消息）由调用方保留原消息——此类消息本就面向用户，归一会丢失可操作性。
"""

from ..exceptions import (
    BackupError,
    DatabaseError,
    DecryptionError,
    PayloadTooLargeError,
    SchemaError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)

__all__ = ['to_user_message']


def to_user_message(exc: BaseException) -> str:
    """将领域异常翻译为面向用户的中文提示。

    匹配顺序按具体→一般：先匹配最具体的领域异常子类（如 ``PayloadTooLargeError``
    先于 ``BackupError``）。技术性异常返回固定友好消息，不暴露 ``str(exc)`` 的
    内部细节；未明确归类的异常兜底为通用提示。

    非 :class:`CipherBoxError` 家族的异常（如用户输入校验的 ``ValueError``）不应
    走本函数——调用方应保留其可操作消息。本函数仅服务于「技术性失败」场景。
    """
    if isinstance(exc, VaultLockedError):
        return '保险库已锁定，请先解锁后重试。'
    if isinstance(exc, VaultKeyEpochMismatchError):
        return '保险库已被其他进程更新，请重新打开应用。'
    if isinstance(exc, PayloadTooLargeError):
        return '数据或文件超出大小限制，请减少内容后重试。'
    if isinstance(exc, BackupError):
        return '备份文件已损坏或格式无效，无法读取。'
    if isinstance(exc, VaultIntegrityError):
        return '数据完整性校验失败，文件可能已损坏或被篡改。'
    if isinstance(exc, DecryptionError):
        return '解密失败，数据可能已损坏。'
    if isinstance(exc, SchemaError):
        return '数据库结构异常，可能已损坏或不兼容。'
    if isinstance(exc, DatabaseError):
        return '数据库操作失败，请稍后重试。'
    # 未明确归类的领域异常兜底为通用提示，避免暴露 str(exc) 技术细节。
    return '操作失败，请重试。'
