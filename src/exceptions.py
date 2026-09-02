"""CipherBox 自定义异常层次结构。

提供领域化异常类型替代散落的 RuntimeError / ValueError。部分异常多重继承标准异常
（``DecryptionError`` / ``EntryError`` / ``PayloadTooLargeError`` 也是 ``ValueError``；
``VaultError`` / ``DatabaseError`` 也是 ``RuntimeError``），可经 ``except ValueError`` /
``except RuntimeError`` 兜底捕获。

.. warning::

    多重继承意味着上述兜底会连带吞掉领域异常子类而掩盖真实问题——应优先捕获具体的
    ``CipherBox`` 异常。``EntryError`` 保留 ValueError 兼容：用户输入校验异常本就面向
    ``except ValueError`` 处理范式（UI/测试），属刻意设计。
"""

__all__ = [
    "CipherBoxError",
    "VaultError",
    "VaultLockedError",
    "VaultIntegrityError",
    "VaultKeyEpochMismatchError",
    "VaultAlreadyInitializedError",
    "MasterPasswordPolicyError",
    "DecryptionError",
    "EntryError",
    "EntryIntegrityError",
    "BackupError",
    "RestoreAbortedError",
    "PayloadTooLargeError",
    "ShareError",
    "DatabaseError",
    "TransactionError",
    "SchemaError",
    "ImportDataError",
    "ImportFormatError",
    "ImportSizeError",
]


class CipherBoxError(Exception):
    """CipherBox 所有自定义异常的基类。"""


class VaultError(CipherBoxError, RuntimeError):
    """保险库操作异常，可被 ``except RuntimeError`` 捕获。"""


class VaultLockedError(VaultError):
    """保险库未解锁。"""


class VaultIntegrityError(VaultError):
    """元数据完整性校验失败。"""


class VaultKeyEpochMismatchError(VaultError):
    """主密钥 epoch 与库内 ``key_epoch`` 不一致，通常因并发改密/锁定改写密钥。

    由 ``VaultManager.epoch_guarded_read`` / ``vault_write_lock`` 在持 ``db_lock`` 期间
    比对内存与库内 epoch 不一致时抛出（ARCH-005）：中止读路径以防用旧密钥解密新密文
    致 GCM 认证失败，中止事务/单条写以防写入旧密钥密文。后台只读路径（列表/搜索/摘要）
    捕获后返回空，用户主动路径（导出）向上传播。
    """


class VaultAlreadyInitializedError(VaultError):
    """保险库已初始化，不能重复设置主密码。"""


class MasterPasswordPolicyError(VaultError, ValueError):
    """主密码策略校验失败（新密码强度不足、新旧相同等可预期的用户输入问题）。

    ARCH-042：``change_master_password`` 的 ``(bool, str)`` 返回契约中 ``False``
    收窄为唯一语义「旧主密码认证失败」，策略类失败以本异常类型化走异常通道，
    调用方（改密对话框）据返回值形态区分「计入速率限制」与「不惩罚用户」，
    不再比对文案字符串。双重继承 ``ValueError`` 对齐 :class:`EntryError` 的
    用户输入校验范式，经 ``to_user_message`` 保留 ``str(exc)`` 原文。
    """


class DecryptionError(CipherBoxError, ValueError):
    """解密失败。"""


class EntryError(CipherBoxError, ValueError):
    """条目操作异常（用户输入校验、字段非法等）。

    双重继承 ``ValueError``：用户输入校验异常面向 ``except ValueError`` 处理范式
    （UI 校验、``pytest.raises(ValueError)``），与 :class:`DecryptionError` /
    :class:`PayloadTooLargeError` 策略一致。业务层仍应优先 ``except EntryError`` 精确捕获。
    """


class EntryIntegrityError(EntryError):
    """条目完整性异常：字段解密失败或元数据签名校验不通过。

    亦覆盖密文已解密但结构损坏（如 custom_fields 解密后非合法 JSON），与解密层损坏
    （:class:`DecryptionError`，GCM 认证失败/密钥问题）区分。
    """


class BackupError(CipherBoxError):
    """备份/恢复操作异常。"""


class RestoreAbortedError(BackupError):
    """恢复流程面向用户的中止（缺备份密码/保险库未解锁/备份文件无效等）。

    ARCH-045：恢复各阶段方法以本异常替代 ``数据 | tuple[bool, str] | None``
    联合返回，``str(exc)`` 即面向用户的完整中止文案，经
    :func:`src.business.services.error_messages.to_user_message` 原样保留（先于
    ``BackupError`` 的固定文案归一分支拦截）。
    """


class PayloadTooLargeError(BackupError, ValueError):
    """数据/文件/字段超出大小上限。

    双重继承：上层可经 ``except BackupError`` 归入备份错误，也可被 ``except ValueError`` 兜底。
    """


class ShareError(CipherBoxError):
    """限时加密共享包操作异常（创建/解析/解密/篡改）。"""


class ImportDataError(CipherBoxError):
    """导入数据解析或校验异常。

    命名 ImportDataError（QL-004）以消除与 Python 内置 ``ImportError`` 的同名遮蔽——
    旧名 ``ImportError`` 会使 ``except (ImportError, ...)`` 误吞合并器调用链中真实的
    内置 ImportError（如可选依赖缺失），改用语义化名称后类型边界清晰。
    """


class ImportFormatError(ImportDataError):
    """导入文件格式或结构无效（如非 CipherBox JSON、字段类型不符）。"""


class ImportSizeError(ImportDataError):
    """导入数据超出数量或大小上限（条目过多、字段/文件过大）。"""


class DatabaseError(CipherBoxError, RuntimeError):
    """数据库操作异常，可被 ``except RuntimeError`` 捕获。"""


class TransactionError(DatabaseError):
    """事务状态异常。"""


class SchemaError(DatabaseError):
    """数据库 schema 异常。"""
