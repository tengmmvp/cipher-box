"""CipherBox 自定义异常层次结构。

提供领域化的异常类型，替代散落在各层的 RuntimeError / ValueError。
部分异常通过多重继承同时属于 CipherBoxError 和标准异常类型，
使调用方既可精确捕获领域异常，也可通过 ``except ValueError`` /
``except RuntimeError`` 兜底捕获。

.. warning::

    多重继承意味着 ``DecryptionError`` / ``PayloadTooLargeError`` / ``EntryError``
    也是 ``ValueError``，``VaultError`` / ``DatabaseError`` 也是 ``RuntimeError``。
    **捕获这些标准异常时会连带捕获对应的领域异常子类**——若某处用
    ``except ValueError:`` 兜底，会同时吞掉 ``DecryptionError`` 等领域异常而掩盖
    真实问题。应优先捕获具体的 ``CipherBox`` 异常，仅在确认要兜底时才用标准异常
    基类。``EntryError`` 保留 ValueError 兼容是因为用户输入校验异常本就面向该处理
    范式（UI/测试），属刻意设计而非遗漏。
"""

__all__ = [
    'CipherBoxError',
    'VaultError',
    'VaultLockedError',
    'VaultIntegrityError',
    'VaultKeyEpochMismatchError',
    'VaultAlreadyInitializedError',
    'DecryptionError',
    'EntryError',
    'EntryIntegrityError',
    'BackupError',
    'PayloadTooLargeError',
    'DatabaseError',
    'TransactionError',
    'SchemaError',
    'ImportError',
    'ImportFormatError',
    'ImportSizeError',
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
    """主密钥版本不匹配，可能被其他进程更新。"""


class VaultAlreadyInitializedError(VaultError):
    """保险库已初始化，不能重复设置主密码。"""


class DecryptionError(CipherBoxError, ValueError):
    """解密失败。"""


class EntryError(CipherBoxError, ValueError):
    """条目操作异常（用户输入校验、字段非法等）。

    双重继承 ``CipherBoxError`` 与 ``ValueError``：用户输入校验类异常
    （字段过长、类型非法、分类名为空等）本就面向 ``except ValueError`` 处理范式
    （UI 校验处理器、测试 ``pytest.raises(ValueError)``），保留 ValueError 兼容
    使其既能被领域精确捕获，也可经既有 ValueError 兜底承接，与
    :class:`DecryptionError` / :class:`PayloadTooLargeError` 的双重继承策略一致。
    业务层仍应优先 ``except EntryError`` 精确捕获，避免裸 ``except ValueError``
    连带吞掉无关 ValueError。
    """


class EntryIntegrityError(EntryError):
    """条目完整性异常，字段解密失败或元数据签名校验不通过。

    亦覆盖「密文已解密但结构损坏」的场景（如 custom_fields 密文解密后非合法
    JSON 或结构不符），与解密层损坏（:class:`DecryptionError`）区分：后者是
    GCM 认证失败/密钥问题，前者是密文已通过认证但内容损坏。
    """


class BackupError(CipherBoxError):
    """备份/恢复操作异常。"""


class PayloadTooLargeError(BackupError, ValueError):
    """数据/文件/字段超出大小上限。

    双重继承 ``BackupError`` 与 ``ValueError``：上层既可经 ``except BackupError``
    归入备份错误映射，也可被 ``except ValueError`` 兜底。替代原先以
    ``'过大' in str(exc)`` 字符串匹配判别大小超限的脆弱方式。
    """


class ImportError(CipherBoxError):
    """导入数据解析或校验异常。

    注意：此类名与 Python 内置 ``ImportError``（``import`` 语句失败）同名，
    但属于 CipherBox 导入数据领域。本模块及其导入方均不依赖内置 ``ImportError``
    （无可选 import 需捕获该内置异常），故同名遮蔽在本项目内安全。
    """


class ImportFormatError(ImportError):
    """导入文件格式或结构无效（如非 CipherBox JSON、字段类型不符）。"""


class ImportSizeError(ImportError):
    """导入数据超出数量或大小上限（条目过多、字段/文件过大）。"""


class DatabaseError(CipherBoxError, RuntimeError):
    """数据库操作异常，可被 ``except RuntimeError`` 捕获。"""


class TransactionError(DatabaseError):
    """事务状态异常。"""


class SchemaError(DatabaseError):
    """数据库 schema 异常。"""
