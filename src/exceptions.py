"""CipherBox 自定义异常层次结构。

提供领域化的异常类型，替代散落在各层的 RuntimeError / ValueError。
部分异常通过多重继承同时属于 CipherBoxError 和标准异常类型，
使调用方既可精确捕获领域异常，也可通过 ``except ValueError`` /
``except RuntimeError`` 兜底捕获。

.. warning::

    多重继承意味着 ``DecryptionError`` / ``PayloadTooLargeError`` 也是 ``ValueError``，
    ``VaultError`` / ``DatabaseError`` 也是 ``RuntimeError``。**捕获这些标准异常时会
    连带捕获对应的领域异常子类**——若某处用 ``except ValueError:`` 兜底，会同时吞掉
    ``DecryptionError`` 等领域异常而掩盖真实问题。应优先捕获具体的 ``CipherBox``
    异常，仅在确认要兜底时才用标准异常基类。
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


class EntryError(CipherBoxError):
    """条目操作异常。"""


class EntryIntegrityError(EntryError):
    """条目完整性异常，字段解密失败或元数据签名校验不通过。"""


class BackupError(CipherBoxError):
    """备份/恢复操作异常。"""


class PayloadTooLargeError(BackupError, ValueError):
    """数据/文件/字段超出大小上限。

    双重继承 ``BackupError`` 与 ``ValueError``：上层既可经 ``except BackupError``
    归入备份错误映射，也可被 ``except ValueError`` 兜底。替代原先以
    ``'过大' in str(exc)`` 字符串匹配判别大小超限的脆弱方式。
    """


class DatabaseError(CipherBoxError, RuntimeError):
    """数据库操作异常，可被 ``except RuntimeError`` 捕获。"""


class TransactionError(DatabaseError):
    """事务状态异常。"""


class SchemaError(DatabaseError):
    """数据库 schema 异常。"""
