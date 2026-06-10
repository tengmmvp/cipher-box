"""CipherBox 自定义异常层次结构。

提供领域化的异常类型，替代散落在各层的 RuntimeError / ValueError。
继承关系设计确保向后兼容：

- VaultError / DatabaseError 继承 RuntimeError → 现有 ``except RuntimeError`` 仍可捕获
- CryptoError 继承 ValueError → 现有 ``except ValueError`` 仍可捕获
"""

__all__ = [
    'CipherBoxError',
    'VaultError',
    'VaultLockedError',
    'VaultIntegrityError',
    'VaultKeyEpochMismatchError',
    'VaultAlreadyInitializedError',
    'CryptoError',
    'DecryptionError',
    'EntryError',
    'EntryIntegrityError',
    'BackupError',
    'BackupCorruptionError',
    'DatabaseError',
    'TransactionError',
    'SchemaError',
]


class CipherBoxError(Exception):
    """CipherBox 所有自定义异常的基类。"""


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class VaultError(CipherBoxError, RuntimeError):
    """保险库操作异常（兼容 ``except RuntimeError``）。"""


class VaultLockedError(VaultError):
    """保险库未解锁。"""


class VaultIntegrityError(VaultError):
    """元数据完整性校验失败。"""


class VaultKeyEpochMismatchError(VaultError):
    """主密钥版本不匹配（可能被其他进程更新）。"""


class VaultAlreadyInitializedError(VaultError):
    """保险库已初始化，不能重复设置主密码。"""


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

class CryptoError(CipherBoxError, ValueError):
    """加密/解密操作异常（兼容 ``except ValueError``）。"""


class DecryptionError(CryptoError):
    """解密失败。"""


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

class EntryError(CipherBoxError):
    """条目操作异常。"""


class EntryIntegrityError(EntryError):
    """条目完整性异常（字段解密失败或元数据签名校验不通过）。"""


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

class BackupError(CipherBoxError):
    """备份/恢复操作异常。"""


class BackupCorruptionError(BackupError):
    """备份数据损坏或格式无效。"""


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class DatabaseError(CipherBoxError, RuntimeError):
    """数据库操作异常（兼容 ``except RuntimeError``）。"""


class TransactionError(DatabaseError):
    """事务状态异常。"""


class SchemaError(DatabaseError):
    """数据库 schema 异常。"""
