"""异常定义 — 已迁移至 src.exceptions，此模块保留用于向后兼容。"""

__all__ = [
    'BackupCorruptionError',
    'BackupError',
    'CipherBoxError',
    'CryptoError',
    'DatabaseError',
    'DecryptionError',
    'EntryError',
    'EntryIntegrityError',
    'SchemaError',
    'TransactionError',
    'VaultAlreadyInitializedError',
    'VaultError',
    'VaultIntegrityError',
    'VaultKeyEpochMismatchError',
    'VaultLockedError',
]

from ..exceptions import (  # noqa: F401
    BackupCorruptionError,
    BackupError,
    CipherBoxError,
    CryptoError,
    DatabaseError,
    DecryptionError,
    EntryError,
    EntryIntegrityError,
    SchemaError,
    TransactionError,
    VaultAlreadyInitializedError,
    VaultError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)
