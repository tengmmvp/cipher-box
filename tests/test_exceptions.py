"""领域异常层次测试。

守护多继承关系（见 :mod:`src.exceptions` 模块 docstring 警告）：领域异常刻意多重继承
标准异常，使上层可经 ``except ValueError`` / ``except RuntimeError`` 兜底捕获。重构时若
误移除这些继承会破坏兜底语义，本测试以 ``issubclass`` 固化契约（M9）。
"""

import pytest

from src.exceptions import (
    BackupError,
    CipherBoxError,
    DatabaseError,
    DecryptionError,
    EntryError,
    PayloadTooLargeError,
    VaultError,
)

_DOMAIN_ERRORS = [
    VaultError,
    DatabaseError,
    DecryptionError,
    EntryError,
    BackupError,
    PayloadTooLargeError,
]


class TestExceptionHierarchy:
    """所有领域异常均为 CipherBoxError 子类。"""

    @pytest.mark.parametrize("exc_cls", _DOMAIN_ERRORS)
    def test_all_domain_errors_are_cipherbox_errors(self, exc_cls):
        """每个领域异常均派生自 CipherBoxError，统一为可捕获的项目异常基类。"""
        assert issubclass(exc_cls, CipherBoxError)


class TestMultipleInheritance:
    """多继承标准异常的兜底契约（M9）：重构误移除会破坏 except 兜底。"""

    def test_vault_error_is_runtime_error(self):
        assert issubclass(VaultError, RuntimeError)

    def test_database_error_is_runtime_error(self):
        assert issubclass(DatabaseError, RuntimeError)

    def test_decryption_error_is_value_error(self):
        assert issubclass(DecryptionError, ValueError)

    def test_entry_error_is_value_error(self):
        assert issubclass(EntryError, ValueError)

    def test_payload_too_large_error_is_value_error(self):
        assert issubclass(PayloadTooLargeError, ValueError)

    def test_payload_too_large_error_is_backup_error(self):
        """PayloadTooLargeError 双重继承 BackupError + ValueError，两者兜底都生效。"""
        assert issubclass(PayloadTooLargeError, BackupError)
        assert issubclass(PayloadTooLargeError, ValueError)

    def test_catch_value_error_subsumes_entry_error(self):
        """except ValueError 兜底能捕获 EntryError（UI 校验/测试范式依赖，M9）。"""
        caught: ValueError | None = None
        try:
            raise EntryError("bad input")
        except ValueError as exc:
            caught = exc
        assert isinstance(caught, EntryError)

    def test_catch_runtime_error_subsumes_vault_error(self):
        """except RuntimeError 兜底能捕获 VaultError（M9）。"""
        caught: RuntimeError | None = None
        try:
            raise VaultError("vault fault")
        except RuntimeError as exc:
            caught = exc
        assert isinstance(caught, VaultError)
