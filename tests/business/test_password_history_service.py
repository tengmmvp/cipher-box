"""``PasswordHistoryService`` 子域服务测试。

覆盖 ``src/business/services/password_history_service.py``：
- ``decrypt`` 正常解密密码历史、解密失败的损坏记录静默跳过。
- ``get`` / ``get_count`` 委托 vault.db。

经 MagicMock 注入 vault（``is_unlocked``/``key``/``vault_write_lock`` 满足
``require_vault_key`` 与持锁契约），真实加解密经 ``crypto_utils.encrypt_field`` /
``decrypt_field`` 的单一域分离路径（``entry:<crypto_id>:password``）。
"""

import logging
from unittest.mock import MagicMock

from src.business.services.crypto_utils import encrypt_field
from src.business.services.password_history_service import PasswordHistoryService
from src.models import PasswordHistory

_KEY = b"\x00" * 32


def _make_vault() -> MagicMock:
    """构造解锁态 vault mock，vault_write_lock 作为上下文管理器可用。"""
    vault = MagicMock()
    vault.is_unlocked = True
    vault.key = _KEY
    return vault


def _hist(crypto_id: str, enc: str, changed_at: str = "2026-01-01T00:00:00Z") -> PasswordHistory:
    return PasswordHistory(
        id=1,
        entry_id=10,
        old_password_enc=enc,
        changed_at=changed_at,
        entry_crypto_id=crypto_id,
    )


class TestDecrypt:
    """PasswordHistoryService.decrypt 测试：正常解密、损坏记录跳过与持锁契约。"""

    def test_decrypt_returns_decrypted_passwords(self):
        """正常加密的历史密码经 decrypt 返回带 changed_at 与明文密码的字典。"""
        vault = _make_vault()
        history = [
            _hist(
                "cid", encrypt_field("old-pwd-1", _KEY, "cid", "password"), "2026-01-01T00:00:00Z"
            ),
            _hist(
                "cid", encrypt_field("old-pwd-2", _KEY, "cid", "password"), "2026-02-01T00:00:00Z"
            ),
        ]
        svc = PasswordHistoryService(vault)

        result = svc.decrypt(history)

        assert len(result) == 2
        assert result[0]["password"] == "old-pwd-1"
        assert "changed_at" in result[0]
        assert result[1]["password"] == "old-pwd-2"

    def test_decrypt_skips_failed_decryption(self, caplog):
        """解密失败的损坏记录静默跳过（lenient decrypt_field 返回 ''），仅保留成功项。

        损坏密文经 decrypt_field(strict=False) 返回 ''，被 ``if pwd`` 过滤；记 warning
        便于排查但不抛异常，避免单条损坏历史阻断整个列表展示。
        """
        vault = _make_vault()
        good = _hist("cid", encrypt_field("good-pwd", _KEY, "cid", "password"))
        corrupt = _hist("cid", "cb2:!!corrupt!!")  # 合法 cb2: 前缀但内容损坏
        svc = PasswordHistoryService(vault)

        with caplog.at_level(
            logging.WARNING, logger="src.business.services.password_history_service"
        ):
            result = svc.decrypt([good, corrupt])

        assert len(result) == 1
        assert result[0]["password"] == "good-pwd"
        assert any("解密失败" in r.message for r in caplog.records)

    def test_decrypt_holds_vault_write_lock(self):
        """decrypt 接触全量明文密码，持 vault_write_lock 保证与 lock() 串行。

        守卫：持锁契约不被移除——否则 lock() 可能在解密中途清零主密钥，用失效密钥
        解密得到错误结果或抛异常。
        """
        vault = _make_vault()
        vault.vault_write_lock = MagicMock()
        svc = PasswordHistoryService(vault)

        svc.decrypt([_hist("cid", encrypt_field("p", _KEY, "cid", "password"))])

        vault.vault_write_lock.assert_called_once()

    def test_decrypt_empty_history_returns_empty(self):
        vault = _make_vault()
        svc = PasswordHistoryService(vault)
        assert svc.decrypt([]) == []


class TestGetAndGetCount:
    """get / get_count 委托 vault.db 的查询与计数。"""

    def test_get_delegates_to_db(self):
        vault = _make_vault()
        vault.db.get_password_history.return_value = ["h1", "h2"]
        svc = PasswordHistoryService(vault)

        result = svc.get(5)

        vault.db.get_password_history.assert_called_once_with(5)
        assert result == ["h1", "h2"]

    def test_get_count_delegates_to_db(self):
        vault = _make_vault()
        vault.db.get_password_history_count.return_value = 7
        svc = PasswordHistoryService(vault)

        assert svc.get_count(3) == 7
        vault.db.get_password_history_count.assert_called_once_with(3)
