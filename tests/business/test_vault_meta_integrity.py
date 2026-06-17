"""vault_meta 完整性签名测试。

验证 unlock 的 vault_meta 完整性校验（强制）：篡改安全相关字段（如 key_epoch）
后即使主密码正确也会因 vault_meta_mac 不符而被拒绝；签名缺失亦被拒绝。
"""
import pytest

from src.business.managers.vault_manager import VaultManager
from src.exceptions import VaultIntegrityError


class TestVaultMetaIntegrity:
    def test_normal_unlock_passes(self, vault_config):
        """正常库的 vault_meta_mac 与 unlock 重算一致，解锁通过。"""
        vault = VaultManager(vault_config)
        vault.initialize("test_password_12345")
        vault.close()
        vault2 = VaultManager(vault_config)
        try:
            ok, msg = vault2.unlock("test_password_12345")
            assert ok, msg
        finally:
            vault2.close()

    def test_tampered_key_epoch_rejected(self, vault_config):
        """篡改 key_epoch 但不更新 vault_meta_mac → unlock 拒绝。

        verify_token 解密仍成功（凭据未改），但 vault_meta_mac 校验不符，
        抛 VaultIntegrityError 阻止在篡改后的元数据上解锁。
        """
        vault = VaultManager(vault_config)
        vault.initialize("test_password_12345")
        conn = vault.db._conn
        assert conn is not None
        conn.execute(
            "UPDATE vault_meta SET value=? WHERE key='key_epoch'",
            ('tampered_epoch_value',),
        )
        conn.commit()
        vault.close()

        vault2 = VaultManager(vault_config)
        try:
            with pytest.raises(VaultIntegrityError):
                vault2.unlock("test_password_12345")
        finally:
            vault2.close()

    def test_missing_meta_mac_rejected(self, vault_config):
        """vault_meta_mac 缺失（被删除）→ unlock 拒绝（强制校验契约）。

        initialize/改密/恢复均写入 mac，缺失意味着签名被删除篡改或为不兼容旧格式。
        """
        vault = VaultManager(vault_config)
        vault.initialize("test_password_12345")
        conn = vault.db._conn
        assert conn is not None
        conn.execute("DELETE FROM vault_meta WHERE key='vault_meta_mac'")
        conn.commit()
        vault.close()

        vault2 = VaultManager(vault_config)
        try:
            with pytest.raises(VaultIntegrityError):
                vault2.unlock("test_password_12345")
        finally:
            vault2.close()
