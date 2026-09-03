"""vault_meta 完整性签名测试。

验证 unlock 的 vault_meta 完整性校验（强制）：篡改安全相关字段（如 key_epoch）
后即使主密码正确也会因 vault_meta_mac 不符而被拒绝；签名缺失亦被拒绝。

双保险库形态（建库会话 + 重开会话）经 make_vault_env 两次调用同一 root 构造：
第一个 env 初始化并 close 后，第二个 env 以 ``initialize=False`` 仅装配，凭主密码
unlock。``db._conn`` 直写 SQL 属篡改注入点（MAINT-095 豁免）。
"""

import pytest

from src.exceptions import VaultIntegrityError


class TestVaultMetaIntegrity:
    """验证 unlock 的 vault_meta_mac 校验：正常通过、篡改签字段拒绝与签名缺失拒绝。"""

    def test_normal_unlock_passes(self, make_vault_env, tmp_path):
        """正常库的 vault_meta_mac 与 unlock 重算一致，解锁通过。"""
        root = tmp_path / "vault"
        make_vault_env(root=root).vault.close()
        vault2 = make_vault_env(root=root, initialize=False).vault
        ok, msg = vault2.unlock("TestPassword123!")
        assert ok, msg

    def test_tampered_key_epoch_rejected(self, make_vault_env, tmp_path):
        """篡改 key_epoch 但不更新 vault_meta_mac → unlock 拒绝。

        verify_token 解密仍成功（凭据未改），但 vault_meta_mac 校验不符，
        抛 VaultIntegrityError 阻止在篡改后的元数据上解锁。
        """
        root = tmp_path / "vault"
        env = make_vault_env(root=root)
        conn = env.vault.db._conn
        assert conn is not None
        conn.execute(
            "UPDATE vault_meta SET value=? WHERE key='key_epoch'",
            ("tampered_epoch_value",),
        )
        conn.commit()
        env.vault.close()

        vault2 = make_vault_env(root=root, initialize=False).vault
        with pytest.raises(VaultIntegrityError):
            vault2.unlock("TestPassword123!")

    def test_missing_meta_mac_rejected(self, make_vault_env, tmp_path):
        """vault_meta_mac 缺失（被删除）→ unlock 拒绝（强制校验契约）。

        initialize/改密/恢复均写入 mac，缺失意味着签名被删除篡改或为不兼容旧格式。
        """
        root = tmp_path / "vault"
        env = make_vault_env(root=root)
        conn = env.vault.db._conn
        assert conn is not None
        conn.execute("DELETE FROM vault_meta WHERE key='vault_meta_mac'")
        conn.commit()
        env.vault.close()

        vault2 = make_vault_env(root=root, initialize=False).vault
        with pytest.raises(VaultIntegrityError):
            vault2.unlock("TestPassword123!")
