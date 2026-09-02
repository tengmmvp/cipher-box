"""vault_meta_keys 单一事实源不变量测试。

键集常量（ALL/SIGNED/KDF 参数键）是 unlock 批量读取与完整性签名的派生基础：
漏登记新键会使写入即签错、下次 unlock 比对失败；SIGNED 多含 ``vault_meta_mac``
会自指签名、多含 ``master_kdf`` 会把信息性键纳入 MAC 载荷。此处锚定派生关系。
"""

from src.business.services.vault_meta_keys import (
    KDF_MEMORY_COST_KEY,
    KDF_PARALLELISM_KEY,
    KDF_PARAM_KEYS,
    KDF_TIME_COST_KEY,
    VAULT_META_ALL_KEYS,
    VAULT_META_SIGNED_KEYS,
)


class TestVaultMetaKeysInvariants:
    """键集派生关系与无重复不变量。"""

    def test_kdf_param_keys_complete(self):
        """KDF 三参数键齐备且与 KdfParams 字段一一对应。"""
        assert KDF_PARAM_KEYS == (
            KDF_TIME_COST_KEY,
            KDF_MEMORY_COST_KEY,
            KDF_PARALLELISM_KEY,
        )

    def test_kdf_keys_within_all_keys(self):
        """KDF 参数键登记在 ALL_KEYS（unlock 读取与签名覆盖同步）。"""
        assert set(KDF_PARAM_KEYS) <= set(VAULT_META_ALL_KEYS)

    def test_all_keys_no_duplicates(self):
        """ALL_KEYS 无重复键（重复会致 unlock 批量读取顺序漂移）。"""
        assert len(VAULT_META_ALL_KEYS) == len(set(VAULT_META_ALL_KEYS))

    def test_signed_keys_derive_from_all(self):
        """SIGNED = ALL − {master_kdf, vault_meta_mac}（信息性键与签名自身排除）。"""
        assert set(VAULT_META_SIGNED_KEYS) == set(VAULT_META_ALL_KEYS) - {
            "master_kdf",
            "vault_meta_mac",
        }

    def test_mac_key_never_signed(self):
        """vault_meta_mac 不在签名键集（签名不能含自身）。"""
        assert "vault_meta_mac" not in VAULT_META_SIGNED_KEYS

    def test_signed_subset_of_all(self):
        """SIGNED ⊆ ALL（签名键不得逸出 unlock 读取键集）。"""
        assert set(VAULT_META_SIGNED_KEYS) <= set(VAULT_META_ALL_KEYS)

    def test_sensitive_keys_are_signed(self):
        """安全相关键（salt/verify/epoch/snapshot_key_enc）均在签名覆盖内。"""
        signed = set(VAULT_META_SIGNED_KEYS)
        for key in ("master_salt", "master_verify", "key_epoch", "snapshot_key_enc"):
            assert key in signed
