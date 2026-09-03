"""vault_meta_keys 单一事实源不变量测试。

键集常量（ALL/SIGNED/KDF 参数键）是 unlock 批量读取与完整性签名的派生基础：
漏登记新键会使写入即签错、下次 unlock 比对失败。此处锚定**跨键集语义关系**
（包含性/无重复/敏感键覆盖），不复述源码定义本身——「KDF_PARAM_KEYS == 三常量
元组」「SIGNED == ALL − 两个排除键」等源码公式的镜像断言已删除（源码改定义时
镜像必然同步手改，不构成回归守护）。
"""

from src.business.services.vault_meta_keys import (
    KDF_PARAM_KEYS,
    VAULT_META_ALL_KEYS,
    VAULT_META_SIGNED_KEYS,
)


class TestVaultMetaKeysInvariants:
    """键集派生关系与无重复不变量。"""

    def test_kdf_keys_within_all_keys(self):
        """KDF 参数键登记在 ALL_KEYS（unlock 读取与签名覆盖同步）。"""
        assert set(KDF_PARAM_KEYS) <= set(VAULT_META_ALL_KEYS)

    def test_all_keys_no_duplicates(self):
        """ALL_KEYS 无重复键（重复会致 unlock 批量读取顺序漂移）。"""
        assert len(VAULT_META_ALL_KEYS) == len(set(VAULT_META_ALL_KEYS))

    def test_signed_subset_of_all(self):
        """SIGNED ⊆ ALL（签名键不得逸出 unlock 读取键集）。"""
        assert set(VAULT_META_SIGNED_KEYS) <= set(VAULT_META_ALL_KEYS)

    def test_sensitive_keys_are_signed(self):
        """安全相关键（salt/verify/epoch/snapshot_key_enc）均在签名覆盖内。"""
        signed = set(VAULT_META_SIGNED_KEYS)
        for key in ("master_salt", "master_verify", "key_epoch", "snapshot_key_enc"):
            assert key in signed
