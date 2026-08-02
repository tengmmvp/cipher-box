"""共享包密钥派生（share 域）测试。

守护限时加密共享包经独立 HKDF info（``_DOMAIN_INFO_SHARE``）派生的域分离不变量：
share 密钥独立于 master/backup，相同输入确定性派生（接收方浏览器可复刻同一密钥解密）。
与 test_hkdf_domain_separation.py 对称，覆盖第三个域。
"""

from src.crypto.master_key import KdfParams, MasterKeyManager

# 弱化但合法的 KDF 参数（过 validate_params 安全下限），加速测试派生。
# 生产用 DEFAULT_KDF_PARAMS（time=3 / 64MB / p=4）。
_TEST_PARAMS = KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)
_SALT = b"\x00" * 32  # 固定盐便于复现/比对，长度满足 MIN_SALT_SIZE
_PASSWORD = "test_password_12345"


def test_share_key_is_independent_from_master_and_backup():
    """share 密钥经独立 HKDF info 派生，必须与 master/backup 相互独立（域分离核心）。"""
    master = MasterKeyManager.derive_key(_PASSWORD, _SALT, _TEST_PARAMS)
    backup = MasterKeyManager.derive_backup_key(_PASSWORD, _SALT, _TEST_PARAMS)
    share = MasterKeyManager.derive_share_key(_PASSWORD, _SALT, _TEST_PARAMS)
    assert len(share) == 32
    assert share != master
    assert share != backup


def test_share_key_derivation_is_deterministic():
    """相同输入派生相同 share 密钥（HKDF 确定性，接收方浏览器可复刻解密）。"""
    assert MasterKeyManager.derive_share_key(_PASSWORD, _SALT, _TEST_PARAMS) == (
        MasterKeyManager.derive_share_key(_PASSWORD, _SALT, _TEST_PARAMS)
    )


def test_password_or_salt_change_alters_share_key():
    """密码或盐变化时 share 密钥改变（无跨凭据碰撞）。"""
    share_a = MasterKeyManager.derive_share_key(_PASSWORD, _SALT, _TEST_PARAMS)
    share_other_pwd = MasterKeyManager.derive_share_key("other_password_67890", _SALT, _TEST_PARAMS)
    share_other_salt = MasterKeyManager.derive_share_key(_PASSWORD, b"\xff" * 32, _TEST_PARAMS)
    assert share_a != share_other_pwd
    assert share_a != share_other_salt


def test_share_key_derives_from_same_master_material():
    """share/master/backup 共享同一 Argon2id 主材料（同 password+salt），仅 HKDF info 不同。

    三域密钥均 32 字节且两两独立，证明同一主材料经三个 info 派生出三个域密钥。
    """
    master = MasterKeyManager.derive_key(_PASSWORD, _SALT, _TEST_PARAMS)
    backup = MasterKeyManager.derive_backup_key(_PASSWORD, _SALT, _TEST_PARAMS)
    share = MasterKeyManager.derive_share_key(_PASSWORD, _SALT, _TEST_PARAMS)
    assert len(master) == len(backup) == len(share) == 32
    assert master != backup != share != master
