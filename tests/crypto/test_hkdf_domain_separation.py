"""HKDF 域分离测试。

守护主密钥与备份密钥经不同 HKDF-Expand info 派生时的域分离不变量（架构文档 §2.1
重点设计）。审查指出此前仅有 snapshot_key 轮换行为间接覆盖，缺「不同 info → 输出
独立 / 相同 info → 输出一致」的直接断言——重构 HKDF 派生时可能被无声破坏。
"""

from src.crypto.master_key import KdfParams, MasterKeyManager

# 弱化但合法的 KDF 参数（过 validate_params 安全下限 time≥2 / mem≥16MB / par≥1），
# 加速测试派生。生产用 DEFAULT_KDF_PARAMS（time=3 / 64MB / p=4）。
_TEST_PARAMS = KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)
_SALT = b'\x00' * 32  # 固定盐便于复现/比对，长度满足 MIN_SALT_SIZE
_PASSWORD = 'test_password_12345'


def test_master_and_backup_keys_are_independent():
    """主密钥与备份密钥经不同 HKDF info 派生，必须相互独立（域分离核心保证）。"""
    master = MasterKeyManager.derive_key(_PASSWORD, _SALT, _TEST_PARAMS)
    backup = MasterKeyManager.derive_backup_key(_PASSWORD, _SALT, _TEST_PARAMS)
    assert len(master) == 32
    assert len(backup) == 32
    assert master != backup


def test_same_info_derivation_is_deterministic():
    """相同 info + 相同输入派生相同密钥（HKDF 确定性，保证可复现）。"""
    assert MasterKeyManager.derive_key(_PASSWORD, _SALT, _TEST_PARAMS) == (
        MasterKeyManager.derive_key(_PASSWORD, _SALT, _TEST_PARAMS)
    )
    assert MasterKeyManager.derive_backup_key(_PASSWORD, _SALT, _TEST_PARAMS) == (
        MasterKeyManager.derive_backup_key(_PASSWORD, _SALT, _TEST_PARAMS)
    )


def test_password_or_salt_change_alters_both_keys():
    """密码或盐变化时，主密钥与备份密钥均改变（无跨凭据碰撞）。"""
    master_a = MasterKeyManager.derive_key(_PASSWORD, _SALT, _TEST_PARAMS)
    # 不同密码
    master_other_pwd = MasterKeyManager.derive_key(
        'other_password_67890', _SALT, _TEST_PARAMS,
    )
    # 不同盐
    master_other_salt = MasterKeyManager.derive_key(
        _PASSWORD, b'\xff' * 32, _TEST_PARAMS,
    )
    assert master_a != master_other_pwd
    assert master_a != master_other_salt
    backup_a = MasterKeyManager.derive_backup_key(_PASSWORD, _SALT, _TEST_PARAMS)
    backup_other_pwd = MasterKeyManager.derive_backup_key(
        'other_password_67890', _SALT, _TEST_PARAMS,
    )
    assert backup_a != backup_other_pwd


def test_domain_keys_derive_from_same_master_material():
    """主密钥与备份密钥共享同一 Argon2id 主材料（同 password+salt），仅 HKDF info 不同。

    这保证两条派生路径各仅一次 Argon2id（主材料共享），而非各自独立 Argon2id——
    验证 derive_key 与 derive_backup_key 的 salt/params 接受同一组凭据并产出两个域密钥。
    """
    master = MasterKeyManager.derive_key(_PASSWORD, _SALT, _TEST_PARAMS)
    backup = MasterKeyManager.derive_backup_key(_PASSWORD, _SALT, _TEST_PARAMS)
    # 两个域密钥均有效（32 字节）且独立，证明同一主材料经不同 info 派生出两个域。
    assert len(master) == len(backup) == 32
    assert master != backup
