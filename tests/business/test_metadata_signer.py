"""MetadataSigner 单元测试：签名往返、篡改检测、域密钥派生、跨 epoch 签名失效与 vault_meta MAC 字段绑定。"""

import dataclasses
import os

import pytest

from src.business.services.metadata_signer import (
    VAULT_META_SIGNED_KEYS,
    MetadataSigner,
)
from src.exceptions import VaultIntegrityError, VaultLockedError
from src.models import Category, RawEntry


def _make_entry(**overrides) -> RawEntry:
    """构造用于测试的 RawEntry（签名操作密文态），提供合理默认值。"""
    entry = RawEntry(
        crypto_id="test-crypto-id-001",
        title="示例条目",
        username="",
        password="",
        url="",
        category_id=None,
        tags="",
        notes="",
        custom_fields="",
        is_favorite=False,
        is_deleted=False,
        password_strength=0,
        entry_type="login",
        totp_secret="",
        created_at="2025-01-01T00:00:00",
        updated_at="2025-01-01T00:00:00",
        deleted_at="",
        password_changed_at="",
        metadata_mac="",
    )
    return dataclasses.replace(entry, **overrides)


def _make_category(**overrides) -> Category:
    """构造用于测试的 Category（name 为密文态，与签名载荷预期一致），提供合理默认值。"""
    category = Category(
        id=1,
        name="cb2:category-name-ciphertext",
        icon_char="[DIR]",
        color="#666666",
        sort_order=0,
        created_at="2025-01-01T00:00:00",
        metadata_mac="",
    )
    return dataclasses.replace(category, **overrides)


def test_verify_passes_on_untampered_entry():
    """verify() 正常验证，未篡改条目验证通过。"""
    master_key = b"test-master-key-for-verify"
    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key))
    entry = _make_entry()

    entry = dataclasses.replace(entry, metadata_mac=signer.sign(entry))

    # 不应抛出任何异常
    signer.verify(entry)


def test_verify_detects_tampered_title():
    """verify() 篡改检测，修改 title 后验证失败。"""
    master_key = b"test-master-key-for-tamper"
    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key))
    entry = _make_entry(title="原始标题")

    entry = dataclasses.replace(entry, metadata_mac=signer.sign(entry))

    entry = dataclasses.replace(entry, title="被篡改的标题")

    with pytest.raises(VaultIntegrityError):
        signer.verify(entry)


def test_verify_raises_when_no_key():
    """verify() 无域密钥时抛异常。"""
    signer = MetadataSigner()  # domain_key 为 None
    entry = _make_entry()
    entry = dataclasses.replace(entry, metadata_mac="some-mac-value")

    with pytest.raises(VaultLockedError):
        signer.verify(entry)


def test_sign_with_domain_key_matches_sign():
    """sign_with_domain_key() 与预设同一域密钥的 sign() 结果一致。"""
    master_key = b"test-master-key-for-dk"
    domain_key = MetadataSigner.compute_domain_key(master_key)
    signer = MetadataSigner(domain_key=domain_key)
    entry = _make_entry()

    mac_via_domain_key = signer.sign_with_domain_key(entry, domain_key)
    mac_via_sign = signer.sign(entry)

    assert mac_via_domain_key == mac_via_sign


def test_compute_domain_key_returns_bytearray():
    """compute_domain_key() 返回 32 字节 bytearray，以便 secure_zero 真正清零。"""
    master_key = b"any-key-material"
    dk = MetadataSigner.compute_domain_key(master_key)

    assert isinstance(dk, bytearray)
    assert len(dk) == 32  # SHA-256 output
    assert dk != master_key  # 派生结果应不同于输入


def test_sign_uses_preset_domain_key():
    """sign() 使用构造时设置的域密钥。"""
    master_key = b"test-key-for-preset"
    domain_key = MetadataSigner.compute_domain_key(master_key)
    signer = MetadataSigner(domain_key=domain_key)
    entry = _make_entry()

    mac = signer.sign(entry)

    assert isinstance(mac, str)
    assert len(mac) == 64

    # 用同一域密钥验证
    entry = dataclasses.replace(entry, metadata_mac=mac)
    signer.verify(entry)


def test_verify_no_mac_raises_integrity_error():
    """verify() 条目 metadata_mac 为空时抛 VaultIntegrityError。"""
    signer = MetadataSigner(domain_key=b"x" * 32)
    entry = _make_entry()
    entry = dataclasses.replace(entry, metadata_mac="")

    with pytest.raises(VaultIntegrityError, match="缺少元数据完整性签名"):
        signer.verify(entry)


def test_sign_without_domain_key_raises():
    """sign() 域密钥未设置时抛 VaultLockedError。"""
    signer = MetadataSigner()  # domain_key 为 None
    entry = _make_entry()

    with pytest.raises(VaultLockedError):
        signer.sign(entry)


def test_different_entries_produce_different_macs():
    """不同条目应产生不同签名。"""
    master_key = b"test-key-for-diff"
    domain_key = MetadataSigner.compute_domain_key(master_key)
    signer = MetadataSigner(domain_key=domain_key)
    entry_a = _make_entry(title="条目 A")
    entry_b = _make_entry(title="条目 B")

    mac_a = signer.sign(entry_a)
    mac_b = signer.sign(entry_b)

    assert mac_a != mac_b


def test_payload_length_prefix_prevents_ciphertext_collision():
    """长度前缀拼接消除密文歧义：朴素 '|' 拼接会碰撞的密文对产生不同载荷。

    回归守护 ``_payload`` 的 ``f'{len(p)}:{p}'`` 长度前缀设计——若未来误改为
    固定分隔符拼接，此测试会失败（两 entry 载荷将相同，签名亦相同）。
    """
    # 朴素 '|' join 下两 entry 的密文字段拼接完全相同（歧义场景）：
    # ('a', 'b|c') 与 ('a|b', 'c') 的 u|p 拼接均为 'a|b|c'，字段边界歧义
    entry_a = _make_entry(username="a", password="b|c")
    entry_b = _make_entry(username="a|b", password="c")

    def naive_concat(entry: RawEntry) -> str:
        return "|".join(
            [
                entry.username,
                entry.password,
                entry.notes,
                entry.totp_secret,
                entry.custom_fields,
            ]
        )

    assert naive_concat(entry_a) == naive_concat(entry_b)  # 朴素拼接确有歧义

    # 长度前缀载荷不同 → _enc_hash 不同 → 签名不同
    assert MetadataSigner._payload(entry_a) != MetadataSigner._payload(entry_b)


def test_verify_detects_ciphertext_field_tamper():
    """密文字段（password）被置换/篡改后 verify 失败。

    _enc_hash 绑定密文防止密文置换/回滚攻击；现有篡改测试仅覆盖明文 title，
    此测试补齐密文字段篡改的回归守护。
    """
    master_key = b"test-key-for-cipher-tamper"
    signer = MetadataSigner(domain_key=MetadataSigner.compute_domain_key(master_key))
    entry = _make_entry(password="cb2:original-ciphertext")
    entry = dataclasses.replace(entry, metadata_mac=signer.sign(entry))
    # 模拟密文置换/回滚攻击：仅改密文字段，不改明文元数据
    entry = dataclasses.replace(entry, password="cb2:attacker-ciphertext")
    with pytest.raises(VaultIntegrityError):
        signer.verify(entry)


# 跨 epoch / 密钥轮换的签名失效：旧签名在新域密钥下验证必须失败。


def test_verify_fails_after_domain_key_rotation():
    """跨 epoch 条目签名失效：用 domain_key_A 签名后，换 domain_key_B verify 必抛错。

    set_domain_key(A) → sign → set_domain_key(B) → verify 同 entry 必失败，
    验证域密钥原地轮换后旧签名失效（同时守护 set_domain_key 真正替换而非累积）。
    """
    master_key_a = os.urandom(32)
    master_key_b = os.urandom(32)

    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key_a))
    entry = _make_entry()
    entry = dataclasses.replace(entry, metadata_mac=signer.sign(entry))

    # 模拟改密/恢复后的域密钥轮换：用不同主密钥派生新域密钥并原地替换
    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key_b))
    with pytest.raises(VaultIntegrityError):
        signer.verify(entry)


def test_verify_category_fails_after_domain_key_rotation():
    """跨 epoch 分类签名失效：用 domain_key_A 签名后，换 domain_key_B verify_category 必抛错。

    与条目签名共享同一域密钥，故跨 epoch 隔离同样由域密钥轮换提供。守护改密时
    re_encrypt_categories 必须用新域密钥重签分类——否则改密后 verify_category 永久失败；
    反向守护：若重构误使旧分类签名在新 key 下验证通过，此测试会失败。
    """
    master_key_a = os.urandom(32)
    master_key_b = os.urandom(32)

    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key_a))
    category = _make_category()
    category = dataclasses.replace(category, metadata_mac=signer.sign_category(category))

    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key_b))
    with pytest.raises(VaultIntegrityError):
        signer.verify_category(category)


# compute_vault_meta_mac 字段绑定边界测试用的基准值（覆盖全部 VAULT_META_SIGNED_KEYS）。
_BASE_VAULT_META = {
    "master_salt": "salt-abc",
    "master_verify": "verify-token",
    "master_kdf_time_cost": 3,
    "master_kdf_memory_cost": 65536,
    "master_kdf_parallelism": 4,
    "ciphertext_format": "cb2",
    "key_epoch": 1,
    "snapshot_key_enc": "cb2:snapshot-original",
}
# 每个签字段的篡改值（类型与原值一致，仅内容不同），供参数化篡改测试使用。
_VAULT_META_TAMPERED_VALUES = {
    "master_salt": "salt-attacker",
    "master_verify": "verify-attacker",
    "master_kdf_time_cost": 99,
    "master_kdf_memory_cost": 32768,
    "master_kdf_parallelism": 8,
    "ciphertext_format": "cb3",
    "key_epoch": 2,
    "snapshot_key_enc": "cb2:snapshot-attacker",
}


@pytest.mark.parametrize("signed_key", VAULT_META_SIGNED_KEYS)
def test_compute_vault_meta_mac_binds_each_signed_field(signed_key):
    """compute_vault_meta_mac 对每一个 VAULT_META_SIGNED_KEYS 字段都绑定：篡改任一字段 mac 必变。

    参数化遍历全部签字段（而非仅抽 master_kdf_time_cost 一例），完整守护「任一签字段
    被篡改→mac 变化」的不变式。若重构误把某字段从 VAULT_META_SIGNED_KEYS 移除或载荷
    构造误漏某键，对应参数用例会失败。
    """
    master_key = os.urandom(32)
    meta = dict(_BASE_VAULT_META)
    mac_original = MetadataSigner.compute_vault_meta_mac(meta, master_key)

    meta[signed_key] = _VAULT_META_TAMPERED_VALUES[signed_key]
    mac_tampered = MetadataSigner.compute_vault_meta_mac(meta, master_key)

    assert mac_original != mac_tampered


def test_compute_vault_meta_mac_ignores_unsigned_field():
    """compute_vault_meta_mac 篡改非签字段（master_kdf KDF 名）后 mac 不变。

    master_kdf（KDF 名，如 'argon2id'）不纳入 VAULT_META_SIGNED_KEYS——它仅作格式
    标识，其校验由 unlock 显式比对（meta['master_kdf'] != KDF_NAME 即拒绝），无需
    MAC 绑定。守护此排除是有意的：若误把非安全字段纳入签名，会增加无谓的 mac 失配
    面。注意 snapshot_key_enc 已纳入签名（防 GCM 重放回滚），不再是"非签字段"。
    """
    master_key = os.urandom(32)
    meta = dict(_BASE_VAULT_META, master_kdf="argon2id")
    mac_original = MetadataSigner.compute_vault_meta_mac(meta, master_key)

    meta["master_kdf"] = "pbkdf2"
    mac_tampered = MetadataSigner.compute_vault_meta_mac(meta, master_key)

    assert mac_original == mac_tampered


def test_verify_category_no_mac_raises_integrity_error():
    """verify_category() 分类 metadata_mac 为空时抛 VaultIntegrityError。

    与条目 verify() 的空签名拒绝对称——分类元数据篡改（icon/color/sort_order 等非加密
    字段）若仅记日志、空签名不拒绝，会使分类层 HMAC 失败对用户静默通过。
    """
    signer = MetadataSigner(domain_key=b"x" * 32)
    category = _make_category()
    category = dataclasses.replace(category, metadata_mac="")

    with pytest.raises(VaultIntegrityError, match="缺少元数据完整性签名"):
        signer.verify_category(category)
