"""MetadataSigner 单元测试。

覆盖签名生成、未篡改条目验证、篡改检测、域密钥派生与预置、
缺密钥与缺签名的异常路径，以及不同条目产生不同签名。
"""

import dataclasses

import pytest

from src.business.services.metadata_signer import MetadataSigner
from src.exceptions import VaultIntegrityError, VaultLockedError
from src.models import RawEntry


def _make_entry(**overrides) -> RawEntry:
    """构造用于测试的 RawEntry（签名操作密文态），提供合理默认值。"""
    entry = RawEntry(
        crypto_id='test-crypto-id-001',
        title='示例条目',
        username='',
        password='',
        url='',
        category_id=None,
        tags='',
        notes='',
        custom_fields='',
        is_favorite=False,
        is_deleted=False,
        password_strength=0,
        entry_type='login',
        totp_secret='',
        created_at='2025-01-01T00:00:00',
        updated_at='2025-01-01T00:00:00',
        deleted_at='',
        password_changed_at='',
        metadata_mac='',
    )
    return dataclasses.replace(entry, **overrides)


def test_verify_passes_on_untampered_entry():
    """verify() 正常验证，未篡改条目验证通过。"""
    master_key = b'test-master-key-for-verify'
    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key))
    entry = _make_entry()

    entry.metadata_mac = signer.sign(entry)

    # 不应抛出任何异常
    signer.verify(entry)


def test_verify_detects_tampered_title():
    """verify() 篡改检测，修改 title 后验证失败。"""
    master_key = b'test-master-key-for-tamper'
    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(master_key))
    entry = _make_entry(title='原始标题')

    entry.metadata_mac = signer.sign(entry)

    entry.title = '被篡改的标题'

    with pytest.raises(VaultIntegrityError):
        signer.verify(entry)


def test_verify_raises_when_no_key():
    """verify() 无域密钥时抛异常。"""
    signer = MetadataSigner()  # domain_key 为 None
    entry = _make_entry()
    entry.metadata_mac = 'some-mac-value'

    with pytest.raises(VaultLockedError):
        signer.verify(entry)


def test_sign_with_domain_key_matches_sign():
    """sign_with_domain_key() 与预设同一域密钥的 sign() 结果一致。"""
    master_key = b'test-master-key-for-dk'
    domain_key = MetadataSigner.compute_domain_key(master_key)
    signer = MetadataSigner(domain_key=domain_key)
    entry = _make_entry()

    mac_via_domain_key = signer.sign_with_domain_key(entry, domain_key)
    mac_via_sign = signer.sign(entry)

    assert mac_via_domain_key == mac_via_sign


def test_compute_domain_key_returns_bytearray():
    """compute_domain_key() 返回 32 字节 bytearray，以便 secure_zero 真正清零。"""
    master_key = b'any-key-material'
    dk = MetadataSigner.compute_domain_key(master_key)

    assert isinstance(dk, bytearray)
    assert len(dk) == 32  # SHA-256 output
    assert dk != master_key  # 派生结果应不同于输入


def test_sign_uses_preset_domain_key():
    """sign() 使用构造时设置的域密钥。"""
    master_key = b'test-key-for-preset'
    domain_key = MetadataSigner.compute_domain_key(master_key)
    signer = MetadataSigner(domain_key=domain_key)
    entry = _make_entry()

    mac = signer.sign(entry)

    assert isinstance(mac, str)
    assert len(mac) == 64

    # 用同一域密钥验证
    entry.metadata_mac = mac
    signer.verify(entry)


def test_verify_no_mac_raises_integrity_error():
    """verify() 条目 metadata_mac 为空时抛 VaultIntegrityError。"""
    signer = MetadataSigner(domain_key=b'x' * 32)
    entry = _make_entry()
    entry.metadata_mac = ''

    with pytest.raises(VaultIntegrityError, match='缺少元数据完整性签名'):
        signer.verify(entry)


def test_sign_without_domain_key_raises():
    """sign() 域密钥未设置时抛 VaultLockedError。"""
    signer = MetadataSigner()  # domain_key 为 None
    entry = _make_entry()

    with pytest.raises(VaultLockedError):
        signer.sign(entry)


def test_different_entries_produce_different_macs():
    """不同条目应产生不同签名。"""
    master_key = b'test-key-for-diff'
    domain_key = MetadataSigner.compute_domain_key(master_key)
    signer = MetadataSigner(domain_key=domain_key)
    entry_a = _make_entry(title='条目 A')
    entry_b = _make_entry(title='条目 B')

    mac_a = signer.sign(entry_a)
    mac_b = signer.sign(entry_b)

    assert mac_a != mac_b
