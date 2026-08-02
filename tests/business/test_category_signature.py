"""分类元数据 HMAC 签名单元测试（category 完整性纵深防御）。

验证 MetadataSigner.sign_category / verify_category 的签名往返、篡改检测
（分类名密文 + 非密文元数据）、空签名拒绝、未解锁拒绝签名，以及分类签名与
条目签名虽共享域密钥但因载荷结构不同而互异。
"""

import dataclasses
import os

import pytest

from src.business.services.metadata_signer import MetadataSigner
from src.exceptions import VaultIntegrityError, VaultLockedError
from src.models import Category, RawEntry


def _make_signer() -> MetadataSigner:
    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(os.urandom(32)))
    return signer


def _make_category(**overrides) -> Category:
    return Category(
        id=1,
        name="cb2:ciphertext",
        icon_char="[X]",
        color="#abcdef",
        sort_order=2,
        created_at="2025-01-01T00:00:00",
        **overrides,
    )


def test_sign_verify_category_roundtrip():
    signer = _make_signer()
    cat = _make_category()
    cat = dataclasses.replace(cat, metadata_mac=signer.sign_category(cat))
    signer.verify_category(cat)  # 不抛即通过


def test_verify_category_detects_name_tamper():
    """篡改分类名密文（绑定 name_hash）应验签失败。"""
    signer = _make_signer()
    cat = _make_category()
    cat = dataclasses.replace(cat, metadata_mac=signer.sign_category(cat))
    cat = dataclasses.replace(cat, name="cb2:tampered")
    with pytest.raises(VaultIntegrityError):
        signer.verify_category(cat)


def test_verify_category_detects_metadata_tamper():
    """篡改非密文元数据（color/sort_order 等）应验签失败。"""
    signer = _make_signer()
    cat = _make_category()
    cat = dataclasses.replace(cat, metadata_mac=signer.sign_category(cat))
    cat = dataclasses.replace(cat, color="#000000", sort_order=99)
    with pytest.raises(VaultIntegrityError):
        signer.verify_category(cat)


def test_verify_category_missing_mac_raises():
    signer = _make_signer()
    cat = _make_category(metadata_mac="")
    with pytest.raises(VaultIntegrityError):
        signer.verify_category(cat)


def test_sign_category_requires_domain_key():
    signer = MetadataSigner()  # 无 domain_key
    cat = _make_category()
    with pytest.raises(VaultLockedError):
        signer.sign_category(cat)


def test_category_signature_differs_from_entry():
    """分类与条目共享域密钥但载荷结构不同，签名互异。"""
    signer = _make_signer()
    cat = _make_category()
    entry = RawEntry(id=1, crypto_id="abc", title="cb2:title")
    assert signer.sign_category(cat) != signer.sign(entry)


def test_category_signature_constant_time_compare():
    """verify 用 hmac.compare_digest，篡改签名不抛非 VaultIntegrityError 的异常。"""
    signer = _make_signer()
    cat = _make_category()
    cat = dataclasses.replace(cat, metadata_mac=signer.sign_category(cat))
    # 篡改签名本身（模拟 MAC 被替换）
    cat = dataclasses.replace(cat, metadata_mac="0" * len(cat.metadata_mac))
    with pytest.raises(VaultIntegrityError):
        signer.verify_category(cat)
