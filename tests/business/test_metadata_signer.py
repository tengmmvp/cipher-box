"""MetadataSigner 单元测试：签名往返、篡改检测、域密钥派生、跨 epoch 签名失效与 vault_meta MAC 字段绑定。"""

import dataclasses
import os

import pytest

from src.business.services.metadata_signer import (
    _PAYLOAD_ROW_ATTRS,
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

    mac = signer.sign(entry)
    # 值比对：签名非空、同载荷确定性一致、跨载荷互异（空串会走缺 MAC 拒绝分支）
    assert mac != ""
    assert signer.sign(entry) == mac
    assert signer.sign(dataclasses.replace(entry, title="cb2:other")) != mac

    entry = dataclasses.replace(entry, metadata_mac=mac)

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


def test_verify_non_ascii_mac_raises_integrity_error_not_typeerror():
    """非 ASCII metadata_mac（篡改形态）走「验签失败」抛 VaultIntegrityError（SEC-071）。

    裸 compare_digest 对非 ASCII str 抛 TypeError，会逃出 db 层 _row_to_entry 的
    except VaultIntegrityError 捕获面（STRICT/LENIENT 双模式）——篡改条目每读必崩、
    TOTP 定时器每秒冲刷异常日志；共享比较器内置 isascii 守卫使其落入既有验签
    失败语义。
    """
    signer = MetadataSigner(domain_key=MetadataSigner.compute_domain_key(b"test-key-na"))
    entry = _make_entry()
    entry = dataclasses.replace(entry, metadata_mac="被篡改的非ASCII签名")

    with pytest.raises(VaultIntegrityError):
        signer.verify(entry)


def test_verify_category_non_ascii_mac_raises_integrity_error_not_typeerror():
    """分类签名同款：非 ASCII metadata_mac 抛 VaultIntegrityError，不抛 TypeError（SEC-071）。"""
    signer = MetadataSigner(domain_key=MetadataSigner.compute_domain_key(b"test-key-na"))
    category = _make_category()
    category = dataclasses.replace(category, metadata_mac="分类被篡改签名")

    with pytest.raises(VaultIntegrityError):
        signer.verify_category(category)


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


# SEC-073：id 纳入条目签名载荷——整行克隆/换 id 形态不得再通过验签。


def test_verify_detects_row_clone_with_changed_id():
    """SEC-073：整行克隆（含合法签名）仅改 numeric id 后验签失败。

    id 不入载荷时整行克隆或两行互换 id 均不破坏验签，入载荷后必致失败。
    """
    signer = MetadataSigner(domain_key=MetadataSigner.compute_domain_key(b"test-key-clone"))
    entry = _make_entry(id=7, password="cb2:cipher")
    entry = dataclasses.replace(entry, metadata_mac=signer.sign(entry))

    # 同载荷不同 id → 签名不同（id 确实进入载荷）
    assert signer.sign(dataclasses.replace(entry, id=8)) != entry.metadata_mac

    # 整行克隆仅改 id：旧签名在新 id 下验签失败
    clone = dataclasses.replace(entry, id=99)
    with pytest.raises(VaultIntegrityError):
        signer.verify(clone)

    # 原 id 下验签仍通过（正对照，非全域失效）
    signer.verify(entry)


# PERF-101：行字典直签路径（sign_entry_from_row / sign 的 Mapping 分发）。


def _make_row(entry: RawEntry, **overrides) -> dict:
    """把 RawEntry 转成 entries 表列名键的行字典（sqlite3 行形态），供行直签测试。

    bool 列转 int 0/1、可空列以 None 模拟，检验取值胁迫与 RawEntry 路径一致。
    """
    row = {
        "id": entry.id,
        "crypto_id": entry.crypto_id,
        "title_enc": entry.title,
        "username_enc": entry.username,
        "password_enc": entry.password,
        "url_enc": entry.url,
        "category_id": entry.category_id,
        "tags_enc": entry.tags,
        "notes_enc": entry.notes,
        "custom_fields_enc": entry.custom_fields,
        "is_favorite": int(entry.is_favorite),
        "is_deleted": int(entry.is_deleted),
        "password_strength": entry.password_strength,
        "entry_type": entry.entry_type,
        "totp_secret_enc": entry.totp_secret,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
        "deleted_at": entry.deleted_at,
        "password_changed_at": entry.password_changed_at,
    }
    row.update(overrides)
    return row


def test_sign_entry_from_row_matches_entry_path():
    """PERF-101：行字典直签与 RawEntry 路径对同一逻辑行产出相同签名。

    clear_category_signatures 写回的行直签 mac 经读取验签（RawEntry 路径）复核，
    两路径载荷必须字节一致；覆盖 bool→int、可空列 None 的行形态差异。
    """
    signer = MetadataSigner(domain_key=MetadataSigner.compute_domain_key(b"test-key-row"))
    entry = _make_entry(
        id=42,
        username="cb2:u",
        password="cb2:p",
        notes="cb2:n",
        totp_secret="cb2:t",
        custom_fields="cb2:cf",
        is_favorite=True,
        category_id=3,
    )

    assert signer.sign_entry_from_row(_make_row(entry)) == signer.sign(entry)
    # sqlite 形态：bool→int；可空密文列 None 与 "" 同载荷（or "" 胁迫一致）
    assert signer.sign_entry_from_row(_make_row(entry, url_enc=None)) == signer.sign(
        dataclasses.replace(entry, url="")
    )

    # 载荷随行值变化（非恒等签名）：篡改行密文后签名不同
    assert signer.sign_entry_from_row(_make_row(entry, password_enc="cb2:x")) != signer.sign(entry)


def test_sign_dispatches_mapping_to_row_path():
    """PERF-101：sign() 收到行字典（Mapping）时分发到行直签路径。

    db 层注入的 EntrySigner 回调传行字典，分发落点须与显式调用一致。
    """
    signer = MetadataSigner(domain_key=MetadataSigner.compute_domain_key(b"test-key-dispatch"))
    row = _make_row(_make_entry(id=5))

    assert signer.sign(row) == signer.sign_entry_from_row(row)


def test_sign_entry_from_row_without_domain_key_raises():
    """PERF-101：行直签在域密钥未设置时与 sign() 同抛 VaultLockedError。"""
    signer = MetadataSigner()  # domain_key 为 None
    row = _make_row(_make_entry(id=1))

    with pytest.raises(VaultLockedError):
        signer.sign_entry_from_row(row)


@pytest.mark.parametrize("key", sorted(_PAYLOAD_ROW_ATTRS))
def test_signature_payload_binds_each_payload_key(key):
    """SEC-073 补充守护：篡改任一载荷键值 → 签名必变。

    键集一致性（_PAYLOAD_ROW_ATTRS vs 列集）在 test_field_consistency 守护；本测试
    锚定渲染器 _payload_from_row 消费全部键——新载荷键被渲染器静默忽略（脱离 MAC
    保护）在此立即失败。
    """
    signer = MetadataSigner(domain_key=MetadataSigner.compute_domain_key(b"test-key-bindcols"))
    row = _make_row(_make_entry(id=11, password="cb2:p"))
    baseline = signer.sign_entry_from_row(row)

    value = row[key]
    row[key] = value + 1 if isinstance(value, int) else "mutated" if value is None else f"{value}-x"
    assert signer.sign_entry_from_row(row) != baseline


def test_clear_category_signatures_resigns_entries_for_null_category(tmp_path):
    """PERF-101 + SEC-073 集成：删除分类后条目 category_id 置空且行直签 mac 可验。

    行直签写回的 mac 经 get_entry STRICT 验签（RawEntry 路径）复核，守护两路径
    载荷一致与 id 插入回填。
    """
    from src.database.db_manager import DatabaseManager

    signer = MetadataSigner()
    signer.set_domain_key(MetadataSigner.compute_domain_key(b"test-key-clear-cat"))
    db = DatabaseManager(tmp_path / "clear-cat.db", test_mode=True)
    db.set_entry_integrity_handlers(signer.sign, signer.verify)
    db.open()
    db.init_tables()
    try:
        cat = Category(
            name="cb2:cat",
            icon_char="[DIR]",
            color="#111111",
            sort_order=99,
            created_at="2025-01-01T00:00:00",
        )
        cat_id = db.add_category(cat)
        entry_ids = [
            db.add_entry(
                _make_entry(
                    crypto_id=f"cb2-cid-{i}",
                    title=f"cb2:t{i}",
                    password=f"cb2:p{i}",
                    category_id=cat_id,
                )
            )
            for i in range(3)
        ]

        db.delete_category(cat_id)

        for entry_id in entry_ids:
            # get_entry 默认 STRICT：category_id 置空 + 行直签/插入回填 mac 任一
            # 失配都会在此抛 VaultIntegrityError
            entry = db.get_entry(entry_id)
            assert entry is not None
            assert entry.category_id is None
            assert entry.metadata_mac != ""
    finally:
        db.close()
