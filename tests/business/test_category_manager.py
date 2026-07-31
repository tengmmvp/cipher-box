"""CategoryManager 测试 — 分类 CRUD 的加密落库、重名/空名拒绝与缓存失效。

经 entry_mgr.categories 访问 CategoryManager。add_category 两阶段加密事务：
先用 pending_id 占位加密写入获得真实 id，再用真实 category_crypto_id 重加密。
测试断言数据库层分类名为 cb2: 前缀密文（vault fixture 注入 test_mode=True
仅关闭 _enforce_encrypted_fields 断言，加密本身不受影响）。

vault initialize 会预置若干默认分类，故所有测试用例使用计数器生成的唯一名，
避免与默认分类或同会话其他用例的名称碰撞。
"""

import itertools

import pytest

from src.models import Category

_name_counter = itertools.count(1)


def _unique_name(prefix: str = 'Cat') -> str:
    """生成会话内唯一分类名，避免默认分类与跨用例碰撞导致的「已存在」。"""
    return f'{prefix}{next(_name_counter)}UniqueX9'


class TestCategoryManagerAdd:
    """add_category 成功与各类拒绝路径。"""

    def test_add_returns_id_and_encrypts_name(self, entry_mgr, vault):
        """成功新增返回 id，数据库层分类名为 cb2: 密文。"""
        name = _unique_name('工作')
        cat_id = entry_mgr.categories.add_category(
            Category(name=name, icon_char='[DIR]', color='#fff'),
        )
        assert isinstance(cat_id, int) and cat_id > 0

        raw = vault.db.get_category(cat_id)
        assert raw is not None
        assert raw.name.startswith('cb2:'), (
            f'数据库层分类名应为密文 cb2: 前缀，实际: {raw.name!r}'
        )
        assert name not in raw.name  # 明文不应出现在密文中

    def test_add_duplicate_name_rejected(self, entry_mgr):
        """重名（大小写不敏感）应拒绝。"""
        base = _unique_name('Dup')
        entry_mgr.categories.add_category(Category(name=base))
        with pytest.raises(ValueError, match='已存在'):
            entry_mgr.categories.add_category(Category(name=base.swapcase()))

    def test_add_empty_name_rejected(self, entry_mgr):
        """空名或纯空白应拒绝。"""
        with pytest.raises(ValueError, match='空'):
            entry_mgr.categories.add_category(Category(name='   '))

    def test_add_decrypts_back_to_plaintext_via_get(self, entry_mgr):
        """新增后经 get_categories 读取应得到明文名。"""
        name = _unique_name('财务')
        entry_mgr.categories.add_category(Category(name=name))
        cats = entry_mgr.categories.get_categories()
        assert any(c.name == name for c in cats)

    def test_add_notify_true_propagates(self, entry_mgr):
        """notify=True（默认）应触发变更总线（不抛异常即正常传播）。"""
        entry_mgr.categories.add_category(Category(name=_unique_name('N1')))
        # 再加一个，验证总线多次通知无累积异常
        entry_mgr.categories.add_category(Category(name=_unique_name('N2')))

    def test_add_notify_false_skips_bus(self, entry_mgr):
        """notify=False 不触发总线（仅落库，无回调）。"""
        name = _unique_name('Silent')
        cat_id = entry_mgr.categories.add_category(
            Category(name=name), notify=False,
        )
        assert cat_id > 0
        cats = entry_mgr.categories.get_categories()
        assert any(c.name == name for c in cats)

    def test_add_category_signature_verifies_after_reload(self, entry_mgr, vault):
        """新建分类的两阶段签名须与持久化行一致：重载后 verify_category 通过。

        回归守护 created_at 回填：created_at 由 DB 层填充，若未回填内存对象，
        两阶段重签会用空 created_at 算 mac，导致重载后验签永久失败、
        category HMAC 纵深防御对该分类系统性失效。
        """
        from src.business.services.metadata_signer import MetadataSigner

        cat_id = entry_mgr.categories.add_category(Category(name=_unique_name('签名')))
        # 从 DB 重载原始行（未经 CategoryManager 缓存），用当前域密钥验签
        raw = vault.db.get_category(cat_id)
        assert raw is not None
        key = vault.key
        assert key is not None
        signer = MetadataSigner()
        signer.set_domain_key(MetadataSigner.compute_domain_key(key))
        signer.verify_category(raw)  # 不抛即通过：created_at 与签名一致


class TestCategoryManagerUpdate:
    """update_category 改名后缓存失效。"""

    def test_update_renames(self, entry_mgr, vault):
        """改名后 get_categories 返回新名，数据库层仍为密文。"""
        cat_id = entry_mgr.categories.add_category(Category(name=_unique_name('Old')))
        new_name = _unique_name('New')
        entry_mgr.categories.update_category(
            Category(id=cat_id, name=new_name, icon_char='[DIR]', color='#fff'),
        )
        cats = entry_mgr.categories.get_categories()
        names = [c.name for c in cats]
        assert new_name in names
        # 数据库层仍密文
        raw = vault.db.get_category(cat_id)
        assert raw is not None
        assert raw.name.startswith('cb2:')
        # 回归守护：本测试以不带 created_at 的 Category 调 update_category（模拟
        # 不安全调用模式）。update_category 须从 DB 回填 created_at 再签名，使重载
        # 后 verify_category 通过——否则签名与持久化行错配，category HMAC 失效。
        from src.business.services.metadata_signer import MetadataSigner
        key = vault.key
        assert key is not None
        signer = MetadataSigner()
        signer.set_domain_key(MetadataSigner.compute_domain_key(key))
        signer.verify_category(raw)

    def test_update_requires_id(self, entry_mgr):
        """id 为 None 应拒绝。"""
        with pytest.raises(ValueError, match='ID'):
            entry_mgr.categories.update_category(Category(name=_unique_name('X')))

    def test_category_tamper_logs_warning_lenient(self, entry_mgr, vault, caplog):
        """篡改 DB 行 metadata_mac，get_categories LENIENT 路径记 warning 且不抛。

        端到端守护 category HMAC 纵深：直接篡改持久化的 metadata_mac（绕过 repository
        签名），LENIENT 验签应检测到并记 warning，但不阻断返回分类（GCM 仍兜底名密文）。
        """
        import logging
        cat_id = entry_mgr.categories.add_category(Category(name=_unique_name('篡改')))
        # 直接篡改 DB 的 metadata_mac，绕过 repository 签名
        conn = vault.db.connection
        conn.execute("UPDATE categories SET metadata_mac='tampered' WHERE id=?", (cat_id,))
        conn.commit()
        with caplog.at_level(logging.WARNING, logger='src.database.category_repository'):
            cats = vault.db.get_categories()  # 默认 LENIENT 验签
        # LENIENT 不抛，仍返回分类；篡改的分类记完整性 warning
        assert any(cat.id == cat_id for cat in cats)
        assert any(
            '元数据完整性校验失败' in r.message and str(cat_id) in r.message
            for r in caplog.records
        )


class TestCategoryManagerDelete:
    """delete_category 删除后不再出现在 get_categories。"""

    def test_delete_removes_from_list(self, entry_mgr):
        cat_id = entry_mgr.categories.add_category(Category(name=_unique_name('Del')))
        entry_mgr.categories.delete_category(cat_id)
        cats = entry_mgr.categories.get_categories()
        assert all(c.id != cat_id for c in cats)

    def test_get_category_after_delete_returns_none(self, entry_mgr):
        cat_id = entry_mgr.categories.add_category(Category(name=_unique_name('Tmp')))
        entry_mgr.categories.delete_category(cat_id)
        assert entry_mgr.categories.get_category(cat_id) is None


class TestCategoryManagerCount:
    """分类条目计数。"""

    def test_entry_count_zero_for_empty_category(self, entry_mgr):
        cat_id = entry_mgr.categories.add_category(Category(name=_unique_name('Empty')))
        assert entry_mgr.categories.get_category_entry_count(cat_id) == 0

    def test_entry_counts_dict_structure(self, entry_mgr):
        """get_category_entry_counts 返回 dict[int, int]。"""
        entry_mgr.categories.add_category(Category(name=_unique_name('C')))
        counts = entry_mgr.categories.get_category_entry_counts()
        assert isinstance(counts, dict)
        # 新增分类可能在计数中为 0 或不出现，但不应抛异常
        assert all(isinstance(k, int) for k in counts)
        assert all(isinstance(v, int) for v in counts.values())


class TestCategoryManagerSorting:
    """get_categories 排序语义（仅比较本用例新增的三个分类的相对顺序）。"""

    def test_sorted_by_sort_order_then_name(self, entry_mgr):
        """结果按 (sort_order, name casefold) 排序。"""
        n_banana = _unique_name('banana')
        n_apple = _unique_name('Apple')
        n_zebra = _unique_name('zebra')
        entry_mgr.categories.add_category(Category(name=n_banana, sort_order=1))
        entry_mgr.categories.add_category(Category(name=n_apple, sort_order=1))
        entry_mgr.categories.add_category(Category(name=n_zebra, sort_order=0))
        cats = entry_mgr.categories.get_categories()
        idx = {c.name: i for i, c in enumerate(cats)}
        # sort_order=0 的 zebra 在前；sort_order=1 内 Apple(casefold) < banana
        assert idx[n_zebra] < idx[n_apple]
        assert idx[n_apple] < idx[n_banana]
