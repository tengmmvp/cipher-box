"""分类条目计数会话缓存的命中与失效矩阵测试（PERF-064）。

``CategoryManager.get_category_entry_counts`` 经会话缓存跳过 GROUP BY 全表扫描
（50k 库实测 ~25ms/次，条目变更后的侧边栏刷新每次触发）。失效矩阵的焦点验证：

- 未失效时二次读取不触 DB（计数 spy）。
- 单条字段编辑（不改归属）保缓存；改 category_id 后计数正确重算。
- 增删条目（结构性变更）失效。
- 分类 CRUD 走内部失效（add_category 后新分类计数可见）。
"""

import dataclasses

import pytest

from src.models import Category, Entry


@pytest.fixture
def counts_spy(vault, monkeypatch):
    """spy 计数 db.get_category_entry_counts 的实际触发次数。"""
    calls = 0
    original = vault.db.get_category_entry_counts

    def _spy() -> dict[int, int]:
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(vault.db, "get_category_entry_counts", _spy)
    return lambda: calls


def _add_category(entry_mgr, name: str) -> int:
    return entry_mgr.categories.add_category(Category(name=name))


class TestCategoryEntryCountsCache:
    """会话缓存的命中、失效与正确性。"""

    def test_second_read_hits_cache_without_db(self, entry_mgr, counts_spy):
        """未失效时二次读取直接命中缓存，不触发 GROUP BY 查询。"""
        entry_mgr.categories.get_category_entry_counts()
        assert counts_spy() == 1
        entry_mgr.categories.get_category_entry_counts()
        assert counts_spy() == 1  # 命中，无第二次 DB 查询

    def test_field_edit_keeps_cache(self, entry_mgr, counts_spy):
        """单条字段编辑（不改 category_id）不失效计数缓存。"""
        entry_id = entry_mgr.add_entry(Entry(title="t", username="u", password="Pass123!@#"))
        entry_mgr.categories.get_category_entry_counts()
        db_calls_after_first = counts_spy()

        entry = entry_mgr.get_entry(entry_id)
        entry_mgr.update_entry(dataclasses.replace(entry, title="t2"))

        assert counts_spy() == db_calls_after_first  # 未失效
        assert entry_mgr.categories.get_category_entry_counts() is not None
        assert counts_spy() == db_calls_after_first  # 读取仍命中

    def test_category_move_updates_counts(self, entry_mgr, counts_spy):
        """条目改分类后计数正确：源分类 -1、目标分类 +1（失效后重算）。"""
        cat_a = _add_category(entry_mgr, "源分类-A")
        cat_b = _add_category(entry_mgr, "目标分类-B")
        entry_id = entry_mgr.add_entry(
            Entry(
                title="t",
                username="u",
                password="Pass123!@#",
                category_id=cat_a,
            )
        )
        counts = entry_mgr.categories.get_category_entry_counts()
        # 计数映射仅含非零分类（GROUP BY 天然省略空分类），消费方以 get(id, 0) 取值。
        assert counts.get(cat_a, 0) == 1
        assert counts.get(cat_b, 0) == 0

        entry = entry_mgr.get_entry(entry_id)
        entry_mgr.update_entry(dataclasses.replace(entry, category_id=cat_b))

        # 归属变化已失效：重读触 DB 且计数正确。
        refreshed = entry_mgr.categories.get_category_entry_counts()
        assert counts_spy() == 2  # 首次读取 + 归属变化后的重读
        assert refreshed.get(cat_a, 0) == 0
        assert refreshed.get(cat_b, 0) == 1

    def test_add_and_delete_invalidate(self, entry_mgr, counts_spy):
        """新增/软删除条目（结构性变更）失效计数缓存。"""
        cat = _add_category(entry_mgr, "计数分类")
        entry_mgr.categories.get_category_entry_counts()
        assert counts_spy() == 1

        entry_id = entry_mgr.add_entry(
            Entry(title="t", username="u", password="Pass123!@#", category_id=cat)
        )
        assert entry_mgr.categories.get_category_entry_counts().get(cat, 0) == 1
        assert counts_spy() == 2  # 新增已失效重读

        # 软删除使条目离开有效计数（is_deleted=0 过滤）。
        entry_mgr.delete_entry(entry_id)
        assert entry_mgr.categories.get_category_entry_counts().get(cat, 0) == 0
        assert counts_spy() == 3

    def test_category_crud_invalidates(self, entry_mgr, counts_spy):
        """分类 CRUD 经内部失效：新分类创建后立即可见其计数。"""
        entry_mgr.categories.get_category_entry_counts()
        new_cat = _add_category(entry_mgr, "新分类-唯一")
        counts = entry_mgr.categories.get_category_entry_counts()
        assert counts_spy() == 2  # 分类创建已失效重读
        assert counts.get(new_cat, 0) == 0

    def test_toggle_favorite_keeps_cache(self, entry_mgr, counts_spy):
        """纯旁路变更（toggle_favorite）不失效计数缓存。"""
        entry_id = entry_mgr.add_entry(Entry(title="t", username="u", password="Pass123!@#"))
        entry_mgr.categories.get_category_entry_counts()
        db_calls = counts_spy()

        entry_mgr.toggle_favorite(entry_id)

        assert counts_spy() == db_calls
        entry_mgr.categories.get_category_entry_counts()
        assert counts_spy() == db_calls

    def test_epoch_rotation_invalidates(self, entry_mgr, vault, counts_spy):
        """epoch 轮换（备份恢复整体替换数据）后读时守卫失效，重读 DB。"""
        entry_mgr.categories.get_category_entry_counts()
        assert counts_spy() == 1

        original_epoch = vault.key_epoch
        vault.set_epoch("rotated-e-counts")  # 模拟恢复后的 epoch 轮换
        try:
            entry_mgr.categories.get_category_entry_counts()
            assert counts_spy() == 2  # epoch 失配 → 重读
        finally:
            vault.set_epoch(original_epoch)
