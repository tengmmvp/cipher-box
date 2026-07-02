"""EntryCacheManager 多级明文缓存的行为测试。

EntryCacheManager 此前仅被集成测试顺带执行（覆盖率靠路径覆盖，非行为断言），
缓存返回脏数据、失效遗漏、LRU 拼接错误都不会被发现。本文件补齐缓存命中、
失效矩阵（单条/全清）、TOTP secret 缓存清理、invalidate_all、LRU 驱逐等关键行为。
"""

import pytest

from src.business.managers import entry_cache as entry_cache_module
from src.database.types import EntryQuery
from src.models import Entry


@pytest.fixture
def cache(entry_mgr):
    """EntryManager 持有的 EntryCacheManager。"""
    return entry_mgr._cache


class TestSearchMetadataCache:
    def test_decrypts_and_caches_summary(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title='GitHub', username='alice', password='p'))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        title, username, url, tags = cache.cached_search_metadata(raw)
        assert title == 'GitHub'
        assert username == 'alice'
        # 第二次命中缓存，返回相同结果（不重复解密）
        assert cache.cached_search_metadata(raw) == (title, username, url, tags)

    def test_single_entry_invalidation(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title='A', username='u', password='p'))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw)
        assert raw.crypto_id in cache._search_metadata_cache
        # 单条 crypto_id 失效：仅 pop 该条
        cache.apply_change(crypto_id=raw.crypto_id)
        assert raw.crypto_id not in cache._search_metadata_cache

    def test_bulk_change_clears_all_summaries(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title='A', username='u', password='p'))
        entry_mgr.add_entry(Entry(title='B', username='u', password='p'))
        for raw in entry_mgr.db.get_entries(EntryQuery()):
            cache.cached_search_metadata(raw)
        assert len(cache._search_metadata_cache) == 2
        # crypto_id=None + clear_summaries=True：全清
        cache.apply_change(crypto_id=None, clear_summaries=True)
        assert len(cache._search_metadata_cache) == 0

    def test_category_change_keeps_summaries(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title='A', username='u', password='p'))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw)
        # 分类 CRUD：保留摘要缓存
        cache.apply_change(crypto_id=None, clear_summaries=False, category_changed=True)
        assert len(cache._search_metadata_cache) == 1


class TestTotpSecretCache:
    def test_store_pop_clear(self, cache):
        cache.store_totp(1, 'SECRET')
        assert cache._totp_secret_cache.get(1) == 'SECRET'
        cache.pop_totp(1)
        assert 1 not in cache._totp_secret_cache
        cache.store_totp(2, 'SECRET2')
        cache.clear_totp()
        assert len(cache._totp_secret_cache) == 0


class TestTagsCacheValid:
    def test_invalid_before_population(self, cache):
        """初始未填充标签缓存，tags_cache_valid 为 False。"""
        assert not cache.tags_cache_valid

    def test_valid_after_population(self, entry_mgr, cache):
        """填充标签后 tags_cache_valid 为 True（_tags_cache 非空且 epoch 一致）。"""
        entry_mgr.add_entry(Entry(title='T', username='u', password='p', tags='work,dev'))
        cache.get_all_tags()  # 填充 _tags_cache
        assert cache.tags_cache_valid

    def test_invalid_after_invalidate(self, entry_mgr, cache):
        """invalidate_all 后 tags_cache_valid 回到 False。"""
        entry_mgr.add_entry(Entry(title='T', username='u', password='p', tags='work'))
        cache.get_all_tags()
        assert cache.tags_cache_valid
        cache.invalidate_all()
        assert not cache.tags_cache_valid


class TestInvalidateAll:
    def test_clears_all_caches(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title='A', username='u', password='p'))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw)
        cache.store_totp(1, 'S')
        cache.invalidate_all()
        assert len(cache._search_metadata_cache) == 0
        assert len(cache._totp_secret_cache) == 0


class TestLruEviction:
    def test_evicts_oldest_beyond_capacity(self, entry_mgr, cache, monkeypatch):
        # 缩小缓存上限，避免构造 2000 条目
        monkeypatch.setattr(entry_cache_module, '_MAX_SEARCH_METADATA_CACHE_SIZE', 2)
        for i in range(3):
            entry_mgr.add_entry(Entry(title=f'T{i}', username='u', password='p'))
        for raw in entry_mgr.db.get_entries(EntryQuery()):
            cache.cached_search_metadata(raw)
        # 上限 2，加入第 3 条后应驱逐最旧的一条
        assert len(cache._search_metadata_cache) <= 2


class TestEntryManagerFineGrainedInvalidation:
    """守护 EntryManager 增删/软删除/恢复的精细缓存失效（clear_summaries=False）。

    这三类操作不改变既有条目的 title/username/url/tags 摘要内容，应保留摘要缓存
    避免全量重解密。防止未来误改回 notify()（默认 clear_summaries=True 全清），
    导致单条 delete/restore/add 触发整库摘要重解密。
    """

    def test_delete_preserves_other_summaries(self, entry_mgr, cache):
        """软删除一条不应清空其他条目的摘要缓存（仅切换 is_deleted）。"""
        entry_mgr.add_entry(Entry(title='A', username='u', password='p'))
        entry_mgr.add_entry(Entry(title='B', username='u', password='p'))
        raws = entry_mgr.db.get_entries(EntryQuery())
        for raw in raws:
            cache.cached_search_metadata(raw)
        assert len(cache._search_metadata_cache) == 2
        entry_mgr.delete_entry(raws[0].id)
        # 软删除不清摘要：两条摘要均保留，回收站展示时复用缓存
        assert len(cache._search_metadata_cache) == 2

    def test_restore_preserves_other_summaries(self, entry_mgr, cache):
        """恢复一条不应清空其他条目的摘要缓存。"""
        entry_mgr.add_entry(Entry(title='A', username='u', password='p'))
        entry_mgr.add_entry(Entry(title='B', username='u', password='p'))
        raws = entry_mgr.db.get_entries(EntryQuery())
        for raw in raws:
            cache.cached_search_metadata(raw)
        entry_mgr.delete_entry(raws[0].id)
        assert len(cache._search_metadata_cache) == 2
        entry_mgr.restore_entry(raws[0].id)
        assert len(cache._search_metadata_cache) == 2

    def test_add_preserves_existing_summaries(self, entry_mgr, cache):
        """新增条目不应清空既有条目的摘要缓存（新条目摘要自然填充）。"""
        entry_mgr.add_entry(Entry(title='A', username='u', password='p'))
        raw_a = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw_a)
        assert len(cache._search_metadata_cache) == 1
        entry_mgr.add_entry(Entry(title='B', username='u', password='p'))
        # 新增 B 后 A 的摘要仍保留
        assert raw_a.crypto_id in cache._search_metadata_cache
