"""测试 EntryManager 搜索元数据缓存的 epoch 失效行为。"""

from unittest.mock import MagicMock, PropertyMock

from src.business.managers.entry_manager import EntryManager


class TestSearchMetadataCacheEpochInvalidation:
    """验证 _invalidate_if_epoch_changed 在 key_epoch 变化时清除缓存。"""

    def test_epoch_change_clears_cache(self):
        """key_epoch 变化时，搜索元数据缓存被清空。"""
        vault = MagicMock()
        vault.is_unlocked = True
        type(vault).key_epoch = PropertyMock(return_value='epoch_v2')

        mgr = EntryManager(vault)
        mgr._cache._search_metadata_cache = {
            'id1': ('title1', 'user1', 'url1', 'tags1'),
            'id2': ('title2', 'user2', '', ''),
        }
        mgr._cache._cache_epoch = 'epoch_v1'

        mgr._invalidate_if_epoch_changed()

        assert len(mgr._cache._search_metadata_cache) == 0
        assert mgr._cache._cache_epoch == 'epoch_v2'

    def test_epoch_none_clears_cache(self):
        """key_epoch 为 None 表示保险库已锁定，此时缓存被清空。

        这是 _clear_vault_state 设置 _key_epoch=None 后的关键行为：
        即使 _cache_epoch 也是 None，也应清空缓存。
        """
        vault = MagicMock()
        vault.is_unlocked = True
        type(vault).key_epoch = PropertyMock(return_value=None)

        mgr = EntryManager(vault)
        mgr._cache._search_metadata_cache = {'id1': ('title1', 'user1', 'url1', 'tags1')}
        mgr._cache._cache_epoch = None

        mgr._invalidate_if_epoch_changed()

        assert len(mgr._cache._search_metadata_cache) == 0

    def test_same_epoch_keeps_cache(self):
        """key_epoch 未变化时，缓存保持不变。"""
        vault = MagicMock()
        vault.is_unlocked = True
        type(vault).key_epoch = PropertyMock(return_value='same_epoch')

        mgr = EntryManager(vault)
        mgr._cache._search_metadata_cache = {'id1': ('title1', 'user1', 'url1', 'tags1')}
        mgr._cache._cache_epoch = 'same_epoch'

        mgr._invalidate_if_epoch_changed()

        assert mgr._cache._search_metadata_cache == {'id1': ('title1', 'user1', 'url1', 'tags1')}

    def test_invalidate_caches_clears_all(self):
        """invalidate_caches() 显式清空所有缓存。"""
        vault = MagicMock()
        vault.is_unlocked = True
        vault.key_epoch = 'some_epoch'

        mgr = EntryManager(vault)
        mgr._cache._search_metadata_cache = {'id1': ('title1', 'user1', 'url1', 'tags1')}
        mgr._cache._search_metadata_failed = {'id2': {'username'}}

        mgr.invalidate_caches()

        assert len(mgr._cache._search_metadata_cache) == 0
        assert len(mgr._cache._search_metadata_failed) == 0
