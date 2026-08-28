"""测试 EntryManager 搜索元数据缓存的 epoch 失效行为。"""

from unittest.mock import MagicMock, PropertyMock

from src.business.managers.entry_cache import SearchMetadata
from tests.helpers import make_entry_manager


class TestSearchMetadataCacheEpochInvalidation:
    """验证搜索元数据缓存的 epoch 失效与显式 invalidate_caches 清空行为。"""

    def test_epoch_change_clears_cache(self):
        """key_epoch 变化时，搜索元数据缓存被清空。"""
        vault = MagicMock()
        vault.is_unlocked = True
        type(vault).key_epoch = PropertyMock(return_value="epoch_v2")

        mgr = make_entry_manager(vault)
        mgr._cache._search_metadata_cache = {
            "id1": SearchMetadata(
                "title1", "user1", "url1", "tags1", "title1", "user1", "url1", "tags1"
            ),
            "id2": SearchMetadata("title2", "user2", "", "", "title2", "user2", "", ""),
        }
        mgr._cache._cache_epoch = "epoch_v1"

        mgr._cache.invalidate_if_epoch_changed()

        assert len(mgr._cache._search_metadata_cache) == 0
        assert mgr._cache._cache_epoch == "epoch_v2"

    def test_epoch_none_clears_cache(self):
        """key_epoch 为 None 表示保险库已锁定，此时缓存被清空。

        这是 clear_vault_state 设置 _key_epoch=None 后的关键行为：
        即使 _cache_epoch 也是 None，也应清空缓存。
        """
        vault = MagicMock()
        vault.is_unlocked = True
        type(vault).key_epoch = PropertyMock(return_value=None)

        mgr = make_entry_manager(vault)
        mgr._cache._search_metadata_cache = {
            "id1": SearchMetadata(
                "title1", "user1", "url1", "tags1", "title1", "user1", "url1", "tags1"
            ),
        }
        mgr._cache._cache_epoch = None

        mgr._cache.invalidate_if_epoch_changed()

        assert len(mgr._cache._search_metadata_cache) == 0

    def test_same_epoch_keeps_cache(self):
        """key_epoch 未变化时，缓存保持不变。"""
        vault = MagicMock()
        vault.is_unlocked = True
        type(vault).key_epoch = PropertyMock(return_value="same_epoch")

        mgr = make_entry_manager(vault)
        cached = SearchMetadata(
            "title1", "user1", "url1", "tags1", "title1", "user1", "url1", "tags1"
        )
        mgr._cache._search_metadata_cache = {"id1": cached}
        mgr._cache._cache_epoch = "same_epoch"

        mgr._cache.invalidate_if_epoch_changed()

        assert mgr._cache._search_metadata_cache == {"id1": cached}

    def test_invalidate_caches_clears_all(self):
        """invalidate_caches() 显式清空所有缓存。"""
        vault = MagicMock()
        vault.is_unlocked = True
        vault.key_epoch = "some_epoch"

        mgr = make_entry_manager(vault)
        mgr._cache._search_metadata_cache = {
            "id1": SearchMetadata(
                "title1", "user1", "url1", "tags1", "title1", "user1", "url1", "tags1"
            ),
        }
        mgr._cache._search_metadata_failed = {"id2": {"username"}}

        mgr.invalidate_caches()

        assert len(mgr._cache._search_metadata_cache) == 0
        assert len(mgr._cache._search_metadata_failed) == 0


class TestFailedFieldsCacheSemantics:
    """get_failed_fields 拷贝语义与 LRU 淘汰联动（QL-056/058 守护）。"""

    def test_get_failed_fields_returns_copy(self):
        """返回内部 set 的拷贝（QL-056）：调用方原地修改不污染缓存。"""
        vault = MagicMock()
        vault.is_unlocked = True
        mgr = make_entry_manager(vault)
        mgr._cache._search_metadata_failed = {"id1": {"title", "username"}}

        failed = mgr._cache.get_failed_fields("id1")
        failed.add("password")  # 原地修改
        failed.discard("title")

        # 内部缓存不受调用方修改影响
        assert mgr._cache._search_metadata_failed["id1"] == {"title", "username"}
        # 再次取值仍是干净的缓存内容
        assert mgr._cache.get_failed_fields("id1") == {"title", "username"}
        # 未知条目返回空集（新构造，非共享哨兵）
        missing = mgr._cache.get_failed_fields("missing")
        assert missing == set()
        missing.add("x")
        assert "missing" not in mgr._cache._search_metadata_failed

    def test_lru_eviction_cleans_failed_dict(self, monkeypatch):
        """LRU 淘汰条目时同步清理其 failed 记录（QL-058）。

        「解密失败 + 缓存超上限」同现时，failed 字典若不随 LRU popitem 联动，
        会随时间无界驻留。把容量压到 1 构造淘汰，断言被淘汰条目的 failed
        记录一并移除。解密经 monkeypatch 绕过真实密钥（测缓存行为非密码学）。
        """
        import src.business.managers.entry_cache as entry_cache_module
        from src.exceptions import DecryptionError

        monkeypatch.setattr(entry_cache_module, "_MAX_SEARCH_METADATA_CACHE_SIZE", 1)

        # title 解密恒失败（触发 failed 记录），其余字段成功——每个条目都会进
        # 摘要缓存（结果仍缓存）+ failed 字典
        def fake_decrypt(encrypted, key, crypto_id, field_name, strict=False):
            if field_name == "title":
                raise DecryptionError("模拟损坏")
            return f"plain_{field_name}"

        monkeypatch.setattr(entry_cache_module, "_decrypt_field_impl", fake_decrypt)

        vault = MagicMock()
        vault.is_unlocked = True
        mgr = make_entry_manager(vault)
        cache = mgr._cache
        cache._cache_epoch = "e1"  # 与回写守卫的 data_epoch 对齐

        def _row(cid):
            from types import SimpleNamespace

            return SimpleNamespace(
                crypto_id=cid,
                title="enc",
                username="enc",
                url="enc",
                tags="enc",
            )

        cache._cached_search_metadata_no_check(_row("id1"), key=b"k" * 32, data_epoch="e1")
        cache._cached_search_metadata_no_check(_row("id2"), key=b"k" * 32, data_epoch="e1")

        # 容量 1：id1 被淘汰，failed 记录应联动清理
        assert list(cache._search_metadata_cache) == ["id2"]
        assert "id1" not in cache._search_metadata_failed
        assert cache._search_metadata_failed["id2"] == {"title"}
