"""测试 EntryManager 搜索元数据缓存的 epoch 失效行为。

缓存预置经公开入口 ``cached_search_metadata_full``（monkeypatch 模块级解密原语
绕过真实密码学，与既有 LRU 用例同范式），断言经 ``search_metadata_cached_ids`` /
``cache_epoch`` / ``get_failed_fields`` 观察面（MAINT-095），不再直读直写
``_search_metadata_cache`` / ``_cache_epoch`` 内部结构。
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest

import src.business.managers.entry_cache as entry_cache_module
from src.exceptions import DecryptionError
from tests.helpers import make_entry_manager


def _row(cid: str) -> SimpleNamespace:
    """构造满足 SearchRowSource 协议的密文行替身（5 个密文属性）。"""
    return SimpleNamespace(
        crypto_id=cid,
        title="enc",
        username="enc",
        url="enc",
        tags="enc",
    )


def _fake_decrypt(monkeypatch, *, fail_fields: frozenset[str] = frozenset()):
    """替换 entry_cache 模块的解密原语：成功字段返回明文，fail_fields 抛 DecryptionError。"""

    def _decrypt(encrypted, key, crypto_id, field_name, strict=False):
        if field_name in fail_fields:
            raise DecryptionError(f"模拟损坏: {field_name}")
        return f"{field_name}_plain_{crypto_id}"

    monkeypatch.setattr(entry_cache_module, "_decrypt_field_impl", _decrypt)


@pytest.fixture
def vault_with_epoch():
    """key_epoch 可切换的 MagicMock vault（PropertyMock 持有，测试中途改 return_value）。"""
    vault = MagicMock()
    vault.is_unlocked = True
    epoch = PropertyMock(return_value="epoch_v1")
    type(vault).key_epoch = epoch
    return vault, epoch


class TestSearchMetadataCacheEpochInvalidation:
    """验证搜索元数据缓存的 epoch 失效与显式 invalidate_caches 清空行为。"""

    def test_epoch_change_clears_cache(self, vault_with_epoch, monkeypatch):
        """key_epoch 变化时，搜索元数据缓存被清空。"""
        vault, epoch = vault_with_epoch
        _fake_decrypt(monkeypatch)
        mgr = make_entry_manager(vault)
        cache = mgr.cache
        # 在 epoch_v1 世代下经公开入口填充缓存
        cache.invalidate_if_epoch_changed()  # 重臂 _cache_epoch=epoch_v1
        meta = cache.cached_search_metadata_full(_row("id1"), key=b"k" * 32, data_epoch="epoch_v1")
        assert meta.title == "title_plain_id1"
        assert cache.search_metadata_cached_ids == frozenset({"id1"})

        epoch.return_value = "epoch_v2"
        cache.invalidate_if_epoch_changed()

        assert cache.search_metadata_cached_ids == frozenset()
        assert cache.cache_epoch == "epoch_v2"

    def test_epoch_none_clears_cache(self, vault_with_epoch, monkeypatch):
        """key_epoch 为 None 表示保险库已锁定，此时缓存被清空。

        这是 clear_vault_state 设置 _key_epoch=None 后的关键行为：
        即使 _cache_epoch 也是 None，也应清空缓存。
        """
        vault, epoch = vault_with_epoch
        epoch.return_value = None
        _fake_decrypt(monkeypatch)
        mgr = make_entry_manager(vault)
        cache = mgr.cache
        # None 世代下仍可填充（entry_epoch 回退缓存侧采样 None，守卫 None==None 放行）
        cache.invalidate_if_epoch_changed()
        cache.cached_search_metadata_full(_row("id1"), key=b"k" * 32, data_epoch=None)
        assert cache.search_metadata_cached_ids == frozenset({"id1"})

        cache.invalidate_if_epoch_changed()

        assert cache.search_metadata_cached_ids == frozenset()
        assert cache.cache_epoch is None

    def test_same_epoch_keeps_cache(self, vault_with_epoch, monkeypatch):
        """key_epoch 未变化时，缓存保持不变。"""
        vault, epoch = vault_with_epoch
        epoch.return_value = "same_epoch"
        _fake_decrypt(monkeypatch)
        mgr = make_entry_manager(vault)
        cache = mgr.cache
        cache.invalidate_if_epoch_changed()
        cache.cached_search_metadata_full(_row("id1"), key=b"k" * 32, data_epoch="same_epoch")

        cache.invalidate_if_epoch_changed()

        assert cache.search_metadata_cached_ids == frozenset({"id1"})

    def test_invalidate_caches_clears_all(self, vault_with_epoch, monkeypatch):
        """invalidate_caches() 显式清空所有缓存（摘要 + 解密失败字段记录）。"""
        vault, _epoch = vault_with_epoch
        _fake_decrypt(monkeypatch, fail_fields=frozenset({"username"}))
        mgr = make_entry_manager(vault)
        cache = mgr.cache
        cache.invalidate_if_epoch_changed()
        cache.cached_search_metadata_full(_row("id1"), key=b"k" * 32, data_epoch="epoch_v1")
        assert cache.search_metadata_cached_ids == frozenset({"id1"})
        assert cache.get_failed_fields("id1") == {"username"}

        mgr.invalidate_caches()

        assert cache.search_metadata_cached_ids == frozenset()
        assert cache.get_failed_fields("id1") == set()


class TestFailedFieldsCacheSemantics:
    """get_failed_fields 拷贝语义与 LRU 淘汰联动（QL-056/058 守护）。"""

    def test_get_failed_fields_returns_copy(self, vault_with_epoch, monkeypatch):
        """返回内部 set 的拷贝（QL-056）：调用方原地修改不污染缓存。"""
        vault, _epoch = vault_with_epoch
        _fake_decrypt(monkeypatch, fail_fields=frozenset({"title", "username"}))
        mgr = make_entry_manager(vault)
        cache = mgr.cache
        cache.invalidate_if_epoch_changed()
        cache.cached_search_metadata_full(_row("id1"), key=b"k" * 32, data_epoch="epoch_v1")

        failed = cache.get_failed_fields("id1")
        failed.add("password")  # 原地修改
        failed.discard("title")

        # 内部缓存不受调用方修改影响
        assert cache.get_failed_fields("id1") == {"title", "username"}
        # 再次取值仍是干净的缓存内容
        assert cache.get_failed_fields("id1") == {"title", "username"}
        # 未知条目返回空集（新构造，非共享哨兵）
        missing = cache.get_failed_fields("missing")
        assert missing == set()
        missing.add("x")
        assert cache.get_failed_fields("missing") == set()

    def test_lru_eviction_cleans_failed_dict(self, vault_with_epoch, monkeypatch):
        """LRU 淘汰条目时同步清理其 failed 记录（QL-058）。

        「解密失败 + 缓存超上限」同现时，failed 字典若不随 LRU popitem 联动，
        会随时间无界驻留。把容量压到 1 构造淘汰，断言被淘汰条目的 failed
        记录一并移除。解密经 monkeypatch 绕过真实密钥（测缓存行为非密码学）。
        """
        vault, epoch = vault_with_epoch
        epoch.return_value = "e1"
        # title 解密恒失败（触发 failed 记录），其余字段成功——每个条目都会进
        # 摘要缓存（结果仍缓存）+ failed 字典
        _fake_decrypt(monkeypatch, fail_fields=frozenset({"title"}))
        monkeypatch.setattr(entry_cache_module, "_MAX_SEARCH_METADATA_CACHE_SIZE", 1)

        mgr = make_entry_manager(vault)
        cache = mgr.cache
        cache.invalidate_if_epoch_changed()  # 重臂 _cache_epoch=e1

        cache.cached_search_metadata_full(_row("id1"), key=b"k" * 32, data_epoch="e1")
        cache.cached_search_metadata_full(_row("id2"), key=b"k" * 32, data_epoch="e1")

        # 容量 1：id1 被淘汰，failed 记录应联动清理
        assert cache.search_metadata_cached_ids == frozenset({"id2"})
        assert cache.get_failed_fields("id1") == set()
        assert cache.get_failed_fields("id2") == {"title"}
