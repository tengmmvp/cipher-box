"""EntryChangeBus 测试 — 缓存失效与回调编排。

验证关键约束：notify 先调 cache.apply_change（持 cache_lock）后跑回调（锁外），
且回调吞异常不中断后续回调。用 MagicMock 注入可控 cache 与验证回调执行顺序，
同时用真实 vault fixture 跑一条端到端路径。
"""

import dataclasses
import logging
from unittest.mock import MagicMock

from src.business.managers.entry_cache import SearchMetadata
from src.business.managers.entry_change_bus import EntryChangeBus
from src.models import Category


class TestEntryChangeBusNotifyOrder:
    """notify 先失效缓存，再调用回调。"""

    def test_apply_change_called_before_callback(self):
        """cache.apply_change 必须在回调之前被调用（顺序约束守护）。"""
        cache = MagicMock()
        bus = EntryChangeBus(cache)
        call_order: list[str] = []

        cache.apply_change.side_effect = lambda **kw: call_order.append("cache")
        bus.register(lambda pw, md, cid=None: call_order.append("callback"))

        bus.notify(password_changed=True)
        assert call_order == ["cache", "callback"]

    def test_apply_change_receives_granular_args(self):
        """notify 的 crypto_id/tags_changed 等参数透传给 apply_change。"""
        cache = MagicMock()
        bus = EntryChangeBus(cache)
        bus.notify(
            password_changed=False,
            crypto_id="abc123",
            tags_changed=False,
            category_changed=True,
            clear_summaries=False,
        )
        cache.apply_change.assert_called_once_with(
            crypto_id="abc123",
            tags_changed=False,
            category_changed=True,
            clear_summaries=False,
        )


class TestEntryChangeBusCallbacks:
    """回调注册与执行。"""

    def test_callback_receives_change_flags(self):
        """回调应收到 (password_changed, metadata_changed) 两个布尔参数。"""
        cache = MagicMock()
        bus = EntryChangeBus(cache)
        received: list[tuple[bool, bool]] = []
        bus.register(lambda pw, md, cid=None: received.append((pw, md)))
        bus.notify(password_changed=True)  # metadata_changed 默认 True
        bus.notify(password_changed=False, metadata_changed=False)
        assert received == [(True, True), (False, False)]

    def test_callback_receives_crypto_id(self):
        """回调第三个参数为 crypto_id（PERF-021）：提供时透传，默认 None=全量语义。"""
        cache = MagicMock()
        bus = EntryChangeBus(cache)
        received: list[str | None] = []
        bus.register(lambda pw, md, cid=None: received.append(cid))
        bus.notify(password_changed=False, crypto_id="cid-xyz")
        bus.notify(password_changed=True)  # 增删/批量不传 crypto_id
        assert received == ["cid-xyz", None]

    def test_multiple_callbacks_all_invoked(self):
        """注册多个回调，每个都应被调用。"""
        cache = MagicMock()
        bus = EntryChangeBus(cache)
        calls: list[str] = []
        bus.register(lambda pw, md, cid=None: calls.append("first"))
        bus.register(lambda pw, md, cid=None: calls.append("second"))
        bus.register(lambda pw, md, cid=None: calls.append("third"))
        bus.notify(password_changed=True)
        assert calls == ["first", "second", "third"]

    def test_callback_exception_does_not_block_subsequent(self):
        """第一个回调抛异常，后续回调仍应被调用（吞异常约束）。"""
        cache = MagicMock()
        bus = EntryChangeBus(cache)

        def boom(pw, md, cid=None):
            raise RuntimeError("callback exploded")

        second_called: list[bool] = []
        bus.register(boom)
        bus.register(lambda pw, md, cid=None: second_called.append(True))

        bus.notify(password_changed=True)
        assert second_called == [True]

    def test_callback_exception_logged_not_raised(self, caplog):
        """回调异常被吞掉，notify 本身不抛（吞掉且可见双契约，记录断言补强 MAINT-111）。"""
        cache = MagicMock()
        bus = EntryChangeBus(cache)
        bus.register(lambda pw, md, cid=None: (_ for _ in ()).throw(ValueError("x")))
        with caplog.at_level(logging.WARNING, logger="src.business.managers.entry_change_bus"):
            bus.notify(password_changed=True)
        # 吞掉但不静默：异常经 logger.warning(exc_info=True) 落盘可见（调试线索），
        # 与「回调异常不得中断后续回调」的吞异常约束共同构成完整契约。
        assert any("回调执行失败" in r.message for r in caplog.records)


def _seed_meta(title: str) -> SearchMetadata:
    """构造与生产解密同构的摘要缓存条目（QL-076）。

    直接写裸 4 元组是 SearchMetadata（8 字段 NamedTuple）的半镜像表示：字段
    增删时裸元组静默落入错位形态、成员断言照常通过，无失败信号；经 NamedTuple
    构造（小写 4 项按 title.lower() 派生，与解密路径一致）一改即碎。
    """
    return SearchMetadata(title, "", "", "", title.lower(), "", "", "")


class TestEntryChangeBusEndToEnd:
    """用真实 vault fixture 的端到端路径：缓存真实失效 + 回调触发。

    深链豁免（MAINT-095 台账 C1 类，见 docs/audit_codes.md）：``_category_name_cache``
    成员断言（分类名缓存无公开观察面）、``_search_metadata_cache`` 写注入（播种
    缓存条目，只读观察面 search_metadata_cached_ids 不支持写）、``_change_bus``
    直驱（守护对象即 bus 本身的编排顺序）。
    """

    def test_notify_invalidates_real_category_cache(self, entry_mgr):
        """经真实 EntryManager.change_bus notify，分类名缓存应失效。"""
        cat_id = entry_mgr.categories.add_category(Category(name="Orig"))
        cache = entry_mgr.cache  # 公开只读 property（QL-044），免双层私有穿透

        cats = entry_mgr.categories.get_categories()
        orig_name = next(c.name for c in cats if c.id == cat_id)
        assert orig_name == "Orig"
        assert cat_id in cache._category_name_cache

        entry_mgr._change_bus.notify(
            password_changed=False,
            tags_changed=False,
            category_changed=True,
            clear_summaries=False,
        )
        assert cat_id not in cache._category_name_cache

    def test_notify_clear_summaries_clears_search_cache(self, entry_mgr, make_entry):
        """notify 默认 clear_summaries=True 清空搜索摘要缓存。"""
        import uuid

        cache = entry_mgr.cache  # 公开只读 property（QL-044），免双层私有穿透
        cid = uuid.uuid4().hex
        entry = make_entry(title="Hello")
        entry = dataclasses.replace(entry, crypto_id=cid)
        entry_mgr.add_entry(entry)

        # 手动填充一条摘要缓存（模拟列表访问后缓存命中）
        cache._search_metadata_cache[cid] = _seed_meta("Hello")
        assert cid in cache._search_metadata_cache

        entry_mgr._change_bus.notify(password_changed=False)
        assert cid not in cache._search_metadata_cache

    def test_notify_with_crypto_id_pops_single_entry(self, entry_mgr, make_entry):
        """notify 传 crypto_id 仅 pop 单条摘要，不清空全部。"""
        import uuid

        cache = entry_mgr.cache  # 公开只读 property（QL-044），免双层私有穿透
        cid_a = uuid.uuid4().hex
        cid_b = uuid.uuid4().hex
        entry_a = make_entry(title="A")
        entry_a = dataclasses.replace(entry_a, crypto_id=cid_a)
        entry_b = make_entry(title="B")
        entry_b = dataclasses.replace(entry_b, crypto_id=cid_b)
        entry_mgr.add_entry(entry_a)
        entry_mgr.add_entry(entry_b)
        cache._search_metadata_cache[cid_a] = _seed_meta("A")
        cache._search_metadata_cache[cid_b] = _seed_meta("B")

        entry_mgr._change_bus.notify(
            password_changed=False,
            crypto_id=cid_a,
        )
        assert cid_a not in cache._search_metadata_cache
        assert cid_b in cache._search_metadata_cache
