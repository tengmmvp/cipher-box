"""composition 组装根的回调连线守护测试。

build_business_context 注册两条安全相关不变量回调：
- 锁定 → EntryManager 缓存失效（避免锁定后缓存残留明文摘要/分类名/TOTP/标签）
- 条目变更 → SecurityAnalyzer 缓存失效（避免安全分析基于过期数据）

二者若在重构中漏注册一行，会导致锁定后缓存残留明文（安全属性）。本测试以
行为方式守护：填充缓存后触发 lock / change，断言对应缓存已清空。
"""

from src.business.composition import build_business_context
from src.models import Entry
from tests.helpers import make_test_config, make_vault


def _make_ctx(tmp_dir: str):
    config = make_test_config(tmp_dir)
    vault = make_vault(config)
    vault.initialize("TestComposition!2026")
    return build_business_context(config, vault), vault


def test_lock_callback_invalidates_entry_cache(tmp_path):
    """锁定触发 entry 缓存清空（守护 register_on_lock → invalidate_caches 连线）。"""
    ctx, vault = _make_ctx(str(tmp_path))
    ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.entry_mgr.get_entry_summaries()  # 填充搜索摘要缓存
    assert ctx.entry_mgr._cache._search_metadata_cache  # 已填充
    vault.lock()
    # 经 register_on_lock 回调（entry_mgr.invalidate_caches → cache.invalidate_all）
    # 锁定后明文摘要缓存须清空，避免崩溃 dump 残留明文
    assert not ctx.entry_mgr._cache._search_metadata_cache


def test_change_callback_invalidates_security_cache(tmp_path):
    """条目变更触发 security 缓存失效（守护 register_on_change 连线）。"""
    ctx, vault = _make_ctx(str(tmp_path))
    ctx.security._cached_analysis()  # 填充安全分析缓存
    assert ctx.security._analysis_cache is not None
    # add_entry → change_bus.notify → security.invalidate_cache（经注册回调）
    ctx.entry_mgr.add_entry(Entry(title="t2", username="u2", password="pw789012"))
    assert ctx.security._analysis_cache is None
