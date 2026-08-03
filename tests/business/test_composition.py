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
    assert ctx.entry_mgr._cache._search_metadata_cache
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


def test_toggle_favorite_preserves_security_cache(tmp_path):
    """收藏切换不触发安全分析整库重算（守护 metadata_changed=False 失效粒度）。

    is_favorite 不进入 weak/duplicate/old 的判定或展示，toggle_favorite 经
    change_bus.notify(password_changed=False, metadata_changed=False) 通知，
    SecurityAnalyzer.invalidate_cache 据此跳过失效——避免大库下每次收藏切换
    触发整库重解密（PERF 回归守护）。
    """
    ctx, vault = _make_ctx(str(tmp_path))
    entry_id = ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.security._cached_analysis()  # 填充安全分析缓存
    assert ctx.security._analysis_cache is not None

    ctx.entry_mgr.toggle_favorite(entry_id)  # 纯旁路变更

    # 缓存保留：invalidate_cache(False, False) 直接返回，未触发重算
    assert ctx.security._analysis_cache is not None


def test_category_change_preserves_security_cache(tmp_path):
    """分类调整不触发安全分析重算（分类不进入安全报告判定）。"""
    from src.models import Category

    ctx, vault = _make_ctx(str(tmp_path))
    ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.security._cached_analysis()
    assert ctx.security._analysis_cache is not None

    ctx.entry_mgr.categories.add_category(Category(name="TestCat_unique_42"))

    assert ctx.security._analysis_cache is not None
