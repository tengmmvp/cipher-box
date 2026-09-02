"""composition 组装根的回调连线守护测试。

build_business_context 注册三条安全相关不变量回调：
- 锁定 → EntryManager 缓存失效（避免锁定后缓存残留明文摘要/分类名/TOTP/标签）
- 锁定 → CategoryManager 明文分类缓存清空（SEC-053）
- 条目变更 → SecurityAnalyzer 缓存失效（避免安全分析基于过期数据）

三者若在重构中漏注册一行，会导致锁定后缓存残留明文（安全属性）。本测试以
行为方式守护：填充缓存后触发 lock / change，断言对应缓存已清空。
另守护装配约束（ARCH-043/044）：限流器组合根装配与防重入守卫。
"""

import pytest

from src.business.composition import (
    build_business_context,
    build_change_master_rate_limiter,
    build_login_rate_limiter,
)
from src.business.services.rate_limiter import (
    CHANGE_MASTER_RATE_LIMIT_FILENAME,
    LOGIN_RATE_LIMIT_FILENAME,
)
from src.models import Category, Entry
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
    assert ctx.entry_mgr.cache.search_metadata_cached_ids
    vault.lock()
    # 经 register_on_lock 回调（entry_mgr.invalidate_caches → cache.invalidate_all）
    # 锁定后明文摘要缓存须清空，避免崩溃 dump 残留明文
    assert not ctx.entry_mgr.cache.search_metadata_cached_ids


def test_lock_callback_clears_category_plaintext_cache(tmp_path):
    """锁定触发 CategoryManager 明文分类缓存清空（SEC-053 守护）。

    ``_categories_cache`` 持有解密后的明文分类名，entry_mgr.invalidate_caches 只清
    EntryCacheManager 五套缓存、不含这份自持缓存——组合根漏注册时明文分类名会在
    锁定态（密钥已清零）驻留内存直至解锁重建，读时 epoch 守卫只防复用不清内存。
    """
    ctx, vault = _make_ctx(str(tmp_path))
    ctx.entry_mgr.categories.add_category(Category(name="PlaintextCategory"))
    categories = ctx.entry_mgr.categories.get_categories()  # 填充明文分类会话缓存
    assert any(c.name == "PlaintextCategory" for c in categories)
    assert ctx.entry_mgr.categories.categories_cache_present
    counts = ctx.entry_mgr.categories.get_category_entry_counts()  # 填充纯计数缓存
    assert ctx.entry_mgr.categories.entry_counts_cache is not None

    vault.lock()

    # 经 register_on_lock 注册的 category_mgr.invalidate_caches 清空明文缓存对象
    # （观察面 categories_cache_present 锚定缓存与 epoch 一并置空）
    assert not ctx.entry_mgr.categories.categories_cache_present
    # 纯计数缓存有意保留（无明文，锁定不改数据），此处锚定该决策防误清/漏清漂移
    assert ctx.entry_mgr.categories.entry_counts_cache == counts


def test_change_callback_invalidates_security_cache(tmp_path):
    """条目变更触发 security 增量更新（守护 register_on_change 连线）。

    add_entry 携带 crypto_id 走单条增量（PERF-079）：缓存保留并即时反映新条目
    （total +1）——若 register_on_change 漏注册，缓存将保持旧 total=0，本测试
    以缓存内容的即时正确性守护连线（原断言「缓存整体失效」已被增量路径取代）。
    """
    ctx, vault = _make_ctx(str(tmp_path))
    ctx.security.get_or_compute_report()  # 填充安全分析缓存（公开入口）
    assert ctx.security.get_cached_counts() is not None
    # add_entry → change_bus.notify → security.invalidate_cache（经注册回调）
    ctx.entry_mgr.add_entry(Entry(title="t2", username="u2", password="pw789012"))
    # 增量更新生效：缓存存活且 total 即时 +1（漏注册回调时残留 total=0）
    counts = ctx.security.get_cached_counts()
    assert counts is not None
    assert counts.total == 1


def test_toggle_favorite_preserves_security_cache(tmp_path):
    """收藏切换不触发安全分析整库重算（守护 metadata_changed=False 失效粒度）。

    is_favorite 不进入 weak/duplicate/old 的判定或展示，toggle_favorite 经
    change_bus.notify(password_changed=False, metadata_changed=False) 通知，
    SecurityAnalyzer.invalidate_cache 据此跳过失效——避免大库下每次收藏切换
    触发整库重解密（PERF 回归守护）。
    """
    ctx, vault = _make_ctx(str(tmp_path))
    entry_id = ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.security.get_or_compute_report()  # 填充安全分析缓存（公开入口）
    assert ctx.security.get_cached_counts() is not None

    ctx.entry_mgr.toggle_favorite(entry_id)  # 纯旁路变更

    # 缓存保留：invalidate_cache(False, False) 直接返回，未触发重算
    assert ctx.security.get_cached_counts() is not None


def test_category_change_preserves_security_cache(tmp_path):
    """分类调整不触发安全分析重算（分类不进入安全报告判定）。"""
    from src.models import Category

    ctx, vault = _make_ctx(str(tmp_path))
    ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.security.get_or_compute_report()
    assert ctx.security.get_cached_counts() is not None

    ctx.entry_mgr.categories.add_category(Category(name="TestCat_unique_42"))

    assert ctx.security.get_cached_counts() is not None


def test_build_business_context_rejects_reassembly(tmp_path):
    """同一 vault 重复 build_business_context 抛清晰错误（ARCH-044 防重入）。

    重复调用会在同一 vault 上叠加注册锁定/轮换回调（同一失效执行两遍）并泄漏旧
    cache/change_bus 实例——属装配错误，须在装配期立即暴露而非静默累积。
    """
    ctx, vault = _make_ctx(str(tmp_path))
    lock_callbacks_before = len(vault._on_lock_callbacks)

    with pytest.raises(RuntimeError, match="重复调用"):
        build_business_context(ctx.config, vault)

    # 失败的重复装配不产生副作用：回调列表未增长、无新 cache 实例泄漏
    assert len(vault._on_lock_callbacks) == lock_callbacks_before


def test_build_vault_orchestrator_uses_vault_assembly(tmp_path):
    """build_vault 装配的 orchestrator 与 vault 共享同一 db/signer 实例（ARCH-044）。

    编排器绕过 vault 直接写库时须受 vault 所装配 write_guard 保护；若允许传入独立
    db/signer，组合根可构造出「vault 与编排器各持一套」的漂移形态使该保护失效。
    """
    config = make_test_config(str(tmp_path))
    vault = make_vault(config)

    orchestrator = vault._lifecycle
    assert orchestrator is not None
    assert orchestrator._db is vault._assembly_db
    assert orchestrator._signer is vault._assembly_signer


def test_rate_limiters_built_by_composition_root(tmp_path):
    """登录/改密限流器经组合根工厂创建，状态文件名归业务模块单一事实源（ARCH-043）。

    限流器有跨进程持久状态（状态文件+哨兵+签名 config 登记），文件名散落 UI 时改名
    会使既有哨兵登记「孤儿化」；此处锚定组合根产物与业务层常量的一致性。
    """
    config = make_test_config(str(tmp_path))

    login = build_login_rate_limiter(config)
    change = build_change_master_rate_limiter(config)

    assert login._state_path == config.data_dir / LOGIN_RATE_LIMIT_FILENAME
    assert change._state_path == config.data_dir / CHANGE_MASTER_RATE_LIMIT_FILENAME
    # 注入 config：签名密钥就位（状态文件可签名持久化 + 哨兵登记到签名 config）
    assert login._signing_key is not None
    assert change._signing_key is not None

    # BusinessContext 携带改密限流器供 MenuController 注入 ChangeMasterDialog
    ctx, _vault = _make_ctx(str(tmp_path))
    assert isinstance(ctx.change_master_rate_limiter._state_path, type(config.data_dir))
    assert ctx.change_master_rate_limiter._state_path.name == CHANGE_MASTER_RATE_LIMIT_FILENAME
