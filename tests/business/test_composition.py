"""composition 组装根的回调连线守护测试。

build_business_context 注册三条安全相关不变量回调：
- 锁定 → EntryManager 缓存失效（避免锁定后缓存残留明文摘要/分类名/TOTP/标签）
- 锁定 → CategoryManager 明文分类缓存清空（SEC-053）
- 条目变更 → SecurityAnalyzer 缓存失效（避免安全分析基于过期数据）

三者若在重构中漏注册一行，会导致锁定后缓存残留明文（安全属性）。本测试以
行为方式守护：填充缓存后触发 lock / change，断言对应缓存已清空。
另守护装配约束（ARCH-043/044）：限流器组合根装配与防重入守卫。

MAINT-095 豁免：本文件对装配内部形态（``_on_lock_callbacks`` /
``_lifecycle/_assembly_db/_assembly_signer`` / ``_signing_key``）的直读属装配
不变量白盒守护（守护对象即内部装配形态本身，无公开观察面），豁免类别与数量
口径见 docs/audit_codes.md 的 MAINT-095 豁免台账（本文件属台账 C1 类）。
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
from tests.helpers import make_test_config


def _make_ctx(make_vault_env):
    """组装生产接线的 BusinessContext（建库→初始化经 make_vault_env 工厂统一装配/回收）。"""
    env = make_vault_env()
    return build_business_context(env.config, env.vault), env.vault


def test_lock_callback_invalidates_entry_cache(make_vault_env):
    """锁定触发 entry 缓存清空（守护 register_on_lock → invalidate_caches 连线）。"""
    ctx, vault = _make_ctx(make_vault_env)
    ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.entry_mgr.get_entry_summaries()  # 填充搜索摘要缓存
    assert ctx.entry_mgr.cache.search_metadata_cached_ids
    vault.lock()
    # 经 register_on_lock 回调（entry_mgr.invalidate_caches → cache.invalidate_all）
    # 锁定后明文摘要缓存须清空，避免崩溃 dump 残留明文
    assert not ctx.entry_mgr.cache.search_metadata_cached_ids


def test_lock_callback_clears_category_plaintext_cache(make_vault_env):
    """锁定触发 CategoryManager 明文分类缓存清空（SEC-053 守护）。

    ``_categories_cache`` 持有解密后的明文分类名，entry_mgr.invalidate_caches 只清
    EntryCacheManager 五套缓存、不含这份自持缓存——组合根漏注册时明文分类名会在
    锁定态（密钥已清零）驻留内存直至解锁重建，读时 epoch 守卫只防复用不清内存。
    """
    ctx, vault = _make_ctx(make_vault_env)
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


def test_change_callback_invalidates_security_cache(make_vault_env):
    """条目变更触发 security 增量更新（守护 register_on_change 连线）。

    add_entry 携带 crypto_id 走单条增量（PERF-079）：缓存保留并即时反映新条目
    （total +1）——若 register_on_change 漏注册，缓存将保持旧 total=0，本测试
    以缓存内容的即时正确性守护连线（原断言「缓存整体失效」已被增量路径取代）。
    """
    ctx, vault = _make_ctx(make_vault_env)
    ctx.security.get_or_compute_report()  # 填充安全分析缓存（公开入口）
    assert ctx.security.get_cached_counts() is not None
    # add_entry → change_bus.notify → security.invalidate_cache（经注册回调）
    ctx.entry_mgr.add_entry(Entry(title="t2", username="u2", password="pw789012"))
    # 增量更新生效：缓存存活且 total 即时 +1（漏注册回调时残留 total=0）
    counts = ctx.security.get_cached_counts()
    assert counts is not None
    assert counts.total == 1


def test_toggle_favorite_preserves_security_cache(make_vault_env):
    """收藏切换不触发安全分析整库重算（守护 metadata_changed=False 失效粒度）。

    is_favorite 不进入 weak/duplicate/old 的判定或展示，toggle_favorite 经
    change_bus.notify(password_changed=False, metadata_changed=False) 通知，
    SecurityAnalyzer.invalidate_cache 据此跳过失效——避免大库下每次收藏切换
    触发整库重解密（PERF 回归守护）。
    """
    ctx, vault = _make_ctx(make_vault_env)
    entry_id = ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.security.get_or_compute_report()  # 填充安全分析缓存（公开入口）
    assert ctx.security.get_cached_counts() is not None

    ctx.entry_mgr.toggle_favorite(entry_id)  # 纯旁路变更

    # 缓存保留：invalidate_cache(False, False) 直接返回，未触发重算
    assert ctx.security.get_cached_counts() is not None


def test_category_change_preserves_security_cache(make_vault_env):
    """分类调整不触发安全分析重算（分类不进入安全报告判定）。"""
    from src.models import Category

    ctx, vault = _make_ctx(make_vault_env)
    ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
    ctx.security.get_or_compute_report()
    assert ctx.security.get_cached_counts() is not None

    ctx.entry_mgr.categories.add_category(Category(name="TestCat_unique_42"))

    assert ctx.security.get_cached_counts() is not None


def test_build_business_context_rejects_reassembly(make_vault_env):
    """同一 vault 重复 build_business_context 抛清晰错误（ARCH-044 防重入）。

    重复调用会在同一 vault 上叠加注册锁定/轮换回调（同一失效执行两遍）并泄漏旧
    cache/change_bus 实例——属装配错误，须在装配期立即暴露而非静默累积。
    ``vault._on_lock_callbacks`` 直读属装配不变量白盒守护（MAINT-095 豁免）。
    """
    ctx, vault = _make_ctx(make_vault_env)
    lock_callbacks_before = len(vault._on_lock_callbacks)

    with pytest.raises(RuntimeError, match="重复调用"):
        build_business_context(ctx.config, vault)

    # 失败的重复装配不产生副作用：回调列表未增长、无新 cache 实例泄漏
    assert len(vault._on_lock_callbacks) == lock_callbacks_before


def test_build_business_context_rejects_vault_without_lifecycle(tmp_path):
    """未装配生命周期编排器的 vault 被组合根前置拒绝（ARCH-047）。

    绕过 build_vault 手工构造（或漏调 attach_lifecycle）的 vault 若被放行，其
    生命周期方法（initialize/unlock/lock/close/change_master_password）会推迟到
    首次调用才抛「attach_lifecycle 未调用」——错误远离装配根且语义含糊。装配期
    显式校验使错误前置、指向装配代码；挂上编排器后同一 vault 可正常装配（校验
    的是装配态而非身份）。
    """
    from src.business.managers.vault_lifecycle import VaultLifecycleOrchestrator
    from src.business.managers.vault_manager import VaultManager
    from src.business.services.database_bootstrap import DatabaseBootstrap

    config = make_test_config(str(tmp_path))
    db, signer = DatabaseBootstrap.bootstrap(config, test_mode=True)
    vault = VaultManager(config, db, signer)  # 绕过 build_vault，未挂编排器

    assert vault.lifecycle_attached is False
    with pytest.raises(RuntimeError, match="attach_lifecycle"):
        build_business_context(config, vault)

    # 补挂编排器后同一 vault 正常装配：校验可修复而非永久拒绝
    vault.attach_lifecycle(VaultLifecycleOrchestrator(vault))
    ctx = build_business_context(config, vault)
    assert ctx.vault is vault


def test_build_business_context_allows_retry_after_failed_assembly(make_vault_env, monkeypatch):
    """装配中途异常回退防重入登记，修复后重试可成功（ARCH-046）。

    原实现先登记再装配：manager 构造抛异常时 vault 已入 _assembled_vaults，
    重试被误拒且报错语义误导（「上次装配失败」被述为「重复调用」）。回退后重试
    等价全新装配；成功路径的防重入守卫由 rejects_reassembly 测试守护。
    """
    env = make_vault_env()
    config, vault = env.config, env.vault

    from src.business import composition

    def _boom(*args, **kwargs):
        raise RuntimeError("装配中途失败")

    monkeypatch.setattr(composition, "BackupRestoreManager", _boom)
    with pytest.raises(RuntimeError, match="装配中途失败"):
        build_business_context(config, vault)

    # 防重入登记已随异常回退：恢复正常装配体后重试成功（而非被误拒为重复调用）
    monkeypatch.undo()
    ctx = build_business_context(config, vault)
    assert ctx.vault is vault
    # 成功装配后防重入守卫仍生效（回退未破坏 ARCH-044 语义）
    with pytest.raises(RuntimeError, match="重复调用"):
        build_business_context(config, vault)


def test_failed_assembly_leaves_no_orphan_callbacks(make_vault_env, monkeypatch):
    """构造异常时回调零注册，重试后回调列表不翻倍（ARCH-057）。

    原实现 register_on_transaction_committed 与 lock/epoch 回调夹杂在构造链
    中间：链上构造抛异常时 vault 已永久持有孤儿回调，discard 重试再注册一套
    （clear 幂等故无功能错误，但「失败回退无回调残留」的声明不变量为假）。
    重排后构造段零注册。``_on_lock_callbacks`` /
    ``_on_transaction_committed_callbacks`` 直读属装配不变量白盒守护
    （MAINT-095 豁免）。
    """
    env = make_vault_env()
    config, vault = env.config, env.vault
    # make_vault_env 的 EntryManager 已注册 1 个 seam 回调，断言按增量计
    tx_before = len(vault._on_transaction_committed_callbacks)
    lock_before = len(vault._on_lock_callbacks)

    from src.business import composition

    def _boom(*args, **kwargs):
        raise RuntimeError("装配中途失败")

    # 构造链末段的 BackupRestoreManager 抛异常——修复前此刻 tx/lock 回调均已注册
    monkeypatch.setattr(composition, "BackupRestoreManager", _boom)
    with pytest.raises(RuntimeError, match="装配中途失败"):
        build_business_context(config, vault)
    # 失败路径零注册：两类回调列表均未增长（无孤儿残留）
    assert len(vault._on_transaction_committed_callbacks) == tx_before
    assert len(vault._on_lock_callbacks) == lock_before

    # 重试成功后回调各注册一套，不翻倍
    monkeypatch.undo()
    ctx = build_business_context(config, vault)
    assert ctx.vault is vault
    assert len(vault._on_transaction_committed_callbacks) == tx_before + 1
    assert len(vault._on_lock_callbacks) == lock_before + 3


def test_build_vault_orchestrator_uses_vault_assembly(make_vault_env):
    """build_vault 装配的 orchestrator 与 vault 共享同一 db/signer 实例（ARCH-044）。

    编排器绕过 vault 直接写库时须受 vault 所装配 write_guard 保护；若允许传入独立
    db/signer，组合根可构造出「vault 与编排器各持一套」的漂移形态使该保护失效。
    ``_lifecycle/_assembly_db/_assembly_signer`` 直读属装配不变量白盒守护
    （MAINT-095 豁免：守护对象即内部装配形态本身，无公开观察面）。
    """
    vault = make_vault_env(initialize=False).vault

    orchestrator = vault._lifecycle
    assert orchestrator is not None
    assert orchestrator._db is vault._assembly_db
    assert orchestrator._signer is vault._assembly_signer


def test_rate_limiters_built_by_composition_root(tmp_path, make_vault_env):
    """登录/改密限流器经组合根工厂创建，状态文件名归业务模块单一事实源（ARCH-043）。

    限流器有跨进程持久状态（状态文件+哨兵+签名 config 登记），文件名散落 UI 时改名
    会使既有哨兵登记「孤儿化」；此处锚定组合根产物与业务层常量的一致性。
    """
    config = make_test_config(tmp_path)

    login = build_login_rate_limiter(config)
    change = build_change_master_rate_limiter(config)

    assert login.state_path == config.data_dir / LOGIN_RATE_LIMIT_FILENAME
    assert change.state_path == config.data_dir / CHANGE_MASTER_RATE_LIMIT_FILENAME
    # 注入 config：签名密钥就位（状态文件可签名持久化 + 哨兵登记到签名 config）。
    # _signing_key 直读属装配不变量白盒守护（MAINT-095 豁免，无公开观察面）。
    assert login._signing_key is not None
    assert change._signing_key is not None

    # BusinessContext 携带改密限流器供 MenuController 注入 ChangeMasterDialog
    ctx, _vault = _make_ctx(make_vault_env)
    assert isinstance(ctx.change_master_rate_limiter.state_path, type(config.data_dir))
    assert ctx.change_master_rate_limiter.state_path.name == CHANGE_MASTER_RATE_LIMIT_FILENAME
