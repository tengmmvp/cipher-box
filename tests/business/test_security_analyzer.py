"""``SecurityAnalyzer.compute_health_score`` 与搜索匹配等价性测试。

覆盖 ``src/business/services/security_analyzer.py::compute_health_score`` 静态方法的
边界（空库、满分、各档累加、clamp）与 ``src/business/services/entry_search_match.py``
的 ``matches_search`` / ``matches_search_lower`` 在相同输入下结果等价（后者复用预
计算小写字段，是前者的批量优化版，匹配语义须完全一致）。

MAINT-095 豁免说明：本文件对 ``_analysis_cache`` 内部键（``_fingerprint_map`` /
``_summaries_with_dates`` / ``_key_epoch`` 等）的直读属**白盒结构守护**——出口契约
（PERF-062 剥离）、指纹桶对象身份共享（PERF-076/085）、epoch 快照（SEC-040）等
不变量本身就是「内部缓存结构与出口视图的差异」，公开观察面（get_cached_report
已剥离内部键）无法表达；有公开等价观测的一律走公开面。豁免类别与数量口径见
docs/audit_codes.md 的 MAINT-095 豁免台账（本文件属台账 C1 类）。
"""

import dataclasses

import pytest

from src.business.composition import build_business_context
from src.business.services.entry_search_match import matches_search, matches_search_lower
from src.business.services.security_analyzer import SecurityAnalyzer
from src.models import Entry
from tests.helpers import decrypt_all_entries


class TestComputeHealthScore:
    """compute_health_score 边界与权重：空库满分、clamp、各档累加与权重排序。"""

    def test_empty_vault_scores_full(self):
        """total=0（空库）得满分 100：无风险条目即无扣分。"""
        assert SecurityAnalyzer.compute_health_score(0, 0, 0, 0) == 100

    def test_perfect_vault_with_entries_scores_full(self):
        """有条目但无任何风险（weak/dup/old 全 0）仍得 100。"""
        assert SecurityAnalyzer.compute_health_score(0, 0, 0, 5) == 100

    def test_all_weak_clamps_to_zero(self):
        """全部为弱密码时扣分超出 100，clamp 到 0（HEALTH_PENALTY_WEAK=15 → 1.0*1500）。"""
        assert SecurityAnalyzer.compute_health_score(10, 0, 0, 10) == 0

    def test_partial_penalties_exact_value(self):
        """各档累加：total=100、weak=2、dup=1、old=3 → 100-(30+10+15)=45。"""
        score = SecurityAnalyzer.compute_health_score(2, 1, 3, 100)
        assert score == 45

    @pytest.mark.parametrize(
        "weak,dup,old,total",
        [
            (0, 0, 0, 0),
            (5, 5, 5, 5),  # 全风险 → clamp 0
            (100, 100, 100, 100),
            (1, 1, 1, 100),  # 轻微风险
            (0, 0, 100, 100),  # 全过期
        ],
    )
    def test_score_always_in_zero_to_hundred(self, weak, dup, old, total):
        """任意合法输入，得分恒在 [0, 100]。"""
        score = SecurityAnalyzer.compute_health_score(weak, dup, old, total)
        assert 0 <= score <= 100

    def test_weak_penalty_heavier_than_duplicate_and_old(self):
        """弱密码惩罚(15) > 重复(10) > 过期(5)：同等占比下弱密码扣分最多。

        守护权重常量不被误调换（HEALTH_PENALTY_WEAK/DUPLICATE/OLD）。用 count=1、
        total=100 的小占比避免 clamp 到 0 抹平差异。
        """
        total = 100
        score_weak = SecurityAnalyzer.compute_health_score(1, 0, 0, total)
        score_dup = SecurityAnalyzer.compute_health_score(0, 1, 0, total)
        score_old = SecurityAnalyzer.compute_health_score(0, 0, 1, total)
        assert score_weak < score_dup < score_old


def _entry(title="", username="", url="", tags="") -> Entry:
    return Entry(title=title, username=username, url=url, tags=tags)


@pytest.mark.parametrize(
    "title,username,url,tags,query",
    [
        ("GitHub", "alice", "https://github.com", "dev,code", ""),
        ("GitHub", "alice", "https://github.com", "dev,code", "git"),
        ("GitHub", "alice", "https://github.com", "dev,code", "ALICE"),  # 大写关键词
        ("GitHub", "alice", "https://github.com", "dev,code", "CODE"),  # 命中 tags
        ("GitHub", "alice", "https://github.com", "dev,code", "xyz"),  # 无匹配
        ("博客", "用户", "https://blog.cn", "中文,测试", "中"),  # unicode 命中
        ("博客", "用户", "https://blog.cn", "中文,测试", "BLOG"),  # url 命中
        ("", "", "", "", "missing"),  # 全空字段
    ],
)
def test_matches_search_equivalence(title, username, url, tags, query):
    """``matches_search`` 与 ``matches_search_lower`` 对相同输入返回相同结果。

    ``matches_search_lower`` 复用预计算小写字段 (title_lower, username_lower,
    url_lower, tags_lower)，是批量搜索热路径的优化版；其匹配语义（关键词 lower 后
    对 4 字段做子串匹配）须与 ``matches_search`` 完全一致，否则热路径与同步路径漂移。
    """
    entry = _entry(title, username, url, tags)
    lower = (title.lower(), username.lower(), url.lower(), tags.lower())

    assert matches_search(entry, query) == matches_search_lower(lower, query)


def test_matches_search_empty_query_always_matches():
    """空关键词匹配所有（两函数一致返回 True）。"""
    entry = _entry("Any", "u", "https://x", "t")
    lower = ("any", "u", "https://x", "t")
    assert matches_search(entry, "") is True
    assert matches_search_lower(lower, "") is True


# ======== 单条增量缓存失效（PERF-021）========


class TestIncrementalCacheInvalidation:
    """单条条目变更的增量报告更新（PERF-021）。

    change_bus 回调携带 crypto_id 后，SecurityAnalyzer.invalidate_caches 走单条
    增量路径：仅重读/重分类该条并重算聚合计数，其余条目的解密与 HMAC 指纹结果
    复用（不再整库重算）。经 build_business_context 以生产连线（change_bus →
    invalidate_caches）驱动，避免绕过注册路径的假阳性。
    """

    @pytest.fixture
    def ctx_vault(self, make_vault_env):
        """组装生产接线的 BusinessContext（change_bus → security 增量失效）。"""
        env = make_vault_env(master_password="TestIncremental!2026")
        ctx = build_business_context(env.config, env.vault)
        yield ctx, env.vault

    @staticmethod
    def _forbid_full_analysis():
        def _raise(*args, **kwargs):
            raise AssertionError("增量失效后不应触发整库 full_analysis 重算")

        return _raise

    def test_title_edit_keeps_analysis_cache(self, ctx_vault, monkeypatch):
        """纯元数据编辑（改标题）后报告缓存命中：不重算，展示标题已刷新。"""
        ctx, _vault = ctx_vault
        entry_id = ctx.entry_mgr.add_entry(Entry(title="旧标题", username="u", password="weak"))
        report = ctx.security.get_or_compute_report()
        assert report["weak_count"] == 1
        assert report["weak_entries"][0].title == "旧标题"

        # 改标题（密码未变）→ 增量更新；缓存命中路径不得触发整库重算
        entry = ctx.entry_mgr.get_entry(entry_id)
        entry = dataclasses.replace(entry, title="新标题")
        ctx.entry_mgr.update_entry(entry)

        monkeypatch.setattr(ctx.security, "full_analysis", self._forbid_full_analysis())
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["weak_count"] == 1
        assert refreshed["weak_entries"][0].title == "新标题"

    def test_password_change_flips_duplicate_state_incrementally(self, ctx_vault, monkeypatch):
        """改单条密码：同旧指纹条目的重复状态正确翻转，其余结果复用不重算。"""
        ctx, _vault = ctx_vault
        shared = "SharedPass!2026"
        id_a = ctx.entry_mgr.add_entry(Entry(title="A", username="a", password=shared))
        ctx.entry_mgr.add_entry(Entry(title="B", username="b", password=shared))
        ctx.entry_mgr.add_entry(Entry(title="C", username="c", password="UniquePass!2026"))

        report = ctx.security.get_or_compute_report()
        assert report["total"] == 3
        assert report["duplicate_count"] == 1
        assert {e.title for g in report["duplicate_groups"] for e in g} == {"A", "B"}

        # A 改为全新唯一密码：A 离开共享指纹桶，B 不再构成重复
        entry = ctx.entry_mgr.get_entry(id_a)
        entry = dataclasses.replace(entry, password="FreshSecret!2026")
        ctx.entry_mgr.update_entry(entry)

        monkeypatch.setattr(ctx.security, "full_analysis", self._forbid_full_analysis())
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["duplicate_count"] == 0
        assert refreshed["duplicate_groups"] == []
        assert refreshed["total"] == 3  # 单条更新不改 total

        # 与全量重算结果一致（新鲜实例直接从库计算）
        from src.business.managers.entry_cache import EntryCacheManager
        from src.business.services.security_analyzer import SecurityAnalyzer

        fresh = SecurityAnalyzer(ctx.vault, EntryCacheManager(ctx.vault))
        baseline = fresh.full_analysis()
        assert baseline["duplicate_count"] == refreshed["duplicate_count"]
        assert baseline["weak_count"] == refreshed["weak_count"]
        assert baseline["old"] == refreshed["old"]

    def test_add_delete_restore_are_incremental(self, ctx_vault, monkeypatch):
        """增删恢复携带 crypto_id 走单条增量（PERF-079）：缓存保留、total 差分正确。

        原行为：增删经 crypto_id=None 触发整库失效，100ms 后状态栏 worker 执行
        full_analysis（O(n) 全库解密+指纹+摘要）。现 add/restore 重读插入并按缓存
        成员资格上调 total，delete 见 is_deleted 构造移除差分下调 total——全程
        不触发整库重算。
        """
        ctx, _vault = ctx_vault
        ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
        report = ctx.security.get_or_compute_report()
        assert report["total"] == 1

        monkeypatch.setattr(ctx.security, "full_analysis", self._forbid_full_analysis())

        # 新增：total 1→2，缓存命中即反映（无整库重算）
        ctx.entry_mgr.add_entry(Entry(title="t2", username="u2", password="pw654321"))
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["total"] == 2

        # 与全量重算等价（新鲜实例直接从库计算）
        self._assert_matches_fresh_full_analysis(ctx)

        # 软删除：total 2→1，重复/弱名单同步移除
        entry_id = next(e.id for e in decrypt_all_entries(ctx.entry_mgr) if e.title == "t2")
        ctx.entry_mgr.delete_entry(entry_id)
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["total"] == 1
        self._assert_matches_fresh_full_analysis(ctx)

        # 恢复：total 1→2（重读插入）
        ctx.entry_mgr.restore_entry(entry_id)
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["total"] == 2
        self._assert_matches_fresh_full_analysis(ctx)

        # 物理删除（回收站路径，条目已软删）：差分幂等 no-op，total 不变
        ctx.entry_mgr.delete_entry(entry_id)
        ctx.security.get_or_compute_report()
        ctx.entry_mgr.permanent_delete_entry(entry_id)
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["total"] == 1
        self._assert_matches_fresh_full_analysis(ctx)

    @staticmethod
    def _assert_matches_fresh_full_analysis(ctx) -> None:
        """增量后的缓存报告与新鲜全量分析在四项计数上一致（等价守护）。"""
        from src.business.managers.entry_cache import EntryCacheManager
        from src.business.services.security_analyzer import SecurityAnalyzer

        refreshed = ctx.security.get_or_compute_report()
        fresh = SecurityAnalyzer(ctx.vault, EntryCacheManager(ctx.vault)).full_analysis()
        for key in ("total", "weak_count", "duplicate_count", "old"):
            assert refreshed[key] == fresh[key], f"增量与全量在 {key} 上分叉"

    def test_delete_flips_duplicate_state_incrementally(self, ctx_vault, monkeypatch):
        """删除共享密码的一条：另一条离开重复分组，total 差分 -1，不整库重算。"""
        ctx, _vault = ctx_vault
        shared = "SharedDelete!2026"
        ctx.entry_mgr.add_entry(Entry(title="A", username="a", password=shared))
        id_b = ctx.entry_mgr.add_entry(Entry(title="B", username="b", password=shared))
        report = ctx.security.get_or_compute_report()
        assert report["total"] == 2
        assert report["duplicate_count"] == 1

        monkeypatch.setattr(ctx.security, "full_analysis", self._forbid_full_analysis())
        ctx.entry_mgr.delete_entry(id_b)

        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["duplicate_count"] == 0
        assert refreshed["duplicate_groups"] == []
        assert refreshed["total"] == 1

    def test_add_with_empty_cache_falls_back_cleanly(self, ctx_vault):
        """缓存缺失时增删通知回退全量失效语义（无缓存可增量，行为不变）。"""
        ctx, _vault = ctx_vault
        ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
        # 未曾 get_or_compute_report → 缓存为 None（公开观察面 get_cached_report
        # 同样返回 None），增量路径返回 False 后的全量失效对 None 缓存是无操作，
        # 随后首次计算正常覆盖新条目。
        assert ctx.security.get_cached_report() is None
        report = ctx.security.get_or_compute_report()
        assert report["total"] == 1


class TestInflightInvalidationGenerationGuard:
    """在飞 full_analysis 期间的全量失效不污染缓存（PERF-080 补全的写回守卫）。

    场景：状态栏 worker 的 full_analysis 读库后用户删除条目 → 删除的增量 notify
    发现缓存为 None 直接 no-op（仅失效世代递增）→ worker 完成时把删除前报告写入
    缓存（fresh TTL）→ _on_finished 消费脏标记重启 → fast path get_cached_counts
    命中刚写的过期报告（原缺陷：计数陈旧需等 TTL 自愈）。守卫：写回前比对失效
    世代，不一致则丢弃写回（报告照常返回供本次渲染），重启轮走新全量。
    """

    @pytest.fixture
    def ctx_vault(self, make_vault_env):
        """组装生产接线的 BusinessContext（change_bus → security 增量失效）。"""
        env = make_vault_env(master_password="TestGenerationGuard!2026")
        ctx = build_business_context(env.config, env.vault)
        yield ctx, env.vault

    def test_midflight_invalidation_discards_stale_writeback(self, ctx_vault, monkeypatch):
        """读库后失效、完成后写回：缓存不被过期报告污染，重启轮重新全量。"""
        ctx, _vault = ctx_vault
        id_t1 = ctx.entry_mgr.add_entry(Entry(title="t1", username="u", password="pw123456"))
        ctx.entry_mgr.add_entry(Entry(title="t2", username="u", password="pw654321"))

        # 模拟「worker 读库后、写回前」的并发删除：real_full 返回后才删除，
        # 契合 full_analysis 已越过读库点、缓存尚未写回的窗口。
        real_full = ctx.security.full_analysis
        midflight_done: list[bool] = []

        def _full_then_delete(days, *, cancel_check=None, now=None):
            report = real_full(days, cancel_check=cancel_check, now=now)
            if not midflight_done:
                midflight_done.append(True)
                ctx.entry_mgr.delete_entry(id_t1)
            return report

        monkeypatch.setattr(ctx.security, "full_analysis", _full_then_delete)

        report = ctx.security.get_or_compute_report()

        # 本次渲染照常返回删除前报告（worker 结果不丢弃）
        assert report["total"] == 2
        assert midflight_done
        # 核心断言：缓存未被过期报告污染——fast path miss（修复前此处命中
        # fresh TTL 的 total=2 过期报告）
        assert ctx.security.get_cached_counts() is None
        # 脏标记重启轮（_on_finished → update_status_bar → get_or_compute_report）
        # 走新全量：计数反映删除
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["total"] == 1
        assert ctx.security.get_cached_counts() is not None


# ======== 出口契约与增量重建局部化（PERF-062）========


class TestReportExitContract:
    """缓存报告出口剥离内部键（PERF-062）+ 增量更新指纹桶局部重建验证。

    出口契约：get_cached_report / get_or_compute_report 返回的报告仅含公开字段
    （SecurityReport 出口形态的键集），不含 ``_fingerprint_map`` /
    ``_summaries_with_dates`` / ``_key_epoch`` 内部键——这些仅缓存分层内部消费，
    剥离后出口深拷贝消失、增量更新的桶共享变安全。行为回归：days 重过滤与增量
    更新语义须与剥离前一致（仍基于内部缓存本体完成）。
    """

    @pytest.fixture
    def ctx_vault(self, make_vault_env):
        """组装生产接线的 BusinessContext（change_bus → security 增量失效）。"""
        env = make_vault_env(master_password="TestExitContract!2026")
        ctx = build_business_context(env.config, env.vault)
        yield ctx, env.vault

    _PUBLIC_KEYS = {
        "total",
        "weak_count",
        "weak_entries",
        "duplicate_groups",
        "duplicate_count",
        "old_entries",
        "old",
    }

    def test_exit_report_contains_only_public_keys(self, ctx_vault):
        """get_or_compute_report 与 get_cached_report 的出口均不含下划线内部键。"""
        ctx, _vault = ctx_vault
        ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="Str0ngPass!2026"))
        report = ctx.security.get_or_compute_report()
        assert set(report) == self._PUBLIC_KEYS
        # 缓存命中路径（get_cached_report）同样剥离。
        cached = ctx.security.get_cached_report()
        assert cached is not None
        assert set(cached) == self._PUBLIC_KEYS

    def test_exit_internal_cache_retains_full_keys(self, ctx_vault):
        """内部缓存本体仍持内部键（供 days 重过滤与增量更新），且不再持有公开
        列表键（PERF-085 收口：map 是唯一事实源，出口经 _export_report 派生，
        消除「同名公开列表键自首次增量差分起陈旧」的双表示）。"""
        ctx, _vault = ctx_vault
        ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="Str0ngPass!2026"))
        ctx.security.get_or_compute_report()
        internal = ctx.security._analysis_cache
        assert internal is not None
        assert "_fingerprint_map" in internal
        assert "_summaries_with_dates" in internal
        assert "_key_epoch" in internal
        # 收口守护：公开列表键不在缓存本体（出口从 map 派生）
        assert "weak_entries" not in internal
        assert "old_entries" not in internal
        assert "duplicate_groups" not in internal

    def test_days_refilter_still_works_after_stripping(self, ctx_vault):
        """days 重过滤行为不变：days 变化时按 _summaries_with_dates（内部键）重算 old。"""
        from datetime import UTC, datetime, timedelta

        ctx, _vault = ctx_vault
        ctx.entry_mgr.add_entry(
            Entry(
                title="old",
                username="u",
                password="Str0ngPass!2026",
                password_changed_at=(datetime.now(UTC) - timedelta(days=200)).isoformat(),
            )
        )
        ctx.security.get_or_compute_report(days=90)
        # days=365：200 天前未超阈值 → old=0；days=100：超阈值 → old=1。
        assert ctx.security.get_cached_report(days=365)["old"] == 0
        assert ctx.security.get_cached_report(days=100)["old"] == 1

    def test_incremental_update_shares_untouched_buckets(self, ctx_vault):
        """单条增量更新仅重建涉及的指纹桶，其余桶对象身份不变（共享验证）。"""
        ctx, _vault = ctx_vault
        shared = "SharedPass!2026"
        id_c = ctx.entry_mgr.add_entry(Entry(title="C", username="c", password="UniquePass!1"))
        ctx.entry_mgr.add_entry(Entry(title="A", username="a", password=shared))
        ctx.entry_mgr.add_entry(Entry(title="B", username="b", password=shared))
        ctx.security.get_or_compute_report()

        internal = ctx.security._analysis_cache
        assert internal is not None
        raw_c = ctx.entry_mgr.db.get_entry(id_c)
        assert raw_c is not None
        # 记录各桶的对象身份；「C 所在桶」应被重建，「A/B 所在桶」原样共享。
        buckets_before = {fp: id(group) for fp, group in internal["_fingerprint_map"].items()}
        c_fingerprint = next(
            fp
            for fp, group in internal["_fingerprint_map"].items()
            if any(e.crypto_id == raw_c.crypto_id for e in group)
        )

        # 纯元数据编辑（改标题）→ 增量更新 C 所在桶。
        entry = ctx.entry_mgr.get_entry(id_c)
        entry = dataclasses.replace(entry, title="C2")
        ctx.entry_mgr.update_entry(entry)

        buckets_after = {fp: id(group) for fp, group in internal["_fingerprint_map"].items()}
        # 未涉及的桶（A/B 指纹）对象身份不变；C 的指纹桶被重建（新 list 对象）。
        for fp, bucket_id in buckets_before.items():
            if fp == c_fingerprint:
                assert buckets_after[fp] != bucket_id
            else:
                assert buckets_after[fp] == bucket_id
        # 行为回归：重复分组仍正确（A/B 互为重复，C 唯一）。
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["duplicate_count"] == 1
        assert {e.title for g in refreshed["duplicate_groups"] for e in g} == {"A", "B"}


class TestIncrementalUpdateEpochSnapshot:
    """增量更新二次校验比对快照 epoch 而非实时 epoch（SEC-040，防跨 epoch grafting）。"""

    @pytest.fixture
    def ctx_vault(self, make_vault_env):
        """组装生产接线的 BusinessContext（change_bus → security 增量失效）。"""
        env = make_vault_env(master_password="TestEpochGuard!2026")
        ctx = build_business_context(env.config, env.vault)
        yield ctx, env.vault

    def test_cross_epoch_refill_aborts_incremental_grafting(self, ctx_vault):
        """锁外重分类期间 epoch 轮换且缓存被新 epoch 重填时，增量结果不得并入。

        防御纵深（当前 UI 时序不可达）：旧密钥派生的 _ClassifyResult 并入新 epoch
        缓存会污染重复检测指纹桶。二次校验比对首次校验快照的 epoch——快照失配
        即放弃本次增量（返回 False 交由调用方全量失效）。按实时 epoch 双检的旧
        实现会全部通过（实时 epoch 与重填缓存同为新值）并返回 True。
        """
        ctx, vault = ctx_vault
        entry_id = ctx.entry_mgr.add_entry(
            Entry(title="T", username="u", password="Str0ngPass!2026")
        )
        report = ctx.security.get_or_compute_report()
        assert report["total"] == 1
        raw = ctx.entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        original_epoch = vault.key_epoch
        original_classify = ctx.security._classify_entry

        def _classify_with_concurrent_rotation(raw_arg, key, **kwargs):
            # 模拟锁外重分类期间的并发改密/恢复：epoch 轮换 + full_analysis 以新 epoch
            # 重填缓存（_key_epoch 更新为新世代）。kwargs 透传 SEC-043 的 data_epoch
            # 等 keyword-only 参数，保持与生产签名解耦。
            vault.set_epoch("rotated-e2")
            assert ctx.security._analysis_cache is not None
            ctx.security._analysis_cache["_key_epoch"] = "rotated-e2"
            return original_classify(raw_arg, key, **kwargs)

        ctx.security._classify_entry = _classify_with_concurrent_rotation
        try:
            assert ctx.security._try_incremental_update(raw.crypto_id) is False
        finally:
            ctx.security._classify_entry = original_classify
            vault.set_epoch(original_epoch)
        # 缓存仍属新 epoch 重填的世代，未被旧世代结果并入
        assert ctx.security._analysis_cache is not None
        assert ctx.security._analysis_cache["_key_epoch"] == "rotated-e2"


class TestIncrementalFingerprintIndex:
    """_crypto_id_to_fp 反向索引与指纹桶的一致性守护（PERF-076/085）。

    索引是增量更新 O(1) 定位旧桶的依据，与 ``_fingerprint_map`` 平行维护
    （full_analysis 构建 / 增量更新同步）。两者失同步会使增量路径定位错桶——
    索引指向的桶不含该条目（误删/漏删桶成员）或桶内条目不在索引（回退扫描
    兜底但 O(桶数) 退化）。PERF-085 起无指纹条目以 None 哨兵入索引（键集与
    ``_summaries_with_dates`` 一致），本类锚定三条不变量在全量与增量路径后均成立。
    """

    @pytest.fixture
    def ctx_vault(self, make_vault_env):
        """组装生产接线的 BusinessContext（change_bus → security 增量失效）。"""
        env = make_vault_env(master_password="TestFpIndex!20260828")
        ctx = build_business_context(env.config, env.vault)
        yield ctx, env.vault

    @staticmethod
    def _assert_index_consistent(ctx):
        """三条不变量：索引键==summaries 键集；有指纹条目指向的桶含该条目；
        None 哨兵条目不在任何桶。"""
        internal = ctx.security._analysis_cache
        assert internal is not None
        fp_map = internal["_fingerprint_map"]
        index = internal["_crypto_id_to_fp"]
        summaries = internal["_summaries_with_dates"]
        assert set(index) == set(summaries), "索引键集须与 summaries 键集一致"
        for crypto_id, fingerprint in index.items():
            if fingerprint is None:
                continue
            assert fingerprint in fp_map, f"哨兵外索引值 {crypto_id} 须指向真实指纹桶"
            group = fp_map[fingerprint]
            assert any(e.crypto_id == crypto_id for e in group), (
                f"索引 {crypto_id} 指向的桶不含该条目"
            )

    def test_index_consistent_after_full_and_incremental(self, ctx_vault):
        """full_analysis 构建后一致；改密/改元数据两类增量更新后仍一致。"""
        import dataclasses

        ctx, _vault = ctx_vault
        shared = "SharedPass!2026"
        id_a = ctx.entry_mgr.add_entry(Entry(title="A", username="a", password=shared))
        id_b = ctx.entry_mgr.add_entry(Entry(title="B", username="b", password=shared))
        id_c = ctx.entry_mgr.add_entry(Entry(title="C", username="c", password="Pass0123!Unique"))
        ctx.security.get_or_compute_report()
        self._assert_index_consistent(ctx)

        # 增量一：改标题（元数据编辑，指纹不变）
        entry = ctx.entry_mgr.get_entry(id_c)
        ctx.entry_mgr.update_entry(dataclasses.replace(entry, title="C2"))
        self._assert_index_consistent(ctx)

        # 增量二：改密码（指纹移动——C 并入 A/B 的重复桶）
        entry = ctx.entry_mgr.get_entry(id_c)
        ctx.entry_mgr.update_entry(dataclasses.replace(entry, password=shared))
        self._assert_index_consistent(ctx)
        internal = ctx.security._analysis_cache
        assert internal is not None
        raw_c = ctx.entry_mgr.db.get_entry(id_c)
        assert raw_c is not None
        # C 的新指纹 == A 的指纹（同密码同密钥）
        fp_a = internal["_crypto_id_to_fp"][ctx.entry_mgr.db.get_entry(id_a).crypto_id]
        assert internal["_crypto_id_to_fp"][raw_c.crypto_id] == fp_a
        # 行为回归：三条同密码 → duplicate_count == 2
        assert ctx.security.get_or_compute_report()["duplicate_count"] == 2

        # 增量三：改为无密码（NOTE 语义——指纹移除，索引须换回 None 哨兵）
        entry = ctx.entry_mgr.get_entry(id_c)
        ctx.entry_mgr.update_entry(dataclasses.replace(entry, password=""))
        self._assert_index_consistent(ctx)
        internal = ctx.security._analysis_cache
        assert internal is not None
        assert internal["_crypto_id_to_fp"][raw_c.crypto_id] is None


class TestIncrementalNoFingerprintSentinel:
    """无指纹条目经索引 None 哨兵直达差分分支，不触发逐桶全扫描（PERF-085）。

    原缺陷：索引仅收录有指纹条目，无密码条目（note/identity/未填密码等常态）
    每次 add/update/delete/restore 差分的 ``fp_index.pop`` 必 miss，落入逐桶
    ``any(e.crypto_id == ...)`` 全扫描且注定失败——50k 库实测每次 8.8ms 纯浪费。
    守护：无指纹条目差分期间 ``_fingerprint_map.items()`` 不得被迭代（回退扫描
    的唯一入口），且行为与全量等价。
    """

    @pytest.fixture
    def ctx_vault(self, make_vault_env):
        """组装生产接线的 BusinessContext（change_bus → security 增量失效）。"""
        env = make_vault_env(master_password="TestNoFpSentinel!20260903")
        ctx = build_business_context(env.config, env.vault)
        yield ctx, env.vault

    @staticmethod
    def _install_counting_fp_map(ctx) -> None:
        """把缓存本体的 _fingerprint_map 换成 items() 计数子类，返回计数器。"""
        internal = ctx.security._analysis_cache
        assert internal is not None

        class _CountingFpMap(dict):
            """dict 子类：仅对 items() 迭代（回退扫描入口）计数。"""

            items_calls = 0

            def items(self):
                type(self).items_calls += 1
                return super().items()

        original = internal["_fingerprint_map"]
        internal["_fingerprint_map"] = _CountingFpMap(original)
        assert _CountingFpMap.items_calls == 0

    def test_passwordless_edit_and_delete_skip_bucket_scan(self, ctx_vault, monkeypatch):
        """无密码条目的编辑与软删除差分均不逐桶扫描，报告与全量等价。"""
        import dataclasses

        from src.business.managers.entry_cache import EntryCacheManager
        from src.business.services.security_analyzer import SecurityAnalyzer

        ctx, _vault = ctx_vault
        id_note = ctx.entry_mgr.add_entry(
            Entry(title="笔记", username="u", entry_type="note", password="")
        )
        # 无密码条目创建后先行全量（缓存就位，条目以哨兵入索引）
        ctx.security.get_or_compute_report()
        self._install_counting_fp_map(ctx)

        def _forbid_full(*_args, **_kwargs):
            raise AssertionError("无指纹差分不应触发整库 full_analysis 重算")

        monkeypatch.setattr(ctx.security, "full_analysis", _forbid_full)

        # 编辑（改标题）与删除均为无指纹差分：哨兵命中，不迭代任何桶
        entry = ctx.entry_mgr.get_entry(id_note)
        ctx.entry_mgr.update_entry(dataclasses.replace(entry, title="新标题"))
        ctx.entry_mgr.delete_entry(id_note)
        refreshed = ctx.security.get_or_compute_report()
        assert refreshed["total"] == 0

        internal = ctx.security._analysis_cache
        assert internal is not None
        assert type(internal["_fingerprint_map"]).items_calls == 0, (
            "无指纹条目差分不得触发逐桶全扫描（PERF-085 哨兵回归）"
        )
        # 行为等价守护：与新鲜全量一致
        fresh = SecurityAnalyzer(ctx.vault, EntryCacheManager(ctx.vault)).full_analysis()
        for key in ("total", "weak_count", "duplicate_count", "old"):
            assert refreshed[key] == fresh[key], f"增量与全量在 {key} 上分叉"

    def test_index_bucket_tear_tolerated_without_keyerror(self, ctx_vault):
        """索引与桶的两种撕裂形态（QL-068）差分不抛 KeyError、结果仍收敛。

        - 反向撕裂：索引有旧指纹但指纹桶缺失——兜底视同无旧桶，不 KeyError；
        - 正向撕裂：索引缺键但条目实际在某桶——回退逐桶扫描定位。
        """
        import dataclasses

        ctx, _vault = ctx_vault
        shared = "TornIndex!2026"
        id_a = ctx.entry_mgr.add_entry(Entry(title="A", username="a", password=shared))
        ctx.security.get_or_compute_report()

        # 反向撕裂：从指纹桶删除 A 所在桶（索引仍指向该指纹）
        internal = ctx.security._analysis_cache
        assert internal is not None
        raw_a = ctx.entry_mgr.db.get_entry(id_a)
        assert raw_a is not None
        fp_a = internal["_crypto_id_to_fp"][raw_a.crypto_id]
        del internal["_fingerprint_map"][fp_a]
        entry = ctx.entry_mgr.get_entry(id_a)
        ctx.entry_mgr.update_entry(dataclasses.replace(entry, password="FreshTorn!2026"))
        # 不抛 KeyError 即通过；结果与全量一致（差分视同无旧桶，A 以新指纹重建）
        self._assert_matches_fresh(ctx)

        # 正向撕裂：索引删除 A 新键（桶里仍有 A）——回退逐桶扫描定位旧桶
        internal = ctx.security._analysis_cache
        assert internal is not None
        del internal["_crypto_id_to_fp"][raw_a.crypto_id]
        ctx.entry_mgr.update_entry(
            dataclasses.replace(ctx.entry_mgr.get_entry(id_a), password="FreshTorn2!2026")
        )
        self._assert_matches_fresh(ctx)

    @staticmethod
    def _assert_matches_fresh(ctx) -> None:
        """增量后的缓存报告与新鲜全量分析在四项计数上一致（等价守护）。"""
        from src.business.managers.entry_cache import EntryCacheManager
        from src.business.services.security_analyzer import SecurityAnalyzer

        refreshed = ctx.security.get_or_compute_report()
        fresh = SecurityAnalyzer(ctx.vault, EntryCacheManager(ctx.vault)).full_analysis()
        for key in ("total", "weak_count", "duplicate_count", "old"):
            assert refreshed[key] == fresh[key], f"增量与全量在 {key} 上分叉"


class TestIncrementalClockInjection:
    """invalidate_caches 的 now 注入在增量路径真实生效（QL-057 守护）。

    原缺陷：``_apply_reclassified_entry`` 硬编码 ``datetime.now(UTC)``，测试注入
    时钟时增量路径与全量路径（full_analysis/_refilter_cache 均可注入）行为分叉，
    now 参数形同虚设。守护：注入未来时钟的增量更新须按注入时刻重判过期。
    """

    @pytest.fixture
    def ctx_vault(self, make_vault_env):
        """组装生产接线的 BusinessContext（同 TestIncrementalFingerprintIndex）。"""
        env = make_vault_env(master_password="TestClockInj!20260828")
        ctx = build_business_context(env.config, env.vault)
        yield ctx, env.vault

    def test_injected_clock_drives_incremental_old_reclassification(self, ctx_vault):
        """注入未来时钟的增量更新把未过期条目重判为过期。"""
        from datetime import UTC, datetime, timedelta

        ctx, _vault = ctx_vault
        now = datetime.now(UTC)
        # 密码 50 天前变更：days=90 下未过期
        id_e = ctx.entry_mgr.add_entry(
            Entry(
                title="E",
                username="e",
                password="Pass0123!Unique",
                password_changed_at=(now - timedelta(days=50)).isoformat(),
            )
        )
        report = ctx.security.get_or_compute_report(days=90)
        assert report["old"] == 0

        raw_e = ctx.entry_mgr.db.get_entry(id_e)
        assert raw_e is not None
        # 注入 400 天后的时钟做增量更新：50+400=450 天前 > 90 天 → 应计入过期
        future = now + timedelta(days=400)
        ctx.security.invalidate_caches(crypto_id=raw_e.crypto_id, now=future)

        followup = ctx.security.get_or_compute_report(days=90)
        assert followup["old"] == 1, "注入时钟须被增量路径消费（硬编码 now 的回归）"
