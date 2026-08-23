"""``SecurityAnalyzer.compute_health_score`` 与搜索匹配等价性测试。

覆盖 ``src/business/services/security_analyzer.py::compute_health_score`` 静态方法的
边界（空库、满分、各档累加、clamp）与 ``src/business/services/crypto_utils.py`` 的
``matches_search`` / ``matches_search_lower`` 在相同输入下结果等价（后者复用预计算
小写字段，是前者的批量优化版，匹配语义须完全一致）。
"""

import dataclasses

import pytest

from src.business.services.crypto_utils import matches_search, matches_search_lower
from src.business.services.security_analyzer import SecurityAnalyzer
from src.models import Entry


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

    change_bus 回调携带 crypto_id 后，SecurityAnalyzer.invalidate_cache 走单条
    增量路径：仅重读/重分类该条并重算聚合计数，其余条目的解密与 HMAC 指纹结果
    复用（不再整库重算）。经 build_business_context 以生产连线（change_bus →
    invalidate_cache）驱动，避免绕过注册路径的假阳性。
    """

    @pytest.fixture
    def ctx_vault(self, tmp_path):
        """组装生产接线的 BusinessContext（change_bus → security 增量失效）。"""
        from src.business.composition import build_business_context
        from tests.helpers import make_test_config, make_vault

        config = make_test_config(str(tmp_path))
        vault = make_vault(config)
        vault.initialize("TestIncremental!2026")
        ctx = build_business_context(config, vault)
        yield ctx, vault
        vault.close()

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

    def test_add_and_delete_still_fully_invalidate(self, ctx_vault):
        """增删条目不携带 crypto_id（全量语义），缓存整体失效下次重算。"""
        ctx, _vault = ctx_vault
        entry_id = ctx.entry_mgr.add_entry(Entry(title="t", username="u", password="pw123456"))
        ctx.security.get_or_compute_report()
        assert ctx.security._analysis_cache is not None

        ctx.entry_mgr.add_entry(Entry(title="t2", username="u2", password="pw654321"))
        assert ctx.security._analysis_cache is None

        ctx.security.get_or_compute_report()
        assert ctx.security._analysis_cache is not None
        ctx.entry_mgr.delete_entry(entry_id)
        assert ctx.security._analysis_cache is None
