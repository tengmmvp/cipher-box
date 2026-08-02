"""``SecurityAnalyzer.compute_health_score`` 与搜索匹配等价性测试。

覆盖 ``src/business/services/security_analyzer.py::compute_health_score`` 静态方法的
边界（空库、满分、各档累加、clamp）与 ``src/business/services/crypto_utils.py`` 的
``matches_search`` / ``matches_search_lower`` 在相同输入下结果等价（后者复用预计算
小写字段，是前者的批量优化版，匹配语义须完全一致）。
"""

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
