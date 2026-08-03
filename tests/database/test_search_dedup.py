"""搜索匹配工具函数测试。

验证 matches_search 在 title、username、url、tags 上的大小写不敏感匹配行为，
覆盖精确匹配、部分匹配、域名片段匹配以及空关键字命中全部等场景。
"""

from src.business.services.crypto_utils import matches_search
from src.models import Entry


class TestMatchesSearch:
    """验证 matches_search 在各字段上的大小写不敏感搜索行为。"""

    def _make_entry(self, **kwargs):
        """构建仅含搜索字段的 Entry，其他字段使用默认值。"""
        return Entry(**kwargs)

    def test_matches_title(self):
        """title 字段子串匹配命中。"""
        e = self._make_entry(title="GitHub Login")
        assert matches_search(e, "github") is True

    def test_matches_username(self):
        """username 字段子串匹配命中。"""
        e = self._make_entry(username="user@example.com")
        assert matches_search(e, "example") is True

    def test_matches_url(self):
        """url 字段子串匹配命中。"""
        e = self._make_entry(url="https://github.com")
        assert matches_search(e, "github") is True

    def test_matches_tags(self):
        """tags 字段子串匹配命中。"""
        e = self._make_entry(tags="work,important")
        assert matches_search(e, "important") is True

    def test_case_insensitive(self):
        """大小写不敏感：小写/大写关键字均命中同一字段。"""
        e = self._make_entry(title="MyBank")
        assert matches_search(e, "mybank") is True
        assert matches_search(e, "MYBANK") is True

    def test_no_match(self):
        """关键字不在任一可搜索字段中，返回 False。"""
        e = self._make_entry(title="Hello", username="world", url="http://test.com", tags="demo")
        assert matches_search(e, "xyz123") is False

    def test_empty_keyword_matches_all(self):
        """空关键字视为无条件命中（UI 默认列表全展示依赖此契约）。"""
        e = self._make_entry(title="anything")
        assert matches_search(e, "") is True

    def test_partial_match(self):
        """部分子串匹配命中（非全词匹配）。"""
        e = self._make_entry(title="My Secret Vault")
        assert matches_search(e, "secret") is True

    def test_keyword_longer_than_field(self):
        """关键字比所有字段都长时不命中。"""
        e = self._make_entry(title="ab")
        assert matches_search(e, "abcdef") is False

    def test_matches_url_domain(self):
        """url 子串匹配覆盖域名片段（主机名部分）。"""
        e = self._make_entry(url="https://mail.google.com/inbox")
        assert matches_search(e, "google") is True

    def test_tags_partial(self):
        """tags 子串匹配覆盖单标签内与跨标签前缀片段。"""
        e = self._make_entry(tags="personal,finance")
        assert matches_search(e, "finance") is True
        assert matches_search(e, "person") is True
