"""搜索去重工具函数测试 — matches_search"""

from src.business.services.crypto_utils import matches_search
from src.database.models import Entry


class TestMatchesSearch:
    """matches_search — 大小写不敏感搜索 title/username/url/tags"""

    def _make_entry(self, **kwargs):
        """构建仅含搜索字段的 Entry（其他字段使用默认值）"""
        entry = Entry()
        for key, value in kwargs.items():
            setattr(entry, key, value)
        return entry

    def test_matches_title(self):
        e = self._make_entry(title='GitHub Login')
        assert matches_search(e, 'github') is True

    def test_matches_username(self):
        e = self._make_entry(username='user@example.com')
        assert matches_search(e, 'example') is True

    def test_matches_url(self):
        e = self._make_entry(url='https://github.com')
        assert matches_search(e, 'github') is True

    def test_matches_tags(self):
        e = self._make_entry(tags='work,important')
        assert matches_search(e, 'important') is True

    def test_case_insensitive(self):
        e = self._make_entry(title='MyBank')
        assert matches_search(e, 'mybank') is True
        assert matches_search(e, 'MYBANK') is True

    def test_no_match(self):
        e = self._make_entry(title='Hello', username='world', url='http://test.com', tags='demo')
        assert matches_search(e, 'xyz123') is False

    def test_empty_keyword_matches_all(self):
        e = self._make_entry(title='anything')
        assert matches_search(e, '') is True

    def test_partial_match(self):
        """部分匹配"""
        e = self._make_entry(title='My Secret Vault')
        assert matches_search(e, 'secret') is True

    def test_keyword_longer_than_field(self):
        """关键词比字段值长"""
        e = self._make_entry(title='ab')
        assert matches_search(e, 'abcdef') is False

    def test_matches_url_domain(self):
        """URL 中匹配域名片段"""
        e = self._make_entry(url='https://mail.google.com/inbox')
        assert matches_search(e, 'google') is True

    def test_tags_partial(self):
        """标签中的部分匹配"""
        e = self._make_entry(tags='personal,finance')
        assert matches_search(e, 'finance') is True
        assert matches_search(e, 'person') is True
