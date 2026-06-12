"""CSV 注入防护与读取值提取测试。

验证 ImportExportManager._csv_safe 对公式注入前缀的转义，
以及 _get_val 在读取路径上保持原值不变的设计意图。
"""

from src.business.managers.import_export import ImportExportManager


class TestCsvSafe:
    """ImportExportManager._csv_safe 转义防护测试。"""

    def test_formula_prefix_equals(self):
        """以 = 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe('=CMD')
        assert result == "'=CMD"

    def test_formula_prefix_plus(self):
        """以 + 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe('+CMD')
        assert result == "'+CMD"

    def test_formula_prefix_minus(self):
        """以 - 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe('-CMD')
        assert result == "'-CMD"

    def test_formula_prefix_at(self):
        """以 @ 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe('@SUM')
        assert result == "'@SUM"

    def test_normal_text_unchanged(self):
        """普通文本不应被修改。"""
        assert ImportExportManager._csv_safe('hello') == 'hello'
        assert ImportExportManager._csv_safe('user@example.com') == 'user@example.com'
        assert ImportExportManager._csv_safe('1+2=3') == '1+2=3'

    def test_none_returns_empty(self):
        """None 应返回空字符串。"""
        assert ImportExportManager._csv_safe(None) == ''

    def test_empty_string_unchanged(self):
        """空字符串不变。"""
        assert ImportExportManager._csv_safe('') == ''

    def test_non_string_converted(self):
        """非字符串值应先转为字符串。"""
        assert ImportExportManager._csv_safe(42) == '42'
        assert ImportExportManager._csv_safe(3.14) == '3.14'


class TestGetVal:
    """ImportExportManager._get_val 值提取测试。

    _get_val 不在读取路径上剥离 CSV 注入前缀。CSV 注入防护仅在写入路径
    的 _csv_safe 中处理，读取时保持原值不变。
    """

    def test_value_returned_as_is(self):
        """值应原样返回，不做任何前缀处理。"""
        row = {'key': "'=VALUE"}
        result = ImportExportManager._get_val(row, 'key')
        assert result == "'=VALUE"

    def test_plain_value_unchanged(self):
        """普通值不应被修改。"""
        row = {'key': 'normal_value'}
        result = ImportExportManager._get_val(row, 'key')
        assert result == 'normal_value'

    def test_single_quote_value_preserved(self):
        """单引号开头的值应原样保留。"""
        row = {'key': "'hello"}
        result = ImportExportManager._get_val(row, 'key')
        assert result == "'hello"

    def test_fallback_keys(self):
        """应返回第一个非空值。"""
        row = {'a': '', 'b': 'found'}
        result = ImportExportManager._get_val(row, 'a', 'b')
        assert result == 'found'

    def test_missing_key_returns_empty(self):
        """缺失键返回空字符串。"""
        row = {}
        result = ImportExportManager._get_val(row, 'missing')
        assert result == ''
