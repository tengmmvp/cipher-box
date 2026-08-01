"""CSV 注入防护测试。

验证 ImportExportManager._csv_safe 对公式注入前缀的转义，
确保 CSV 公式注入仅在导出写入路径处理。
"""

from src.business.managers.import_export import ImportExportManager


class TestCsvSafe:
    """ImportExportManager._csv_safe 转义防护测试。"""

    def test_formula_prefix_equals(self):
        """以 = 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe("=CMD")
        assert result == "'=CMD"

    def test_formula_prefix_plus(self):
        """以 + 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe("+CMD")
        assert result == "'+CMD"

    def test_formula_prefix_minus(self):
        """以 - 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe("-CMD")
        assert result == "'-CMD"

    def test_formula_prefix_at(self):
        """以 @ 开头的值应被单引号前缀转义。"""
        result = ImportExportManager._csv_safe("@SUM")
        assert result == "'@SUM"

    def test_normal_text_unchanged(self):
        """普通文本不应被修改。"""
        assert ImportExportManager._csv_safe("hello") == "hello"
        assert ImportExportManager._csv_safe("user@example.com") == "user@example.com"
        assert ImportExportManager._csv_safe("1+2=3") == "1+2=3"

    def test_none_returns_empty(self):
        """None 应返回空字符串。"""
        assert ImportExportManager._csv_safe(None) == ""

    def test_empty_string_unchanged(self):
        """空字符串不变。"""
        assert ImportExportManager._csv_safe("") == ""

    def test_non_string_converted(self):
        """非字符串值应先转为字符串。"""
        assert ImportExportManager._csv_safe(42) == "42"
        assert ImportExportManager._csv_safe(3.14) == "3.14"
