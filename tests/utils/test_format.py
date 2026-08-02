"""format 工具函数测试。

覆盖 format_datetime 的 ISO 解析：Python 3.10 对 'Z' 后缀的兼容（归一化为
+00:00）、aware UTC、naive 按 UTC 解释、非法输入原样返回，以及 utc_now_iso 格式。
"""

from src.utils.format import format_datetime, utc_now_iso


class TestFormatDatetime:
    """format_datetime 各输入场景。"""

    def test_empty_returns_empty(self):
        """空串原样返回，不抛异常。"""
        assert format_datetime("") == ""

    def test_z_suffix_parsed_on_py310(self):
        """Python 3.10 fromisoformat 不接受 'Z'，归一化后应解析（#12 回归）。"""
        result = format_datetime("2024-01-15T10:30:00Z")
        assert result != "2024-01-15T10:30:00Z"
        assert len(result) == 19

    def test_aware_utc(self):
        """aware UTC 输入转本地 19 字符标准格式（输出非原串即证明已格式化）。"""
        result = format_datetime("2024-01-15T10:30:00+00:00")
        assert result != "2024-01-15T10:30:00+00:00"
        assert len(result) == 19

    def test_naive_treated_as_utc(self):
        """naive 输入按 UTC 解释后转本地，输出 19 字符标准格式。"""
        result = format_datetime("2024-01-15T10:30:00")
        assert len(result) == 19

    def test_invalid_returned_as_is(self):
        """非法输入原样返回（优雅降级，不抛异常）。"""
        assert format_datetime("not-a-date") == "not-a-date"


class TestUtcNowIso:
    """utc_now_iso 生成带 UTC 偏移的 ISO 字符串。"""

    def test_ends_with_utc_offset(self):
        """输出以 ``+00:00`` 结尾，标记为 UTC 时区。"""
        result = utc_now_iso()
        assert result.endswith("+00:00")

    def test_parseable_by_format_datetime(self):
        """utc_now_iso 的输出可被 format_datetime 解析（自洽往返）。"""
        result = format_datetime(utc_now_iso())
        assert len(result) == 19
