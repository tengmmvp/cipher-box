"""constant_time_mac_equals 共享比较器测试（SEC-071）。

守护三形态契约：ASCII 等值 True / ASCII 失配（含同前缀）False / 非 ASCII 存储
侧短路 False 不抛 TypeError——期望值恒为 hexdigest（ASCII），非 ASCII stored 属
篡改形态，短路结论与任何密钥/载荷下的比较结果同为「必不相等」。
"""

from src.utils.secure_compare import constant_time_mac_equals

_HEX_A = "ab12" * 16  # 与真实 hexdigest 同长（64 字符）
_HEX_B = "ab12" * 15 + "ab13"  # 与 _HEX_A 仅末 2 字符不同（同前缀形态）


class TestConstantTimeMacEquals:
    """等值 / 失配 / 非 ASCII 存储侧三形态与空串边界。"""

    def test_equal_ascii_hex_returns_true(self):
        """ASCII hexdigest 等值比较返回 True。"""
        assert constant_time_mac_equals(_HEX_A, _HEX_A) is True

    def test_mismatched_ascii_returns_false(self):
        """ASCII 失配（公共前缀相同）返回 False。"""
        assert constant_time_mac_equals(_HEX_B, _HEX_A) is False

    def test_non_ascii_stored_returns_false_without_type_error(self):
        """非 ASCII stored（篡改形态）短路 False，不抛 TypeError。"""
        # 裸 hmac.compare_digest 对非 ASCII str 抛 TypeError，此处必须无异常返回
        assert constant_time_mac_equals("被篡改的签名值", _HEX_A) is False

    def test_empty_stored_returns_false(self):
        """空串 stored 与任意期望值失配返回 False（compare_digest 既有语义）。"""
        assert constant_time_mac_equals("", _HEX_A) is False
