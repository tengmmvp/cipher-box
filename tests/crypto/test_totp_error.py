"""测试 TOTP 错误处理和边界情况。

仅覆盖 test_new_features.py 中 TestTOTP 未触及的场景，包括无效 otpauth URI、
损坏密钥的降级行为，以及私有解析方法对非法 period、digits 的校验。
"""

import pytest

from src.crypto.totp import TOTPGenerator


class TestTOTPErrorHandling:
    """验证 TOTP 生成与配置解析的错误处理及边界行为。"""

    # --- 边界情况，test_new_features.py::TestTOTP 未覆盖 ---

    def test_generate_invalid_uri(self):
        """无效 otpauth URI 返回空字符串。"""
        result = TOTPGenerator.generate('otpauth://hotp/test?secret=AAA')
        assert result == ''

    def test_get_remaining_seconds_invalid_secret(self):
        """损坏密钥的 get_remaining_seconds 使用传入 period。"""
        remaining = TOTPGenerator.get_remaining_seconds(secret='!!!bad!!!')
        assert 1 <= remaining <= 30

    def test_get_period_invalid_secret(self):
        """损坏密钥的 get_period 返回默认 period。"""
        period = TOTPGenerator.get_period('!!!bad!!!')
        assert period == 30

    # --- 私有方法边界测试 ---

    def test_parse_config_invalid_period(self):
        """URI 中非整数 period 抛出 ValueError。"""
        uri = 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=abc'
        with pytest.raises(ValueError, match='period'):
            TOTPGenerator._parse_config(uri, 'SHA1', 30, 6)  # type: ignore[arg-type]

    def test_parse_config_invalid_digits(self):
        """URI 中非整数 digits 抛出 ValueError。"""
        uri = 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=abc'
        with pytest.raises(ValueError, match='digits'):
            TOTPGenerator._parse_config(uri, 'SHA1', 30, 6)  # type: ignore[arg-type]

    def test_extract_period_from_uri(self):
        """_extract_period 从 otpauth URI 提取 period。"""
        uri = 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=60'
        assert TOTPGenerator._extract_period(uri, 30) == 60

    def test_extract_period_default_without_uri(self):
        """_extract_period 对非 URI 输入返回默认值。"""
        assert TOTPGenerator._extract_period('JBSWY3DPEHPK3PXP', 30) == 30

    def test_extract_period_invalid_period_in_uri(self):
        """_extract_period 对 URI 中无效 period 返回默认值。"""
        uri = 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=abc'
        assert TOTPGenerator._extract_period(uri, 30) == 30

    def test_normalize_base32(self):
        """_normalize_base32 正确标准化密钥，自动补齐 Base32 填充。"""
        assert TOTPGenerator._normalize_base32('  abc def  ') == 'ABCDEF=='
        assert TOTPGenerator._normalize_base32('jbswy3dpehpk3pxp') == 'JBSWY3DPEHPK3PXP'
        assert TOTPGenerator._normalize_base32('') == ''
