"""信用卡校验函数测试。

覆盖信用卡号的 Luhn 算法校验、MM/YY 有效期格式校验、CVV 格式校验，
验证合法输入通过、非法输入被拒绝的各类边界。
"""

from src.ui.dialogs.entry_dialog import (
    validate_card_cvv,
    validate_card_expiry,
    validate_card_number,
)


class TestValidateCardNumber:
    """Luhn 算法验证信用卡号"""

    def test_valid_visa(self):
        """Visa 测试卡号 (4111 1111 1111 1111) — Luhn 合法"""
        assert validate_card_number('4111111111111111') is True

    def test_valid_mastercard(self):
        """MasterCard 测试卡号 (5500 0000 0000 0004) — Luhn 合法"""
        assert validate_card_number('5500000000000004') is True

    def test_valid_13_digit(self):
        """13 位 Visa 测试卡号 (4222 2222 2222 2) — Luhn 合法"""
        assert validate_card_number('4222222222222') is True

    def test_invalid_checksum(self):
        """末位改动后 Luhn 校验失败"""
        assert validate_card_number('4111111111111112') is False

    def test_non_numeric(self):
        """去除分隔符后仍为非数字字符时应失败"""
        assert validate_card_number('abcdefghijklmnop') is False

    def test_too_short(self):
        """12 位数字过短"""
        assert validate_card_number('123456789012') is False

    def test_empty(self):
        """空字符串"""
        assert validate_card_number('') is False

    def test_with_spaces(self):
        """空格分隔的合法卡号"""
        assert validate_card_number('4111 1111 1111 1111') is True

    def test_with_dashes(self):
        """连字符分隔的合法卡号"""
        assert validate_card_number('4111-1111-1111-1111') is True

    def test_invalid_luhn(self):
        """Luhn 校验失败的卡号"""
        assert validate_card_number('1234567890123456') is False


class TestValidateCardExpiry:
    """MM/YY 格式有效期校验"""

    def test_valid_expiry(self):
        """正常 MM/YY"""
        assert validate_card_expiry('12/25') is True

    def test_valid_january(self):
        """01 月份"""
        assert validate_card_expiry('01/26') is True

    def test_invalid_month_zero(self):
        """月份 00 无效"""
        assert validate_card_expiry('00/25') is False

    def test_invalid_month_13(self):
        """月份 13 无效"""
        assert validate_card_expiry('13/25') is False

    def test_wrong_format_dash(self):
        """连字符分隔格式"""
        assert validate_card_expiry('12-25') is False

    def test_wrong_format_single_digit_month(self):
        """单数字月份"""
        assert validate_card_expiry('1/25') is False

    def test_wrong_format_no_slash(self):
        """无斜杠分隔"""
        assert validate_card_expiry('1225') is False

    def test_empty(self):
        """空字符串"""
        assert validate_card_expiry('') is False


class TestValidateCardCvv:
    """CVV 格式校验"""

    def test_valid_cvv_3(self):
        """3 位 CVV"""
        assert validate_card_cvv('123') is True

    def test_valid_cvv_4(self):
        """4 位 CVV，对应 Amex 卡"""
        assert validate_card_cvv('1234') is True

    def test_invalid_cvv_2(self):
        """2 位 CVV 过短"""
        assert validate_card_cvv('12') is False

    def test_invalid_cvv_5(self):
        """5 位 CVV 过长"""
        assert validate_card_cvv('12345') is False

    def test_invalid_cvv_non_digit(self):
        """非数字字符"""
        assert validate_card_cvv('abc') is False

    def test_invalid_cvv_empty(self):
        """空字符串"""
        assert validate_card_cvv('') is False

    def test_invalid_cvv_with_space(self):
        """含空格"""
        assert validate_card_cvv('12 3') is False
