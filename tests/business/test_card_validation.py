"""信用卡校验函数测试。

覆盖信用卡号的 Luhn 算法校验、MM/YY 有效期格式校验、CVV 格式校验，
验证合法输入通过、非法输入被拒绝的各类边界。
"""

from src.business.services.card_validation import (
    validate_card_cvv,
    validate_card_expiry,
    validate_card_number,
)


class TestValidateCardNumber:
    """Luhn 算法验证信用卡号。"""

    def test_valid_visa(self):
        assert validate_card_number("4111111111111111") is True

    def test_valid_mastercard(self):
        assert validate_card_number("5500000000000004") is True

    def test_valid_13_digit(self):
        assert validate_card_number("4222222222222") is True

    def test_invalid_checksum(self):
        assert validate_card_number("4111111111111112") is False

    def test_non_numeric(self):
        assert validate_card_number("abcdefghijklmnop") is False

    def test_too_short(self):
        assert validate_card_number("123456789012") is False

    def test_empty(self):
        assert validate_card_number("") is False

    def test_with_spaces(self):
        assert validate_card_number("4111 1111 1111 1111") is True

    def test_with_dashes(self):
        assert validate_card_number("4111-1111-1111-1111") is True

    def test_invalid_luhn(self):
        assert validate_card_number("1234567890123456") is False

    def test_fullwidth_digits_rejected(self):
        """全角数字（４而非 4）应被拒绝：isdigit() 通过但非 ASCII，与卡号规范不符。"""
        assert validate_card_number("４１１１１１１１１１１１１１１１") is False

    def test_arabic_indic_digits_rejected(self):
        """阿拉伯-印度数字（٤ 而非 4）应被拒绝：与全角同属 isdigit() 通过但非 ASCII 的越界输入。"""
        assert validate_card_number("٤١١١١١١١١١١١١١١") is False


class TestValidateCardExpiry:
    """MM/YY 格式有效期校验。"""

    def test_valid_expiry(self):
        assert validate_card_expiry("12/25") is True

    def test_valid_january(self):
        assert validate_card_expiry("01/26") is True

    def test_invalid_month_zero(self):
        assert validate_card_expiry("00/25") is False

    def test_invalid_month_13(self):
        assert validate_card_expiry("13/25") is False

    def test_wrong_format_dash(self):
        assert validate_card_expiry("12-25") is False

    def test_wrong_format_single_digit_month(self):
        assert validate_card_expiry("1/25") is False

    def test_wrong_format_no_slash(self):
        assert validate_card_expiry("1225") is False

    def test_empty(self):
        assert validate_card_expiry("") is False


class TestValidateCardCvv:
    """CVV 格式校验。"""

    def test_valid_cvv_3(self):
        assert validate_card_cvv("123") is True

    def test_valid_cvv_4(self):
        assert validate_card_cvv("1234") is True

    def test_invalid_cvv_2(self):
        assert validate_card_cvv("12") is False

    def test_invalid_cvv_5(self):
        assert validate_card_cvv("12345") is False

    def test_invalid_cvv_non_digit(self):
        assert validate_card_cvv("abc") is False

    def test_invalid_cvv_empty(self):
        assert validate_card_cvv("") is False

    def test_invalid_cvv_with_space(self):
        assert validate_card_cvv("12 3") is False
