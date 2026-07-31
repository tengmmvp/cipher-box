"""信用卡字段校验（Luhn 算法等）。业务规则集中于业务层供多路径复用，避免跨层依赖 UI。"""

import re

# 卡号长度范围（13-19 位，主流卡网规范）与 CVV 长度范围（3-4 位）。
_MIN_CARD_NUMBER_LEN = 13
_MAX_CARD_NUMBER_LEN = 19
_CVV_LENGTH_MIN = 3
_CVV_LENGTH_MAX = 4


def validate_card_number(number: str) -> bool:
    """使用 Luhn 算法校验信用卡号是否合法。"""
    number = number.replace(' ', '').replace('-', '')
    # 限定 ASCII 数字：str.isdigit() 对全角/阿拉伯-印度数字也返回 True，虽能通过
    # Luhn 但与卡号规范不符，存储后显示异常。
    if not (number.isascii() and number.isdigit()):
        return False
    if not _MIN_CARD_NUMBER_LEN <= len(number) <= _MAX_CARD_NUMBER_LEN:
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def validate_card_expiry(expiry: str) -> bool:
    """校验有效期格式为 MM/YY 且月份在 1-12 之间。

    注意：仅校验格式与月份，**不校验是否已过期**——过期由 UI 层基于条目时间字段提示。
    """
    if not re.match(r'^\d{2}/\d{2}$', expiry):
        return False
    month = int(expiry[:2])
    return 1 <= month <= 12


def validate_card_cvv(cvv: str) -> bool:
    """校验 CVV 是否为 3 至 4 位 ASCII 数字。"""
    # 限定 ASCII 数字，与 validate_card_number 一致（见上）。
    return cvv.isascii() and cvv.isdigit() and _CVV_LENGTH_MIN <= len(cvv) <= _CVV_LENGTH_MAX
