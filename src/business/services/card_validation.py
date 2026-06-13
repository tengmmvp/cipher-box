"""信用卡字段校验（Luhn 算法等）。

业务规则从 UI 层下沉至业务层，供条目对话框与未来的导入校验等其他路径复用，
避免业务逻辑泄漏到 UI 模块或造成跨层依赖 UI。
"""

import re


def validate_card_number(number: str) -> bool:
    """使用 Luhn 算法校验信用卡号是否合法。"""
    number = number.replace(' ', '').replace('-', '')
    if not number.isdigit() or len(number) < 13:
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
    """校验有效期是否为 MM/YY 格式且月份在 1 至 12 之间。"""
    if not re.match(r'^\d{2}/\d{2}$', expiry):
        return False
    month = int(expiry[:2])
    return 1 <= month <= 12


def validate_card_cvv(cvv: str) -> bool:
    """校验 CVV 是否为 3 至 4 位数字。"""
    return cvv.isdigit() and 3 <= len(cvv) <= 4
