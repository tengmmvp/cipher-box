"""密码生成器与强度检测"""

import re
import secrets
import string
from dataclasses import dataclass


# 模糊字符集
AMBIGUOUS_CHARS = 'Il1O0o'

# 常见弱密码模式
COMMON_PATTERNS = [
    r'^(123456|password|qwerty|abc123|111111|admin|letmein|welcome|monkey|dragon)$',
    r'^(\d)\1{4,}$',           # 全相同数字如 111111
    r'^(012345|123456|234567|345678|456789)$',  # 连续数字
    r'^(abcdef|bcdefg|cdefgh|qwerty|asdfgh|zxcvbn)$',  # 连续字母
]


@dataclass
class StrengthResult:
    """密码强度检测结果"""
    score: int          # 0-4 分
    label: str          # 非常弱 / 弱 / 一般 / 强 / 非常强
    length_ok: bool
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    is_common: bool
    feedback: list[str]  # 改进建议


class PasswordGenerator:
    """密码生成与强度检测"""

    @staticmethod
    def generate(
        length: int = 16,
        uppercase: bool = True,
        lowercase: bool = True,
        digits: bool = True,
        symbols: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        """生成随机密码

        Args:
            length: 密码长度 (最小 4)
            uppercase: 包含大写字母
            lowercase: 包含小写字母
            digits: 包含数字
            symbols: 包含特殊字符
            exclude_ambiguous: 排除模糊字符

        Returns:
            生成的随机密码
        """
        if length < 4:
            length = 4

        charset = ''
        required = []

        if uppercase:
            chars = string.ascii_uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in AMBIGUOUS_CHARS)
            charset += chars
            if chars:
                required.append(chars)

        if lowercase:
            chars = string.ascii_lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in AMBIGUOUS_CHARS)
            charset += chars
            if chars:
                required.append(chars)

        if digits:
            chars = string.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in AMBIGUOUS_CHARS)
            charset += chars
            if chars:
                required.append(chars)

        if symbols:
            chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            charset += chars
            if chars:
                required.append(chars)

        if not charset:
            charset = string.ascii_lowercase
            required = [charset]

        # 确保每种要求的字符类型至少出现一次
        password_chars = []
        for req_chars in required:
            password_chars.append(secrets.choice(req_chars))

        # 填充剩余长度
        remaining = length - len(password_chars)
        for _ in range(max(0, remaining)):
            password_chars.append(secrets.choice(charset))

        # 随机打乱顺序
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)

    @staticmethod
    def check_strength(password: str) -> StrengthResult:
        """检测密码强度

        Args:
            password: 待检测的密码

        Returns:
            StrengthResult 检测结果
        """
        if not password:
            return StrengthResult(
                score=0, label='非常弱',
                length_ok=False, has_upper=False, has_lower=False,
                has_digit=False, has_symbol=False, is_common=True,
                feedback=['密码不能为空'],
            )

        length_ok = len(password) >= 12
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))

        # 检查是否为常见密码
        is_common = False
        pwd_lower = password.lower()
        for pattern in COMMON_PATTERNS:
            if re.match(pattern, pwd_lower, re.IGNORECASE):
                is_common = True
                break

        # 计算分数
        score = 0
        feedback = []

        if len(password) >= 8:
            score += 1
        elif len(password) < 8:
            feedback.append('建议密码长度不少于 8 个字符')

        if len(password) >= 12:
            score += 1
        elif len(password) >= 8:
            feedback.append('建议密码长度达到 12 个字符以上')

        if has_upper:
            score += 1
        else:
            feedback.append('建议包含大写字母')

        if has_lower:
            score += 1
        else:
            feedback.append('建议包含小写字母')

        if has_digit:
            score += 1
        else:
            feedback.append('建议包含数字')

        if has_symbol:
            score += 1
        else:
            feedback.append('建议包含特殊字符')

        if is_common:
            score = min(score, 1)
            feedback.append('这是一个常见密码，极易被破解')

        # 有重复字符惩罚
        unique_ratio = len(set(password)) / len(password) if password else 0
        if unique_ratio < 0.4:
            score = max(0, score - 1)
            feedback.append('密码中重复字符过多')

        # 限制分数在 0-4 范围
        score = min(4, max(0, score))

        labels = ['非常弱', '弱', '一般', '强', '非常强']
        label = labels[score]

        if score >= 4 and not feedback:
            feedback.append('密码强度优秀')

        return StrengthResult(
            score=score,
            label=label,
            length_ok=length_ok,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_symbol=has_symbol,
            is_common=is_common,
            feedback=feedback,
        )

    @staticmethod
    def validate_master_password(password: str) -> tuple[bool, str]:
        """主密码策略：至少 12 字符，并达到最低强度要求。"""
        if len(password) < 12:
            return False, '主密码长度不能少于 12 个字符'
        strength = PasswordGenerator.check_strength(password)
        if strength.is_common:
            return False, '不能使用常见弱密码作为主密码'
        if strength.score < 3:
            return False, '主密码强度不足，请增加字符种类并避免重复字符'
        return True, ''
