"""密码生成器与强度检测。

生成时可排除模糊字符，强度检测基于长度、字符种类、常见密码模式
和重复字符比例综合评分，分数区间为 0 至 4 分，并给出具体改进建议。
"""

import logging
import re
import secrets
import string
from dataclasses import dataclass

from ..models import MAX_FIELD_PASSWORD

logger = logging.getLogger(__name__)

# 模块级安全随机数生成器，避免每次调用重复创建
_RNG = secrets.SystemRandom()

# 模糊字符集
AMBIGUOUS_CHARS = 'Il1O0o'

# ---- 密码生成/强度/主密码策略的魔法数字集中为命名常量（单一事实源）----
# generate 长度区间：低于 4 无法覆盖各字符类至少 1 个的要求，高于 128 无实际
# 安全收益且拖慢生成；越界仅 warning + clamp，兼容 UI 滑块等调用方。
PASSWORD_LENGTH_MIN = 4
PASSWORD_LENGTH_MAX = 128
# 强度评分上限（0..MAX_STRENGTH_SCORE），backup_validator 与本模块复用，避免 4 字面量
# 漂移（如未来调整为 0..5 评分刻度时一处生效）。
MAX_STRENGTH_SCORE = 4
# 重复字符比例低于此阈值扣分（unique_chars / len），0.4 即 10 字符密码唯一字符少于 4。
WEAK_UNIQUE_RATIO = 0.4
# 主密码策略：至少 15 字符（OWASP 建议的最低门槛），上限复用条目密码字段上限
# MAX_FIELD_PASSWORD，使「密码最大长度」在主密码与条目密码两处单一对齐。
MIN_MASTER_PASSWORD_LENGTH = 15
MASTER_PASSWORD_MAX_LENGTH = MAX_FIELD_PASSWORD

# 常见弱密码模式，预编译以避免 check_strength 每次调用重新编译
_COMMON_WEAK = r'^(123456|password|qwerty|abc123|111111|admin|letmein|welcome|monkey|dragon)'
COMMON_PATTERNS = [
    re.compile(_COMMON_WEAK + r'$'),           # 精确匹配
    re.compile(r'^(\d)\1{4,}$'),                # 全相同数字如 111111
    re.compile(r'^(012345|123456|234567|345678|456789)$'),  # 连续数字
    re.compile(r'^(abcdef|bcdefg|cdefgh|qwerty|asdfgh|zxcvbn)$'),  # 连续字母
    re.compile(_COMMON_WEAK),                    # 前缀匹配：以常见弱密码开头的变体
]

# 字符组成检测正则，预编译
_RE_UPPER = re.compile(r'[A-Z]')
_RE_LOWER = re.compile(r'[a-z]')
_RE_DIGIT = re.compile(r'\d')
_RE_SYMBOL = re.compile(r'[^A-Za-z0-9]')


@dataclass
class StrengthResult:
    """密码强度检测结果。"""
    score: int          # 0-4 分
    label: str          # 非常弱 / 弱 / 一般 / 强 / 非常强
    length_ok: bool
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    is_common: bool
    feedback: list[str]  # 改进建议


def _build_charset(base_chars: str, exclude_ambiguous: bool) -> str:
    """构建字符集，可选排除模糊字符。

    Args:
        base_chars: 基础字符集
        exclude_ambiguous: 是否排除模糊字符 Il1O0o

    Returns:
        处理后的字符集字符串
    """
    if exclude_ambiguous:
        return ''.join(c for c in base_chars if c not in AMBIGUOUS_CHARS)
    return base_chars


class PasswordGenerator:
    """密码生成与强度检测。"""

    @staticmethod
    def generate(
        length: int = 16,
        uppercase: bool = True,
        lowercase: bool = True,
        digits: bool = True,
        symbols: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        """生成随机密码。

        Args:
            length: 密码长度，会被静默 clamp 到 ``[4, 128]``——低于 4 无法覆盖各
                字符类至少 1 个的要求，高于 128 无实际安全收益且拖慢生成。调用方
                应在此区间内取值；越界仅记录 warning 不抛错，以兼容 UI 滑块等调用方。
            uppercase: 包含大写字母
            lowercase: 包含小写字母
            digits: 包含数字
            symbols: 包含特殊字符
            exclude_ambiguous: 排除模糊字符

        Returns:
            生成的随机密码
        """
        if length < PASSWORD_LENGTH_MIN:
            logger.warning("密码长度 %d 低于最小值 %d，已自动调整", length, PASSWORD_LENGTH_MIN)
            length = PASSWORD_LENGTH_MIN
        if length > PASSWORD_LENGTH_MAX:
            logger.warning("密码长度 %d 超过上限 %d，已自动截断", length, PASSWORD_LENGTH_MAX)
            length = PASSWORD_LENGTH_MAX

        charset = ''
        required = []

        if uppercase:
            chars = _build_charset(string.ascii_uppercase, exclude_ambiguous)
            charset += chars
            if chars:
                required.append(chars)

        if lowercase:
            chars = _build_charset(string.ascii_lowercase, exclude_ambiguous)
            charset += chars
            if chars:
                required.append(chars)

        if digits:
            chars = _build_charset(string.digits, exclude_ambiguous)
            charset += chars
            if chars:
                required.append(chars)

        if symbols:
            # 排除反引号、引号、斜杠等字符以保证 shell/URL 兼容性
            chars = _build_charset('!@#$%^&*()_+-=[]{}|;:,.<>?~', exclude_ambiguous)
            charset += chars
            if chars:
                required.append(chars)

        if not charset:
            charset = string.ascii_lowercase
            required = [charset]

        # 确保每种要求的字符类型至少出现一次
        password_chars = []
        for req_chars in required:
            password_chars.append(_RNG.choice(req_chars))

        remaining = length - len(password_chars)
        for _ in range(max(0, remaining)):
            password_chars.append(_RNG.choice(charset))

        _RNG.shuffle(password_chars)
        return ''.join(password_chars)

    @staticmethod
    def check_strength(password: str) -> StrengthResult:
        """检测密码强度。

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
        has_upper = bool(_RE_UPPER.search(password))
        has_lower = bool(_RE_LOWER.search(password))
        has_digit = bool(_RE_DIGIT.search(password))
        has_symbol = bool(_RE_SYMBOL.search(password))

        is_common = False
        pwd_lower = password.lower()
        for pattern in COMMON_PATTERNS:
            if pattern.match(pwd_lower):
                is_common = True
                logger.debug("检测到常见密码模式")
                break

        # 评分体系共 5 档：0 非常弱、1 弱、2 一般、3 强、4 非常强。
        # 理论原始满分 6 分，分别来自长度达 8、长度达 12、含大写、含小写、
        # 含数字、含特殊字符六项；再经常见密码惩罚与重复字符惩罚下调，
        # 最终限制在 0 到 4 区间。
        score = 0
        feedback = []

        if len(password) >= 8:
            score += 1
        else:
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

        # 常见密码惩罚：无论得分多高，强制降至最高 1 分
        if is_common:
            score = min(score, 1)
            feedback.append('这是一个常见密码，极易被破解')

        # 先 clamp 到 [0, MAX_STRENGTH_SCORE]，再应用重复惩罚：确保强密码（原始分 5-6）
        # 的重复问题能实际降档，而非被最终 clamp 重新拉回 MAX_STRENGTH_SCORE。
        score = min(MAX_STRENGTH_SCORE, max(0, score))

        # 有重复字符惩罚：降低 1 分，但不低于 0
        unique_ratio = len(set(password)) / len(password) if password else 0
        if unique_ratio < WEAK_UNIQUE_RATIO:
            score = max(0, score - 1)
            feedback.append('密码中重复字符过多')

        labels = ['非常弱', '弱', '一般', '强', '非常强']
        label = labels[score]

        if score >= MAX_STRENGTH_SCORE and not feedback:
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
    def validate_master_password(password: str, label: str = '主密码') -> tuple[bool, str]:
        """主密码策略：至少 15 字符，拒绝常见与明显重复密码。"""
        if not password:
            return False, f'{label}不能为空'
        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            return False, f'{label}长度不能少于 {MIN_MASTER_PASSWORD_LENGTH} 个字符'
        if len(password) > MASTER_PASSWORD_MAX_LENGTH:
            return False, f'{label}长度不能超过 {MASTER_PASSWORD_MAX_LENGTH} 个字符'
        if len(set(password)) <= 2:
            return False, f'{label}包含过多重复字符'
        strength = PasswordGenerator.check_strength(password)
        if strength.is_common:
            return False, f'不能使用常见弱密码作为{label}'
        if len(password) < 20 and strength.score < 3:
            return False, f'{label}强度不足，请增加字符种类并避免重复字符'
        return True, ''
