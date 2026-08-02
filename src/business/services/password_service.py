"""业务层密码服务，封装密码生成、强度检测与 TOTP 操作。

切断 UI → Crypto 的跨层依赖，确保依赖方向为 UI → Business → Crypto。所有方法为
纯静态方法，不持状态。EntryManager 同层导入 PasswordGenerator/TOTPGenerator 属
Business → Crypto 同层依赖可接受，本服务仅供 UI 层调用。
"""

from ...crypto.password_generator import PasswordGenerator, StrengthResult
from ...crypto.totp import TOTPGenerator


class PasswordService:
    """密码生成与强度检测的统一入口。"""

    @staticmethod
    def generate(
        length: int = 16,
        uppercase: bool = True,
        lowercase: bool = True,
        digits: bool = True,
        symbols: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        """生成随机密码。"""
        return PasswordGenerator.generate(
            length,
            uppercase,
            lowercase,
            digits,
            symbols,
            exclude_ambiguous,
        )

    @staticmethod
    def check_strength(password: str) -> StrengthResult:
        """检测密码强度，返回 StrengthResult。"""
        return PasswordGenerator.check_strength(password)

    @staticmethod
    def validate_master_password(password: str, label: str = "主密码") -> tuple[bool, str]:
        """验证主密码强度要求，返回由是否有效与错误信息组成的二元组。"""
        return PasswordGenerator.validate_master_password(password, label)

    @staticmethod
    def validate_totp_secret(secret: str) -> bool:
        """验证 TOTP 密钥格式是否有效。"""
        return TOTPGenerator.validate_secret(secret)

    @staticmethod
    def validate_charset_selection(
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        symbols: bool,
    ) -> tuple[bool, str]:
        """校验密码生成至少选中一种字符集，返回 ``(是否有效, 错误信息)``。

        统一字符类型校验为单一事实源（MAINT-010）。有效时错误信息为空串，无效时返回
        固定文案供直接经 ``QMessageBox.warning`` 展示。
        """
        if not any((uppercase, lowercase, digits, symbols)):
            return False, "至少需要选择一种密码字符类型。"
        return True, ""

    @staticmethod
    def generate_totp_or_raise(secret: str) -> str:
        """生成 TOTP 验证码，失败时抛出 ValueError。"""
        return TOTPGenerator.generate_or_raise(secret)
