"""业务层密码服务，封装密码生成、强度检测与 TOTP 操作。

消除 UI 层对 crypto 层的直接依赖，确保依赖方向为 UI → Business → Crypto。
所有方法为纯静态方法，不持有状态，不依赖 VaultManager。

架构说明：EntryManager 同层直接导入 PasswordGenerator/TOTPGenerator，
属 Business → Crypto 的同层依赖，这是可接受的。PasswordService 的存在
是为了切断 UI → Crypto 的跨层依赖，而非在 Business 内部再增加一层间接。
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
            length, uppercase, lowercase, digits, symbols, exclude_ambiguous,
        )

    @staticmethod
    def check_strength(password: str) -> StrengthResult:
        """检测密码强度，返回 StrengthResult。"""
        return PasswordGenerator.check_strength(password)

    @staticmethod
    def validate_master_password(password: str, label: str = '主密码') -> tuple[bool, str]:
        """验证主密码强度要求，返回由是否有效与错误信息组成的二元组。"""
        return PasswordGenerator.validate_master_password(password, label)

    @staticmethod
    def validate_totp_secret(secret: str) -> bool:
        """验证 TOTP 密钥格式是否有效。"""
        return TOTPGenerator.validate_secret(secret)

    @staticmethod
    def generate_totp_or_raise(secret: str) -> str:
        """生成 TOTP 验证码，失败时抛出 ValueError。"""
        return TOTPGenerator.generate_or_raise(secret)
