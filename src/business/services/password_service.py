"""业务层密码服务，封装密码生成、强度检测与 TOTP 操作。

切断 UI → Crypto 的跨层依赖，确保依赖方向为 UI → Business → Crypto。所有方法为
纯静态方法，不持状态。EntryManager 同层导入 PasswordGenerator/TOTPGenerator 属
Business → Crypto 同层依赖可接受，本服务仅供 UI 层调用。
"""

import hmac

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

    @staticmethod
    def passwords_match(a: str, b: str) -> bool:
        """常量时间比较两个密码是否一致（SEC-031）。

        确认密码校验的统一门面，供 UI 对话框（改密/备份/共享包）与业务层
        （entry_manager）共用，收敛两处风险：

        - 时序侧信道：短路 ``==`` 的比较耗时随公共前缀长度变化，可能泄露
          前缀信息；``hmac.compare_digest`` 常量时间。
        - QL-019 同型 bug：``compare_digest`` 对 ``str`` 仅接受 ASCII，非 ASCII
          密码直接抛 ``TypeError`` 且被 Qt 槽吞掉、表单静默失败。两参统一先
          ``encode("utf-8")`` 再比较，调用方不得各自内联展开。

        Args:
            a / b: 待比较的两个密码明文（可含任意 Unicode 字符）。
        """
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
