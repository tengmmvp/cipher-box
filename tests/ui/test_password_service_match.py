"""PasswordService.passwords_match 统一门面测试（SEC-031）。

守护确认密码常量时间比较的公共契约：等值/不等/前缀/非 ASCII（QL-019 同型
bug 的回归面——``compare_digest`` 对 str 仅接受 ASCII，直接内联会抛 TypeError
被 Qt 槽吞掉）。UI 三个对话框（改密/备份/共享包）与业务层 entry_manager 均经
此门面调用，行为等价性与 Unicode 安全是本文件守护的边界。
"""

from src.business.services.password_service import PasswordService


class TestPasswordsMatch:
    """passwords_match 的等值语义与 Unicode 安全。"""

    def test_equal_strings_match(self):
        assert PasswordService.passwords_match("s3cret-P@ss", "s3cret-P@ss") is True

    def test_different_strings_do_not_match(self):
        assert PasswordService.passwords_match("s3cret-P@ss", "s3cret-P@sS") is False

    def test_common_prefix_does_not_match(self):
        """公共前缀 + 长度不同 → 不匹配（时序侧信道防护下的语义正确性）。"""
        assert PasswordService.passwords_match("abcdefgh", "abcdefghi") is False

    def test_empty_vs_non_empty(self):
        assert PasswordService.passwords_match("", "x") is False
        assert PasswordService.passwords_match("", "") is True

    def test_non_ascii_passwords_do_not_raise(self):
        """非 ASCII（中文/emoji）密码不抛 TypeError（QL-019 回归守护）。"""
        assert PasswordService.passwords_match("主密码·强口令", "主密码·强口令") is True
        assert PasswordService.passwords_match("主密码·强口令", "主密码·强口令2") is False
        assert PasswordService.passwords_match("p@ss🔑🔑", "p@ss🔑🔑") is True

    def test_matches_plain_equality_semantics(self):
        """与 ``==`` 语义等价（仅比较方式不同：常量时间）。"""
        cases = [("a", "a"), ("a", "b"), ("ab", "ba"), ("密码", "密码"), ("密码", "密碼")]
        for a, b in cases:
            assert PasswordService.passwords_match(a, b) == (a == b)
