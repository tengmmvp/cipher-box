"""日志脱敏过滤器测试。

验证 SensitiveDataFilter 对 cb2 密文标记与 password=/key= 等敏感赋值的打码，
以及对正常日志的透传，确保纵深防御不破坏常规日志可读性。
"""

import logging

from src.logging_config import RedactingFormatter, SensitiveDataFilter


def _make_record(msg, args=None):
    """构造 INFO 级 LogRecord 桩，供 SensitiveDataFilter.filter 喂入测试。"""
    return logging.LogRecord(
        "test",
        logging.INFO,
        __file__,
        1,
        msg,
        args,
        None,
    )


class TestSensitiveDataFilter:
    """验证敏感模式打码。"""

    def test_redacts_password_assignment(self):
        """``password=`` 等号赋值的值整段打码为 [REDACTED]。"""
        record = _make_record("login password=hunter2-secret")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert "hunter2-secret" not in message
        assert "[REDACTED]" in message

    def test_redacts_cb2_ciphertext(self):
        """``cb2:`` 前缀的密文标记整段打码，避免密文落日志被截获后离线推敲。"""
        ciphertext = "cb2:ABCDEFGHabcdefgh0123456789+/=="
        record = _make_record(f"decrypt failed: {ciphertext}")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert ciphertext not in message
        assert "cb2:[REDACTED]" in message

    def test_redacts_chinese_key_assignment(self):
        """中文敏感关键词（密码）赋值同样打码。"""
        record = _make_record("save 密码=p@ssw0rd done")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert "p@ssw0rd" not in message
        assert "[REDACTED]" in message

    def test_redacts_colon_separator(self):
        """冒号分隔的敏感赋值同样打码。"""
        record = _make_record("token: abc123def456")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert "abc123def456" not in message

    def test_preserves_normal_logs(self):
        """不含敏感模式的正常日志保持原样。"""
        original = "解锁完成 (15.3ms)，共 42 条条目"
        record = _make_record(original)
        SensitiveDataFilter().filter(record)
        assert record.getMessage() == original

    def test_redacts_with_percent_args(self):
        """logger.info('pwd=%s', value) 形式的参数化记录也被打码。"""
        record = _make_record("pwd=%s", ("supersecret",))
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert "supersecret" not in message
        assert "[REDACTED]" in message

    def test_redacts_value_with_spaces(self):
        """含空格的敏感值整段打码（贪婪到行尾），不泄漏首个词之后的内容（#8 回归）。"""
        record = _make_record("password=correct horse battery staple")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert "correct" not in message
        assert "horse" not in message
        assert "staple" not in message
        assert "[REDACTED]" in message

    def test_does_not_redact_mid_word_match(self):
        """关键词作为单词一部分时不误打码（donkey=/monkey= 不触发 key= 规则，#8 回归）。"""
        original = "donkey=foo bar monkey=baz"
        record = _make_record(original)
        SensitiveDataFilter().filter(record)
        assert record.getMessage() == original

    def test_redacts_otpauth_secret(self):
        """otpauth URL 中的 secret 参数打码（M15），防 TOTP 凭证明文进日志。

        otpauth URL 的 ``secret=`` 命中 secret 关键词模式，贪婪到行尾一并遮蔽后续参数，
        不泄漏 Base32 TOTP 密钥。
        """
        secret = "JBSWY3DPEHPK3PDP"
        record = _make_record(f"otpauth://totp/label?secret={secret}&issuer=Test")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert secret not in message
        assert "[REDACTED]" in message

    def test_redacts_username_assignment(self):
        """username 关键词赋值打码（SEC-009 回归守护，防误删 alternation 分支）。"""
        record = _make_record("login username=alice@example.com ok")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert "alice@example.com" not in message
        assert "[REDACTED]" in message

    def test_redacts_card_cvv_assignment(self):
        """card cvv/cvc 关键词赋值打码（SEC-009 回归守护）。"""
        record = _make_record("card cvv=123 saved")
        SensitiveDataFilter().filter(record)
        message = record.getMessage()
        assert "123" not in message
        assert "[REDACTED]" in message


class TestRedactingFormatter:
    """验证异常 traceback 中的敏感模式被打码（闭合 exc_info=True 的缺口）。

    SensitiveDataFilter 仅作用于 record.getMessage()，标准 Formatter 在 format()
    末尾拼接的 traceback 不经 filter；RedactingFormatter 覆盖 formatException
    对 traceback 应用同一打码正则。
    """

    def _format_with_exception(self, exc):
        import sys

        try:
            raise exc
        except Exception:
            record = logging.LogRecord(
                "test",
                logging.ERROR,
                __file__,
                1,
                "operation failed",
                None,
                sys.exc_info(),
            )
            return RedactingFormatter("%(message)s").format(record)

    def test_redacts_cb2_ciphertext_in_traceback(self):
        """traceback 中的 cb2 密文标记应被打码。"""
        ciphertext = "cb2:ABCDEFGHabcdefgh0123456789+/=="
        output = self._format_with_exception(ValueError(f"decrypt failed: {ciphertext}"))
        assert ciphertext not in output
        assert "cb2:[REDACTED]" in output

    def test_redacts_password_assignment_in_traceback(self):
        """traceback 中的 password= 赋值应被打码。"""
        secret = "supersecret_value_99"
        output = self._format_with_exception(ValueError(f"auth failed password={secret}"))
        assert secret not in output
