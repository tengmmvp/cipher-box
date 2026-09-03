"""日志脱敏过滤器测试。

验证 SensitiveDataFilter 对 cb2 密文标记与 password=/key= 等敏感赋值的打码，
以及对正常日志的透传，确保纵深防御不破坏常规日志可读性。
"""

import logging
from pathlib import Path

import pytest

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

    def test_redacts_crypto_and_metadata_keywords(self):
        """nonce/salt/title/url/notes/tags 赋值打码（SEC-060，防未来误写纵深）。

        六个关键词均为加密列对应明文或其派生输入（nonce/salt 是密文/密钥派生参数，
        title/url/notes/tags 是条目元数据），误写日志时与 password 同级敏感。
        """
        cases = (
            ("encrypt nonce=aGVsbG8gd29ybGQxMjM=", "aGVsbG8gd29ybGQxMjM="),
            ("kdf salt=c2FsdHktc2FsdC12YWx1ZQ==", "c2FsdHktc2FsdC12YWx1ZQ=="),
            ("entry title=我的银行账号", "我的银行账号"),
            ("login url=https://bank.example.com/login", "bank.example.com"),
            ("notes=内部主机 10.0.0.1 的凭据", "内部主机"),
            ("tags=工作,银行", "银行"),
        )
        for text, secret in cases:
            record = _make_record(text)
            SensitiveDataFilter().filter(record)
            message = record.getMessage()
            assert secret not in message, f"未打码：{text}"
            assert "[REDACTED]" in message, f"缺少 REDACTED 标记：{text}"

    def test_does_not_redact_normal_words_containing_new_keywords(self):
        """新关键词作为普通单词的一部分时不误打码（如 result=/salts=/titling=）。"""
        original = "step result=ok totals=3 titling=auto"
        record = _make_record(original)
        SensitiveDataFilter().filter(record)
        assert record.getMessage() == original


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


class TestSecureRotatingFileHandler:
    """轮转后重新收紧文件权限（SEC-059）。

    标准 ``doRollover`` 以进程 umask 重建新的 ``baseFilename``（POSIX 默认 0644），
    启动时的一次 secure_file 只覆盖首个文件——轮转后的新文件回退世界可读。守护
    覆写 doRollover 对当前文件与轮转备份的重收紧；POSIX 分支经 mode 位断言，任意
    平台经 secure_file 调用桩断言（Windows 下至少验证不回归）。
    """

    def test_rollover_resecures_current_and_backup(self, tmp_path, monkeypatch):
        """emit 触发轮转后，secure_file 被调用于新 baseFilename 与 .1 备份。"""
        import src.logging_config as logging_config
        from src.logging_config import SecureRotatingFileHandler

        secured: list[str] = []
        real_secure_file = logging_config.secure_file

        def _spy(path, **kwargs):
            secured.append(str(path))
            return real_secure_file(path, **kwargs)

        monkeypatch.setattr(logging_config, "secure_file", _spy)

        handler = SecureRotatingFileHandler(
            tmp_path / "cipherbox.log", maxBytes=100, backupCount=3, encoding="utf-8"
        )
        try:
            big = "x" * 200  # 单条即超 maxBytes，第二次 emit 触发轮转
            handler.emit(_make_record(big))
            handler.emit(_make_record(big))
        finally:
            handler.close()

        names = {str(Path(name).name) for name in secured}
        assert "cipherbox.log" in names
        assert "cipherbox.log.1" in names
        assert (tmp_path / "cipherbox.log.1").exists()

    def test_rolled_files_are_owner_only_on_posix(self, tmp_path):
        """POSIX：轮转产生的新文件与备份均为 0600（无世界可读回退）。"""
        import sys

        if sys.platform == "win32":
            pytest.skip("POSIX mode 位断言")
        import stat

        from src.logging_config import SecureRotatingFileHandler

        handler = SecureRotatingFileHandler(
            tmp_path / "cipherbox.log", maxBytes=100, backupCount=3, encoding="utf-8"
        )
        try:
            big = "y" * 200
            handler.emit(_make_record(big))
            handler.emit(_make_record(big))
        finally:
            handler.close()

        for name in ("cipherbox.log", "cipherbox.log.1"):
            mode = stat.S_IMODE((tmp_path / name).stat().st_mode)
            assert mode == 0o600, f"{name} 应为 0600，实际 {oct(mode)}"

    def test_configure_logging_uses_secure_handler_and_secures_backups(self, tmp_path, monkeypatch):
        """configure_logging 挂载 SecureRotatingFileHandler，且启动即收紧既有轮转备份。

        既有备份（升级前权限宽松的遗留文件）在启动 glob 中一并 secure_file，
        不等下次轮转才恢复受限权限。
        """
        import src.logging_config as logging_config

        (tmp_path / "logs").mkdir()
        legacy_backup = tmp_path / "logs" / "cipherbox.log.1"
        legacy_backup.write_text("legacy", encoding="utf-8")

        secured: list[str] = []
        real_secure_file = logging_config.secure_file

        def _spy(path, **kwargs):
            secured.append(str(path))
            return real_secure_file(path, **kwargs)

        monkeypatch.setattr(logging_config, "secure_file", _spy)

        root = logging.getLogger()
        saved_handlers = root.handlers[:]
        try:
            logging_config.configure_logging(tmp_path)
            assert root.handlers, "configure_logging 应挂载 root handler"
            assert isinstance(root.handlers[0], logging_config.SecureRotatingFileHandler)
        finally:
            for h in root.handlers[:]:
                root.removeHandler(h)
                h.close()
            for h in saved_handlers:
                root.addHandler(h)

        names = {str(Path(name).name) for name in secured}
        assert "cipherbox.log" in names
        assert "cipherbox.log.1" in names

    def test_rollover_new_file_created_0600_even_without_resecure(self, tmp_path, monkeypatch):
        """轮转新建文件落地即 0600（SEC-068）：即便 secure_file 全程缺席也不出现窗口。

        以 no-op 掉 doRollover 的 secure_file（排除事后收紧的贡献），POSIX 下以
        umask 022 断言新 baseFilename 的创建 mode 位即 0600——修复前 _open 以
        umask 创建为 0644，「创建 → secure_file 收紧」间存在世界可读窗口。
        """
        import sys

        if sys.platform == "win32":
            pytest.skip("POSIX mode 位断言（Windows 忽略 mode 位，靠父目录 ACL）")
        import os
        import stat

        import src.logging_config as logging_config
        from src.logging_config import SecureRotatingFileHandler

        monkeypatch.setattr(logging_config, "secure_file", lambda path, **kwargs: path)
        old_umask = os.umask(0o022)
        try:
            handler = SecureRotatingFileHandler(
                tmp_path / "cipherbox.log", maxBytes=100, backupCount=3, encoding="utf-8"
            )
            try:
                big = "z" * 200
                handler.emit(_make_record(big))
                handler.emit(_make_record(big))  # 触发轮转：_open 重建 baseFilename
            finally:
                handler.close()
        finally:
            os.umask(old_umask)

        mode = stat.S_IMODE((tmp_path / "cipherbox.log").stat().st_mode)
        assert mode == 0o600, f"落地即 0600 失败（umask 022 下创建为 {oct(mode)}）"

    def test_rollover_works_on_windows_no_regression(self, tmp_path):
        """Windows 不回归：opener 覆写 _open 后轮转/写入/备份链路照常（mode 位忽略）。"""
        from src.logging_config import SecureRotatingFileHandler

        handler = SecureRotatingFileHandler(
            tmp_path / "cipherbox.log", maxBytes=100, backupCount=3, encoding="utf-8"
        )
        try:
            big = "w" * 200
            handler.emit(_make_record(big))
            handler.emit(_make_record(big))
            handler.flush()
        finally:
            handler.close()

        # 当前文件可读回（写入链路正常），轮转备份存在
        assert (tmp_path / "cipherbox.log").stat().st_size > 0
        assert (tmp_path / "cipherbox.log.1").exists()
