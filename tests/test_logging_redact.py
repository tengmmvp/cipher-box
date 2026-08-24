r"""SEC-019 日志脱敏补充测试：repr 引号形态、中文关键词与 traceback 打码。

基础形态（``password=``/``key=``/``cb2:``/``otpauth``）已由 ``tests/test_logging.py``
覆盖；本文件补齐 SEC-019 新增的 dict/dataclass repr 引号键形态（``'password': 'x'``
——repr 中引号挡在 key 与冒号之间，原 ``\s*[:=]`` 漏匹配）、中文关键词的密钥/冒号
变体，以及 ``RedactingFormatter`` 对 traceback 中引号形态的打码闭环。
"""

import logging
import sys

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


class TestSensitiveDataFilterSec019:
    """SEC-019：关键词后可选引号捕获，覆盖 dict/dataclass repr 形态。"""

    def test_redacts_quoted_key_repr_form(self):
        """``'password': 'x'`` / ``"password": "x"`` repr 形态打码，引号回填保持可读。"""
        for text, secret in (
            ("entry = {'password': 'hunter2-secret', 'title': 'Bank'}", "hunter2-secret"),
            ('payload = {"password": "topsecret99"}', "topsecret99"),
        ):
            record = _make_record(text)
            SensitiveDataFilter().filter(record)
            message = record.getMessage()
            assert secret not in message
            assert "[REDACTED]" in message
            # 捕获的引号经 \1\2 回填（SEC-019）：key 名保留且不产生悬空不平衡替换
            assert "password" in message

    def test_redacts_chinese_keywords(self):
        """中文关键词 密码/密钥 的等号与冒号赋值形态均打码。"""
        for text, secret in (
            ("保存 密码=中文密码明文 done", "中文密码明文"),
            ("derive 密钥: raw_master_key_1", "raw_master_key_1"),
        ):
            record = _make_record(text)
            SensitiveDataFilter().filter(record)
            message = record.getMessage()
            assert secret not in message
            assert "[REDACTED]" in message


class TestRedactingFormatterSec019:
    """traceback 中 repr 引号形态经 formatException 应用同一打码（SEC-019 闭环）。"""

    def test_redacts_quoted_key_in_traceback(self):
        """异常消息里的 ``'token': '…'`` repr 形态在 traceback 输出中不打码即落盘。"""
        secret = "token_abc123"
        payload = {"token": secret}
        try:
            raise RuntimeError(f"payload={payload!r}")
        except RuntimeError:
            record = logging.LogRecord(
                "test",
                logging.ERROR,
                __file__,
                1,
                "operation failed",
                None,
                sys.exc_info(),
            )
            output = RedactingFormatter("%(message)s").format(record)
        assert secret not in output
        assert "[REDACTED]" in output
