"""应用日志配置 — 仅记录运行状态，不记录敏感字段。

为防御未来误写或第三方库（cryptography/argon2）意外输出敏感信息，对 handler 挂载
:class:`SensitiveDataFilter` 对常见敏感模式（cb2: 密文、password=/key=/secret= 赋值）
做正则打码，作为纵深防御。
"""

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType

from .models import CIPHERTEXT_PREFIX
from .utils.file_security import secure_directory, secure_file


class SensitiveDataFilter(logging.Filter):
    """对日志记录中的敏感模式做正则打码（纵深防御，防未来误写或第三方库 DEBUG 泄漏）。

    打码作用于 ``record.getMessage()`` 结果，回填 ``record.msg`` 并清空 ``record.args``
    避免 handler 二次插值还原原值。匹配模式：``cb2:`` 密文标记、``otpauth://``、
    ``password=``/``key=``/``密码=`` 等赋值。异常 traceback 由 :class:`RedactingFormatter`
    单独打码（标准 Formatter 在 format() 末尾拼接 traceback，不经 filter）。
    """

    _PATTERNS = (
        # 密文标记（CIPHERTEXT_PREFIX）+ base64 主体，整段打码。前缀取自共享层单一事实源，
        # 避免格式升级时正则与实际前缀漂移致脱敏静默失效。
        (
            re.compile(re.escape(CIPHERTEXT_PREFIX) + r"[A-Za-z0-9+/=]{8,}"),
            CIPHERTEXT_PREFIX + "[REDACTED]",
        ),
        # otpauth:// URI（TOTP 配置，含 secret 参数与账户名），整段打码
        (re.compile(r"otpauth://\S+"), "otpauth://[REDACTED]"),
        # key=value / key:value 敏感赋值，等号/冒号后值贪婪到行尾（含空格 passphrase 整段打码）。
        # 过度打码（一行多赋值整行打码）优于漏打码。关键词前置否定环视 (?<![A-Za-z]) 避免
        # mid-word 误匹配（donkey=…），中文关键词（密码/密钥/令牌）不受影响。SEC-009 补充
        # username/信用卡字段(card_number/card_holder/card_cvv)/cvv 等账号与卡密关键词。
        # SEC-LOG-001：关键词后可选引号 ([\'"]?) 捕获并在替换串回填，覆盖 dict/dataclass
        # repr 的 'password': ... 形态——repr 中 key 带引号，原 \s*[:=] 因引号挡在 key 与
        # 冒号间而漏匹配；捕获引号使 \1\2 回填，避免 'password=[REDACTED] 引号不平衡。
        (
            re.compile(
                r"(?i)(?<![A-Za-z])(password|pwd|passwd|secret|token|api[_-]?key|key"
                r"|username|user[_-]?name|card[_-]?(?:number|holder|cvv|cvc)|cvv|cvc"
                r'|密码|密钥|令牌)([\'"]?)\s*[:=]\s*.+'
            ),
            r"\1\2=[REDACTED]",
        ),
    )

    @staticmethod
    def redact(text: str) -> str:
        """对文本应用敏感模式打码，供 :meth:`filter`（message）与 :class:`RedactingFormatter`（traceback）复用同一逻辑。"""
        for pattern, replacement in SensitiveDataFilter._PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = self.redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


class RedactingFormatter(logging.Formatter):
    """对异常 traceback 应用与 message 相同的打码。

    标准 ``Formatter.format()`` 末尾拼接 traceback 不经 ``SensitiveDataFilter``，
    ``logger.error(..., exc_info=True)`` 的异常 str 或栈帧变量含 ``cb2:`` 密文 /
    ``password=`` 赋值时会明文落盘。覆盖 :meth:`formatException` 闭合该缺口。
    """

    def formatException(
        self,
        ei: tuple[type[BaseException], BaseException, TracebackType | None]
        | tuple[None, None, None],
    ) -> str:
        # 参数名 ei 与 logging.Formatter.formatException 签名一致（typeshed 定义）
        return SensitiveDataFilter.redact(super().formatException(ei))


def configure_logging(data_dir: Path) -> None:
    """配置应用日志，使用轮转文件 handler，仅记录运行状态。"""
    log_dir = data_dir / "logs"
    secure_directory(log_dir)
    log_path = log_dir / "cipherbox.log"
    handler = RotatingFileHandler(
        log_path,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    secure_file(log_path)
    handler.setFormatter(
        RedactingFormatter(
            # 含 threadName：BackgroundWorker 在子线程执行，调试锁定时序/worker 与主线程日志交织时线程名是关键定位信息。
            "%(asctime)s %(levelname)s %(name)s [%(threadName)s]: %(message)s"
        )
    )
    # 挂载脱敏过滤器：纵深防御，避免敏感数据意外落入日志文件
    handler.addFilter(SensitiveDataFilter())
    root = logging.getLogger()
    # 清理已有 handler，防止测试或多次调用导致重复
    for h in root.handlers[:]:
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(logging.INFO)
