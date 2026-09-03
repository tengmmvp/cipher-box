"""应用日志配置 — 仅记录运行状态，不记录敏感字段。

为防御未来误写或第三方库（cryptography/argon2）意外输出敏感信息，对 handler 挂载
:class:`SensitiveDataFilter` 对常见敏感模式（cb2: 密文、password=/key=/secret= 赋值）
做正则打码，作为纵深防御。
"""

import logging
import os
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType
from typing import IO, Any

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
        # SEC-019：关键词后可选引号 ([\'"]?) 捕获并在替换串回填，覆盖 dict/dataclass
        # repr 的 'password': ... 形态——repr 中 key 带引号，原 \s*[:=] 因引号挡在 key 与
        # 冒号间而漏匹配；捕获引号使 \1\2 回填，避免 'password=[REDACTED] 引号不平衡。
        # SEC-060：补齐条目元数据与密码学参数关键词（nonce/salt/title/url/notes/tags）——
        # 均为加密列对应明文或其派生输入，误写日志时与 password 同级敏感（防未来误写纵深）。
        (
            re.compile(
                r"(?i)(?<![A-Za-z])(password|pwd|passwd|passphrase|passcode|secret"
                r"|token|api[_-]?key|key"
                r"|username|user[_-]?name|card[_-]?(?:number|holder|cvv|cvc)|cvv|cvc"
                r"|nonce|salt|title|url|notes|tags"
                r'|密码|密钥|令牌|口令)([\'"]?)\s*[:=]\s*.+'
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
        """原地打码后放行所有记录（恒返回 True），绝不因脱敏丢弃日志。

        对 message 命中敏感模式时回填 ``record.msg`` 并清空 ``record.args`` 避免 handler
        二次插值还原原值；``getMessage`` 抛异常时仍放行，避免脱敏逻辑本身致日志丢失。
        """
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


class SecureRotatingFileHandler(RotatingFileHandler):
    """轮转后重新收紧文件权限的 RotatingFileHandler（SEC-059；落地即 0600 见 SEC-068）。

    标准实现 ``doRollover`` 以进程 umask 重建新的 ``baseFilename``（POSIX 默认
    0644 世界可读），启动时的一次 :func:`secure_file` 只覆盖首个文件——轮转产生
    的每个新文件都回退宽松权限。覆写 ``doRollover`` 在轮转完成后对当前文件与
    全部轮转备份重新 :func:`secure_file`；``strict=False`` 降级告警不抛出，日志
    轮转绝不因权限收紧失败而中断记录（与启动路径的降级语义一致）。

    覆写 ``_open`` 以 0600 opener 创建/打开当前文件（SEC-068，对齐 SEC-015 为
    atomic_write 建立的「落地即 0600」标准）：``super().doRollover()`` 内部经
    ``_open()`` 重建 baseFilename，此前以 umask（POSIX 典型 0644）创建、其后的
    :func:`secure_file` 收紧存在毫秒级世界可读窗口——轮转是日志含敏感行（脱敏
    过滤器为纵深防御、非保证）时可被并发的本地进程读取的时点。opener 方式使
    创建那一刻即 0600，窗口归零；doRollover 的 secure_file 保留（幂等，覆盖
    既有备份与升级前遗留的宽松文件）。Windows 忽略 POSIX mode 位（靠父目录
    ACL），覆写无行为差异。
    """

    def _open(self) -> IO[Any]:  # type: ignore[override]
        # 以 os.open 0600 opener 打开（SEC-068）：mode='a' 的 flags 已含
        # O_WRONLY|O_CREAT|O_APPEND，opener 的第三参在创建时刻生效——umask 只会
        # 再收紧不会放宽，落地权限恒 ≤0600。ignore 说明：基类 FileHandler._open
        # 的 typeshed 标注为具体 TextIOWrapper[_WrappedBuffer]（_WrappedBuffer 是
        # typeshed 私有名，用户代码无法可移植引用），本实现的 encoding 可为 None
        # 形态用宽化的 IO[Any] 标注，与内置 logging.handlers 实现的实际行为一致
        # （仅 encoding=str 时产出 TextIOWrapper）。
        return open(
            self.baseFilename,
            self.mode,
            encoding=self.encoding,
            opener=lambda name, flags: os.open(name, flags, 0o600),
        )

    def doRollover(self) -> None:
        super().doRollover()
        # 当前文件：_open() 已落地即 0600（SEC-068），此处收紧保留为幂等纵深
        # （覆盖升级前遗留的宽松备份被滚动改名等形态）
        secure_file(Path(self.baseFilename), strict=False)
        # 轮转备份：正常路径保留既有权限，但重收紧幂等且覆盖「升级前权限宽松的
        # 既有备份被滚动改名后仍宽松」的形态
        for index in range(1, self.backupCount + 1):
            backup = Path(f"{self.baseFilename}.{index}")
            if backup.exists():
                secure_file(backup, strict=False)


def configure_logging(data_dir: Path) -> None:
    """配置应用日志，使用轮转文件 handler，仅记录运行状态。"""
    log_dir = data_dir / "logs"
    secure_directory(log_dir)
    log_path = log_dir / "cipherbox.log"
    handler = SecureRotatingFileHandler(
        log_path,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    # 启动即收紧当前日志与既有轮转备份（含升级前权限宽松的遗留文件，SEC-059）
    for existing in sorted(log_dir.glob(f"{log_path.name}*")):
        secure_file(existing, strict=False)
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
