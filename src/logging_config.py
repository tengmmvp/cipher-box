"""应用日志配置。

日志只记录运行状态，不记录密码等敏感字段。为防御未来误写或第三方库
（cryptography/argon2 等）意外输出敏感信息，对 handler 挂载
:class:`SensitiveDataFilter`，对常见敏感模式（cb2 密文标记、password=/key=/
secret= 等赋值）做正则打码，作为纵深防御。
"""

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .utils.file_security import secure_directory, secure_file


class SensitiveDataFilter(logging.Filter):
    """对日志记录中的敏感模式做正则打码。

    CipherBox 自身代码已自律不记录密码/密钥，此 filter 防御未来误写
    ``logger.debug("pwd=%s", pwd)`` 或第三方库的 DEBUG 输出将明文落盘到
    ``%APPDATA%\\CipherBox\\logs\\``。匹配并打码：

    - ``cb2:`` 前缀的密文标记（含 base64 主体）
    - ``password=``/``pwd=``/``key=``/``secret=``/``token=``/``密码=``/``密钥=``
      等赋值后的值

    打码作用于 ``record.getMessage()`` 的结果：改写后的文本回填 ``record.msg``
    并清空 ``record.args``，避免 handler 二次 ``%`` 插值还原原值。getMessage
    异常时不打码（保留原始 record 以免丢失日志）。
    """

    _PATTERNS = (
        # cb2: 密文标记 + base64 主体（至少 8 字符），整段打码
        (re.compile(r'cb2:[A-Za-z0-9+/=]{8,}'), 'cb2:[REDACTED]'),
        # key=value / key:value 形式的敏感赋值，等号或冒号后的非空白内容打码
        (
            re.compile(
                r'(?i)(password|pwd|passwd|secret|token|api[_-]?key|key|密码|密钥|令牌)'
                r'\s*[:=]\s*\S+'
            ),
            r'\1=[REDACTED]',
        ),
    )

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = message
        for pattern, replacement in self._PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


def configure_logging(data_dir: Path):
    """配置应用日志，使用轮转文件 handler，仅记录运行状态。"""
    log_dir = data_dir / 'logs'
    secure_directory(log_dir)
    log_path = log_dir / 'cipherbox.log'
    handler = RotatingFileHandler(
        log_path,
        maxBytes=1_000_000,
        backupCount=3,
        encoding='utf-8',
    )
    secure_file(log_path)
    handler.setFormatter(logging.Formatter(
        # 含 threadName：BackgroundWorker 在子线程执行，调试锁定时序、worker
        # 与主线程日志交织问题时线程名是关键定位信息。
        '%(asctime)s %(levelname)s %(name)s [%(threadName)s]: %(message)s'
    ))
    # 挂载脱敏过滤器：纵深防御，避免敏感数据意外落入日志文件
    handler.addFilter(SensitiveDataFilter())
    root = logging.getLogger()
    # 清理已有 handler，防止测试或多次调用导致重复
    for h in root.handlers[:]:
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(logging.INFO)
