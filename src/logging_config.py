"""应用日志配置。日志只记录运行状态，不记录密码等敏感字段。"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(data_dir: Path):
    log_dir = data_dir / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / 'cipherbox.log',
        maxBytes=1_000_000,
        backupCount=3,
        encoding='utf-8',
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(name)s: %(message)s'
    ))
    root = logging.getLogger()
    if not any(isinstance(item, RotatingFileHandler) for item in root.handlers):
        root.addHandler(handler)
    root.setLevel(logging.INFO)
