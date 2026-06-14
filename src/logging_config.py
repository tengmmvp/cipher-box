"""应用日志配置。日志只记录运行状态，不记录密码等敏感字段。"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .utils.file_security import secure_directory, secure_file


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
    root = logging.getLogger()
    # 清理已有 handler，防止测试或多次调用导致重复
    for h in root.handlers[:]:
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(logging.INFO)
