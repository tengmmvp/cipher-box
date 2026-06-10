"""数据库层类型定义。"""

from enum import Enum, auto


class VerifyMode(Enum):
    """条目完整性校验模式。"""
    STRICT = auto()    # 校验失败时抛出异常
    LENIENT = auto()   # 设置 integrity_error 标志，不抛出异常
    SKIP = auto()      # 完全跳过校验
