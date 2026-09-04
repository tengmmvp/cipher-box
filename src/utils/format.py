"""公共格式化工具 — 全项目统一的时间戳格式与本地化展示。

``utc_now_iso`` 提供 aware UTC ISO 8601 字符串作为数据库时间戳单一格式；
``format_datetime`` 将其转换为本地时区的可读形式供 UI 展示；
``timestamped_suffix`` 构造「UTC 时间戳 + 随机后缀」的文件名后缀干，供备份与
共享包两域文件命名共用（QL-082）。属零上层依赖共享层。
"""

import uuid
from datetime import UTC, datetime


def utc_now_iso(now: datetime | None = None) -> str:
    """返回当前 UTC 时间的 ISO 8601 字符串，全项目统一时间戳格式。

    ``now`` 为可注入时钟（aware datetime），供时序相关测试精确控制时间戳；
    生产路径不传，保持实时取值。
    """
    return (now if now is not None else datetime.now(UTC)).isoformat()


def timestamped_suffix(now: datetime | None = None) -> str:
    """返回「UTC 时间戳_8 位随机 hex」的文件名后缀干，供备份与共享包两域共用（QL-082）。

    微秒精度 + 随机后缀保证快速连续生成不重名；返回值不含前缀与扩展名，
    调用方按域拼接。

    Args:
        now: 可注入时钟（aware datetime），供测试；生产路径不传。
    """
    stamp = (now if now is not None else datetime.now(UTC)).strftime("%Y%m%d_%H%M%S_%f")
    return f"{stamp}_{uuid.uuid4().hex[:8]}"


def format_datetime(iso_str: str) -> str:
    """将 ISO 8601 字符串格式化为本地时区的 'YYYY-MM-DD HH:MM:SS'，解析失败原样返回。

    数据库时间戳为 aware UTC（``utc_now_iso``）；naive 输入（如外部导入数据）按 UTC 解释，
    与 ``security_analyzer`` 时间认知一致。
    """
    if not iso_str:
        return ""
    try:
        # 'Z' 后缀先归一化为 +00:00 再解析：项目 requires-python >= 3.12 的
        # fromisoformat 虽已接受 Z，但显式归一使解析输入与 utc_now_iso 产物形态
        # 一致，防御外部导入数据可能携带的边界形态。
        normalized = iso_str[:-1] + "+00:00" if iso_str.endswith("Z") else iso_str
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, AttributeError):
        # AttributeError：非 str 输入（如外部构造的 int 时间戳）的 endswith 调用失败，
        # 入口已防 None/空，此处兜底其余类型并原样返回。
        return iso_str
