"""公共格式化工具函数。"""

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """返回当前 UTC 时间的 ISO 8601 字符串，全项目统一时间戳格式。"""
    return datetime.now(timezone.utc).isoformat()


def format_datetime(iso_str: str) -> str:
    """将 ISO 8601 字符串格式化为本地时区的 'YYYY-MM-DD HH:MM:SS'，解析失败原样返回。

    数据库时间戳为 aware UTC（``utc_now_iso``）；naive 输入（如外部导入数据）按 UTC 解释，
    与 ``security_analyzer`` 时间认知一致。
    """
    if not iso_str:
        return ''
    # Python 3.10 的 fromisoformat 不接受 'Z' 后缀（3.11+ 才支持），先归一化为 +00:00 再解析。
    normalized = iso_str[:-1] + '+00:00' if iso_str.endswith('Z') else iso_str
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return iso_str
