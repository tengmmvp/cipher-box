"""公共格式化工具函数。"""

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """返回当前 UTC 时间的 ISO 8601 字符串。

    全项目统一使用此函数生成时间戳，确保格式一致且便于未来变更。
    """
    return datetime.now(timezone.utc).isoformat()


def format_datetime(iso_str: str) -> str:
    """将 ISO 8601 日期字符串格式化为 'YYYY-MM-DD HH:MM:SS'。

    优先使用 ``datetime.fromisoformat`` 进行严格解析，
    解析失败时原样返回。

    注意：使用 ``fromisoformat`` 解析，带时区偏移的字符串会保留为
    aware datetime，但 strftime 输出不含时区标识。当前数据库存储的
    时间戳均为 UTC 且无时区偏移，因此不存在歧义。若未来存储格式
    变更，需在此处统一时区转换。
    """
    if not iso_str:
        return ''
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return iso_str
