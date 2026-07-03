"""公共格式化工具函数。"""

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """返回当前 UTC 时间的 ISO 8601 字符串。

    全项目统一使用此函数生成时间戳，确保格式一致且便于未来变更。
    """
    return datetime.now(timezone.utc).isoformat()


def format_datetime(iso_str: str) -> str:
    """将 ISO 8601 日期字符串格式化为本地时区的 'YYYY-MM-DD HH:MM:SS'。

    优先使用 ``datetime.fromisoformat`` 严格解析，解析失败时原样返回。

    数据库时间戳由 ``utc_now_iso`` 生成，带 ``+00:00`` 偏移（aware UTC），
    此处转为本地时区显示。naive 输入（如外部导入数据）按 UTC 解释，
    避免与 aware 混用，与 ``security_analyzer`` 对时间戳的认知保持一致。
    """
    if not iso_str:
        return ''
    # Python 3.10 的 fromisoformat 不接受 UTC 'Z' 后缀（3.11+ 才支持），naive 外部
    # 数据（如手改/导入 JSON）可能含 'Z'；归一化为 +00:00 后再解析，与 aware UTC
    # 路径一致，避免 'Z' 串落入 except 原样返回未格式化。
    normalized = iso_str[:-1] + '+00:00' if iso_str.endswith('Z') else iso_str
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return iso_str
