"""列表搜索与标签过滤的匹配谓词（纯函数，无加解密依赖）。

自 crypto_utils 拆出（MAINT-097）：搜索域谓词与「统一字段加解密入口 +
SENSITIVE_ENCRYPTED_FIELDS 单一事实源」本是两个职责域，混驻稀释 crypto_utils
的加密守护面。消费方：UI 的 entry_list_controller（搜索/标签过滤）、
EntryManager 搜索热路径（matches_search_lower 复用预计算小写值，PERF-074）。
"""

from __future__ import annotations

from ...models import Entry, RawEntry


def matches_search(entry: Entry | RawEntry, query: str) -> bool:
    """检查条目是否匹配搜索关键词（大小写不敏感，搜 title/username/url/tags）。

    Args:
        entry: 待匹配的明文 Entry 摘要。生产路径不应传入 RawEntry。
        query: 搜索关键词，空串匹配所有。
    """
    if not query:
        return True
    kw = query.lower()
    username = entry.username or ""
    return (
        kw in (entry.title or "").lower()
        or kw in username.lower()
        or kw in (entry.url or "").lower()
        or kw in (entry.tags or "").lower()
    )


def matches_search_lower(
    lower: tuple[str, str, str, str],
    query: str,
) -> bool:
    """检查条目是否匹配搜索关键词，复用预计算的小写字段值，省去每条目 4 次 ``.lower()``。

    供批量搜索热路径消除 N×4 次 ``.lower()`` 开销，匹配语义与 :func:`matches_search` 一致。

    Args:
        lower: 预计算小写形式的 (title, username, url, tags)。
        query: 搜索关键词，空串匹配所有。
    """
    if not query:
        return True
    kw = query.lower()
    return kw in lower[0] or kw in lower[1] or kw in lower[2] or kw in lower[3]


def matches_tag(entry: Entry, tag: str) -> bool:
    """检查条目是否含指定标签（大小写不敏感精确匹配），解析逻辑与 ``Entry.get_tag_list()`` 一致。"""
    if not tag:
        return True
    tag_lower = tag.strip().lower()
    entry_tags = [t.strip().lower() for t in (entry.tags or "").split(",") if t.strip()]
    return tag_lower in entry_tags
