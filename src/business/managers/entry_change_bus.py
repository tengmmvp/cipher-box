"""条目变更通知总线 — 缓存失效与回调编排。

统一「条目变更 → 缓存失效 → 回调」通知管线（从 EntryManager 抽离，使
SecurityAnalyzer 等订阅方与缓存失效逻辑解耦，EntryManager 不再持有回调列表）。

关键约束（严格保留原 _notify_entry_change 顺序）：必须先
``cache.apply_change``（持 cache_lock）后跑回调（锁外），且回调吞异常。
否则 SecurityAnalyzer 回调重入 cache 会与失效竞态。
"""

import logging
from collections.abc import Callable

from .entry_cache import EntryCacheManager

logger = logging.getLogger(__name__)


class EntryChangeBus:
    """条目变更事件总线：先失效缓存，再在锁外通知订阅回调。"""

    def __init__(self, cache: EntryCacheManager):
        self._cache = cache
        self._callbacks: list[Callable[[bool], None]] = []

    def register(self, callback: Callable[[bool], None]) -> None:
        """注册条目变更时自动调用的回调，用于缓存失效等。"""
        self._callbacks.append(callback)

    def notify(
        self,
        password_changed: bool = True,
        *,
        crypto_id: str | None = None,
        tags_changed: bool = True,
        category_changed: bool = False,
        clear_summaries: bool = True,
    ) -> None:
        """通知条目变更：先失效缓存，再在锁外调用注册回调。

        password_changed 为 False，如仅修改标题或 URL 时，不涉及密码的分析维度，
        即弱密码、重复、过期结果不变，订阅方可据此跳过昂贵的缓存重算。
        增删条目等结构性变更保持默认 True，因其改变 total 与重复分组。

        缓存失效粒度（避免单条编辑触发全量重解密）：
        - crypto_id 提供（单条更新）：仅 pop 该条目的搜索摘要缓存，而非全清。
        - crypto_id 为 None 且 clear_summaries=True（增删/批量）：清空全部摘要缓存。
        - crypto_id 为 None 且 clear_summaries=False（分类 CRUD）：保留摘要缓存，
          因分类变更不改变条目的 title/username/url/tags 摘要内容。
        - tags_changed：仅当 tags 字段或条目增删改变标签分布时失效 _tags_cache。
        - category_changed：仅分类增删改改变分类名时失效 _category_name_cache。

        回调在锁外执行，避免回调重入缓存方法时与持锁线程竞争。
        """
        self._cache.apply_change(
            crypto_id=crypto_id, tags_changed=tags_changed,
            category_changed=category_changed, clear_summaries=clear_summaries,
        )
        for cb in self._callbacks:
            try:
                cb(password_changed)
            except Exception:
                logger.debug("条目变更回调执行失败", exc_info=True)
