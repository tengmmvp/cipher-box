"""条目变更通知总线 — 缓存失效与回调编排。

统一「条目变更 → 缓存失效 → 回调」通知管线，使订阅方与缓存失效逻辑解耦。

关键约束：必须先 ``cache.apply_change``（持 cache_lock）后跑回调（锁外），
且回调吞异常——否则回调重入 cache 会与失效竞态。
"""

import logging
from collections.abc import Callable

from .entry_cache import EntryCacheManager

logger = logging.getLogger(__name__)


class EntryChangeBus:
    """条目变更事件总线：先失效缓存，再在锁外通知订阅回调。"""

    def __init__(self, cache: EntryCacheManager):
        self._cache = cache
        # 回调签名 (password_changed, metadata_changed)：订阅方据此判断是否需昂贵的
        # 缓存重算。metadata_changed 表示 title/username 等安全报告元数据是否变更，
        # 与 password_changed 共同决定 SecurityAnalyzer 是否失效（两者皆 False 的纯
        # 旁路变更如 is_favorite 切换可跳过，避免无谓整库重解密）。
        self._callbacks: list[Callable[[bool, bool], None]] = []

    def register(self, callback: Callable[[bool, bool], None]) -> None:
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
        metadata_changed: bool = True,
    ) -> None:
        """通知条目变更：先失效缓存，再在锁外调用注册回调。

        两个语义维度供订阅方（如 SecurityAnalyzer）决定是否跳过昂贵的缓存重算：

        - ``password_changed``：密码是否变更。False（如仅改标题/URL）时弱密码/重复/
          过期判定不变。增删条目等结构性变更保持默认 True（改变 total 与重复分组）。
        - ``metadata_changed``：安全报告展示的条目元数据（title/username 等）是否
          变更。纯旁路变更（如 ``is_favorite`` 切换、分类调整）传 False——这些不进入
          weak/duplicate/old 的判定或展示，失效只会触发无谓的整库重解密。

        缓存失效粒度详见 :meth:`EntryCacheManager.apply_change`；回调在锁外执行，
        避免回调重入缓存方法时与持锁线程竞争。
        """
        self._cache.apply_change(
            crypto_id=crypto_id,
            tags_changed=tags_changed,
            category_changed=category_changed,
            clear_summaries=clear_summaries,
        )
        for cb in self._callbacks:
            try:
                cb(password_changed, metadata_changed)
            except Exception:
                logger.warning("条目变更回调执行失败", exc_info=True)
