"""条目明文缓存管理 — 搜索摘要、分类名、TOTP secret、标签计数。

从 EntryManager 抽离的缓存关注点：集中 5 套明文缓存与统一失效矩阵，
由 ``_cache_lock`` 保护，消除 TOTP 定时器与锁定失效的并发竞态。缓存填充需
主密钥解密，经 vault 访问；``key_epoch`` 变化（改密/锁定）整体失效。

约定（与原 EntryManager 一致）：锁内不调用数据库方法或变更回调，避免与
db 事务锁构成顺序反转死锁。
"""

import logging
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...database.types import EntryQuery, VerifyMode
from ...exceptions import DecryptionError
from ...models import RawEntry
from ..services.crypto_utils import (
    category_crypto_id,
    decrypt_field as _decrypt_field_impl,
    require_vault_key,
)

logger = logging.getLogger(__name__)

# 搜索摘要缓存容量上限：沿用 encryption.py 的「有限容量 LRU」设计理念，
# 避免大库下明文摘要 dict 以条目数为上界无界增长。LRU 淘汰最久未访问项。
_MAX_SEARCH_METADATA_CACHE_SIZE = 2000


class EntryCacheManager:
    """条目明文缓存的存储、填充与失效。

    持有搜索摘要 / 失败字段 / 分类名 / TOTP secret / 标签计数 5 套缓存，
    统一 ``_cache_lock`` 保护。缓存填充（解密）与失效逻辑从 EntryManager
    迁入，使缓存成为独立可测试的关注点。
    """

    def __init__(self, vault: 'VaultManager'):
        self._vault = vault
        # 搜索摘要缓存保存 title/username/url/tags 明文，减少重复搜索解密。
        # OrderedDict + LRU 上限，防止大库下明文摘要无界增长。
        self._search_metadata_cache: OrderedDict[str, tuple[str, str, str, str]] = OrderedDict()
        self._search_metadata_failed: dict[str, set[str]] = {}
        self._category_name_cache: dict[int, str] = {}
        self._totp_secret_cache: dict[int, str] = {}
        self._tags_cache: list[tuple[str, int]] | None = None
        self._cache_epoch: str | None = None
        # 缓存锁：保护上述缓存及 _cache_epoch 的结构性读写，消除 TOTP 定时器线程
        # 与锁定 invalidate_all 并发时的竞态。锁内不调用数据库方法或变更回调。
        self._cache_lock = threading.RLock()

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def invalidate_if_epoch_changed(self) -> None:
        """检测 vault.key_epoch 变化，变化则清空所有明文缓存。

        当 key_epoch 变为 None 时（保险库已锁定或 epoch 不匹配强制清除），
        无论 _cache_epoch 是否也为 None，都应清空缓存。
        """
        current = self._vault.key_epoch
        if current is None or current != self._cache_epoch:
            with self._cache_lock:
                # 持锁后再次确认，避免与并发 invalidate 重复执行清空序列
                current = self._vault.key_epoch
                if current is None or current != self._cache_epoch:
                    self._search_metadata_cache.clear()
                    self._search_metadata_failed.clear()
                    self._category_name_cache.clear()
                    self._totp_secret_cache.clear()
                    self._tags_cache = None
                    self._cache_epoch = current

    def invalidate_all(self) -> None:
        """外部调用：锁定或改密后显式清空全部明文缓存。"""
        with self._cache_lock:
            self._search_metadata_cache.clear()
            self._search_metadata_failed.clear()
            self._category_name_cache.clear()
            self._totp_secret_cache.clear()
            self._tags_cache = None
            self._cache_epoch = None

    def apply_change(
        self,
        *,
        crypto_id: str | None = None,
        tags_changed: bool = True,
        category_changed: bool = False,
        clear_summaries: bool = True,
    ) -> None:
        """条目变更的缓存失效（不含回调，回调由 EntryManager 在锁外执行）。

        失效粒度：
        - crypto_id 提供（单条更新）：仅 pop 该条目的搜索摘要缓存。
        - crypto_id 为 None 且 clear_summaries=True（增删/批量）：清空全部摘要。
        - crypto_id 为 None 且 clear_summaries=False（分类 CRUD）：保留摘要缓存。
        - tags_changed：tags 分布改变时失效 _tags_cache。
        - category_changed：分类名改变时失效 _category_name_cache。
        """
        with self._cache_lock:
            if crypto_id is not None:
                self._search_metadata_cache.pop(crypto_id, None)
                self._search_metadata_failed.pop(crypto_id, None)
            elif clear_summaries:
                self._search_metadata_cache.clear()
                self._search_metadata_failed.clear()
            if tags_changed:
                self._tags_cache = None
            if category_changed:
                self._category_name_cache.clear()

    def cached_search_metadata(
        self, raw_entry: RawEntry,
    ) -> tuple[str, str, str, str]:
        """解密并缓存列表/搜索所需的 title、username、url、tags（单条路径）。

        取缓存前校验 epoch。批量循环路径应改用 :meth:`_cached_search_metadata_no_check`
        并在循环外调用一次 :meth:`invalidate_if_epoch_changed`，避免每条目重复
        加锁取 epoch——同一批 raw 在单次列表/搜索调用内 epoch 不可能变化
        （调用方事务内已固定），逐条校验属冗余的 N 次 RLock + epoch 查询。
        """
        self.invalidate_if_epoch_changed()
        return self._cached_search_metadata_no_check(raw_entry)

    def _cached_search_metadata_no_check(
        self, raw_entry: RawEntry,
    ) -> tuple[str, str, str, str]:
        """cached_search_metadata 的无 epoch 校验版本，供批量循环复用。

        调用方须保证循环外已调用 ``invalidate_if_epoch_changed``。
        """
        cid = raw_entry.crypto_id
        with self._cache_lock:
            cached = self._search_metadata_cache.get(cid)
            if cached is not None:
                self._search_metadata_cache.move_to_end(cid)
                return cached
            entry_epoch = self._cache_epoch

        values: list[str] = []
        failed: set[str] = set()
        for field_name, encrypted in (
            ('title', raw_entry.title),
            ('username', raw_entry.username),
            ('url', raw_entry.url),
            ('tags', raw_entry.tags),
        ):
            try:
                value = _decrypt_field_impl(
                    encrypted, self._key, cid, field_name, strict=True,
                )
            except DecryptionError:
                value = ''
                failed.add(field_name)
            values.append(value)
        result = (values[0], values[1], values[2], values[3])
        with self._cache_lock:
            if self._cache_epoch == entry_epoch:
                self._search_metadata_cache[cid] = result
                self._search_metadata_cache.move_to_end(cid)
                if len(self._search_metadata_cache) > _MAX_SEARCH_METADATA_CACHE_SIZE:
                    self._search_metadata_cache.popitem(last=False)
                if failed:
                    self._search_metadata_failed[cid] = failed
        return result

    def search_metadata_for_analysis(
        self, raw_entry: RawEntry,
    ) -> tuple[str, str, str, str]:
        """供批量分析路径复用的摘要解密（公开入口，无逐条 epoch 校验）。

        :meth:`_cached_search_metadata_no_check` 的公开版本，供 services 层
        （如 :class:`SecurityAnalyzer`）批量循环复用，使 services 不必跨层访问
        managers 的私有方法，守住分层方向（services 不反向耦合 managers
        内部实现）。调用方须在循环外调用 :meth:`invalidate_if_epoch_changed`。
        """
        return self._cached_search_metadata_no_check(raw_entry)

    def get_failed_fields(self, crypto_id: str) -> set[str]:
        """取某条目摘要解密失败的字段集（锁内采样，避免与 clear 竞态）。"""
        with self._cache_lock:
            return self._search_metadata_failed.get(crypto_id, set())

    def decrypt_category_name(self, category_id: int | None, value: str) -> str:
        """解密分类名并缓存（首次解密后缓存）。"""
        if category_id is None or not value:
            return ''
        with self._cache_lock:
            cached = self._category_name_cache.get(category_id)
        if cached is not None:
            return cached
        name = _decrypt_field_impl(
            value,
            self._key,
            category_crypto_id(category_id),
            'category_name',
            strict=True,
        )
        with self._cache_lock:
            self._category_name_cache[category_id] = name
        return name

    def resolve_totp_secret(
        self, entry_id: int, *, use_cache: bool = False,
    ) -> str | None:
        """解析条目的 totp_secret 明文，单一解密路径供 TOTP 方法复用。

        Args:
            entry_id: 条目 ID。
            use_cache: 是否读写会话内 totp_secret 缓存。TotpService.generate_cached
                传 True 复用缓存；TotpService.generate 传 False 仅解密不落缓存。
        """
        if use_cache:
            with self._cache_lock:
                secret = self._totp_secret_cache.get(entry_id)
            if secret is not None:
                return secret
        # DB 查询与解密在锁外，避免持锁阻塞并发缓存访问
        raw = self._vault.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        secret = _decrypt_field_impl(
            raw.totp_secret, self._key, raw.crypto_id, 'totp_secret',
        )
        if not secret:
            return None
        if use_cache:
            with self._cache_lock:
                self._totp_secret_cache[entry_id] = secret
        return secret

    def store_totp(self, entry_id: int, secret: str) -> None:
        """预热 TOTP secret 缓存（供 TotpService.get_state 首次展示后预热）。"""
        with self._cache_lock:
            self._totp_secret_cache[entry_id] = secret

    def pop_totp(self, entry_id: int) -> None:
        """失效单条 TOTP secret 缓存（条目更新/删除修改 totp_secret）。"""
        with self._cache_lock:
            self._totp_secret_cache.pop(entry_id, None)

    def clear_totp(self) -> None:
        """清空全部 TOTP secret 缓存（清空回收站）。"""
        with self._cache_lock:
            self._totp_secret_cache.clear()

    def _decrypt_tags(self, raw_entry: RawEntry) -> str:
        """仅解密 tags 字段供标签聚合。

        优先复用搜索摘要缓存的 tags（列表 worker 已解密填充于元组第 4 项），命中则
        省去一次 AES-GCM 解密；未命中再走专用单字段解密（冷缓存下省去
        title/username/url 的冗余解密，约 3/4 开销）。失败回退空串，与
        :meth:`_cached_search_metadata_no_check` 的容错一致。
        """
        cached = self._search_metadata_cache.get(raw_entry.crypto_id)
        if cached is not None:
            return cached[3]
        try:
            return _decrypt_field_impl(
                raw_entry.tags, self._key, raw_entry.crypto_id, 'tags', strict=True,
            )
        except DecryptionError:
            return ''

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率，结果在会话内缓存。

        标签列为密文，仅解密 tags 字段后聚合；缓存于条目增删改与锁定/改密时失效。
        """
        self.invalidate_if_epoch_changed()
        with self._cache_lock:
            cached = self._tags_cache
            observed_epoch = self._cache_epoch
        if cached is not None:
            return cached
        tag_count: dict[str, int] = {}
        for raw in self._vault.db.get_entries(
            EntryQuery(include_deleted=False, verify=VerifyMode.LENIENT)
        ):
            tags_str = self._decrypt_tags(raw)
            for tag in (t.strip() for t in tags_str.split(',') if t.strip()):
                tag_count[tag] = tag_count.get(tag, 0) + 1
        result = sorted(tag_count.items(), key=lambda x: -x[1])
        with self._cache_lock:
            # 双重检查：期间可能已被并发填充，或 epoch 已变化（改密/锁定清空了缓存）。
            # 比对 observed_epoch 避免返回跨 epoch 的脏缓存。
            if self._tags_cache is not None and self._cache_epoch == observed_epoch:
                return self._tags_cache
            self._tags_cache = result
            return result

    @property
    def tags_cache_valid(self) -> bool:
        """标签缓存是否有效（非空且 key_epoch 未变），供 UI 决定同步/异步刷新。

        缓存命中时 get_all_tags() 仅锁内取值（微秒级），UI 可据此同步重建下拉、
        省去无谓的后台线程创建；缓存失效时才需异步全量解密。
        """
        with self._cache_lock:
            return (
                self._tags_cache is not None
                and self._cache_epoch == self._vault.key_epoch
            )
