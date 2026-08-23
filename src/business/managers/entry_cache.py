"""条目明文缓存管理 — 搜索摘要、分类名、TOTP secret、标签计数。

集中 5 套明文缓存与统一失效矩阵，由 ``_cache_lock`` 保护，消除 TOTP 定时器
与锁定失效的并发竞态。缓存填充需主密钥解密；``key_epoch`` 变化（改密/锁定）
整体失效。

约定：锁内不调用数据库方法或变更回调，避免与 db 事务锁构成顺序反转死锁。
"""

import logging
import threading
from collections import OrderedDict
from collections.abc import Iterable
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...exceptions import DecryptionError, VaultKeyEpochMismatchError
from ...models import MAX_ENTRIES_LIMIT, RawEntry
from ..services.crypto_utils import (
    category_crypto_id,
    decrypt_field as _decrypt_field_impl,
    require_vault_key,
)

logger = logging.getLogger(__name__)

# 搜索摘要缓存容量上限：与条目数上限（MAX_ENTRIES_LIMIT）对齐，使大库
# （上限内）的 title/username/url/tags 摘要全部驻留缓存、避免每次列表刷新
# 全量重解密。明文驻留面由锁定/改密时 invalidate_all 清零兜底。LRU 仅在
# 超出上限（理论上仅极端入库规模）时淘汰最久未访问项。
_MAX_SEARCH_METADATA_CACHE_SIZE = MAX_ENTRIES_LIMIT


class SearchMetadata(NamedTuple):
    """搜索摘要缓存条目：title/username/url/tags 明文原形及对应小写形式。

    前 4 项为明文原形（列表展示），后 4 项为小写形式（供 matches_search 跳过每条目
    4 字段实时 .lower()）。两者一同解密一次并缓存，消费方按字段名访问取代位置切片。
    """

    title: str
    username: str
    url: str
    tags: str
    title_lower: str
    username_lower: str
    url_lower: str
    tags_lower: str


class EntryCacheManager:
    """条目明文缓存的存储、填充与失效。

    持有搜索摘要 / 失败字段 / 分类名 / TOTP secret / 标签计数 5 套缓存，
    统一 ``_cache_lock`` 保护。
    """

    def __init__(self, vault: "VaultManager"):
        self._vault = vault
        # 搜索摘要 LRU 缓存（字段结构见 SearchMetadata）：容量对齐 MAX_ENTRIES_LIMIT，
        # 防止大库明文摘要无界增长。
        self._search_metadata_cache: OrderedDict[str, SearchMetadata] = OrderedDict()
        self._search_metadata_failed: dict[str, set[str]] = {}
        self._category_name_cache: dict[int, str] = {}
        self._totp_secret_cache: dict[int, str] = {}
        self._tags_cache: list[tuple[str, int]] | None = None
        self._cache_epoch: str | None = None
        # 失效版本号（M4）：单调递增，任何 apply_change / invalidate 都推进。与
        # _cache_epoch（改密/锁定整体失效）正交——单条 apply_change 只 pop 个别条目
        # 不改 epoch，但锁外解密回写仍会基于旧密文重新污染已 pop 的条目；解密回写时
        # 复查 version 未变，确保「解密开始 → 回写」期间发生过任何失效则丢弃结果。
        self._invalidate_version: int = 0
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
                    self._invalidate_version += 1

    def invalidate_all(self) -> None:
        """外部调用：锁定或改密后显式清空全部明文缓存。"""
        with self._cache_lock:
            self._search_metadata_cache.clear()
            self._search_metadata_failed.clear()
            self._category_name_cache.clear()
            self._totp_secret_cache.clear()
            self._tags_cache = None
            self._cache_epoch = None
            self._invalidate_version += 1

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
            # 推进失效版本号（M4）：apply_change 必因条目/分类/tags 变更调用，使进行中的
            # 锁外解密回写丢弃结果——单条 pop 不改 epoch，若无 version 守卫，并发解密会
            # 基于旧密文重新污染刚 pop 的条目摘要/分类名。
            self._invalidate_version += 1
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

    def pop_search_metadata_batch(self, crypto_ids: Iterable[str]) -> None:
        """按 crypto_id 批量 pop 搜索摘要缓存（导入覆盖路径，PERF-022）。

        与 :meth:`apply_change` 的单条 pop 语义一致（摘要 + 失败字段集），但一次
        失效多条且不触发任何回调——导入覆盖的统一通知由调用方经
        ``notify_batch_change(clear_summaries=False)`` 在失效完成后发出一次，
        避免逐条 notify 的 N 次回调派发。须在通知发出前调用（与 change_bus
        「先失效缓存、后跑回调」的顺序约束一致）。version 推进语义同 apply_change
        （M4：进行中的锁外解密回写据此丢弃结果）。
        """
        with self._cache_lock:
            self._invalidate_version += 1
            for crypto_id in crypto_ids:
                self._search_metadata_cache.pop(crypto_id, None)
                self._search_metadata_failed.pop(crypto_id, None)

    def cached_search_metadata(
        self,
        raw_entry: RawEntry,
        *,
        key: bytes | None = None,
    ) -> tuple[str, str, str, str]:
        """解密并缓存列表/搜索所需的 title、username、url、tags（单条路径）。

        取缓存前校验 epoch。批量循环路径应改用 :meth:`_cached_search_metadata_no_check`
        并在循环外调用一次 :meth:`invalidate_if_epoch_changed`，避免每条目重复
        加锁取 epoch——同一批 raw 在单次列表/搜索调用内 epoch 不可能变化
        （调用方事务内已固定），逐条校验属冗余的 N 次 RLock + epoch 查询。

        ``key`` 为 PERF-001 并发修补（M3）：调用方（如 :meth:`EntryManager.get_entry`
        经 ``decrypt_entry`` 视图解密）在 ``epoch_guarded_read`` with 块内快照的主密钥。
        不传则用实时 ``self._key``，保持非并发调用方零改动。锁外解密期间若发生改密，
        实时 ``self._key`` 已轮换为新密钥，与本批旧密文不匹配会致 GCM 认证失败、
        错误摘要以新 epoch 写入缓存而持续污染；传 ``key`` 用快照密钥解密旧密文确保
        结果正确。

        返回明文原形 4 元组；小写形式经 :meth:`search_lower_no_check` 取得，
        两者一同缓存以避免 matches_search 每条目实时 .lower()。
        """
        self.invalidate_if_epoch_changed()
        meta = self._cached_search_metadata_no_check(raw_entry, key=key)
        return (meta.title, meta.username, meta.url, meta.tags)

    def _cached_search_metadata_no_check(
        self,
        raw_entry: RawEntry,
        *,
        key: bytes | None = None,
    ) -> SearchMetadata:
        """cached_search_metadata 的无 epoch 校验版本，供批量循环复用。

        返回 :class:`SearchMetadata`：前 4 项为明文原形（title/username/url/tags，
        列表展示），后 4 项为对应小写形式（供 matches_search 跳过实时 .lower()）。
        两者一同解密一次并缓存。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）。

        调用方须保证循环外已调用 ``invalidate_if_epoch_changed``。
        """
        cid = raw_entry.crypto_id
        with self._cache_lock:
            cached = self._search_metadata_cache.get(cid)
            if cached is not None:
                self._search_metadata_cache.move_to_end(cid)
                return cached
            entry_epoch = self._cache_epoch
            entry_version = self._invalidate_version

        # PERF-001 并发修补（M3）：用调用方传入的锁内快照密钥，避免锁外解密期间
        # 改密 activate 致 self._key 轮换为新密钥、本批 raw 仍旧密文引发 GCM 失败。
        decrypt_key = key if key is not None else self._key
        values: list[str] = []
        failed: set[str] = set()
        for field_name, encrypted in (
            ("title", raw_entry.title),
            ("username", raw_entry.username),
            ("url", raw_entry.url),
            ("tags", raw_entry.tags),
        ):
            try:
                value = _decrypt_field_impl(
                    encrypted,
                    decrypt_key,
                    cid,
                    field_name,
                    strict=True,
                )
            except DecryptionError:
                value = ""
                failed.add(field_name)
            values.append(value)
        # 小写形式与原形一同缓存：一次 .lower()（远廉价于 AES-GCM 解密）换取
        # matches_search 每次搜索跳过 4 字段实时 .lower() 的 N 倍开销。
        result = SearchMetadata(
            values[0],
            values[1],
            values[2],
            values[3],
            values[0].lower(),
            values[1].lower(),
            values[2].lower(),
            values[3].lower(),
        )
        with self._cache_lock:
            # epoch 守卫（改密/锁定整体失效）+ version 守卫（M4：单条 apply_change 未改
            # epoch 但已 pop 本条目，须丢弃基于旧密文的解密结果避免回写污染）。
            if self._cache_epoch == entry_epoch and self._invalidate_version == entry_version:
                self._search_metadata_cache[cid] = result
                self._search_metadata_cache.move_to_end(cid)
                if len(self._search_metadata_cache) > _MAX_SEARCH_METADATA_CACHE_SIZE:
                    self._search_metadata_cache.popitem(last=False)
                if failed:
                    self._search_metadata_failed[cid] = failed
        return result

    def search_metadata_for_analysis(
        self,
        raw_entry: RawEntry,
        *,
        key: bytes | None = None,
    ) -> tuple[str, str, str, str]:
        """供批量分析路径复用的摘要解密（公开入口，无逐条 epoch 校验）。

        :meth:`_cached_search_metadata_no_check` 的公开版本，供 services 层
        （如 :class:`SecurityAnalyzer`）批量循环复用，使 services 不必跨层访问
        managers 的私有方法，守住分层方向（services 不反向耦合 managers
        内部实现）。调用方须在循环外调用 :meth:`invalidate_if_epoch_changed`。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）；
        services 层的非并发调用方不传 key，保持实时 ``self._key`` 行为。

        返回明文原形 4 元组（取自 :class:`SearchMetadata` 前 4 字段）。
        """
        meta = self._cached_search_metadata_no_check(raw_entry, key=key)
        return (meta.title, meta.username, meta.url, meta.tags)

    def search_lower_no_check(
        self,
        raw_entry: RawEntry,
        *,
        key: bytes | None = None,
    ) -> tuple[str, str, str, str]:
        """返回摘要字段的小写形式 (title, username, url, tags)，供搜索匹配复用。

        直接复用 :meth:`_cached_search_metadata_no_check` 已填充的缓存取后 4 项
        （命中缓存时为纯锁内 dict 查询），跳过 :func:`matches_search` 每条目 4 字段
        实时 ``.lower()``。调用方须在循环外已调用 ``invalidate_if_epoch_changed``。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）。
        """
        meta = self._cached_search_metadata_no_check(raw_entry, key=key)
        return (meta.title_lower, meta.username_lower, meta.url_lower, meta.tags_lower)

    def cached_search_metadata_full(
        self,
        raw_entry: RawEntry,
        *,
        key: bytes | None = None,
    ) -> SearchMetadata:
        """返回完整 :class:`SearchMetadata`（原形 + 小写），供调用方一次取用复用。

        搜索热路径经此一次取完整 meta，摘要构建（原形 4 字段）与搜索匹配（小写 4 字段）
        共用，省去分别调 :meth:`search_metadata_for_analysis` 与 :meth:`search_lower_no_check`
        的第二次缓存查询（PERF-016）。调用方须在循环外已调用 ``invalidate_if_epoch_changed``。
        """
        return self._cached_search_metadata_no_check(raw_entry, key=key)

    def get_failed_fields(self, crypto_id: str) -> set[str]:
        """取某条目摘要解密失败的字段集（锁内采样，避免与 clear 竞态）。"""
        with self._cache_lock:
            return self._search_metadata_failed.get(crypto_id, set())

    def decrypt_category_name(
        self,
        category_id: int | None,
        value: str,
        *,
        key: bytes | None = None,
    ) -> str:
        """解密分类名并缓存（首次解密后缓存）。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）：调用方
        （如 :meth:`EntryViewDecryptor.decrypt_entry` / ``decrypt_summary``）在
        ``epoch_guarded_read`` with 块内快照的主密钥。锁外解密期间若发生改密，
        实时 ``self._key`` 已轮换为新密钥与本批旧密文不匹配致 GCM 认证失败、错误
        空分类名以新 epoch 写入缓存持续污染；传 ``key`` 用快照解密旧密文确保正确。
        """
        if category_id is None or not value:
            return ""
        with self._cache_lock:
            cached = self._category_name_cache.get(category_id)
            # 采样 epoch，回写时复查（与 _cached_search_metadata_no_check 对称）：锁外
            # 解密期间若改密清缓存致 _cache_epoch 变化，不回写避免旧明文 stale 污染。
            entry_epoch = self._cache_epoch
            entry_version = self._invalidate_version
        if cached is not None:
            return cached
        name = _decrypt_field_impl(
            value,
            key if key is not None else self._key,
            category_crypto_id(category_id),
            "category_name",
            strict=True,
        )
        with self._cache_lock:
            # epoch + version 双重守卫，语义同 _cached_search_metadata_no_check（M4）。
            if self._cache_epoch == entry_epoch and self._invalidate_version == entry_version:
                self._category_name_cache[category_id] = name
        return name

    def resolve_totp_secret(
        self,
        entry_id: int,
        *,
        use_cache: bool = False,
    ) -> str | None:
        """解析条目的 totp_secret 明文，单一解密路径供 TOTP 方法复用。

        Args:
            entry_id: 条目 ID。
            use_cache: 是否读写会话内 totp_secret 缓存。TotpService.generate_cached
                传 True 复用缓存；TotpService.generate 传 False 仅解密不落缓存。

        读路径经 ``epoch_guarded_read`` 守卫（ARCH-005）：TOTP 定时器是真实并发读者，
        改密 commit 与密钥激活的微秒窗口内裸读会用旧密钥解密新密文致 GCM 认证失败。
        单条解密锁内开销可忽略；epoch 不一致时返回 None，下次定时器周期重新解析。
        """
        if use_cache:
            with self._cache_lock:
                secret = self._totp_secret_cache.get(entry_id)
            if secret is not None:
                return secret
        try:
            with self._vault.epoch_guarded_read():
                raw = self._vault.db.get_entry(entry_id)
                if raw is None or not raw.totp_secret:
                    return None
                secret = _decrypt_field_impl(
                    raw.totp_secret,
                    self._key,
                    raw.crypto_id,
                    "totp_secret",
                )
        except VaultKeyEpochMismatchError:
            return None
        if not secret:
            return None
        if use_cache:
            with self._cache_lock:
                self._totp_secret_cache[entry_id] = secret
        return secret

    def store_totp(self, entry_id: int, secret: str) -> None:
        """预热 TOTP secret 缓存（供 TotpService.get_state 首次展示后预热）。

        空串归一：与 :meth:`resolve_totp_secret` 的 ``if not secret: return None`` 对齐——
        空串等价无 secret，不入缓存，避免空串落缓存后 use_cache 命中返回空串绕过归一。
        """
        if not secret:
            return
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

    def _decrypt_tags_by_crypto_id(
        self,
        crypto_id: str,
        tags_enc: str,
        key: bytes | None = None,
    ) -> str:
        """仅解密 tags 字段供标签聚合（窄投影版，PERF-020）。

        优先复用搜索摘要缓存的 tags（列表 worker 已解密填充于 ``tags`` 字段），命中则
        省去一次 AES-GCM 解密；未命中再走专用单字段解密（冷缓存下省去
        title/username/url 的冗余解密，约 3/4 开销）。``key`` 由批量调用方循环外传入
        快照避免每条经 ``self._key`` 复制密钥（PERF-009）。失败回退空串，与
        :meth:`_cached_search_metadata_no_check` 的容错一致。
        """
        with self._cache_lock:
            cached = self._search_metadata_cache.get(crypto_id)
        if cached is not None:
            return cached.tags
        try:
            return _decrypt_field_impl(
                tags_enc,
                key if key is not None else self._key,
                crypto_id,
                "tags",
                strict=True,
            )
        except DecryptionError:
            return ""

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
        # 标签聚合仅需 tags 字段（PERF-013 跳过验签 + PERF-020 窄投影只取两列）。
        # 安全性不降：tags_enc 完整性由 _decrypt_tags_by_crypto_id 的 GCM 认证保护
        # （篡改即解密失败回退空串）；命中摘要缓存时 tags 已由列表 worker 以 LENIENT
        # 验签。故标签聚合正确性不依赖元数据 HMAC，也不需要其余列。
        try:
            # 读路径 epoch 守卫（SEC-020，对称 resolve_totp_secret 的 ARCH-005）：
            # 改密 commit 与本聚合读的微秒窗口内裸读会用旧密钥解密新密文致 GCM 认证
            # 失败、tags 回退空串丢失。持 db_lock 期间校验内存与库内 epoch 一致。
            with self._vault.epoch_guarded_read():
                # 密钥快照须在校验通过后、锁内取（PERF-009 循环外取一次）：
                # 锁外取会在「取快照→进锁」间遭遇改密 activate，此时 epoch 已同为新、
                # 校验通过，但快照仍是旧密钥，解密新密文致 GCM 失败。
                vault_key = self._key
                for crypto_id, tags_enc in self._vault.db.get_entries_tags_projection():
                    tags_str = self._decrypt_tags_by_crypto_id(crypto_id, tags_enc, vault_key)
                    for tag in (t.strip() for t in tags_str.split(",") if t.strip()):
                        tag_count[tag] = tag_count.get(tag, 0) + 1
        except VaultKeyEpochMismatchError:
            # epoch 不一致：返回已聚合部分，不回填缓存（observed_epoch != 当前
            # _cache_epoch，下方回填守卫跳过），下次调用重新解密。
            pass
        result = sorted(tag_count.items(), key=lambda x: -x[1])
        with self._cache_lock:
            # 双重检查：期间可能已被并发填充，或 epoch 已变化（改密/锁定清空了缓存）。
            # 比对 observed_epoch 避免返回跨 epoch 的脏缓存。
            if self._tags_cache is not None and self._cache_epoch == observed_epoch:
                return self._tags_cache
            # 仅当 epoch 未变才回填（SEC-010）：epoch 变化时 result 为旧密钥解密的旧明文，
            # 而 _cache_epoch 已被 invalidate 更新为新值，此时回填会令下次命中返回跨 epoch
            # 脏缓存。当前调用方返回 result（旧 epoch 上下文可接受），下次调用重新解密。
            if self._cache_epoch == observed_epoch:
                self._tags_cache = result
            return result

    @property
    def tags_cache_valid(self) -> bool:
        """标签缓存是否有效（非空且 key_epoch 未变），供 UI 决定同步/异步刷新。

        缓存命中时 get_all_tags() 仅锁内取值（微秒级），UI 可据此同步重建下拉、
        省去无谓的后台线程创建；缓存失效时才需异步全量解密。
        """
        with self._cache_lock:
            return self._tags_cache is not None and self._cache_epoch == self._vault.key_epoch
