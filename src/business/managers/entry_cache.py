"""条目明文缓存管理 — 搜索摘要、分类名、TOTP secret、标签计数、搜索投影行集。

集中 6 套缓存与统一失效矩阵，由 ``_cache_lock`` 保护，消除 TOTP 定时器
与锁定失效的并发竞态。缓存填充需主密钥解密；``key_epoch`` 变化（改密/锁定）
整体失效。搜索投影行集（PERF-086）为密文行缓存，无明文驻留顾虑。

约定：锁内不调用数据库方法或变更回调，避免与 db 事务锁构成顺序反转死锁。
"""

import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, NamedTuple, Protocol

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...database.types import SearchRow
from ...exceptions import DecryptionError, VaultKeyEpochMismatchError
from ...models import MAX_ENTRIES_LIMIT, parse_tag_list
from ..services.crypto_utils import (
    category_crypto_id,
    decrypt_field as _decrypt_field_impl,
    require_vault_key,
)

# 搜索摘要缓存容量上限：与条目数上限（MAX_ENTRIES_LIMIT）对齐，使大库
# （上限内）的 title/username/url/tags 摘要全部驻留缓存、避免每次列表刷新
# 全量重解密。明文驻留面由锁定/改密时 invalidate_all 清零兜底。LRU 仅在
# 超出上限（理论上仅极端入库规模）时淘汰最久未访问项。
_MAX_SEARCH_METADATA_CACHE_SIZE = MAX_ENTRIES_LIMIT

# 搜索投影缓存键容量上限（PERF-086）：键=(deleted_only, category_id,
# favorite_only, order_by, order_desc) 组合。典型常驻组合为主视图当前排序 +
# 近期更新视图（updated_at DESC）+ 回收站视图各占一键，上限 4 覆盖工作集。
# 内存依据：单键最坏 = 条目数上限（50k）行 SearchRow，全密文 + 5 个明文定位/
# 排序列，实测规模 ~20MB/50k 行——密文行无明文驻留顾虑（AES-GCM 密文不可检索，
# 泄漏面等价于 db 文件本身），且仅在接近条目数上限的库才达到该量级，常规库
# （≤5k 条）单键 ~2MB；超限按 LRU 淘汰整键（行集整体失效，粒度即键）。
_MAX_PROJECTION_CACHE_KEYS = 4

# 投影缓存键（PERF-086）：(deleted_only, category_id, favorite_only, order_by,
# order_desc)。order_by=None 表示 SQL 复合序（默认序），此时 order_desc 恒规范化
# 为 True（复合序固定 is_favorite DESC, updated_at DESC，方向参数无意义），避免
# 同义键重复占用缓存槽；非 None 时行集已按该白名单字段排好序，与无序行集不可
# 混存同一键（消费方对行序敏感：排序下推分支依赖行序做提前终止）。
ProjectionCacheKey = tuple[bool, int | None, bool, str | None, bool]


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


class SearchRowSource(Protocol):
    """摘要解密的最小输入协议（PERF-074，对齐 ARCH-032 的 TotpCacheProtocol 模式）。

    本类对输入行的依赖面仅 5 个密文属性（crypto_id + 四摘要字段），结构上由
    :class:`models.RawEntry` 与 db 层窄投影 :class:`database.types.SearchRow`
    同时满足——搜索路径改窄投影拉取（SearchRow）后无需物化完整宽行，本协议
    使同一解密入口接受两者。属性名与 RawEntry 密文属性同名（title 等存密文）。
    """

    @property
    def crypto_id(self) -> str: ...

    @property
    def title(self) -> str: ...

    @property
    def username(self) -> str: ...

    @property
    def url(self) -> str: ...

    @property
    def tags(self) -> str: ...


def _decrypt_search_metadata(
    raw_entry: SearchRowSource,
    decrypt_key: bytes,
) -> tuple[SearchMetadata, set[str]]:
    """解密单行摘要四字段，返回 (原形+小写的 SearchMetadata, 失败字段集)。

    :meth:`EntryCacheManager._cached_search_metadata_no_check`（单条路径）与
    ``_SearchMetadataBatch.get``（批量会话，PERF-086）共用的解密核心单一事实源：
    失败字段回退空串并记入 ``failed`` 集（LENIENT 容错口径，调用方据此展示完整性
    警示/区分合法空）。小写形式与原形一同产出，供 matches_search 跳过每条目
    4 字段实时 ``.lower()``。
    """
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
                raw_entry.crypto_id,
                field_name,
                strict=True,
            )
        except DecryptionError:
            value = ""
            failed.add(field_name)
        values.append(value)
    return (
        SearchMetadata(
            values[0],
            values[1],
            values[2],
            values[3],
            values[0].lower(),
            values[1].lower(),
            values[2].lower(),
            values[3].lower(),
        ),
        failed,
    )


class _SearchMetadataBatch:
    """批量摘要读取会话（PERF-086）：一次持锁快照命中集 + 锁外解密 + 一次持锁回写。

    搜索热路径逐行经 ``_cached_search_metadata_no_check`` 取 meta 时每行两次
    RLock 往返（命中读 + move_to_end），50k 行规模是可测成本（实测 ~78ms）。本会话
    把锁开销摊销为三次：进入时快照 ``_search_metadata_cache`` 的 dict 拷贝，循环内
    零锁（命中查快照 / 缺失锁外解密入 pending），退出时一次回写全部 pending。

    回写守卫（epoch + version 整批双比对）：批量解密窗口比单条长，窗口内任何失效
    （并发写 notify / 恢复重臂）都会使整批丢弃——比单条路径「失效前行已回写」更
    保守（失效是低频事件，丢弃只损失缓存填充、下次重解密，正确性无损）。

    LRU 语义取舍：批量命中**不**推进 recency（不 move_to_end）。LRU 仅在缓存超出
    ``_MAX_SEARCH_METADATA_CACHE_SIZE``（= 条目数上限）时才产生淘汰，应用自身以
    该上限约束入库，超限仅理论场景；其最坏后果是超限库中批量扫描命中的行提前被
    淘汰（下次重解密），无正确性影响——不值得为推进 recency 重引逐行锁。
    """

    def __init__(
        self,
        snapshot: dict[str, SearchMetadata],
        entry_epoch: str | None,
        entry_version: int,
        decrypt_key: bytes,
    ):
        self._snapshot = snapshot
        self._entry_epoch = entry_epoch
        self._entry_version = entry_version
        self._decrypt_key = decrypt_key
        self._pending: list[tuple[str, SearchMetadata, set[str]]] = []

    def get(self, raw_entry: SearchRowSource) -> SearchMetadata:
        """取单行摘要 meta：命中快照直接返回，缺失则锁外解密并入 pending 待回写。"""
        cached = self._snapshot.get(raw_entry.crypto_id)
        if cached is not None:
            return cached
        meta, failed = _decrypt_search_metadata(raw_entry, self._decrypt_key)
        self._pending.append((raw_entry.crypto_id, meta, failed))
        return meta


class EntryCacheManager:
    """条目明文缓存的存储、填充与失效。

    持有搜索摘要 / 失败字段 / 分类名 / TOTP secret / 标签计数 / 搜索投影行集
    6 套缓存，统一 ``_cache_lock`` 保护。失效版本分域（QL-070）：主域
    ``_invalidate_version`` 守卫投影行集/摘要回写/标签差分，TOTP 域
    ``_totp_invalidate_version`` 守卫 TOTP secret 回写——单条 TOTP 失效不击穿
    主域缓存（详见 ``__init__`` 注释），全局失效两域一并推进。
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
        # 搜索投影行集缓存（PERF-086）：键/容量语义见 ProjectionCacheKey 与
        # _MAX_PROJECTION_CACHE_KEYS；以 _invalidate_version 失效（全部写路径
        # 均经 apply_change / invalidate_all 推进版本，见 search_projection_rows）。
        self._projection_cache: OrderedDict[ProjectionCacheKey, tuple[int, list[SearchRow]]] = (
            OrderedDict()
        )
        self._cache_epoch: str | None = None
        # 失效版本号（M4）：单调递增，任何 apply_change / invalidate 都推进。与
        # _cache_epoch（改密/锁定整体失效）正交——单条 apply_change 只 pop 个别条目
        # 不改 epoch，但锁外解密回写仍会基于旧密文重新污染已 pop 的条目；解密回写时
        # 复查 version 未变，确保「解密开始 → 回写」期间发生过任何失效则丢弃结果。
        self._invalidate_version: int = 0
        # TOTP 域失效版本号（QL-070 分域）：与 _invalidate_version 平行的独立计数器，
        # 仅 resolve_totp_secret 的回写守卫消费。pop_totp/clear_totp 只推进本域——
        # 单条 TOTP secret 失效不改变条目表行集与摘要/标签数据，若推进主域，UI 每次
        # 离开带 TOTP 的条目（detail_panel 的 evict → pop_totp，无任何 DB 写）都会
        # 作废全部 4 个投影缓存键（PERF-086），50k 行集重取 ~160ms 的目标交互被无关
        # 失效击穿；主域的摘要批回写/标签差分/投影缓存守卫均不受 TOTP 域失效影响。
        # 全局失效（apply_change / pop_search_metadata_batch / invalidate_all /
        # invalidate_if_epoch_changed）经 _advance_global_invalidation 同时推进两域：
        # 条目写窗口内 TOTP secret 可能随变更，在飞的 TOTP 解密回写仍须被拒收。
        # 初始值与 _invalidate_version 同刻起步，两者各自单调即可（守卫只比对同域）。
        self._totp_invalidate_version: int = 0
        # 缓存锁：保护上述缓存及 _cache_epoch 的结构性读写，消除 TOTP 定时器线程
        # 与锁定 invalidate_all 并发时的竞态。锁内不调用数据库方法或变更回调。
        self._cache_lock = threading.RLock()

    def _advance_global_invalidation(self) -> None:
        """全局失效同时推进主域与 TOTP 域版本（调用方须持 ``_cache_lock``）。

        QL-070 分域后的整体失效入口：主域（投影行集/摘要回写/标签差分守卫）与
        TOTP 域（TOTP secret 回写守卫）一并推进——整体失效意味着条目数据已变，
        在飞的各域解密回写均基于旧数据，须全部拒收。
        """
        self._invalidate_version += 1
        self._totp_invalidate_version += 1

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
                    # 投影行集随 epoch 轮换整体清空（PERF-086）：改密/恢复会重写
                    # 全部密文，旧密文行集对新密钥不可解密。
                    self._projection_cache.clear()
                    self._cache_epoch = current
                    self._advance_global_invalidation()

    def invalidate_all(self) -> None:
        """外部调用：锁定或改密后显式清空全部明文缓存与投影行集。"""
        with self._cache_lock:
            self._search_metadata_cache.clear()
            self._search_metadata_failed.clear()
            self._category_name_cache.clear()
            self._totp_secret_cache.clear()
            self._tags_cache = None
            self._projection_cache.clear()
            self._cache_epoch = None
            self._advance_global_invalidation()

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
            # 基于旧密文重新污染刚 pop 的条目摘要/分类名。两域一并推进（QL-070 分域）。
            self._advance_global_invalidation()
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
            self._advance_global_invalidation()
            for crypto_id in crypto_ids:
                self._search_metadata_cache.pop(crypto_id, None)
                self._search_metadata_failed.pop(crypto_id, None)

    def cached_search_metadata(
        self,
        raw_entry: SearchRowSource,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
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

        ``data_epoch`` 语义见 :meth:`_cached_search_metadata_no_check`（SEC-041 写入方
        世代守卫）。

        返回明文原形 4 元组；小写形式与原形一同缓存在 :class:`SearchMetadata`
        （经 :meth:`cached_search_metadata_full` 一次取用），避免 matches_search
        每条目实时 .lower()。
        """
        self.invalidate_if_epoch_changed()
        meta = self._cached_search_metadata_no_check(raw_entry, key=key, data_epoch=data_epoch)
        return (meta.title, meta.username, meta.url, meta.tags)

    def _cached_search_metadata_no_check(
        self,
        raw_entry: SearchRowSource,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> SearchMetadata:
        """cached_search_metadata 的无 epoch 校验版本，供批量循环复用。

        返回 :class:`SearchMetadata`：前 4 项为明文原形（title/username/url/tags，
        列表展示），后 4 项为对应小写形式（供 matches_search 跳过实时 .lower()）。
        两者一同解密一次并缓存。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）。

        ``data_epoch`` 为写入方世代守卫（SEC-041，对齐 M3/M4 的 key/version 快照
        风格）：调用方在 ``epoch_guarded_read`` 锁内与 raw/密钥同刻快照的
        ``vault.key_epoch``。回写要求「当前 ``_cache_epoch`` == 写入方世代」，而非仅
        比对缓存侧自身采样值——后台 worker 在恢复/改密提交（``invalidate_all`` 置
        ``_cache_epoch=None``）后被新读路径重臂为新 epoch 时，缓存侧双检的两侧均为
        新世代会放行回写，旧 raw+旧密钥解密出的**恢复前明文**即被 grafting 进新
        epoch 缓存（last-writer-wins 持久污染）。不传时退回缓存侧采样，既有调用方
        行为不变。

        调用方须保证循环外已调用 ``invalidate_if_epoch_changed``。
        """
        cid = raw_entry.crypto_id
        with self._cache_lock:
            cached = self._search_metadata_cache.get(cid)
            if cached is not None:
                self._search_metadata_cache.move_to_end(cid)
                return cached
            # 写入方世代（SEC-041）：优先取调用方锁内快照的 epoch，未提供（既有调用方）
            # 时退回缓存侧采样，保持原行为。
            entry_epoch = data_epoch if data_epoch is not None else self._cache_epoch
            entry_version = self._invalidate_version

        # PERF-001 并发修补（M3）：用调用方传入的锁内快照密钥，避免锁外解密期间
        # 改密 activate 致 self._key 轮换为新密钥、本批 raw 仍旧密文引发 GCM 失败。
        decrypt_key = key if key is not None else self._key
        # 解密核心（PERF-086 抽出）：单条与批量会话共用，失败回退空串 + failed 集。
        result, failed = _decrypt_search_metadata(raw_entry, decrypt_key)
        with self._cache_lock:
            # epoch 守卫（改密/锁定整体失效）+ version 守卫（M4：单条 apply_change 未改
            # epoch 但已 pop 本条目，须丢弃基于旧密文的解密结果避免回写污染）。
            # entry_epoch 为写入方世代（SEC-041）：data_epoch 提供时即调用方锁内快照，
            # 恢复/改密重臂后的新 epoch 缓存不再接收旧世代解密结果（跨世代 grafting）。
            if self._cache_epoch == entry_epoch and self._invalidate_version == entry_version:
                self._search_metadata_cache[cid] = result
                self._search_metadata_cache.move_to_end(cid)
                self._writeback_failed_and_evict(cid, failed)
        return result

    def _writeback_failed_and_evict(self, cid: str, failed: set[str]) -> None:
        """回写失败字段集并执行超容量 LRU 淘汰（调用方须持 ``_cache_lock``）。

        单条回写与批量会话回写共用的收尾步骤（PERF-086 抽出）：failed 记录与
        LRU 淘汰联动（QL-058：被淘汰条目的 failed 记录同步清理，否则「解密失败 +
        缓存超上限」同现时 failed 字典随时间无界驻留）。
        """
        if len(self._search_metadata_cache) > _MAX_SEARCH_METADATA_CACHE_SIZE:
            evicted_cid, _ = self._search_metadata_cache.popitem(last=False)
            self._search_metadata_failed.pop(evicted_cid, None)
        if failed:
            self._search_metadata_failed[cid] = failed

    @contextmanager
    def search_metadata_batch(
        self,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> Iterator[_SearchMetadataBatch]:
        """批量循环路径的摘要读取会话（PERF-086）。

        搜索/去重等批量循环改经 :class:`_SearchMetadataBatch` 取 meta：进入时一次
        持锁快照命中集（dict 拷贝）替代逐行 RLock + move_to_end（50k 行实测 ~78ms），
        退出时一次持锁回写 pending（epoch + version 整批守卫，语义同
        :meth:`_cached_search_metadata_no_check` 的单条双守卫；try/finally 包 yield，
        正常退出、循环 break/return 与 with 体抛异常退出均执行回写）。
        ``key``/``data_epoch`` 语义与单条路径一致（PERF-001/SEC-041）；调用方须在
        进入前调用 ``invalidate_if_epoch_changed`` 固定本批世代。
        """
        with self._cache_lock:
            snapshot = dict(self._search_metadata_cache)
            entry_epoch = data_epoch if data_epoch is not None else self._cache_epoch
            entry_version = self._invalidate_version
        batch = _SearchMetadataBatch(
            snapshot,
            entry_epoch,
            entry_version,
            key if key is not None else self._key,
        )
        try:
            yield batch
        finally:
            # 回写（含循环 break/return 与 with 体抛异常退出的场景，PERF-086）：
            # 异常路径同样回写——已解密的 pending 是正确结果（基于采样世代密钥的
            # 自洽解密），丢弃只损失缓存填充；回写内的 epoch + version 整批守卫在
            # 异常时刻依然安全（版本比对的是「采样 → 回写」窗口内的失效，与退出
            # 原因无关）。finally 内不得 return/raise（会吞掉/替换原异常）：pending
            # 为空时跳过回写块自然结束；回写段为纯 dict/list 操作，若极端情况下再
            # 抛异常，Python 隐式异常链（__context__）会保留原异常上下文。
            if batch._pending:
                with self._cache_lock:
                    # epoch + version 整批守卫：批量解密窗口内的任何失效使整批丢弃
                    # （见 _SearchMetadataBatch 类 docstring 的保守性论证）。
                    if (
                        self._cache_epoch == entry_epoch
                        and self._invalidate_version == entry_version
                    ):
                        for cid, meta, failed in batch._pending:
                            self._search_metadata_cache[cid] = meta
                            self._search_metadata_cache.move_to_end(cid)
                            self._writeback_failed_and_evict(cid, failed)

    def search_projection_rows(
        self,
        key: ProjectionCacheKey,
        fetch: Callable[[], list[SearchRow]],
    ) -> list[SearchRow]:
        """搜索窄投影行集的会话缓存（PERF-086）：行集仅取决于过滤三元组与排序规格。

        行集内容与搜索词无关（过滤/匹配在内存进行），暖态重复搜索（逐字符输入、
        视图切换）每次重拉投影行集（fetchall + SearchRow 构造，50k 行实测 ~160ms）
        是主导成本之一，此处按键缓存密文行集。行内容全部为密文与明文定位/排序列，
        无明文驻留顾虑；以 ``_invalidate_version`` 失效——全部写路径（增删改/
        导入/恢复/锁定/改密）都经 apply_change / pop_search_metadata_batch /
        invalidate_all 推进版本，任何写后本缓存必然失配重取。

        ``fetch`` 由调用方在 ``epoch_guarded_read`` 内构造执行（行集一致性由调用方
        持 db_lock 保证）；本方法遵守「锁内不调用数据库」约定，fetch 在
        ``_cache_lock`` 外调用。回填守卫：fetch 期间版本推进（并发写已 notify）则
        拒收——行集相对新库已陈旧，下次重取吸收，当前调用方仍使用本次 fetch 结果
        （与无缓存时的读视图语义一致）。

        出口浅拷贝（PERF-086）：命中与回填两条路径均返回 ``list(rows)`` 新容器，
        不外泄缓存内部 list 引用——消费方（EntryManager 匹配循环）虽只读，返回
        引用会让任何未来调用方的就地变异（sort/append）直接污染缓存行集且无失败
        信号，属本文件防御性拷贝纪律（对齐 get_failed_fields 的 QL-056）的潜伏
        破口。成本：仅拷贝引用的容器分配，50k 行实测 ~0.4ms，相对命中省下的
        fetchall ~160ms 可忽略；SearchRow 为不可变 NamedTuple，行对象本身无隔离面。
        """
        with self._cache_lock:
            cached = self._projection_cache.get(key)
            if cached is not None and cached[0] == self._invalidate_version:
                self._projection_cache.move_to_end(key)
                return list(cached[1])
            observed_version = self._invalidate_version
        rows = fetch()
        with self._cache_lock:
            if self._invalidate_version == observed_version:
                self._projection_cache[key] = (observed_version, rows)
                self._projection_cache.move_to_end(key)
                while len(self._projection_cache) > _MAX_PROJECTION_CACHE_KEYS:
                    self._projection_cache.popitem(last=False)
        return list(rows)

    def search_metadata_for_analysis(
        self,
        raw_entry: SearchRowSource,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> tuple[str, str, str, str]:
        """供批量分析路径复用的摘要解密（公开入口，无逐条 epoch 校验）。

        :meth:`_cached_search_metadata_no_check` 的公开版本，供 services 层
        （如 :class:`SecurityAnalyzer`）批量循环复用，使 services 不必跨层访问
        managers 的私有方法，守住分层方向（services 不反向耦合 managers
        内部实现）。调用方须在循环外调用 :meth:`invalidate_if_epoch_changed`。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）；
        services 层的非并发调用方不传 key，保持实时 ``self._key`` 行为。
        ``data_epoch`` 语义见 :meth:`_cached_search_metadata_no_check`（SEC-041）。

        返回明文原形 4 元组（取自 :class:`SearchMetadata` 前 4 字段）。
        """
        meta = self._cached_search_metadata_no_check(raw_entry, key=key, data_epoch=data_epoch)
        return (meta.title, meta.username, meta.url, meta.tags)

    def cached_search_metadata_full(
        self,
        raw_entry: SearchRowSource,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> SearchMetadata:
        """返回完整 :class:`SearchMetadata`（原形 + 小写），供调用方一次取用复用。

        搜索热路径经此一次取完整 meta，摘要构建（原形 4 字段）与搜索匹配（小写 4 字段）
        共用，省去分别调 :meth:`search_metadata_for_analysis` 与独立小写入口的第二次
        缓存查询（PERF-016；独立小写入口 search_lower_no_check 已随 MAINT-102 删除，
        全库零调用且其能力为本方法后 4 字段的子集）。调用方须在循环外已调用
        ``invalidate_if_epoch_changed``。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）；
        ``data_epoch`` 语义见 :meth:`_cached_search_metadata_no_check`（SEC-041）——
        搜索 worker 经 :meth:`EntryManager.get_entry_summaries` 传入锁内快照世代。
        """
        return self._cached_search_metadata_no_check(raw_entry, key=key, data_epoch=data_epoch)

    def get_failed_fields(self, crypto_id: str) -> set[str]:
        """取某条目摘要解密失败的字段集（锁内采样，返回拷贝）。

        返回内部 set 的拷贝（QL-056）：直接返回 ``dict.get`` 引用时，调用方原地
        修改（add/discard）会污染缓存——当前消费方只读或已有 ``set(...)`` 拷贝
        防御，此处收口使 API 语义与「采样」docstring 一致，新调用方无需自防。
        """
        with self._cache_lock:
            return set(self._search_metadata_failed.get(crypto_id, ()))

    @property
    def cache_epoch(self) -> str | None:
        """缓存当前臂住的 key_epoch（测试观察用，MAINT-095）。

        只读视图：测试经此断言失效/重臂后的世代值，不再直读 ``_cache_epoch``。
        """
        with self._cache_lock:
            return self._cache_epoch

    @property
    def search_metadata_cached_ids(self) -> frozenset[str]:
        """搜索摘要缓存当前持有的 crypto_id 集合（测试观察用，MAINT-095）。

        只读快照：测试经此断言缓存命中/清空/精确失效（成员资格与规模），不再
        直读 ``_search_metadata_cache`` 内部 OrderedDict。
        """
        with self._cache_lock:
            return frozenset(self._search_metadata_cache)

    @property
    def invalidate_version(self) -> int:
        """当前失效版本号（调用方快照用，QL-065）。

        EntryManager 在增删/编辑的写事务**前**经此快照版本，事务提交后随
        :meth:`apply_tag_delta` 的 ``expected_version`` 复查——「读 raw → 提交 →
        差分」窗口内若发生任何失效（并发导入/恢复的 notify 置空标签缓存并重建），
        差分被放弃，由下次全量重算吸收，堵双扣。
        """
        with self._cache_lock:
            return self._invalidate_version

    def decrypt_category_name(
        self,
        category_id: int | None,
        value: str,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> str:
        """解密分类名并缓存（首次解密后缓存）。

        ``key`` 语义见 :meth:`cached_search_metadata`（PERF-001 并发修补）：调用方
        （如 :meth:`EntryViewDecryptor.decrypt_entry` / ``decrypt_summary``）在
        ``epoch_guarded_read`` with 块内快照的主密钥。锁外解密期间若发生改密，
        实时 ``self._key`` 已轮换为新密钥与本批旧密文不匹配致 GCM 认证失败、错误
        空分类名以新 epoch 写入缓存持续污染；传 ``key`` 用快照解密旧密文确保正确。

        ``data_epoch`` 为写入方世代（SEC-043，语义同 :meth:`_cached_search_metadata_no_check`
        的 SEC-041 守卫）：调用方在锁内与 raw/密钥同刻快照的世代，提供时优先于缓存
        侧采样参与回写守卫，堵「锁外解密期间恢复重臂新世代、旧明文植入新缓存」的
        跨世代 grafting。未提供时保持缓存侧采样原行为——剩余不传的调用方为
        category_manager 的分类名解密（自持会话缓存路径，不在本守卫改造的文件集内，
        其窗口与既有 version 守卫的防护面一致，接入留作后续）。
        """
        if category_id is None or not value:
            return ""
        with self._cache_lock:
            cached = self._category_name_cache.get(category_id)
            # 采样 epoch，回写时复查（与 _cached_search_metadata_no_check 对称）：锁外
            # 解密期间若改密清缓存致 _cache_epoch 变化，不回写避免旧明文 stale 污染。
            # data_epoch 提供时取代缓存侧采样（SEC-043，理由见 docstring）。
            entry_epoch = data_epoch if data_epoch is not None else self._cache_epoch
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
            # epoch + version 双重守卫，语义同 _cached_search_metadata_no_check（M4/SEC-043）。
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

        缓存回写带写入方世代守卫（SEC-044，镜像摘要缓存回写模式）：解密前在读守卫
        锁内采样缓存世代与失效版本，回写前双重复查——解密完成（退出读守卫）到回写
        之间若恢复/锁定触发 ``invalidate_all`` 且新读路径重臂新世代，旧世代 secret
        不得写入新世代缓存（TOTP secret 是双因子凭证，跨世代驻留泄漏面更大）。
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
                # 解密前锁内采样世代与版本（SEC-044）：读守卫持有 db_lock，恢复/
                # 改密 commit 无法插入采样与解密之间，故此处缓存侧采样即调用方世代。
                # version 取 TOTP 域（QL-070 分域）：本守卫只关心 TOTP secret 缓存的
                # 失效（pop_totp/clear_totp 与全局失效两域均覆盖本域），主域版本（投影
                # 行集/摘要/标签）与本 secret 的有效性无关。
                with self._cache_lock:
                    entry_epoch = self._cache_epoch
                    entry_version = self._totp_invalidate_version
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
                # epoch + version 双重复查（SEC-044）：语义同 _cached_search_metadata_no_check
                # （M4/SEC-041）——解密期间发生过任何整体失效（含恢复重臂新世代，两域
                # 一并推进）或单条 TOTP 失效（pop_totp，仅本域），本次解密结果均不回写。
                if (
                    self._cache_epoch == entry_epoch
                    and self._totp_invalidate_version == entry_version
                ):
                    self._totp_secret_cache[entry_id] = secret
        return secret

    def store_totp(
        self,
        entry_id: int,
        secret: str,
        *,
        data_epoch: str | None = None,
    ) -> None:
        """预热 TOTP secret 缓存（供 TotpService.get_state 首次展示后预热）。

        空串归一：与 :meth:`resolve_totp_secret` 的 ``if not secret: return None`` 对齐——
        空串等价无 secret，不入缓存，避免空串落缓存后 use_cache 命中返回空串绕过归一。

        ``data_epoch`` 为写入方世代复查（SEC-044）：提供时要求当前缓存世代仍等于
        该世代才落缓存，堵「secret 解密于恢复前世代、store 晚于恢复重臂」的跨世代
        grafting——本方法自身无解密窗口（无可复查的采样-回写间隙），世代来源只能
        是调用方随 secret 一并传递的快照。未提供保持无条件落缓存（既有调用方的
        secret 与缓存世代同线程同世代，无跨世代窗口）。
        """
        if not secret:
            return
        with self._cache_lock:
            if data_epoch is not None and self._cache_epoch != data_epoch:
                return
            self._totp_secret_cache[entry_id] = secret

    def pop_totp(self, entry_id: int) -> None:
        """失效单条 TOTP secret 缓存（条目更新/删除修改 totp_secret，或离开条目时
        的驻留面收缩 evict）。

        持锁推进 ``_totp_invalidate_version``（QL-070）：:meth:`resolve_totp_secret`
        的回写守卫须能检测「解密前采样 → pop → 回写」窗口内的单条失效——此前 pop
        只清 dict 不推进版本，守卫的 version 比对检测不到单条失效、防护名存实亡
        （当前主线程串行执行使竞态不可达，属线程模型巧合而非设计保证）。

        只推进 TOTP 域而不动主域 ``_invalidate_version``（QL-070 分域）：pop 的两个
        高频来源是条目写路径与 detail_panel 的 evict（离开条目即 pop，无任何 DB
        写）——单条 TOTP secret 失效不改变条目表行集/摘要/标签数据，推进主域会使
        上述交互每次作废全部投影缓存键（PERF-086）与摘要批回写守卫；TOTP 域独立
        计数后，两域守卫各查各的版本，互不击穿。
        """
        with self._cache_lock:
            self._totp_invalidate_version += 1
            self._totp_secret_cache.pop(entry_id, None)

    def clear_totp(self) -> None:
        """清空全部 TOTP secret 缓存（清空回收站）。

        version 推进语义同 :meth:`pop_totp`（QL-070 分域：仅 TOTP 域）。
        """
        with self._cache_lock:
            self._totp_invalidate_version += 1
            self._totp_secret_cache.clear()

    def decrypt_tags_for_delta(
        self,
        crypto_id: str,
        tags_enc: str,
        key: bytes | None = None,
    ) -> str | None:
        """解密单条 tags 供计数差分（QL-066 单一事实源），失败返回 None 哨兵。

        区分「解密失败」（None，差分不可依赖，调用方保守整表失效）与「合法空串」
        （''，差分 no-op）——此前 ``_decrypt_tags_for_delta``（EntryManager 侧）与
        本方法聚合口径均失败回退 ''，使 tags 密文损坏条目被删除（LENIENT 读路径
        服务的清理场景）后差分静默 no-op，``_tags_cache`` 陈旧。

        优先复用搜索摘要缓存的 tags（列表 worker 已解密，PERF-020 的暖缓存复用）；
        暖缓存的 tags 为「失败回退空串」形态，须经 ``_search_metadata_failed`` 的
        字段集区分失败与合法空。``key`` 由批量调用方循环外传入快照（PERF-009）。

        Returns:
            解密成功的 tags 明文（可为空串）；解密失败（GCM 认证失败）为 None。
        """
        with self._cache_lock:
            cached = self._search_metadata_cache.get(crypto_id)
            if cached is not None:
                if "tags" in self._search_metadata_failed.get(crypto_id, ()):
                    return None
                return cached.tags
        if not tags_enc:
            return ""
        try:
            return _decrypt_field_impl(
                tags_enc,
                key if key is not None else self._key,
                crypto_id,
                "tags",
                strict=True,
            )
        except DecryptionError:
            return None

    def _decrypt_tags_by_crypto_id(
        self,
        crypto_id: str,
        tags_enc: str,
        key: bytes | None = None,
    ) -> str:
        """仅解密 tags 字段供标签聚合（窄投影版，PERF-020），失败回退空串。

        :meth:`decrypt_tags_for_delta` 的聚合口径包装（QL-066 收敛解密单一事实源）：
        全量重算对损坏 tags 回退空串（该条目不贡献标签计数），与
        :meth:`_cached_search_metadata_no_check` 的容错口径一致。
        """
        result = self.decrypt_tags_for_delta(crypto_id, tags_enc, key)
        return result if result is not None else ""

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率，结果在会话内缓存。

        标签列为密文，仅解密 tags 字段后聚合；缓存于条目增删改与锁定/改密时失效。
        """
        self.invalidate_if_epoch_changed()
        with self._cache_lock:
            cached = self._tags_cache
            observed_epoch = self._cache_epoch
            # 失效版本同刻快照（QL-069）：聚合在 db_lock 内进行，「聚合出锁 → 回填」
            # 窗口内主线程的写入 + notify 只推进 version 不动 epoch（单条 apply_change
            # 不改 epoch）——若回填仅比 epoch，基于旧库的快照会落入 _tags_cache 且
            # 无自愈（标签缓存无 TTL，仅锁定/改密/恢复/写路径可纠正），与本文件
            # 摘要（_cached_search_metadata_no_check）与分类名（decrypt_category_name）
            # 的 epoch+version 双守卫对齐。
            observed_version = self._invalidate_version
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
                    # 解析走 models.parse_tag_list 单一事实源（QL-065）：与差分路径
                    # （apply_tag_delta）共用同一解析，两口径计数不漂移。
                    for tag in parse_tag_list(tags_str):
                        tag_count[tag] = tag_count.get(tag, 0) + 1
        except VaultKeyEpochMismatchError:
            # epoch 不一致：返回已聚合部分，不回填缓存（observed_epoch != 当前
            # _cache_epoch，下方回填守卫跳过），下次调用重新解密。
            pass
        result = sorted(tag_count.items(), key=lambda x: -x[1])
        with self._cache_lock:
            # 双重检查：期间可能已被并发填充，或 epoch 已变化（改密/锁定清空了缓存）。
            # 比对 observed_epoch 避免返回跨 epoch 的脏缓存。并发填充分支不比 version：
            # 此时 _tags_cache 内是比本快照更新的数据（填充者晚于本快照采样），返回它
            # 恒优于本 result。
            if self._tags_cache is not None and self._cache_epoch == observed_epoch:
                return self._tags_cache
            # 仅当 epoch 且 version 均未变才回填（SEC-010 + QL-069）：epoch 变化时
            # result 为旧密钥解密的旧明文，而 _cache_epoch 已被 invalidate 更新为新值，
            # 此时回填会令下次命中返回跨 epoch 脏缓存；version 变化说明聚合窗口内
            # 发生过任何失效（写入 notify / 并发差分），result 相对新库已陈旧，回填
            # 会使标签缓存永久停留在旧快照（下次 get_all_tags 命中缓存不再重算）。
            # 两种失配均丢弃（下次调用重算吸收），当前调用方返回 result（旧上下文
            # 可接受，与仅比 epoch 时的既有语义一致）。
            if self._cache_epoch == observed_epoch and self._invalidate_version == observed_version:
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

    def apply_tag_delta(
        self,
        old_tags: str = "",
        new_tags: str = "",
        *,
        expected_version: int | None = None,
    ) -> bool:
        """单条条目的标签计数差分（PERF-079），一次锁内先减旧再加新，返回是否应用。

        增删/恢复/编辑 tags 路径以此原地增减该条 tags 的各标签计数（重排保持
        「计数降序」出口契约、清零标签移除），免去 ``tags_changed=True`` 触发的
        下次 get_all_tags 全量重解密重算。old/new 任一为空是合法端点（纯增或纯减）。

        单次锁内完成「减旧+加新」（QL-065）：此前编辑路径两次锁调用（先 removed
        后 added），中间并发 get_all_tags 可见「旧已减、新未加」的撕裂态。

        ``expected_version`` 为写回世代守卫（QL-065，SEC-041 的同款模式）：调用方
        （EntryManager）在写事务**前**经 :attr:`invalidate_version` 快照，「读 raw →
        提交事务 → 差分」窗口内若发生任何失效（并发导入/恢复的 notify 置空
        ``_tags_cache`` 并由后续 get_all_tags 基于新库重建），本次差分被放弃——
        重建结果已含本条变更，再扣即双扣。不传时保持无条件写回（测试直调等
        既有调用方语义不变）。

        Returns:
            是否应用：True 为差分已应用，或 old/new 解析后均为空（本就无需变更，
            缓存状态正确）；False 为差分被放弃（缓存未填充，或 ``expected_version``
            世代失配）——调用方（``_notify_entry_structure_changed``）据此保守置
            ``tags_changed=True`` 走整表失效（QL-070），消除「既未差分也未失效」
            的第三态：旧行为放弃后仍 tags_changed=False，缓存正确性依赖
            apply_change 恰好整表失效的未声明不变量巧合收敛。

        应用即推进 ``_invalidate_version``（QL-069）：get_all_tags 的回填守卫接入
        version 后，差分是唯一「改变 ``_tags_cache`` 却不推进 version」的路径——
        不推进时，在飞聚合的旧快照（不含差分对应的写入）会通过 version 比对回填，
        覆盖已差分的正确缓存。推进的副作用（丢弃在飞的摘要/分类名解密回写）可
        忽略：差分后紧随的 change_bus.notify → apply_change 本就会推进，额外丢弃
        窗口仅微秒级。
        """
        removed = parse_tag_list(old_tags)
        added = parse_tag_list(new_tags)
        if not removed and not added:
            return True
        with self._cache_lock:
            cached = self._tags_cache
            if cached is None:
                return False
            # 写回世代守卫：快照版本与当前不一致说明差分窗口内发生过失效，
            # 放弃本次差分（下次全量重算吸收），不向重建后的缓存叠加旧变更。
            if expected_version is not None and self._invalidate_version != expected_version:
                return False
            counts = dict(cached)
            for tag in removed:
                counts[tag] = counts.get(tag, 0) - 1
            for tag in added:
                counts[tag] = counts.get(tag, 0) + 1
            self._tags_cache = sorted(
                ((tag, count) for tag, count in counts.items() if count > 0),
                key=lambda item: -item[1],
            )
            # 推进失效版本（QL-069，理由见 docstring）：使在飞 get_all_tags 聚合的
            # 回填守卫拒收旧快照。
            self._invalidate_version += 1
            return True
