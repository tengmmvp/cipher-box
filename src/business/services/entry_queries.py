"""条目查询读服务：详情/列表摘要/近期更新/导入去重/导出读取的读路径编排（MAINT-116）。

从 EntryManager 下沉的查询读族（同类先例：MAINT-021 视图解密族下沉、MAINT-104
排序键纯函数迁出 managers）。读路径的公共骨架——「进读块前固定缓存 epoch（PERF-086）
→ ``epoch_guarded_read`` 锁内拉行集 + 同刻快照 key/世代（PERF-001/SEC-041）→ 锁外
解密/内存排序/截断/构建」——与写路径（CRUD/加密/变更通知/失效）在 EntryManager 内
界限清晰但长期共处，随两族各自增长拆出：EntryManager 聚焦写路径与加密原语，公开
查询方法保持薄委托，调用方/UI/测试零改动。

模块成员：

- :class:`EntryQueryService`：读路径编排服务（无自有状态，vault/cache/视图解密器
  均由宿主 EntryManager 注入共享实例）；
- :class:`EntryRead`：详情读的锁内同刻快照载荷（SEC-054/063）；
- :func:`projection_cache_key`（ARCH-052 键构造单一事实源）与 :data:`ProjectionCacheKey`
  （键类型别名，home 随迁见其注释，ARCH-053 先例）。

职责边界：只读——不触写路径、变更通知与缓存失效决策（失效由 EntryManager 与
EntryChangeBus 负责；本服务对缓存只做「读行集/读摘要/会话回写」消费）。密钥经
锁内快照传入锁外解密（PERF-001），缓存回写的写入方世代守卫由锁内同刻快照
``data_epoch`` 承担（SEC-041/043/049）。
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, NamedTuple, Protocol

if TYPE_CHECKING:
    # vault 维持 TYPE_CHECKING 具体类（ARCH-039 显式决策，对齐 security_analyzer /
    # entry_batch_writer 先例）：本服务对 VaultManager 的依赖面（epoch_guarded_read /
    # key_epoch / db / key 四成员）即其读路径核心，协议化只会产出「影子类」——把
    # 读核心 API 抄一遍再让唯一实现满足，无测试替身或第二实现的净收益。cache 依赖
    # 面窄（4 成员），按 AnalysisCacheProtocol 先例协议化（见 QueryCacheProtocol）。
    from ..managers.vault_manager import VaultManager

from ...database.types import (
    ORDER_BY_FIELDS,
    EntryQuery,
    SearchRow,
    VaultDataStore,
    VerifyMode,
)
from ...exceptions import VaultKeyEpochMismatchError
from ...models import DEFAULT_RECENT_SUMMARIES_LIMIT, Entry, RawEntry
from .crypto_utils import require_vault_key
from .entry_batch_writer import should_report_progress
from .entry_search_match import matches_search_lower
from .entry_sorting import SortKeySource, entry_sort_key
from .entry_view_decryption import EntryViewDecryptor, SearchMetadata

# 投影缓存键（PERF-086）：(deleted_only, category_id, favorite_only, order_by,
# order_desc)。order_by=None 表示 SQL 复合序（默认序），此时 order_desc 恒规范化
# 为 True（复合序固定 is_favorite DESC, updated_at DESC，方向参数无意义），避免
# 同义键重复占用缓存槽；非 None 时行集已按该白名单字段排好序，与无序行集不可
# 混存同一键（消费方对行序敏感：排序下推分支依赖行序做提前终止）。
#
# home 迁移（MAINT-116 随查询族迁入，对齐 ARCH-053 的 SearchMetadata 先例）：原
# 定义于 managers/entry_cache，唯一的 services 消费方是本模块的键构造函数
# :func:`projection_cache_key`——纯数据类型（零 managers 依赖）随消费方归位，
# entry_cache 经 managers→services 正向 import 引用。
ProjectionCacheKey = tuple[bool, int | None, bool, str | None, bool]


def projection_cache_key(query: EntryQuery) -> ProjectionCacheKey:
    """从 EntryQuery 构造投影行集缓存键（ARCH-052，键构造单一事实源）。

    此前 ``get_entry_summaries`` 手工拼五元组、与 EntryQuery 的维度声明双源——
    未来加过滤维度漏改键则不同行集共享同键静默错数据，收敛为本函数显式提取。

    键维度 ↔ query 维度契约（键形态见 :data:`ProjectionCacheKey`）：

    - ``(deleted_only, category_id, favorite_only)`` ↔ 同名三维过滤条件；
    - ``(order_by, order_desc)`` ↔ 行集实际下推的排序规格；``order_by=None``
      （SQL 复合序）时规范化为 ``(None, True)``——复合序固定方向、方向参数无
      意义，避免同义键占多个缓存槽（PERF-086 键语义）。

    不参与键的维度及理由（入口校验升格为运行期拒绝，防「行集不同而键相同」）：

    - ``include_deleted``/``after_id``/``limit``：影响行集，但当前投影缓存的全部
      消费方（get_entry_summaries 内存路径、get_entry_dedup_index）恒传默认值
      （内存路径 limit 恒 None——截断由排序后/循环提前终止承担；after_id 无
      投影消费方）。传入非默认值须经新键维度（或显式论证）后再放行。
    - ``order_by`` 非 None 而 ``tie_break_order=False``：tie_break 只改行序不改
      行集，键的 order 段不区分两形态——当前消费方带显式排序时恒
      ``tie_break_order=True``（PERF-087 等价性诉求），混入 False 形态会使同键
      缓存两种并列序的行集，故拒绝。
    - ``verify``：投影查询本身无验签（``get_entries_search_projection``），
      对行集零影响，任意取值同键。

    MAINT-116 随查询族自 entry_manager 迁入并去下划线公开（跨模块消费的函数
    不再是 managers 的私有实现细节，对齐 MAINT-104 的 SortKeySource 先例）；
    键语义零变化，TestProjectionCacheKeyContract 行为锚定。

    Raises:
        ValueError: 上述「影响行集/行序但未入键」的维度被传入非默认形态。
    """
    if query.include_deleted or query.after_id is not None or query.limit is not None:
        raise ValueError(
            "投影缓存键不含 include_deleted/after_id/limit 维度，"
            "当前消费方须以默认值调用（见 projection_cache_key 契约）"
        )
    if query.order_by is not None and not query.tie_break_order:
        raise ValueError("投影缓存键不区分并列裁决形态：order_by 非 None 时须 tie_break_order=True")
    order: tuple[str | None, bool] = (
        (None, True) if query.order_by is None else (query.order_by, query.order_desc)
    )
    return (
        query.deleted_only,
        query.category_id,
        query.favorite_only,
        order[0],
        order[1],
    )


class _MetadataBatchView(Protocol):
    """批量摘要读取会话的最小视图：查询服务仅消费 ``get`` 单成员。

    实现方 :class:`entry_cache._SearchMetadataBatch`（PERF-086 会话）经结构化满足
    ——参数 ``SearchRow`` 满足其 ``SearchRowSource`` 协议入参（NamedTuple 结构满足
    只读属性协议），返回的 :class:`SearchMetadata` 本就在 services 域（ARCH-053），
    services 不反向 import managers 的会话实现类。参数名 ``raw_entry`` 与实现方
    一致：pyright 按名匹配协议成员参数，改名即失配。
    """

    def get(self, raw_entry: SearchRow) -> SearchMetadata: ...


class QueryCacheProtocol(Protocol):
    """查询读族所需的最小缓存协议，解耦 EntryQueryService 与 EntryCacheManager。

    对齐 :class:`ViewDecryptCacheProtocol` / :class:`AnalysisCacheProtocol` 模式
    （ARCH-032/039）：``EntryCacheManager`` 自然满足此协议，由宿主（EntryManager）
    构造时注入与其共享的实例，services 子包运行时不 import managers，守住分层
    方向。协议面以本服务实际消费为准（4 成员）——投影行集缓存的**失效**决策不在
    此面（失效由 EntryManager/EntryChangeBus 触发，本服务只读行集与会话回写）。

    保留决策（复核 ARCH-039 的「单实现协议=影子类」批评后仍保留）：全库一致性
    的既定规则是「services 层对 **cache** 依赖一律协议化（TotpCacheProtocol /
    ViewDecryptCacheProtocol / AnalysisCacheProtocol / 本协议，均为单消费方），
    对 **vault/manager** 依赖锚定 TYPE_CHECKING 具体类（ARCH-039：成员面与核心
    同构、协议无净收益）」——本协议在规则内侧，删此留彼反而引入新的不一致。
    已知代价：与 EntryCacheManager 的签名 lockstep 维护（SEC-063 曾随 store_totp
    返回 bool 同步过一次），作为规则成本接受；出现第二实现或测试替身需求时
    本协议即产生净收益。
    """

    def invalidate_if_epoch_changed(self) -> None:
        """key_epoch 变化时清空全部明文缓存与投影行集；读路径进读块前调用。"""
        ...

    def search_projection_rows(
        self,
        key: ProjectionCacheKey,
        fetch: Callable[[], list[SearchRow]],
    ) -> list[SearchRow]:
        """搜索窄投影行集的会话缓存（PERF-086）：行集仅取决于过滤三元组与排序规格。"""
        ...

    def search_metadata_batch(
        self,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> AbstractContextManager[_MetadataBatchView]:
        """批量摘要读取会话（PERF-086）：一次持锁快照命中集 + 锁外解密 + 一次回写。"""
        ...

    @property
    def totp_invalidate_version(self) -> int:
        """当前 TOTP 域失效版本号（详情读锁内同刻快照用，SEC-063 b 层）。"""
        ...


class _SummaryRead(NamedTuple):
    """摘要读路径的锁内快照载荷（MAINT-092）：行集与密钥/世代同刻采集。

    两条行集互斥（内存路径仅 search_rows、SQL 下推路径仅 raw_entries），由
    :meth:`EntryQueryService.get_entry_summaries` 在 ``epoch_guarded_read`` 块内
    填充后传给锁外的摘要构建私有方法——行集与 key/data_epoch 的同刻性由构造点
    保证。
    """

    search_rows: list[SearchRow]
    raw_entries: list[RawEntry]
    key: bytes
    data_epoch: str | None


class EntryRead(NamedTuple):
    """详情读路径的锁内同刻快照载荷（SEC-063 b 层）：entry 与解密世代、TOTP 域版本。

    ``data_epoch`` 语义见 :meth:`EntryQueryService.get_entry_with_epoch`（SEC-054）；
    ``data_version`` 为 totp_secret 解密时点（读锁内与 raw/key/epoch 同刻快照）的
    TOTP 域失效版本，随 preloaded secret 沿预热链（detail_panel → TOTPWidget →
    TotpService.get_state → store_totp）透传——「解密 → 预热」窗口内发生过**本条目**
    的 TOTP 失效（pop_totp 不改 epoch，如导入覆盖 prepare 的 evict）或整体失效时，
    旧 secret 被 store 侧版本守卫拒收入缓存并触发 get_state 的 DB 重解密回退
    （SEC-063 b 层真实通道；守卫按条目粒度判定，TOTP→TOTP 切换时对上一条目的
    evict 不误伤本条目的预热）。entry 为 None（条目不存在 / epoch 失配）时 epoch
    与 version 均为 None，调用方先判 entry 再消费。
    """

    entry: Entry | None
    data_epoch: str | None
    data_version: int | None


class EntryQueryService:
    """条目查询读服务：查询读族的锁内外编排（MAINT-116 自 EntryManager 下沉）。

    无自有状态：vault（密钥/世代/读守卫/db）、cache（投影行集/摘要缓存）、
    view_decryptor（raw→Entry 三视图纯变换）均由宿主 EntryManager 注入共享实例
    （ARCH-033 宿主内部构造模式）。注入契约如实化（MAINT-116 拆分时修正）：
    本服务在 ``__init__`` 捕获 ``_view_decryptor`` 实例引用一次，宿主事后整体
    替换 ``entry_mgr._view_decryptor`` 属性**不会传播**到本服务（test_lenient_verify
    依赖的形态是对共享实例的方法打 spy——monkeypatch 实例属性/方法对宿主与本
    服务同步生效，因两者持有同一实例）。
    """

    def __init__(
        self,
        vault_manager: VaultManager,
        cache: QueryCacheProtocol,
        view_decryptor: EntryViewDecryptor,
    ):
        self._vault = vault_manager
        # 投影行集/摘要缓存（协议视图，ARCH-032 模式）：只读消费 + 会话回写，
        # 失效决策留在 EntryManager/EntryChangeBus。
        self._cache = cache
        # 详情/导出/摘要三视图解密（MAINT-021 下沉的子服务），与宿主共享同一实例。
        self._view_decryptor = view_decryptor

    @property
    def _db(self) -> VaultDataStore:
        """数据访问协议视图，委托 vault（同宿主 ``EntryManager.db`` 的收窄面）。"""
        return self._vault.db

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def get_entry_with_epoch(self, entry_id: int) -> EntryRead:
        """获取并解密单个条目，随行携带解密世代与 TOTP 域版本（:class:`EntryRead`）。

        与 ``get_entry`` 同一读路径（epoch 守卫 + 锁内快照 key/世代 + 锁外解密），
        区别仅在于把锁内快照的 ``data_epoch``（SEC-054 残余窗口闭合）与
        ``data_version``（SEC-063 b 层：TOTP 域失效版本的解密时点快照）一并返回：
        消费方（detail_panel 的 TOTP 预热）需要「entry 敏感字段解密时所处世代/版本」
        ——世代与版本从锁内带出后，「解密后→预热前」窗口内发生恢复轮换（改 epoch）
        或单条 TOTP 失效（pop_totp 不改 epoch、仅推进 TOTP 域版本）时，旧 secret
        分别被 store_totp 的世代/版本守卫拒收；在 show_entry 调用点另行快照会把
        该窗口误判为零间隙。其余不消费世代/版本的调用方继续用 ``get_entry``
        （宿主薄委托，丢弃世代与版本）。

        详情读 LENIENT + 列表标记一致性（QL-077 半应用的补齐）：取行走
        ``get_entries_by_ids``（LENIENT 验签）而非 ``db.get_entry``（STRICT）——
        STRICT 抛出的 :class:`VaultIntegrityError` 直入 Qt 选择槽
        （do_select_entry）被全局异常钩子吞掉，详情面板静默空白、
        detail_panel._render_integrity_warning（为此而建）不可达；LENIENT 失败
        仅标记 ``integrity_error``，decrypt_entry 透传后由详情面板渲染既有完整性
        警示并禁用编辑/共享，与列表路径的标记语义一致（取径先例：
        EntryManager._read_raw_for_delta 的同款论证）。
        """
        try:
            with self._vault.epoch_guarded_read():
                # 取行走 LENIENT 验签（理由见方法 docstring）：篡改行标记
                # integrity_error 随 entry 透传，不抛入 Qt 槽。
                rows = self._db.get_entries_by_ids([entry_id])
                raw = rows[0] if rows else None
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
                key = self._key
                # SEC-043 写入方世代：详情路径同样快照世代传入缓存回写（语义见
                # get_entry_summaries 处注释）——此前仅搜索分支接入，详情的摘要/
                # 分类名缓存回写退回缓存侧采样，跨世代后旧明文可植入新 epoch 缓存。
                data_epoch = self._vault.key_epoch
                # SEC-063 b 层：TOTP 域版本与 raw/key/epoch 同刻快照——store_totp 的
                # 版本守卫据此拒收「解密 → 预热」窗口内被 pop_totp 失效的旧 secret
                # （pop 不改 epoch，SEC-054 的世代守卫对该失效盲）。
                data_version = self._cache.totp_invalidate_version
        except VaultKeyEpochMismatchError:
            return EntryRead(None, None, None)
        if raw is None:
            return EntryRead(None, None, None)
        entry = self._view_decryptor.decrypt_entry(raw, key=key, data_epoch=data_epoch)
        return EntryRead(entry, data_epoch, data_version)

    def get_entry_summaries(
        self,
        deleted_only: bool = False,
        category_id: int | None = None,
        favorite_only: bool = False,
        search: str = "",
        limit: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
        *,
        order_by: str | None = None,
        order_desc: bool = True,
    ) -> list[Entry]:
        """获取不含密码等敏感明文的列表摘要。

        Note:
            ``limit`` 的生效方式（PERF-078 后统一）：
            - 无搜索且排序为 SQL 白名单字段/默认复合序：``limit`` 经
              ``ORDER BY ... LIMIT`` 下推 SQL（PERF-073）。字段序为纯单列序，
              不附加并列裁决键（PERF-090）：该路径无内存对等路径，裁决键只会在
              updated_at 序上破坏 idx_entries_active_updated 的索引下推
              （退化为 TEMP B-TREE filesort）而无等价性收益。
            - 搜索非空或不可 SQL 下推的排序（内存路径）：匹配/收集必须全量（加密字段
              不可先截断后过滤），排序在内存按 meta/窄行键完成后取前 ``limit``——
              仅这前 N 条回查宽行与构建摘要，语义与 SQL「ORDER BY ... LIMIT`` 同构；
              排序可 SQL 下推且 ``limit`` 非 None 时走排序下推分支（PERF-087，投影
              查询带 ORDER BY、匹配循环凑满即止，跳过内存排序）。下推的 SQL 序带
              并列裁决键（排序列 + is_favorite DESC, updated_at DESC），与内存稳定
              排序继承的复合序一致——并列 + limit 截断边界上两路径选出同一集合与
              同一序。
            - ``limit`` 为 None 返回全部（内存全量回查，既有调用方语义不变）；
              ``limit=0`` 两路径一致返回空集（QL-072 统一：此前内存路径的
              ``if limit`` 视 0 为 falsy 跳过截断返回全部，与 SQL 路径 LIMIT 0
              返回空集语义分叉）。

        ``order_by``/``order_desc``（PERF-073/078）：``database.types.ORDER_BY_FIELDS``
        白名单字段 + 无搜索 → SQL 下推；白名单外的排序（如 ``"title"``，密文列不可
        SQL 排序）或搜索非空 → 内存排序（title 键为缓存的 meta.title_lower，其余键
        为窄投影明文列），截断集合=排序序前 N。``None``（默认）走复合序（内存路径
        下即窄投影的 SQL 序，不重排）。

        读路径经 ``epoch_guarded_read`` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        返回空列表，触发 UI 经变更回调刷新。锁定期 :class:`VaultLockedError` 仍正常传播。

        实现（MAINT-092 拆分，对齐 MAINT-021 模式）：本方法保持薄编排——锁内
        （``epoch_guarded_read`` 块）完成行集读取与 key/世代快照、组装
        :class:`_SummaryRead` 载荷，锁外按路径分派到
        :meth:`_summaries_via_search_projection` / :meth:`_summaries_from_raw_rows`
        构建摘要，逐块自原 190 行单体方法搬运，语义零变化。
        """
        # 路径分流（PERF-078；ARCH-051 白名单驱动）：搜索路径与不可 SQL 下推的排序
        # （ORDER_BY_FIELDS 之外的密文字段，如 title）走「窄投影全量 → 内存 meta
        # 排序 → 仅前 limit 回查宽行」；其余（无搜索 + SQL 白名单字段/默认复合序）
        # 维持 PERF-073 的 SQL ``ORDER BY ... LIMIT`` 下推宽行路径。此前硬编码
        # ``order_by == "title"`` 与 ORDER_BY_FIELDS 构成双源——白名单新增字段时
        # 本判定不自动跟随（新增可下推字段会被误判为 SQL 路径之外的第三态）；
        # 改为白名单否定式后，「不可下推」集合自动继承单一事实源。
        in_memory_path = bool(search) or (order_by is not None and order_by not in ORDER_BY_FIELDS)
        sql_pushdown = not in_memory_path
        # 内存路径的排序下推（PERF-087）：order_by 属 SQL 白名单且 limit 非 None 时，
        # 投影查询下推 ORDER BY，行集即目标序——匹配循环按序扫描凑满 limit 即 break，
        # 跳过 O(n log n) 的全量收集+内存排序（50k 库内存排序 ~100ms）。语义同构
        # 论证：「近期更新」等带 limit 的视图用户意图即「最新匹配的前 N」，与
        # 「全量收集 → 内存排序 → 取前 N」选出同一集合与同一序。等价性含并列裁决
        # （PERF-087）：SQL 序带固定 tie-breaker（ORDER BY <列> <方向>, is_favorite
        # DESC, updated_at DESC，见 entry_repository._entry_query_clauses），与内存
        # 稳定排序继承的复合序逐层一致——排序键同值并列时（强度刻度 0-4 并列常见、
        # 批量导入 created_at 同刻），截断边界上的入选集合与「全量收集→稳定排序→
        # 截断」完全相同；不带裁决键的引擎内序会在并列+limit 处选出分叉的集合。
        order_pushdown = (
            in_memory_path
            and limit is not None
            and order_by is not None
            and order_by in ORDER_BY_FIELDS
        )
        # SQL 路径的 limit 直接下推；内存路径的 limit 在排序后截断（匹配必须全量，
        # 截断在排序后语义等价于 SQL「ORDER BY ... LIMIT」的前 N；排序下推分支的
        # 截断由匹配循环的提前终止承担）。
        sql_limit = limit if sql_pushdown else None
        # 列表（无搜索词）传 LENIENT：逐行 HMAC 验签并标记篡改条目（不抛异常），使列表
        # 能检测非加密元数据篡改（is_favorite/category_id/password_strength/deleted_at）。
        # _view_decryptor.decrypt_summary 将 raw.integrity_error 透传到 summary，列表
        # delegate 据此显示完整性警示。
        # 进读块前先固定本批缓存 epoch（PERF-086 前移，原在锁外解密前）：首次调用
        # 的重臂（清空+推进 version）若发生在投影拉取**之后**，会把本次刚回填的投影
        # 行集一并清掉，首次调用自废缓存；前移后拉取的版本快照已含重臂推进，回填
        # 可存活。逐条目不再重复校验（同批 epoch 不可能变化）的既有语义不变。
        self._cache.invalidate_if_epoch_changed()
        try:
            with self._vault.epoch_guarded_read():
                query = EntryQuery(
                    deleted_only=deleted_only,
                    category_id=category_id,
                    favorite_only=favorite_only,
                    limit=sql_limit,
                    # 字段序下推（PERF-073/087）：SQL 路径与内存路径的排序下推分支
                    # 都把白名单字段序传入查询（后者的截断由循环提前终止承担）；
                    # 其余内存路径恒传 None——SQL 层保持复合序作为内存排序的稳定基数
                    # （同键条目的相对序继承复合序，与 SQL 字段序的稳定语义一致）。
                    order_by=order_by if (sql_pushdown or order_pushdown) else None,
                    order_desc=order_desc,
                    # 并列裁决键仅搜索的排序下推分支需要（PERF-090）：该分支依赖
                    # 「行集序 == 内存稳定排序序」的等价性（PERF-087）；SQL 直连
                    # 路径（sql_pushdown，与 order_pushdown 互斥）无内存对等路径，
                    # 追加裁决键只会在 updated_at 序上破坏索引下推、纯付 filesort
                    # 成本。
                    tie_break_order=order_pushdown,
                    verify=VerifyMode.LENIENT,
                )
                if in_memory_path:
                    # 窄投影拉取（PERF-074/078）：宽行（e.* + 24 字段 RawEntry 构造）是
                    # 温态主导成本（50k 库实测 656ms，同条件窄投影仅 102ms）；搜索只需
                    # 4 个摘要密文字段做小写匹配，标题序只需 meta.title_lower + 行明文
                    # 排序键。投影无验签（不含签名载荷列），回查完整行时经
                    # get_entries_by_ids 的 LENIENT 验签补偿；未命中/未截断行不验签的
                    # 取舍与 PERF-019 声明一致（篡改检测由无搜索词的全量列表刷新覆盖）。
                    # 行集经投影缓存复用（PERF-086）：行集仅取决于过滤三元组与排序
                    # 规格、与搜索词无关，暖态重复搜索免重拉。键构造收敛至
                    # projection_cache_key（ARCH-052）单一函数：从本 query 显式提取
                    # 影响行集/行序的维度（未下推排序已在 query 构造点规范化为
                    # order_by=None 的复合序），有序行集与无序行集因消费方对行序敏感
                    # （排序下推分支依赖行序提前终止）不可混存同一键。
                    search_rows = self._cache.search_projection_rows(
                        projection_cache_key(query),
                        lambda: self._db.get_entries_search_projection(query),
                    )
                    raw_entries = []
                else:
                    search_rows = []
                    raw_entries = self._db.get_entries(query)
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
                key = self._key
                # SEC-041/043 写入方世代：与 raw/key 同刻快照 epoch，供摘要/分类名缓存
                # 回写守卫——后台 worker 在恢复提交（invalidate_all → 新读路径重臂新
                # epoch）后未被取消时，其旧 raw+旧密钥的解密结果不得写入新世代缓存
                # （跨世代 grafting 会把恢复前明文持久污染进新缓存）。该快照覆盖本方法
                # 全部分支（含搜索分支的 decrypt_summary meta 路径——分类名解密经
                # data_epoch 守卫，PERF-074 重写时曾掉落、PERF-078 复核补齐）。
                data_epoch = self._vault.key_epoch
            # 解密移出 db_lock（PERF-001）：with 块内仅读 raw（持锁快速），锁外逐条解密，
            # 释放 db_lock 供 TOTP 定时器读与写入。epoch 已在读块前固定（见方法头
            # PERF-086 前移注释），循环内走无校验路径避免每条目重复加锁取 epoch。
            read = _SummaryRead(
                search_rows=search_rows,
                raw_entries=raw_entries,
                key=key,
                data_epoch=data_epoch,
            )
            if in_memory_path:
                summaries = self._summaries_via_search_projection(
                    read,
                    search=search,
                    order_by=order_by,
                    order_desc=order_desc,
                    limit=limit,
                    cancel_check=cancel_check,
                    pre_sorted=order_pushdown,
                )
            else:
                summaries = self._summaries_from_raw_rows(read, cancel_check)
        except VaultKeyEpochMismatchError:
            return []
        # 内存路径的 limit 已在排序后截断（回查与构建仅前 limit 条），无出口二次截断。
        return summaries

    def _summaries_via_search_projection(
        self,
        read: _SummaryRead,
        *,
        search: str,
        order_by: str | None,
        order_desc: bool,
        limit: int | None,
        cancel_check: Callable[[], bool] | None,
        pre_sorted: bool = False,
    ) -> list[Entry]:
        """内存路径（搜索/不可下推排序）的摘要构建（MAINT-092 自 get_entry_summaries 拆出）。

        「窄投影全量 → 匹配 → 内存 meta 排序 → 前 limit 回查宽行 → 构建」逐块
        搬运自原单体方法；各块的 PERF/SEC 决策注释随块迁移。``pre_sorted=True``
        （PERF-087 排序下推分支）时行集已按 SQL 白名单序排好，匹配循环凑满
        ``limit`` 即提前终止，跳过内存排序与截断。
        """
        key = read.key
        data_epoch = read.data_epoch
        selected: list[tuple[SearchRow, SearchMetadata]] = []
        # 批量摘要会话（PERF-086）：一次持锁快照命中集、循环内零锁取 meta、退出
        # 一次回写，替代逐行 cached_search_metadata_full 的 N 次 RLock 往返。
        # data_epoch 语义不变（SEC-041）：会话进入时作为整批回写的世代守卫。
        with self._cache.search_metadata_batch(key=key, data_epoch=data_epoch) as batch:
            for row in read.search_rows:
                if cancel_check and cancel_check():
                    break
                # 提前终止（PERF-087）：行集已按目标序排好（pre_sorted）时，凑满
                # limit 个命中即停——limit=0 时首次循环即跳出（与 SQL 路径 LIMIT 0
                # 返回空集的语义对齐，QL-072）。
                if pre_sorted and limit is not None and len(selected) >= limit:
                    break
                # 一次取完整 SearchMetadata，匹配与排序键共用，省第二次缓存查询
                # （PERF-016）。
                meta = batch.get(row)
                if search:
                    # 匹配检查前移到回查/摘要构建之前（PERF-018）：仅命中条目进入
                    # 排序与回查（meta 已含匹配所需小写形式）。
                    if not matches_search_lower(
                        (
                            meta.title_lower,
                            meta.username_lower,
                            meta.url_lower,
                            meta.tags_lower,
                        ),
                        search,
                    ):
                        continue
                selected.append((row, meta))
        # 内存排序（PERF-078）：title 序的键在 meta.title_lower（缓存已有，
        # UI 的 (e.title or "").lower() 与其同源），其余键来自窄投影的明文列
        # ——排序无需宽行 Entry。原「标题序需重构 UI 排序数据流、暂受 1.76s」
        # 的声明被推翻：排序键全在窄行+meta，5k 库实测标题序全量宽行
        # 165.9ms → meta 排序+前 1000 回查 53.8ms（3.1×，50k 等比外推
        # ~1.7s → ~0.5s）。order_by 为 None（搜索调用方未指定排序）时不重排
        # ——窄投影的 SQL 复合序（is_favorite DESC, updated_at DESC）即默认
        # 视图序，稳定排序继承之。排序下推分支（pre_sorted）行集已按目标序
        # 排好，跳过重排。
        if order_by is not None and not pre_sorted:
            # 键函数单一事实源（MAINT-091，模块归属 MAINT-104 迁 services/entry_sorting）：
            # 窄投影行+meta 经 SortKeySource 适配为 Entry 同名属性形态，经
            # entry_sort_key 取键——此前 4 键逻辑在本方法与 UI 各一份（UI 重排入口
            # 已随 QL-074 删除死代码，本路径为键函数唯一生产消费方；title 键直接取
            # meta.title_lower 已小写，经 entry_sort_key 再 .lower() 幂等，语义等价）。
            key_of = entry_sort_key(order_by)

            def sort_key(item: tuple[SearchRow, SearchMetadata]) -> str | int:
                row_i, meta_i = item
                return key_of(
                    SortKeySource(
                        meta_i.title_lower,
                        row_i.password_strength,
                        row_i.created_at,
                        row_i.updated_at,
                    )
                )

            selected.sort(key=sort_key, reverse=order_desc)
        # 截断在排序后（PERF-078 收口）：匹配/收集必须全量，排序后取前 limit
        # 才与「ORDER BY ... LIMIT」语义同构——原实现收集全部命中后**全量回查**
        # 才在出口截断，宽搜索词（单字符命中 20k）时 836ms 反超旧宽行直拉且
        # 双份驻留；现仅回查/构建前 limit 条（5k 全命中实测 187.7ms →
        # 50.6ms，3.7×）。判定统一为 ``is not None``（QL-072）：limit=0 截断为
        # 空集（此前 ``if limit`` 视 0 为 falsy 跳过截断返回全部，与 SQL 路径
        # LIMIT 0 语义分叉）；pre_sorted 分支的截断已由循环提前终止承担。
        if limit is not None and not pre_sorted:
            selected = selected[:limit]
        # 回查完整行（PERF-074）：LENIENT 验签在 db 层 _row_to_entry 完成
        # （替代原 PERF-067 的就地验签——窄投影后宽行不再物化，回查是摘要
        # 构建的必要步骤而非重复读库），损坏行带 integrity_error 标记不抛
        # 异常。无命中/截断后为空时跳过回查（守护「未命中行不回查」的测试
        # 以哨兵 spy 断言零调用）。
        hit_ids = [row.id for row, _meta in selected if row.id is not None]
        full_by_id: dict[int | None, RawEntry] = {}
        if hit_ids:
            for hit_raw in self._db.get_entries_by_ids(hit_ids):
                full_by_id[hit_raw.id] = hit_raw
        summaries = []
        for row, meta in selected:
            # 回查段同样可取消（PERF-078）：原第二段（回查+构建）无探针，宽
            # 搜索词取消后 worker 空转数秒——与第一段 break 语义一致，返回
            # 已构建部分。
            if cancel_check and cancel_check():
                break
            full = full_by_id.get(row.id) if row.id is not None else None
            # 回查缺失（窄投影后行被并发删除）：跳过而非中断——尽力视图，
            # 与列表路径对并发删除的容忍语义一致。
            if full is None:
                continue
            summaries.append(
                self._view_decryptor.decrypt_summary(
                    full,
                    skip_epoch_check=True,
                    key=key,
                    meta=meta,
                    # data_epoch 透传（PERF-078 修复 PERF-074 的回归）：meta 路径
                    # 的 title 等四字段取自 meta 无回写，但分类名解密回写需要
                    # 世代守卫——漏传使搜索 worker 在飞+恢复重臂新世代时旧
                    # 分类名植入新缓存（SEC-043 的搜索分支漏点）。
                    data_epoch=data_epoch,
                )
            )
        return summaries

    def _summaries_from_raw_rows(
        self,
        read: _SummaryRead,
        cancel_check: Callable[[], bool] | None,
    ) -> list[Entry]:
        """SQL 下推路径（无搜索+白名单字段序）的摘要构建（MAINT-092 自 get_entry_summaries 拆出）。"""
        summaries = []
        for raw in read.raw_entries:
            if cancel_check and cancel_check():
                break
            # 非搜索分支同样透传锁内快照世代（SEC-043）：此前 meta=None 走
            # 缓存侧采样，跨世代后旧明文可植入新 epoch 缓存（与搜索分支
            # 的差异是 SEC-041 的遗留漏点，本处补齐）。
            summaries.append(
                self._view_decryptor.decrypt_summary(
                    raw,
                    skip_epoch_check=True,
                    key=read.key,
                    data_epoch=read.data_epoch,
                )
            )
        return summaries

    def get_recent_summaries(self, limit: int = DEFAULT_RECENT_SUMMARIES_LIMIT) -> list[Entry]:
        """获取最近更新的条目摘要，供「近期更新」视图。

        相较 ``get_entry_summaries``（按 is_favorite DESC, updated_at DESC 排序），
        本方法仅按 updated_at DESC 排序并下推 LIMIT 到 SQL，避免拉全量内存排序
        再截断，消除大库下「近期更新」切换的全量解密与内存驻留开销。

        Args:
            limit: 返回条目数上限。

        读路径经 ``epoch_guarded_read`` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        返回空列表，触发 UI 经变更回调刷新。
        """
        if limit <= 0:
            return []
        # 进读块前先固定本批缓存 epoch（ARCH-056 对齐 get_entry_summaries 的位置
        # 模式，原在锁外解密前）：本路径虽不消费投影行集缓存，但摘要构建的
        # decrypt_summary 回写（分类名缓存等）与其它读路径共用同一 epoch 臂，
        # 「读块后 invalidate」的模式分裂会误导后来者在新读路径复制旧位置——
        # 前移统一后，任何读路径首次调用的重臂（清空+推进 version）都发生在其
        # 拉取/解密之前，不废自己刚回填的缓存（PERF-086 的前移论证同源）。
        self._cache.invalidate_if_epoch_changed()
        try:
            with self._vault.epoch_guarded_read():
                raw_entries = self._db.get_entries(
                    # 字段序下推（PERF-073）：updated_at DESC 明文表达，替代原
                    # sort_by_updated 布尔单字段特例。纯单列序不附加并列裁决键
                    # （PERF-090）：本路径无内存对等路径，裁决键只会把
                    # idx_entries_active_updated 的索引序下推退化为 filesort。
                    EntryQuery(
                        order_by="updated_at",
                        limit=limit,
                        verify=VerifyMode.LENIENT,
                    ),
                )
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
                key = self._key
                # SEC-043 写入方世代：近期更新视图同样快照世代传入缓存回写（语义见
                # get_entry_summaries 处注释），补齐 SEC-041 仅接搜索分支的遗留漏点。
                data_epoch = self._vault.key_epoch
            # 解密移出 db_lock（PERF-001），与 get_entry_summaries 一致；用锁内快照 key
            # 解密。epoch 已在读块前固定（见上方 ARCH-056 注释），此处不再重复校验。
            return [
                self._view_decryptor.decrypt_summary(
                    entry,
                    skip_epoch_check=True,
                    key=key,
                    data_epoch=data_epoch,
                )
                for entry in raw_entries
            ]
        except VaultKeyEpochMismatchError:
            return []

    def get_entry_dedup_index(self) -> list[tuple[str, str, int]]:
        """导入去重对照所需的 ``(title, username, id)`` 明文索引（PERF-075）。

        去重只需 ``(title, username)`` casefold 对照与覆盖目标的 id，原路径经
        ``get_entry_summaries()`` 拉全量摘要——多解密 url/tags 之外的完整 summary
        构建（50k 冷缓存实测 1834ms，导入 worker 后台）。现改搜索同款窄投影 +
        摘要缓存解密：四摘要字段一次解密入会话缓存（去重只消费 title/username，
        但导入后紧随的列表/搜索刷新命中同一缓存，摊销后整体更优），不物化宽行
        与 summary Entry。title 解密失败的条目摘要为空串，被调用方的
        ``if entry.title`` 前置过滤天然排除（与原摘要路径语义一致）。

        行集拉取接投影行集缓存（ARCH-055）：键为「未删除全量 + 复合序」
        （``(False, None, False, None, True)``，经 :func:`projection_cache_key`
        构造），与「未指定排序 / 排序不可 SQL 下推（如 title 序）」的搜索路径
        同键复用（两者 order_by 均规范化为 None 的复合序键）——原直连
        ``get_entries_search_projection`` 与 PERF-086 缓存路径并行，50k ~160ms
        全量拉取每次重复支付。互摊的如实边界：带 SQL 白名单排序下推的搜索
        （如 ``order_by="updated_at"`` + limit）键含排序段、与本键不同，互不
        摊销；且互摊以导入提交为终点——提交经 notify 推进主域失效版本，全部
        投影键一并失效，导入去重与前后脚的刷新各重拉一次（行集确已变化，
        失效是正确性要求而非损耗）。

        去重对照取「未删除」条目（与原实现一致）：回收站条目不参与覆盖判定，
        导入同名条目仍走新增而非覆盖已删条目。invalidate_if_epoch_changed
        前移至读块前（对齐 get_entry_summaries 的 PERF-086 前移论证：首次调用
        的 epoch 重臂若发生在投影拉取之后，会把本次刚回填的投影行集一并清掉）。

        读路径经 ``epoch_guarded_read`` 守卫，语义与 ``get_entry_summaries``
        一致（改密窗口内 epoch 不一致时返回空列表）。
        """
        # 进读块前先固定本批缓存 epoch（PERF-086 前移，语义见 docstring）。
        self._cache.invalidate_if_epoch_changed()
        try:
            with self._vault.epoch_guarded_read():
                query = EntryQuery(include_deleted=False)
                rows = self._cache.search_projection_rows(
                    projection_cache_key(query),
                    lambda: self._db.get_entries_search_projection(query),
                )
                key = self._key
                data_epoch = self._vault.key_epoch
            result: list[tuple[str, str, int]] = []
            # 批量摘要会话（PERF-094）：对齐搜索路径（_summaries_via_search_
            # projection）的同款调用形态——原逐行 cached_search_metadata_full
            # 每行 2 次 RLock 往返（命中读 + move_to_end），50k 逐行实测 ~78ms；
            # 会话把锁开销摊销为进出各一次持锁（快照命中集 + 整批守卫回写）。
            with self._cache.search_metadata_batch(key=key, data_epoch=data_epoch) as batch:
                for row in rows:
                    if row.id is None:
                        continue
                    meta = batch.get(row)
                    result.append((meta.title, meta.username, row.id))
            return result
        except VaultKeyEpochMismatchError:
            return []

    def get_entries_for_export(
        self,
        include_secrets: bool = False,
        cancel_check: Callable[[], bool] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> list[Entry]:
        """获取用于导出的全部条目（不含回收站），默认不解密密码/TOTP。

        走 ``decrypt_entry_for_export`` 的 export 模式：任何字段完整性/解密
        失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据；测试断言用的一次性
        全量解密助手见 tests/helpers.decrypt_all_entries，生产 API 面不保留该入口，
        MAINT-098）。``include_secrets=False`` 时跳过 password/totp_secret 解密。

        Args:
            include_secrets: 是否解密 password 与 totp_secret 入结果。
            cancel_check: 可选取消探针，返回真值时中止遍历。
            progress: 可选 ``(done, total)`` 进度回调（PERF-070）：按已解密条目数
                上报，每 ``PROGRESS_REPORT_EVERY`` 条节流、终值恒上报——50k 库解密
                实测 5.1s，此前导出全程不确定旋转。百分比映射由 UI 调用方完成。

        读路径经 ``epoch_guarded_read`` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        抛 :class:`VaultKeyEpochMismatchError` 让导出 worker 据此报错（导出为用户主动
        操作，空结果会误导用户认为成功导出 0 条，故向上传播而非返回空）。
        """
        with self._vault.epoch_guarded_read():
            raw_entries = self._db.get_entries(EntryQuery(include_deleted=False))
            # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
            key = self._key
            # 锁内快照世代（SEC-049）：分类名缓存回写守卫据此拒收「导出 worker 在飞 +
            # 恢复提交重臂新世代」交错下的跨世代解密结果（与 get_entry/摘要路径对齐）。
            data_epoch = self._vault.key_epoch
        # 解密移出 db_lock（PERF-001）；epoch 不一致已在 with 块内抛 VaultKeyEpochMismatchError
        # 向上传播（导出为用户主动操作，空结果会误导用户）。用锁内快照 key 解密。
        entries = []
        total = len(raw_entries)
        done = 0
        for raw_entry in raw_entries:
            if cancel_check and cancel_check():
                break
            entries.append(
                self._view_decryptor.decrypt_entry_for_export(
                    raw_entry, include_secrets, key=key, data_epoch=data_epoch
                )
            )
            done += 1
            if progress is not None and should_report_progress(done, total):
                progress(done, total)
        if progress is not None and total == 0:
            progress(0, 0)  # 空库也上报终值（UI 侧映射为 100，进度不留悬挂）
        return entries
