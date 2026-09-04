"""密码安全分析器：提供弱密码、重复密码、过期密码三项分析，结果经 TTL 缓存复用。

缓存分层（基础分析不依赖 days，days 变化仅重过滤过期条目）、失效策略与线程安全
细节见 :class:`SecurityAnalyzer`。
"""

import dataclasses
import hmac
import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, NamedTuple, Protocol, TypedDict, TypeGuard, cast

if TYPE_CHECKING:
    # vault 维持 TYPE_CHECKING 具体类（ARCH-039 显式决策）：本类对 VaultManager 的
    # 依赖面（key_epoch 读取×4 / epoch_guarded_read / db / vault_write_lock /
    # is_cancel_requested）与其核心职责近乎同构，协议化只会产出「影子类」——把
    # VaultManager 的核心 API 抄一遍再让唯一实现满足，无测试替身或第二实现的
    # 净收益。cache 依赖面窄（4 成员），按 TotpCacheProtocol 先例协议化（见
    # AnalysisCacheProtocol）。
    from ..managers.vault_manager import VaultManager

from ...config import OLD_PASSWORD_WARNING_DAYS_DEFAULT
from ...database.types import VerifyMode
from ...exceptions import (
    DecryptionError,
    EntryIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)
from ...models import Entry, RawEntry
from .crypto_utils import decrypt_field, require_vault_key
from .entry_view_decryption import build_entry_summary

logger = logging.getLogger(__name__)

# 全量分析取消探测掩码：每 64 条检查一次取消请求，降低热循环开销。安全分析扫描
# 频率高于改密，故取消探测比改密路径（每条检查）更稀疏。
_CANCEL_CHECK_MASK = 0x3F

# 分析缓存存活时间（秒）。命中期内复用基础分析与指纹结果，避免重复 O(n) 解密与
# HMAC。条目增删/改密立即失效缓存，此 TTL 仅控制时间维度淘汰。作为业务层时序参数
# 的命名事实源（未集中到 UI 层以免业务层反向依赖 UI）。
SECURITY_ANALYSIS_CACHE_TTL_SECONDS = 120

# 安全健康评分惩罚系数（业务规则，集中于此供非 UI 场景复用）。
HEALTH_PENALTY_WEAK = 15
HEALTH_PENALTY_DUPLICATE = 10
HEALTH_PENALTY_OLD = 5

# 过期检测默认天数（ARCH-034）：直接引用 config.OLD_PASSWORD_WARNING_DAYS_DEFAULT，
# 与设置页可配置项的默认值同源——原「业务层不反向依赖 config 故本地同值声明」的
# 解耦理由已失效（business→config 合法且有 composition/database_bootstrap/rate_limiter
# 等先例），双源同值一旦漂移会使分析口径与设置页展示默认不一致。供全部分析入口的
# days 默认值引用，消除 90 字面量散落。
DEFAULT_ANALYSIS_DAYS = OLD_PASSWORD_WARNING_DAYS_DEFAULT


class AnalysisCacheProtocol(Protocol):
    """安全分析所需的最小摘要缓存协议，解耦 SecurityAnalyzer 与 EntryCacheManager。

    对齐 :class:`TotpCacheProtocol` 模式（ARCH-039）：``EntryCacheManager`` 自然满足
    此协议，构造时注入。协议面以本类实际消费为准（4 成员），services 子包运行时
    不 import managers，守住分层方向；测试替身按协议构造即可（MagicMock 天然满足
    结构协议）。摘要取值经单条入口 ``cached_search_metadata``（MAINT-119 收敛后
    唯一的公开单条入口）。
    """

    def invalidate_if_epoch_changed(self) -> None:
        """key_epoch 变化时清空摘要缓存；分析循环外调用以守卫过期数据。"""
        ...

    def cached_search_metadata(
        self,
        raw_entry: RawEntry,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> tuple[str, str, str, str]:
        """解密并缓存 title/username/url/tags 明文原形（单条路径，含 epoch 校验）。"""
        ...

    def get_failed_fields(self, crypto_id: str) -> set[str]:
        """取某条目摘要解密失败的字段集（返回拷贝，QL-056）。"""
        ...

    def decrypt_category_name(
        self,
        category_id: int | None,
        value: str,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> str:
        """解密分类名并缓存（解密失败抛 DecryptionError，由调用方定容错语义）。"""
        ...


class _SecurityReportCounts(TypedDict):
    """安全分析报告的聚合计数（内部形态与出口形态共有的 required 键）。"""

    total: int
    weak_count: int
    duplicate_count: int
    old: int


class _SecurityReportInternal(_SecurityReportCounts, total=False):
    """安全分析报告的内部形态：缓存本体（``_analysis_cache``）与
    :meth:`SecurityAnalyzer.full_analysis` 生产结果的类型契约。

    七个下划线内部键为缓存分层私有（total=False 可选）：

    - ``_summaries_with_dates``（dict[crypto_id → (Entry, changed_utc)]，PERF-085
      dict 化）：供 days 重过滤与增量差分 O(1) 定位；dict 保插入序，days 重过滤的
      输出序与列表时代一致。
    - ``_fingerprint_map``：含单例桶的完整指纹分桶（PERF-021 增量失效据此移动
      单条条目桶位——duplicate_groups 仅含 >1 的桶，不足以支撑增量更新）。
    - ``_crypto_id_to_fp``（PERF-085 值可 None）：crypto_id→指纹反向索引，值 None
      是「条目无指纹」的**常态哨兵**（无密码/密码解密失败，note/identity 等），
      命中哨兵即知无旧指纹桶可移除；**键缺失**才是异常缓存形态（索引与桶撕裂），
      差分回退逐桶扫描兜底。
    - ``_weak_map`` / ``_old_map`` / ``_duplicate_groups_map``（PERF-085）：weak/
      old/重复分组的 dict 形态**唯一事实源**——出口公开列表键
      （weak_entries/old_entries/duplicate_groups）经 :meth:`_export_report` 从
      它们派生，缓存本体不再持有同名公开列表键（PERF-085 收口：双表示中列表键
      自首次增量差分起即陈旧，无内部读方，纯维护陷阱）。
    - ``_key_epoch``：epoch 失效判定（仅缓存层填充）。
    """

    _summaries_with_dates: dict[str, tuple[Entry, datetime | None]]
    _fingerprint_map: dict[bytes, list[Entry]]
    _crypto_id_to_fp: dict[str, bytes | None]
    _weak_map: dict[str, Entry]
    _old_map: dict[str, Entry]
    _duplicate_groups_map: dict[bytes, list[Entry]]
    _key_epoch: str | None


class SecurityReport(_SecurityReportCounts):
    """安全分析报告的出口形态（PERF-062 契约）：计数 + 公开列表键。

    ``get_cached_report`` / ``get_or_compute_report`` 的返回值为此形态——公开
    列表键从内部 map 派生（PERF-085），**不含**任何下划线内部键（无外部消费方，
    携带是纯开销）；列表容器经 :meth:`_export_report` 拷贝隔离（防调用方就地变异
    污染增量更新基准）。
    """

    weak_entries: list[Entry]
    duplicate_groups: list[list[Entry]]
    old_entries: list[Entry]


class SecurityCounts(NamedTuple):
    """安全分析的计数视图（total/weak/duplicate/old），供仅读计数的消费者。

    不含 Entry 列表，获取时无需 :meth:`_refilter_cache` 深拷贝（PERF-014）。
    """

    total: int
    weak_count: int
    duplicate_count: int
    old: int


class _ClassifyResult(NamedTuple):
    """单条条目安全分类结果（full_analysis 循环体抽取）。

    summary 为 None 表示完全跳过（损坏，仅计 skipped_count）；fingerprint 为 None
    表示无密码或解密失败（不计入重复检测，但 summary 仍计入 summaries/weak）。
    """

    summary: Entry | None
    changed_utc: datetime | None
    is_weak: bool
    fingerprint: bytes | None
    counted_in_skipped: bool


class SecurityAnalyzer:
    """密码安全分析器，提供三项分析维度：弱密码（强度≤1）、重复密码（HMAC 指纹分组）、
    过期密码（password_changed_at 等时间字段超期）。

    缓存分层：基础分析覆盖弱密码与重复密码（不依赖 days）；days 变化时仅重过滤过期
    条目，避免重复解密全部密码。命中仅校验 key_epoch 与 TTL；条目增删由
    EntryManager 主动 invalidate_caches 失效，TTL 兜底。
    """

    def __init__(
        self,
        vault_manager: "VaultManager",
        entry_cache: AnalysisCacheProtocol,
        cache_ttl_seconds: int = SECURITY_ANALYSIS_CACHE_TTL_SECONDS,
    ):
        self._vault = vault_manager
        # 摘要缓存经最小协议注入（ARCH-039）：EntryCacheManager 自然满足
        # AnalysisCacheProtocol，经单一解密源获取摘要，避免独立解密产生重复明文
        # 副本，收缩驻留面。
        self._cache = entry_cache
        self._cache_ttl_seconds = cache_ttl_seconds
        self._analysis_cache: _SecurityReportInternal | None = None
        self._analysis_cache_time: float = 0
        self._analysis_cache_days: int = 0
        # 失效世代计数（PERF-080 补全）：invalidate_caches 的全量失效路径在清缓存
        # 同时递增；full_analysis 在飞期间发生过失效即世代不一致，其结果拒绝写回
        # 缓存（详见 _cached_analysis 写回守卫）。持 _cache_lock 读写。
        self._invalidated_generation = 0
        self._cache_lock = threading.Lock()

    @staticmethod
    def compute_health_score(weak_count: int, dup_count: int, old_count: int, total: int) -> int:
        """按各类风险占比与对应惩罚系数计算 0 至 100 的安全健康评分。"""
        if total == 0:
            return 100
        weak_ratio = min(weak_count / total, 1.0)
        dup_ratio = min(dup_count / total, 1.0)
        old_ratio = min(old_count / total, 1.0)
        return max(
            0,
            int(
                100
                - (
                    weak_ratio * 100 * HEALTH_PENALTY_WEAK
                    + dup_ratio * 100 * HEALTH_PENALTY_DUPLICATE
                    + old_ratio * 100 * HEALTH_PENALTY_OLD
                )
            ),
        )

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def _make_summary(self, raw: RawEntry, *, data_epoch: str | None = None) -> Entry:
        """只返回分析界面所需字段，避免缓存敏感明文。

        摘要字段与分类名复用 EntryCacheManager 的缓存解密，避免独立解密产生重复
        明文副本。检测到损坏字段即抛 EntryIntegrityError，供 full_analysis 计入
        skipped_count。刻意用 EntryIntegrityError（非 ValueError 子类）：使「损坏即
        跳过」不依赖「缓存层吸收 DecryptionError」隐性契约，即便未来透传
        DecryptionError（IS-A ValueError）也不被跳过分支误吞。

        ``data_epoch``（SEC-043 写入方世代）：调用方与 raw/密钥同刻快照的世代，
        透传摘要/分类名缓存作回写守卫——分析 worker 在恢复重臂新世代后回写时，
        守卫拒收跨世代解密结果（语义见 EntryCacheManager._cached_search_metadata_no_check）。
        """
        # 摘要取值经单条入口（MAINT-119 收敛）：自带 epoch 校验，full_analysis 持
        # vault_write_lock 期间 epoch 不变，无额外加锁开销。
        title, username, url, tags = self._cache.cached_search_metadata(raw, data_epoch=data_epoch)
        if self._cache.get_failed_fields(raw.crypto_id):
            raise EntryIntegrityError(f"条目 {raw.crypto_id} 摘要字段解密失败")
        summary = build_entry_summary(raw, username)
        summary = dataclasses.replace(summary, title=title, url=url, tags=tags)
        if raw.category_id is not None and raw.category_name:
            # 分类名损坏转 EntryIntegrityError，使 _make_summary 只抛这一种类型，
            # 跳过分支据此 skip 而非终止整次分析。
            try:
                category_name = self._cache.decrypt_category_name(
                    raw.category_id,
                    raw.category_name,
                    data_epoch=data_epoch,
                )
            except DecryptionError:
                raise EntryIntegrityError(f"条目 {raw.crypto_id} 分类名解密失败") from None
            summary = dataclasses.replace(summary, category_name=category_name)
        return summary

    def _password_fingerprint(self, password: str, key: bytes | None = None) -> bytes:
        """使用主密钥生成密码指纹用于去重检测。

        权衡：主密码变更后指纹失效，但缓存 TTL 内自然淘汰；优点是无需额外存储 HMAC
        密钥，指纹不出本进程。传入 ``key`` 复用调用方密钥副本，避免批量分析中每条
        经 ``self._key`` 触发密钥复制，缩小驻留面。
        """
        return hmac.digest(
            key if key is not None else self._key, password.encode("utf-8"), "sha256"
        )

    def _refilter_cache(
        self, cache: _SecurityReportInternal, days: int, *, now: datetime | None = None
    ) -> SecurityReport:
        """从缓存按 days 重新过滤过期条目，返回剥离内部键的出口副本（PERF-062）。

        须持 _cache_lock 调用。顺序：先 ``dict()`` 浅拷贝并在副本上完成 days 重过滤
        与 QL-001 实例回写（依赖内部键 ``_summaries_with_dates``，须在剥离前），再
        经 :meth:`_export_report` 从内部 map 派生公开列表键并剥离全部下划线内部键
        ——``_fingerprint_map``/``_summaries_with_dates`` 仅缓存分层内部消费（增量
        失效/days 重过滤），无任何外部读方，此前出口深拷贝在 50k 库温态
        get_cached_report 实测占 2/3 耗时，是纯浪费。内部缓存本体
        （``_analysis_cache``）仍持全键。
        """
        # dict(TypedDict) 退化为 dict[str, object]，cast 标注此复制边界。
        result = cast("_SecurityReportInternal", dict(cache))
        if days != self._analysis_cache_days:
            cutoff = (now if now is not None else datetime.now(UTC)) - timedelta(days=days)
            # days 重过滤从 _summaries_with_dates（dict 形态）派生新的 _old_map，
            # 计数统一经 _recompute_aggregates 重算（MAINT-101 单一事实源）。
            new_old_map = {
                cid: s
                for cid, (s, dt) in cache.get("_summaries_with_dates", {}).items()
                if dt is not None and dt < cutoff
            }
            result["_old_map"] = new_old_map
            self._recompute_aggregates(result)
            # 同步回写实例缓存（QL-001）：_analysis_cache_days 与实例的 old 计数必须
            # 一致，否则 get_cached_counts 快路径（days == _analysis_cache_days）会读
            # 实例中旧 days 的 old 计数（多报过期）。此前仅改副本致实例与 days 脱钩。
            if self._analysis_cache is not None:
                self._analysis_cache["_old_map"] = dict(new_old_map)
                self._recompute_aggregates(self._analysis_cache)
            # 更新 days 使后续相同 days 命中跳过重复 O(n) 过滤。
            self._analysis_cache_days = days
        return self._export_report(result)

    @staticmethod
    def _export_report(report: _SecurityReportInternal) -> SecurityReport:
        """内部形态转出口副本（PERF-062 契约 + PERF-085 派生）。

        供 :meth:`_refilter_cache` 尾段与失效世代守卫的拒收路径
        （:meth:`_cached_analysis`）共用：后者返回的报告不入缓存，仍须遵守出口
        契约——不含内部键（无外部消费方）、列表容器隔离（防调用方就地变异）。

        公开列表键从内部 map 派生（PERF-085）：weak_entries/old_entries/
        duplicate_groups 分别取自 ``_weak_map``/``_old_map``/
        ``_duplicate_groups_map`` 的 values——map 是唯一事实源（缓存本体不持同名
        公开列表键，收口双表示）；map 缺失的退化形态（手工构造的报告 dict）以空
        map 兜底派生空列表。list(map.values()) 浅拷贝容器、共享 Entry 引用
        （Entry 为 frozen 且无可变容器，无变异面）；duplicate_groups 内层 list
        复制，防消费方经出口引用就地变异桶成员污染增量更新基准。
        """
        # dict(TypedDict) 退化为 dict[str, object]：剥离在通用 dict 副本上完成
        # （出口 TypedDict 已不含内部键，逐键 pop 于类型不通），cast 标注此边界。
        internal = dict(report)
        # 剥离内部键（PERF-062）：出口不含任何下划线键，缓存本体不受影响（副本与
        # 内部 dict 为不同容器）。
        for key in (
            "_summaries_with_dates",
            "_fingerprint_map",
            "_crypto_id_to_fp",
            "_weak_map",
            "_old_map",
            "_duplicate_groups_map",
            "_key_epoch",
        ):
            internal.pop(key, None)
        result = cast("SecurityReport", internal)
        result["weak_entries"] = list(report.get("_weak_map", {}).values())
        result["old_entries"] = list(report.get("_old_map", {}).values())
        result["duplicate_groups"] = [
            list(group) for group in report.get("_duplicate_groups_map", {}).values()
        ]
        return result

    def _cached_analysis(
        self,
        days: int = DEFAULT_ANALYSIS_DAYS,
        *,
        cancel_check: Callable[[], bool] | None = None,
        now: datetime | None = None,
    ) -> SecurityReport:
        """带缓存的安全分析，基础分析不依赖 days。

        命中仅校验 key_epoch 与 TTL；条目增删改由 EntryManager 主动 invalidate_caches
        失效，TTL 兜底。key_epoch 校验保证改密后缓存失效（密码指纹依赖旧主密钥）。
        full_analysis 在飞期间的全量失效经失效世代守卫拒收其写回（PERF-080 补全），
        防过期报告以 fresh TTL 污染缓存。days 变化仅从 ``_summaries_with_dates``
        重过滤过期条目，避免重新解密全部密码（重复检测的 HMAC 是性能瓶颈）。
        """
        with self._cache_lock:
            current_epoch = self._vault.key_epoch
            # 失效世代快照（PERF-080 补全）：full_analysis 读库期间若有全量失效到达，
            # 本次结果基于失效前数据，写回前据此拒收（见下方写回守卫）。
            generation = self._invalidated_generation
            cached = self._analysis_cache
            if (
                cached is not None
                and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
                and cached.get("_key_epoch") == current_epoch
            ):
                return self._refilter_cache(cached, days, now=now)
        try:
            result = self.full_analysis(days, cancel_check=cancel_check, now=now)
        except VaultLockedError:
            # 分析期间保险库被锁定（并发改密/自动锁），密钥不可用无法完成解密。
            # 返回空报告且不缓存，避免后台线程崩溃；下次解锁后重新计算填充。
            logger.debug("安全分析期间保险库被锁定，返回空报告")
            # 出口契约（PERF-062）：空报告同样只含公开字段，不含内部键。
            return {
                "total": 0,
                "weak_count": 0,
                "weak_entries": [],
                "duplicate_groups": [],
                "duplicate_count": 0,
                "old_entries": [],
                "old": 0,
            }
        with self._cache_lock:
            # 双重检查锁：full_analysis 在锁外执行，期间可能已被并发线程填充；
            # 持锁后重新校验，若仍有效直接复用以避免覆盖冗余写入。缓存非 None
            # 且 TTL 内意味着其写入晚于最后一次全量失效（失效路径会清缓存），
            # 复用安全。
            cached = self._analysis_cache
            if (
                cached is not None
                and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
                and cached.get("_key_epoch") == current_epoch
            ):
                return self._refilter_cache(cached, days, now=now)
            # 写回守卫（PERF-080 补全）：读库后有全量失效到达（典型：worker 读库后
            # 用户删条目，增量 notify 发现缓存为 None 直接 no-op 仅 bump 世代）——
            # 本次结果已过期，写回会以 fresh TTL 污染缓存，使 _on_finished 消费脏
            # 标记的重启轮 fast path 命中过期报告（原缺陷：计数陈旧需等 TTL 自愈）。
            # 报告照常返回供本次渲染，缓存不写，重启轮走新全量。比对与 bump 在
            # 同一 _cache_lock 临界区内，无检查-写回竞态。
            if generation != self._invalidated_generation:
                return self._export_report(result)
            result["_key_epoch"] = current_epoch
            self._analysis_cache = result
            self._analysis_cache_time = time.monotonic()
            self._analysis_cache_days = days
            # 出口复制：与 hit 路径一致，防调用方修改污染缓存。
            return self._refilter_cache(result, days, now=now)

    def get_cached_report(
        self, days: int = DEFAULT_ANALYSIS_DAYS, *, now: datetime | None = None
    ) -> SecurityReport | None:
        """返回仍有效的缓存报告，无缓存或已过期返回 None。days 变化仅重过滤过期条目。

        除 TTL 外校验 key_epoch（SEC-002）：改密轮换密钥后，旧 epoch 派生的报告即便在
        invalidate_caches 未及时触发的并发窗口内也不复用，避免锁定/改密后旧明文摘要驻留。
        """
        with self._cache_lock:
            cached = self._analysis_cache
            if self._cache_valid_locked(cached):
                return self._refilter_cache(cached, days, now=now)
        return None

    def get_cached_counts(
        self, days: int = DEFAULT_ANALYSIS_DAYS, *, now: datetime | None = None
    ) -> SecurityCounts | None:
        """返回缓存计数（total/weak/duplicate/old），无缓存或过期返回 None。

        仅读计数消费者（状态栏刷新、空态「分析中」判定）用此轻量入口，跳过
        get_cached_report 的 Entry 深拷贝（PERF-014）。old 依赖 days：days 不同时
        按 days 计次（O(n) 日期比较，无深拷贝），其余直接读缓存。

        除 TTL 外校验 key_epoch（SEC-002），与 get_cached_report 一致。
        """
        with self._cache_lock:
            cached = self._analysis_cache
            if not self._cache_valid_locked(cached):
                return None
            if days == self._analysis_cache_days:
                old = cached.get("old", 0)
            else:
                cutoff = (now if now is not None else datetime.now(UTC)) - timedelta(days=days)
                # _summaries_with_dates 为 dict 形态（PERF-085），按 values 迭代。
                old = sum(
                    1
                    for _s, dt in cached.get("_summaries_with_dates", {}).values()
                    if dt is not None and dt < cutoff
                )
            return SecurityCounts(
                cached.get("total", 0),
                cached.get("weak_count", 0),
                cached.get("duplicate_count", 0),
                old,
            )

    def get_or_compute_report(
        self,
        days: int = DEFAULT_ANALYSIS_DAYS,
        *,
        cancel_check: Callable[[], bool] | None = None,
        now: datetime | None = None,
    ) -> SecurityReport:
        """返回缓存报告，若无效则重新计算并缓存。"""
        return self._cached_analysis(days, cancel_check=cancel_check, now=now)

    def _cache_valid_locked(
        self,
        cached: _SecurityReportInternal | None,
        *,
        expected_epoch: str | None = None,
    ) -> TypeGuard[_SecurityReportInternal]:
        """缓存有效性判定（TTL + key_epoch，SEC-002），须持 ``_cache_lock`` 调用。

        TypeGuard：返回 True 时调用方分支内 ``cached`` 收窄为非 None，免去逐调用点
        重复窄化样板。epoch 失配即失效：密码指纹依赖旧主密钥，跨 epoch 的指纹/明文
        不可比。

        ``expected_epoch``：提供时取代实时 ``self._vault.key_epoch`` 参与比较，供
        :meth:`_try_incremental_update` 二次校验比对首次校验快照的 epoch（SEC-040，
        防跨 epoch grafting，见该方法注释）。
        """
        epoch = self._vault.key_epoch if expected_epoch is None else expected_epoch
        return (
            cached is not None
            and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
            and cached.get("_key_epoch") == epoch
        )

    def invalidate_caches(
        self,
        password_changed: bool = True,
        metadata_changed: bool = True,
        crypto_id: str | None = None,
        *,
        now: datetime | None = None,
    ) -> None:
        """清除分析缓存，下次访问时重新计算。

        命名（MAINT-121）：复数形态 ``invalidate_caches`` 与
        ``EntryManager.invalidate_caches`` / ``CategoryManager.invalidate_caches``
        对齐——本类同样持多套缓存态。

        仅当安全相关维度变更时失效，避免纯旁路变更（如 ``is_favorite`` 切换、分类
        调整）触发整库重解密：

        - ``password_changed``：密码变更 → 弱密码/重复/过期判定均可能变。
        - ``metadata_changed``：title/username 等报告展示元数据变更 → 缓存的
          weak_entries/duplicate_groups 元数据陈旧。
        - ``crypto_id``：变更涉及的单条条目（PERF-021）。提供且缓存仍有效时走
          **单条增量更新**——仅重读/重分类该条并重算聚合计数（指纹桶、重复分组、
          弱/过期名单），其余 N-1 条的密码解密与 HMAC 指纹结果原样复用。纯元数据
          编辑与改单条密码共用此路径：重分类一条是常数开销，报告内嵌的展示元数据
          （标题等）亦随之刷新，无需按 password_changed 分支。**增删路径同走此通道**
          （PERF-079）：新增/恢复携带 crypto_id 重读插入并按缓存成员资格上调 total，
          删除/物理删除重读见 ``is_deleted``/行缺失时构造「仅移除」差分——替代原
          crypto_id=None 的整库失效（增删一次即触发状态栏 worker 的 O(n) 全量重算）。
          任何读取失败（锁定/改密窗口）回退全量失效，语义保守。

        两者皆 False 时直接返回（PERF：旁路变更不影响任何安全分析输入）。回调签名
        经 :meth:`EntryChangeBus.notify` 以位置参数 ``(password_changed,
        metadata_changed, crypto_id)`` 传入；锁定/epoch 轮换通道零参调用经默认
        True 保持全量失效不变。

        全量失效路径同时递增失效世代（PERF-080 补全）：在飞 full_analysis 的
        写回守卫据此拒收过期结果——典型场景是缓存尚为 None 时增删到达（增量
        no-op、清 None 亦 no-op），仅世代递增承载「失效已发生」的事实。

        ``now`` 供测试注入时钟（QL-057）：增量路径的过期重过滤与 full_analysis/
        _refilter_cache 的注入时钟对齐，否则注入时钟的测试中增量与全量行为分叉。
        """
        if not (password_changed or metadata_changed):
            return
        if crypto_id is not None and self._try_incremental_update(crypto_id, now=now):
            return
        with self._cache_lock:
            self._analysis_cache = None
            self._analysis_cache_time = 0
            # 维持「cache 为 None 时 days 必为 0」不变量，避免下次 days 比较基于残留值误判。
            self._analysis_cache_days = 0
            # 失效世代递增（PERF-080 补全）：与清缓存同一临界区，写回守卫的比对
            # 无检查-写回竞态。
            self._invalidated_generation += 1

    def _try_incremental_update(self, crypto_id: str, *, now: datetime | None = None) -> bool:
        """单条增量更新缓存报告（PERF-021/079），成功返回 True。

        步骤：锁外经 ``get_entry_by_crypto_id``（crypto_id UNIQUE 索引，O(1)）重读
        该条并重分类（复用 full_analysis 的 :meth:`_classify_entry`，含单条密码
        解密与指纹计算），再持 ``_cache_lock`` 把旧分类从 weak/old/指纹桶/
        _summaries_with_dates 中移除、插入新分类并重算聚合计数。db 读不持
        _cache_lock（cache 锁内禁访问数据库的锁序约定）；重分类期间缓存被并发
        失效则放弃更新（返回 False 交由调用方全量失效）。

        重读结果为行缺失或 ``is_deleted``（PERF-079 增删扩展）：构造 summary=None
        的「仅移除」差分——该条目已离开分析集合（get_entries_for_analysis 过滤
        is_deleted），按缓存成员资格移出各名单并下调 total；条目本就不在缓存
        （如已软删条目的物理删除二次通知）时整体为幂等 no-op。

        回退全量的情形：缓存缺失/过期/epoch 失配（指纹与密钥绑定，跨 epoch 不可比）、
        保险库锁定或改密窗口（无法取密钥）。

        ``now`` 透传 :meth:`_apply_reclassified_entry`（QL-057 测试时钟注入）。
        """
        with self._cache_lock:
            if not self._cache_valid_locked(self._analysis_cache):
                return False
            # 快照首次校验时刻的 epoch（SEC-040）：二次校验比对快照而非实时 epoch。
            # 防御跨 epoch grafting——锁外重分类期间若发生改密/恢复（epoch 轮换）且缓存
            # 被并发 full_analysis 以新 epoch 重填，按实时 epoch 双检会全部通过，旧密钥
            # 派生的 _ClassifyResult（含旧域密钥下的密码指纹）将被并入新 epoch 缓存，
            # 污染重复检测分组。当前 UI 时序（同线程串行触发失效）不可达，属防御纵深。
            snapshot_epoch = self._vault.key_epoch
        try:
            with self._vault.epoch_guarded_read():
                # SKIP 验签与 full_analysis 一致（PERF-010）：逐字段解密已含 GCM 认证，
                # 增量路径同样以解密失败（EntryIntegrityError/跳过语义）吸收损坏。
                raw = self._vault.db.get_entry_by_crypto_id(crypto_id, verify=VerifyMode.SKIP)
                # PERF-001 对齐：锁内快照主密钥，锁外重分类用快照。
                key = self._key
                # SEC-043 写入方世代：与 raw/key 同刻快照，供 _make_summary 的摘要/
                # 分类名缓存回写守卫拒收跨世代解密结果（增量路径的 db 读仅持 db_lock，
                # 锁外重分类期间恢复可提交并重臂缓存，是真实可达的跨世代窗口）。
                data_epoch = self._vault.key_epoch
        except (VaultLockedError, VaultKeyEpochMismatchError):
            return False
        if raw is None or raw.is_deleted:
            # 增删差分（PERF-079）：移除结果不经解密，key 立即释放。
            result = _ClassifyResult(None, None, False, None, False)
            del key
        else:
            self._cache.invalidate_if_epoch_changed()
            try:
                result = self._classify_entry(raw, key, data_epoch=data_epoch)
            except (DecryptionError, EntryIntegrityError):
                # _classify_entry 内部已吸收这两类；此处防御未来透传路径的意外逃逸。
                return False
            del key
        with self._cache_lock:
            cached = self._analysis_cache
            # 二次校验比对快照 epoch（SEC-040）：缓存报告须仍属首次校验的同一世代，
            # 期间被并发 full_analysis 以新 epoch 重填则放弃本次增量并入。
            if not self._cache_valid_locked(cached, expected_epoch=snapshot_epoch):
                return False
            self._apply_reclassified_entry(cached, crypto_id, result, now=now)
        return True

    @staticmethod
    def _recompute_aggregates(cached: _SecurityReportInternal) -> None:
        """从容器状态重算三项聚合计数，就地写回 ``cached``（MAINT-101 单一事实源）。

        聚合公式（weak_count==len(_weak_map)、old==len(_old_map)、
        duplicate_count==Σ(len(group)-1)）此前在增量差分与 full_analysis 各维护
        一份，对不齐时静默分叉（无报错，仅增量与全量计数漂移）。提取为单一函数
        供两路消费后，公式只有一处可改。输入容器须已由调用方建好键
        （full_analysis 构建 / _apply_reclassified_entry 差分维护 /
        _refilter_cache 的 days 重过滤）。
        """
        groups_map = cached.get("_duplicate_groups_map", {})
        cached["duplicate_count"] = sum(len(group) - 1 for group in groups_map.values())
        cached["weak_count"] = len(cached.get("_weak_map", {}))
        cached["old"] = len(cached.get("_old_map", {}))

    def _apply_reclassified_entry(
        self,
        cached: _SecurityReportInternal,
        crypto_id: str,
        result: _ClassifyResult,
        *,
        now: datetime | None = None,
    ) -> None:
        """持锁把单条条目的旧分类替换为新分类并重算聚合计数。须持 ``_cache_lock``。

        全 O(1) 差分（PERF-085）：容器全部 dict 化（_summaries_with_dates/
        _weak_map/_old_map/_crypto_id_to_fp）+ duplicate_groups 增量维护
        （_duplicate_groups_map 仅在旧/新指纹桶跨越 len>1 边界时增删组），消除
        PERF-076 时代残留的 O(n) 段——weak/summaries/old 三处线性定位、fp_map/
        fp_index 全量 dict 拷贝、duplicate_groups 全量重建（50k 有密码库单次编辑
        实测 16-19ms，差分后亚毫秒级）。无密码条目（note/identity 等常态）经反向
        索引的 None 哨兵直达无指纹分支，不再落入逐桶 any() 全扫描（50k 库实测
        每次差分 8.8ms 纯浪费）。就地修改的容器均为缓存私有（出口经
        _refilter_cache/_export_report 从内部 map 派生并隔离，PERF-062/085），
        不会外泄。指纹桶的局部 copy-on-write 保持：仅重建「旧指纹桶」与「新指纹
        桶」，其余桶原样共享。

        读/写两阶段（QL-068）：全部读取与判定（get/in/比较）先于任何就地修改完成，
        写阶段仅剩 dict 基本操作——change_bus 回调吞异常（EntryChangeBus.notify
        except Exception 后缓存继续被出口消费），此前「先就地改 weak/summaries、
        后访问指纹桶可 KeyError」的中途异常会留下撕裂缓存；两阶段化后读阶段无
        KeyError 面（索引/桶不一致经本方法读阶段的兜底分支吸收），写阶段无数据
        依赖型异常。

        old 差分的正确性依赖 _old_map 与 _summaries_with_dates 此前一致
        （full_analysis 构建 / _refilter_cache 的 days 重过滤 / 本方法的同步维护
        三方保证）：先移除旧条目的 old 成员资格，再按新 changed_utc 判定加入，
        与「以当前时刻与缓存 days 过滤」语义一致。result.summary 为 None（条目
        移除/损坏）时仅移除不插入，与 full_analysis 的跳过语义一致；此时 total
        按缓存成员资格下调（PERF-079 增删差分）。

        ``now`` 缺省实时（QL-057）：此前的硬编码 ``datetime.now(UTC)`` 使测试注入
        时钟时增量路径与全量路径行为分叉（full_analysis/_refilter_cache 均可注入）。
        """
        # ═══ 读阶段（QL-068）：完成全部读取与判定，不修改任何容器 ═══
        weak_map = cached.get("_weak_map", {})
        summaries = cached.get("_summaries_with_dates", {})
        old_map = cached.get("_old_map", {})
        fp_map = cached.get("_fingerprint_map", {})
        fp_index = cached.get("_crypto_id_to_fp", {})
        groups_map = cached.get("_duplicate_groups_map", {})
        # total 差分（PERF-079）的成员资格判定：summaries dict 化后 O(1)。
        was_in_summaries = crypto_id in summaries
        # 旧指纹 O(1) 定位（PERF-085 三态）：键存在且值为 bytes→旧指纹；值为 None→
        # 哨兵（条目无指纹的常态，无旧桶可移除）；键缺失→异常缓存形态（索引与桶
        # 撕裂），回退逐桶扫描兜底，保证任意来源缓存的行为与原实现一致。
        old_fingerprint: bytes | None = None
        if crypto_id in fp_index:
            old_fingerprint = fp_index[crypto_id]
        else:
            for fingerprint, group in fp_map.items():
                if any(e.crypto_id == crypto_id for e in group):
                    old_fingerprint = fingerprint
                    break
        # 反向一致性兜底（QL-068）：索引有旧指纹但指纹桶缺失（撕裂）时视同无旧桶
        # 可移除而非 KeyError——与上方「键缺失回退逐桶扫描」的正向兜底对称，撕裂
        # 形态仅记日志不中断差分。
        old_bucket = fp_map.get(old_fingerprint) if old_fingerprint is not None else None
        if old_fingerprint is not None and old_bucket is None:
            logger.debug("安全分析缓存索引与指纹桶不一致（crypto_id=%s），跳过旧桶移除", crypto_id)
            old_fingerprint = None
        # 新分类的过期判定（QL-057：now 可注入）在读阶段完成。
        join_old = (
            result.summary is not None
            and result.changed_utc is not None
            and result.changed_utc
            < (datetime.now(UTC) if now is None else now)
            - timedelta(days=self._analysis_cache_days)
        )

        # ═══ 写阶段：就地单点修改（全 O(1)，容器均为缓存私有）═══
        weak_map.pop(crypto_id, None)
        summaries.pop(crypto_id, None)
        old_map.pop(crypto_id, None)
        fp_index.pop(crypto_id, None)
        if old_fingerprint is not None and old_bucket is not None:
            kept = [e for e in old_bucket if e.crypto_id != crypto_id]
            if kept:
                fp_map[old_fingerprint] = kept
                if len(kept) > 1:
                    # 桶仍重复：组内成员同步换新桶引用。
                    groups_map[old_fingerprint] = kept
                else:
                    # 桶跌出重复边界（len 2→1）：移除组。
                    groups_map.pop(old_fingerprint, None)
            else:
                del fp_map[old_fingerprint]
                # 单例桶本就不在组内，pop 幂等。
                groups_map.pop(old_fingerprint, None)
        summary = result.summary
        if summary is not None:
            summaries[crypto_id] = (summary, result.changed_utc)
            if result.is_weak:
                weak_map[crypto_id] = summary
            # 哨兵收录（PERF-085）：无指纹条目也入索引（值 None），下次差分免逐桶
            # 扫描；与 full_analysis 的构建口径一致（键集==summaries 键集）。
            fp_index[crypto_id] = result.fingerprint
            if result.fingerprint is not None:
                bucket = fp_map.get(result.fingerprint)
                # copy-on-write：目标桶可能与其余未触及桶共享同一 list 引用，插入前
                # 复制以防污染共享桶。
                new_bucket = [*bucket, summary] if bucket is not None else [summary]
                fp_map[result.fingerprint] = new_bucket
                if len(new_bucket) > 1:
                    # 桶跨入/保持重复边界：入组（新键 append 尾部，与全量重建的
                    # fp_map 迭代序仅相对位置可能不同，组序无正确性语义）。
                    groups_map[result.fingerprint] = new_bucket
                else:
                    groups_map.pop(result.fingerprint, None)
            if join_old:
                old_map[crypto_id] = summary
        # total 差分（PERF-079）：按「缓存成员资格」调节——插入此前不在缓存的条目
        # （新增/恢复/外部新条目）+1，移除此前在缓存的条目（删除）-1，原位替换
        # （编辑/改密）不变，与 full_analysis 的 total==分析集行数语义保持一致。
        # 成员资格以 _summaries_with_dates 为准；已知取舍：损坏条目（summary 为
        # None，full_analysis 计 total 但不入 summaries）的增删在 total 上最多滞后
        # 一个 TTL 窗口，由任何后续全量失效自愈——损坏态条目本不可正常编辑，属可
        # 接受边界。
        if summary is not None and not was_in_summaries:
            cached["total"] = cached.get("total", 0) + 1
        elif summary is None and was_in_summaries:
            cached["total"] = max(0, cached.get("total", 0) - 1)
        # 容器同引用回写：就地修改时零成本，且在键缺失的异常缓存形态下补建键
        # （对齐原实现的赋值语义）。公开列表键（weak_entries/old_entries/
        # duplicate_groups）不在此维护——出口统一从 map 派生（PERF-085）。
        cached["_weak_map"] = weak_map
        cached["_summaries_with_dates"] = summaries
        cached["_old_map"] = old_map
        cached["_fingerprint_map"] = fp_map
        cached["_crypto_id_to_fp"] = fp_index
        cached["_duplicate_groups_map"] = groups_map
        # 聚合计数重算（MAINT-101 单一事实源，公式与 full_analysis 共享）。
        self._recompute_aggregates(cached)

    def _parse_changed_utc(self, raw: RawEntry) -> datetime | None:
        """解析条目密码变更时间为 UTC datetime，供过期检测。

        回退顺序 password_changed_at → updated_at → created_at。naive 视为 UTC，
        避免与 aware cutoff 比较抛 TypeError。解析失败返回 None（不计入过期）。
        """
        changed_at_str = raw.password_changed_at or raw.updated_at or raw.created_at
        if not changed_at_str:
            return None
        try:
            changed_utc = datetime.fromisoformat(changed_at_str)
            if changed_utc.tzinfo is None:
                return changed_utc.replace(tzinfo=UTC)
            return changed_utc.astimezone(UTC)
        except (ValueError, TypeError):
            # 日志纪律（SEC-056）：只记条目标识不记解密后的字段值——changed_at_str
            # 是解密后明文，虽仅时间戳，仍对齐项目「日志只记 id」纪律。
            logger.debug("条目 %s 密码变更时间解析失败", raw.crypto_id)
            return None

    def full_analysis(
        self,
        days: int = DEFAULT_ANALYSIS_DAYS,
        *,
        cancel_check: Callable[[], bool] | None = None,
        now: datetime | None = None,
    ) -> _SecurityReportInternal:
        """一次性完成所有安全分析（弱/重复/过期），避免重复解密。结果由 _cached_analysis 缓存。

        返回值为**内部形态**（计数 + 内部 map，PERF-085 收口）：生产调用链仅
        :meth:`_cached_analysis`（其出口经 :meth:`_export_report` 派生公开列表键），
        直接调用方（测试等）须自行经 map/计数消费，公开列表键不在本形态上。

        有意始终执行全部三项并解密所有密码算 HMAC 指纹；days 变化仅重过滤
        过期条目，避免重新解密（重复检测的 HMAC 是瓶颈）。

        警告：执行 O(n) 解密，调用方**必须**在 BackgroundWorker 中执行，不得在 UI 线程。

        线程安全：``get_entries_for_analysis`` 在 _cache_lock 外，并发下缓存可能在
        读取期间失效（MAINT-114：docstring 引用自不存在的 ``get_entries`` 更正为
        实际调用的窄投影入口）。单用户桌面应用无此问题；若未来引入后台定期分析，
        需在调用方加锁或方法内持读锁。
        """
        # 全量分析持有主密钥并逐条解密，整个敏感生命周期持 vault_write_lock，
        # 使 lock() 须等分析释放密钥后才能清零，避免后台 Worker 超时后仍持密钥。
        #
        # 触发频次取舍（PERF-102，维持现状）：每次解锁后状态栏 worker 走一次全量
        # 分析（锁定清密钥与缓存后 TTL 必为空）。跨锁定保留缓存不可行——指纹绑定
        # 主密钥（_password_fingerprint），保留即跨密钥世代污染重复检测分组；等待
        # 上界已由取消探针封顶（见 _CANCEL_CHECK_MASK 与 PERF-092）。
        #
        # 持锁取舍（PERF-092，评估后维持全程持锁）：曾评估「锁内快照 entries+key、
        # 锁外分类」的锁拆分——正确性守卫确已齐备（_cached_analysis 写回的 epoch+
        # 失效世代双守卫拒收陈旧结果，_make_summary 的 SEC-043 data_epoch 守卫拒收
        # 跨世代摘要回写，陈旧报告仅一次性返回渲染不污染缓存），且增量差分路径
        # （_apply_reclassified_entry）本就在 epoch_guarded_read 快照后锁外解密。
        # 但全程持锁承载的是**安全**不变量而非正确性：lock()/close() 的
        # clear_vault_state 清零密钥并 gc.collect，须等本 worker 解完密、释放全部
        # 密钥与明文引用后再执行，密钥材料才真正可回收——拆分后 lock() 无需等待，
        # 清零与 GC 在 worker 仍持 vault_key 副本与在途明文时进行，「后台 Worker
        # 超时后仍持密钥」的窗口（本持锁设计要关闭的）重开。持锁代价已由取消机制
        # 封顶：lock()/close()/change_master_password（PERF-092 补齐对称取消）取锁
        # 前均 request_cancel，本循环每 64 条检查一次取消，等待上界 = 检查点间隔 +
        # unwind 而非分析全程；唯一不取消的持锁竞争方是 password_history_service
        # .decrypt（UI 线程短操作），阻塞上界为在飞分析的剩余时长，接受。
        with self._vault.vault_write_lock():
            # PERF-010：逐条解密已含 GCM 认证，_classify_entry 双重判定损坏，
            # 故跳过 HMAC 验签省去全量重算。PERF-020：窄投影扫描——分析仅消费摘要
            # 字段与 password_enc（解密算指纹），notes/custom_fields/totp_secret
            # 三个大列不进入扫描（宽 SELECT 物化后即弃是温态分析的主导开销之一）。
            entries = self._vault.db.get_entries_for_analysis()
            total = len(entries)
            weak_map: dict[str, Entry] = {}
            password_map: dict[bytes, list[Entry]] = {}
            # crypto_id→指纹反向索引（PERF-076/085）：与 password_map 平行构建，
            # 增量更新据此 O(1) 定位旧指纹桶，替代逐桶 any() 全扫描（50k 库桶数
            # 可达数万）。值 None 为「无指纹」哨兵（PERF-085）：入索引条件是
            # summary 非 None（即进入 _summaries_with_dates 的全部条目），无密码
            # 条目（note/identity 等）也收录，键集与 summaries 一致——否则常态
            # 无密码条目的每次差分都因 pop miss 落入逐桶全扫描。
            fp_index: dict[str, bytes | None] = {}
            cutoff = (now if now is not None else datetime.now(UTC)) - timedelta(days=days)
            # 保存所有条目的 summary + changed_at_utc（dict 形态，PERF-085：增量
            # 差分 O(1) 定位；保插入序使 days 重过滤输出序稳定），供缓存后不同
            # days 重新过滤。
            _summaries_with_dates: dict[str, tuple[Entry, datetime | None]] = {}

            skipped_count = 0
            # 循环外取一次主密钥副本，供重复检测的 HMAC 指纹复用。
            vault_key = self._key
            # SEC-043 写入方世代：与 entries/vault_key 同刻快照（持写锁期间 epoch 不变，
            # 属防御纵深——堵「分析循环中被外部失效重臂」的极端交错），供
            # _make_summary 的摘要/分类名缓存回写守卫。
            data_epoch = self._vault.key_epoch
            # 循环外一次性 epoch 校验，循环内避免每条重复加锁（持写锁期间 epoch 不变）。
            self._cache.invalidate_if_epoch_changed()
            for idx, raw in enumerate(entries):
                # 周期性检查取消/锁定：用户点锁定时 lock() set 取消事件并等写锁；
                # 此处主动中止抛 VaultLockedError（被 _cached_analysis 捕获返回空报告），
                # 释放写锁让 lock() 尽快完成，避免 UI 冻结与明文驻留。
                if (idx & _CANCEL_CHECK_MASK) == 0 and (
                    self._vault.is_cancel_requested()
                    or (cancel_check is not None and cancel_check())
                ):
                    raise VaultLockedError("安全分析因锁定/取消请求而中止")
                result = self._classify_entry(raw, vault_key, data_epoch=data_epoch)
                if result.counted_in_skipped:
                    skipped_count += 1
                if result.summary is None:
                    continue
                _summaries_with_dates[result.summary.crypto_id] = (
                    result.summary,
                    result.changed_utc,
                )
                if result.is_weak:
                    weak_map[result.summary.crypto_id] = result.summary
                if result.fingerprint is not None:
                    password_map.setdefault(result.fingerprint, []).append(result.summary)
                fp_index[result.summary.crypto_id] = result.fingerprint

            old_map = {
                cid: s
                for cid, (s, dt) in _summaries_with_dates.items()
                if dt is not None and dt < cutoff
            }
            # 重复分组 dict 形态事实源（PERF-085）：仅含 >1 的桶，值与指纹桶同引用，
            # 增量差分据此在桶跨越 len>1 边界时增删组，免全量重建。
            groups_map = {fp: g for fp, g in password_map.items() if len(g) > 1}
            del vault_key

        if skipped_count:
            logger.warning("安全分析共跳过 %d 条损坏条目", skipped_count)

        # 报告为内部形态（PERF-085 收口）：计数 + 内部 map，公开列表键不入本体——
        # 出口（_cached_analysis 的各返回点）统一经 _export_report 从 map 派生，消除
        # 「同名公开列表键自首次增量差分起陈旧」的双表示；聚合计数经
        # _recompute_aggregates 统一产出（MAINT-101）。
        report: _SecurityReportInternal = {
            "total": total,
            "weak_count": 0,
            "duplicate_count": 0,
            "old": 0,
            "_summaries_with_dates": _summaries_with_dates,  # 缓存分层：供不同 days 重过滤
            # 指纹桶全集（含单例桶，PERF-021）：增量失效据此移动单条条目桶位并重算
            # 重复分组；duplicate_groups 仅含 >1 的桶，不足以支撑增量更新。
            "_fingerprint_map": password_map,
            # 反向索引（PERF-076/085）：增量更新 O(1) 定位旧桶，与指纹桶平行维护。
            "_crypto_id_to_fp": fp_index,
            "_weak_map": weak_map,
            "_old_map": old_map,
            "_duplicate_groups_map": groups_map,
        }
        self._recompute_aggregates(report)
        return report

    def _classify_entry(
        self,
        raw: RawEntry,
        vault_key: bytes,
        *,
        data_epoch: str | None = None,
    ) -> _ClassifyResult:
        """对单条目做安全分类（弱/日期/重复指纹），抽取自 full_analysis 循环体。

        返回 :class:`_ClassifyResult`：None 语义见该类（summary None=完全跳过，
        fingerprint None=无密码或解密失败）。``data_epoch``（SEC-043）透传
        :meth:`_make_summary` 作缓存回写世代守卫。
        """
        if raw.integrity_error:
            logger.debug("安全分析跳过元数据完整性失败条目 id=%s", raw.id)
            return _ClassifyResult(None, None, False, None, True)
        try:
            summary = self._make_summary(raw, data_epoch=data_epoch)
        except EntryIntegrityError:
            logger.debug("安全分析跳过损坏条目 id=%s", raw.id, exc_info=True)
            return _ClassifyResult(None, None, False, None, True)
        changed_utc = self._parse_changed_utc(raw)
        is_weak = (raw.password_strength or 0) <= 1 and bool(raw.password)
        if not raw.password:
            return _ClassifyResult(summary, changed_utc, is_weak, None, False)
        try:
            password = decrypt_field(
                raw.password,
                vault_key,
                raw.crypto_id,
                "password",
                strict=True,
            )
        except DecryptionError:
            logger.debug("安全分析跳过损坏条目 id=%s，原因：密码解密失败", raw.id)
            return _ClassifyResult(summary, changed_utc, is_weak, None, True)
        if not password:
            # 空密码（note/identity 等无密码条目）不计为弱：is_weak 在上方用密文 bool
            # 判断（空明文也产生非空密文，bool 恒 True），此处解密确认空后置 False，
            # 避免无密码条目虚增 weak_count、拉低健康分。
            return _ClassifyResult(summary, changed_utc, False, None, False)
        fingerprint = self._password_fingerprint(password, vault_key)
        del password
        return _ClassifyResult(summary, changed_utc, is_weak, fingerprint, False)
