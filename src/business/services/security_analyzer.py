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
from typing import TYPE_CHECKING, NamedTuple, TypedDict, TypeGuard, cast

if TYPE_CHECKING:
    from ..managers.entry_cache import EntryCacheManager
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
from .crypto_utils import build_entry_summary, decrypt_field, require_vault_key

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


class _SecurityReportBase(TypedDict):
    """安全分析报告的公开字段（生产/消费契约，required）。"""

    total: int
    weak_count: int
    weak_entries: list[Entry]
    duplicate_groups: list[list[Entry]]
    duplicate_count: int
    old_entries: list[Entry]
    old: int


class SecurityReport(_SecurityReportBase, total=False):
    """安全分析报告结构（full_analysis / get_cached_report 返回值的类型契约）。

    生产者与消费者共享此 TypedDict，键集漂移由类型检查捕获。``_summaries_with_dates``
    ``_fingerprint_map`` 与 ``_key_epoch`` 为缓存分层内部键（total=False 可选）：
    第一个供不同 days 重过滤，第二个是含单例桶的完整指纹分桶（PERF-021 增量失效
    据此移动单条条目桶位——duplicate_groups 仅含 >1 的桶，不足以支撑增量更新），
    第三个供 epoch 失效判定（仅缓存层填充 _key_epoch）。出口契约（PERF-062）：
    ``get_cached_report`` / ``get_or_compute_report`` 的返回副本**不含**这三个内部键
    （无外部消费方，深拷贝是纯开销）；仅内部缓存本体与 :meth:`full_analysis` 的
    生产结果持全键。
    """

    _summaries_with_dates: list[tuple[Entry, datetime | None]]
    _fingerprint_map: dict[bytes, list[Entry]]
    _key_epoch: str | None


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
    EntryManager 主动 invalidate_cache 失效，TTL 兜底。
    """

    def __init__(
        self,
        vault_manager: "VaultManager",
        entry_cache: "EntryCacheManager",
        cache_ttl_seconds: int = SECURITY_ANALYSIS_CACHE_TTL_SECONDS,
    ):
        self._vault = vault_manager
        # 复用 EntryCacheManager 摘要缓存：经单一解密源获取，避免独立解密产生重复
        # 明文副本，收缩驻留面。
        self._cache = entry_cache
        self._cache_ttl_seconds = cache_ttl_seconds
        self._analysis_cache: SecurityReport | None = None
        self._analysis_cache_time: float = 0
        self._analysis_cache_days: int = 0
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
        # 循环外已 invalidate_if_epoch_changed，此处经无校验入口避免每条重复加锁。
        title, username, url, tags = self._cache.search_metadata_for_analysis(
            raw, data_epoch=data_epoch
        )
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
        self, cache: SecurityReport, days: int, *, now: datetime | None = None
    ) -> SecurityReport:
        """从缓存按 days 重新过滤过期条目，返回剥离内部键的出口副本（PERF-062）。

        须持 _cache_lock 调用。顺序：先 ``dict()`` 浅拷贝并在副本上完成 days 重过滤
        与 QL-001 实例回写（依赖内部键 ``_summaries_with_dates``，须在剥离前），再
        剥离出口副本的全部下划线内部键——``_fingerprint_map``/``_summaries_with_dates``
        仅缓存分层内部消费（增量失效/days 重过滤），无任何外部读方，此前出口深拷贝
        在 50k 库温态 get_cached_report 实测占 2/3 耗时，是纯浪费。出口仅公开字段；
        weak/old 列表浅拷贝容器并直接共享 Entry 引用（Entry 为 frozen 且无可变容器，
        逐条 ``dataclasses.replace`` 重建 24-kwarg 实例无变异面可防）；duplicate_groups
        内层 list 仍复制，防消费方经出口引用就地变异桶成员污染增量更新基准。内部
        缓存本体（``_analysis_cache``）仍持全键。
        """
        # dict(TypedDict) 退化为 dict[str, object]，cast 标注此复制边界。
        result = cast("SecurityReport", dict(cache))
        if days != self._analysis_cache_days:
            cutoff = (now if now is not None else datetime.now(UTC)) - timedelta(days=days)
            new_old_entries = [
                s
                for s, dt in cache.get("_summaries_with_dates", [])
                if dt is not None and dt < cutoff
            ]
            result["old_entries"] = new_old_entries
            result["old"] = len(new_old_entries)
            # 同步回写实例缓存（QL-001）：_analysis_cache_days 与 old/old_entries 必须一致，
            # 否则 get_cached_counts 快路径（days == _analysis_cache_days）会读实例中旧 days
            # 的 old 计数（多报过期）。此前仅改副本致实例与 days 脱钩。
            if self._analysis_cache is not None:
                self._analysis_cache["old_entries"] = list(new_old_entries)
                self._analysis_cache["old"] = len(new_old_entries)
            # 更新 days 使后续相同 days 命中跳过重复 O(n) 过滤。
            self._analysis_cache_days = days
        # 剥离内部键（PERF-062）：出口不含 _fingerprint_map/_summaries_with_dates/
        # _key_epoch，缓存本体不受影响（副本与内部 dict 为不同容器）。
        result.pop("_summaries_with_dates", None)
        result.pop("_fingerprint_map", None)
        result.pop("_key_epoch", None)
        # 列表容器浅拷贝（共享 Entry 引用）：隔离调用方对列表结构的就地变异。
        if "weak_entries" in result:
            result["weak_entries"] = list(result["weak_entries"])
        if "old_entries" in result:
            result["old_entries"] = list(result["old_entries"])
        if "duplicate_groups" in result:
            result["duplicate_groups"] = [list(group) for group in result["duplicate_groups"]]
        return result

    def _cached_analysis(
        self,
        days: int = DEFAULT_ANALYSIS_DAYS,
        *,
        cancel_check: Callable[[], bool] | None = None,
        now: datetime | None = None,
    ) -> SecurityReport:
        """带缓存的安全分析，基础分析不依赖 days。

        命中仅校验 key_epoch 与 TTL；条目增删改由 EntryManager 主动 invalidate_cache
        失效，TTL 兜底。key_epoch 校验保证改密后缓存失效（密码指纹依赖旧主密钥）。
        days 变化仅从 ``_summaries_with_dates`` 重过滤过期条目，避免重新解密全部密码
        （重复检测的 HMAC 是性能瓶颈）。
        """
        with self._cache_lock:
            current_epoch = self._vault.key_epoch
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
            # 持锁后重新校验，若仍有效直接复用以避免覆盖冗余写入。
            cached = self._analysis_cache
            if (
                cached is not None
                and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
                and cached.get("_key_epoch") == current_epoch
            ):
                return self._refilter_cache(cached, days, now=now)
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
        invalidate_cache 未及时触发的并发窗口内也不复用，避免锁定/改密后旧明文摘要驻留。
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
                old = sum(
                    1
                    for _s, dt in cached.get("_summaries_with_dates", [])
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
        cached: SecurityReport | None,
        *,
        expected_epoch: str | None = None,
    ) -> TypeGuard[SecurityReport]:
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

    def invalidate_cache(
        self,
        password_changed: bool = True,
        metadata_changed: bool = True,
        crypto_id: str | None = None,
    ) -> None:
        """清除分析缓存，下次访问时重新计算。

        仅当安全相关维度变更时失效，避免纯旁路变更（如 ``is_favorite`` 切换、分类
        调整）触发整库重解密：

        - ``password_changed``：密码变更 → 弱密码/重复/过期判定均可能变。
        - ``metadata_changed``：title/username 等报告展示元数据变更 → 缓存的
          weak_entries/duplicate_groups 元数据陈旧。
        - ``crypto_id``：变更涉及的单条条目（PERF-021）。提供且缓存仍有效时走
          **单条增量更新**——仅重读/重分类该条并重算聚合计数（指纹桶、重复分组、
          弱/过期名单），其余 N-1 条的密码解密与 HMAC 指纹结果原样复用。纯元数据
          编辑与改单条密码共用此路径：重分类一条是常数开销，报告内嵌的展示元数据
          （标题等）亦随之刷新，无需按 password_changed 分支。任何读取失败（锁定/
          改密窗口/条目缺失）回退全量失效，语义保守。

        两者皆 False 时直接返回（PERF：旁路变更不影响任何安全分析输入）。回调签名
        经 :meth:`EntryChangeBus.notify` 以位置参数 ``(password_changed,
        metadata_changed, crypto_id)`` 传入；锁定/epoch 轮换通道零参调用经默认
        True 保持全量失效不变。
        """
        if not (password_changed or metadata_changed):
            return
        if crypto_id is not None and self._try_incremental_update(crypto_id):
            return
        with self._cache_lock:
            self._analysis_cache = None
            self._analysis_cache_time = 0
            # 维持「cache 为 None 时 days 必为 0」不变量，避免下次 days 比较基于残留值误判。
            self._analysis_cache_days = 0

    def _try_incremental_update(self, crypto_id: str) -> bool:
        """单条增量更新缓存报告（PERF-021），成功返回 True。

        步骤：锁外经 ``get_entry_by_crypto_id``（crypto_id UNIQUE 索引，O(1)）重读
        该条并重分类（复用 full_analysis 的 :meth:`_classify_entry`，含单条密码
        解密与指纹计算），再持 ``_cache_lock`` 把旧分类从 weak/old/指纹桶/
        _summaries_with_dates 中移除、插入新分类并重算聚合计数。db 读不持
        _cache_lock（cache 锁内禁访问数据库的锁序约定）；重分类期间缓存被并发
        失效则放弃更新（返回 False 交由调用方全量失效）。

        回退全量的情形：缓存缺失/过期/epoch 失配（指纹与密钥绑定，跨 epoch 不可比）、
        条目已删/不存在（增删路径不携带 crypto_id，到达此处属异常状态）、保险库
        锁定或改密窗口（无法取密钥）。
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
            return False
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
            self._apply_reclassified_entry(cached, crypto_id, result)
        return True

    def _apply_reclassified_entry(
        self,
        cached: SecurityReport,
        crypto_id: str,
        result: _ClassifyResult,
    ) -> None:
        """持锁把单条条目的旧分类替换为新分类并重算聚合计数。须持 ``_cache_lock``。

        局部 copy-on-write（PERF-062）：仅重建「旧指纹所在的桶」（移除该条目后）与
        「新指纹桶」，其余桶原样共享——出口已剥离 ``_fingerprint_map``（无消费方可
        触达桶），共享安全；此前每次单条编辑对全部指纹桶逐桶重建（20k 库实测
        12-45ms 且在 UI 线程）。total 不变（单条更新），weak/duplicate/old 从保留
        条目重算；old 以当前时刻与缓存 days 重过滤（O(n) 日期比较，无解密），与
        _refilter_cache 的 days 重过滤语义一致。result.summary 为 None（条目损坏/
        无密码损坏）时仅移除不插入，与 full_analysis 的跳过语义一致。
        """
        # 1) 移除旧分类（weak 名单与 _summaries_with_dates 整列表重建：仅引用搬运）
        cached["weak_entries"] = [
            e for e in cached.get("weak_entries", []) if e.crypto_id != crypto_id
        ]
        summaries = [
            (s, dt) for s, dt in cached.get("_summaries_with_dates", []) if s.crypto_id != crypto_id
        ]
        old_map = cached.get("_fingerprint_map", {})
        # 定位旧指纹桶：条目至多出现在一个桶（密码指纹唯一），其余桶无需重建。
        old_fingerprint: bytes | None = None
        for fingerprint, group in old_map.items():
            if any(e.crypto_id == crypto_id for e in group):
                old_fingerprint = fingerprint
                break
        fp_map: dict[bytes, list[Entry]] = dict(old_map)
        if old_fingerprint is not None:
            kept = [e for e in old_map[old_fingerprint] if e.crypto_id != crypto_id]
            if kept:
                fp_map[old_fingerprint] = kept
            else:
                del fp_map[old_fingerprint]
        # 2) 插入新分类
        if result.summary is not None:
            summaries.append((result.summary, result.changed_utc))
            if result.is_weak:
                cached["weak_entries"].append(result.summary)
            if result.fingerprint is not None:
                bucket = fp_map.get(result.fingerprint)
                # copy-on-write：目标桶可能与其余未触及桶共享同一 list 引用，插入前
                # 复制以防污染共享桶。
                fp_map[result.fingerprint] = (
                    [*bucket, result.summary] if bucket is not None else [result.summary]
                )
        # 3) 重算聚合
        cached["_summaries_with_dates"] = summaries
        cached["_fingerprint_map"] = fp_map
        groups = [list(g) for g in fp_map.values() if len(g) > 1]
        cached["duplicate_groups"] = groups
        cached["duplicate_count"] = sum(len(g) - 1 for g in groups)
        cached["weak_count"] = len(cached["weak_entries"])
        cutoff = datetime.now(UTC) - timedelta(days=self._analysis_cache_days)
        old_entries = [s for s, dt in summaries if dt is not None and dt < cutoff]
        cached["old_entries"] = old_entries
        cached["old"] = len(old_entries)

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
            logger.debug("条目 %s 日期解析失败: %s", raw.id, changed_at_str)
            return None

    def full_analysis(
        self,
        days: int = DEFAULT_ANALYSIS_DAYS,
        *,
        cancel_check: Callable[[], bool] | None = None,
        now: datetime | None = None,
    ) -> SecurityReport:
        """一次性完成所有安全分析（弱/重复/过期），避免重复解密。结果由 _cached_analysis 缓存。

        有意始终执行全部三项并解密所有密码算 HMAC 指纹；days 变化仅重过滤
        过期条目，避免重新解密（重复检测的 HMAC 是瓶颈）。

        警告：执行 O(n) 解密，调用方**必须**在 BackgroundWorker 中执行，不得在 UI 线程。

        线程安全：``get_entries`` 在 _cache_lock 外，并发下缓存可能在读取期间失效。
        单用户桌面应用无此问题；若未来引入后台定期分析，需在调用方加锁或方法内持读锁。
        """
        # 全量分析持有主密钥并逐条解密，整个敏感生命周期持 vault_write_lock，
        # 使 lock() 须等分析释放密钥后才能清零，避免后台 Worker 超时后仍持密钥。
        with self._vault.vault_write_lock():
            # PERF-010：逐条解密已含 GCM 认证，_classify_entry 双重判定损坏，
            # 故跳过 HMAC 验签省去全量重算。PERF-020：窄投影扫描——分析仅消费摘要
            # 字段与 password_enc（解密算指纹），notes/custom_fields/totp_secret
            # 三个大列不进入扫描（宽 SELECT 物化后即弃是温态分析的主导开销之一）。
            entries = self._vault.db.get_entries_for_analysis()
            total = len(entries)
            weak_entries = []
            password_map: dict[bytes, list[Entry]] = {}
            cutoff = (now if now is not None else datetime.now(UTC)) - timedelta(days=days)
            # 保存所有条目的 summary + changed_at_utc，供缓存后不同 days 重新过滤
            _summaries_with_dates: list[tuple[Entry, datetime | None]] = []

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
                _summaries_with_dates.append((result.summary, result.changed_utc))
                if result.is_weak:
                    weak_entries.append(result.summary)
                if result.fingerprint is not None:
                    password_map.setdefault(result.fingerprint, []).append(result.summary)

            old_entries = [s for s, dt in _summaries_with_dates if dt is not None and dt < cutoff]
            duplicate_groups = [g for g in password_map.values() if len(g) > 1]
            duplicate_count = sum(len(g) - 1 for g in duplicate_groups)
            del vault_key

        if skipped_count:
            logger.warning("安全分析共跳过 %d 条损坏条目", skipped_count)

        return {
            "total": total,
            "weak_count": len(weak_entries),
            "weak_entries": weak_entries,
            "duplicate_groups": duplicate_groups,
            "duplicate_count": duplicate_count,
            "old_entries": old_entries,
            "old": len(old_entries),
            "_summaries_with_dates": _summaries_with_dates,  # 缓存分层：供不同 days 重过滤
            # 指纹桶全集（含单例桶，PERF-021）：增量失效据此移动单条条目桶位并重算
            # 重复分组；duplicate_groups 仅含 >1 的桶，不足以支撑增量更新。
            "_fingerprint_map": password_map,
        }

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
