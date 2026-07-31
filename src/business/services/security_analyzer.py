"""安全分析器，提供弱密码检测、重复密码检测与过期提醒。"""

import dataclasses
import hmac
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, NamedTuple, TypedDict, cast

if TYPE_CHECKING:
    from ..managers.entry_cache import EntryCacheManager
    from ..managers.vault_manager import VaultManager

logger = logging.getLogger(__name__)

from ...database.types import EntryQuery, VerifyMode
from ...exceptions import DecryptionError, EntryIntegrityError, VaultLockedError
from ...models import Entry, RawEntry
from .crypto_utils import build_entry_summary, decrypt_field, require_vault_key

# 全量分析取消探测掩码：每 64 条检查一次取消请求（idx & _CANCEL_CHECK_MASK == 0
# 即 idx 为 64 倍数），降低热循环高频调用的开销。安全分析扫描频率高于改密，故取消
# 探测比 vault_manager 改密路径（每条检查）更稀疏。
_CANCEL_CHECK_MASK = 0x3F

# 分析缓存存活时间，单位为秒。命中期内复用基础分析与密码指纹结果，
# 避免重复执行 O(n) 解密与 HMAC 计算。条目增删或改密会立即失效缓存，
# 此 TTL 仅控制时间维度的淘汰。跨层时序常量未集中到 UI 层，以避免
# 业务层反向依赖 UI 模块；本常量作为业务层时序参数的命名事实来源。
SECURITY_ANALYSIS_CACHE_TTL_SECONDS = 120

# 安全健康评分的惩罚系数：弱/重复/过期密码各自占总数的占比乘以对应系数，从满分
# 100 扣减。属业务规则（非 UI 呈现参数），集中于此使评分算法可被非 UI 场景
# （CLI/导出/告警）复用，权重调整无需触及 UI 资源包。
HEALTH_PENALTY_WEAK = 15
HEALTH_PENALTY_DUPLICATE = 10
HEALTH_PENALTY_OLD = 5


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

    生产者（SecurityAnalyzer）与消费者（ListRefreshController / SecurityDashboard）
    共享此 TypedDict，使两侧键集一致——新增/改名字段时类型检查即时捕获漂移，
    而非运行时 KeyError。``_summaries_with_dates`` 与 ``_key_epoch`` 为缓存分层
    内部键（``total=False`` 可选）：前者供不同 days 重过滤，后者供 epoch 失效判定；
    仅缓存层填充 ``_key_epoch``，full_analysis 与空报告不设，故标可选。
    """

    _summaries_with_dates: list[tuple[Entry, datetime | None]]
    _key_epoch: str | None


class SecurityCounts(NamedTuple):
    """安全分析的计数视图（total/weak/duplicate/old），供仅读计数的消费者。

    与 :class:`SecurityReport` 区分：不含 Entry 列表，获取时无需 :meth:`_refilter_cache`
    的深拷贝（PERF-2），状态栏刷新与空态判定等只读计数场景用它避免无谓深拷贝。
    """

    total: int
    weak_count: int
    duplicate_count: int
    old: int


class _ClassifyResult(NamedTuple):
    """单条条目安全分类结果（full_analysis 循环体抽取，降低嵌套）。

    summary 为 None 表示完全跳过（integrity/摘要损坏，不计入 summaries 仅
    skipped_count）；fingerprint 为 None 表示无密码或解密失败（不计入重复检测，
    但 summary 仍计入 summaries/weak）。
    """

    summary: Entry | None
    changed_utc: datetime | None
    is_weak: bool
    fingerprint: bytes | None
    counted_in_skipped: bool


class SecurityAnalyzer:
    """密码安全分析器，提供三项分析维度：

    1. **弱密码检测**：基于已存储的强度评分，筛选评分不大于 1 的条目。
    2. **重复密码检测**：解密密码后计算 HMAC 指纹，按指纹分组找出使用相同
       密码的条目集合。
    3. **过期密码检测**：按 ``password_changed_at`` 等时间字段，筛选超过指定
       天数未修改的条目。

    缓存策略：分析结果默认缓存 ``SECURITY_ANALYSIS_CACHE_TTL_SECONDS`` 秒，
    采用分层设计。基础分析覆盖弱密码与重复密码，不依赖 days 参数；days 变化
    时仅重新过滤过期条目，避免重复解密全部密码。缓存命中仅校验主密钥版本
    ``key_epoch`` 与 TTL；条目增删由 ``EntryManager`` 主动调用
    ``invalidate_cache`` 失效，TTL 作为最终兜底，避免每次命中都查 DB 计数。
    """

    def __init__(
        self,
        vault_manager: 'VaultManager',
        entry_cache: 'EntryCacheManager',
        cache_ttl_seconds: int = SECURITY_ANALYSIS_CACHE_TTL_SECONDS,
    ):
        self._vault = vault_manager
        # 复用 EntryCacheManager 的摘要缓存：title/username/url/tags/category_name
        # 经单一解密源获取，避免本分析器独立解密产生与列表路径重复的明文字符串副本
        # （str 不可变，复用后 summary Entry 与缓存引用同一字符串对象，收缩明文驻留面）。
        self._cache = entry_cache
        self._cache_ttl_seconds = cache_ttl_seconds
        self._analysis_cache: SecurityReport | None = None
        self._analysis_cache_time: float = 0
        self._analysis_cache_days: int = 0
        self._cache_lock = threading.Lock()

    @staticmethod
    def compute_health_score(weak_count: int, dup_count: int, old_count: int, total: int) -> int:
        """按各类风险占比与对应惩罚系数计算 0 至 100 的安全健康评分。

        评分算法与惩罚系数属于业务规则，集中于此供 UI 与潜在的非 UI 场景复用，
        避免 UI 层持有业务权重导致的分层违反。
        """
        if total == 0:
            return 100
        weak_ratio = min(weak_count / total, 1.0)
        dup_ratio = min(dup_count / total, 1.0)
        old_ratio = min(old_count / total, 1.0)
        return max(0, int(100 - (
            weak_ratio * 100 * HEALTH_PENALTY_WEAK
            + dup_ratio * 100 * HEALTH_PENALTY_DUPLICATE
            + old_ratio * 100 * HEALTH_PENALTY_OLD
        )))

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def _make_summary(self, raw: RawEntry) -> Entry:
        """只返回分析界面所需字段，避免缓存敏感明文。

        摘要字段（title/username/url/tags）复用 EntryCacheManager 的缓存解密结果，
        分类名复用其 ``decrypt_category_name``，避免在此独立解密产生与列表路径
        重复的明文字符串副本。cache 以 strict 解密，损坏字段返回 ``''`` 并记入
        failed 集合；此处检测到任一字段失败即抛 EntryIntegrityError，供
        full_analysis 计入 ``skipped_count``。刻意选用 EntryIntegrityError（非
        ValueError 子类）而非 ValueError：使「损坏即跳过」语义不依赖「缓存层吸收
        DecryptionError 不外抛」这一隐性契约——即便未来缓存层透传 DecryptionError
        （其 IS-A ValueError），也不会被 full_analysis 的跳过分支误吞而静默。
        """
        # 批量路径：full_analysis 循环外已 invalidate_if_epoch_changed，此处经公开的
        # 无校验入口避免每条重复加锁+查 epoch（持 vault_write_lock 期间 epoch 不变）。
        title, username, url, tags = self._cache.search_metadata_for_analysis(raw)
        if self._cache.get_failed_fields(raw.crypto_id):
            raise EntryIntegrityError(f'条目 {raw.crypto_id} 摘要字段解密失败')
        summary = build_entry_summary(raw, username)
        summary = dataclasses.replace(summary, title=title, url=url, tags=tags)
        if raw.category_id is not None and raw.category_name:
            # 分类名密文损坏时 decrypt_category_name 抛 DecryptionError（strict=True
            # 透传）。统一转 EntryIntegrityError，使 _make_summary 只抛这一种类型——
            # full_analysis 的跳过分支据此 skip 损坏条目，不因 DecryptionError 透传
            # 而终止整次分析（保持与摘要字段损坏一致的容错）。
            try:
                category_name = self._cache.decrypt_category_name(
                    raw.category_id, raw.category_name,
                )
            except DecryptionError:
                raise EntryIntegrityError(
                    f'条目 {raw.crypto_id} 分类名解密失败'
                ) from None
            summary = dataclasses.replace(summary, category_name=category_name)
        return summary

    def _password_fingerprint(self, password: str, key: bytes | None = None) -> bytes:
        """使用主密钥生成密码指纹，用于去重检测。

        权衡说明：使用主密钥意味着主密码变更后指纹失效，但缓存会在
        ``SECURITY_ANALYSIS_CACHE_TTL_SECONDS`` 秒 TTL 内自然淘汰。
        优点是无需额外存储独立 HMAC 密钥；指纹不出本进程，安全性
        依赖主密钥保护。

        传入 ``key`` 复用调用方已获取的密钥副本，避免在批量分析中对每条密码
        都经 ``self._key`` 触发一次密钥 bytes 复制，缩小主密钥驻留面。
        """
        return hmac.digest(
            key if key is not None else self._key, password.encode('utf-8'), 'sha256'
        )

    def _refilter_cache(self, cache: SecurityReport, days: int) -> SecurityReport:
        """从缓存按 days 重新过滤过期条目，返回独立副本。

        提取公共逻辑以消除 _cached_analysis 与 get_cached_report 的 DRY 违规。
        调用方须在持有 _cache_lock 的上下文中调用，传入原始缓存——本方法内部
        ``dict()`` 浅拷贝保护原始（days-specific 的 old_entries 等只落到副本，
        不污染缓存本体）。

        返回的每个 Entry 均通过 ``dataclasses.replace`` 创建为独立副本，调用方
        修改其属性不会污染缓存。duplicate_groups 中的每个分组列表与组内 Entry
        同样复制。summary Entry 不含可变容器字段，其 custom_fields 为空列表，
        故浅层 replace 已足够。
        """
        # dict(TypedDict) 在 mypy 下退化为 dict[str, object]，丢失 TypedDict 类型，
        # cast 标注此复制边界（TypedDict 的已知类型限制，非兼容代码）。
        cache = cast('SecurityReport', dict(cache))
        if days != self._analysis_cache_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cache['old_entries'] = [
                s for s, dt in cache.get('_summaries_with_dates', [])
                if dt is not None and dt < cutoff
            ]
            cache['old'] = len(cache['old_entries'])
            # 更新已生效的 days，使后续相同 days 命中跳过重复 O(n) 过滤。
            # 持 _cache_lock 调用，写自亦受同一锁保护，无额外竞态。
            self._analysis_cache_days = days
        # 出口复制：列表新建，Entry 用 dataclasses.replace 创建独立实例，
        # 防止调用方修改返回对象污染缓存中的共享 Entry。
        if 'weak_entries' in cache:
            cache['weak_entries'] = [dataclasses.replace(e) for e in cache['weak_entries']]
        if 'old_entries' in cache:
            cache['old_entries'] = [dataclasses.replace(e) for e in cache['old_entries']]
        if 'duplicate_groups' in cache:
            cache['duplicate_groups'] = [
                [dataclasses.replace(e) for e in group]
                for group in cache['duplicate_groups']
            ]
        # _summaries_with_dates 同样出口复制：返回的 cache 若被调用方修改该列表
        # 会污染缓存本体。元素为 (Entry, datetime) 元组，浅拷贝列表即可。
        if '_summaries_with_dates' in cache:
            cache['_summaries_with_dates'] = list(cache['_summaries_with_dates'])
        return cache

    def _cached_analysis(
        self, days: int = 90, *, cancel_check: Callable[[], bool] | None = None,
    ) -> SecurityReport:
        """带缓存的安全分析。采用缓存分层设计，基础分析不依赖 days 参数。

        缓存有效期由 ``_cache_ttl_seconds`` 控制，默认为
        ``SECURITY_ANALYSIS_CACHE_TTL_SECONDS`` 秒，命中时仅校验主密钥版本
        ``key_epoch`` 与 TTL，不再执行条目计数的 DB 查询。条目增删改由
        ``EntryManager`` 主动调用 ``invalidate_cache`` 失效，TTL 作为最终兜底；
        key_epoch 校验保证改密轮换密钥后缓存自动失效——密码指纹依赖旧主密钥，必须重算。

        缓存命中时不再因 days 不同而 miss。基础分析涵盖弱密码和重复密码两项，
        均不依赖 days；days 变化时仅从缓存的 ``_summaries_with_dates`` 重新过滤
        过期条目，避免重新解密全部密码，其中重复检测的 HMAC 计算是性能瓶颈。
        """
        with self._cache_lock:
            current_epoch = self._vault.key_epoch
            cached = self._analysis_cache
            if (cached is not None
                    and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
                    and cached.get('_key_epoch') == current_epoch):
                return self._refilter_cache(cached, days)
        try:
            result = self.full_analysis(days, cancel_check=cancel_check)
        except VaultLockedError:
            # 分析期间保险库被锁定（并发改密/自动锁），密钥不可用无法完成解密。
            # 返回空报告且不缓存，避免后台线程崩溃；下次解锁后重新计算填充。
            logger.debug("安全分析期间保险库被锁定，返回空报告")
            return {
                'total': 0, 'weak_count': 0, 'weak_entries': [],
                'duplicate_groups': [], 'duplicate_count': 0,
                'old_entries': [], 'old': 0, '_summaries_with_dates': [],
            }
        with self._cache_lock:
            # 双重检查锁：full_analysis 在 _cache_lock 外执行，期间可能已被并发
            # 线程填充。持锁后重新校验缓存，若已被填充且仍有效（TTL 与 key_epoch
            # 不变），直接复用以避免覆盖并消除本线程 full_analysis 的冗余写入。
            cached = self._analysis_cache
            if (cached is not None
                    and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
                    and cached.get('_key_epoch') == current_epoch):
                return self._refilter_cache(cached, days)
            result['_key_epoch'] = current_epoch
            self._analysis_cache = result
            self._analysis_cache_time = time.monotonic()
            self._analysis_cache_days = days
            # 出口复制：与 hit 路径一致，返回经 _refilter_cache 的独立副本，
            # 防止调用方修改返回的列表/Entry 污染缓存本体。
            return self._refilter_cache(result, days)

    def get_cached_report(self, days: int = 90) -> SecurityReport | None:
        """返回仍有效的缓存报告，无缓存或已过期则返回 None。

        缓存有效时不再因 days 不同返回 None。days 变化时仅重新过滤
        过期条目，不触发重新计算。
        """
        with self._cache_lock:
            cached = self._analysis_cache
            if (cached is not None
                    and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds):
                return self._refilter_cache(cached, days)
        return None

    def get_cached_counts(self, days: int = 90) -> SecurityCounts | None:
        """返回缓存计数（total/weak/duplicate/old），无缓存或过期返回 None。

        仅读计数的消费者（状态栏刷新、weak/duplicate 空态的「分析中」判定）用此轻量
        入口，跳过 :meth:`get_cached_report` 经 :meth:`_refilter_cache` 对 weak/old/
        duplicate 列表的 Entry 深拷贝（PERF-2）。``old`` 计数依赖 days：days 与缓存
        days 不同时按 days 过滤 ``_summaries_with_dates`` 的日期计次（O(n) 日期比较，
        无 Entry 深拷贝），其余计数不依赖 days，直接读缓存。
        """
        with self._cache_lock:
            cached = self._analysis_cache
            if (cached is None
                    or (time.monotonic() - self._analysis_cache_time) >= self._cache_ttl_seconds):
                return None
            if days == self._analysis_cache_days:
                old = cached.get('old', 0)
            else:
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                old = sum(
                    1 for _s, dt in cached.get('_summaries_with_dates', [])
                    if dt is not None and dt < cutoff
                )
            return SecurityCounts(
                cached.get('total', 0),
                cached.get('weak_count', 0),
                cached.get('duplicate_count', 0),
                old,
            )

    def get_or_compute_report(
        self, days: int = 90, *, cancel_check: Callable[[], bool] | None = None,
    ) -> SecurityReport:
        """返回缓存报告，若无效则重新计算并缓存。"""
        return self._cached_analysis(days, cancel_check=cancel_check)

    def invalidate_cache(self, password_changed: bool = True) -> None:
        """清除分析缓存，下次访问时将重新计算。

        password_changed 为 False，即非密码字段变更时直接返回：弱密码、重复、过期
        三项分析均仅依赖密码相关字段 strength、password、password_changed_at，
        非密码变更不改变分析结果，复用缓存可避免无谓的全量 HMAC 重算。

        边界：对「从未改过密码」的条目，password_changed_at 为空，过期检测回退
        到 updated_at，修改非密码字段会更新 updated_at，其过期归属可能短暂
        过时，至多延迟一个 TTL 即 ``SECURITY_ANALYSIS_CACHE_TTL_SECONDS`` 秒
        周期后自动修正，对提醒类信息可接受。
        """
        if not password_changed:
            return
        with self._cache_lock:
            self._analysis_cache = None
            self._analysis_cache_time = 0
            # 维持「cache 为 None 时 _analysis_cache_days 必为 0」不变量，与
            # __init__ 初始值对齐，避免下次 _cached_analysis 的 days 比较基于
            # 上次的残留值而误判是否需要重新过滤过期条目。
            self._analysis_cache_days = 0

    def _parse_changed_utc(self, raw: RawEntry) -> datetime | None:
        """解析条目的密码变更时间为 UTC datetime，供过期检测。

        回退顺序 password_changed_at → updated_at → created_at。naive 视为 UTC、
        aware 归一化到 UTC，避免 naive 与 aware cutoff 比较抛 TypeError。解析
        失败返回 None（不计入过期）。
        """
        changed_at_str = (
            raw.password_changed_at or raw.updated_at or raw.created_at
        )
        if not changed_at_str:
            return None
        try:
            changed_utc = datetime.fromisoformat(changed_at_str)
            if changed_utc.tzinfo is None:
                return changed_utc.replace(tzinfo=timezone.utc)
            return changed_utc.astimezone(timezone.utc)
        except (ValueError, TypeError):
            logger.debug('条目 %s 日期解析失败: %s', raw.id, changed_at_str)
            return None

    def full_analysis(
        self, days: int = 90, *, cancel_check: Callable[[], bool] | None = None,
    ) -> SecurityReport:
        """一次性完成所有安全分析，避免重复解密。

        设计说明：此方法始终执行全部三种分析，即弱密码、重复密码和过期密码，
        包括解密所有密码以计算 HMAC 指纹用于重复检测。这是有意为之，
        结果由 ``_cached_analysis`` 缓存 ``_cache_ttl_seconds`` 秒，
        在缓存有效期内只计算一次。缓存分层后，基础分析涵盖弱密码和重复密码，
        不依赖 days 参数；days 变化时仅重新过滤过期条目，避免重新解密全部密码，
        其中重复检测是性能瓶颈。

        警告：此方法执行 O(n) 解密操作，n 为条目数，耗时随条目增长线性增长。
        调用方**必须**在 BackgroundWorker 中执行此方法，不得直接在 UI 线程调用。
        ``SecurityDashboard`` 已通过 ``BackgroundWorker`` 正确处理。

        线程安全说明：此方法内部的数据库读取 ``get_entries`` 发生在
        _cache_lock 之外。这意味着在并发场景下，缓存可能在读取期间失效。
        对于单用户桌面应用，这不是问题，分析操作不会被并发触发。若未来
        引入后台线程定期分析，需在调用方加锁或在方法内持有读锁。
        """
        # 全量分析会持有主密钥副本并逐条解密。整个敏感生命周期都持保险库
        # 操作锁，使 lock() 必须等待分析释放密钥后才能清零并返回，避免后台
        # Worker 超时后在“已锁定”状态继续持有主密钥和明文。
        with self._vault.vault_write_lock():
            # PERF-002：full_analysis 会对每个条目解密（GCM 认证已覆盖密文篡改检测），
            # 且 _classify_entry 经 raw.integrity_error 与解密失败双重判定损坏条目，
            # 故此处跳过 HMAC 验签（与 get_all_tags 对齐），省去全量 HMAC-SHA256 重算。
            entries = self._vault.db.get_entries(
                EntryQuery(include_deleted=False, verify=VerifyMode.SKIP)
            )
            total = len(entries)
            weak_entries = []
            password_map: dict[bytes, list[Entry]] = {}
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            # 保存所有条目的 summary + changed_at_utc，供缓存后不同 days 重新过滤
            _summaries_with_dates: list[tuple[Entry, datetime | None]] = []

            skipped_count = 0
            # 循环外取一次主密钥副本，供重复检测的 HMAC 指纹复用。
            vault_key = self._key
            # 批量路径：循环外一次性 epoch 校验，循环内 _make_summary 经
            # _cached_search_metadata_no_check 避免每条重复加锁（持 vault_write_lock
            # 期间 key_epoch 不变，逐条校验冗余）。
            self._cache.invalidate_if_epoch_changed()
            for idx, raw in enumerate(entries):
                # 周期性检查取消/锁定请求：用户点锁定时 lock() 会 set 取消事件并阻塞等
                # vault 写锁；此处主动中止并抛 VaultLockedError（已被 _cached_analysis
                # 捕获返回空报告），释放写锁让 lock() 尽快完成，避免 UI 冻结与明文驻留。
                # 与改密/重加密/备份的取消探针模式对齐。
                if (idx & _CANCEL_CHECK_MASK) == 0 and (
                    self._vault.is_cancel_requested()
                    or (cancel_check is not None and cancel_check())
                ):
                    raise VaultLockedError('安全分析因锁定/取消请求而中止')
                result = self._classify_entry(raw, vault_key)
                if result.counted_in_skipped:
                    skipped_count += 1
                if result.summary is None:
                    continue
                _summaries_with_dates.append((result.summary, result.changed_utc))
                if result.is_weak:
                    weak_entries.append(result.summary)
                if result.fingerprint is not None:
                    password_map.setdefault(result.fingerprint, []).append(result.summary)

            old_entries = [
                s for s, dt in _summaries_with_dates
                if dt is not None and dt < cutoff
            ]
            duplicate_groups = [g for g in password_map.values() if len(g) > 1]
            duplicate_count = sum(len(g) - 1 for g in duplicate_groups)
            del vault_key

        if skipped_count:
            logger.warning("安全分析共跳过 %d 条损坏条目", skipped_count)

        return {
            'total': total,
            'weak_count': len(weak_entries),
            'weak_entries': weak_entries,
            'duplicate_groups': duplicate_groups,
            'duplicate_count': duplicate_count,
            'old_entries': old_entries,
            'old': len(old_entries),
            '_summaries_with_dates': _summaries_with_dates,  # 缓存分层：供不同 days 重过滤
        }

    def _classify_entry(self, raw: RawEntry, vault_key: bytes) -> _ClassifyResult:
        """对单条目做安全分类（弱/日期/重复指纹），抽取自 full_analysis 循环体。

        返回 :class:`_ClassifyResult`：summary 为 None 表示完全跳过（integrity/摘要
        损坏，不计入 summaries 仅 skipped_count）；fingerprint 为 None 表示无密码或
        解密失败（不计入重复检测，但 summary 仍计入 summaries/weak）。
        """
        if raw.integrity_error:
            logger.debug("安全分析跳过元数据完整性失败条目 id=%s", raw.id)
            return _ClassifyResult(None, None, False, None, True)
        try:
            summary = self._make_summary(raw)
        except EntryIntegrityError:
            logger.debug("安全分析跳过损坏条目 id=%s", raw.id, exc_info=True)
            return _ClassifyResult(None, None, False, None, True)
        changed_utc = self._parse_changed_utc(raw)
        is_weak = (raw.password_strength or 0) <= 1 and bool(raw.password)
        if not raw.password:
            return _ClassifyResult(summary, changed_utc, is_weak, None, False)
        try:
            password = decrypt_field(
                raw.password, vault_key, raw.crypto_id, 'password', strict=True,
            )
        except DecryptionError:
            logger.debug("安全分析跳过损坏条目 id=%s，原因：密码解密失败", raw.id)
            return _ClassifyResult(summary, changed_utc, is_weak, None, True)
        if not password:
            return _ClassifyResult(summary, changed_utc, is_weak, None, False)
        fingerprint = self._password_fingerprint(password, vault_key)
        del password
        return _ClassifyResult(summary, changed_utc, is_weak, fingerprint, False)
