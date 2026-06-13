"""安全分析器，提供弱密码检测、重复密码检测与过期提醒。"""

import dataclasses
import hmac
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.entry_manager import EntryManager
    from ..managers.vault_manager import VaultManager

logger = logging.getLogger(__name__)

from ...exceptions import VaultLockedError
from ...models import Entry
from .crypto_utils import build_entry_summary, decrypt_field, require_vault_key

# 分析缓存存活时间，单位为秒。命中期内复用基础分析与密码指纹结果，
# 避免重复执行 O(n) 解密与 HMAC 计算。条目增删或改密会立即失效缓存，
# 此 TTL 仅控制时间维度的淘汰。跨层时序常量未集中到 UI 层，以避免
# 业务层反向依赖 UI 模块；本常量作为业务层时序参数的命名事实来源。
SECURITY_ANALYSIS_CACHE_TTL_SECONDS = 120


class SecurityAnalyzer:
    """密码安全分析器，提供三项分析维度：

    1. **弱密码检测**：基于已存储的强度评分，筛选评分不大于 1 的条目。
    2. **重复密码检测**：解密密码后计算 HMAC 指纹，按指纹分组找出使用相同
       密码的条目集合。
    3. **过期密码检测**：按 ``password_changed_at`` 等时间字段，筛选超过指定
       天数未修改的条目。

    缓存策略：分析结果默认缓存 ``SECURITY_ANALYSIS_CACHE_TTL_SECONDS`` 秒，
    采用分层设计。基础分析覆盖弱密码与重复密码，不依赖 days 参数；days 变化
    时仅重新过滤过期条目，避免重复解密全部密码。缓存同时校验条目计数与
    主密钥版本，确保数据一致性。
    """

    def __init__(self, vault_manager: 'VaultManager', entry_manager: 'EntryManager | None' = None, cache_ttl_seconds: int = SECURITY_ANALYSIS_CACHE_TTL_SECONDS):
        self._vault = vault_manager
        self._entry_mgr = entry_manager
        self._cache_ttl_seconds = cache_ttl_seconds
        self._analysis_cache: dict | None = None
        self._analysis_cache_time: float = 0
        self._analysis_cache_days: int = 0
        self._cache_lock = threading.Lock()

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def _decrypt(
        self, raw: Entry, field_name: str, value: str, *,
        strict: bool = False, key: bytes | None = None,
    ) -> str:
        if not value:
            return ''
        return decrypt_field(
            value, key or self._key, raw.crypto_id, field_name, strict=strict
        )

    def _make_summary(self, raw: Entry, key: bytes | None = None) -> Entry:
        """只返回分析界面所需字段，避免缓存敏感明文。

        Summary Entry 不含 password/notes/totp_secret/custom_fields 明文，
        仅包含 username，用于重复密码分组的展示。缓存中的 duplicate_groups
        因此不会暴露完整密码明文，仅有 username 和条目元数据。

        后台线程每次 full_analysis 独立解密 username（不读 EntryManager 的
        _username_cache），避免与 UI 线程并发读写该 dict 导致数据竞争。传入
        ``key`` 复用调用方快照的主密钥，与 full_analysis 全程一致。username
        解密用 strict=True：损坏时抛 ValueError 供调用方计入 skipped_count。
        """
        username = self._decrypt(raw, 'username', raw.username, strict=True, key=key)
        return build_entry_summary(raw, username)

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

    def _refilter_cache(self, cache: dict, days: int) -> dict:
        """从缓存副本中按 days 重新过滤过期条目，并返回列表副本。

        提取公共逻辑以消除 _cached_analysis 与 get_cached_report 的 DRY 违规。
        调用方须在持有 _cache_lock 的上下文中调用，且 cache 须为通过 ``dict(cache)`` 创建的浅拷贝。

        返回的每个 Entry 均通过 ``dataclasses.replace`` 创建为独立副本，调用方
        修改其属性不会污染缓存。duplicate_groups 中的每个分组列表与组内 Entry
        同样复制。summary Entry 不含可变容器字段，其 custom_fields 为空列表，
        故浅层 replace 已足够。
        """
        if days != self._analysis_cache_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cache['old_entries'] = [
                s for s, dt in cache.get('_summaries_with_dates', [])
                if dt is not None and dt < cutoff
            ]
            cache['old'] = len(cache['old_entries'])
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
        return cache

    def _cached_analysis(self, days: int = 90) -> dict:
        """带缓存的安全分析。采用缓存分层设计，基础分析不依赖 days 参数。

        缓存有效期由 ``_cache_ttl_seconds`` 控制，默认为
        ``SECURITY_ANALYSIS_CACHE_TTL_SECONDS`` 秒，同时校验条目计数与
        主密钥版本 ``key_epoch``：条目增删或改密轮换密钥时立即失效并重新计算。
        key_epoch 校验作为防御性失效手段，即使某调用点遗漏 invalidate_cache，
        改密后缓存也会因 epoch 变化而自动失效，因为密码指纹依赖旧主密钥，必须重算。

        缓存命中时不再因 days 不同而 miss。基础分析涵盖弱密码和重复密码两项，
        均不依赖 days；days 变化时仅从缓存的 ``_summaries_with_dates`` 重新过滤
        过期条目，避免重新解密全部密码，其中重复检测的 HMAC 计算是性能瓶颈。
        """
        with self._cache_lock:
            current_count = self._vault.db.get_entry_count(include_deleted=True)
            current_epoch = self._vault.key_epoch
            if (self._analysis_cache is not None
                    and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
                    and self._analysis_cache.get('_entry_count') == current_count
                    and self._analysis_cache.get('_key_epoch') == current_epoch):
                result = dict(self._analysis_cache)
                return self._refilter_cache(result, days)
        try:
            result = self.full_analysis(days)
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
            result['_entry_count'] = current_count
            result['_key_epoch'] = current_epoch
            self._analysis_cache = result
            self._analysis_cache_time = time.monotonic()
            self._analysis_cache_days = days
            # 出口复制：与 hit 路径一致，返回经 _refilter_cache 的独立副本，
            # 防止调用方修改返回的列表/Entry 污染缓存本体。
            return self._refilter_cache(dict(result), days)

    def get_cached_report(self, days: int = 90) -> dict | None:
        """返回仍有效的缓存报告，无缓存或已过期则返回 None。

        缓存有效时不再因 days 不同返回 None。days 变化时仅重新过滤
        过期条目，不触发重新计算。
        """
        with self._cache_lock:
            if (self._analysis_cache is not None
                    and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds):
                result = dict(self._analysis_cache)
                return self._refilter_cache(result, days)
        return None

    def get_or_compute_report(self, days: int = 90) -> dict:
        """返回缓存报告，若无效则重新计算并缓存。"""
        return self._cached_analysis(days)

    def invalidate_cache(self, password_changed: bool = True):
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

    def full_analysis(self, days: int = 90) -> dict:
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
        entries = self._vault.db.get_entries(include_deleted=False)
        total = len(entries)
        weak_entries = []
        password_map: dict[bytes, list[Entry]] = {}
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        # 保存所有条目的 summary + changed_at_utc，供缓存后不同 days 重新过滤
        _summaries_with_dates: list[tuple] = []  # summary 与 changed_utc 的配对列表

        skipped_count = 0
        # 循环外取一次主密钥副本，供重复检测的 HMAC 指纹复用，避免逐条密码都经
        # self._key 触发 bytes 复制而累积主密钥驻留面。
        vault_key = self._key
        for raw in entries:
            try:
                summary = self._make_summary(raw, vault_key)
            except ValueError:
                # 容错：跳过单条损坏条目，继续分析其余条目
                logger.debug("安全分析跳过损坏条目 id=%s", raw.id, exc_info=True)
                skipped_count += 1
                continue

            # 解析 changed_at 为 UTC datetime：naive 视为 UTC、aware 归一化到 UTC，
            # 避免 naive 与 aware cutoff 比较抛 TypeError 使整个分析崩溃
            changed_at_str = (
                raw.password_changed_at or raw.updated_at or raw.created_at
            )
            changed_utc = None
            if changed_at_str:
                try:
                    changed_utc = datetime.fromisoformat(changed_at_str)
                    if changed_utc.tzinfo is None:
                        changed_utc = changed_utc.replace(tzinfo=timezone.utc)
                    else:
                        changed_utc = changed_utc.astimezone(timezone.utc)
                except (ValueError, TypeError):
                    logger.debug('条目 %s 日期解析失败: %s', raw.id, changed_at_str)
            _summaries_with_dates.append((summary, changed_utc))

            # 弱密码检测，使用已存储的强度评分，无需解密
            if (raw.password_strength or 0) <= 1 and raw.password:
                weak_entries.append(summary)

            if not raw.password:
                continue

            # 重复检测，需要解密密码以计算 HMAC 指纹
            try:
                password = self._decrypt(
                    raw, 'password', raw.password, strict=True, key=vault_key,
                )
            except ValueError:
                logger.debug("安全分析跳过损坏条目 id=%s，原因：密码解密失败", raw.id)
                skipped_count += 1
                continue
            if not password:
                continue

            fingerprint = self._password_fingerprint(password, vault_key)
            del password  # 显式释放明文密码，缩短驻留时间
            password_map.setdefault(fingerprint, []).append(summary)

        # 从收集的日期数据过滤过期条目，与循环内即时过滤等效，
        # 但允许缓存后对不同 days 参数重新过滤而无需重新解密
        old_entries = [
            s for s, dt in _summaries_with_dates
            if dt is not None and dt < cutoff
        ]
        duplicate_groups = [g for g in password_map.values() if len(g) > 1]
        duplicate_count = sum(len(g) - 1 for g in duplicate_groups)

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
