"""安全分析器 - 弱密码检测、重复密码检测、过期提醒"""

import hmac
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .entry_manager import EntryManager
    from .vault_manager import VaultManager

logger = logging.getLogger(__name__)

from ..database.models import Entry
from .crypto_utils import build_entry_summary, decrypt_field, require_vault_key
from .exceptions import EntryIntegrityError


class SecurityAnalyzer:
    """密码安全分析"""

    _CACHE_TTL_SECONDS = 120  # 默认缓存有效期（秒），实例可通过 cache_ttl_seconds 参数覆盖

    def __init__(self, vault_manager: 'VaultManager', entry_manager: 'EntryManager | None' = None, cache_ttl_seconds: int = 120):
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

    def _decrypt(self, raw: Entry, field_name: str, value: str) -> str:
        if not value:
            return ''
        return decrypt_field(value, self._key, raw.crypto_id, field_name)

    def _make_summary(self, raw: Entry) -> Entry:
        """只返回分析界面所需字段，避免缓存敏感明文。

        Summary Entry 不含 password/notes/totp_secret/custom_fields 明文，
        仅包含 username（用于重复密码分组的展示）。缓存中的 duplicate_groups
        因此不会暴露完整密码明文，仅有 username 和条目元数据。
        """
        if self._entry_mgr is not None:
            username = self._entry_mgr.get_cached_username(raw)
        else:
            username = self._decrypt(raw, 'username', raw.username)
        return build_entry_summary(raw, username)

    def _password_fingerprint(self, password: str) -> bytes:
        """使用主密钥生成密码指纹，用于去重检测。

        权衡说明：使用主密钥意味着主密码变更后指纹失效（缓存自然淘汰，120s TTL）。
        优点是无需额外存储独立 HMAC 密钥；指纹不出本进程，安全性依赖主密钥保护。
        """
        return hmac.digest(self._key, password.encode('utf-8'), 'sha256')

    def find_weak_passwords(self) -> list[Entry]:
        """查找弱密码条目（强度评分 <= 1）。"""
        return self._cached_analysis()['weak_entries']

    def find_duplicate_passwords(self) -> list[list[Entry]]:
        """查找重复密码（返回分组列表，每组包含使用相同密码的条目）"""
        return self._cached_analysis()['duplicate_groups']

    def find_old_passwords(self, days: int = 90) -> list[Entry]:
        """查找超过指定天数未修改的条目"""
        return self._cached_analysis(days)['old_entries']

    def _refilter_cache(self, cache: dict, days: int) -> dict:
        """从缓存副本中按 days 重新过滤过期条目，并返回列表副本。

        提取公共逻辑以消除 _cached_analysis 与 get_cached_report 的 DRY 违规。
        调用方须在持有 _cache_lock 的上下文中调用，且 cache 须为浅拷贝（dict(cache)）。

        注意：返回的 Entry 对象为缓存中的共享引用（summary Entry 无敏感字段）。
        调用方应将返回的 Entry 视为只读，不应修改其属性，否则会污染缓存。
        若未来需要可变返回值，应在此处改用 dataclasses.replace 创建深拷贝。
        """
        if days != self._analysis_cache_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cache['old_entries'] = [
                s for s, dt in cache.get('_summaries_with_dates', [])
                if dt is not None and dt < cutoff
            ]
            cache['old'] = len(cache['old_entries'])
        for key in ('weak_entries', 'duplicate_groups', 'old_entries'):
            if key in cache:
                cache[key] = list(cache[key])
        return cache

    def _cached_analysis(self, days: int = 90) -> dict:
        """带缓存的安全分析（L16 缓存分层：基础分析不依赖 days）。

        缓存有效期由 _CACHE_TTL_SECONDS（120 秒）控制，同时校验条目计数与
        主密钥版本（key_epoch）：条目增删或改密轮换密钥时立即失效并重新计算。
        M-S4：key_epoch 校验作为防御性失效——即使某调用点遗漏 invalidate_cache，
        改密后缓存也会因 epoch 变化而自动失效（密码指纹依赖旧主密钥，必须重算）。

        L16：缓存命中时不再因 days 不同而 miss。基础分析（弱密码、重复密码）
        不依赖 days；days 变化时仅从缓存的 ``_summaries_with_dates`` 重新过滤
        过期条目，避免重新解密全部密码（重复检测的 HMAC 计算是性能瓶颈）。
        """
        with self._cache_lock:
            current_count = self._vault.db.get_entry_count()
            current_epoch = self._vault.key_epoch
            if (self._analysis_cache is not None
                    and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds
                    and self._analysis_cache.get('_entry_count') == current_count
                    and self._analysis_cache.get('_key_epoch') == current_epoch):
                result = dict(self._analysis_cache)
                return self._refilter_cache(result, days)
        result = self.full_analysis(days)
        with self._cache_lock:
            result['_entry_count'] = current_count
            result['_key_epoch'] = current_epoch
            self._analysis_cache = result
            self._analysis_cache_time = time.monotonic()
            self._analysis_cache_days = days
            return result

    def get_cached_report(self, days: int = 90) -> dict | None:
        """返回仍有效的缓存报告，无缓存或已过期则返回 None。

        L16：缓存有效时不再因 days 不同返回 None。days 变化时仅重新过滤
        过期条目（不触发重新计算）。
        """
        with self._cache_lock:
            if (self._analysis_cache is not None
                    and (time.monotonic() - self._analysis_cache_time) < self._cache_ttl_seconds):
                result = dict(self._analysis_cache)
                return self._refilter_cache(result, days)
        return None

    def get_or_compute_report(self, days: int = 90) -> dict:
        """Return cached report if valid, otherwise compute and cache a new one."""
        return self._cached_analysis(days)

    def invalidate_cache(self):
        """Clear the analysis cache to force recomputation on next access."""
        with self._cache_lock:
            self._analysis_cache = None
            self._analysis_cache_time = 0

    def full_analysis(self, days: int = 90) -> dict:
        """一次性完成所有安全分析，避免重复解密。

        设计说明：此方法始终执行全部三种分析（弱密码、重复密码、过期密码），
        包括解密所有密码以计算 HMAC 指纹用于重复检测。这是有意为之——
        结果由 _cached_analysis 缓存 120 秒（_CACHE_TTL_SECONDS），
        在缓存有效期内只计算一次。L16 缓存分层后，基础分析（弱密码、重复
        密码）不依赖 days 参数；days 变化时仅重新过滤过期条目，避免重新
        解密全部密码（重复检测是性能瓶颈）。

        .. warning::
           此方法执行 O(n) 解密操作（n = 条目数），耗时随条目增长线性增长。
           调用方**必须**在 BackgroundWorker 中执行此方法，不得直接在 UI 线程调用。
           ``SecurityDashboard`` 已通过 ``BackgroundWorker`` 正确处理。

        线程安全说明：此方法内部的数据库读取（get_entries）发生在
        _cache_lock 之外。这意味着在并发场景下，缓存可能在读取期间失效。
        对于单用户桌面应用，这不是问题——分析操作不会被并发触发。若未来
        引入后台线程定期分析，需在调用方加锁或在方法内持有读锁。
        """
        entries = self._vault.db.get_entries(include_deleted=False)
        total = len(entries)
        weak_entries = []
        password_map: dict[bytes, list[Entry]] = {}
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        # L16：保存所有条目的 summary + changed_at_utc，供缓存后不同 days 重新过滤
        _summaries_with_dates: list[tuple] = []  # [(summary, changed_utc | None)]

        for raw in entries:
            try:
                summary = self._make_summary(raw)
            except ValueError as exc:
                raise EntryIntegrityError(
                    f'条目 {raw.id} 安全分析失败，数据可能已损坏'
                ) from exc

            # 解析 changed_at 为 UTC datetime（统一处理 naive/aware）
            changed_at_str = (
                raw.password_changed_at or raw.updated_at or raw.created_at
            )
            changed_utc = None
            if changed_at_str:
                try:
                    changed_utc = datetime.fromisoformat(changed_at_str)
                    if changed_utc.tzinfo is not None:
                        changed_utc = changed_utc.astimezone(timezone.utc)
                except (ValueError, TypeError):
                    logger.debug('条目 %s 日期解析失败: %s', raw.id, changed_at_str)
            _summaries_with_dates.append((summary, changed_utc))

            # Weak password detection (uses stored strength score, no decryption)
            if (raw.password_strength or 0) <= 1 and raw.password:
                weak_entries.append(summary)

            # Skip entries without passwords for duplicate detection
            if not raw.password:
                continue

            # Duplicate detection (requires decryption for HMAC fingerprint)
            try:
                password = self._decrypt(raw, 'password', raw.password)
            except ValueError as exc:
                raise EntryIntegrityError(
                    f'条目 {raw.id} 安全分析失败，数据可能已损坏'
                ) from exc
            if not password:
                continue

            fingerprint = self._password_fingerprint(password)
            del password  # 显式释放明文密码，缩短驻留时间
            password_map.setdefault(fingerprint, []).append(summary)

        # L16：从收集的日期数据过滤过期条目（与循环内即时过滤等效，
        # 但允许缓存后对不同 days 参数重新过滤而无需重新解密）
        old_entries = [
            s for s, dt in _summaries_with_dates
            if dt is not None and dt < cutoff
        ]
        duplicate_groups = [g for g in password_map.values() if len(g) > 1]
        duplicate_count = sum(len(g) - 1 for g in duplicate_groups)

        return {
            'total': total,
            'weak_count': len(weak_entries),
            'weak_entries': weak_entries,
            'duplicate_groups': duplicate_groups,
            'duplicate_count': duplicate_count,
            'old_entries': old_entries,
            'old': len(old_entries),
            '_summaries_with_dates': _summaries_with_dates,  # L16：缓存分层
        }
