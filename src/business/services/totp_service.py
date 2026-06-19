"""TOTP 服务 — 从 EntryManager 抽离的 TOTP 生成与状态查询。

UI→Business 迁移，调用方不接触明文 TOTP secret。secret 解密与缓存复用
EntryCacheManager 的单一解密路径（resolve_totp_secret/store_totp/pop_totp），
避免与 EntryManager 其它缓存失效逻辑耦合。
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...crypto.totp import TOTPGenerator
from ..managers.entry_cache import EntryCacheManager


class TotpService:
    """条目 TOTP 验证码生成与状态查询。"""

    def __init__(self, vault: 'VaultManager', cache: EntryCacheManager):
        self._vault = vault
        self._cache = cache

    def generate(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码。

        仅解密 totp_secret 字段，避免触发 password/notes/custom_fields
        等其他敏感字段的不必要解密。

        解密逻辑复用 generate_cached 的单一解密路径，避免两份独立的
        解密与空值判断逻辑漂移。与 generate_cached 的区别：本方法
        不写入会话内 totp_secret 缓存（调用方按需自行预热）。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        secret = self._resolve_totp_secret(entry_id)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def generate_cached(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码，复用会话内缓存的 totp_secret。

        与 generate 的区别：缓存命中时跳过 DB 查询与 AESGCM 解密，
        仅做纯 HOTP 计算，供 TOTP 定时器每秒刷新调用。缓存以 entry_id 为键，
        由以下途径失效：
        - key_epoch 变化（改密/锁定）：整体清空（cache.invalidate_if_epoch_changed）。
        - 条目更新修改 totp_secret：按 entry_id 失效（update_entry）。
        - 条目删除：按 entry_id 失效（delete_entry / permanent_delete_entry）。
        get_state 在条目首次展示时预热缓存，此后定时器全程命中缓存。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        self._cache.invalidate_if_epoch_changed()
        secret = self._resolve_totp_secret(entry_id, use_cache=True)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def get_state(self, entry_id: int) -> dict | None:
        """获取指定条目的 TOTP 完整状态，含验证码、倒计时和周期。

        仅解密 totp_secret 字段，供 detail_panel 的 TOTP 显示和刷新定时器使用。
        首次调用时将解密后的 secret 写入 totp_secret 缓存，使后续
        generate_cached 命中缓存，避免定时器每秒重复解密。

        Returns:
            包含验证码 code、剩余秒数 remaining、周期 period 三个键的字典；
            条目不存在或无 TOTP 密钥时返回 None。
        """
        self._cache.invalidate_if_epoch_changed()
        raw = self._vault.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        from .crypto_utils import decrypt_field, require_vault_key

        secret = decrypt_field(raw.totp_secret, require_vault_key(self._vault), raw.crypto_id, 'totp_secret')
        if not secret:
            return None
        # 预热缓存，供 generate_cached 复用。
        self._cache.store_totp(entry_id, secret)
        return {
            'code': TOTPGenerator.generate(secret),
            'remaining': TOTPGenerator.get_remaining_seconds(secret=secret),
            'period': TOTPGenerator.get_period(secret),
        }

    def evict(self, entry_id: int) -> None:
        """清理指定条目的 TOTP secret 明文缓存。

        供详情面板在切换条目或清空时调用，避免用户离开条目后 TOTP secret
        （双因子凭证）长期驻留缓存——泄露可独立生成验证码绕过 2FA。锁定/改密
        由缓存层整体失效（invalidate_all）兜底，此处覆盖「保险库仍解锁但用户
        已离开该条目」的窗口。
        """
        self._cache.pop_totp(entry_id)

    def _resolve_totp_secret(
        self, entry_id: int, *, use_cache: bool = False,
    ) -> str | None:
        """解析条目的 totp_secret 明文，单一解密路径供 TOTP 方法复用。委托 cache。"""
        return self._cache.resolve_totp_secret(entry_id, use_cache=use_cache)
