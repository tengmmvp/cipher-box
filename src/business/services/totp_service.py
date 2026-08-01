"""TOTP 服务：TOTP 生成与状态查询。调用方不接触明文 TOTP secret。

secret 解密与缓存复用缓存层（EntryCacheManager）的单一解密路径
（resolve_totp_secret/store_totp/pop_totp）。依赖 :class:`TotpCacheProtocol` 而非
具体 ``EntryCacheManager``：services 子包保持不反向依赖 managers 的契约，运行时不
import managers，由 ``EntryCacheManager`` 实现协议在构造时注入，守住分层方向。
"""

from typing import TYPE_CHECKING, Protocol, TypedDict

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...crypto.totp import TOTPGenerator


class TotpState(TypedDict):
    """TOTP 完整状态：验证码、剩余秒数、周期，供 detail_panel 显示与刷新定时器。"""

    code: str
    remaining: int
    period: int


class TotpCacheProtocol(Protocol):
    """TOTP secret 缓存的最小协议，解耦 TotpService 与 EntryCacheManager。

    ``EntryCacheManager`` 自然满足此协议，构造时注入。定义协议使 services/ 不必
    运行时 import managers/，守住分层方向。
    """

    def invalidate_if_epoch_changed(self) -> None:
        """key_epoch 变化时清空缓存；TotpService 读取前调用以守卫过期数据。"""
        ...

    def resolve_totp_secret(
        self,
        entry_id: int,
        *,
        use_cache: bool = False,
    ) -> str | None:
        """解析条目 totp_secret 明文；use_cache 为真时读写会话内缓存。"""
        ...

    def store_totp(self, entry_id: int, secret: str) -> None:
        """预热 TOTP secret 缓存。"""
        ...

    def pop_totp(self, entry_id: int) -> None:
        """失效单条 TOTP secret 缓存。"""
        ...


class TotpService:
    """条目 TOTP 验证码生成与状态查询。"""

    def __init__(self, vault: "VaultManager", cache: TotpCacheProtocol):
        self._vault = vault
        self._cache = cache

    def generate(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码，仅解密 totp_secret 避免触发其他敏感字段。

        解密逻辑复用 generate_cached 的单一解密路径避免漂移；区别在于本方法不写入
        会话内缓存（调用方按需自行预热）。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        secret = self._resolve_totp_secret(entry_id)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def generate_cached(self, entry_id: int) -> str | None:
        """生成 TOTP 验证码，复用会话内缓存的 totp_secret（供定时器每秒刷新）。

        缓存命中时跳过 DB 查询与解密仅做 HOTP 计算。以 entry_id 为键，失效途径：
        key_epoch 变化（改密/锁定）整体清空；条目更新改 totp_secret / 删除按 entry_id
        失效。get_state 首次展示时预热，此后全程命中。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        self._cache.invalidate_if_epoch_changed()
        secret = self._resolve_totp_secret(entry_id, use_cache=True)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def get_state(
        self,
        entry_id: int,
        *,
        preloaded_secret: str | None = None,
    ) -> TotpState | None:
        """获取指定条目的 TOTP 完整状态（验证码、倒计时、周期）。

        preloaded_secret：调用方已解密的 totp_secret 明文（如详情面板经 get_entry
        解密得到），传入则直接用并预热缓存，跳过重复解密（P3）。为空时走
        resolve_totp_secret 单一解密路径。

        Returns:
            含 code/remaining/period 的字典；条目不存在或无 TOTP 密钥时返回 None。
        """
        self._cache.invalidate_if_epoch_changed()
        if preloaded_secret:
            secret = preloaded_secret
            self._cache.store_totp(entry_id, secret)
        else:
            # 用临时变量承接 str|None 并收窄后再赋给 secret，避免跨分支类型冲突。
            resolved = self._resolve_totp_secret(entry_id, use_cache=True)
            if not resolved:
                return None
            secret = resolved
        return {
            "code": TOTPGenerator.generate(secret),
            "remaining": TOTPGenerator.get_remaining_seconds(secret=secret),
            "period": TOTPGenerator.get_period(secret),
        }

    def remaining_seconds(self, period: int) -> int:
        """当前时间步长剩余秒数，供 TOTP 定时器倒计时刷新。

        纯时间计算（不查 DB/不解密）。经本服务暴露使 TOTPWidget 不直接依赖 crypto 层，
        守住 UI→Business→Crypto 分层方向。
        """
        return TOTPGenerator.get_remaining_seconds(period=period)

    def evict(self, entry_id: int) -> None:
        """清理指定条目的 TOTP secret 明文缓存。

        供详情面板切换/清空条目时调用，避免 TOTP secret（双因子凭证）离开条目后
        长期驻留缓存——泄露可独立生成验证码绕过 2FA。锁定/改密由缓存层整体失效兜底，
        此处覆盖「保险库仍解锁但用户已离开条目」的窗口。
        """
        self._cache.pop_totp(entry_id)

    def _resolve_totp_secret(
        self,
        entry_id: int,
        *,
        use_cache: bool = False,
    ) -> str | None:
        """解析条目的 totp_secret 明文，单一解密路径供 TOTP 方法复用。委托 cache。"""
        return self._cache.resolve_totp_secret(entry_id, use_cache=use_cache)
