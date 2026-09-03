"""TOTP 服务：TOTP 生成与状态查询。调用方不接触明文 TOTP secret。

secret 解密与缓存复用缓存层（EntryCacheManager）的单一解密路径
（resolve_totp_secret/store_totp/pop_totp）。依赖 :class:`TotpCacheProtocol` 而非
具体 ``EntryCacheManager``：services 子包保持不反向依赖 managers 的契约，运行时不
import managers，由 ``EntryCacheManager`` 实现协议在构造时注入，守住分层方向。
"""

from typing import Protocol, TypedDict

from ...crypto.totp import TOTPGenerator
from ...exceptions import VaultLockedError


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

    def store_totp(
        self,
        entry_id: int,
        secret: str,
        *,
        data_epoch: str | None = None,
        data_version: int | None = None,
    ) -> bool:
        """预热 TOTP secret 缓存；提供 data_epoch/data_version 时按写入方世代与
        TOTP 域版本（条目粒度）复查后落缓存。返回是否落缓存（False 为拒收）。"""
        ...

    def pop_totp(self, entry_id: int) -> None:
        """失效单条 TOTP secret 缓存。"""
        ...

    @property
    def totp_invalidate_version(self) -> int:
        """当前 TOTP 域失效版本号（解密时点快照通道 + get_state 兜底自采样，SEC-063）。"""
        ...


class TotpService:
    """条目 TOTP 验证码生成与状态查询。"""

    def __init__(self, cache: TotpCacheProtocol):
        # 死依赖删除（ARCH-039「一删三协议」）：原 ``vault: VaultManager`` 参数在
        # 本类全文件零读取（self._vault 仅赋值一次），为永不使用的字段服务的参数、
        # TYPE_CHECKING import 与构造传参一并移除——依赖不该协议化，该删除。
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
        data_epoch: str | None = None,
        data_version: int | None = None,
    ) -> TotpState | None:
        """获取指定条目的 TOTP 完整状态（验证码、倒计时、周期）。

        preloaded_secret：调用方已解密的 totp_secret 明文（如详情面板经 get_entry
        解密得到），传入则直接用并预热缓存，跳过重复解密。为空时走
        resolve_totp_secret 单一解密路径。

        data_epoch：preloaded_secret 的解密世代（SEC-054，补 SEC-044 的 preloaded
        漏点）。预热写入带写入方世代守卫——「secret 解密于恢复前世代、预热晚于恢复
        重臂新世代」时旧世代 secret 不落新世代缓存（TOTP secret 是双因子凭证，跨
        世代驻留泄漏面更大）。调用方应在收到解密条目的时点（而非本方法调用时点）
        快照世代传入，锁内解密与预热间隔越短守卫越严。无 preloaded_secret 时本
        参数无意义（resolve 路径自带 SEC-044 守卫），忽略。

        data_version：preloaded_secret 解密时刻的 TOTP 域失效版本快照（SEC-063 b 层
        真实通道，由 ``EntryManager.get_entry_with_epoch`` 在读锁内与 secret 同刻带
        出，经 detail_panel / TOTPWidget 透传至此）。「解密 → 预热」窗口内发生过
        **本条目**的 TOTP 失效（pop_totp——导入覆盖 prepare 的 evict）或整体失效
        （clear_totp / 任意条目写路径，守卫按条目粒度判定，其他条目的失效不误伤）
        时，旧 secret 被 store_totp 的版本守卫拒收。拒收时 preloaded 即弃用：本
        方法改走 ``_resolve_totp_secret``（DB 重解密，自带 SEC-044 回写守卫）取
        新鲜值计算验证码并顺势重新预热——被拒收的旧 secret 不再参与一次性
        显示/复制。未提供时在此兜底自采样**当前**版本：仅覆盖「本方法调用 →
        store 落缓存」的微秒窗口（自采样与 store 侧比对同源，「解密 → 本方法
        调用」窗口内的失效检测不到），不能替代调用方快照——生产链路
        （detail_panel 预热）均应传入。无 preloaded_secret 时忽略。

        Returns:
            含 code/remaining/period 的字典；条目不存在或无 TOTP 密钥时返回 None。
        """
        self._cache.invalidate_if_epoch_changed()
        if preloaded_secret:
            # SEC-063 兜底（非主通道）：调用方未携带解密时点快照时自采样当前 TOTP
            # 域版本，仅覆盖「本方法调用 → store 落缓存」窗口内并发的单条失效；
            # 「解密 → 本方法调用」窗口内的失效无法经自采样检测——主通道是
            # get_entry_with_epoch 的同刻快照透传（SEC-063 b 层）。
            version = (
                data_version if data_version is not None else self._cache.totp_invalidate_version
            )
            stored = self._cache.store_totp(
                entry_id,
                preloaded_secret,
                data_epoch=data_epoch,
                data_version=version,
            )
            if stored:
                secret = preloaded_secret
            else:
                # 拒收出口（SEC-063 演进，与安全 P3 合并修复）：被守卫拒收的
                # preloaded 属「解密后库已变化」的旧值，旧出口仍以其计算验证码
                # 参与一次性显示/复制；现丢弃改走 resolve 单一解密路径（DB 重解
                # 密），用新鲜值计算并重新预热缓存。resolve 返回空（条目已删/
                # 无 secret/篡改降级）时如实返回 None。
                #
                # 锁定交错守卫（QL-078）：「store 拒收 → resolve」窗口内发生锁定
                # 时 require_vault_key 抛 VaultLockedError——get_state 由 Qt 槽
                # （TOTPWidget._build）同步调用，未捕获异常在 PyQt6 槽内 qFatal；
                # 旧 preloaded 分支（直接用 preloaded）无此异常面，系拒收回退
                # 引入。返回 None 与 TOTPWidget 的 ``if not state: return`` 既有
                # 处理一致。DecryptionError 不捕获：resolve 的解密为非 strict
                # 容错模式（失败归空串），该异常不可达，捕获面按实际收窄。
                try:
                    resolved = self._resolve_totp_secret(entry_id, use_cache=True)
                except VaultLockedError:
                    return None
                if not resolved:
                    return None
                secret = resolved
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
