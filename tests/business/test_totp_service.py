"""``TotpService`` 子域服务测试。

覆盖 ``src/business/services/totp_service.py``：generate / generate_cached /
get_state / evict 的缓存命中/未命中/驱逐行为与对 ``TotpCacheProtocol`` 的委托。
经 MagicMock 注入 cache（满足 ``TotpCacheProtocol``），不触真实 DB 与解密。
"""

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from src.business.services.totp_service import TotpService

if TYPE_CHECKING:
    from src.business.managers.entry_cache import EntryCacheManager

_VALID_SECRET = "JBSWY3DPEHPK3PXP"  # 10 字节 base32，满足 validate_secret 下限


def _make_service() -> tuple[TotpService, MagicMock]:
    """构造 TotpService + 其 cache mock，便于断言缓存调用。

    单参构造（ARCH-039 死依赖删除后无 vault 参数）。
    """
    cache = MagicMock()
    return TotpService(cache), cache


def _make_service_with_real_cache(epoch: str) -> tuple[TotpService, "EntryCacheManager"]:
    """构造 TotpService + 真实 EntryCacheManager（stub vault 仅提供 key_epoch）。

    供写入方世代（SEC-054）与 TOTP 域版本快照（SEC-063）守卫测试共用：拒收
    「旧世代/旧版本值不落缓存」的行为语义须真实缓存才能断言，MagicMock 只能
    断言委托调用。
    """
    from src.business.managers.entry_cache import EntryCacheManager

    vault = type("StubVault", (), {"key_epoch": epoch})()
    cache = EntryCacheManager(vault)  # type: ignore[arg-type]
    return TotpService(cache), cache


class TestGenerate:
    """generate 直生验证码：合法 secret 返回 6 位码，无/空 secret 返回 None。"""

    def test_generate_returns_six_digit_code_for_valid_secret(self):
        """合法 secret 经 generate 返回 6 位验证码（不经会话缓存写入）。"""
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = _VALID_SECRET

        code = svc.generate(7)

        assert len(code) == 6 and code.isdigit()
        # generate 不使用会话缓存（use_cache=False）
        cache.resolve_totp_secret.assert_called_once_with(7, use_cache=False)

    def test_generate_returns_none_when_no_secret(self):
        """条目无 TOTP secret（缓存返回 None）→ generate 返回 None。"""
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = None

        assert svc.generate(1) is None

    def test_generate_returns_none_for_empty_secret(self):
        """空 secret → None（TOTPGenerator.generate('') 返回 ''，被 falsy 命中）。"""
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = ""

        assert svc.generate(1) is None


class TestGenerateCached:
    """generate_cached 经会话缓存生码：先做 epoch 失效检查再走缓存解析。"""

    def test_generate_cached_uses_session_cache(self):
        """generate_cached 走会话缓存（use_cache=True）并先做 epoch 失效检查。"""
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = _VALID_SECRET

        code = svc.generate_cached(3)

        assert len(code) == 6 and code.isdigit()
        cache.invalidate_if_epoch_changed.assert_called_once()
        cache.resolve_totp_secret.assert_called_once_with(3, use_cache=True)

    def test_generate_cached_returns_none_when_resolved_empty(self):
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = None
        assert svc.generate_cached(1) is None


class TestGetState:
    """get_state 状态组装：preloaded 预热、resolve 回填与无/空 secret 的空值返回。"""

    def test_get_state_with_preloaded_secret_stores_and_returns_state(self):
        """preloaded_secret 非空时直接使用并预热缓存，返回完整状态。"""
        svc, cache = _make_service()

        state = svc.get_state(9, preloaded_secret=_VALID_SECRET)

        assert state is not None
        assert set(state) == {"code", "remaining", "period"}
        assert len(state["code"]) == 6 and state["code"].isdigit()
        assert 1 <= state["remaining"] <= state["period"]
        assert state["period"] == 30  # 默认周期
        cache.store_totp.assert_called_once_with(
            9, _VALID_SECRET, data_epoch=None, data_version=cache.totp_invalidate_version
        )

    def test_get_state_without_preloaded_resolves_via_cache(self):
        """无 preloaded_secret 时走 resolve_totp_secret（use_cache=True）。"""
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = _VALID_SECRET

        state = svc.get_state(2)

        assert state is not None
        cache.resolve_totp_secret.assert_called_once_with(2, use_cache=True)
        cache.store_totp.assert_not_called()

    def test_get_state_returns_none_when_no_secret(self):
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = None

        assert svc.get_state(5) is None

    def test_get_state_ignores_empty_preloaded(self):
        """preloaded_secret='' 视为未提供，走 resolve 路径。"""
        svc, cache = _make_service()
        cache.resolve_totp_secret.return_value = _VALID_SECRET

        state = svc.get_state(5, preloaded_secret="")

        assert state is not None
        cache.resolve_totp_secret.assert_called_once_with(5, use_cache=True)

    def test_get_state_preloaded_forwards_data_epoch(self):
        """preloaded 预热写入透传写入方世代（SEC-054），由缓存侧复查后落缓存。"""
        svc, cache = _make_service()

        state = svc.get_state(9, preloaded_secret=_VALID_SECRET, data_epoch="epoch-a")

        assert state is not None
        cache.store_totp.assert_called_once_with(
            9,
            _VALID_SECRET,
            data_epoch="epoch-a",
            data_version=cache.totp_invalidate_version,
        )

    def test_get_state_preloaded_forwards_data_version(self):
        """preloaded 预热写入透传 TOTP 域版本快照（SEC-063），由缓存侧复查后落缓存。"""
        svc, cache = _make_service()

        state = svc.get_state(9, preloaded_secret=_VALID_SECRET, data_version=7)

        assert state is not None
        cache.store_totp.assert_called_once_with(9, _VALID_SECRET, data_epoch=None, data_version=7)


class TestPreloadedEpochGuard:
    """preloaded 路径的写入方世代守卫（SEC-054，补 SEC-044 的 preloaded 漏点）。

    经真实 EntryCacheManager（stub vault 仅提供 key_epoch）验证行为语义：
    「secret 解密于恢复前世代、预热晚于恢复重臂新世代」时旧世代 secret
    不落新世代缓存；同世代写入正常落缓存。
    """

    def test_stale_epoch_preloaded_write_is_rejected(self):
        """旧世代 preloaded secret 不写入新世代缓存（跨恢复窗口回归守护）。"""
        svc, cache = _make_service_with_real_cache("epoch-new")
        cache.invalidate_if_epoch_changed()  # 模拟恢复后新读路径重臂缓存世代
        assert cache.cache_epoch == "epoch-new"  # 公开观察面（MAINT-095）

        # secret 解密于恢复前世代（epoch-old），恢复提交后预热：写入被拒
        state = svc.get_state(11, preloaded_secret=_VALID_SECRET, data_epoch="epoch-old")

        assert state is not None  # 本次展示仍用 preloaded 值（不阻断 UI）
        assert 11 not in cache._totp_secret_cache  # 但不得污染新世代缓存

    def test_current_epoch_preloaded_write_is_stored(self):
        """同世代 preloaded secret 正常落缓存（对照：守卫不误伤正常路径）。"""
        svc, cache = _make_service_with_real_cache("epoch-cur")
        cache.invalidate_if_epoch_changed()

        state = svc.get_state(12, preloaded_secret=_VALID_SECRET, data_epoch="epoch-cur")

        assert state is not None
        assert cache._totp_secret_cache.get(12) == _VALID_SECRET


class TestPreloadedVersionGuard:
    """preloaded 路径的 TOTP 域版本快照守卫（SEC-063，镜像 SEC-044 补 store 侧缺口）。

    场景：secret 解密时刻采样版本 → 窗口内单条 TOTP 失效（pop_totp，如导入覆盖
    prepare 阶段 worker 线程的 evict）→ store 携旧快照到达——旧 secret 属已被
    失效的值，拒收入缓存（epoch 守卫检测不到该失效：pop 不改世代）。
    """

    def test_stale_version_preloaded_write_is_rejected(self):
        """pop 后窗口内到达的预热写入被拒收（版本快照失配，SEC-063）。"""
        svc, cache = _make_service_with_real_cache("epoch-stable")
        cache.invalidate_if_epoch_changed()
        # 解密时刻采样版本（同世代，epoch 守卫的对照面）
        sampled_version = cache.totp_invalidate_version
        # 「解密 → 预热」窗口内：导入覆盖 prepare 的 evict（pop 只推进 TOTP 域，
        # 不改 epoch——epoch 守卫对本失效盲）
        cache.pop_totp(11)

        state = svc.get_state(
            11,
            preloaded_secret=_VALID_SECRET,
            data_epoch="epoch-stable",
            data_version=sampled_version,
        )

        assert state is not None  # 本次展示仍用 preloaded 值（不阻断 UI）
        assert 11 not in cache._totp_secret_cache  # 旧值不得回写缓存

    def test_current_version_preloaded_write_is_stored(self):
        """版本未变（无失效插入）时预热正常落缓存（对照：守卫不误伤正常路径）。"""
        svc, cache = _make_service_with_real_cache("epoch-stable")
        cache.invalidate_if_epoch_changed()
        sampled_version = cache.totp_invalidate_version

        state = svc.get_state(
            12,
            preloaded_secret=_VALID_SECRET,
            data_epoch="epoch-stable",
            data_version=sampled_version,
        )

        assert state is not None
        assert cache._totp_secret_cache.get(12) == _VALID_SECRET

    def test_store_without_version_falls_back_to_self_sampling(self):
        """未提供 data_version 时兜底自采样：仅覆盖 get_state→store 微秒窗口。

        pop 发生在 get_state **之前**时自采样取的是已推进版本，比对恒等、写入放行
        ——这是兜底的已知局限（SEC-063 b 层主通道要求调用方携带解密时点快照，
        生产链路经 get_entry_with_epoch 透传，见 test_entry_batch_writer 的
        TestStalePreloadedSecretRejected）。
        """
        svc, cache = _make_service_with_real_cache("epoch-stable")
        cache.invalidate_if_epoch_changed()
        cache.pop_totp(13)  # pop 先于 get_state：自采样取已推进版本，窗口外失效不可见

        state = svc.get_state(13, preloaded_secret=_VALID_SECRET, data_epoch="epoch-stable")

        assert state is not None
        assert cache._totp_secret_cache.get(13) == _VALID_SECRET


class TestEvictAndRemaining:
    """evict 委托清理与 remaining_seconds 纯时间计算。"""

    def test_evict_delegates_to_cache_pop(self):
        """evict 委托 cache.pop_totp 清理单条 TOTP secret 明文缓存。"""
        svc, cache = _make_service()

        svc.evict(42)

        cache.pop_totp.assert_called_once_with(42)

    def test_remaining_seconds_pure_time_calculation(self):
        """remaining_seconds 不查 DB / 不解密，纯时间计算委托 TOTPGenerator。"""
        svc, _ = _make_service()
        remaining = svc.remaining_seconds(30)
        assert 1 <= remaining <= 30


def test_generate_cached_and_generate_share_decode_path():
    """generate 与 generate_cached 仅缓存写入语义不同，同一 secret 产出相同码。"""
    svc1, cache1 = _make_service()
    svc2, cache2 = _make_service()
    cache1.resolve_totp_secret.return_value = _VALID_SECRET
    cache2.resolve_totp_secret.return_value = _VALID_SECRET

    assert svc1.generate(1) == svc2.generate_cached(1)
