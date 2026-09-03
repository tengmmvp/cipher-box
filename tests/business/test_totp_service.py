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
    """构造 TotpService + 真实 EntryCacheManager（stub vault 提供最小读路径）。

    供写入方世代（SEC-054）与 TOTP 域版本快照（SEC-063）守卫测试共用：拒收
    「旧世代/旧版本值不落缓存」的行为语义须真实缓存才能断言，MagicMock 只能
    断言委托调用。stub 的 ``db.get_entry`` 恒返回 None——preloaded 被守卫拒收后
    get_state 回退 resolve 在 stub 上走「条目不存在」分支返回 None，被测的是
    拒收行为（旧值不落缓存），不依赖回退取值。
    """
    from contextlib import contextmanager
    from types import SimpleNamespace

    from src.business.managers.entry_cache import EntryCacheManager

    @contextmanager
    def _stub_guarded_read():
        yield

    vault = type(
        "StubVault",
        (),
        {
            "key_epoch": epoch,
            # staticmethod 防 type() 类字典中的普通函数被绑定为方法（绑定时实例
            # 会被作为首参传入 _stub_guarded_read 的 *args 转发链致 TypeError）。
            "epoch_guarded_read": staticmethod(_stub_guarded_read),
            "db": SimpleNamespace(get_entry=lambda entry_id: None),
        },
    )()
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

    经真实 EntryCacheManager（stub vault 提供最小读路径）验证行为语义：
    「secret 解密于恢复前世代、预热晚于恢复重臂新世代」时旧世代 secret
    不落新世代缓存；同世代写入正常落缓存。
    """

    def test_stale_epoch_preloaded_write_is_rejected(self):
        """旧世代 preloaded secret 不写入新世代缓存（跨恢复窗口回归守护）。"""
        svc, cache = _make_service_with_real_cache("epoch-new")
        cache.invalidate_if_epoch_changed()  # 模拟恢复后新读路径重臂缓存世代
        assert cache.cache_epoch == "epoch-new"  # 公开观察面（MAINT-095）

        # secret 解密于恢复前世代（epoch-old），恢复提交后预热：写入被拒，
        # preloaded 弃用（拒收出口，SEC-063 演进）——回退 resolve 在 stub 的
        # 「无条目」分支返回 None（生产路径会 DB 重解密新值计算验证码）
        state = svc.get_state(11, preloaded_secret=_VALID_SECRET, data_epoch="epoch-old")

        assert state is None
        assert 11 not in cache._totp_secret_cache  # 但不得污染新世代缓存

    def test_current_epoch_preloaded_write_is_stored(self):
        """同世代 preloaded secret 正常落缓存（对照：守卫不误伤正常路径）。"""
        svc, cache = _make_service_with_real_cache("epoch-cur")
        cache.invalidate_if_epoch_changed()

        state = svc.get_state(12, preloaded_secret=_VALID_SECRET, data_epoch="epoch-cur")

        assert state is not None
        assert cache._totp_secret_cache.get(12) == _VALID_SECRET


class TestPreloadedVersionGuard:
    """preloaded 路径的 TOTP 域版本快照守卫（SEC-063，镜像 SEC-044 补 store 侧缺口，
    守卫粒度按条目）。

    场景：secret 解密时刻采样版本 → 窗口内**本条目** TOTP 失效（pop_totp，如
    导入覆盖 prepare 阶段 worker 线程的 evict）或整体失效 → store 携旧快照到达
    ——旧 secret 属已被失效的值，拒收入缓存（epoch 守卫检测不到该失效：pop 不改
    世代）。守卫按条目粒度判定：其他条目的 evict（TOTP→TOTP 切换）不误伤本条目。
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

        # 拒收后 preloaded 弃用，回退 resolve 在 stub 的「无条目」分支返回 None
        assert state is None
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

    def test_totp_to_totp_switch_preload_accepted(self):
        """TOTP→TOTP 切换：对上一条目的 evict 不再拒收新条目的预热（SEC-063 守卫
        粒度修复的核心场景）。

        时序复刻 do_select_entry 链路：get_entry_with_epoch 锁内快照版本 →
        show_entry 的 _prepare_display 对**上一条目** pop_totp（全局版本推进）→
        _render_totp_and_history 带快照预热新条目。原守卫比对全局版本恒失配
        （时序自冲突），新条目 preloaded secret 永远进不了缓存；改条目粒度后
        正常落缓存，_refresh 定时器全程命中免重解密。
        """
        svc, cache = _make_service_with_real_cache("epoch-stable")
        cache.invalidate_if_epoch_changed()
        sampled_version = cache.totp_invalidate_version
        cache.pop_totp(99)  # 离开上一条目的 evict（与条目 11 无关）

        state = svc.get_state(
            11,
            preloaded_secret=_VALID_SECRET,
            data_epoch="epoch-stable",
            data_version=sampled_version,
        )

        assert state is not None
        assert cache._totp_secret_cache.get(11) == _VALID_SECRET

    def test_revisit_after_own_pop_accepted(self):
        """A→B→A 往返重访：快照晚于自身失效的预热被接受（单条版本水位语义）。"""
        svc, cache = _make_service_with_real_cache("epoch-stable")
        cache.invalidate_if_epoch_changed()
        cache.pop_totp(11)  # A→B 切换时对 A 的 evict
        sampled_version = cache.totp_invalidate_version  # B→A 重访快照（晚于 A 的失效）
        cache.pop_totp(12)  # 离开 B 的 evict（全局版本再推进）

        state = svc.get_state(
            11,
            preloaded_secret=_VALID_SECRET,
            data_epoch="epoch-stable",
            data_version=sampled_version,
        )

        assert state is not None
        assert cache._totp_secret_cache.get(11) == _VALID_SECRET

    def test_global_invalidation_after_snapshot_still_rejected(self):
        """整体失效（任意条目写路径）后的旧快照仍被整体拒收（全局口径保持）。"""
        svc, cache = _make_service_with_real_cache("epoch-stable")
        cache.invalidate_if_epoch_changed()
        sampled_version = cache.totp_invalidate_version
        cache.apply_change(crypto_id="other-entry")  # 整体失效：版本推进 + 水位前移

        state = svc.get_state(
            11,
            preloaded_secret=_VALID_SECRET,
            data_epoch="epoch-stable",
            data_version=sampled_version,
        )

        # 拒收 + 回退 resolve（stub 无条目）→ None；旧值不得回写缓存
        assert state is None
        assert 11 not in cache._totp_secret_cache

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


class TestPreloadedRejectedFallsBackToResolve:
    """拒收出口（SEC-063 演进，与安全 P3 合并修复）：被守卫拒收的 preloaded
    丢弃，改走 resolve 单一解密路径（DB 重解密）计算验证码——修复「被拒收的
    旧 secret 仍参与一次性显示/复制」的出口。"""

    _FRESH_SECRET = "KRSXG5CTMVRXEZLU"  # 回退 resolve 取到的新值

    def test_rejected_preloaded_re_resolves_fresh_secret(self):
        """拒收后回退 resolve：验证码由新 secret 计算，resolve 走 use_cache=True。"""
        from src.crypto.totp import TOTPGenerator

        svc, cache = _make_service()
        cache.store_totp.return_value = False
        cache.resolve_totp_secret.return_value = self._FRESH_SECRET

        state = svc.get_state(9, preloaded_secret=_VALID_SECRET, data_epoch="e", data_version=3)

        assert state is not None
        assert state["code"] == TOTPGenerator.generate(self._FRESH_SECRET)
        cache.resolve_totp_secret.assert_called_once_with(9, use_cache=True)

    def test_rejected_preloaded_returns_none_when_resolve_empty(self):
        """回退 resolve 无值（条目已删/无 secret/篡改降级）时如实返回 None。"""
        svc, cache = _make_service()
        cache.store_totp.return_value = False
        cache.resolve_totp_secret.return_value = None

        state = svc.get_state(9, preloaded_secret=_VALID_SECRET, data_epoch="e", data_version=3)

        assert state is None

    def test_rejected_preloaded_lock_during_fallback_returns_none(self):
        """锁定交错：store 拒收后回退 resolve 抛 VaultLockedError → 返回 None（QL-078）。

        「store 拒收 → resolve」窗口内发生锁定时 require_vault_key 抛
        VaultLockedError——get_state 由 Qt 槽（TOTPWidget._build）同步调用，未捕获
        异常在 PyQt6 槽内 qFatal；旧 preloaded 分支（直接用 preloaded）无此异常
        面，系拒收回退引入。返回 None 与 TOTPWidget 的既有空值处理一致。
        """
        from src.exceptions import VaultLockedError

        svc, cache = _make_service()
        cache.store_totp.return_value = False
        cache.resolve_totp_secret.side_effect = VaultLockedError("保险库未解锁")

        state = svc.get_state(9, preloaded_secret=_VALID_SECRET, data_epoch="e", data_version=3)

        assert state is None

    def test_accepted_preloaded_skips_resolve(self):
        """对照：store 成功（正常路径）不触发回退，保留预热免重解密收益。"""
        svc, cache = _make_service()
        cache.store_totp.return_value = True

        state = svc.get_state(9, preloaded_secret=_VALID_SECRET)

        assert state is not None
        cache.resolve_totp_secret.assert_not_called()


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
