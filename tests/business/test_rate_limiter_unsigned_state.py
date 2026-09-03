"""RateLimiter 无签名降级不落盘测试（SEC-042 / SEC-057）。

签名密钥不可用（无 config、瞬时 keyring/DPAPI 故障或会话级临时密钥）时
``_save_state`` 完全不落盘、不建哨兵：若仍写无签名状态文件，下次会话密钥恢复后
会按「签名被剥离」误判为篡改并降级最高阶梯锁定（SEC-029 保守分支），对合法用户
形成误锁。
"""

from __future__ import annotations

from src.business.services.rate_limiter import RateLimiter


class _BrokenKeyConfig:
    """integrity_key 抛异常的 config 替身（模拟瞬时 keyring/DPAPI 故障）。"""

    session_only = False

    @property
    def integrity_key(self) -> bytes:
        raise RuntimeError("keyring unavailable")


class _SessionOnlyConfig:
    """session_only=True 的 config 替身（模拟 DPAPI protect 失败的会话级降级）。"""

    session_only = True

    @property
    def integrity_key(self) -> bytes:
        raise AssertionError("session_only 会话不应取持久化密钥签名")


def test_no_config_instance_does_not_persist_state(tmp_path):
    """无 config 实例：record_failure 仅内存生效，状态文件与哨兵均不创建。"""
    state = tmp_path / "login_rate_limit.json"
    rl = RateLimiter(state)  # 无 config → _signing_key 为 None
    assert rl._signing_key is None

    rl.record_failure()
    rl.record_failure()

    assert rl._fail_count == 2  # 内存限流仍生效
    assert not state.exists()
    assert not (tmp_path / "login_rate_limit.json.sentinel").exists()


def test_failing_signing_key_does_not_persist_state(tmp_path):
    """config 注入但取密钥抛异常（瞬时故障）同样不落盘（SEC-042）。"""
    state = tmp_path / "login_rate_limit.json"
    rl = RateLimiter(state, config=_BrokenKeyConfig())  # type: ignore[arg-type]
    assert rl._signing_key is None

    rl.record_failure()
    rl.record_success()
    rl.record_failure()

    assert not state.exists()
    assert not (tmp_path / "login_rate_limit.json.sentinel").exists()


def test_degraded_session_next_session_treated_as_first_use(tmp_path):
    """降级会话不落盘后，下次会话（密钥恢复）按首次使用处理，不误判锁定。

    守护端到端链路：无签名状态文件形态不存在 → 哨兵/config 见证均未登记 →
    新会话 ``check()`` 返回 None（不触发 SEC-029 的篡改/删除降级锁定）。
    """
    state = tmp_path / "login_rate_limit.json"
    degraded = RateLimiter(state)
    for _ in range(5):
        degraded.record_failure()
    assert not state.exists()

    # 下次会话：仍无 config（密钥未恢复），状态缺失按首次使用
    recovered_like = RateLimiter(state)
    assert recovered_like.check() is None
    assert recovered_like._fail_count == 0


class TestSessionOnlyKeyDoesNotPersist:
    """会话级临时密钥（SEC-057）不签名限流状态落盘，走 SEC-042 既有不落盘路径。

    触发链（修复前）：DPAPI protect 失败 → ConfigKeyStore 返回会话级内存密钥 →
    RateLimiter 以临时密钥签名状态落盘 → 下次启动密钥重新生成 → 签名失配按
    SEC-029 保守分支降级最高阶梯锁定（15 次 / 600 秒）——DPAPI 持续故障时用户
    每次启动都误锁 10 分钟。修复后 ``config.session_only`` 置位时签名密钥解析为
    None，状态文件与哨兵均不落盘，下次启动按首次使用处理。
    """

    def test_session_only_stub_does_not_persist_state(self, tmp_path):
        """session_only=True 的 config：仅内存限流，状态文件与哨兵均不创建。"""
        state = tmp_path / "login_rate_limit.json"
        rl = RateLimiter(state, config=_SessionOnlyConfig())  # type: ignore[arg-type]
        assert rl._signing_key is None

        rl.record_failure()
        rl.record_failure()

        assert rl.fail_count == 2  # 内存限流仍生效（公开观察面，MAINT-095）
        assert rl.check() is None  # 未达锁定阈值
        assert not state.exists()
        assert not (tmp_path / "login_rate_limit.json.sentinel").exists()

    def test_dpapi_failure_end_to_end_does_not_persist_state(self, tmp_path, monkeypatch):
        """端到端：模拟 protect 失败 → session_only 置位 → 状态不落盘、下次按首次使用。

        经真实 ConfigManager + ConfigKeyStore 链路（monkeypatch sys.platform=win32 与
        protect_with_dpapi 返回 None），跨平台可跑（Linux CI 同样覆盖 win32 分支，
        参照 tests/config/test_config_integrity.py 的 TestDpapiProtectFailureFallback）。
        """
        import sys

        import src.config_key_store as cks
        from tests.helpers import make_test_config

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(cks, "protect_with_dpapi", lambda data: None)

        config = make_test_config(tmp_path)
        assert config.session_only is True  # DPAPI 失败 → 会话级临时密钥（SEC-055/056）
        assert len(config.integrity_key) == 32  # 内存密钥照常可用

        state = tmp_path / "login_rate_limit.json"
        rl = RateLimiter(state, config)
        assert rl._signing_key is None  # 临时密钥不用于状态签名（SEC-057）
        for _ in range(5):
            rl.record_failure()
        # 内存限流生效（第 5 次失败触发第二档锁定），但状态与哨兵均不落盘
        assert rl.check() is not None
        assert not state.exists()
        assert not (tmp_path / "login_rate_limit.json.sentinel").exists()

        # 下次启动（DPAPI 恢复）：状态/哨兵成对缺失 → 按首次使用，不误锁 600 秒
        monkeypatch.setattr(cks, "protect_with_dpapi", lambda data: b"dpapi:" + data)
        recovered_config = make_test_config(tmp_path)
        assert recovered_config.session_only is False
        recovered = RateLimiter(state, recovered_config)
        assert recovered.check() is None
        assert recovered.fail_count == 0  # 公开观察面（MAINT-095）
