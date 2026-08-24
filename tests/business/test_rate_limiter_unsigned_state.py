"""RateLimiter 无签名降级不落盘测试（SEC-042）。

签名密钥不可用（无 config 或瞬时 keyring/DPAPI 故障）时 ``_save_state`` 完全不
落盘、不建哨兵：若仍写无签名状态文件，下次会话密钥恢复后会按「签名被剥离」
误判为篡改并降级最高阶梯锁定（SEC-029 保守分支），对合法用户形成误锁。
"""

from __future__ import annotations

from src.business.services.rate_limiter import RateLimiter


class _BrokenKeyConfig:
    """integrity_key 抛异常的 config 替身（模拟瞬时 keyring/DPAPI 故障）。"""

    @property
    def integrity_key(self) -> bytes:
        raise RuntimeError("keyring unavailable")


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
