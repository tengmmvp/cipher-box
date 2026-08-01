"""RateLimiter 行为测试。

覆盖递增退避的「到期保留计数」与「状态文件被删除即降级最高阶梯锁定」
两项加固，以及首次使用不误伤、损坏降级、成功清零等基础不变量。
"""

import time

import pytest

from src.business.services.rate_limiter import RateLimiter
from src.config import RATE_LIMITS


@pytest.fixture
def limiter(tmp_path):
    """构造一个指向临时目录的 RateLimiter。"""
    return RateLimiter(tmp_path / "rate_limit.json")


class TestRateLimiterBackoff:
    """验证递增退避在锁定到期后仍能爬档。"""

    def test_first_use_not_locked(self, limiter):
        """首次使用（无状态文件、无哨兵）不应被锁定。"""
        assert limiter._fail_count == 0
        assert limiter.check() is None

    def test_record_failure_locks_at_threshold(self, limiter):
        """累计失败达阈值触发锁定。"""
        for _ in range(RATE_LIMITS[0][0]):
            limiter.record_failure()
        assert limiter._lock_until > 0
        assert limiter.check() is not None

    def test_expiry_preserves_fail_count(self, limiter, monkeypatch):
        """锁定到期后 fail_count 必须保留，使下一轮失败能爬升到更高档位。"""
        for _ in range(RATE_LIMITS[0][0]):
            limiter.record_failure()
        preserved = limiter._fail_count
        assert limiter._lock_until > 0

        # 推进时间到锁定到期之后
        monkeypatch.setattr(time, "monotonic", lambda: limiter._lock_until + 1)
        assert limiter.check() is None  # 到期允许重试
        assert limiter._fail_count == preserved  # 关键：未清零
        assert limiter._lock_until == 0.0

    def test_escalation_survives_expiry(self, limiter, monkeypatch):
        """到期保留计数后，后续失败应爬升到更高退避档，而非从最低档重爬。"""
        # 第一轮：失败到第一档阈值并锁定
        for _ in range(RATE_LIMITS[0][0]):
            limiter.record_failure()
        # 到期
        monkeypatch.setattr(time, "monotonic", lambda: limiter._lock_until + 1)
        limiter.check()
        # 再失败到第二档阈值：若计数已清零，则需再失败 5 次才到 30s；
        # 保留计数时仅需补足差额。
        remaining = RATE_LIMITS[1][0] - RATE_LIMITS[0][0]
        last_secs = 0
        for _ in range(remaining):
            last_secs = limiter.record_failure()
        assert last_secs == RATE_LIMITS[1][1]

    def test_record_success_resets(self, limiter):
        """成功登录清零计数与锁定。"""
        for _ in range(RATE_LIMITS[0][0]):
            limiter.record_failure()
        limiter.record_success()
        assert limiter._fail_count == 0
        assert limiter._lock_until == 0.0


class TestRateLimiterSentinel:
    """验证哨兵机制：状态文件被删除即降级最高阶梯锁定。"""

    def test_save_creates_sentinel(self, tmp_path):
        state = tmp_path / "rate_limit.json"
        rl = RateLimiter(state)
        rl.record_failure()  # 触发 _save_state → 创建哨兵
        assert state.exists()
        assert (tmp_path / "rate_limit.json.sentinel").exists()

    def test_state_deletion_triggers_lockdown(self, tmp_path):
        """状态文件被删除但哨兵存在 → 判定为恶意删除，降级最高阶梯。"""
        state = tmp_path / "rate_limit.json"
        rl = RateLimiter(state)
        rl.record_success()  # 仅写哨兵与零计数状态
        assert (tmp_path / "rate_limit.json.sentinel").exists()

        state.unlink()  # 模拟攻击者删除状态文件

        rl_reloaded = RateLimiter(state)
        assert rl_reloaded._fail_count == RATE_LIMITS[-1][0]
        assert rl_reloaded._lock_until > 0
        assert rl_reloaded.check() is not None  # 仍处于锁定

    def test_first_use_without_sentinel_not_locked(self, tmp_path):
        """无状态文件且无哨兵 → 首次正常使用，不误锁。"""
        state = tmp_path / "rate_limit.json"
        assert not state.exists()
        assert not (tmp_path / "rate_limit.json.sentinel").exists()
        rl = RateLimiter(state)
        assert rl._fail_count == 0
        assert rl.check() is None

    def test_corrupt_state_triggers_lockdown(self, tmp_path):
        """状态文件存在但损坏 → 降级最高阶梯。"""
        state = tmp_path / "rate_limit.json"
        state.write_text("{invalid json", encoding="utf-8")
        rl = RateLimiter(state)
        assert rl._fail_count == RATE_LIMITS[-1][0]
        assert rl._lock_until > 0


class TestRateLimiterConfigWitness:
    """签名 config 见证：状态文件 + 哨兵被同时删除亦不归零计数（S5）。

    文件可被一并删除，但 HMAC 签名的 config 登记无法被伪造抹除——据此判定
    「同时删除」为恶意删除并降级最高阶梯锁定。
    """

    def test_both_deleted_with_config_witness_lockdown(self, tmp_path):
        """签名 config 登记过哨兵后，状态+哨兵均被删除 → 判定恶意删除 → 降级。"""
        from tests.helpers import make_test_config

        config = make_test_config(tmp_path)
        state = tmp_path / "login_rate_limit.json"
        rl = RateLimiter(state, config)
        rl.record_success()  # 写状态 + 哨兵 + 签名 config 登记
        assert config.is_security_sentinel_established("login_rate_limit")
        # 同时删除状态文件与哨兵
        state.unlink()
        (tmp_path / "login_rate_limit.json.sentinel").unlink()
        rl2 = RateLimiter(state, config)
        assert rl2._fail_count == RATE_LIMITS[-1][0]
        assert rl2._lock_until > 0
        assert rl2.check() is not None

    def test_first_use_with_intact_config_not_locked(self, tmp_path):
        """config 完整、哨兵未登记 → 真首次使用，不误锁新用户。"""
        from tests.helpers import make_test_config

        config = make_test_config(tmp_path)
        state = tmp_path / "login_rate_limit.json"
        rl = RateLimiter(state, config)
        assert rl._fail_count == 0
        assert rl.check() is None

    def test_config_integrity_failure_lockdown(self, tmp_path):
        """config 完整性失败 → 保守降级（签名 config 被篡改本身已可疑）。"""
        from tests.helpers import make_test_config

        config = make_test_config(tmp_path)
        # 写一个无签名行 config.json，触发完整性失败（reason='missing'）
        config._config_path.write_text('{"theme": "light"}', encoding="utf-8")
        config.load()
        assert not config.check_integrity()
        state = tmp_path / "login_rate_limit.json"
        rl = RateLimiter(state, config)
        assert rl._fail_count == RATE_LIMITS[-1][0]

    def test_no_config_witness_preserves_first_use(self, tmp_path):
        """无 config 见证（config=None）退回哨兵配对行为，不削弱保护。"""
        state = tmp_path / "login_rate_limit.json"
        # 无 config：状态+哨兵均缺失 → 首次使用
        rl = RateLimiter(state)
        assert rl._fail_count == 0
        assert rl.check() is None
