"""生产 RateLimiter 的跨进程持久化测试。"""

import time

from src.business.services.rate_limiter import RateLimiter


class TestLoginLockPersistence:
    """验证失败次数和锁定截止时间可由新实例恢复。"""

    def test_lock_state_persists_across_restart(self, tmp_path):
        """锁定状态跨进程重启可恢复，且基于单调时钟抵抗系统时钟回拨。

        持久化「剩余秒数」而非绝对时间戳，重启加载时基于当前 monotonic 重算到期
        点——单调时钟在进程间不连续但不可回拨，攻击者回拨系统时钟无法提前解锁。
        """
        lock_file = tmp_path / "login_lock.json"
        limiter = RateLimiter(lock_file)
        for _ in range(3):
            limiter.record_failure()

        restarted = RateLimiter(lock_file)
        assert restarted._lock_until > 0  # 仍处于锁定窗口
        assert restarted.check() is not None

    def test_expired_lock_is_recognized(self, tmp_path):
        """锁定到期后 check() 返回 None 允许重试。"""
        lock_file = tmp_path / "login_lock.json"
        limiter = RateLimiter(lock_file)
        limiter._fail_count = 5
        limiter._lock_until = time.monotonic() - 10
        limiter._save_state()

        restarted = RateLimiter(lock_file)
        assert restarted.check() is None  # 到期允许重试
        # 退避保留：到期后 fail_count 保留以使后续失败爬升退避档位，
        # 仅 lock_until 清零解除锁定。
        assert restarted._lock_until == 0.0
        assert restarted._fail_count == 5

    def test_lock_state_survives_simulated_restart(self, tmp_path):
        """未触发锁定的失败计数经重启后保留（fail_count 持久化的最小情形）。"""
        lock_file = tmp_path / "login_lock.json"
        limiter = RateLimiter(lock_file)
        limiter.record_failure()
        limiter.record_failure()

        restarted = RateLimiter(lock_file)
        assert restarted._fail_count == 2

    def test_corrupt_state_fails_closed(self, tmp_path):
        """状态文件损坏时锁定而非重置（fail-closed），抵抗破坏状态文件绕过限流。"""
        lock_file = tmp_path / "login_lock.json"
        lock_file.write_text("{broken", encoding="utf-8")

        limiter = RateLimiter(lock_file)

        assert limiter.check() is not None
