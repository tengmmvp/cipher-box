"""生产 RateLimiter 的跨进程持久化测试。"""

import time

from src.ui.components.widgets import RateLimiter


class TestLoginLockPersistence:
    """验证失败次数和锁定截止时间可由新实例恢复。"""

    def test_lock_state_uses_wall_clock(self, tmp_path):
        lock_file = tmp_path / 'login_lock.json'
        limiter = RateLimiter(lock_file)
        for _ in range(3):
            limiter.record_failure()

        restarted = RateLimiter(lock_file)
        assert restarted._lock_until > time.time()
        assert restarted.check() is not None

    def test_expired_lock_is_recognized(self, tmp_path):
        lock_file = tmp_path / 'login_lock.json'
        limiter = RateLimiter(lock_file)
        limiter._fail_count = 5
        limiter._lock_until = time.time() - 10
        limiter._save_state()

        restarted = RateLimiter(lock_file)
        assert restarted.check() is None  # 到期允许重试
        # 退避保留：到期后 fail_count 保留以使后续失败爬升退避档位，
        # 仅 lock_until 清零解除锁定（原先到期清零会让退避退化为固定最低档）。
        assert restarted._lock_until == 0.0
        assert restarted._fail_count == 5

    def test_lock_state_survives_simulated_restart(self, tmp_path):
        lock_file = tmp_path / 'login_lock.json'
        limiter = RateLimiter(lock_file)
        limiter.record_failure()
        limiter.record_failure()

        restarted = RateLimiter(lock_file)
        assert restarted._fail_count == 2

    def test_corrupt_state_fails_closed(self, tmp_path):
        lock_file = tmp_path / 'login_lock.json'
        lock_file.write_text('{broken', encoding='utf-8')

        limiter = RateLimiter(lock_file)

        assert limiter.check() is not None
