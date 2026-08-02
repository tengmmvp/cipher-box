"""apply_rate_limit 工具函数测试。

覆盖登录失败后的速率限制阶梯计算，验证各失败次数阈值对应的锁定时长，
以及 RATE_LIMITS 阶梯定义的升序不变量。
"""

from src.business.services.rate_limiter import apply_rate_limit
from src.config import RATE_LIMITS


class TestApplyRateLimit:
    """验证速率限制阶梯计算。"""

    def test_zero_failures_returns_zero(self):
        """零次失败应不触发锁定。"""
        assert apply_rate_limit(0) == 0

    def test_below_first_threshold_returns_zero(self):
        """未达首个锁定阈值时应不锁定。"""
        assert apply_rate_limit(1) == 0
        assert apply_rate_limit(2) == 0

    def test_first_threshold(self):
        # (3, 10) → 3 次失败锁定 10 秒
        assert apply_rate_limit(3) == 10

    def test_between_thresholds(self):
        """落在两档阈值之间时取较低档的锁定时长。"""
        assert apply_rate_limit(4) == 10

    def test_second_threshold(self):
        # (5, 30)
        assert apply_rate_limit(5) == 30

    def test_third_threshold(self):
        # (8, 60)
        assert apply_rate_limit(8) == 60

    def test_threshold_ten(self):
        # (10, 120)
        assert apply_rate_limit(10) == 120

    def test_threshold_fifteen(self):
        # (15, 600) — 累进锁定：持续失败封顶至 10 分钟，提高在线暴力破解成本
        assert apply_rate_limit(15) == 600

    def test_beyond_max_threshold(self):
        """超过最高阈值后锁定时长封顶不再累加。"""
        assert apply_rate_limit(20) == 600
        assert apply_rate_limit(100) == 600

    def test_rate_limits_sorted_ascending(self):
        """RATE_LIMITS 阈值应为升序。"""
        thresholds = [t for t, _ in RATE_LIMITS]
        assert thresholds == sorted(thresholds)
