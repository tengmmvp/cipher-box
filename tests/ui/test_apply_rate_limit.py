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
        """达首档阈值（3 次失败）锁定 10 秒。"""
        assert apply_rate_limit(3) == 10

    def test_between_thresholds(self):
        """落在两档阈值之间时取较低档的锁定时长。"""
        assert apply_rate_limit(4) == 10

    def test_second_threshold(self):
        """达第二档阈值（5 次失败）锁定 30 秒。"""
        assert apply_rate_limit(5) == 30

    def test_third_threshold(self):
        """达第三档阈值（8 次失败）锁定 60 秒。"""
        assert apply_rate_limit(8) == 60

    def test_threshold_ten(self):
        """达第四档阈值（10 次失败）锁定 120 秒。"""
        assert apply_rate_limit(10) == 120

    def test_threshold_fifteen(self):
        """达最高档阈值（15 次失败）锁定 600 秒（封顶 10 分钟，提高在线暴力破解成本）。"""
        assert apply_rate_limit(15) == 600

    def test_beyond_max_threshold(self):
        """超过最高阈值后锁定时长封顶不再累加。"""
        assert apply_rate_limit(20) == 600
        assert apply_rate_limit(100) == 600

    def test_rate_limits_sorted_ascending(self):
        """RATE_LIMITS 阈值应为升序。"""
        thresholds = [t for t, _ in RATE_LIMITS]
        assert thresholds == sorted(thresholds)
