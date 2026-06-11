"""测试 ConfigManager.get_safe() 的安全下限强制执行。"""

from src.config import ConfigManager


class TestGetSafeSecurityMinimums:
    """验证 get_safe 对安全关键配置项的运行时下限强制执行。"""

    def test_clipboard_clear_seconds_below_minimum_clamped(self):
        """clipboard_clear_seconds 低于下限 10 时被修正为 10。"""
        cfg = ConfigManager()
        cfg._config = {'clipboard_clear_seconds': 1}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 10

    def test_clipboard_clear_seconds_negative_clamped(self):
        """clipboard_clear_seconds 为负值时被修正为下限。"""
        cfg = ConfigManager()
        cfg._config = {'clipboard_clear_seconds': -5}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 10

    def test_clipboard_clear_seconds_at_minimum_passes(self):
        """clipboard_clear_seconds 等于下限 10 时直接通过。"""
        cfg = ConfigManager()
        cfg._config = {'clipboard_clear_seconds': 10}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 10

    def test_clipboard_clear_seconds_above_minimum_passes(self):
        """clipboard_clear_seconds 高于下限时保留原值。"""
        cfg = ConfigManager()
        cfg._config = {'clipboard_clear_seconds': 60}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 60

    def test_auto_lock_minutes_zero_passes_through(self):
        """auto_lock_minutes=0 是合法的"禁用"语义，不受下限约束。"""
        cfg = ConfigManager()
        cfg._config = {'auto_lock_minutes': 0}
        assert cfg.get_safe('auto_lock_minutes', 5) == 0

    def test_auto_lock_minutes_negative_clamped(self):
        """auto_lock_minutes 为负值时被修正为下限 1。"""
        cfg = ConfigManager()
        cfg._config = {'auto_lock_minutes': -1}
        assert cfg.get_safe('auto_lock_minutes', 5) == 1

    def test_auto_lock_minutes_at_minimum_passes(self):
        """auto_lock_minutes 等于下限 1 时直接通过。"""
        cfg = ConfigManager()
        cfg._config = {'auto_lock_minutes': 1}
        assert cfg.get_safe('auto_lock_minutes', 5) == 1

    def test_non_security_key_unchanged(self):
        """非安全关键配置项不受 get_safe 影响。"""
        cfg = ConfigManager()
        cfg._config = {'theme': 'dark'}
        assert cfg.get_safe('theme', 'light') == 'dark'

    def test_missing_key_returns_default(self):
        """缺失的键返回默认值。"""
        cfg = ConfigManager()
        cfg._config = {}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 30
