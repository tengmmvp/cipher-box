"""测试 ConfigManager.get_safe() 的安全下限强制执行。

覆盖剪贴板清空秒数与自动锁定分钟两项安全关键配置的运行时下限钳制，
验证低于下限的值被修正、合法值原样通过，以及非安全关键项与缺失键不受影响。
"""

import pytest

from tests.helpers import make_test_config


class TestGetSafeSecurityMinimums:
    """验证 get_safe 对安全关键配置项的运行时下限强制执行。"""

    @pytest.fixture()
    def cfg(self, tmp_path):
        """用临时目录构造 ConfigManager，避免污染真实用户数据目录。"""
        return make_test_config(str(tmp_path))

    def test_clipboard_clear_seconds_below_minimum_clamped(self, cfg):
        """clipboard_clear_seconds 低于下限 10 时被修正为 10。"""
        cfg._config = {'clipboard_clear_seconds': 1}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 10

    def test_clipboard_clear_seconds_negative_clamped(self, cfg):
        """clipboard_clear_seconds 为负值时被修正为下限。"""
        cfg._config = {'clipboard_clear_seconds': -5}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 10

    def test_clipboard_clear_seconds_at_minimum_passes(self, cfg):
        """clipboard_clear_seconds 等于下限 10 时直接通过。"""
        cfg._config = {'clipboard_clear_seconds': 10}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 10

    def test_clipboard_clear_seconds_above_minimum_passes(self, cfg):
        """clipboard_clear_seconds 高于下限时保留原值。"""
        cfg._config = {'clipboard_clear_seconds': 60}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 60

    def test_auto_lock_minutes_zero_passes_through(self, cfg):
        """auto_lock_minutes=0 是合法的"禁用"语义，不受下限约束。"""
        cfg._config = {'auto_lock_minutes': 0}
        assert cfg.get_safe('auto_lock_minutes', 5) == 0

    def test_auto_lock_minutes_negative_clamped(self, cfg):
        """auto_lock_minutes 为负值时被修正为下限 1。"""
        cfg._config = {'auto_lock_minutes': -1}
        assert cfg.get_safe('auto_lock_minutes', 5) == 1

    def test_auto_lock_minutes_at_minimum_passes(self, cfg):
        """auto_lock_minutes 等于下限 1 时直接通过。"""
        cfg._config = {'auto_lock_minutes': 1}
        assert cfg.get_safe('auto_lock_minutes', 5) == 1

    def test_non_security_key_unchanged(self, cfg):
        """非安全关键配置项不受 get_safe 影响。"""
        cfg._config = {'theme': 'dark'}
        assert cfg.get_safe('theme', 'light') == 'dark'

    def test_missing_key_returns_default(self, cfg):
        """缺失的键返回默认值。"""
        cfg._config = {}
        assert cfg.get_safe('clipboard_clear_seconds', 30) == 30

    def test_auto_lock_minutes_zero_clamped_when_integrity_compromised(self, cfg):
        """完整性失败（被篡改/签名缺失）时，auto_lock=0 不再豁免，钳制到安全下限。

        防止攻击者篡改配置禁用自动锁定：仅当完整性校验通过时，0 才作为合法的
        "禁用"语义豁免；完整性可疑时 0 视为篡改，强制回到安全下限。
        """
        cfg._config = {'auto_lock_minutes': 0}
        cfg._integrity_warning = True
        assert cfg.get_safe('auto_lock_minutes', 5) == 1


def test_integrity_key_read_failure_does_not_block_startup(tmp_path, monkeypatch):
    """config.key 读取失败（TOCTOU/IO）时 fall-through 生成新密钥，不阻断启动（#11）。"""
    from pathlib import Path
    cfg = make_test_config(str(tmp_path))
    key_path = cfg._integrity_key_path
    assert key_path.exists()

    real_read = Path.read_bytes

    def _fail(self, *args, **kwargs):
        if self == key_path:
            raise OSError('io error')
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_bytes', _fail)
    # 再次构造指向同目录：读取失败应 fall-through 生成新密钥，不抛异常
    cfg2 = make_test_config(str(tmp_path))
    assert cfg2._integrity_key_path.exists()
