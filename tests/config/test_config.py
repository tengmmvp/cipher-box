"""配置边界与持久化测试。

验证 ConfigManager 加载时丢弃未知键与非法值、回退到默认值，以及 set 拒绝
未知键与越界值，确保配置文件读写符合安全与一致性的边界约束。
"""

import json
import tempfile
from pathlib import Path

import pytest

from src.config import DEFAULT_CONFIG, ConfigManager
from tests.helpers import make_test_config


def _manager(root: str) -> ConfigManager:
    return make_test_config(root)


def test_load_drops_unknown_and_invalid_values():
    with tempfile.TemporaryDirectory() as root:
        path = Path(root) / 'config.json'
        path.write_text(json.dumps({
            'theme': 'invalid',
            'auto_lock_minutes': 999,
            'default_password_length': 20,  # 合法非安全键，无签名时仍加载
            'unknown': True,
        }), encoding='utf-8')
        manager = _manager(root)
        manager.load()
        assert manager.get('theme') == DEFAULT_CONFIG['theme']
        assert manager.get('auto_lock_minutes') == DEFAULT_CONFIG['auto_lock_minutes']
        assert manager.get('default_password_length') == 20
        assert 'unknown' not in manager.get_all()


def test_load_unsigned_drops_security_keys():
    """无签名配置的安全关键键回退默认（P2-S4）：HMAC 密钥硬编码不防有意篡改，
    攻击者删除签名即可绕过校验，此时文件中的安全配置值不可信，强制回退默认
    收缩篡改面（如删除签名后将 auto_lock_minutes 改为 0 禁用自动锁定）。"""
    with tempfile.TemporaryDirectory() as root:
        path = Path(root) / 'config.json'
        path.write_text(json.dumps({
            'clipboard_clear_seconds': 0,
            'auto_lock_minutes': 0,
        }), encoding='utf-8')
        manager = _manager(root)
        manager.load()
        assert manager.get('clipboard_clear_seconds') == DEFAULT_CONFIG['clipboard_clear_seconds']
        assert manager.get('auto_lock_minutes') == DEFAULT_CONFIG['auto_lock_minutes']
        assert not manager.check_integrity()
        assert manager.integrity_reason == 'missing'


def test_set_rejects_unknown_or_invalid_values():
    with tempfile.TemporaryDirectory() as root:
        manager = _manager(root)
        with pytest.raises(KeyError):
            manager.set('unknown', True)
        with pytest.raises(ValueError):
            manager.set('auto_lock_minutes', -1)
