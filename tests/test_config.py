"""配置边界与持久化测试。"""

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
            'clipboard_clear_seconds': 45,
            'unknown': True,
        }), encoding='utf-8')
        manager = _manager(root)
        manager.load()
        assert manager.get('theme') == DEFAULT_CONFIG['theme']
        assert manager.get('auto_lock_minutes') == DEFAULT_CONFIG['auto_lock_minutes']
        assert manager.get('clipboard_clear_seconds') == 45
        assert 'unknown' not in manager.get_all()


def test_set_rejects_unknown_or_invalid_values():
    with tempfile.TemporaryDirectory() as root:
        manager = _manager(root)
        with pytest.raises(KeyError):
            manager.set('unknown', True)
        with pytest.raises(ValueError):
            manager.set('auto_lock_minutes', -1)
