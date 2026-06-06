"""配置管理模块 - 管理 CipherBox 应用的所有配置项"""

import json
import os
from pathlib import Path
from typing import Any


def get_data_dir() -> Path:
    """获取应用数据目录"""
    if os.name == 'nt':
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
    else:
        base = os.environ.get('XDG_CONFIG_HOME', os.path.join(os.path.expanduser('~'), '.config'))
    data_dir = Path(base) / 'CipherBox'
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


# 默认配置
DEFAULT_CONFIG = {
    'theme': 'light',
    'auto_lock_minutes': 5,
    'clipboard_clear_seconds': 30,
    'password_visible_seconds': 10,
    'default_password_length': 16,
    'default_uppercase': True,
    'default_lowercase': True,
    'default_digits': True,
    'default_symbols': True,
    'default_exclude_ambiguous': False,
    'backup_directory': '',
    'auto_backup_enabled': False,
    'auto_backup_interval_hours': 24,
    'auto_backup_retention': 10,
    'last_auto_backup_at': '',
    'show_tray_icon': True,
    'minimize_to_tray': True,
    'close_to_tray': False,
    'old_password_warning_days': 90,
    'sort_field': 'updated_at',       # title, updated_at, created_at, password_strength
    'sort_order': 'desc',             # asc, desc
    'window_geometry': None,
}


class ConfigManager:
    """配置管理器 - 读写 JSON 配置文件"""

    def __init__(self):
        self._data_dir = get_data_dir()
        self._config_path = self._data_dir / 'config.json'
        self._config: dict = dict(DEFAULT_CONFIG)
        self.load()

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def db_path(self) -> Path:
        return self._data_dir / 'vault.db'

    @property
    def config_path(self) -> Path:
        return self._config_path

    def load(self):
        """从文件加载配置"""
        if self._config_path.exists():
            try:
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                self._config.update(saved)
            except (json.JSONDecodeError, OSError):
                pass

    def save(self):
        """原子保存配置，避免异常退出留下半个 JSON 文件。"""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._config_path.with_suffix('.json.tmp')
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(self._config, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, self._config_path)

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        """设置配置项"""
        self._config[key] = value

    def get_all(self) -> dict:
        """获取所有配置"""
        return dict(self._config)

    def reset_to_defaults(self):
        """重置为默认配置"""
        self._config = dict(DEFAULT_CONFIG)
        self.save()
