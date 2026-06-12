"""配置管理模块 — 管理 CipherBox 应用的所有配置项"""

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any

from .utils.file_security import secure_directory, secure_file

# 配置完整性 HMAC 密钥。
# 此密钥硬编码于源码中，仅用于防护意外损坏，如磁盘错误或部分写入，
# 不防护有意篡改。攻击者若能修改配置文件且可访问源码，可重新计算 HMAC
# 绕过检查。所有配置值在使用时应通过 validate_file_path() 等函数做二次校验。
# 这是本地优先应用的常见防御模式。
_CONFIG_INTEGRITY_KEY = b'cipherbox:config-integrity-v1'
_CONFIG_SIG_PREFIX = '#__sig__:'

logger = logging.getLogger(__name__)


def get_data_dir() -> Path:
    """获取应用数据目录"""
    if os.name == 'nt':
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
    else:
        base = os.environ.get(
            'XDG_DATA_HOME',
            os.path.join(os.path.expanduser('~'), '.local', 'share'),
        )
    data_dir = Path(base) / 'CipherBox'
    return secure_directory(data_dir)


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
    'splitter_sizes': None,
}

_INT_RANGES = {
    'auto_lock_minutes': (0, 60),
    'clipboard_clear_seconds': (0, 300),
    'password_visible_seconds': (3, 60),
    'default_password_length': (4, 64),
    'auto_backup_interval_hours': (1, 168),
    'auto_backup_retention': (2, 50),
    'old_password_warning_days': (30, 365),
}
_BOOL_KEYS = {
    'default_uppercase', 'default_lowercase', 'default_digits',
    'default_symbols', 'default_exclude_ambiguous', 'auto_backup_enabled',
    'show_tray_icon', 'minimize_to_tray', 'close_to_tray',
}

# 速率限制策略：每组为失败次数和对应锁定秒数
RATE_LIMITS: list[tuple[int, int]] = [(3, 10), (5, 30), (8, 60), (10, 120)]


class ConfigManager:
    """配置管理器 — 读写 JSON 配置文件"""

    def __init__(self):
        self._data_dir = get_data_dir()
        self._config_path = self._data_dir / 'config.json'
        self._config: dict = dict(DEFAULT_CONFIG)
        self._integrity_warning = False
        self.load()

    @classmethod
    def for_testing(cls, data_dir) -> 'ConfigManager':
        """创建用于测试的 ConfigManager 实例。

        使用指定目录作为数据目录，不加载真实配置文件。
        """
        cfg = cls.__new__(cls)
        cfg._data_dir = Path(data_dir)
        cfg._config_path = Path(data_dir) / 'config.json'
        cfg._config = dict(DEFAULT_CONFIG)
        cfg._config['show_tray_icon'] = False
        cfg._integrity_warning = False
        return cfg

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
        self._integrity_warning = False
        self._config = dict(DEFAULT_CONFIG)
        if self._config_path.exists():
            try:
                raw_text = self._config_path.read_text(encoding='utf-8')
                # 分离签名行，若存在
                json_text = raw_text
                stored_sig = ''
                lines = raw_text.rstrip().rsplit('\n', 1)
                if len(lines) == 2 and lines[1].startswith(_CONFIG_SIG_PREFIX):
                    json_text = lines[0]
                    stored_sig = lines[1][len(_CONFIG_SIG_PREFIX):]
                # 验证完整性签名
                expected_sig = hmac.new(
                    _CONFIG_INTEGRITY_KEY,
                    json_text.encode('utf-8'),
                    hashlib.sha256,
                ).hexdigest()
                if stored_sig:
                    if not hmac.compare_digest(stored_sig, expected_sig):
                        logger.warning(
                            '配置文件完整性校验失败，可能已被篡改。'
                            '将使用默认配置覆盖异常值。'
                        )
                        self._integrity_warning = True
                saved = json.loads(json_text)
                if not isinstance(saved, dict):
                    raise ValueError('配置文件根节点必须是对象')
                for key, value in saved.items():
                    if key in DEFAULT_CONFIG:
                        if self._is_valid(key, value):
                            self._config[key] = value
                        else:
                            logger.warning('配置项 %s 值无效，已使用默认值', key)
                    else:
                        logger.debug('忽略未知配置项：%s', key)
            except (json.JSONDecodeError, OSError, ValueError):
                logger.warning('配置文件无效，已使用默认配置', exc_info=True)

    def check_integrity(self) -> bool:
        """检查配置文件完整性是否通过。返回 False 表示可能被篡改。"""
        return not self._integrity_warning

    def save(self):
        """原子保存配置，避免异常退出留下半个 JSON 文件。"""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._config_path.with_suffix('.json.tmp')
        content = json.dumps(self._config, indent=2, ensure_ascii=False)
        sig = hmac.new(
            _CONFIG_INTEGRITY_KEY,
            content.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
            f.write(f'\n{_CONFIG_SIG_PREFIX}{sig}')
            f.flush()
            os.fsync(f.fileno())
        secure_file(temp_path)
        os.replace(temp_path, self._config_path)
        secure_file(self._config_path)

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        return self._config.get(key, default)

    # 安全关键配置项的运行时下限，即使配置文件被篡改也不接受低于阈值的值
    _SECURITY_MINIMUMS: dict[str, int] = {
        'clipboard_clear_seconds': 10,
        'auto_lock_minutes': 1,
    }

    def get_safe(self, key: str, default=None):
        """获取配置值，对安全关键键强制运行时下限。

        与 get() 相同，但对 _SECURITY_MINIMUMS 中定义的键，
        返回值不低于安全阈值，防止配置文件被篡改后降低安全策略。

        设计折衷：``auto_lock_minutes=0`` 是用户主动禁用自动锁定的合法语义，
        不受安全下限约束，直接返回 0。这优先尊重用户选择而非强制安全策略。
        负值等非法篡改值仍会被修正为安全下限。
        """
        value = self.get(key, default)
        if isinstance(value, int) and key in self._SECURITY_MINIMUMS:
            minimum = self._SECURITY_MINIMUMS[key]
            # auto_lock_minutes=0 是合法的"禁用"语义，不受安全下限约束
            if key == 'auto_lock_minutes' and value == 0:
                return value
            if value < minimum:
                logger.warning("配置 %s=%d 低于安全下限 %d，已修正", key, value, minimum)
                return minimum
        return value

    def set(self, key: str, value: Any):
        """设置配置项"""
        if key not in DEFAULT_CONFIG:
            raise KeyError(f'未知配置项：{key}')
        if not self._is_valid(key, value):
            raise ValueError(f'配置项值无效：{key}')
        self._config[key] = value

    @staticmethod
    def _is_valid(key: str, value: Any) -> bool:
        if key in _INT_RANGES:
            minimum, maximum = _INT_RANGES[key]
            return type(value) is int and minimum <= value <= maximum
        if key in _BOOL_KEYS:
            return type(value) is bool
        if key == 'theme':
            return value in {'light', 'dark'}
        if key == 'sort_field':
            return value in {'title', 'updated_at', 'created_at', 'password_strength'}
        if key == 'sort_order':
            return value in {'asc', 'desc'}
        if key in {'backup_directory', 'last_auto_backup_at'}:
            return isinstance(value, str) and len(value) <= 4096 and '\x00' not in value
        if key == 'window_geometry':
            if value is None:
                return True
            if not isinstance(value, str) or len(value) > 16384:
                return False
            try:
                bytes.fromhex(value)
                return True
            except ValueError:
                return False
        if key == 'splitter_sizes':
            return value is None or (
                isinstance(value, list)
                and len(value) == 3
                and all(type(item) is int and 0 <= item <= 10000 for item in value)
            )
        logger.debug("配置键 %s 无验证规则，已拒绝", key)
        return False

    def get_all(self) -> dict:
        """获取所有配置"""
        return dict(self._config)
