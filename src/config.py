"""配置管理模块 — 管理 CipherBox 应用的所有配置项。"""

import hashlib
import hmac
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from .models import is_real_int
from .utils.file_security import (
    protect_with_dpapi,
    secure_directory,
    secure_file,
    unprotect_with_dpapi,
)

_CONFIG_SIG_PREFIX = '#__sig__:'
_CONFIG_KEY_SIZE = 32

logger = logging.getLogger(__name__)


def get_data_dir() -> Path:
    """获取应用数据目录。"""
    if os.name == 'nt':
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
    else:
        base = os.environ.get(
            'XDG_DATA_HOME',
            os.path.join(os.path.expanduser('~'), '.local', 'share'),
        )
    data_dir = Path(base) / 'CipherBox'
    return secure_directory(data_dir)


# 密码过期警告天数默认值。单一真相源，供 DEFAULT_CONFIG 与各 UI 处的
# config.get('old_password_warning_days')（依赖此默认）共享，避免字面量 90
# 散落多处导致默认值修改漂移。
OLD_PASSWORD_WARNING_DAYS_DEFAULT = 90

# 窗口几何位置(hex 字符串)允许的最大字节数。Qt saveGeometry 实际输出约 40-60
# 字节，256 字节留足余量供未来 Qt 版本增长。config._is_valid（hex 字符数 = 字节数 × 2）
# 与 MainWindow 窗口位置恢复（解码后字节数）共用此单一常量，消除校验端与消费端
# 各自硬编码导致上限不一致、合法 geometry 被静默丢弃的问题。
MAX_WINDOW_GEOMETRY_BYTES = 256
DEFAULT_CONFIG: dict[str, Any] = {
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
    'old_password_warning_days': OLD_PASSWORD_WARNING_DAYS_DEFAULT,
    'sort_field': 'updated_at',       # title, updated_at, created_at, password_strength
    'sort_order': 'desc',             # asc, desc
    'window_geometry': None,
    'splitter_sizes': None,
}

# 整型配置字段规范：(文件可接受下限, 上限, 运行时安全下限 or None)。
# 单一真相源：_INT_RANGES（供 _is_valid 校验文件值）与 _SECURITY_MINIMUMS
# （供 get_safe 在使用时强制下限）均由此派生，避免两处常量各自维护导致改一处漏一处。
# 文件下限允许 0（如 auto_lock_minutes=0 表「禁用」），运行时安全下限由 get_safe 强制，
# 防止配置文件被篡改后降低安全策略；为 None 表示该字段无额外运行时约束。
_INT_SPECS: dict[str, tuple[int, int, int | None]] = {
    'auto_lock_minutes': (0, 60, 1),
    'clipboard_clear_seconds': (0, 300, 10),
    'password_visible_seconds': (3, 60, 3),
    'default_password_length': (4, 64, None),
    'auto_backup_interval_hours': (1, 168, None),
    'auto_backup_retention': (2, 50, None),
    'old_password_warning_days': (30, 365, None),
}
_INT_RANGES = {k: (lo, hi) for k, (lo, hi, _) in _INT_SPECS.items()}
_SECURITY_MINIMUMS: dict[str, int] = {
    k: sm for k, (_, _, sm) in _INT_SPECS.items() if sm is not None
}
# 完整性校验失败（签名缺失/不符）时必须回退默认值的键集合：除安全下限相关
# 整型键外，还包含 backup_directory——完整性失败时其值不可信（可能被定向篡改
# 以诱导明文备份落入攻击者可读目录），与安全键同等回退默认。
_INTEGRITY_SENSITIVE_KEYS: set[str] = set(_SECURITY_MINIMUMS) | {'backup_directory'}
_BOOL_KEYS = {
    'default_uppercase', 'default_lowercase', 'default_digits',
    'default_symbols', 'default_exclude_ambiguous', 'auto_backup_enabled',
    'show_tray_icon', 'minimize_to_tray', 'close_to_tray',
}

# 速率限制策略：每组为失败次数和对应锁定秒数。最高阶梯封顶至 10 分钟，
# 提高持续在线暴力破解的成本（配合 check() 到期保留 fail_count 的累进机制）。
# 状态文件损坏/删除降级使用 RATE_LIMITS[-1]，故最高阶梯时长也是降级锁定时长。
RATE_LIMITS: list[tuple[int, int]] = [(3, 10), (5, 30), (8, 60), (10, 120), (15, 600)]


class ConfigManager:
    """配置管理器 — 读写 JSON 配置文件。"""

    def __init__(self) -> None:
        self._data_dir = get_data_dir()
        self._config_path = self._data_dir / 'config.json'
        self._integrity_key_path = self._data_dir / 'config.key'
        self._integrity_key = self._load_or_create_integrity_key()
        self._config: dict = dict(DEFAULT_CONFIG)
        self._integrity_warning = False
        self._integrity_reason: str | None = None
        self._lock = threading.RLock()
        self.load()

    @classmethod
    def for_testing(cls, data_dir: str | Path) -> 'ConfigManager':
        """创建用于测试的 ConfigManager 实例。

        使用指定目录作为数据目录，不加载真实配置文件。
        """
        cfg = cls.__new__(cls)
        cfg._data_dir = Path(data_dir)
        cfg._config_path = Path(data_dir) / 'config.json'
        cfg._integrity_key_path = Path(data_dir) / 'config.key'
        cfg._integrity_key = cfg._load_or_create_integrity_key()
        cfg._config = dict(DEFAULT_CONFIG)
        cfg._config['show_tray_icon'] = False
        cfg._integrity_warning = False
        cfg._integrity_reason = None
        cfg._lock = threading.RLock()
        return cfg

    def _load_or_create_integrity_key(self) -> bytes:
        """加载安装级配置签名密钥；缺失或损坏时原子生成新密钥。

        Windows 下密钥经 DPAPI（当前用户凭据）封装存储，使 config.key 即便被
        同权限进程读取也无法在别处解密重算签名——收缩「本地攻击者读 config.key
        重算签名绕过配置完整性校验」的攻击面。非 Windows 或 DPAPI 不可用时回退
        明文存储（靠文件权限保护），绝不阻断启动。
        """
        secure_directory(self._data_dir, strict=True)
        if self._integrity_key_path.exists():
            blob = self._integrity_key_path.read_bytes()
            key = unprotect_with_dpapi(blob)
            if key is None:
                # 非 DPAPI 封装：当作明文密钥（旧格式或非 Windows），长度校验
                key = blob if len(blob) == _CONFIG_KEY_SIZE else None
            if key is not None and len(key) == _CONFIG_KEY_SIZE:
                secure_file(self._integrity_key_path, strict=True)
                return key
            logger.warning('配置签名密钥损坏，将生成新密钥')

        key = os.urandom(_CONFIG_KEY_SIZE)
        # 优先 DPAPI 封装；失败回退明文（不阻断启动）
        stored = protect_with_dpapi(key)
        if stored is None:
            stored = key
        temp_path = self._integrity_key_path.with_suffix('.key.tmp')
        try:
            with open(temp_path, 'wb') as file:
                file.write(stored)
                file.flush()
                os.fsync(file.fileno())
            secure_file(temp_path, strict=True)
            os.replace(temp_path, self._integrity_key_path)
            secure_file(self._integrity_key_path, strict=True)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        return key

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def db_path(self) -> Path:
        return self._data_dir / 'vault.db'

    @property
    def config_path(self) -> Path:
        return self._config_path

    def load(self) -> None:
        """从文件加载配置。"""
        with self._lock:
            self._integrity_warning = False
            self._integrity_reason = None
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
                        self._integrity_key,
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
                            self._integrity_reason = 'mismatch'
                    else:
                        # 无签名行：攻击者删除签名即可绕过 HMAC 校验。容错加载
                        # （避免配置损坏导致无法启动），但 check_integrity 反映此风险，
                        # 供调用方提示用户或触发重写带签名的配置。缺失签名比签名不符
                        # 更可疑（主动删除篡改痕迹），以独立 reason 区分供调用方分级提示。
                        self._integrity_warning = True
                        self._integrity_reason = 'missing'
                    saved = json.loads(json_text)
                    if not isinstance(saved, dict):
                        raise ValueError('配置文件根节点必须是对象')
                    for key, value in saved.items():
                        if key in DEFAULT_CONFIG:
                            if self._is_valid(key, value):
                                # 完整性校验失败（签名不符或缺失）时，安全关键键强制
                                # 使用默认值——HMAC 密钥硬编码不防有意篡改，此时文件中
                                # 的安全配置值不可信，回退默认以收缩篡改面（如攻击者
                                # 删除签名后将 auto_lock_minutes 改为 0 禁用自动锁定）。
                                # 与 get_safe 的运行时钳制叠加，构成 load + 读取双层防御。
                                if self._integrity_warning and key in _INTEGRITY_SENSITIVE_KEYS:
                                    logger.warning(
                                        '配置完整性失败，敏感键 %s 回退默认值', key,
                                    )
                                    continue
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

    @property
    def integrity_reason(self) -> str | None:
        """完整性失败原因：``'mismatch'`` 签名不符、``'missing'`` 签名行缺失，None 表示通过。

        供调用方分级提示——缺失签名行比签名不符更可疑（主动删除篡改痕迹）。
        """
        return self._integrity_reason

    def save(self) -> None:
        """原子保存配置，避免异常退出留下半个 JSON 文件。"""
        with self._lock:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self._config_path.with_suffix('.json.tmp')
            content = json.dumps(self._config, indent=2, ensure_ascii=False)
            sig = hmac.new(
                self._integrity_key,
                content.encode('utf-8'),
                hashlib.sha256,
            ).hexdigest()
            try:
                with open(temp_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                    f.write(f'\n{_CONFIG_SIG_PREFIX}{sig}')
                    f.flush()
                    os.fsync(f.fileno())
                secure_file(temp_path, strict=True)
                os.replace(temp_path, self._config_path)
                secure_file(self._config_path, strict=True)
            except Exception:
                # 异常时清理临时文件，避免残留含明文配置的 .tmp 孤儿文件
                temp_path.unlink(missing_ok=True)
                raise
            # 成功写出带有效签名的配置，清除会话内的完整性告警状态：避免此前
            # 检测到的篡改/缺失状态在 save 后仍粘滞，导致 get_safe 的 auto_lock
            # 豁免被持续钳制而误伤合法用户，以及内存状态与磁盘实际不一致。
            self._integrity_warning = False
            self._integrity_reason = None

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项。"""
        with self._lock:
            return self._config.get(key, default)

    def get_safe(self, key: str, default: Any = None) -> Any:
        """获取配置值，对安全关键键强制运行时下限。

        与 get() 相同，但对模块级 ``_SECURITY_MINIMUMS`` 中定义的键，
        返回值不低于安全阈值，防止配置文件被篡改后降低安全策略。

        设计折衷：``auto_lock_minutes=0`` 是用户主动禁用自动锁定的合法语义，
        不受安全下限约束，直接返回 0。这优先尊重用户选择而非强制安全策略。
        负值等非法篡改值仍会被修正为安全下限。

        威胁模型边界：完整性 HMAC 密钥（config.key）与配置文件同处数据目录，具备
        该目录读写权限的本地攻击者可重算签名使 _integrity_warning 保持 False，
        继而放行 auto_lock_minutes=0。此为本地威胁模型的固有限制——外层防御依赖
        secure_file 将配置文件收紧到当前用户独占。彻底修复（如独立、签名强制保护
        的「禁用自动锁定」开关）属 feature 级改动，不在本层处理。
        """
        value = self.get(key, default)
        if isinstance(value, int) and key in _SECURITY_MINIMUMS:
            minimum = _SECURITY_MINIMUMS[key]
            # auto_lock_minutes=0 是合法的"禁用"语义，不受安全下限约束。
            # 但仅在配置完整性通过时豁免：若配置已被篡改或签名缺失，0 视为可疑，
            # 修正到安全下限，防止攻击者篡改配置文件以禁用自动锁定。
            if key == 'auto_lock_minutes' and value == 0 and not self._integrity_warning:
                return value
            if value < minimum:
                logger.warning("配置 %s=%d 低于安全下限 %d，已修正", key, value, minimum)
                return minimum
        return value

    def set(self, key: str, value: Any) -> None:
        """设置配置项。"""
        with self._lock:
            if key not in DEFAULT_CONFIG:
                raise KeyError(f'未知配置项：{key}')
            if not self._is_valid(key, value):
                raise ValueError(f'配置项值无效：{key}')
            self._config[key] = value

    @staticmethod
    def _is_valid(key: str, value: Any) -> bool:
        if key in _INT_RANGES:
            minimum, maximum = _INT_RANGES[key]
            return is_real_int(value) and minimum <= value <= maximum
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
            if not isinstance(value, str) or len(value) > MAX_WINDOW_GEOMETRY_BYTES * 2:
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
                and all(is_real_int(item) and 1 <= item <= 10000 for item in value)
            )
        logger.debug("配置键 %s 无验证规则，已拒绝", key)
        return False

    def get_all(self) -> dict:
        """获取所有配置。"""
        with self._lock:
            return dict(self._config)
