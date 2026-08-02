"""配置管理模块 — 管理 CipherBox 应用的所有配置项。"""

import copy
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, get_args, overload

from .models import is_real_int
from .utils.file_security import (
    atomic_write,
    protect_with_dpapi,
    secure_directory,
    secure_file,
    unprotect_with_dpapi,
)

_CONFIG_SIG_PREFIX = "#__sig__:"
_CONFIG_KEY_SIZE = 32

logger = logging.getLogger(__name__)


def get_data_dir() -> Path:
    """获取应用数据目录。"""
    if sys.platform == "win32":
        # APPDATA 缺失时逐级回退 LOCALAPPDATA → USERPROFILE\AppData\Roaming，
        # 避免回退裸 ~ 把 vault.db 写到主目录根，破坏 %APPDATA%\CipherBox 路径约定。
        base = (
            os.environ.get("APPDATA")
            or os.environ.get("LOCALAPPDATA")
            or os.path.join(
                os.environ.get("USERPROFILE", os.path.expanduser("~")),
                "AppData",
                "Roaming",
            )
        )
    else:
        base = os.environ.get(
            "XDG_DATA_HOME",
            os.path.join(os.path.expanduser("~"), ".local", "share"),
        )
    data_dir = Path(base) / "CipherBox"
    return secure_directory(data_dir)


# 密码过期警告天数默认值：DEFAULT_CONFIG 与 UI config.get 共用的单一事实源。
OLD_PASSWORD_WARNING_DAYS_DEFAULT = 90

# 窗口几何(hex 字符串)允许的最大字节数。Qt saveGeometry 实际约 40-60 字节，留足余量。
# config._is_valid 与 MainWindow 窗口恢复共用此单一事实源，避免上限不一致致合法 geometry 被丢弃。
MAX_WINDOW_GEOMETRY_BYTES = 256
# 主题默认值（light/dark）：DEFAULT_CONFIG 与 UI 兜底共用的单一事实源。
DEFAULT_THEME = "light"

# 配置键名常量（MAINT-005 单一事实源）：DEFAULT_CONFIG / _INT_SPECS / _BOOL_KEYS /
# Literal 类型别名及所有调用方均引用这些常量，键名重命名只需改此处。命名约定 CFG_<UPPER_SNAKE>。
CFG_THEME: Final[str] = "theme"
CFG_AUTO_LOCK_MINUTES: Final[str] = "auto_lock_minutes"
CFG_CLIPBOARD_CLEAR_SECONDS: Final[str] = "clipboard_clear_seconds"
CFG_PASSWORD_VISIBLE_SECONDS: Final[str] = "password_visible_seconds"
CFG_DEFAULT_PASSWORD_LENGTH: Final[str] = "default_password_length"
CFG_DEFAULT_UPPERCASE: Final[str] = "default_uppercase"
CFG_DEFAULT_LOWERCASE: Final[str] = "default_lowercase"
CFG_DEFAULT_DIGITS: Final[str] = "default_digits"
CFG_DEFAULT_SYMBOLS: Final[str] = "default_symbols"
CFG_DEFAULT_EXCLUDE_AMBIGUOUS: Final[str] = "default_exclude_ambiguous"
CFG_BACKUP_DIRECTORY: Final[str] = "backup_directory"
CFG_AUTO_BACKUP_ENABLED: Final[str] = "auto_backup_enabled"
CFG_AUTO_BACKUP_INTERVAL_HOURS: Final[str] = "auto_backup_interval_hours"
CFG_AUTO_BACKUP_RETENTION: Final[str] = "auto_backup_retention"
CFG_LAST_AUTO_BACKUP_AT: Final[str] = "last_auto_backup_at"
CFG_SHOW_TRAY_ICON: Final[str] = "show_tray_icon"
CFG_MINIMIZE_TO_TRAY: Final[str] = "minimize_to_tray"
CFG_CLOSE_TO_TRAY: Final[str] = "close_to_tray"
CFG_OLD_PASSWORD_WARNING_DAYS: Final[str] = "old_password_warning_days"
CFG_SORT_FIELD: Final[str] = "sort_field"
CFG_SORT_ORDER: Final[str] = "sort_order"
CFG_WINDOW_GEOMETRY: Final[str] = "window_geometry"
CFG_SPLITTER_SIZES: Final[str] = "splitter_sizes"
CFG_SECURITY_SENTINELS: Final[str] = "security_sentinels"

DEFAULT_CONFIG: dict[str, Any] = {
    CFG_THEME: DEFAULT_THEME,
    CFG_AUTO_LOCK_MINUTES: 5,
    CFG_CLIPBOARD_CLEAR_SECONDS: 30,
    CFG_PASSWORD_VISIBLE_SECONDS: 10,
    CFG_DEFAULT_PASSWORD_LENGTH: 16,
    CFG_DEFAULT_UPPERCASE: True,
    CFG_DEFAULT_LOWERCASE: True,
    CFG_DEFAULT_DIGITS: True,
    CFG_DEFAULT_SYMBOLS: True,
    CFG_DEFAULT_EXCLUDE_AMBIGUOUS: False,
    CFG_BACKUP_DIRECTORY: "",
    CFG_AUTO_BACKUP_ENABLED: False,
    CFG_AUTO_BACKUP_INTERVAL_HOURS: 24,
    CFG_AUTO_BACKUP_RETENTION: 10,
    CFG_LAST_AUTO_BACKUP_AT: "",
    CFG_SHOW_TRAY_ICON: True,
    CFG_MINIMIZE_TO_TRAY: True,
    CFG_CLOSE_TO_TRAY: False,
    CFG_OLD_PASSWORD_WARNING_DAYS: OLD_PASSWORD_WARNING_DAYS_DEFAULT,
    CFG_SORT_FIELD: "updated_at",  # title, updated_at, created_at, password_strength
    CFG_SORT_ORDER: "desc",  # asc, desc
    CFG_WINDOW_GEOMETRY: None,
    CFG_SPLITTER_SIZES: None,
    # 安全哨兵登记名（RateLimiter 首次持久化状态时登记）。HMAC 签名覆盖，用于检测
    # 「状态文件 + 哨兵被同时删除」的速率限制绕过——文件可删，但删后签名 config 仍记录
    # 哨兵曾建立 → 加载时判定恶意删除并降级最高阶梯锁定。非用户面向。
    CFG_SECURITY_SENTINELS: [],
}

# 整型配置字段规范：(文件可接受下限, 上限, 运行时安全下限 or None)。单一事实源，
# _INT_RANGES（校验文件值）与 _SECURITY_MINIMUMS（运行时下限钳制）均由此派生。
# 文件下限允许 0（如 auto_lock_minutes=0 表禁用），运行时安全下限防配置被篡改降低安全策略。
_INT_SPECS: dict[str, tuple[int, int, int | None]] = {
    CFG_AUTO_LOCK_MINUTES: (0, 60, 1),
    CFG_CLIPBOARD_CLEAR_SECONDS: (0, 300, 10),
    CFG_PASSWORD_VISIBLE_SECONDS: (3, 60, 3),
    CFG_DEFAULT_PASSWORD_LENGTH: (4, 64, None),
    CFG_AUTO_BACKUP_INTERVAL_HOURS: (1, 168, None),
    CFG_AUTO_BACKUP_RETENTION: (2, 50, None),
    CFG_OLD_PASSWORD_WARNING_DAYS: (30, 365, None),
}
# 只读映射（MappingProxyType 防误写，ARCH-010）：均派生自 _INT_SPECS。
_INT_RANGES = MappingProxyType({k: (lo, hi) for k, (lo, hi, _) in _INT_SPECS.items()})
_SECURITY_MINIMUMS = MappingProxyType(
    {k: sm for k, (_, _, sm) in _INT_SPECS.items() if sm is not None}
)


def get_ui_int_range(key: str) -> tuple[int, int]:
    """返回 UI Spinner 的可选范围 (min, max)，派生自 _INT_SPECS 单一事实源。

    下限取 config 下限与运行时安全下限的较大者，避免 UI 提供 ``get_safe`` 会钳制的值
    脱节。``auto_lock_minutes`` 例外：0 是合法的禁用选项，UI 下限仍为 0。
    """
    config_min, config_max = _INT_RANGES[key]
    security_min = _SECURITY_MINIMUMS.get(key)
    if security_min is not None and key != CFG_AUTO_LOCK_MINUTES:
        return max(config_min, security_min), config_max
    return config_min, config_max


# 完整性校验失败时必须回退默认的键集合：安全下限整型键 + backup_directory
# （可能被篡改诱导明文备份落入攻击者可读目录）+ security_sentinels
# （由 RateLimiter 据完整性失败保守降级，不采信被篡改登记）。
_INTEGRITY_SENSITIVE_KEYS: set[str] = set(_SECURITY_MINIMUMS) | {
    CFG_BACKUP_DIRECTORY,
    CFG_SECURITY_SENTINELS,
}
_BOOL_KEYS = {
    CFG_DEFAULT_UPPERCASE,
    CFG_DEFAULT_LOWERCASE,
    CFG_DEFAULT_DIGITS,
    CFG_DEFAULT_SYMBOLS,
    CFG_DEFAULT_EXCLUDE_AMBIGUOUS,
    CFG_AUTO_BACKUP_ENABLED,
    CFG_SHOW_TRAY_ICON,
    CFG_MINIMIZE_TO_TRAY,
    CFG_CLOSE_TO_TRAY,
}

# 速率限制阶梯：(失败次数, 锁定秒数)。最高阶梯 10 分钟提高在线暴破成本；
# 状态文件损坏/删除降级使用 RATE_LIMITS[-1]，故最高阶梯亦为降级锁定时长。
RATE_LIMITS: list[tuple[int, int]] = [(3, 10), (5, 30), (8, 60), (10, 120), (15, 600)]

# 已知配置键的字面量类型分组(供 get/get_safe/set 的 @overload 按键派生返回/入参类型,
# 收窄热点调用的静态类型)。键到类型的映射须与 DEFAULT_CONFIG 保持一致:新增或改型
# 配置键须同步更新此处与对应 @overload。
# 注：Literal 须用字面量（mypy/Pyright 不支持从 Final 变量派生），与上方 CFG_ 常量各自
# 维护；启动期断言校验两者一致，重命名时改 CFG_ 常量 + 此处字面量，断言捕获遗漏。
_StrConfigKey = Literal[
    "theme",
    "backup_directory",
    "last_auto_backup_at",
    "sort_field",
    "sort_order",
]
_IntConfigKey = Literal[
    "auto_lock_minutes",
    "clipboard_clear_seconds",
    "password_visible_seconds",
    "default_password_length",
    "auto_backup_interval_hours",
    "auto_backup_retention",
    "old_password_warning_days",
]
_BoolConfigKey = Literal[
    "default_uppercase",
    "default_lowercase",
    "default_digits",
    "default_symbols",
    "default_exclude_ambiguous",
    "auto_backup_enabled",
    "show_tray_icon",
    "minimize_to_tray",
    "close_to_tray",
]

# 启动期断言（QL-006）：overload 的 Literal 键集须与 DEFAULT_CONFIG 中对应类型键一致，
# 新增配置键漏更新 Literal 在模块加载即报错。window_geometry/splitter_sizes/
# security_sentinels 为特殊类型（由独立 overload 覆盖），不纳入此校验。
if set(get_args(_StrConfigKey)) != {k for k, v in DEFAULT_CONFIG.items() if isinstance(v, str)}:
    raise RuntimeError("_StrConfigKey 与 DEFAULT_CONFIG 的 str 键不一致")
if set(get_args(_IntConfigKey)) != {k for k, v in DEFAULT_CONFIG.items() if is_real_int(v)}:
    raise RuntimeError("_IntConfigKey 与 DEFAULT_CONFIG 的 int 键不一致")
if set(get_args(_BoolConfigKey)) != {k for k, v in DEFAULT_CONFIG.items() if type(v) is bool}:
    raise RuntimeError("_BoolConfigKey 与 DEFAULT_CONFIG 的 bool 键不一致")


def _validate_pathlike(value: Any) -> bool:
    """限长、无 NUL 的字符串（备份目录/上次备份时间戳路径）。"""
    return isinstance(value, str) and len(value) <= 4096 and "\x00" not in value


def _validate_geometry(value: Any) -> bool:
    """窗口几何：None 或上限内的 hex 字符串（与 MainWindow 恢复共用 MAX 上限）。"""
    if value is None:
        return True
    if not isinstance(value, str) or len(value) > MAX_WINDOW_GEOMETRY_BYTES * 2:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _validate_splitter(value: Any) -> bool:
    """分隔条尺寸：None 或三元组整型（各项 1-10000）。"""
    return value is None or (
        isinstance(value, list)
        and len(value) == 3
        and all(is_real_int(item) and 1 <= item <= 10000 for item in value)
    )


def _validate_sentinels(value: Any) -> bool:
    """安全哨兵：限长、非空、无 NUL 的纯字符串列表（RateLimiter 状态文件 stem）。"""
    return (
        isinstance(value, list)
        and len(value) <= 64
        and all(
            isinstance(item, str) and item and len(item) <= 128 and "\x00" not in item
            for item in value
        )
    )


# 具体键校验派发表（QL-016）：替代长 if-elif 降 _is_valid 圈复杂度；集合键 _INT_RANGES/_BOOL_KEYS 在 _is_valid 内联判断。
_KEY_VALIDATORS: Final[dict[str, Callable[[Any], bool]]] = {
    CFG_THEME: lambda v: isinstance(v, str) and v in {"light", "dark"},
    CFG_SORT_FIELD: lambda v: (
        isinstance(v, str) and v in {"title", "updated_at", "created_at", "password_strength"}
    ),
    CFG_SORT_ORDER: lambda v: isinstance(v, str) and v in {"asc", "desc"},
    CFG_BACKUP_DIRECTORY: _validate_pathlike,
    CFG_LAST_AUTO_BACKUP_AT: _validate_pathlike,
    CFG_WINDOW_GEOMETRY: _validate_geometry,
    CFG_SPLITTER_SIZES: _validate_splitter,
    CFG_SECURITY_SENTINELS: _validate_sentinels,
}


class ConfigManager:
    """配置管理器 — 读写 JSON 配置文件。"""

    def __init__(self) -> None:
        self._data_dir = get_data_dir()
        self._config_path = self._data_dir / "config.json"
        self._integrity_key_path = self._data_dir / "config.key"
        self._integrity_key = self._load_or_create_integrity_key()
        # deepcopy 而非 dict()：security_sentinels 等嵌套 list 浅拷贝会在多实例间共享，
        # 任一原地突变串扰其他实例默认值。
        self._config: dict = copy.deepcopy(DEFAULT_CONFIG)
        self._integrity_warning = False
        self._integrity_reason: str | None = None
        self._lock = threading.RLock()
        self.load()

    @classmethod
    def for_testing(cls, data_dir: str | Path) -> "ConfigManager":
        """创建测试用 ConfigManager，使用指定数据目录且不加载真实配置。"""
        cfg = cls.__new__(cls)
        cfg._data_dir = Path(data_dir)
        cfg._config_path = Path(data_dir) / "config.json"
        cfg._integrity_key_path = Path(data_dir) / "config.key"
        cfg._integrity_key = cfg._load_or_create_integrity_key()
        cfg._config = copy.deepcopy(DEFAULT_CONFIG)
        cfg._config[CFG_SHOW_TRAY_ICON] = False
        cfg._integrity_warning = False
        cfg._integrity_reason = None
        cfg._lock = threading.RLock()
        return cfg

    def _load_or_create_integrity_key(self) -> bytes:
        """加载安装级配置签名密钥；缺失/损坏时原子生成新密钥。

        Windows 下经 DPAPI（当前用户凭据）封装存储，使 config.key 被读取也无法在别处
        解密重算签名，收缩篡改配置绕过完整性校验的攻击面。非 Windows 回退明文 0600 存储
        （SEC-003 威胁边界：明文可读意味着本地有读权限者可重算签名伪造安全配置，如把
        auto_lock 改 0；彻底修复需引入系统密钥链 keyring，权衡其跨平台失败模式与 CI 复杂度
        后暂维持现状，以 Windows DPAPI 为主平台防护）。绝不阻断启动。
        """
        # strict=False：启动路径绝不阻断。Windows SID 解析失败（EDR/企业策略禁用
        # whoami）时 _restrict_windows_acl 会抛 OSError 致启动崩溃，违背本方法
        # 「绝不阻断启动」契约。权限加固失败降级（warning）而非阻断启动。
        secure_directory(self._data_dir, strict=False)
        if self._integrity_key_path.exists():
            try:
                blob = self._integrity_key_path.read_bytes()
            except (FileNotFoundError, OSError):
                # exists() 与 read_bytes() 间 TOCTOU 或瞬时 IO 错误：与损坏分支一致 fall-through，绝不阻断启动。
                logger.warning("读取配置签名密钥失败，将生成新密钥", exc_info=True)
                blob = None
            if blob is not None:
                key = unprotect_with_dpapi(blob)
                if key is None:
                    # 非 DPAPI 封装：当作明文密钥（旧格式或非 Windows），长度校验
                    key = blob if len(blob) == _CONFIG_KEY_SIZE else None
                if key is not None and len(key) == _CONFIG_KEY_SIZE:
                    # strict=False：启动路径同上，权限加固失败降级而非崩溃。
                    secure_file(self._integrity_key_path, strict=False)
                    return key
                logger.warning("配置签名密钥损坏，将生成新密钥")

        key = os.urandom(_CONFIG_KEY_SIZE)
        # 优先 DPAPI 封装；失败回退明文（不阻断启动）
        stored = protect_with_dpapi(key)
        if stored is None:
            stored = key

        # 经 atomic_write 落地即 0600，消除「写明文密钥 → 关闭 → secure_file 收紧」间的世界可读窗口（SEC-015）。
        def _write_key(f: Any) -> bool:
            f.write(stored)
            return True

        atomic_write(self._integrity_key_path, _write_key, mode="wb")
        return key

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def db_path(self) -> Path:
        return self._data_dir / "vault.db"

    @property
    def config_path(self) -> Path:
        return self._config_path

    def load(self) -> None:
        """从文件加载配置。"""
        with self._lock:
            self._integrity_warning = False
            self._integrity_reason = None
            self._config = copy.deepcopy(DEFAULT_CONFIG)
            if self._config_path.exists():
                try:
                    raw_text = self._config_path.read_text(encoding="utf-8")
                    # 分离末尾签名行：按 splitlines 取末行判断，比 rsplit('\n',1) 鲁棒——
                    # 后者按最后一个换行盲切，JSON 体内若有签名前缀开头的行会误切。
                    json_text = raw_text
                    stored_sig = ""
                    text = raw_text.rstrip()
                    lines = text.splitlines()
                    if len(lines) >= 2 and lines[-1].startswith(_CONFIG_SIG_PREFIX):
                        stored_sig = lines[-1][len(_CONFIG_SIG_PREFIX) :]
                        json_text = text[: -(len(lines[-1]) + 1)]
                    # 验证完整性签名
                    expected_sig = hmac.new(
                        self._integrity_key,
                        json_text.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    if stored_sig:
                        if not hmac.compare_digest(stored_sig, expected_sig):
                            logger.warning(
                                "配置文件完整性校验失败，可能已被篡改。将使用默认配置覆盖异常值。"
                            )
                            self._integrity_warning = True
                            self._integrity_reason = "mismatch"
                    else:
                        # 无签名行：攻击者删签名即可绕过 HMAC。容错加载（避免损坏致无法启动），
                        # 但 check_integrity 反映风险供调用方提示。缺失签名比签名不符更可疑
                        # （主动删除篡改痕迹），独立 reason 区分供分级提示。
                        self._integrity_warning = True
                        self._integrity_reason = "missing"
                    saved = json.loads(json_text)
                    if not isinstance(saved, dict):
                        raise ValueError("配置文件根节点必须是对象")
                    for key, value in saved.items():
                        if key in DEFAULT_CONFIG:
                            if self._is_valid(key, value):
                                # 完整性失败时安全关键键强制默认：HMAC 密钥硬编码不防有意篡改，
                                # 此时文件安全配置不可信，回退默认收缩篡改面（如删签名后把
                                # auto_lock_minutes 改 0 禁用自动锁定）。与 get_safe 叠加双层防御。
                                if self._integrity_warning and key in _INTEGRITY_SENSITIVE_KEYS:
                                    logger.warning(
                                        "配置完整性失败，敏感键 %s 回退默认值",
                                        key,
                                    )
                                    continue
                                self._config[key] = value
                            else:
                                logger.warning("配置项 %s 值无效，已使用默认值", key)
                        else:
                            logger.debug("忽略未知配置项：%s", key)
                except (json.JSONDecodeError, OSError, ValueError, TypeError):
                    # TypeError：_is_valid 对集合成员测试（theme/sort_*）遇到不可哈希的
                    # 数组/对象值会抛 TypeError，须一并兜底，否则损坏配置会穿透崩溃启动。
                    logger.warning("配置文件无效，已使用默认配置", exc_info=True)

    def check_integrity(self) -> bool:
        """检查配置文件完整性是否通过。返回 False 表示可能被篡改。"""
        return not self._integrity_warning

    @property
    def integrity_reason(self) -> str | None:
        """完整性失败原因：``'mismatch'`` 签名不符、``'missing'`` 签名缺失，None 表示通过。

        供调用方分级提示——缺失签名比不符更可疑（主动删除篡改痕迹）。
        """
        return self._integrity_reason

    def save(self) -> None:
        """原子保存配置，避免异常退出留下半个 JSON 文件。"""
        with self._lock:
            content = json.dumps(self._config, indent=2, ensure_ascii=False)
            sig = hmac.new(
                self._integrity_key,
                content.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            # 经 atomic_write 落地即 0600，消除「写含安全配置明文 → 关闭 → secure_file 收紧」间的世界可读窗口（SEC-015）。
            def _write_config(f: Any) -> bool:
                f.write(content)
                f.write(f"\n{_CONFIG_SIG_PREFIX}{sig}")
                return True

            atomic_write(self._config_path, _write_config, mode="w", encoding="utf-8")
            # 清除会话内完整性告警：避免此前篡改/缺失状态在 save 后粘滞，致 get_safe
            # 的 auto_lock 豁免被误钳或内存与磁盘不一致。
            self._integrity_warning = False
            self._integrity_reason = None

    @overload
    def get(self, key: _StrConfigKey, default: Any = None) -> str: ...
    @overload
    def get(self, key: _IntConfigKey, default: Any = None) -> int: ...
    @overload
    def get(self, key: _BoolConfigKey, default: Any = None) -> bool: ...
    @overload
    def get(self, key: Literal["window_geometry"], default: Any = None) -> str | None: ...
    @overload
    def get(self, key: Literal["splitter_sizes"], default: Any = None) -> list[int] | None: ...
    @overload
    def get(self, key: Literal["security_sentinels"], default: Any = None) -> list[str]: ...
    @overload
    def get(self, key: str, default: Any = None) -> Any: ...
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项。"""
        with self._lock:
            return self._config.get(key, default)

    @overload
    def get_safe(self, key: _StrConfigKey, default: Any = None) -> str: ...
    @overload
    def get_safe(self, key: _IntConfigKey, default: Any = None) -> int: ...
    @overload
    def get_safe(self, key: _BoolConfigKey, default: Any = None) -> bool: ...
    @overload
    def get_safe(self, key: Literal["window_geometry"], default: Any = None) -> str | None: ...
    @overload
    def get_safe(self, key: Literal["splitter_sizes"], default: Any = None) -> list[int] | None: ...
    @overload
    def get_safe(self, key: Literal["security_sentinels"], default: Any = None) -> list[str]: ...
    @overload
    def get_safe(self, key: str, default: Any = None) -> Any: ...
    def get_safe(self, key: str, default: Any = None) -> Any:
        """获取配置值，对安全关键键（``_SECURITY_MINIMUMS``）强制运行时下限，防篡改降低安全策略。

        ``auto_lock_minutes=0`` 是合法的禁用语义，不受下限约束（直接返回 0）。

        威胁模型边界：config.key 经 Windows DPAPI 封装，仅防「窃取文件后离线重算签名」，
        不防「能以当前用户身份运行代码的攻击者」（可直接重算签名使 _integrity_warning 保持 False）；
        彻底修复属 feature 级改动，不在本层处理。
        """
        value = self.get(key, default)
        if isinstance(value, int) and key in _SECURITY_MINIMUMS:
            minimum = _SECURITY_MINIMUMS[key]
            # auto_lock_minutes=0 是合法禁用，但仅在完整性通过时豁免：完整性失败时 0 视为可疑，修正到安全下限防篡改禁用锁定。
            if key == CFG_AUTO_LOCK_MINUTES and value == 0 and not self._integrity_warning:
                return value
            if value < minimum:
                logger.warning("配置 %s=%d 低于安全下限 %d，已修正", key, value, minimum)
                return minimum
        return value

    @overload
    def set(self, key: _StrConfigKey, value: str) -> None: ...
    @overload
    def set(self, key: _IntConfigKey, value: int) -> None: ...
    @overload
    def set(self, key: _BoolConfigKey, value: bool) -> None: ...
    @overload
    def set(self, key: Literal["window_geometry"], value: str | None) -> None: ...
    @overload
    def set(self, key: Literal["splitter_sizes"], value: list[int] | None) -> None: ...
    @overload
    def set(self, key: Literal["security_sentinels"], value: list[str]) -> None: ...
    @overload
    def set(self, key: str, value: Any) -> None: ...
    def set(self, key: str, value: Any) -> None:
        """设置配置项。"""
        with self._lock:
            if key not in DEFAULT_CONFIG:
                raise KeyError(f"未知配置项：{key}")
            if not self._is_valid(key, value):
                raise ValueError(f"配置项值无效：{key}")
            self._config[key] = value

    def register_security_sentinel(self, name: str) -> None:
        """登记安全哨兵已建立（写入签名 config，幂等）。

        供 RateLimiter 持久化状态时调用。状态文件与哨兵被同时删除时，签名 config 仍记录其
        曾建立 → 加载时判定恶意删除并降级最高阶梯锁定。攻击者无法伪造签名抹除登记。
        幂等：已登记时直接返回，不重复 save。
        """
        with self._lock:
            current = list(self._config.get(CFG_SECURITY_SENTINELS, []))
            if name in current:
                return
            current.append(name)
            self._config[CFG_SECURITY_SENTINELS] = current
            self.save()

    def is_security_sentinel_established(self, name: str) -> bool:
        """哨兵是否已登记。

        调用方应先查 :meth:`check_integrity`——完整性失败时返回值不可信，应保守视为已建立降级锁定。
        """
        with self._lock:
            return name in self._config.get(CFG_SECURITY_SENTINELS, [])

    @staticmethod
    def _is_valid(key: str, value: Any) -> bool:
        """按 key 分组校验配置值合法性，供 load（容错）与 set（拒绝）复用单一规则。

        集合键（_INT_RANGES 整型范围、_BOOL_KEYS）内联判断；具体键经 _KEY_VALIDATORS
        派发到对应校验器（枚举/限长字符串/窗口几何/分隔条/安全哨兵）。无匹配规则
        （未知键）记 debug 并拒绝——配置键白名单由 DEFAULT_CONFIG 把关，此处只校验
        已知键的值。load 据返回值跳过非法项保留默认，set 据其抛 ValueError。
        """
        if key in _INT_RANGES:
            minimum, maximum = _INT_RANGES[key]
            return is_real_int(value) and minimum <= value <= maximum
        if key in _BOOL_KEYS:
            return type(value) is bool
        validator = _KEY_VALIDATORS.get(key)
        if validator is not None:
            return validator(value)
        logger.debug("配置键 %s 无验证规则，已拒绝", key)
        return False

    def get_all(self) -> dict[str, Any]:
        """获取所有配置。"""
        with self._lock:
            return dict(self._config)
