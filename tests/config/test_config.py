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
    """加载时丢弃未知键、非法值回退默认，合法非安全键保留。"""
    with tempfile.TemporaryDirectory() as root:
        path = Path(root) / "config.json"
        path.write_text(
            json.dumps(
                {
                    "theme": "invalid",
                    "auto_lock_minutes": 999,
                    "default_password_length": 20,  # 合法非安全键，无签名时仍加载
                    "unknown": True,
                }
            ),
            encoding="utf-8",
        )
        manager = _manager(root)
        manager.load()
        assert manager.get("theme") == DEFAULT_CONFIG["theme"]
        assert manager.get("auto_lock_minutes") == DEFAULT_CONFIG["auto_lock_minutes"]
        assert manager.get("default_password_length") == 20
        assert "unknown" not in manager.get_all()


def test_load_unsigned_drops_security_keys():
    """无签名配置的安全关键键回退默认（P2-S4）：HMAC 密钥硬编码不防有意篡改，
    攻击者删除签名即可绕过校验，此时文件中的安全配置值不可信，强制回退默认
    收缩篡改面（如删除签名后将 auto_lock_minutes 改为 0 禁用自动锁定）。"""
    with tempfile.TemporaryDirectory() as root:
        path = Path(root) / "config.json"
        path.write_text(
            json.dumps(
                {
                    "clipboard_clear_seconds": 0,
                    "auto_lock_minutes": 0,
                }
            ),
            encoding="utf-8",
        )
        manager = _manager(root)
        manager.load()
        assert manager.get("clipboard_clear_seconds") == DEFAULT_CONFIG["clipboard_clear_seconds"]
        assert manager.get("auto_lock_minutes") == DEFAULT_CONFIG["auto_lock_minutes"]
        assert not manager.check_integrity()
        assert manager.integrity_reason == "missing"


def test_tampered_backup_directory_falls_back_to_default():
    """篡改 backup_directory 致签名失配后，该敏感键回退默认值（与 clipboard_clear_seconds 等同等处理）。

    backup_directory 属于 _INTEGRITY_SENSITIVE_KEYS：完整性失败时其值不可信——
    可能被定向篡改以诱导明文备份落入攻击者可读目录。覆盖签名「不符（mismatch）」
    路径：先 save 产生有效签名，再改写 JSON 中的 backup_directory 值并保留旧签名行
    使签名失配，重新加载后断言其与 clipboard_clear_seconds 等敏感键同等回退默认。
    """
    with tempfile.TemporaryDirectory() as root:
        manager = _manager(root)
        manager.set("backup_directory", "/tmp/evil_backups")
        manager.save()

        # 篡改：改写 backup_directory 值，保留旧签名行 → 签名失配（mismatch）
        raw = manager.config_path.read_text(encoding="utf-8")
        json_text, sig_line = raw.rsplit("\n", 1)
        tampered = json_text.replace(
            '"backup_directory": "/tmp/evil_backups"',
            '"backup_directory": "/tmp/attacker_readable"',
        )
        manager.config_path.write_text(tampered + "\n" + sig_line, encoding="utf-8")

        # 重新加载
        reloaded = _manager(root)
        reloaded.load()
        assert not reloaded.check_integrity()
        assert reloaded.integrity_reason == "mismatch"
        # 完整性失败，敏感键回退默认值（默认为空字符串），篡改值不被采信
        assert reloaded.get("backup_directory") == DEFAULT_CONFIG["backup_directory"]
        assert reloaded.get("backup_directory") == ""


def test_tampered_backup_schedule_keys_fall_back_to_default():
    """篡改自动备份调度键（SEC-058）致签名失配后回退默认，备份调度恢复运行。

    last_auto_backup_at 被改为远期合法 ISO（如 9999-12-31）会使 is_auto_backup_due
    恒 False——自动备份静默停摆；auto_backup_interval_hours 拉满 168h 同样大幅拉长
    间隔。三键均属 _INTEGRITY_SENSITIVE_KEYS：完整性失败回退默认（last 为空、
    interval 为 24h）即恢复调度，配合用户可见的完整性告警构成可诊断信号。
    """
    with tempfile.TemporaryDirectory() as root:
        manager = _manager(root)
        manager.set("last_auto_backup_at", "2026-08-01T00:00:00+00:00")
        manager.set("auto_backup_interval_hours", 12)
        manager.set("auto_backup_retention", 20)
        manager.save()

        # 篡改：改写三个调度键的值，保留旧签名行 → 签名失配（mismatch）
        raw = manager.config_path.read_text(encoding="utf-8")
        json_text, sig_line = raw.rsplit("\n", 1)
        tampered = json_text.replace(
            '"last_auto_backup_at": "2026-08-01T00:00:00+00:00"',
            '"last_auto_backup_at": "9999-12-31T23:59:59+00:00"',
        ).replace('"auto_backup_interval_hours": 12', '"auto_backup_interval_hours": 168')
        manager.config_path.write_text(tampered + "\n" + sig_line, encoding="utf-8")

        # 重新加载：完整性失败，调度键回退默认值
        reloaded = _manager(root)
        reloaded.load()
        assert not reloaded.check_integrity()
        assert reloaded.get("last_auto_backup_at") == DEFAULT_CONFIG["last_auto_backup_at"]
        assert reloaded.get("last_auto_backup_at") == ""
        assert (
            reloaded.get("auto_backup_interval_hours")
            == DEFAULT_CONFIG["auto_backup_interval_hours"]
        )
        assert reloaded.get("auto_backup_retention") == DEFAULT_CONFIG["auto_backup_retention"]

        # 回退空时间戳后调度恢复：is_auto_backup_due 重新返回 True（无记录即到期）
        from src.business.services.backup.auto_backup_policy import is_auto_backup_due

        assert is_auto_backup_due(reloaded, force=False) is True


def test_set_rejects_unknown_or_invalid_values():
    """set 拒绝未知键（KeyError）与越界值（ValueError）。"""
    with tempfile.TemporaryDirectory() as root:
        manager = _manager(root)
        with pytest.raises(KeyError):
            manager.set("unknown", True)
        with pytest.raises(ValueError):
            manager.set("auto_lock_minutes", -1)
