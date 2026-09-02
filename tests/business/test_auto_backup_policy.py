"""auto_backup_policy 纯策略函数测试。

覆盖 :func:`is_auto_backup_due` 的间隔判定边界（恰好到期/无记录/损坏时间戳/
naive 时间戳/force）与 :func:`purge_expired_auto_backups` 的删文件语义
（retention 保留最新 N 个、0/负 retention、畸形文件名不匹配、目录不存在/
空目录不抛异常）。
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.business.services.backup.auto_backup_policy import (
    is_auto_backup_due,
    purge_expired_auto_backups,
)
from src.config import CFG_AUTO_BACKUP_INTERVAL_HOURS, CFG_LAST_AUTO_BACKUP_AT


class _FakeConfig:
    """最小 AutoBackupConfig 协议实现（仅 get 两键，满足鸭子类型）。

    用类而非 ``{"get": lambda}`` 字典：dict 的原生 ``.get`` 会按键查找遮蔽假实现。
    """

    def __init__(self, last: str = "", hours: int = 24):
        self._values = {CFG_LAST_AUTO_BACKUP_AT: last, CFG_AUTO_BACKUP_INTERVAL_HOURS: hours}

    def get(self, key, default=None):
        return self._values.get(key, default)


def _config(last: str = "", hours: int = 24) -> _FakeConfig:
    return _FakeConfig(last=last, hours=hours)


def _snapshots(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.glob("cipherbox_snapshot_*.cbox"))


class TestIsAutoBackupDue:
    """间隔判定：force / 无记录 / 恰好到期 / 未到期 / 损坏记录。"""

    def test_force_bypasses_interval(self):
        """force=True 无视间隔与记录状态，恒为到期。"""
        now = datetime.now(UTC)
        assert is_auto_backup_due(_config(last=now.isoformat(), hours=24), force=True, now=now)

    def test_no_record_is_due(self):
        """从未备份过（last 为空）视为到期。"""
        assert is_auto_backup_due(_config(last=""), force=False)

    def test_exactly_at_interval_is_due(self):
        """距上次备份恰好等于间隔（elapsed == interval）视为到期（>= 判定）。"""
        now = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
        last = (now - timedelta(hours=24)).isoformat()
        assert is_auto_backup_due(_config(last=last, hours=24), force=False, now=now)

    def test_one_second_before_interval_not_due(self):
        """差一秒未到间隔则跳过（边界严格性：>= 之前为未到期）。"""
        now = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
        # last = now - (24h - 1s) → elapsed = 24h - 1s < 24h
        last = (now - timedelta(hours=23, minutes=59, seconds=59)).isoformat()
        assert not is_auto_backup_due(_config(last=last, hours=24), force=False, now=now)

    def test_over_interval_is_due(self):
        """超过间隔视为到期。"""
        now = datetime.now(UTC)
        last = (now - timedelta(hours=25)).isoformat()
        assert is_auto_backup_due(_config(last=last, hours=24), force=False, now=now)

    def test_malformed_timestamp_is_due(self):
        """损坏的时间戳（非法格式）按到期处理并跳过间隔检查。"""
        assert is_auto_backup_due(_config(last="not-a-timestamp"), force=False)

    def test_naive_timestamp_is_due(self):
        """naive 时间戳（无时区，aware-now 减法抛 TypeError）按到期处理。"""
        assert is_auto_backup_due(_config(last="2026-09-01T00:00:00"), force=False)

    def test_interval_comes_from_config(self):
        """间隔读 config 而非硬编码：25h 前备份在 48h 间隔下未到期。"""
        now = datetime.now(UTC)
        last = (now - timedelta(hours=25)).isoformat()
        assert not is_auto_backup_due(_config(last=last, hours=48), force=False, now=now)


class TestPurgeExpiredAutoBackups:
    """过期快照清理：按文件名降序保留最新 retention 个。"""

    def test_keeps_newest_retention_files(self, tmp_path):
        """按文件名降序保留最新 N 个，更旧的被删除。"""
        for i in range(5):
            (tmp_path / f"cipherbox_snapshot_2023010{i}_000000.cbox").write_bytes(b"x")

        purge_expired_auto_backups(tmp_path, retention=2)

        assert _snapshots(tmp_path) == [
            "cipherbox_snapshot_20230103_000000.cbox",
            "cipherbox_snapshot_20230104_000000.cbox",
        ]

    def test_zero_retention_deletes_all(self, tmp_path):
        """retention=0 删除全部匹配快照。"""
        for i in range(3):
            (tmp_path / f"cipherbox_snapshot_2023010{i}_000000.cbox").write_bytes(b"x")

        purge_expired_auto_backups(tmp_path, retention=0)

        assert _snapshots(tmp_path) == []

    def test_negative_retention_does_not_crash(self, tmp_path):
        """负 retention（配置损坏域）不抛异常，行为落入切片语义。

        secure_purge 的 keep 经 ``matches[keep:]`` 生效：keep=-1 时仅删除最旧
        1 个（``[-1:]`` 切片的偶然后果），并非「全删」也非「全保留」。此处锚定
        该边界的现状（不崩溃 + 确定性结果）；retention 来自用户可改的 config，
        负值属损坏输入，若未来策略层决定钳制为 0，本测试随之更新。
        """
        for i in range(3):
            (tmp_path / f"cipherbox_snapshot_2023010{i}_000000.cbox").write_bytes(b"x")

        purge_expired_auto_backups(tmp_path, retention=-1)

        # 降序 [0102, 0101, 0100] 经 [-1:] 仅剩最旧的 0100 进入删除列表
        assert _snapshots(tmp_path) == [
            "cipherbox_snapshot_20230101_000000.cbox",
            "cipherbox_snapshot_20230102_000000.cbox",
        ]

    def test_malformed_names_not_matched(self, tmp_path):
        """畸形文件名（不匹配 cipherbox_snapshot_*.cbox 模式）不受清理影响。"""
        keep1 = tmp_path / "random_snapshot_20230101_000000.cbox"
        keep2 = tmp_path / "cipherbox_snapshot_old.txt"
        keep1.write_bytes(b"x")
        keep2.write_bytes(b"x")

        purge_expired_auto_backups(tmp_path, retention=0)

        assert keep1.exists()
        assert keep2.exists()

    def test_missing_directory_is_noop(self, tmp_path):
        """目录不存在时不抛异常（secure_purge 跳过缺失目录）。"""
        purge_expired_auto_backups(tmp_path / "no-such-dir", retention=2)

    def test_empty_directory_is_noop(self, tmp_path):
        """空目录清理为无操作。"""
        purge_expired_auto_backups(tmp_path, retention=2)

        assert _snapshots(tmp_path) == []
