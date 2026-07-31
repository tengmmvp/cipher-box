"""自动备份控制器：定时快照编排。

持有自动备份定时器与后台 worker，封装 ``maybe_auto_backup`` 的启用判断、
异步执行与协作取消。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, QTimer

from ...business.managers.backup_restore import BackupRestoreManager
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ..resources.constants import MS_AUTO_BACKUP_CHECK, MS_INITIAL_BACKUP_DELAY

if TYPE_CHECKING:
    from ...business.managers.vault_manager import VaultManager
    from ...config import ConfigManager

logger = logging.getLogger(__name__)


class AutoBackupController:
    """自动备份定时器与 worker 的生命周期管理。"""

    def __init__(
        self,
        vault: VaultManager,
        backup: BackupRestoreManager,
        config: ConfigManager,
    ) -> None:
        self._vault = vault
        self._backup = backup
        self._config = config
        self._parent: QObject | None = None
        self._timer: QTimer | None = None
        self._worker: BackgroundWorker | None = None

    def setup(self, parent: QObject) -> None:
        """创建备份定时器但不启动。

        ``__init__`` 时 vault 尚未解锁，启动会使首次 singleShot 在未解锁状态空转；
        定时器由 ``start_timer`` 在解锁后启动。
        """
        self._parent = parent
        self._timer = QTimer(parent)
        self._timer.setInterval(MS_AUTO_BACKUP_CHECK)
        self._timer.timeout.connect(self._maybe_check)

    def start_timer(self) -> None:
        """解锁后启动定时器（prepare_for_lock 已停止它，解锁后须恢复）。"""
        if self._timer is not None:
            self._timer.start()

    def stop_timer(self) -> None:
        if self._timer is not None:
            self._timer.stop()

    def schedule_initial_check(self) -> None:
        """解锁后延迟首次备份检查，与解锁刷新错峰避免争用主线程。"""
        QTimer.singleShot(MS_INITIAL_BACKUP_DELAY, self._maybe_check)

    def trigger_check(self, force: bool = False) -> None:
        """供设置变更等显式触发（绕过启用开关用 force=True）。"""
        self._maybe_check(force)

    def _maybe_check(self, force: bool = False) -> None:
        """按设置创建当前保险库的本地快速快照，后台执行以避免阻塞 UI。"""
        if not self._vault.is_unlocked:
            return
        # 未启用自动备份时直接返回，避免每 10 分钟空转一个 worker 线程。
        if not force and not self._config.get_safe('auto_backup_enabled', False):
            return
        self._run_async(force)

    def _run_async(self, force: bool = False) -> None:
        """异步执行自动备份。

        maybe_auto_backup 在间隔到期时会执行全量解密 + 备份密钥 Argon2id 派生 +
        加密，同步执行会阻塞 UI 主线程数秒。
        """
        if not self._vault.is_unlocked:
            return
        # 上一个备份仍在运行则跳过，避免覆盖引用导致孤儿线程在锁定后访问已清零密钥
        if self._worker is not None and self._worker.isRunning():
            return

        def _task() -> tuple[bool, str]:
            # worker 是下方赋值的自由变量，闭包延迟绑定：_task 在 worker.run 时执行，
            # 此时 worker 已赋值。cancel_check 直接用 BackgroundWorker 提供的绑定方法，
            # 消除 holder 列表与 lambda 包装。锁定/隐藏到托盘时 wait_worker_shutdown
            # 设置取消标志，maybe_auto_backup 的全量解密循环据此及时退出。
            return self._backup.maybe_auto_backup(
                self._config, force=force,
                cancel_check=worker.cancel_check,
            )

        def _on_backup_error(msg: str) -> None:
            # 守卫：仅当当前备份 worker 仍是本 worker 时记录，避免被后续备份替换后
            # 旧 worker 的延迟错误信号触发误导性日志。worker 为自由变量，延迟绑定。
            if self._worker is worker:
                logger.warning("自动快照失败: %s", msg)

        worker = BackgroundWorker(_task, parent=self._parent)
        worker.error.connect(_on_backup_error)
        self._worker = worker
        worker.start()

    def shutdown(self) -> None:
        """取消并等待 worker 退出，清除引用（锁定/退出/隐藏到托盘前调用）。"""
        wait_worker_shutdown(self._worker)
        self._worker = None

    def cancel(self) -> None:
        """紧急取消 worker（不等待），供 aboutToQuit 等不阻塞退出路径。"""
        if self._worker is not None:
            try:
                self._worker.cancel()
            except RuntimeError:
                pass
