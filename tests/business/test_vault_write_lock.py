"""测试 VaultManager.vault_write_lock 公共上下文管理器。

验证锁的异常安全性（yield 处抛异常时正确释放）与同线程可重入性，确保
备份/恢复等外部协作者经此公共 API 访问锁时不会因异常导致死锁或锁泄漏。
"""

import pytest


class TestVaultWriteLock:
    """验证 vault_write_lock 的锁语义。"""

    def test_lock_released_after_normal_exit(self, vault):
        """正常退出后锁已释放，可再次获取（无泄漏）。"""
        with vault.vault_write_lock():
            pass
        # 再次获取不应阻塞或死锁
        with vault.vault_write_lock():
            pass

    def test_lock_released_on_exception(self, vault):
        """yield 处抛异常时锁正确释放（异常安全，BackupRestoreManager 的契约前提）。"""
        with pytest.raises(ValueError, match='boom'):
            with vault.vault_write_lock():
                raise ValueError('boom')
        # 异常后锁已释放，可再次获取
        with vault.vault_write_lock():
            pass

    def test_lock_reentrant_same_thread(self, vault):
        """RLock 可重入：同线程嵌套获取不死锁（restore 内调 create_backup 重入取锁）。"""
        with vault.vault_write_lock():
            with vault.vault_write_lock():
                pass
