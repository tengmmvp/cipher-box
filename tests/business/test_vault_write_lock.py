"""测试 VaultManager.vault_write_lock 与 epoch_guarded_transaction 的公共契约。

vault_write_lock：验证锁的异常安全性（yield 处抛异常时正确释放）与同线程可重入性，
确保备份/恢复等外部协作者经此公共 API 访问锁时不会因异常导致死锁或锁泄漏。
epoch_guarded_transaction：验证 seam 的嵌套契约守卫（ARCH-058）。
"""

import threading

import pytest

from src.exceptions import TransactionError


class TestVaultWriteLock:
    """验证 vault_write_lock 的锁语义。"""

    def test_lock_released_after_normal_exit(self, vault):
        """正常退出后锁已释放，可再次获取（无泄漏）。"""
        with vault.vault_write_lock():
            pass
        with vault.vault_write_lock():
            pass

    def test_lock_released_on_exception(self, vault):
        """yield 处抛异常时锁正确释放（异常安全，BackupRestoreManager 的契约前提）。"""
        with pytest.raises(ValueError, match="boom"):
            with vault.vault_write_lock():
                raise ValueError("boom")
        with vault.vault_write_lock():
            pass

    def test_lock_reentrant_same_thread(self, vault):
        """RLock 可重入：同线程嵌套获取不死锁（restore 内调 create_backup 重入取锁）。"""
        with vault.vault_write_lock():
            with vault.vault_write_lock():
                pass


class TestEpochGuardedTransactionSeamContract:
    """epoch_guarded_transaction 的 seam 嵌套契约（ARCH-058）。

    seam 两承诺（成功提交后触发 + db_lock 释放后执行）仅顶层事务成立：嵌套调用
    走 SAVEPOINT 分支（RELEASE 非提交、锁仍持），内层退出即触发使承诺失真。入口
    断言把「不支持嵌套」从 docstring 约定升级为结构保证——ARCH-058 演进后由
    ``transaction(require_top_level=True)`` 在 db_manager 同锁临界区内拒绝
    （错误形态从 RuntimeError 变为 TransactionError）。
    """

    def test_nested_call_raises_clear_error(self, vault):
        """外层事务内嵌套调用 → TransactionError 指明要求顶层及理由（外层随之回滚）。"""
        with pytest.raises(TransactionError, match="顶层"):
            with vault.epoch_guarded_transaction(operation="外层"):
                with vault.epoch_guarded_transaction(operation="内层"):
                    pass

    def test_sequential_top_level_calls_still_work(self, vault):
        """守卫不误伤正常形态：先后两个顶层调用照常执行（非嵌套）。"""
        with vault.epoch_guarded_transaction(operation="第一段"):
            pass
        with vault.epoch_guarded_transaction(operation="第二段"):
            pass

    def test_cross_thread_contenders_all_enter_as_top_level(self, vault):
        """跨线程排队不受顶层断言误伤：并发竞争 db_lock 的事务逐一作为顶层执行。

        ARCH-058 演进的回归面：顶层判定在 transaction() 的 db_lock 临界区内进行
        （事务全程持锁，前一线程释放时 depth 已归零），排队线程进入时必见
        depth==0；若把检查移到锁外（裸查 in_transaction），并发竞争者会互相
        误判为嵌套被拒。多线程同时竞争同一 vault 的事务，全部成功即锚定。
        """
        outcomes: list[str] = []
        lock = threading.Lock()

        def _run_txn(label: str) -> None:
            try:
                with vault.epoch_guarded_transaction(operation=label):
                    pass
            except Exception as exc:  # 任意异常（含误拒的 TransactionError）都记为失败供断言
                with lock:
                    outcomes.append(f"{label}: {exc!r}")
            else:
                with lock:
                    outcomes.append(f"{label}: ok")

        threads = [threading.Thread(target=_run_txn, args=(f"t{i}",)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert all(t.is_alive() is False for t in threads)
        assert len(outcomes) == 6
        assert all(r.endswith(": ok") for r in outcomes), outcomes
