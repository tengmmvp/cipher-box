"""数据库线程安全测试。

验证 DatabaseManager 与 VaultManager 在 RLock 保护下的并发访问行为，
覆盖多线程并发读、并发写、读写混合三类场景，确保不出现崩溃或数据丢失。
"""

import threading

from src.database.db_manager import DatabaseManager
from src.database.types import EntryQuery
from src.models import Category, RawEntry


class TestDatabaseThreadSafety:

    def test_concurrent_reads(self, tmp_path):
        """多个线程同时读取不应崩溃。"""
        db = DatabaseManager(tmp_path / 'test.db', test_mode=True)
        db.open()
        db.init_tables()

        errors: list[Exception] = []

        def reader():
            try:
                for _ in range(20):
                    db.get_entries(EntryQuery(include_deleted=False))
                    db.get_categories()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        db.close()

    def test_concurrent_writes(self, tmp_path):
        """多个线程同时写入不应崩溃，且数据不丢失。"""
        db = DatabaseManager(tmp_path / 'test.db', test_mode=True)
        db.open()
        db.init_tables()

        errors: list[Exception] = []

        def writer(i):
            try:
                category = Category(name=f'cat_{i}')
                cat_id = db.add_category(category)
                entry = RawEntry(
                    crypto_id=f'crypto_{i}',
                    title=f'Entry {i}',
                    custom_fields='',
                    category_id=cat_id,
                )
                db.add_entry(entry)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        entries = db.get_entries(EntryQuery())
        assert len(entries) == 5  # RLock 保证全部写入成功
        db.close()

    def test_concurrent_read_write(self, tmp_path):
        """同时读写不应崩溃。"""
        db = DatabaseManager(tmp_path / 'test.db', test_mode=True)
        db.open()
        db.init_tables()

        cat = Category(name='initial_cat')
        cat_id = db.add_category(cat)
        for j in range(5):
            db.add_entry(RawEntry(
                crypto_id=f'init_crypto_{j}',
                title=f'Initial Entry {j}',
                custom_fields='',
                category_id=cat_id,
            ))

        errors: list[Exception] = []

        def reader():
            try:
                for _ in range(30):
                    db.get_entries(EntryQuery(include_deleted=False))
                    db.get_categories()
            except Exception as e:
                errors.append(e)

        def writer(i):
            try:
                for j in range(10):
                    entry = RawEntry(
                        crypto_id=f'rw_crypto_{i}_{j}',
                        title=f'RW Entry {i}-{j}',
                        custom_fields='',
                    )
                    db.add_entry(entry)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer, args=(1,)),
            threading.Thread(target=writer, args=(2,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        db.close()


class TestVaultThreadSafety:

    def test_concurrent_vault_reads(self, vault):
        """多线程同时通过 VaultManager.db 读取条目。"""
        errors: list[Exception] = []

        def read_entries():
            try:
                for _ in range(10):
                    entries = vault.db.get_entries(EntryQuery())
                    assert isinstance(entries, list)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=read_entries) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # join 超时返回不设 errors 会使死锁线程静默「通过」：显式检查线程是否仍
        # 存活，暴露死锁/超时而非误报成功。
        alive = [t for t in threads if t.is_alive()]
        assert not alive, f"线程未在超时内结束（可能死锁）：{len(alive)} 个"
        assert not errors, f"线程安全测试失败: {errors}"
