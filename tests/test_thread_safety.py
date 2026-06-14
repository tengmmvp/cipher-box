"""数据库线程安全测试。

验证 DatabaseManager 与 VaultManager 在 RLock 保护下的并发访问行为，
覆盖多线程并发读、并发写、读写混合三类场景，确保不出现崩溃或数据丢失。
"""

import threading

import pytest

from src.database.db_manager import DatabaseManager
from src.models import Category, RawEntry


@pytest.mark.usefixtures('_disable_encrypted_assertions')
class TestDatabaseThreadSafety:
    """测试 DatabaseManager 在并发访问下的行为。"""

    def test_concurrent_reads(self, tmp_path):
        """多个线程同时读取不应崩溃。"""
        db = DatabaseManager(tmp_path / 'test.db')
        db.open()
        db.init_tables()

        errors: list[Exception] = []

        def reader():
            try:
                for _ in range(20):
                    db.get_entries(include_deleted=False)
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
        db = DatabaseManager(tmp_path / 'test.db')
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
        entries = db.get_entries()
        assert len(entries) == 5  # RLock 保证全部写入成功
        db.close()

    def test_concurrent_read_write(self, tmp_path):
        """同时读写不应崩溃。"""
        db = DatabaseManager(tmp_path / 'test.db')
        db.open()
        db.init_tables()

        # 先插入一些初始数据
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
                    db.get_entries(include_deleted=False)
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
    """测试 VaultManager 在并发访问下的行为。"""

    def test_concurrent_vault_reads(self, vault):
        """多线程同时通过 VaultManager.db 读取条目。"""
        errors: list[Exception] = []

        def read_entries():
            try:
                for _ in range(10):
                    entries = vault.db.get_entries()
                    assert isinstance(entries, list)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=read_entries) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"线程安全测试失败: {errors}"
