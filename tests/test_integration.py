"""集成测试 - 覆盖加密→存储→解密真实流程"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import pytest

from src.business.backup_restore import BackupRestoreManager
from src.business.entry_manager import EntryManager
from src.business.import_export import ImportExportManager
from src.business.security_analyzer import SecurityAnalyzer
from src.business.vault_manager import VaultManager
from src.crypto.encryption import EncryptionEngine
from src.database.db_manager import DatabaseManager
from src.database.models import Category, CustomField, Entry
from tests.helpers import make_test_config


class TestEntryManagerIntegration(unittest.TestCase):
    """条目管理器集成测试（需要 VaultManager + 真实加密）"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        config = make_test_config(self._tmp_dir)
        self._vault = VaultManager(config)
        self._vault.initialize("test_password_123")
        self._entry_mgr = EntryManager(self._vault)

    def tearDown(self):
        self._vault.close()
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_add_and_retrieve_entry(self):
        """添加条目→解密获取→验证所有字段"""
        entry = Entry(
            title='测试网站',
            username='alice@example.com',
            password='Str0ng!P@ssw0rd',
            url='https://example.com',
            tags='测试,集成测试',
            notes='这是一条测试笔记',
            custom_fields=[
                CustomField(name='安全问题', value='小学名字', field_type='text'),
                CustomField(name='API Key', value='sk-12345', field_type='password'),
            ],
            entry_type='login',
            totp_secret='JBSWY3DPEHPK3PXP',
        )
        entry_id = self._entry_mgr.add_entry(entry)
        self.assertGreater(entry_id, 0)

        # 获取并解密
        entries = self._entry_mgr.get_entries()
        self.assertEqual(len(entries), 1)

        decrypted = entries[0]
        self.assertEqual(decrypted.title, '测试网站')
        self.assertEqual(decrypted.username, 'alice@example.com')
        self.assertEqual(decrypted.password, 'Str0ng!P@ssw0rd')
        self.assertEqual(decrypted.url, 'https://example.com')
        self.assertEqual(decrypted.tags, '测试,集成测试')
        self.assertEqual(decrypted.notes, '这是一条测试笔记')
        self.assertEqual(decrypted.entry_type, 'login')
        self.assertEqual(decrypted.totp_secret, 'JBSWY3DPEHPK3PXP')

        # 验证自定义字段
        fields = decrypted.custom_fields
        assert isinstance(fields, list)
        self.assertEqual(len(fields), 2)
        self.assertEqual(fields[0].name, '安全问题')
        self.assertEqual(fields[0].value, '小学名字')
        self.assertEqual(fields[1].name, 'API Key')
        self.assertEqual(fields[1].value, 'sk-12345')

    def test_update_preserves_password_history(self):
        """更新密码→密码历史记录归档→验证旧密码可查"""
        # 1. 添加条目
        entry = Entry(
            title='历史记录测试',
            username='user1',
            password='OldPassword123!',
        )
        entry_id = self._entry_mgr.add_entry(entry)

        # 2. 修改密码
        entry.id = entry_id
        entry.password = 'NewPassword456!'
        self._entry_mgr.update_entry(entry)

        # 3. 查询密码历史，验证旧密码存在
        history = self._entry_mgr.get_password_history(entry_id)
        self.assertEqual(len(history), 1)

        # 解密历史记录中的旧密码
        decrypted_history = self._entry_mgr.decrypt_password_history(history)
        self.assertEqual(len(decrypted_history), 1)
        self.assertEqual(decrypted_history[0]['password'], 'OldPassword123!')

        # 验证当前密码是新密码
        current = self._entry_mgr.get_entry(entry_id)
        assert current is not None
        self.assertEqual(current.password, 'NewPassword456!')

    def test_search_by_username(self):
        """搜索用户名能返回结果"""
        # 1. 添加两个条目（不同的 username）
        entry_a = Entry(
            title='站点 A',
            username='alice@wonderland.com',
            password='P@ssw0rdA!',
        )
        entry_b = Entry(
            title='站点 B',
            username='bob@builder.com',
            password='P@ssw0rdB!',
        )
        self._entry_mgr.add_entry(entry_a)
        self._entry_mgr.add_entry(entry_b)

        # 2. 用 username 搜索
        results = self._entry_mgr.get_entries(search='alice')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].username, 'alice@wonderland.com')

        # 搜索另一个
        results_b = self._entry_mgr.get_entries(search='bob')
        self.assertEqual(len(results_b), 1)
        self.assertEqual(results_b[0].username, 'bob@builder.com')

        # 搜索不存在的
        results_none = self._entry_mgr.get_entries(search='charlie')
        self.assertEqual(len(results_none), 0)

    def test_toggle_favorite(self):
        """切换收藏状态"""
        # 1. 添加条目
        entry = Entry(
            title='收藏测试',
            username='user_fav',
            password='Password123!',
        )
        entry_id = self._entry_mgr.add_entry(entry)

        # 2. 验证初始状态为非收藏
        entry_before = self._entry_mgr.get_entry(entry_id)
        assert entry_before is not None
        self.assertFalse(entry_before.is_favorite)

        # 3. toggle_favorite
        self._entry_mgr.toggle_favorite(entry_id)

        # 4. 获取条目验证 is_favorite 为 True
        entry_after = self._entry_mgr.get_entry(entry_id)
        assert entry_after is not None
        self.assertTrue(entry_after.is_favorite)

        # 再次 toggle 应变回 False
        self._entry_mgr.toggle_favorite(entry_id)
        entry_final = self._entry_mgr.get_entry(entry_id)
        assert entry_final is not None
        self.assertFalse(entry_final.is_favorite)

    def test_toggle_favorite_returns_new_state(self):
        """toggle_favorite 应返回新的收藏状态"""
        entry = Entry(title='收藏返回值测试', username='fav_user', password='Password123!')
        entry_id = self._entry_mgr.add_entry(entry)

        # 初始状态应为非收藏
        new_state = self._entry_mgr.toggle_favorite(entry_id)
        assert new_state is True

        # 再次切换
        new_state = self._entry_mgr.toggle_favorite(entry_id)
        assert new_state is False

    def test_toggle_favorite_nonexistent_returns_none(self):
        """切换不存在条目的收藏状态应返回 None"""
        result = self._entry_mgr.toggle_favorite(99999)
        assert result is None

    def test_get_all_tags(self):
        """获取标签频率统计"""
        # 1. 添加多个带标签的条目
        entries_data = [
            Entry(title='E1', username='u1', password='P1!', tags='社交,邮箱'),
            Entry(title='E2', username='u2', password='P2!', tags='社交,工作'),
            Entry(title='E3', username='u3', password='P3!', tags='社交,邮箱,金融'),
        ]
        for e in entries_data:
            self._entry_mgr.add_entry(e)

        # 2. 调用 get_all_tags
        tags = self._entry_mgr.get_all_tags()

        # 3. 验证标签和频率正确
        tag_dict = dict(tags)
        self.assertEqual(tag_dict['社交'], 3)
        self.assertEqual(tag_dict['邮箱'], 2)
        self.assertEqual(tag_dict['工作'], 1)
        self.assertEqual(tag_dict['金融'], 1)


class TestVaultManagerLifecycle(unittest.TestCase):
    """保险库生命周期测试（需要真实密钥派生）"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._config = make_test_config(self._tmp_dir)

    def _create_vault(self) -> VaultManager:
        return VaultManager(self._config)

    def tearDown(self):
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_initialize_and_unlock(self):
        """初始化→锁定→解锁→验证数据可读"""
        master_pwd = "test_password_123"

        # 1. 初始化并添加条目
        vault = self._create_vault()
        self.assertTrue(vault.initialize(master_pwd))
        self.assertTrue(vault.is_unlocked)

        entry_mgr = EntryManager(vault)
        entry_id = entry_mgr.add_entry(Entry(
            title='持久化测试',
            username='persistent_user',
            password='PersistentP@ss!',
        ))
        self.assertGreater(entry_id, 0)

        # 2. 锁定
        vault.lock()
        self.assertFalse(vault.is_unlocked)
        self.assertIsNone(vault.key)

        # 3. 解锁
        self.assertTrue(vault.unlock(master_pwd))
        self.assertTrue(vault.is_unlocked)
        self.assertIsNotNone(vault.key)

        # 4. 验证数据可读
        entry_mgr2 = EntryManager(vault)
        entries = entry_mgr2.get_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].title, '持久化测试')
        self.assertEqual(entries[0].username, 'persistent_user')
        self.assertEqual(entries[0].password, 'PersistentP@ss!')

        # 用错误密码解锁应失败
        vault.lock()
        self.assertFalse(vault.unlock("wrong_password"))

        vault.close()

    def test_change_password_re_encrypts(self):
        """改密后所有条目可用新密钥解密"""
        old_pwd = "old_password_123"
        new_pwd = "new_password_456"

        # 1. 初始化 + 添加条目
        vault = self._create_vault()
        vault.initialize(old_pwd)
        entry_mgr = EntryManager(vault)

        totp_secret = 'JBSWY3DPEHPK3PXP'
        entry_id = entry_mgr.add_entry(Entry(
            title='改密测试',
            username='rekey_user',
            password='MySecretP@ss!',
            totp_secret=totp_secret,
        ))

        # 2. change_master_password
        self.assertTrue(vault.change_master_password(old_pwd, new_pwd))

        # 3. 验证 get_entries 仍能正确解密
        entry_mgr2 = EntryManager(vault)
        entries = entry_mgr2.get_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].username, 'rekey_user')
        self.assertEqual(entries[0].password, 'MySecretP@ss!')

        # 4. 验证 totp_secret 也正确重加密
        self.assertEqual(entries[0].totp_secret, totp_secret)

        # 5. 锁定后用新密码解锁，验证仍然可用
        vault.lock()
        self.assertTrue(vault.unlock(new_pwd))
        entry_mgr3 = EntryManager(vault)
        entry = entry_mgr3.get_entry(entry_id)
        assert entry is not None
        self.assertEqual(entry.username, 'rekey_user')
        self.assertEqual(entry.password, 'MySecretP@ss!')
        self.assertEqual(entry.totp_secret, totp_secret)

        # 6. 用旧密码解锁应失败
        vault.lock()
        self.assertFalse(vault.unlock(old_pwd))

        vault.close()


class TestBackupRestore(unittest.TestCase):
    """备份恢复测试（需要真实加密）"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        config = make_test_config(self._tmp_dir)
        self._vault = VaultManager(config)
        self._vault.initialize("test_password_123")
        self._entry_mgr = EntryManager(self._vault)
        self._backup_mgr = BackupRestoreManager(self._vault)

    def tearDown(self):
        self._vault.close()
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_backup_and_restore_preserves_all_fields(self):
        """备份→恢复→验证 entry_type/totp/password_history 完整"""
        # 1. 初始化 + 添加条目（含 entry_type, totp_secret）
        entry_id = self._entry_mgr.add_entry(Entry(
            title='备份测试',
            username='backup_user',
            password='OriginalP@ss!',
            entry_type='server',
            totp_secret='JBSWY3DPEHPK3PXP',
            tags='重要,服务器',
            notes='服务器凭据',
        ))

        # 2. 修改密码（产生历史记录）
        entry = Entry(
            id=entry_id,
            title='备份测试',
            username='backup_user',
            password='UpdatedP@ss!',
            entry_type='server',
            totp_secret='JBSWY3DPEHPK3PXP',
            tags='重要,服务器',
            notes='服务器凭据',
        )
        self._entry_mgr.update_entry(entry)

        # 3. 创建备份（H3：必须指定密码或使用快照密钥，flags=0 已移除）
        backup_path = str(Path(self._tmp_dir) / 'test_backup.cbox')
        self.assertTrue(self._backup_mgr.create_backup(backup_path, use_snapshot_key=True))
        self.assertTrue(os.path.exists(backup_path))

        # 4. 清空条目（通过删除后恢复来验证）
        self._entry_mgr.permanent_delete_entry(entry_id)
        self.assertEqual(len(self._entry_mgr.get_entries()), 0)

        # 5. 恢复备份
        self.assertTrue(self._backup_mgr.restore_backup(backup_path))

        # 6. 验证所有字段完整
        entries = self._entry_mgr.get_entries()
        self.assertEqual(len(entries), 1)

        restored = entries[0]
        self.assertEqual(restored.title, '备份测试')
        self.assertEqual(restored.username, 'backup_user')
        self.assertEqual(restored.password, 'UpdatedP@ss!')
        self.assertEqual(restored.entry_type, 'server')
        self.assertEqual(restored.totp_secret, 'JBSWY3DPEHPK3PXP')
        self.assertEqual(restored.tags, '重要,服务器')
        self.assertEqual(restored.notes, '服务器凭据')

        # 验证密码历史恢复
        assert restored.id is not None
        history = self._entry_mgr.get_password_history(restored.id)
        decrypted_history = self._entry_mgr.decrypt_password_history(history)
        self.assertEqual(len(decrypted_history), 1)
        self.assertEqual(decrypted_history[0]['password'], 'OriginalP@ss!')

    def test_rejects_unknown_format(self):
        """仅接受 CipherBox 当前固定格式。"""
        backup_path = str(Path(self._tmp_dir) / 'unknown_backup.cbox')
        with open(backup_path, 'wb') as f:
            f.write(b'CBOX-UNKNOWN')

        success, error = self._backup_mgr.restore_backup(backup_path)
        self.assertFalse(success)
        self.assertIn('无效的备份文件格式', error)

    def test_snapshot_survives_master_password_change(self):
        entry_id = self._entry_mgr.add_entry(Entry(
            title='快照条目', password='SnapshotSecret!2026'
        ))
        backup_path = str(Path(self._tmp_dir) / 'snapshot.cbox')
        success, error = self._backup_mgr.create_backup(
            backup_path, use_snapshot_key=True
        )
        self.assertTrue(success, error)

        self.assertTrue(self._vault.change_master_password(
            'test_password_123', 'NewMasterPassword!2026'
        ))
        self._entry_mgr.permanent_delete_entry(entry_id)
        success, error = self._backup_mgr.restore_backup(backup_path)
        self.assertTrue(success, error)
        restored = self._entry_mgr.get_entries()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].password, 'SnapshotSecret!2026')


class TestSecurityAnalyzer(unittest.TestCase):
    """安全分析器测试"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        config = make_test_config(self._tmp_dir)
        self._vault = VaultManager(config)
        self._vault.initialize("test_password_123")
        self._entry_mgr = EntryManager(self._vault)
        self._analyzer = SecurityAnalyzer(self._vault)

    def tearDown(self):
        self._vault.close()
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_find_weak_passwords(self):
        """检测弱密码"""
        # 添加弱密码条目（常见密码 "password" 会被评为 0-1 分）
        self._entry_mgr.add_entry(Entry(
            title='弱密码条目',
            username='weak_user',
            password='password',
        ))
        # 添加强密码条目
        self._entry_mgr.add_entry(Entry(
            title='强密码条目',
            username='strong_user',
            password='S#r0ng!P@ssw0rd2025',
        ))

        weak = self._analyzer.find_weak_passwords()
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0].title, '弱密码条目')
        self.assertEqual(weak[0].username, 'weak_user')
        self.assertEqual(weak[0].password, '')
        self.assertTrue(weak[0].password_present)

    def test_find_duplicate_passwords(self):
        """检测重复密码分组"""
        shared_pwd = 'DuplicateP@ss123!'
        # 添加两个相同密码的条目
        self._entry_mgr.add_entry(Entry(
            title='重复条目 A',
            username='dup_user_a',
            password=shared_pwd,
        ))
        self._entry_mgr.add_entry(Entry(
            title='重复条目 B',
            username='dup_user_b',
            password=shared_pwd,
        ))
        # 添加一个不同密码的条目
        self._entry_mgr.add_entry(Entry(
            title='唯一条目',
            username='unique_user',
            password='UniqueP@ss456!',
        ))

        groups = self._analyzer.find_duplicate_passwords()
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]), 2)
        titles = {e.title for e in groups[0]}
        self.assertIn('重复条目 A', titles)
        self.assertIn('重复条目 B', titles)

    def test_full_analysis(self):
        """full_analysis 一次性返回所有指标"""
        shared_pwd = 'DuplicateP@ss!'
        # 弱密码
        self._entry_mgr.add_entry(Entry(
            title='弱条目',
            username='weak',
            password='123456',
        ))
        # 两个重复密码
        self._entry_mgr.add_entry(Entry(
            title='重复 A',
            username='dup_a',
            password=shared_pwd,
        ))
        self._entry_mgr.add_entry(Entry(
            title='重复 B',
            username='dup_b',
            password=shared_pwd,
        ))

        result = self._analyzer.full_analysis()

        # 验证返回结构完整
        self.assertIn('total', result)
        self.assertIn('weak_count', result)
        self.assertIn('weak_entries', result)
        self.assertIn('duplicate_groups', result)
        self.assertIn('duplicate_count', result)
        self.assertIn('old_entries', result)
        self.assertIn('old', result)

        self.assertEqual(result['total'], 3)
        self.assertGreaterEqual(result['weak_count'], 1)
        self.assertEqual(result['duplicate_count'], 1)  # 2 个重复中有 1 个多余


@pytest.mark.usefixtures('_disable_encrypted_assertions')
class TestDatabaseTransaction(unittest.TestCase):
    """数据库事务机制测试"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._db_path = Path(self._tmp_dir) / 'test_vault.db'
        self._db = DatabaseManager(self._db_path)
        self._db.open()
        self._db.init_tables()

    def tearDown(self):
        self._db.close()
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_transaction_commit(self):
        """begin→多个操作→commit，所有变更持久化"""
        initial_count = self._db.get_entry_count()

        self._db.begin_transaction()
        try:
            # 添加两个条目（custom_fields 必须为字符串，不能为 list）
            e1 = Entry(title='事务条目1', username='tx_user1', password='tx_pwd1',
                        notes='', custom_fields='')
            e2 = Entry(title='事务条目2', username='tx_user2', password='tx_pwd2',
                        notes='', custom_fields='')
            self._db.add_entry(e1)
            self._db.add_entry(e2)

            # 添加分类
            cat = Category(name='事务分类', icon_char='🔧', color='#FF0000')
            self._db.add_category(cat)

            self._db.commit_transaction()
        except Exception:
            self._db.rollback_transaction()
            raise

        # 验证所有变更已持久化
        self.assertEqual(self._db.get_entry_count(), initial_count + 2)
        categories = self._db.get_categories()
        cat_names = [c.name for c in categories]
        self.assertIn('事务分类', cat_names)

    def test_transaction_rollback(self):
        """begin→多个操作→rollback，所有变更丢弃"""
        initial_count = self._db.get_entry_count()

        self._db.begin_transaction()
        try:
            # 添加条目（custom_fields 必须为字符串，不能为 list）
            e = Entry(title='回滚条目', username='rb_user', password='rb_pwd',
                      notes='', custom_fields='')
            self._db.add_entry(e)

            # 添加分类
            cat = Category(name='回滚分类', icon_char='🔙', color='#000000')
            self._db.add_category(cat)

            # 回滚
            self._db.rollback_transaction()
        except Exception:
            self._db.rollback_transaction()
            raise

        # 验证所有变更已丢弃
        self.assertEqual(self._db.get_entry_count(), initial_count)
        categories = self._db.get_categories()
        cat_names = [c.name for c in categories]
        self.assertNotIn('回滚分类', cat_names)


class TestImportExport(unittest.TestCase):
    """导入导出测试（JSON/CSV 往返 + 去重检测）"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        config = make_test_config(self._tmpdir)
        self._vault = VaultManager(config)
        self._vault.initialize("test_password_123")
        self._entry_mgr = EntryManager(self._vault)
        self._import_export = ImportExportManager(self._entry_mgr)

    def tearDown(self):
        self._vault.close()
        shutil.rmtree(self._tmpdir)

    def test_json_roundtrip(self):
        """JSON 导出→导入→数据完整"""
        # 1. 添加条目
        entry = Entry(
            title='导入导出测试',
            username='export_user@example.com',
            password='ExportP@ss123!',
            url='https://export.example.com',
            tags='导入,导出',
            notes='测试笔记',
        )
        entry_id = self._entry_mgr.add_entry(entry)
        self.assertGreater(entry_id, 0)

        # 2. 导出 JSON
        entries = self._entry_mgr.get_entries()
        json_path = str(Path(self._tmpdir) / 'export.json')
        self._import_export.export_to_json(
            json_path, entries, include_password=True
        )
        self.assertTrue(os.path.exists(json_path))

        # 3. 删除条目
        self._entry_mgr.permanent_delete_entry(entry_id)
        self.assertEqual(len(self._entry_mgr.get_entries()), 0)

        # 4. 导入 JSON
        count = self._import_export.import_from_json(json_path)
        self.assertEqual(count, 1)

        # 5. 验证数据完整
        restored = self._entry_mgr.get_entries()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].title, '导入导出测试')
        self.assertEqual(restored[0].username, 'export_user@example.com')
        self.assertEqual(restored[0].password, 'ExportP@ss123!')
        self.assertEqual(restored[0].url, 'https://export.example.com')
        self.assertEqual(restored[0].tags, '导入,导出')
        self.assertEqual(restored[0].notes, '测试笔记')

    def test_csv_roundtrip(self):
        """CSV 导出→导入→基本字段保留"""
        # 1. 添加条目
        entry = Entry(
            title='CSV测试条目',
            username='csv_user@example.com',
            password='CsvP@ss456!',
            url='https://csv.example.com',
            tags='csv,测试',
            notes='CSV笔记',
        )
        entry_id = self._entry_mgr.add_entry(entry)
        self.assertGreater(entry_id, 0)

        # 2. 导出 CSV
        entries = self._entry_mgr.get_entries()
        csv_path = str(Path(self._tmpdir) / 'export.csv')
        self._import_export.export_to_csv(
            csv_path, entries, include_password=True
        )
        self.assertTrue(os.path.exists(csv_path))

        # 3. 删除条目
        self._entry_mgr.permanent_delete_entry(entry_id)
        self.assertEqual(len(self._entry_mgr.get_entries()), 0)

        # 4. 导入 CSV
        count = self._import_export.import_from_csv(csv_path)
        self.assertEqual(count, 1)

        # 5. 验证基本字段（title, username, url）
        restored = self._entry_mgr.get_entries()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].title, 'CSV测试条目')
        self.assertEqual(restored[0].username, 'csv_user@example.com')
        self.assertEqual(restored[0].url, 'https://csv.example.com')

    def test_duplicate_detection(self):
        """导入去重检测"""
        # 1. 添加条目
        entry = Entry(
            title='重复测试',
            username='dup_user@example.com',
            password='DupP@ss789!',
        )
        self._entry_mgr.add_entry(entry)

        # 2. 构造重复数据
        duplicate_data = [
            {
                'title': '重复测试',
                'username': 'dup_user@example.com',
                'password': 'AnotherP@ss!',
            },
        ]
        existing = self._entry_mgr.get_entries()

        # 3. check_duplicates 应返回匹配
        duplicates = ImportExportManager.check_duplicates(duplicate_data, existing)
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]['title'], '重复测试')
        self.assertEqual(duplicates[0]['username'], 'dup_user@example.com')
        self.assertEqual(duplicates[0]['existing_title'], '重复测试')


class TestErrorPaths(unittest.TestCase):
    """错误路径测试（边界和异常场景）"""

    def test_decrypt_with_wrong_key(self):
        """用错误密钥解密应抛出 ValueError"""
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        aad = 'test:integration'
        ciphertext = EncryptionEngine.encrypt("hello", key1, aad)
        self.assertNotEqual(ciphertext, '')

        # AES-GCM 会因 tag 校验失败而抛出 ValueError
        with self.assertRaises(ValueError):
            EncryptionEngine.decrypt(ciphertext, key2, aad)

    def test_backup_with_locked_vault(self):
        """锁定状态创建备份应失败"""
        self._tmp_dir = tempfile.mkdtemp()
        config = make_test_config(self._tmp_dir)
        vault = VaultManager(config)
        vault.initialize("test_password_123")
        backup_mgr = BackupRestoreManager(vault)

        # 锁定保险库
        vault.lock()
        self.assertFalse(vault.is_unlocked)

        # 创建备份应返回 (False, error_msg)
        backup_path = str(Path(self._tmp_dir) / 'locked_backup.cbox')
        result = backup_mgr.create_backup(backup_path)
        self.assertFalse(result[0])
        self.assertTrue(len(result[1]) > 0)  # 应有错误信息

        vault.close()
        shutil.rmtree(self._tmp_dir)

    def test_change_password_wrong_old(self):
        """旧密码错误时改密应失败"""
        self._tmp_dir = tempfile.mkdtemp()
        config = make_test_config(self._tmp_dir)
        vault = VaultManager(config)
        vault.initialize("OriginalMaster!2026")

        # 用错误的旧密码改密应返回 False
        result = vault.change_master_password(
            "WrongOldMaster!2026", "NewMasterPassword!2026"
        )
        self.assertFalse(result)

        # 验证原密码仍然可用
        vault.lock()
        self.assertTrue(vault.unlock("OriginalMaster!2026"))

        vault.close()
        shutil.rmtree(self._tmp_dir)

    def test_is_initialized_returns_false_when_db_cannot_open(self):
        """is_initialized 在 DB 打开失败时应返回 False"""
        from unittest.mock import PropertyMock, patch
        self._tmp_dir = tempfile.mkdtemp()
        config = make_test_config(self._tmp_dir)
        vault = VaultManager(config)

        # 确保 db_path 存在使文件检查通过
        db_file = Path(self._tmp_dir) / 'vault.db'
        db_file.touch()

        # Mock: is_open 返回 False, open() 返回 False → 模拟 DB 无法打开
        with patch.object(type(vault._db), 'is_open', new_callable=PropertyMock, return_value=False):
            with patch.object(vault._db, 'open', return_value=False):
                result = vault.is_initialized
                self.assertFalse(result)
                self.assertIn('数据库无法打开', vault.last_error)

        vault.close()
        shutil.rmtree(self._tmp_dir)


if __name__ == '__main__':
    unittest.main()
