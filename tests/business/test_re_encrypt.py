from tests.helpers import make_entry_manager

"""_re_encrypt_all 边界条件测试，覆盖空字段、custom_fields 类型、密码历史与事务回滚。

通过 change_master_password 触发全量重加密，验证空字段保持空、
已删除条目、密码历史、自定义字段在改密后均可正确解密，
并验证写入失败时事务回滚保障数据完整性。
"""

from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from src.business.managers.vault_manager import VaultManager
from src.models import CustomField, Entry


class TestReEncryptEdgeCases:
    """_re_encrypt_all 边界条件。"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, tmp_path, vault_config):
        self._tmp_dir = str(tmp_path)
        self._vault = VaultManager(vault_config)
        self._vault.initialize('original_pwd_123')
        self._entry_mgr = make_entry_manager(self._vault)
        yield
        self._vault.close()
        db_path = Path(self._tmp_dir) / 'vault.db'
        try:
            db_path.unlink(missing_ok=True)
            for suffix in ('-wal', '-shm'):
                p = Path(str(db_path) + suffix)
                p.unlink(missing_ok=True)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 1. 空字段：notes=''、totp_secret=''、username=''
    # ------------------------------------------------------------------
    def test_re_encrypt_empty_fields(self):
        """空字符串字段在改密后保持空字符串。"""
        self._entry_mgr.add_entry(Entry(
            title='空字段测试',
            username='',
            password='has_password',
            notes='',
            totp_secret='',
        ))

        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'new_password_456'
        )
        assert ok

        entries = self._entry_mgr.get_entries()
        assert len(entries) == 1
        assert entries[0].username == ''
        assert entries[0].notes == ''
        assert entries[0].totp_secret == ''
        assert entries[0].password == 'has_password'

    # ------------------------------------------------------------------
    # 2. 完整字段：所有 5 个敏感字段都有值
    # ------------------------------------------------------------------
    def test_re_encrypt_all_fields_populated(self):
        """所有敏感字段都有值时改密后完整保留。"""
        custom = [CustomField(name='备注', value='测试值', field_type='text')]
        self._entry_mgr.add_entry(Entry(
            title='完整字段测试',
            username='user@example.com',
            password='Str0ng!Pass',
            notes='这些是备注',
            totp_secret='JBSWY3DPEHPK3PXP',
            custom_fields=custom,
        ))

        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'new_password_456'
        )
        assert ok

        entries = self._entry_mgr.get_entries()
        assert len(entries) == 1
        e = entries[0]
        assert e.username == 'user@example.com'
        assert e.password == 'Str0ng!Pass'
        assert e.notes == '这些是备注'
        assert e.totp_secret == 'JBSWY3DPEHPK3PXP'
        assert len(e.custom_fields) == 1
        assert cast(list[CustomField], e.custom_fields)[0].name == '备注'
        assert cast(list[CustomField], e.custom_fields)[0].value == '测试值'

    # ------------------------------------------------------------------
    # 3. 已删除条目在改密后仍可解密
    # ------------------------------------------------------------------
    def test_re_encrypt_deleted_entry(self):
        """已软删除的条目在改密后仍可正确解密。"""
        eid = self._entry_mgr.add_entry(Entry(
            title='待删除条目',
            username='deleted_user',
            password='deleted_pass',
        ))
        self._entry_mgr.delete_entry(eid)

        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'new_password_456'
        )
        assert ok

        # 获取包含已删除条目的列表
        entries = self._entry_mgr.get_entries(include_deleted=True)
        assert len(entries) == 1
        assert entries[0].username == 'deleted_user'
        assert entries[0].password == 'deleted_pass'
        assert entries[0].is_deleted

    # ------------------------------------------------------------------
    # 4. 密码历史在改密后仍可解密
    # ------------------------------------------------------------------
    def test_re_encrypt_password_history(self):
        """密码历史在改密后仍可正确解密。"""
        eid = self._entry_mgr.add_entry(Entry(
            title='密码历史测试',
            username='hist_user',
            password='first_password',
        ))

        # 修改密码触发历史记录
        entry = self._entry_mgr.get_entry(eid)
        assert entry is not None
        entry.password = 'second_password'
        self._entry_mgr.update_entry(entry)

        # 验证密码历史存在
        history = self._entry_mgr.password_history.decrypt(
            self._entry_mgr.password_history.get(eid)
        )
        assert len(history) == 1
        assert history[0]['password'] == 'first_password'

        # 改密
        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'new_password_456'
        )
        assert ok

        # 验证改密后密码历史仍可解密
        history2 = self._entry_mgr.password_history.decrypt(
            self._entry_mgr.password_history.get(eid)
        )
        assert len(history2) == 1
        assert history2[0]['password'] == 'first_password'

        # 验证当前密码也正确
        e = self._entry_mgr.get_entry(eid)
        assert e is not None
        assert e.password == 'second_password'

    # ------------------------------------------------------------------
    # 5. 多条目混合：部分字段为空，部分字段有值
    # ------------------------------------------------------------------
    def test_re_encrypt_mixed_entries(self):
        """多条目混合场景：空字段和完整字段交替。"""
        self._entry_mgr.add_entry(Entry(
            title='只有密码',
            password='pass1',
        ))
        self._entry_mgr.add_entry(Entry(
            title='全字段',
            username='full_user',
            password='pass2',
            notes='notes',
            totp_secret='JBSWY3DPEHPK3PXP',
            custom_fields=[CustomField(name='k', value='v', field_type='text')],
        ))
        self._entry_mgr.add_entry(Entry(
            title='只有用户名',
            username='name_only',
            password='',
        ))

        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'new_password_456'
        )
        assert ok

        entries = self._entry_mgr.get_entries()
        assert len(entries) == 3

        by_title = {e.title: e for e in entries}
        assert by_title['只有密码'].password == 'pass1'
        assert by_title['只有密码'].username == ''

        assert by_title['全字段'].username == 'full_user'
        assert by_title['全字段'].password == 'pass2'
        assert by_title['全字段'].totp_secret == 'JBSWY3DPEHPK3PXP'

        assert by_title['只有用户名'].username == 'name_only'
        assert by_title['只有用户名'].password == ''

    # ------------------------------------------------------------------
    # 6. 改密失败时事务回滚保护数据完整性
    # ------------------------------------------------------------------
    def test_re_encrypt_rollback_on_failure(self):
        """解密失败时回滚事务，原数据仍可用。"""
        self._entry_mgr.add_entry(Entry(
            title='回滚保护测试',
            username='rollback_user',
            password='original_pass',
        ))

        # 模拟底层 DB 写入失败以触发事务回滚。
        # 改密流程使用 update_entries_batch 批量写入，故 patch 该批量方法。
        def failing_batch(rows):
            raise OSError('模拟写入失败')

        with patch.object(self._vault._db, 'update_entries_batch', side_effect=failing_batch):
            ok, _ = self._vault.change_master_password(
                'original_pwd_123', 'new_password_456'
            )

        # 改密应失败，OSError 被 except Exception 捕获并返回 False
        assert not ok

        # 改密失败后旧密钥仍有效，会话保留；事务回滚保障数据完好
        assert self._vault.unlock('original_pwd_123')[0]
        entry_mgr = make_entry_manager(self._vault)
        entries = entry_mgr.get_entries()
        assert len(entries) == 1
        assert entries[0].username == 'rollback_user'
        assert entries[0].password == 'original_pass'

    # ------------------------------------------------------------------
    # 7. 多条目全部字段保留
    # ------------------------------------------------------------------
    def test_re_encrypt_preserves_all_entries(self):
        """重新加密后所有条目数据完整。"""
        for i in range(5):
            self._entry_mgr.add_entry(Entry(
                title=f'条目{i}',
                username=f'user{i}',
                password=f'password{i}!@#',
                url=f'https://example.com/{i}',
                notes=f'备注{i}',
                entry_type='login',
            ))

        originals = self._entry_mgr.get_entries()

        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'new_password_456'
        )
        assert ok

        assert self._vault.unlock('new_password_456')[0]

        restored = self._entry_mgr.get_entries()
        assert len(restored) == len(originals)
        for orig, rest in zip(
            sorted(originals, key=lambda e: e.title),
            sorted(restored, key=lambda e: e.title),
            strict=True,
        ):
            assert rest.title == orig.title
            assert rest.username == orig.username
            assert rest.password == orig.password
            assert rest.url == orig.url
            assert rest.notes == orig.notes

    # ------------------------------------------------------------------
    # 8. 超过批次大小的条目也能正确重新加密
    # ------------------------------------------------------------------
    def test_re_encrypt_with_more_than_batch_size(self):
        """超过批次大小的条目也能正确重新加密。"""
        for i in range(10):
            self._entry_mgr.add_entry(Entry(
                title=f'条目{i}',
                username=f'user{i}',
                password=f'password{i}',
                entry_type='login',
            ))

        originals = {e.title: e for e in self._entry_mgr.get_entries()}
        assert len(originals) == 10

        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'AnotherPassword!2026'
        )
        assert ok
        assert self._vault.unlock('AnotherPassword!2026')[0]

        restored = {e.title: e for e in self._entry_mgr.get_entries()}
        assert len(restored) == 10
        for title, orig in originals.items():
            assert restored[title].password == orig.password

    # ------------------------------------------------------------------
    # 9. 自定义字段在改密后完整保留
    # ------------------------------------------------------------------
    def test_re_encrypt_preserves_custom_fields(self):
        """重新加密保留自定义字段。"""
        entry = Entry(
            title='带自定义字段',
            username='user',
            password='pass',
            entry_type='login',
            custom_fields=[
                CustomField(name='API Key', value='secret123', field_type='text'),
                CustomField(name='PIN', value='0000', field_type='password'),
            ],
        )
        self._entry_mgr.add_entry(entry)

        ok, _ = self._vault.change_master_password(
            'original_pwd_123', 'new_password_456'
        )
        assert ok
        assert self._vault.unlock('new_password_456')[0]

        restored = self._entry_mgr.get_entries()[0]
        assert isinstance(restored.custom_fields, list)
        assert len(restored.custom_fields) == 2
        field_names = {f.name for f in restored.custom_fields}
        assert field_names == {'API Key', 'PIN'}
