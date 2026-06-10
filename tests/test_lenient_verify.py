"""测试宽松完整性校验 — 列表操作容忍损坏条目"""
import pytest

from src.business.entry_manager import EntryManager
from src.business.vault_manager import VaultManager
from src.database.models import Entry
from src.exceptions import VaultIntegrityError


class TestLenientVerify:
    """验证 get_entries 宽容模式 vs get_entry 严格模式"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, vault_config):
        self._vault = VaultManager(vault_config)
        self._vault.initialize("test_password_12345")
        self._entry_mgr = EntryManager(self._vault)
        yield
        self._vault.close()

    def test_get_entries_with_bad_verifier_marks_integrity_error(self):
        """get_entries 遇到验证失败的条目标记 integrity_error 而非抛异常"""
        self._entry_mgr.add_entry(Entry(
            title='正常条目', username='user', password='pass', entry_type='login',
        ))

        # 设置一个会抛 VaultIntegrityError 的 verifier
        def bad_verifier(_entry):
            raise VaultIntegrityError('元数据签名不匹配')

        self._vault.db._entry_verifier = bad_verifier

        # 通过 db 层直接调用 get_entries 验证宽容模式行为
        # EntryManager.decrypt_entry 会创建新 Entry 覆盖 db 层的 integrity_error，
        # 因此直接使用 db.get_entries 观察元数据校验结果
        entries = self._vault.db.get_entries()
        assert len(entries) == 1
        assert entries[0].integrity_error is True
        assert '完整性' in entries[0].integrity_message

    def test_get_entry_with_bad_verifier_raises(self):
        """get_entry（单条）在验证失败时仍抛异常"""
        self._entry_mgr.add_entry(Entry(
            title='测试条目', username='user', password='pass', entry_type='login',
        ))

        def bad_verifier(_entry):
            raise VaultIntegrityError('元数据签名不匹配')

        self._vault.db._entry_verifier = bad_verifier

        entries = self._entry_mgr.get_entries()
        entry_id = entries[0].id
        assert entry_id is not None

        # get_entry 应该抛出异常（严格模式）
        with pytest.raises(VaultIntegrityError):
            self._vault.db.get_entry(entry_id)

    def test_lenient_mode_is_parameter_not_instance_state(self):
        """宽松验证通过参数传递，不存储在实例变量上"""
        assert not hasattr(self._vault.db, '_lenient_verify')
