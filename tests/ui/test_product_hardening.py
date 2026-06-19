"""正式交付前的关键业务与 UI 回归测试。

覆盖保险库生命周期、密码历史、可移植备份、加密与完整性校验、导入导出、
锁定清理、登录窗口渲染等端到端场景，作为发布前的整体回归防线。
"""

import json
import sqlite3
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest.mock import patch

from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QWidget

from src.business.managers.backup_restore import BackupRestoreManager
from src.business.managers.import_export import ImportExportManager
from src.business.managers.vault_manager import VaultManager
from src.crypto.encryption import EncryptionEngine
from src.crypto.totp import TOTPGenerator
from src.exceptions import SchemaError
from src.models import CustomField, Entry
from src.ui.dialogs.entry_dialog import EntryDialog
from src.ui.dialogs.login_window import LoginWindow
from src.ui.resources.styles import get_style
from src.ui.windows.main_window import MainWindow
from tests.helpers import make_entry_manager, make_test_config

_APP = QApplication.instance() or QApplication([])


def _config(root: str):
    return make_test_config(root)


def test_unchanged_password_does_not_create_history():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Account', password='SamePassword!2026'))
        entry = manager.get_entry(entry_id)
        assert entry is not None
        manager.update_entry(entry)
        assert manager.password_history.get(entry_id) == []
        vault.close()


def test_password_history_survives_master_password_change():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('OldMasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Account', password='FirstPassword!2026'))
        entry = manager.get_entry(entry_id)
        assert entry is not None
        entry.password = 'SecondPassword!2026'
        manager.update_entry(entry)

        assert vault.change_master_password(
            'OldMasterPassword!2026', 'NewMasterPassword!2026'
        )[0]
        history = manager.password_history.decrypt(manager.password_history.get(entry_id))
        assert [item['password'] for item in history] == ['FirstPassword!2026']
        vault.close()


def test_portable_backup_restores_into_different_vault():
    with tempfile.TemporaryDirectory() as source_root, tempfile.TemporaryDirectory() as target_root:
        source = VaultManager(_config(source_root))
        assert source.initialize('SourceMasterPassword!2026')[0]
        source_manager = make_entry_manager(source)
        entry_id = source_manager.add_entry(Entry(
            title='Portable entry',
            username='user@example.com',
            password='FirstPassword!2026',
            entry_type='server',
            custom_fields=[CustomField('_server_host', '10.0.0.8')],
        ))
        edited = source_manager.get_entry(entry_id)
        assert edited is not None
        edited.password = 'SecondPassword!2026'
        source_manager.update_entry(edited)
        source_manager.delete_entry(entry_id)
        backup_path = str(Path(source_root) / 'portable.cbox')
        success, error = BackupRestoreManager(source).create_backup(
            backup_path, 'IndependentBackupPassword!2026'
        )
        assert success, error

        target = VaultManager(_config(target_root))
        assert target.initialize('DifferentMasterPassword!2026')[0]
        success, error = BackupRestoreManager(target).restore_backup(
            backup_path, 'IndependentBackupPassword!2026'
        )
        assert success, error
        target_manager = make_entry_manager(target)
        restored = target_manager.get_entries(include_deleted=True)
        assert len(restored) == 1
        assert restored[0].is_deleted is True
        assert restored[0].password == 'SecondPassword!2026'
        custom_fields = restored[0].custom_fields
        assert isinstance(custom_fields, list)
        assert custom_fields[0].value == '10.0.0.8'
        restored_id = restored[0].id
        assert restored_id is not None
        history = target_manager.password_history.decrypt(
            target_manager.password_history.get(restored_id)
        )
        assert [item['password'] for item in history] == ['FirstPassword!2026']
        source.close()
        target.close()


def test_entry_dialog_restores_type_specific_fields():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry = Entry(
            title='Card',
            entry_type='card',
            custom_fields=[
                CustomField('_card_holder', 'Test User'),
                CustomField('_card_number', '4111111111111111', 'password'),
            ],
        )
        dialog = EntryDialog(manager, manager.categories.get_categories(), entry=entry, config=_config(root))
        assert dialog._type_combo.currentData() == 'card'
        assert not dialog._special_widgets['card_number'].isHidden()
        assert cast(QLineEdit, dialog._special_widgets['card_holder']).text() == 'Test User'
        assert cast(QLineEdit, dialog._special_widgets['card_number']).text() == '4111 1111 1111 1111'
        dialog.close()
        vault.close()


def test_lock_preparation_clears_decrypted_ui_and_clipboard():
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        vault = VaultManager(config)
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        manager.add_entry(Entry(title='Secret', password='VisibleSecret!2026'))
        window = MainWindow(config, vault)
        assert window._entry_model.rowCount() == 1
        window._clipboard.copy_text('VisibleSecret!2026')

        window.prepare_for_lock()
        vault.lock()

        assert window._entry_model.rowCount() == 0
        assert window._detail_panel._current_entry is None
        assert window._detail_panel._current_password == ''
        clipboard = QApplication.clipboard()
        assert clipboard is not None
        assert clipboard.text() != 'VisibleSecret!2026'
        window.close()


def test_lock_closes_and_scrubs_open_entry_dialog():
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        vault = VaultManager(config)
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Secret', password='DialogSecret!2026'))
        window = MainWindow(config, vault)
        window.show()
        dialog = EntryDialog(
            manager,
            manager.categories.get_categories(),
            entry=manager.get_entry(entry_id),
            parent=window,
            config=config,
        )
        dialog.show()
        _APP.processEvents()

        window.prepare_for_lock()
        vault.lock()
        _APP.processEvents()

        assert not dialog.isVisible()
        assert dialog._password_edit.text() == ''
        window.close()
        vault.close()


def test_stale_key_session_cannot_write_after_master_password_change():
    with tempfile.TemporaryDirectory() as root:
        first = VaultManager(_config(root))
        assert first.initialize('OldMasterPassword!2026')[0]
        stale = VaultManager(_config(root))
        assert stale.unlock('OldMasterPassword!2026')[0]
        assert first.change_master_password(
            'OldMasterPassword!2026', 'NewMasterPassword!2026'
        )[0]

        try:
            make_entry_manager(stale).add_entry(
                Entry(title='Stale write', password='OldKeyPassword!2026')
            )
        except RuntimeError as exc:
            assert '密钥已变更' in str(exc)
        else:
            raise AssertionError('过期密钥会话不应继续写入')
        assert not stale.is_unlocked
        stale.close()
        first.close()


def test_context_bound_ciphertext_rejects_cross_entry_swap():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        first_id = manager.add_entry(Entry(title='First', password='FirstSecret!2026'))
        second_id = manager.add_entry(Entry(title='Second', password='SecondSecret!2026'))
        first_raw = vault.db.get_entry(first_id)
        second_raw = vault.db.get_entry(second_id)
        assert first_raw is not None
        assert second_raw is not None
        first_raw.password = second_raw.password
        vault.db.update_entry(first_raw, preserve_updated_at=True)

        swapped = manager.get_entry(first_id)
        assert swapped is not None
        assert swapped.password == ''
        assert swapped.integrity_error is True
        assert 'password' in swapped.integrity_message
        vault.close()


def test_vault_persists_kdf_parameters_and_ciphertext_format():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        # 显式用生产级 DEFAULT_KDF_PARAMS，绕过测试全局弱 KDF monkeypatch——
        # 本测试专门验证 OWASP 级参数被正确持久化到 vault_meta。
        from src.crypto.master_key import DEFAULT_KDF_PARAMS
        assert vault.initialize('MasterPassword!2026', params=DEFAULT_KDF_PARAMS)[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Account', password='Secret!2026'))
        raw = vault.db.get_entry(entry_id)
        assert raw is not None

        assert vault.db.get_meta('master_kdf') == 'argon2id'
        assert vault.db.get_meta('master_kdf_time_cost') == str(DEFAULT_KDF_PARAMS.time_cost)
        assert vault.db.get_meta('master_kdf_memory_cost') == str(DEFAULT_KDF_PARAMS.memory_cost)
        assert vault.db.get_meta('master_kdf_parallelism') == str(DEFAULT_KDF_PARAMS.parallelism)
        assert vault.db.get_meta('ciphertext_format') == 'aes-256-gcm-aad'
        assert raw.password.startswith(EncryptionEngine.TEXT_PREFIX)
        assert raw.title.startswith(EncryptionEngine.TEXT_PREFIX)
        assert raw.url.startswith(EncryptionEngine.TEXT_PREFIX)
        assert raw.tags.startswith(EncryptionEngine.TEXT_PREFIX)
        assert all(
            category.name.startswith(EncryptionEngine.TEXT_PREFIX)
            for category in vault.db.get_categories()
        )
        vault.close()


def test_selecting_first_entry_opens_detail_panel_without_crash():
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        config.set('theme', 'dark')
        vault = VaultManager(config)
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Selectable', password='Strong!2026Password'))
        window = MainWindow(config, vault)
        window._entry_list.setCurrentIndex(window._entry_model.index(0))
        # 等待 80ms 选择防抖定时器触发并处理事件
        # PyQt6 QtTest.pyi 将 qWait 误标为实例方法，首个形参为 self，
        # 导致 pyright 把位置实参绑定到 self 而报 ms 缺失；此处将 qWait
        # cast 为接受单一 int 的可调用对象，消除类型误差，运行时行为不变。
        cast(Callable[[int], None], QTest.qWait)(150)
        _APP.processEvents()
        current_entry = window._detail_panel._current_entry
        assert current_entry is not None
        assert current_entry.id == entry_id
        assert window._detail_panel._title_label.text().endswith('Selectable')
        window.close()
        vault.close()


def test_first_time_login_password_fields_have_matching_dimensions():
    app_widget = cast(QWidget, _APP)
    previous_style = app_widget.styleSheet()
    app_widget.setStyleSheet(get_style('light'))
    try:
        vault = type('FirstTimeVault', (), {'is_initialized': False})()
        dialog = LoginWindow(vault)
        dialog.show()
        _APP.processEvents()

        assert dialog.height() >= dialog.minimumSizeHint().height()
        assert dialog._password_edit.width() == dialog._confirm_edit.width()
        assert dialog._password_edit.height() == dialog._confirm_edit.height()
        assert dialog._confirm_edit.visibleRegion().boundingRect() == dialog._confirm_edit.rect()
        assert (
            dialog._toggle_confirm_btn.visibleRegion().boundingRect()
            == dialog._toggle_confirm_btn.rect()
        )
        dialog.close()
    finally:
        app_widget.setStyleSheet(previous_style)


def test_visible_branding_uses_single_product_name():
    vault = type('FirstTimeVault', (), {'is_initialized': False})()
    dialog = LoginWindow(vault)

    assert dialog.windowTitle() == 'CipherBox - 登录'
    assert all('密匣' not in label.text() for label in dialog.findChildren(QLabel))
    dialog.close()


def test_login_failure_clears_password_input():
    """认证失败后主密码明文须立即从输入框清除，缩短敏感驻留时间。"""
    vault = type('LoginVault', (), {'is_initialized': True})()
    dialog = LoginWindow(vault)
    dialog._password_edit.setText('user-typed-secret')
    dialog._on_auth_result(False, '主密码错误')
    assert dialog._password_edit.text() == ''
    dialog.close()


def test_totp_accepts_standard_otpauth_uri():
    uri = (
        'otpauth://totp/CipherBox:test@example.com?'
        'secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=60'
    )
    assert TOTPGenerator.validate_secret(uri)
    assert len(TOTPGenerator.generate(uri)) == 6
    assert TOTPGenerator.get_period(uri) == 60


def test_bitwarden_import_preserves_folder_totp_and_custom_fields():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        importer = ImportExportManager(manager)
        payload = {
            'folders': [{'id': 'folder-1', 'name': 'Work'}],
            'items': [{
                'type': 1,
                'name': 'Imported login',
                'folderId': 'folder-1',
                'favorite': True,
                'login': {
                    'username': 'user@example.com',
                    'password': 'ImportedPassword!2026',
                    'totp': 'JBSWY3DPEHPK3PXP',
                    'uris': [{'uri': 'https://example.com'}],
                },
                'fields': [{'name': 'PIN', 'value': '1234', 'type': 1}],
            }],
        }
        path = Path(root) / 'bitwarden.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        assert importer.import_from_bitwarden_json(str(path)) == 1
        entry = manager.get_entries()[0]
        assert entry.category_name == 'Work'
        assert entry.totp_secret == 'JBSWY3DPEHPK3PXP'
        assert entry.is_favorite is True
        bitwarden_fields = entry.custom_fields
        assert isinstance(bitwarden_fields, list)
        assert bitwarden_fields[0].name == 'PIN'
        assert bitwarden_fields[0].field_type == 'password'
        vault.close()


def test_import_rolls_back_when_any_entry_fails():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        importer = ImportExportManager(manager)
        path = Path(root) / 'entries.json'
        path.write_text(json.dumps({
            'app': 'CipherBox',
            'secrets_included': True,
            'entries': [
                {'title': 'First', 'password': 'a'},
                {'title': 'Second', 'password': 'b'},
            ]
        }), encoding='utf-8')
        original_add = manager.add_entry
        calls = 0

        def fail_second(entry, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError('simulated import failure')
            return original_add(entry, **kwargs)

        with patch.object(manager, 'add_entry', side_effect=fail_second):
            try:
                importer.import_from_json(str(path))
            except RuntimeError:
                pass
        assert manager.get_entry_count() == 0
        vault.close()


def test_export_without_password_excludes_secret_custom_fields():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        manager.add_entry(Entry(
            title='Card',
            password='LoginSecret!2026',
            totp_secret='JBSWY3DPEHPK3PXP',
            custom_fields=[
                CustomField('Display name', 'Public value'),
                CustomField('_card_number', '4111111111111111', 'password'),
                CustomField('_card_cvv', '123', 'password'),
            ],
        ))
        path = Path(root) / 'safe-export.json'
        ImportExportManager(manager).export_to_json(
            str(path), manager.get_entries(), include_password=False
        )
        payload = json.loads(path.read_text(encoding='utf-8'))
        exported = payload['entries'][0]

        assert payload['secrets_included'] is False
        assert 'password' not in exported
        assert 'totp_secret' not in exported
        assert exported['custom_fields'] == [{
            'name': 'Display name', 'value': 'Public value', 'field_type': 'text'
        }]
        vault.close()


def test_passwordless_overwrite_import_preserves_existing_secrets():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(
            title='Account',
            username='user@example.com',
            password='ExistingPassword!2026',
            totp_secret='JBSWY3DPEHPK3PXP',
            custom_fields=[CustomField('PIN', '1234', 'password')],
        ))
        exporter = ImportExportManager(manager)
        path = Path(root) / 'without-secrets.json'
        exporter.export_to_json(str(path), manager.get_entries(), include_password=False)

        payload = json.loads(path.read_text(encoding='utf-8'))
        payload['entries'][0]['notes'] = 'updated'
        path.write_text(json.dumps(payload), encoding='utf-8')
        assert exporter.import_from_json(str(path), duplicate_action='overwrite') == 1

        restored = manager.get_entry(entry_id)
        assert restored is not None
        assert restored.password == 'ExistingPassword!2026'
        assert restored.totp_secret == 'JBSWY3DPEHPK3PXP'
        restored_fields = restored.custom_fields
        assert isinstance(restored_fields, list)
        assert restored_fields[0].value == '1234'
        assert restored.notes == 'updated'
        vault.close()


def test_favorite_change_does_not_reset_password_age():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Account', password='Password!2026'))
        before_entry = manager.get_entry(entry_id)
        assert before_entry is not None
        before = before_entry.password_changed_at
        manager.toggle_favorite(entry_id)
        after_entry = manager.get_entry(entry_id)
        assert after_entry is not None
        after = after_entry.password_changed_at
        assert after == before
        vault.close()


def test_main_window_filters_entries_by_tag():
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        vault = VaultManager(config)
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        manager.add_entry(Entry(title='Work', tags='工作,重要'))
        manager.add_entry(Entry(title='Personal', tags='个人'))
        window = MainWindow(config, vault)
        index = window._tag_combo.findData('工作')
        assert index >= 0
        window._tag_combo.setCurrentIndex(index)
        _APP.processEvents()
        assert window._entry_model.rowCount() == 1
        first_entry = window._entry_model.data(window._entry_model.index(0), 256)
        assert first_entry is not None
        assert first_entry.title == 'Work'
        window.close()


def test_existing_vault_cannot_be_initialized_again():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('OriginalMaster!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Keep', password='KeepSecret!2026'))

        ok, msg = vault.initialize('ReplacementMaster!2026')
        assert ok is False
        assert '已经初始化' in msg
        vault.lock()
        assert vault.unlock('OriginalMaster!2026')[0]
        kept_entry = manager.get_entry(entry_id)
        assert kept_entry is not None
        assert kept_entry.password == 'KeepSecret!2026'
        vault.close()


def test_entry_metadata_tampering_is_rejected():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Original', password='Secret!2026'))

        connection = sqlite3.connect(Path(root) / 'vault.db')
        connection.execute(
            "UPDATE entries SET title_enc='Tampered' WHERE id=?",
            (entry_id,),
        )
        connection.commit()
        connection.close()

        try:
            manager.get_entry(entry_id)
        except RuntimeError as exc:
            assert '元数据完整性校验失败' in str(exc)
        else:
            raise AssertionError('被篡改的元数据不应被读取')
        vault.close()


def test_entry_metadata_is_resigned_after_master_password_change():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('OldMasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title='Account', password='Secret!2026'))
        old_raw = vault.db.get_entry(entry_id)
        assert old_raw is not None
        old_mac = old_raw.metadata_mac

        assert vault.change_master_password(
            'OldMasterPassword!2026', 'NewMasterPassword!2026'
        )[0]
        entry = manager.get_entry(entry_id)
        assert entry is not None
        assert entry.password == 'Secret!2026'
        new_raw = vault.db.get_entry(entry_id)
        assert new_raw is not None
        assert new_raw.metadata_mac != old_mac
        vault.close()


def test_vault_api_rejects_weak_master_passwords():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        ok, msg = vault.initialize('aaaaaaaaaaaa')
        assert ok is False
        assert msg
        assert not (Path(root) / 'vault.db').exists()


def test_nested_transaction_uses_savepoint_for_inner_rollback():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        with vault.db.transaction():
            manager.add_entry(Entry(title='Outer', password='OuterSecret!2026'))
            try:
                with vault.db.transaction():
                    manager.add_entry(Entry(title='Inner', password='InnerSecret!2026'))
                    raise RuntimeError('rollback inner')
            except RuntimeError:
                pass

        assert [entry.title for entry in manager.get_entries()] == ['Outer']
        vault.close()


def test_import_all_does_not_decrypt_existing_vault():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        manager = make_entry_manager(vault)
        manager.add_entry(Entry(title='Existing', password='ExistingSecret!2026'))
        path = Path(root) / 'entries.json'
        path.write_text(json.dumps({
            'app': 'CipherBox',
            'secrets_included': True,
            'entries': [{'title': 'Imported', 'password': 'ImportedSecret!2026'}],
        }), encoding='utf-8')

        importer = ImportExportManager(manager)
        with patch.object(
            manager, 'get_entry_summaries',
            side_effect=AssertionError('import_all 不应扫描现有条目'),
        ):
            assert importer.import_from_json(
                str(path), duplicate_action='import_all'
            ) == 1
        assert manager.get_entry_count() == 2
        vault.close()


def test_pre_restore_snapshot_purged_on_master_password_change():
    """改密后自动清理恢复点，收缩其中保存的已删除条目明文泄漏面。"""
    with tempfile.TemporaryDirectory() as source_root, tempfile.TemporaryDirectory() as target_root:
        source = VaultManager(_config(source_root))
        assert source.initialize('SourceMaster!2026')[0]
        make_entry_manager(source).add_entry(
            Entry(title='Incoming', password='IncomingSecret!2026')
        )
        portable = str(Path(source_root) / 'portable.cbox')
        success, error = BackupRestoreManager(source).create_backup(
            portable, 'PortableBackup!2026'
        )
        assert success, error

        target = VaultManager(_config(target_root))
        assert target.initialize('OldTargetMaster!2026')[0]
        target_manager = make_entry_manager(target)
        target_manager.add_entry(
            Entry(title='Before restore', password='OriginalSecret!2026')
        )
        backup_manager = BackupRestoreManager(target)
        success, error = backup_manager.restore_backup(
            portable, 'PortableBackup!2026'
        )
        assert success, error
        backup_dir = Path(target_root) / 'backups'
        # 恢复轮换 snapshot_key 并清理恢复点（含恢复前明文），收缩泄漏面
        assert list(backup_dir.glob('pre_restore_*.cbox')) == [], '恢复后恢复点应被清理'

        # 改密同样触发 snapshot_key 轮换与清理，验证改密路径不残留
        assert target.change_master_password(
            'OldTargetMaster!2026', 'NewTargetMaster!2026'
        )[0]
        assert list(backup_dir.glob('pre_restore_*.cbox')) == []
        source.close()
        target.close()


def test_existing_database_missing_table_is_rejected_without_repair():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        vault.close()
        db_path = Path(root) / 'vault.db'
        connection = sqlite3.connect(db_path)
        connection.execute('DROP TABLE password_history')
        connection.commit()
        connection.close()

        reopened = VaultManager(_config(root))
        # schema 损坏（缺表）时 is_initialized 传播 SchemaError 而非静默 False，
        # 避免 UI 误判为未初始化后在损坏库上初始化覆盖既有数据。
        try:
            _ = reopened.is_initialized
            raise AssertionError('缺表的库 is_initialized 应抛 SchemaError')
        except SchemaError:
            pass
        connection = sqlite3.connect(db_path)
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        connection.close()
        assert 'password_history' not in tables
        reopened.close()


def test_deleted_default_category_does_not_reappear_after_restart():
    with tempfile.TemporaryDirectory() as root:
        vault = VaultManager(_config(root))
        assert vault.initialize('MasterPassword!2026')[0]
        category = next(
            item for item in make_entry_manager(vault).categories.get_categories()
            if item.name == '社交'
        )
        category_id = category.id
        assert category_id is not None
        vault.db.delete_category(category_id)
        vault.close()

        reopened = VaultManager(_config(root))
        assert reopened.is_initialized is True
        assert reopened.unlock('MasterPassword!2026')[0]
        assert all(
            item.name != '社交'
            for item in make_entry_manager(reopened).categories.get_categories()
        )
        reopened.close()
