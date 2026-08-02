"""正式交付前的关键业务与 UI 回归测试。

覆盖保险库生命周期、密码历史、可移植备份、加密与完整性校验、导入导出、
锁定清理、登录窗口渲染等端到端场景，作为发布前的整体回归防线。
"""

import dataclasses
import json
import sqlite3
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QLabel, QWidget

from src.business.composition import build_business_context
from src.business.managers.backup_restore import BackupRestoreManager
from src.business.managers.import_export import ImportExportManager
from src.crypto.encryption import EncryptionEngine
from src.crypto.totp import TOTPGenerator
from src.exceptions import SchemaError, VaultLockedError
from src.models import CustomField, Entry
from src.ui.dialogs.entry_dialog import EntryDialog
from src.ui.dialogs.login_window import LoginWindow
from src.ui.resources.styles import get_style
from src.ui.windows.main_window import MainWindow
from tests.helpers import make_entry_manager, make_test_config, make_vault

_APP = QApplication.instance() or QApplication([])


def _config(root: str):
    return make_test_config(root)


def test_unchanged_password_does_not_create_history():
    """密码未变更的 update_entry 不应产生密码历史记录。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Account", password="SamePassword!2026"))
        entry = manager.get_entry(entry_id)
        assert entry is not None
        manager.update_entry(entry)
        assert manager.password_history.get(entry_id) == []
        vault.close()


def test_password_history_survives_master_password_change():
    """改密全量重加密后历史记录仍可解密（回归守护重加密覆盖密码历史）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("OldMasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Account", password="FirstPassword!2026"))
        entry = manager.get_entry(entry_id)
        assert entry is not None
        entry = dataclasses.replace(entry, password="SecondPassword!2026")
        manager.update_entry(entry)

        assert vault.change_master_password("OldMasterPassword!2026", "NewMasterPassword!2026")[0]
        history = manager.password_history.decrypt(manager.password_history.get(entry_id))
        assert [item["password"] for item in history] == ["FirstPassword!2026"]
        vault.close()


def test_portable_backup_restores_into_different_vault():
    """可移植备份跨主密码恢复保留条目、自定义字段与密码历史。"""
    with tempfile.TemporaryDirectory() as source_root, tempfile.TemporaryDirectory() as target_root:
        source = make_vault(_config(source_root))
        assert source.initialize("SourceMasterPassword!2026")[0]
        source_manager = make_entry_manager(source)
        entry_id = source_manager.add_entry(
            Entry(
                title="Portable entry",
                username="user@example.com",
                password="FirstPassword!2026",
                entry_type="server",
                custom_fields=[CustomField("_server_host", "10.0.0.8")],
            )
        )
        edited = source_manager.get_entry(entry_id)
        assert edited is not None
        edited = dataclasses.replace(edited, password="SecondPassword!2026")
        source_manager.update_entry(edited)
        source_manager.delete_entry(entry_id)
        backup_path = str(Path(source_root) / "portable.cbox")
        success, error = BackupRestoreManager(source, make_entry_manager(source)).create_backup(
            backup_path, "IndependentBackupPassword!2026"
        )
        assert success, error

        target = make_vault(_config(target_root))
        assert target.initialize("DifferentMasterPassword!2026")[0]
        success, error = BackupRestoreManager(target, make_entry_manager(target)).restore_backup(
            backup_path, "IndependentBackupPassword!2026"
        )
        assert success, error
        target_manager = make_entry_manager(target)
        restored = target_manager.get_entries(include_deleted=True)
        assert len(restored) == 1
        assert restored[0].is_deleted is True
        assert restored[0].password == "SecondPassword!2026"
        custom_fields = restored[0].custom_fields
        assert isinstance(custom_fields, list)
        assert custom_fields[0].value == "10.0.0.8"
        restored_id = restored[0].id
        assert restored_id is not None
        history = target_manager.password_history.decrypt(
            target_manager.password_history.get(restored_id)
        )
        assert [item["password"] for item in history] == ["FirstPassword!2026"]
        source.close()
        target.close()


def test_entry_dialog_restores_type_specific_fields():
    """编辑对话框按条目类型恢复专属字段（如卡号掩码显示）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry = Entry(
            title="Card",
            entry_type="card",
            custom_fields=[
                CustomField("_card_holder", "Test User"),
                CustomField("_card_number", "4111111111111111", "password"),
            ],
        )
        dialog = EntryDialog(
            manager, manager.categories.get_categories(), entry=entry, config=_config(root)
        )
        assert dialog._type_combo.currentData() == "card"
        assert not dialog._special_edits["card_number"].isHidden()
        assert dialog._special_edits["card_holder"].text() == "Test User"
        assert dialog._special_edits["card_number"].text() == "4111 1111 1111 1111"
        dialog.close()
        vault.close()


def test_lock_preparation_clears_decrypted_ui_and_clipboard():
    """锁定前清理清空 UI 解密数据与剪贴板残留。"""
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        vault = make_vault(config)
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        manager.add_entry(Entry(title="Secret", password="VisibleSecret!2026"))
        window = MainWindow(build_business_context(config, vault))
        assert window._entry_model.rowCount() == 1
        window._clipboard.copy_text("VisibleSecret!2026")

        window.prepare_for_lock()
        vault.lock()

        assert window._entry_model.rowCount() == 0
        assert window._detail_panel._current_entry is None
        assert window._detail_panel._current_password == ""
        clipboard = QApplication.clipboard()
        assert clipboard is not None
        assert clipboard.text() != "VisibleSecret!2026"
        window.close()


def test_change_master_success_triggers_force_backup(monkeypatch):
    """改密成功触发强制快照（force=True）。

    回归守护 P0：``show_change_master`` 应委托 ``AutoBackupController.trigger_check``。
    """
    from src.ui.components.toast import Toast
    from src.ui.dialogs.change_master_dialog import ChangeMasterDialog

    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        vault = make_vault(config)
        assert vault.initialize("MasterPassword!2026")[0]
        make_entry_manager(vault).add_entry(Entry(title="t", password="p"))
        # MenuSlots.refresh_all_data 在 MainWindow 构造时捕获 list_refresh.refresh_all_data
        # 的绑定方法；实例级 monkeypatch 不影响已持有 bound method，故构造前打类级桩。
        from src.ui.controllers.list_refresh_controller import ListRefreshController

        monkeypatch.setattr(ListRefreshController, "refresh_all_data", lambda self: None)
        window = MainWindow(build_business_context(config, vault))
        try:
            # mock 改密对话框直接返回 Accepted，跳过真实改密 UI 与 Argon2id 派生
            monkeypatch.setattr(
                ChangeMasterDialog,
                "exec",
                lambda self: ChangeMasterDialog.DialogCode.Accepted,
            )
            # 屏蔽改密成功路径的 UI 副作用，聚焦 trigger_check 调用断言
            monkeypatch.setattr(Toast, "show", lambda *args, **kwargs: None)
            monkeypatch.setattr(window._detail_panel, "show_empty", lambda: None)
            called: list[bool] = []
            monkeypatch.setattr(
                window._auto_backup,
                "trigger_check",
                lambda force=False: called.append(force),
            )

            window._menu.show_change_master()

            assert called == [True]
        finally:
            window.close()
            vault.close()


def test_lock_closes_and_scrubs_open_entry_dialog():
    """锁定关闭已打开的条目编辑对话框并擦除其中明文字段。"""
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        vault = make_vault(config)
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Secret", password="DialogSecret!2026"))
        window = MainWindow(build_business_context(config, vault))
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
        assert dialog._password_edit.text() == ""
        window.close()
        vault.close()


def test_stale_key_session_cannot_write_after_master_password_change():
    """改密后旧密钥会话写入被拒并锁定（密钥轮换一致性回归）。"""
    with tempfile.TemporaryDirectory() as root:
        first = make_vault(_config(root))
        assert first.initialize("OldMasterPassword!2026")[0]
        stale = make_vault(_config(root))
        assert stale.unlock("OldMasterPassword!2026")[0]
        assert first.change_master_password("OldMasterPassword!2026", "NewMasterPassword!2026")[0]

        try:
            make_entry_manager(stale).add_entry(
                Entry(title="Stale write", password="OldKeyPassword!2026")
            )
        except RuntimeError as exc:
            assert "密钥已变更" in str(exc)
        else:
            raise AssertionError("过期密钥会话不应继续写入")
        assert not stale.is_unlocked
        stale.close()
        first.close()


def test_context_bound_ciphertext_rejects_cross_entry_swap():
    """跨条目密文互换被 AAD 上下文绑定校验拦截（标记完整性错误）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        first_id = manager.add_entry(Entry(title="First", password="FirstSecret!2026"))
        second_id = manager.add_entry(Entry(title="Second", password="SecondSecret!2026"))
        first_raw = vault.db.get_entry(first_id)
        second_raw = vault.db.get_entry(second_id)
        assert first_raw is not None
        assert second_raw is not None
        first_raw = dataclasses.replace(first_raw, password=second_raw.password)
        vault.db.update_entry(first_raw, preserve_updated_at=True)

        swapped = manager.get_entry(first_id)
        assert swapped is not None
        assert swapped.password == ""
        assert swapped.integrity_error is True
        assert "password" in swapped.integrity_message
        vault.close()


def test_vault_persists_kdf_parameters_and_ciphertext_format():
    """vault_meta 持久化 OWASP 级 KDF 参数与密文格式标识。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        # 显式用生产级 DEFAULT_KDF_PARAMS，绕过测试全局弱 KDF monkeypatch——
        # 本测试专门验证 OWASP 级参数被正确持久化到 vault_meta。
        from src.crypto.master_key import DEFAULT_KDF_PARAMS

        assert vault.initialize("MasterPassword!2026", params=DEFAULT_KDF_PARAMS)[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Account", password="Secret!2026"))
        raw = vault.db.get_entry(entry_id)
        assert raw is not None

        assert vault.db.get_meta("master_kdf") == "argon2id"
        assert vault.db.get_meta("master_kdf_time_cost") == str(DEFAULT_KDF_PARAMS.time_cost)
        assert vault.db.get_meta("master_kdf_memory_cost") == str(DEFAULT_KDF_PARAMS.memory_cost)
        assert vault.db.get_meta("master_kdf_parallelism") == str(DEFAULT_KDF_PARAMS.parallelism)
        assert vault.db.get_meta("ciphertext_format") == "aes-256-gcm-aad"
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
    """深色主题下选中首条目经防抖触发详情面板渲染不崩溃。"""
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        config.set("theme", "dark")
        vault = make_vault(config)
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Selectable", password="Strong!2026Password"))
        window = MainWindow(build_business_context(config, vault))
        window._entry_list.setCurrentIndex(window._entry_model.index(0))
        # 等待 150ms 选择防抖定时器触发并处理事件
        # PyQt6 QtTest.pyi 将 qWait 误标为实例方法，首个形参为 self，
        # 导致 pyright 把位置实参绑定到 self 而报 ms 缺失；此处将 qWait
        # cast 为接受单一 int 的可调用对象，消除类型误差，运行时行为不变。
        cast(Callable[[int], None], QTest.qWait)(150)
        _APP.processEvents()
        current_entry = window._detail_panel._current_entry
        assert current_entry is not None
        assert current_entry.id == entry_id
        assert window._detail_panel._title_label.text().endswith("Selectable")
        window.close()
        vault.close()


def test_first_time_login_password_fields_have_matching_dimensions(tmp_path):
    """首次初始化登录窗口密码与确认框尺寸一致且可见（布局回归）。"""
    app_widget = cast(QWidget, _APP)
    previous_style = app_widget.styleSheet()
    app_widget.setStyleSheet(get_style("light"))
    try:
        vault = type(
            "FirstTimeVault",
            (),
            {
                "is_initialized": False,
                "data_dir": tmp_path,
                "ensure_db_open": lambda self: None,
            },
        )()
        dialog = LoginWindow(vault)  # pyright: ignore[reportArgumentType]
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


def test_visible_branding_uses_single_product_name(tmp_path):
    """可见文案统一使用单一产品名 CipherBox（无内部代号残留）。"""
    vault = type(
        "FirstTimeVault",
        (),
        {
            "is_initialized": False,
            "data_dir": tmp_path,
            "ensure_db_open": lambda self: None,
        },
    )()
    dialog = LoginWindow(vault)  # pyright: ignore[reportArgumentType]

    assert dialog.windowTitle() == "CipherBox - 登录"
    assert all("密匣" not in label.text() for label in dialog.findChildren(QLabel))
    dialog.close()


def test_login_failure_clears_password_input(tmp_path):
    """认证失败后主密码明文须立即从输入框清除，缩短敏感驻留时间。"""
    vault = type(
        "LoginVault",
        (),
        {
            "is_initialized": True,
            "data_dir": tmp_path,
            "ensure_db_open": lambda self: None,
        },
    )()
    dialog = LoginWindow(vault)  # pyright: ignore[reportArgumentType]
    dialog._password_edit.setText("user-typed-secret")
    dialog._on_auth_result(False, "主密码错误")
    assert dialog._password_edit.text() == ""
    dialog.close()


def test_totp_accepts_standard_otpauth_uri():
    """TOTP 解析标准 otpauth URI 并生成 6 位验证码。"""
    uri = (
        "otpauth://totp/CipherBox:test@example.com?"
        "secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=60"
    )
    assert TOTPGenerator.validate_secret(uri)
    assert len(TOTPGenerator.generate(uri)) == 6
    assert TOTPGenerator.get_period(uri) == 60


def test_bitwarden_import_preserves_folder_totp_and_custom_fields():
    """Bitwarden 导入保留文件夹分类、TOTP 与自定义字段。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        importer = ImportExportManager(manager)
        payload = {
            "folders": [{"id": "folder-1", "name": "Work"}],
            "items": [
                {
                    "type": 1,
                    "name": "Imported login",
                    "folderId": "folder-1",
                    "favorite": True,
                    "login": {
                        "username": "user@example.com",
                        "password": "ImportedPassword!2026",
                        "totp": "JBSWY3DPEHPK3PXP",
                        "uris": [{"uri": "https://example.com"}],
                    },
                    "fields": [{"name": "PIN", "value": "1234", "type": 1}],
                }
            ],
        }
        path = Path(root) / "bitwarden.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert importer.import_file(str(path), "bitwarden_json") == 1
        entry = manager.get_entries()[0]
        assert entry.category_name == "Work"
        assert entry.totp_secret == "JBSWY3DPEHPK3PXP"
        assert entry.is_favorite is True
        bitwarden_fields = entry.custom_fields
        assert isinstance(bitwarden_fields, list)
        assert bitwarden_fields[0].name == "PIN"
        assert bitwarden_fields[0].field_type == "password"
        vault.close()


def test_import_rolls_back_when_any_entry_fails():
    """导入遇异常经 epoch 守卫事务回滚，不留部分写入数据。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        importer = ImportExportManager(manager)
        path = Path(root) / "entries.json"
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        {"title": "First", "password": "a"},
                        {"title": "Second", "password": "b"},
                    ],
                }
            ),
            encoding="utf-8",
        )

        # 导入经 write_new_entries 批量写入（executemany）。模拟写入失败：RuntimeError
        # 不在导入容错捕获内，异常冒泡使 epoch 守卫事务回滚，不留部分写入的数据。
        with patch.object(
            manager, "write_new_entries", side_effect=RuntimeError("simulated import failure")
        ):
            try:
                importer.import_file(str(path), "json")
            except RuntimeError:
                pass
        assert manager.get_entry_count() == 0
        vault.close()


def test_export_without_password_excludes_secret_custom_fields():
    """不含密码导出时剔除敏感自定义字段（如卡号/CVV）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        manager.add_entry(
            Entry(
                title="Card",
                password="LoginSecret!2026",
                totp_secret="JBSWY3DPEHPK3PXP",
                custom_fields=[
                    CustomField("Display name", "Public value"),
                    CustomField("_card_number", "4111111111111111", "password"),
                    CustomField("_card_cvv", "123", "password"),
                ],
            )
        )
        path = Path(root) / "safe-export.json"
        ImportExportManager(manager).export_to_json(
            str(path), manager.get_entries(), include_password=False
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        exported = payload["entries"][0]

        assert payload["secrets_included"] is False
        assert "password" not in exported
        assert "totp_secret" not in exported
        assert exported["custom_fields"] == [
            {"name": "Display name", "value": "Public value", "field_type": "text"}
        ]
        vault.close()


def test_passwordless_overwrite_import_preserves_existing_secrets():
    """无密码覆盖导入保留既有密码、TOTP 与敏感字段。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(
            Entry(
                title="Account",
                username="user@example.com",
                password="ExistingPassword!2026",
                totp_secret="JBSWY3DPEHPK3PXP",
                custom_fields=[CustomField("PIN", "1234", "password")],
            )
        )
        exporter = ImportExportManager(manager)
        path = Path(root) / "without-secrets.json"
        exporter.export_to_json(str(path), manager.get_entries(), include_password=False)

        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["entries"][0]["notes"] = "updated"
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert exporter.import_file(str(path), "json", duplicate_action="overwrite") == 1

        restored = manager.get_entry(entry_id)
        assert restored is not None
        assert restored.password == "ExistingPassword!2026"
        assert restored.totp_secret == "JBSWY3DPEHPK3PXP"
        restored_fields = restored.custom_fields
        assert isinstance(restored_fields, list)
        assert restored_fields[0].value == "1234"
        assert restored.notes == "updated"
        vault.close()


def test_favorite_change_does_not_reset_password_age():
    """切换收藏不应重置密码变更时间（避免误触发过期判定）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Account", password="Password!2026"))
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
    """MainWindow 按标签筛选条目（端到端验证标签过滤管线）。"""
    with tempfile.TemporaryDirectory() as root:
        config = _config(root)
        vault = make_vault(config)
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        manager.add_entry(Entry(title="Work", tags="工作,重要"))
        manager.add_entry(Entry(title="Personal", tags="个人"))
        window = MainWindow(build_business_context(config, vault))
        index = window._tag_combo.findData("工作")
        assert index >= 0
        window._tag_combo.setCurrentIndex(index)
        _APP.processEvents()
        assert window._entry_model.rowCount() == 1
        first_entry = window._entry_model.data(window._entry_model.index(0), 256)
        assert first_entry is not None
        assert first_entry.title == "Work"
        window.close()


def test_existing_vault_cannot_be_initialized_again():
    """已初始化的保险库拒绝再次初始化（防止覆盖既有数据）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("OriginalMaster!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Keep", password="KeepSecret!2026"))

        ok, msg = vault.initialize("ReplacementMaster!2026")
        assert ok is False
        assert "已经初始化" in msg
        vault.lock()
        assert vault.unlock("OriginalMaster!2026")[0]
        kept_entry = manager.get_entry(entry_id)
        assert kept_entry is not None
        assert kept_entry.password == "KeepSecret!2026"
        vault.close()


def test_entry_metadata_tampering_is_rejected():
    """直接篡改加密字段的元数据 MAC 校验失败被拒。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Original", password="Secret!2026"))

        connection = sqlite3.connect(Path(root) / "vault.db")
        connection.execute(
            "UPDATE entries SET title_enc='Tampered' WHERE id=?",
            (entry_id,),
        )
        connection.commit()
        connection.close()

        try:
            manager.get_entry(entry_id)
        except RuntimeError as exc:
            assert "元数据完整性校验失败" in str(exc)
        else:
            raise AssertionError("被篡改的元数据不应被读取")
        vault.close()


def test_entry_metadata_is_resigned_after_master_password_change():
    """改密后条目元数据重新签名（HMAC 随新密钥刷新）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("OldMasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        entry_id = manager.add_entry(Entry(title="Account", password="Secret!2026"))
        old_raw = vault.db.get_entry(entry_id)
        assert old_raw is not None
        old_mac = old_raw.metadata_mac

        assert vault.change_master_password("OldMasterPassword!2026", "NewMasterPassword!2026")[0]
        entry = manager.get_entry(entry_id)
        assert entry is not None
        assert entry.password == "Secret!2026"
        new_raw = vault.db.get_entry(entry_id)
        assert new_raw is not None
        assert new_raw.metadata_mac != old_mac
        vault.close()


def test_vault_api_rejects_weak_master_passwords():
    """弱主密码在 initialize 即被拒绝且不落库。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        with pytest.raises(VaultLockedError):
            vault.initialize("aaaaaaaaaaaa")
        assert not (Path(root) / "vault.db").exists()


def test_initialize_system_error_raises_vault_locked(monkeypatch):
    """initialize 遇系统错误（DB I/O 等）抛 VaultLockedError（经 worker.error 不计速率锁定）。

    回归守护：系统错误（非密码错误）须走异常路径 is_auth_failure=False，而非 (False, msg)
    误计入速率锁定。monkeypatch ensure_db_open 抛 OSError 模拟 DB 故障。
    """
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))

        def _boom():
            raise OSError("disk I/O error")

        monkeypatch.setattr(vault, "ensure_db_open", _boom)
        with pytest.raises(VaultLockedError):
            vault.initialize("StrongPassword!2026")


def test_nested_transaction_uses_savepoint_for_inner_rollback():
    """嵌套事务用 savepoint 实现内层独立回滚（外层提交保留）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        with vault.db.transaction():
            manager.add_entry(Entry(title="Outer", password="OuterSecret!2026"))
            try:
                with vault.db.transaction():
                    manager.add_entry(Entry(title="Inner", password="InnerSecret!2026"))
                    raise RuntimeError("rollback inner")
            except RuntimeError:
                pass

        assert [entry.title for entry in manager.get_entries()] == ["Outer"]
        vault.close()


def test_import_all_does_not_decrypt_existing_vault():
    """import_all 模式导入不扫描解密既有条目（性能与隔离保证）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        manager = make_entry_manager(vault)
        manager.add_entry(Entry(title="Existing", password="ExistingSecret!2026"))
        path = Path(root) / "entries.json"
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [{"title": "Imported", "password": "ImportedSecret!2026"}],
                }
            ),
            encoding="utf-8",
        )

        importer = ImportExportManager(manager)
        with patch.object(
            manager,
            "get_entry_summaries",
            side_effect=AssertionError("import_all 不应扫描现有条目"),
        ):
            assert importer.import_file(str(path), "json", duplicate_action="import_all") == 1
        assert manager.get_entry_count() == 2
        vault.close()


def test_pre_restore_snapshot_purged_on_master_password_change():
    """改密后自动清理恢复点，收缩其中保存的已删除条目明文泄漏面。"""
    with tempfile.TemporaryDirectory() as source_root, tempfile.TemporaryDirectory() as target_root:
        source = make_vault(_config(source_root))
        assert source.initialize("SourceMaster!2026")[0]
        make_entry_manager(source).add_entry(
            Entry(title="Incoming", password="IncomingSecret!2026")
        )
        portable = str(Path(source_root) / "portable.cbox")
        success, error = BackupRestoreManager(source, make_entry_manager(source)).create_backup(
            portable, "PortableBackup!2026"
        )
        assert success, error

        target = make_vault(_config(target_root))
        assert target.initialize("OldTargetMaster!2026")[0]
        target_manager = make_entry_manager(target)
        target_manager.add_entry(Entry(title="Before restore", password="OriginalSecret!2026"))
        backup_manager = BackupRestoreManager(target, target_manager)
        success, error = backup_manager.restore_backup(portable, "PortableBackup!2026")
        assert success, error
        backup_dir = Path(target_root) / "backups"
        # 恢复轮换 snapshot_key 并清理恢复点（含恢复前明文），收缩泄漏面
        assert list(backup_dir.glob("pre_restore_*.cbox")) == [], "恢复后恢复点应被清理"

        # 改密同样触发 snapshot_key 轮换与清理，验证改密路径不残留
        assert target.change_master_password("OldTargetMaster!2026", "NewTargetMaster!2026")[0]
        assert list(backup_dir.glob("pre_restore_*.cbox")) == []
        source.close()
        target.close()


def test_existing_database_missing_table_is_rejected_without_repair():
    """schema 损坏（缺表）打开数据库抛 SchemaError 而非静默修复（ARCH-004）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        vault.close()
        db_path = Path(root) / "vault.db"
        connection = sqlite3.connect(db_path)
        connection.execute("DROP TABLE password_history")
        connection.commit()
        connection.close()

        reopened = make_vault(_config(root))
        # schema 损坏（缺表）时打开数据库传播 SchemaError 而非静默 False（ARCH-004：
        # is_initialized 为纯查询，schema 校验在 ensure_db_open 命令侧），避免 UI 误判
        # 为未初始化后在损坏库上初始化覆盖既有数据。
        try:
            reopened.ensure_db_open()
            _ = reopened.is_initialized
            raise AssertionError("缺表的库 ensure_db_open 应抛 SchemaError")
        except SchemaError:
            pass
        connection = sqlite3.connect(db_path)
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        connection.close()
        assert "password_history" not in tables
        reopened.close()


def test_deleted_default_category_does_not_reappear_after_restart():
    """删除的默认分类重启后不重新注入（默认分类仅首次初始化注入）。"""
    with tempfile.TemporaryDirectory() as root:
        vault = make_vault(_config(root))
        assert vault.initialize("MasterPassword!2026")[0]
        category = next(
            item
            for item in make_entry_manager(vault).categories.get_categories()
            if item.name == "社交"
        )
        category_id = category.id
        assert category_id is not None
        vault.db.delete_category(category_id)
        vault.close()

        reopened = make_vault(_config(root))
        reopened.ensure_db_open()  # ARCH-004：is_initialized 为纯查询，先打开数据库
        assert reopened.is_initialized is True
        assert reopened.unlock("MasterPassword!2026")[0]
        assert all(
            item.name != "社交" for item in make_entry_manager(reopened).categories.get_categories()
        )
        reopened.close()
