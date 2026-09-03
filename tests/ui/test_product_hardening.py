"""跨主题端到端回归防线（原万能桶文件收敛后的留存面）。

覆盖保险库生命周期、密码历史、可移植备份、加密与完整性校验、登录窗口渲染等
跨主题端到端场景。**准入规则**：新主题测试优先建专门测试文件（主题块已按
「导入导出 → tests/business/test_import_export_hardening.py」「主窗口锁定/交互 →
tests/ui/test_main_window_hardening.py」拆出）；本文件仅收跨主题、无处安放的
端到端回归，防止再度膨胀为万能桶。
"""

import dataclasses
import sqlite3
from pathlib import Path
from typing import cast

import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QWidget

from src.business.managers.vault_lifecycle import LOGIN_AUTH_FAILED_MESSAGE
from src.business.services.rate_limiter import RateLimiter
from src.crypto.encryption import EncryptionEngine
from src.crypto.totp import TOTPGenerator
from src.exceptions import SchemaError, VaultError
from src.models import CustomField, Entry
from src.ui.dialogs.entry_dialog import EntryDialog
from src.ui.dialogs.login_window import LoginWindow
from src.ui.resources.styles import get_style
from tests.helpers import (
    decrypt_all_entries,
    make_backup_manager,
    make_entry_manager,
)

_APP = QApplication.instance() or QApplication([])


def test_unchanged_password_does_not_create_history(make_vault_env):
    """密码未变更的 update_entry 不应产生密码历史记录。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
    entry_id = manager.add_entry(Entry(title="Account", password="SamePassword!2026"))
    entry = manager.get_entry(entry_id)
    assert entry is not None
    manager.update_entry(entry)
    assert manager.password_history.get(entry_id) == []


def test_password_history_survives_master_password_change(make_vault_env):
    """改密全量重加密后历史记录仍可解密（回归守护重加密覆盖密码历史）。"""
    env = make_vault_env(master_password="OldMasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
    entry_id = manager.add_entry(Entry(title="Account", password="FirstPassword!2026"))
    entry = manager.get_entry(entry_id)
    assert entry is not None
    entry = dataclasses.replace(entry, password="SecondPassword!2026")
    manager.update_entry(entry)

    assert vault.change_master_password("OldMasterPassword!2026", "NewMasterPassword!2026")[0]
    history = manager.password_history.decrypt(manager.password_history.get(entry_id))
    assert [item["password"] for item in history] == ["FirstPassword!2026"]


def test_portable_backup_restores_into_different_vault(tmp_path, make_vault_env):
    """可移植备份跨主密码恢复保留条目、自定义字段与密码历史。"""
    source_env = make_vault_env(
        root=tmp_path / "source", master_password="SourceMasterPassword!2026"
    )
    source = source_env.vault
    source_manager = source_env.entry_mgr
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
    backup_path = str(source_env.root / "portable.cbox")
    success, error = make_backup_manager(source).create_backup(
        backup_path, "IndependentBackupPassword!2026"
    )
    assert success, error

    target_env = make_vault_env(
        root=tmp_path / "target", master_password="DifferentMasterPassword!2026"
    )
    target = target_env.vault
    success, error = make_backup_manager(target).restore_backup(
        backup_path, "IndependentBackupPassword!2026"
    )
    assert success, error
    target_manager = target_env.entry_mgr
    restored = decrypt_all_entries(target_manager, include_deleted=True)
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


def test_entry_dialog_restores_type_specific_fields(make_vault_env):
    """编辑对话框按条目类型恢复专属字段（如卡号掩码显示）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
    entry = Entry(
        title="Card",
        entry_type="card",
        custom_fields=[
            CustomField("_card_holder", "Test User"),
            CustomField("_card_number", "4111111111111111", "password"),
        ],
    )
    dialog = EntryDialog(
        manager, manager.categories.get_categories(), entry=entry, config=env.config
    )
    assert dialog._type_combo.currentData() == "card"
    assert not dialog._special_edits["card_number"].isHidden()
    assert dialog._special_edits["card_holder"].text() == "Test User"
    assert dialog._special_edits["card_number"].text() == "4111 1111 1111 1111"
    dialog.close()


def test_stale_key_session_cannot_write_after_master_password_change(make_vault_env):
    """改密后旧密钥会话写入被拒并锁定（密钥轮换一致性回归）。"""
    first = make_vault_env(master_password="OldMasterPassword!2026").vault
    # 同一 db 上的第二个会话：解锁后持有旧密钥（工厂只装配不重复初始化）
    stale = make_vault_env(initialize=False).vault
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


def test_context_bound_ciphertext_rejects_cross_entry_swap(make_vault_env):
    """跨条目密文互换被 AAD 上下文绑定校验拦截（标记完整性错误）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
    first_id = manager.add_entry(Entry(title="First", password="FirstSecret!2026"))
    second_id = manager.add_entry(Entry(title="Second", password="SecondSecret!2026"))
    first_raw = vault.db.get_entry(first_id)
    second_raw = vault.db.get_entry(second_id)
    assert first_raw is not None
    assert second_raw is not None
    first_raw = dataclasses.replace(first_raw, password=second_raw.password)
    # preserve_updated_at 已退役（ARCH-021）：本测试仅依赖跨条目密文互换触发
    # AAD 绑定校验失败，不依赖 updated_at 保值。
    vault.db.update_entry(first_raw)

    swapped = manager.get_entry(first_id)
    assert swapped is not None
    assert swapped.password == ""
    assert swapped.integrity_error is True
    assert "password" in swapped.integrity_message


def test_vault_persists_kdf_parameters_and_ciphertext_format(make_vault_env):
    """vault_meta 持久化 OWASP 级 KDF 参数与密文格式标识。"""
    env = make_vault_env(initialize=False)
    root = env.root
    vault = env.vault
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
        dialog = LoginWindow(vault, RateLimiter())  # pyright: ignore[reportArgumentType]
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
    dialog = LoginWindow(vault, RateLimiter())  # pyright: ignore[reportArgumentType]

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
    dialog = LoginWindow(vault, RateLimiter())  # pyright: ignore[reportArgumentType]
    dialog._password_edit.setText("user-typed-secret")
    dialog._on_auth_result(False, LOGIN_AUTH_FAILED_MESSAGE)
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


def test_favorite_change_does_not_reset_password_age(make_vault_env):
    """切换收藏不应重置密码变更时间（避免误触发过期判定）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
    entry_id = manager.add_entry(Entry(title="Account", password="Password!2026"))
    before_entry = manager.get_entry(entry_id)
    assert before_entry is not None
    before = before_entry.password_changed_at
    manager.toggle_favorite(entry_id)
    after_entry = manager.get_entry(entry_id)
    assert after_entry is not None
    after = after_entry.password_changed_at
    assert after == before


def test_existing_vault_cannot_be_initialized_again(make_vault_env):
    """已初始化的保险库拒绝再次初始化（防止覆盖既有数据）。"""
    env = make_vault_env(master_password="OriginalMaster!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
    entry_id = manager.add_entry(Entry(title="Keep", password="KeepSecret!2026"))

    ok, msg = vault.initialize("ReplacementMaster!2026")
    assert ok is False
    assert "已经初始化" in msg
    vault.lock()
    assert vault.unlock("OriginalMaster!2026")[0]
    kept_entry = manager.get_entry(entry_id)
    assert kept_entry is not None
    assert kept_entry.password == "KeepSecret!2026"


def test_entry_metadata_tampering_is_rejected(make_vault_env):
    """直接篡改加密字段的元数据 MAC 校验失败被拒。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
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


def test_entry_metadata_is_resigned_after_master_password_change(make_vault_env):
    """改密后条目元数据重新签名（HMAC 随新密钥刷新）。"""
    env = make_vault_env(master_password="OldMasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
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


def test_vault_api_rejects_weak_master_passwords(make_vault_env):
    """弱主密码在 initialize 即被拒绝且不落库。"""
    env = make_vault_env(initialize=False)
    root = env.root
    vault = env.vault
    with pytest.raises(VaultError):
        vault.initialize("aaaaaaaaaaaa")
    assert not (Path(root) / "vault.db").exists()


def test_initialize_system_error_raises_vault_error(monkeypatch, make_vault_env):
    """initialize 遇系统错误（DB I/O 等）抛 VaultError（经 worker.error 不计速率锁定）。

    回归守护：系统错误（非密码错误）须走异常路径 is_auth_failure=False，而非 (False, msg)
    误计入速率锁定。monkeypatch ensure_db_open 抛 OSError 模拟 DB 故障。包装用
    VaultError 本体（ARCH-042）：终译保留原文，不被「保险库已锁定」罐头文案覆盖。
    """
    env = make_vault_env(initialize=False)
    root = env.root
    vault = env.vault

    def _boom():
        raise OSError("disk I/O error")

    monkeypatch.setattr(vault, "ensure_db_open", _boom)
    with pytest.raises(VaultError):
        vault.initialize("StrongPassword!2026")


def test_nested_transaction_uses_savepoint_for_inner_rollback(make_vault_env):
    """嵌套事务用 savepoint 实现内层独立回滚（外层提交保留）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    manager = env.entry_mgr
    with vault.db.transaction():
        manager.add_entry(Entry(title="Outer", password="OuterSecret!2026"))
        try:
            with vault.db.transaction():
                manager.add_entry(Entry(title="Inner", password="InnerSecret!2026"))
                raise RuntimeError("rollback inner")
        except RuntimeError:
            pass

    assert [entry.title for entry in decrypt_all_entries(manager)] == ["Outer"]


def test_pre_restore_snapshot_purged_on_master_password_change(tmp_path, make_vault_env):
    """改密后自动清理恢复点，收缩其中保存的已删除条目明文泄漏面。"""
    source_env = make_vault_env(root=tmp_path / "source", master_password="SourceMaster!2026")
    source = source_env.vault
    source_env.entry_mgr.add_entry(Entry(title="Incoming", password="IncomingSecret!2026"))
    portable = str(source_env.root / "portable.cbox")
    success, error = make_backup_manager(source).create_backup(portable, "PortableBackup!2026")
    assert success, error

    target_env = make_vault_env(root=tmp_path / "target", master_password="OldTargetMaster!2026")
    target = target_env.vault
    target_manager = target_env.entry_mgr
    target_manager.add_entry(Entry(title="Before restore", password="OriginalSecret!2026"))
    backup_manager = make_backup_manager(target, target_manager)
    success, error = backup_manager.restore_backup(portable, "PortableBackup!2026")
    assert success, error
    backup_dir = target_env.root / "backups"
    # 恢复轮换 snapshot_key 并清理恢复点（含恢复前明文），收缩泄漏面
    assert list(backup_dir.glob("pre_restore_*.cbox")) == [], "恢复后恢复点应被清理"

    # 改密同样触发 snapshot_key 轮换与清理，验证改密路径不残留
    assert target.change_master_password("OldTargetMaster!2026", "NewTargetMaster!2026")[0]
    assert list(backup_dir.glob("pre_restore_*.cbox")) == []


def test_existing_database_missing_table_is_rejected_without_repair(make_vault_env):
    """schema 损坏（缺表）打开数据库抛 SchemaError 而非静默修复（ARCH-004）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    vault.close()
    db_path = Path(root) / "vault.db"
    connection = sqlite3.connect(db_path)
    connection.execute("DROP TABLE password_history")
    connection.commit()
    connection.close()

    reopened = make_vault_env(initialize=False).vault
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
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    connection.close()
    assert "password_history" not in tables


def test_deleted_default_category_does_not_reappear_after_restart(make_vault_env):
    """删除的默认分类重启后不重新注入（默认分类仅首次初始化注入）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    root = env.root
    vault = env.vault
    category = next(
        item
        for item in make_entry_manager(vault).categories.get_categories()
        if item.name == "社交"
    )
    category_id = category.id
    assert category_id is not None
    vault.db.delete_category(category_id)
    vault.close()

    reopened = make_vault_env(initialize=False).vault
    reopened.ensure_db_open()  # ARCH-004：is_initialized 为纯查询，先打开数据库
    assert reopened.is_initialized is True
    assert reopened.unlock("MasterPassword!2026")[0]
    assert all(
        item.name != "社交" for item in make_entry_manager(reopened).categories.get_categories()
    )
