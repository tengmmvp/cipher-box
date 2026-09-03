"""导入导出端到端回归（自 test_product_hardening 按主题拆出）。

覆盖 Bitwarden 导入字段保真、导入异常的 epoch 守卫事务回滚、无密码导出的敏感
字段剔除、无密码覆盖导入保留既有密钥、import_all 不解密既有库五条端到端链路。
建库经 make_vault_env 工厂（统一装配/幂等 close 回收）。
"""

import json
from pathlib import Path
from unittest.mock import patch

from src.business.managers.import_export import ImportExportManager
from src.models import CustomField, Entry
from tests.helpers import decrypt_all_entries


def test_bitwarden_import_preserves_folder_totp_and_custom_fields(make_vault_env):
    """Bitwarden 导入保留文件夹分类、TOTP 与自定义字段。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    manager = env.entry_mgr
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
    path = Path(env.root) / "bitwarden.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert importer.import_file(str(path), "bitwarden_json") == 1
    entry = decrypt_all_entries(manager)[0]
    assert entry.category_name == "Work"
    assert entry.totp_secret == "JBSWY3DPEHPK3PXP"
    assert entry.is_favorite is True
    bitwarden_fields = entry.custom_fields
    assert isinstance(bitwarden_fields, list)
    assert bitwarden_fields[0].name == "PIN"
    assert bitwarden_fields[0].field_type == "password"


def test_import_rolls_back_when_any_entry_fails(make_vault_env):
    """导入遇异常经 epoch 守卫事务回滚，不留部分写入数据。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    manager = env.entry_mgr
    importer = ImportExportManager(manager)
    path = Path(env.root) / "entries.json"
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

    # 导入经 entry_batch_writer.write_new_entries 批量写入（executemany）。模拟写入
    # 失败：RuntimeError 不在导入容错捕获内，异常冒泡使 epoch 守卫事务回滚，不留部分写入。
    with patch(
        "src.business.managers.import_export.write_new_entries",
        side_effect=RuntimeError("simulated import failure"),
    ):
        try:
            importer.import_file(str(path), "json")
        except RuntimeError:
            pass
    assert manager.get_entry_count() == 0


def test_export_without_password_excludes_secret_custom_fields(make_vault_env):
    """不含密码导出时剔除敏感自定义字段（如卡号/CVV）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    manager = env.entry_mgr
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
    path = Path(env.root) / "safe-export.json"
    ImportExportManager(manager).export_to_json(
        str(path), decrypt_all_entries(manager), include_password=False
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    exported = payload["entries"][0]

    assert payload["secrets_included"] is False
    assert "password" not in exported
    assert "totp_secret" not in exported
    assert exported["custom_fields"] == [
        {"name": "Display name", "value": "Public value", "field_type": "text"}
    ]


def test_passwordless_overwrite_import_preserves_existing_secrets(make_vault_env):
    """无密码覆盖导入保留既有密码、TOTP 与敏感字段。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    manager = env.entry_mgr
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
    path = Path(env.root) / "without-secrets.json"
    exporter.export_to_json(str(path), decrypt_all_entries(manager), include_password=False)

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


def test_import_all_does_not_decrypt_existing_vault(make_vault_env):
    """import_all 模式导入不扫描解密既有条目（性能与隔离保证）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    manager = env.entry_mgr
    manager.add_entry(Entry(title="Existing", password="ExistingSecret!2026"))
    path = Path(env.root) / "entries.json"
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
