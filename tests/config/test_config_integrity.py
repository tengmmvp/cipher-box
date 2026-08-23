"""测试配置文件 HMAC 完整性签名与篡改检测。

覆盖 save 与 load 的签名往返、JSON 内容被篡改后的完整性告警，以及原子写入
使用 .json.tmp 中间文件再 os.replace 的落盘行为。
"""

import sys

import pytest

from tests.helpers import make_test_config


@pytest.fixture
def config(tmp_path):
    """创建使用临时目录的 ConfigManager 实例。"""
    return make_test_config(tmp_path)


class TestConfigIntegrity:
    """配置 save/load 的 HMAC 签名往返、篡改检测与原子写入测试。"""

    def test_save_load_round_trip(self, config):
        """save() 写入 HMAC 签名，load() 正常加载且无警告。"""
        config._config["theme"] = "dark"
        config.save()
        assert config._config_path.exists()

        # 重新加载
        config2 = make_test_config(config._data_dir)
        config2.load()

        assert config2._config["theme"] == "dark"
        assert config2.check_integrity() is True

    def test_tampered_content_detected(self, config):
        """篡改 JSON 内容后 load() 应标记完整性警告。"""
        config.save()

        # 篡改文件内容：修改 JSON 但保留签名行
        raw = config._config_path.read_text(encoding="utf-8")
        lines = raw.rsplit("\n", 1)
        assert len(lines) == 2
        json_text = lines[0]
        sig_line = lines[1]

        tampered = json_text.replace('"theme": "light"', '"theme": "dark"')
        config._config_path.write_text(tampered + "\n" + sig_line, encoding="utf-8")

        # 重新加载
        config2 = make_test_config(config._data_dir)
        config2.load()

        assert config2.check_integrity() is False

    def test_atomic_write_uses_tmp(self, config):
        """save() 使用随机后缀 .tmp 中间文件再 os.replace，完成后不残留。"""
        config.save()
        # 任意随机后缀的 .tmp 中间文件均不应残留（SEC-028 后临时名非固定）
        assert not list(config._config_path.parent.glob("config.json.*.tmp"))
        assert not (config._config_path.parent / "config.json.tmp").exists()
        # 目标文件存在
        assert config._config_path.exists()

    def test_each_install_uses_distinct_integrity_key(self, tmp_path):
        """不同安装目录生成独立的 integrity key 与签名，防止跨安装伪造配置签名。

        integrity key 每安装随机生成（非硬编码），使一处安装的签名密钥无法用于伪造
        另一处安装的 config 签名——守护 config 完整性的安全前提。
        """
        first = make_test_config(tmp_path / "first")
        second = make_test_config(tmp_path / "second")
        first.save()
        second.save()

        assert first._integrity_key != second._integrity_key
        first_sig = first.config_path.read_text(encoding="utf-8").rsplit("\n", 1)[1]
        second_sig = second.config_path.read_text(encoding="utf-8").rsplit("\n", 1)[1]
        assert first_sig != second_sig


class TestSecuritySentinelWitness:
    """签名 config 的安全哨兵登记见证（S5）：使「状态文件+哨兵被同时删除」可检测。"""

    def test_register_persists_signed_and_idempotent(self, tmp_path):
        """register 登记写入签名 config，重载后仍可见；重复登记幂等不重复写。"""
        config = make_test_config(tmp_path)
        config.register_security_sentinel("login_rate_limit")
        assert config.is_security_sentinel_established("login_rate_limit")
        # 幂等：再次登记不重复、不抛异常
        config.register_security_sentinel("login_rate_limit")
        assert config.get("security_sentinels") == ["login_rate_limit"]

        # 重载（经同一 integrity key）签名校验通过，登记仍在
        reloaded = make_test_config(config._data_dir)
        reloaded.load()
        assert reloaded.check_integrity()
        assert reloaded.is_security_sentinel_established("login_rate_limit")

    def test_register_writes_valid_signature(self, tmp_path):
        """register 经 save 写出有效签名——攻击者无法在抹除登记后伪造签名。"""
        config = make_test_config(tmp_path)
        config.register_security_sentinel("change_master_rate_limit")
        raw = config.config_path.read_text(encoding="utf-8")
        assert "#__sig__:" in raw
        assert "change_master_rate_limit" in raw

    def test_tampered_witness_list_detected(self, tmp_path):
        """篡改 security_sentinels 值（保留旧签名）→ 签名失配 → 完整性失败。"""
        config = make_test_config(tmp_path)
        config.register_security_sentinel("login_rate_limit")

        raw = config.config_path.read_text(encoding="utf-8")
        json_text, sig_line = raw.rsplit("\n", 1)
        tampered = json_text.replace('"login_rate_limit"', '"never_existed"')
        config.config_path.write_text(tampered + "\n" + sig_line, encoding="utf-8")

        reloaded = make_test_config(config._data_dir)
        reloaded.load()
        assert not reloaded.check_integrity()
        # 完整性失败时敏感键回退默认（空），不采信被篡改的登记内容
        assert reloaded.get("security_sentinels") == []


class TestKeyringIntegrityKey:
    """非 Windows 平台经 keyring 存储配置签名密钥（SEC-003）。

    守护 macOS/Linux 下签名密钥经系统密钥链（Keychain / Secret Service）存取，
    替代明文 config.key，收缩本地读权限者重算签名伪造安全配置的攻击面。
    密钥链自 config.py 下沉至 ConfigKeyStore（MAINT-020），单测直接构造存储实例；
    端到端用例仍经 ConfigManager 组合验证接线。
    """

    @pytest.fixture
    def store(self, tmp_path):
        """构造指向临时目录的 ConfigKeyStore。"""
        from src.config_key_store import ConfigKeyStore

        return ConfigKeyStore(tmp_path / "config.key", tmp_path)

    def test_store_and_load_via_keyring(self, store, monkeypatch):
        """keyring 存储/读取往返：密钥经 base64 存取原样还原。"""
        import keyring as keyring_mod

        keyring_store: dict[tuple[str, str], str] = {}
        monkeypatch.setattr(
            keyring_mod, "set_password", lambda s, u, p: keyring_store.__setitem__((s, u), p)
        )
        monkeypatch.setattr(keyring_mod, "get_password", lambda s, u: keyring_store.get((s, u)))

        key = b"\x11" * 32
        assert store._store_keyring_integrity_key(key) is True
        assert store._load_keyring_integrity_key() == key

    def test_store_failure_returns_false(self, store, monkeypatch):
        """keyring.set_password 抛异常时返回 False，调用方据此回退明文 0600。"""
        import keyring as keyring_mod

        def boom(*args, **kwargs):
            raise OSError("Secret Service 不可用")

        monkeypatch.setattr(keyring_mod, "set_password", boom)
        assert store._store_keyring_integrity_key(b"\x00" * 32) is False

    def test_load_backend_unavailable_falls_back_plaintext(self, store, monkeypatch):
        """keyring.get_password 抛异常时回退读明文 config.key。"""
        import keyring as keyring_mod

        store._write_integrity_key_file(b"\x22" * 32)  # 遗留明文

        def boom(*args, **kwargs):
            raise OSError("后端不可用")

        monkeypatch.setattr(keyring_mod, "get_password", boom)
        assert store._load_keyring_integrity_key() == b"\x22" * 32

    def test_load_corrupt_keyring_value_returns_none(self, store, monkeypatch):
        """keyring 中存值非法 base64 时返回 None，触发上层重新生成密钥。"""
        import keyring as keyring_mod

        monkeypatch.setattr(keyring_mod, "get_password", lambda *a: "!!!not base64!!!")
        assert store._load_keyring_integrity_key() is None

    def test_load_or_create_uses_keyring_on_non_windows(self, tmp_path, monkeypatch):
        """端到端：非 Windows 平台 load_or_create 优先用 keyring，不落明文文件。

        守护 SEC-003 核心收益——keyring 可用时签名密钥不写明文 config.key，
        使本地读权限者无法获取原始密钥重算签名。
        """
        import sys

        import keyring as keyring_mod

        monkeypatch.setattr(sys, "platform", "linux")
        keyring_store: dict[tuple[str, str], str] = {}
        monkeypatch.setattr(
            keyring_mod, "set_password", lambda s, u, p: keyring_store.__setitem__((s, u), p)
        )
        monkeypatch.setattr(keyring_mod, "get_password", lambda s, u: keyring_store.get((s, u)))

        cfg = make_test_config(tmp_path)
        assert len(cfg._integrity_key) == 32
        # 密钥经 keyring 存储，未落明文文件；条目名按安装目录派生（多安装互不共享）
        assert ("CipherBox", cfg._key_store._keyring_entry_name()) in keyring_store
        assert not cfg._integrity_key_path.exists()

    @pytest.mark.skipif(sys.platform != "win32", reason="DPAPI 迁移仅 Windows")
    def test_plaintext_integrity_key_migrated_to_dpapi(self, tmp_path):
        """pre-SEC-003 明文 config.key 首次加载时迁移到 DPAPI 封装（SEC-021）。

        守护升级路径：既有明文密钥不原样保留（窃取可离线重算签名），而是重新经
        DPAPI 封装原子覆盖写回，值不变但存储形态升级。
        """
        from src.utils.file_security import unprotect_with_dpapi

        cfg = make_test_config(tmp_path)  # 初始化生成 DPAPI 封装密钥
        key_path = cfg._integrity_key_path
        plaintext_key = b"\x33" * 32
        # 模拟 pre-SEC-003 明文 config.key（覆盖为明文）
        key_path.write_bytes(plaintext_key)
        # 重新加载触发迁移
        cfg2 = make_test_config(tmp_path)
        # 加载返回原明文密钥值（签名连续性）
        assert cfg2._integrity_key == plaintext_key
        # 文件已重新封装为 DPAPI（不再是原明文，可经 DPAPI 解封还原）
        blob = key_path.read_bytes()
        assert blob != plaintext_key
        assert unprotect_with_dpapi(blob) == plaintext_key
