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

    def test_non_ascii_signature_line_triggers_integrity_warning(self, config):
        """签名行被改写为非 ASCII（SEC-071）→ 按「签名不符」告警，不被 TypeError 吞掉。

        compare_digest 对非 ASCII str 抛 TypeError：修复前异常被 load 的外层 except
        捕获走「配置文件无效用默认」，_integrity_warning 未置位，篡改的用户通知被
        静默抑制。修复后镜像 rate_limiter 验签的 isascii 前置守卫，按 mismatch 走
        既有告警链（对齐 QL-019/SEC-031 同型 bug 的回归面）。
        """
        config.save()
        raw = config._config_path.read_text(encoding="utf-8")
        json_text, _old_sig = raw.rsplit("\n", 1)
        # 保留 JSON 主体与签名行前缀，仅把签名值改为非 ASCII（中文）
        config._config_path.write_text(json_text + "\n#__sig__:被篡改的签名值", encoding="utf-8")

        reloaded = make_test_config(config._data_dir)
        reloaded.load()

        assert reloaded.check_integrity() is False
        assert reloaded.integrity_reason == "mismatch"

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

    def test_register_keeps_integrity_warning(self, tmp_path):
        """告警置位后哨兵登记不清零完整性告警（QL-064 回归）。

        触发链：config 签名校验失败（告警置位）+ 首会话哨兵未登记 + 限流状态文件
        损坏 → RateLimiter._load_state→_apply_max_lockdown→_save_state→
        _ensure_sentinel→register_security_sentinel→save()。修复前 save() 无条件
        清告警，LoginWindow 构造期即清零、抑制 MainWindow 的完整性用户提示；修复后
        哨兵登记走保留告警的写入变体，会话内告警存活（下个会话加载干净文件自然恢复）。
        """
        config = make_test_config(tmp_path)
        config.register_security_sentinel("login_rate_limit")  # 建立既有干净 config
        config.save()
        # 模拟篡改：修改 JSON 保留旧签名 → 重载检出签名失配、告警置位
        raw = config.config_path.read_text(encoding="utf-8")
        json_text, sig_line = raw.rsplit("\n", 1)
        tampered = json_text.replace('"theme": "light"', '"theme": "dark"')
        config.config_path.write_text(tampered + "\n" + sig_line, encoding="utf-8")
        tampered_cfg = make_test_config(tmp_path)
        tampered_cfg.load()
        assert not tampered_cfg.check_integrity()

        # 限流器在告警置位的会话内登记新哨兵（真实触发链的等价最小化）
        tampered_cfg.register_security_sentinel("change_master_rate_limit")

        # 告警仍在：用户通知不被后台自动写盘静默清除；登记本身生效
        assert not tampered_cfg.check_integrity()
        assert tampered_cfg.integrity_reason == "mismatch"
        assert tampered_cfg.is_security_sentinel_established("change_master_rate_limit")
        # 磁盘文件已重签（含新登记）：下个会话加载干净文件后告警自然消失
        reloaded = make_test_config(tmp_path)
        reloaded.load()
        assert reloaded.check_integrity()
        assert reloaded.is_security_sentinel_established("change_master_rate_limit")

    def test_plain_save_still_clears_integrity_warning(self, tmp_path):
        """普通 save 仍清零告警（QL-064 不改变用户驱动保存的既有语义）。"""
        config = make_test_config(tmp_path)
        config.register_security_sentinel("login_rate_limit")
        config.save()
        raw = config.config_path.read_text(encoding="utf-8")
        json_text, sig_line = raw.rsplit("\n", 1)
        config.config_path.write_text(
            json_text.replace('"theme": "light"', '"theme": "dark"') + "\n" + sig_line,
            encoding="utf-8",
        )
        tampered_cfg = make_test_config(tmp_path)
        tampered_cfg.load()
        assert not tampered_cfg.check_integrity()

        tampered_cfg.save()

        assert tampered_cfg.check_integrity()  # 普通保存后告警按原语义清零


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
        import keyring as keyring_mod

        import src.config_key_store as cks

        # 平台打桩按 _platform docstring 约定 patch 消费方模块的 IS_WINDOWS 绑定
        monkeypatch.setattr(cks, "IS_WINDOWS", False)
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

    def test_keyring_recovery_migrates_plaintext_key_back(self, tmp_path, monkeypatch):
        """keyring 恢复可用后明文回退密钥一次性回迁 keyring 并清理明文文件（SEC-003）。

        修复前的粘滞形态：keyring 故障期明文 config.key 落地，keyring 恢复后
        _load_keyring_integrity_key 只回读明文文件、永不回写——SEC-003 保护对该
        安装持续失效。修复后启动即回迁：密钥写入 keyring + 清理明文文件（统一走
        _purge_plaintext_key_residue chokepoint），后续会话直接走 keyring。
        """
        import keyring as keyring_mod

        import src.config_key_store as cks
        from src.config_key_store import ConfigKeyStore

        monkeypatch.setattr(cks, "IS_WINDOWS", False)
        keyring_store: dict[tuple[str, str], str] = {}
        monkeypatch.setattr(keyring_mod, "get_password", lambda s, u: keyring_store.get((s, u)))
        monkeypatch.setattr(
            keyring_mod, "set_password", lambda s, u, p: keyring_store.__setitem__((s, u), p)
        )

        store = ConfigKeyStore(tmp_path / "config.key", tmp_path)
        plaintext = b"\x44" * 32
        store._write_integrity_key_file(plaintext)  # keyring 故障期写入的明文回退形态

        key = store.load_or_create()
        # 密钥值不变（既有 config 签名连续性保持），但已回迁 keyring、明文文件清除
        assert key == plaintext
        assert ("CipherBox", store._keyring_entry_name()) in keyring_store
        assert not (tmp_path / "config.key").exists()

        # 后续启动：直接命中 keyring，同一密钥，不再产生明文文件
        key2 = ConfigKeyStore(tmp_path / "config.key", tmp_path).load_or_create()
        assert key2 == plaintext
        assert not (tmp_path / "config.key").exists()

    def test_keyring_migration_failure_keeps_plaintext_fallback(
        self, tmp_path, monkeypatch, caplog
    ):
        """回迁失败（set_password 抛异常）保持明文回退现状、密钥照常可用、ERROR 可见。

        迁移失败不阻断启动（与密钥链「绝不阻断启动」契约一致），下次 keyring 恢复
        后重试回迁。
        """
        import logging

        import keyring as keyring_mod

        import src.config_key_store as cks
        from src.config_key_store import ConfigKeyStore

        monkeypatch.setattr(cks, "IS_WINDOWS", False)
        monkeypatch.setattr(keyring_mod, "get_password", lambda s, u: None)
        monkeypatch.setattr(
            keyring_mod,
            "set_password",
            lambda *a, **k: (_ for _ in ()).throw(OSError("keyring 只读")),
        )
        caplog.set_level(logging.ERROR, logger="src.config_key_store")

        store = ConfigKeyStore(tmp_path / "config.key", tmp_path)
        plaintext = b"\x55" * 32
        store._write_integrity_key_file(plaintext)

        key = store.load_or_create()
        assert key == plaintext  # 密钥照常可用，绝不阻断启动
        assert (tmp_path / "config.key").exists()  # 明文回退现状保持
        assert any("回迁失败" in record.message for record in caplog.records)

    @pytest.mark.skipif(sys.platform != "win32", reason="DPAPI 分支仅 Windows")
    def test_plaintext_integrity_key_treated_as_corrupt(self, tmp_path):
        """非 DPAPI 封装的 config.key（含 32 字节明文形态）按损坏处理（SEC-052）。

        pre-SEC-003 明文迁移分支（SEC-021）已删除：项目未发布无遗留安装，明文
        形态不再被特殊接受，一律生成新密钥（旧签名随之失效，走完整性告警与敏感
        键回退），文件重新以 DPAPI 封装写入新密钥。
        """
        from src.utils.dpapi import unprotect_with_dpapi

        cfg = make_test_config(tmp_path)  # 初始化生成 DPAPI 封装密钥
        key_path = cfg._integrity_key_path
        plaintext_key = b"\x33" * 32
        # 模拟非 DPAPI 封装形态（长度合法的明文）
        key_path.write_bytes(plaintext_key)
        # 重新加载触发「损坏 → 生成新密钥」路径
        cfg2 = make_test_config(tmp_path)
        # 旧明文密钥不被采信：生成的新密钥与之不同
        assert cfg2._integrity_key != plaintext_key
        assert len(cfg2._integrity_key) == 32
        # 文件重新以 DPAPI 封装写入（不再是明文，可解封出新密钥）
        blob = key_path.read_bytes()
        assert blob != plaintext_key
        assert unprotect_with_dpapi(blob) == cfg2._integrity_key


class TestDpapiProtectFailureFallback:
    """win32 下 DPAPI protect 失败的降级语义（SEC-055 回归守护）。

    经 monkeypatch cks.IS_WINDOWS 与 protect_with_dpapi 跨平台可跑（Linux CI
    同样覆盖 win32 分支逻辑；平台打桩按 _platform docstring 约定 patch 消费方
    模块的绑定；file_security 的 IS_WINDOWS 常量按真实平台取值，仅影响权限
    加固方式，不影响本测试断言的写盘行为）。
    """

    def test_protect_failure_never_writes_plaintext_key_file(self, tmp_path, monkeypatch, caplog):
        """protect 失败不写明文密钥文件、返回内存密钥并记 CRITICAL（SEC-055）。

        修复前的组合行为：protect 失败回退写明文 32 字节且返回 True——读侧
        （SEC-052）只认 DPAPI 封装，该文件下次启动必被判损坏，触发假「配置文件
        完整性校验失败，可能已被篡改」告警 + 敏感键回退 + RateLimiter 签名失配
        降级到最大锁定。修复后不写任何文件，下次启动走「文件缺失 → 重新生成」
        的诚实路径。
        """
        import logging

        import src.config_key_store as cks

        monkeypatch.setattr(cks, "IS_WINDOWS", True)
        monkeypatch.setattr(cks, "protect_with_dpapi", lambda data: None)
        caplog.set_level(logging.CRITICAL, logger="src.config_key_store")

        store = cks.ConfigKeyStore(tmp_path / "config.key", tmp_path)
        key = store.load_or_create()

        # 内存密钥照常可用（绝不阻断启动）
        assert len(key) == 32
        # 核心断言：绝不产生「写明文 32 字节 + 下次启动判损坏」的组合行为
        assert not (tmp_path / "config.key").exists()
        # 降级可见：CRITICAL 如实暴露「密钥未能安全持久化」
        assert any(record.levelno == logging.CRITICAL for record in caplog.records)

        # 下次启动（protect 恢复后）走「文件缺失 → 重新生成」，与本会话密钥不同
        monkeypatch.setattr(cks, "protect_with_dpapi", lambda data: b"dpapi:" + data)
        key2 = cks.ConfigKeyStore(tmp_path / "config.key", tmp_path).load_or_create()
        assert key2 != key
        assert (tmp_path / "config.key").read_bytes() == b"dpapi:" + key2


def _raise_oserror(*args, **kwargs):
    """atomic_write 失败桩：无条件抛 OSError（模拟磁盘满/只读介质）。"""
    raise OSError("磁盘已满（模拟）")


class TestKeyPersistenceWriteFailure:
    """密钥文件写盘失败的会话级降级（SEC-065）。

    ``_write_integrity_key_file`` 的 atomic_write（secure_file strict=True）在磁盘
    满/只读介质抛 OSError，沿 ``_store_secure_integrity_key → load_or_create →
    ConfigManager.__init__`` 全链无捕获 → 启动即崩，违背「绝不阻断启动」契约。
    修复后两个写盘分支（Windows DPAPI 封装写盘 / 非 Windows 明文回退写盘）均
    降级 session_only 语义：内存密钥 + CRITICAL，与 protect 失败分支（SEC-055）
    对称。
    """

    def test_win32_dpapi_write_failure_degrades_to_session_only(
        self, tmp_path, monkeypatch, caplog
    ):
        """win32：protect 成功但密钥文件写盘 OSError → 不崩、session_only、内存密钥可用。"""
        import logging

        import src.config_key_store as cks

        monkeypatch.setattr(cks, "IS_WINDOWS", True)
        monkeypatch.setattr(cks, "protect_with_dpapi", lambda data: b"dpapi:" + data)
        monkeypatch.setattr(cks, "atomic_write", _raise_oserror)
        caplog.set_level(logging.CRITICAL, logger="src.config_key_store")

        store = cks.ConfigKeyStore(tmp_path / "config.key", tmp_path)
        key = store.load_or_create()  # 修复前此处直接抛 OSError 崩启动

        assert len(key) == 32  # 内存密钥照常可用
        assert store.session_only is True  # SEC-057 会话级降级可见
        assert not (tmp_path / "config.key").exists()
        assert any(record.levelno == logging.CRITICAL for record in caplog.records)

    def test_non_windows_plaintext_fallback_write_failure_degrades(
        self, tmp_path, monkeypatch, caplog
    ):
        """非 Windows：keyring 不可用回退明文，写盘同样 OSError → 同款降级不崩。"""
        import logging

        import keyring as keyring_mod

        import src.config_key_store as cks

        monkeypatch.setattr(cks, "IS_WINDOWS", False)
        # keyring 不可用（conftest 已全局禁用；显式置 None 记录确保走明文回退分支）
        monkeypatch.setattr(keyring_mod, "get_password", lambda s, u: None)
        monkeypatch.setattr(
            keyring_mod, "set_password", lambda *a, **k: (_ for _ in ()).throw(OSError("x"))
        )
        monkeypatch.setattr(cks, "atomic_write", _raise_oserror)
        caplog.set_level(logging.CRITICAL, logger="src.config_key_store")

        store = cks.ConfigKeyStore(tmp_path / "config.key", tmp_path)
        key = store.load_or_create()

        assert len(key) == 32
        assert store.session_only is True
        assert not (tmp_path / "config.key").exists()
        assert any(record.levelno == logging.CRITICAL for record in caplog.records)

    def test_config_manager_init_survives_key_write_failure(self, tmp_path, monkeypatch):
        """端到端：ConfigManager.__init__（启动链）经写盘失败不抛异常、config 可用。

        平台真实值即可：win32 走 DPAPI 封装写盘、非 win32 走明文回退写盘
        （keyring 不可用，conftest 全局禁用），两个分支的 atomic_write 均被拦截。
        """
        import src.config_key_store as cks

        monkeypatch.setattr(cks, "atomic_write", _raise_oserror)

        cfg = make_test_config(tmp_path)
        assert len(cfg.integrity_key) == 32
        assert cfg.session_only is True


class TestKeyringPlaintextResidueCleanup:
    """明文 config.key 残留的统一清理（SEC-067 命中分支 + SEC-070 新生成分支）。

    残留面：a) keyring 记录损坏返回 None 走新生成，降级期明文文件遗留——新生成
    密钥成功写入 keyring 后本启动即清理（SEC-070）；b) 回迁时 secure_delete 失败，
    下次启动 keyring 直接命中时补清理。两分支共用 _purge_plaintext_key_residue
    （幂等、失败 ERROR 不阻断启动）。清理前置条件统一为「密钥已由平台安全存储
    有效供应」——读取侧不先行销毁可能唯一有效的明文回退（SEC-067 修复点）。
    """

    def _linux_keyring_stub(self, monkeypatch, keyring_store):
        import keyring as keyring_mod

        import src.config_key_store as cks

        monkeypatch.setattr(cks, "IS_WINDOWS", False)
        monkeypatch.setattr(keyring_mod, "get_password", lambda s, u: keyring_store.get((s, u)))
        monkeypatch.setattr(
            keyring_mod, "set_password", lambda s, u, p: keyring_store.__setitem__((s, u), p)
        )

    def test_keyring_hit_cleans_stale_plaintext_file(self, tmp_path, monkeypatch):
        """keyring 有效命中 + 盘中明文残留 → 加载即清理（场景 a 的下次启动形态）。"""
        import base64

        from src.config_key_store import ConfigKeyStore

        keyring_store: dict[tuple[str, str], str] = {}
        self._linux_keyring_stub(monkeypatch, keyring_store)

        store = ConfigKeyStore(tmp_path / "config.key", tmp_path)
        # 降级期遗留的明文文件（值与 keyring 无关，属待清理暴露面）
        store._write_integrity_key_file(b"\x66" * 32)
        # keyring 中已有有效密钥（此前会话存入）
        good_key = b"\x77" * 32
        keyring_store[("CipherBox", store._keyring_entry_name())] = base64.b64encode(
            good_key
        ).decode("ascii")

        key = store.load_or_create()

        assert key == good_key  # 密钥来自 keyring（非明文残留值）
        assert not (tmp_path / "config.key").exists()  # 残留已清理（SEC-067）

    def test_migration_delete_failure_retried_on_next_startup(self, tmp_path, monkeypatch):
        """回迁成功但 secure_delete 失败 → 下次启动 keyring 命中时补清理（场景 b）。"""
        import src.config_key_store as cks
        from src.config_key_store import ConfigKeyStore

        keyring_store: dict[tuple[str, str], str] = {}
        self._linux_keyring_stub(monkeypatch, keyring_store)

        # 会话 1：keyring 无记录、明文回退文件存在 → 回迁 keyring 成功、覆写删除失败
        calls = {"count": 0}
        real_delete = cks.secure_delete_file

        def _fail_first_then_real(path):
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("文件被占用（模拟）")
            return real_delete(path)

        monkeypatch.setattr(cks, "secure_delete_file", _fail_first_then_real)

        store = ConfigKeyStore(tmp_path / "config.key", tmp_path)
        plaintext = b"\x88" * 32
        store._write_integrity_key_file(plaintext)
        key = store.load_or_create()

        assert key == plaintext  # 回迁后密钥值不变
        assert (tmp_path / "config.key").exists()  # 删除失败，残留保留
        assert ("CipherBox", store._keyring_entry_name()) in keyring_store

        # 会话 2：keyring 直接命中 + 残留文件存在 → 统一清理补上（SEC-067）
        key2 = ConfigKeyStore(tmp_path / "config.key", tmp_path).load_or_create()
        assert key2 == plaintext
        assert not (tmp_path / "config.key").exists()  # 上次失败的清理在此重试成功

    def test_wrong_length_keyring_value_purges_after_regeneration(self, tmp_path, monkeypatch):
        """keyring 值可解码但长度错（SEC-067 修复点）→ 新生成入 keyring 后本启动即清理。

        原实现先 secure_delete 明文文件再由 load_or_create 验长度——keyring 记录
        损坏（可解码但非 32 字节）时会把可能唯一有效的明文回退密钥销毁在「新密钥
        尚未持久化」之前。修复后长度校验先于清理：损坏记录按损坏处理走新生成；
        新生成密钥成功写入 keyring 后旧明文回退已退役（新密钥生效、旧签名本就
        失配告警并经下次保存自愈），本启动即统一清理残留（SEC-070），无需等下次
        启动的 keyring 命中分支。

        顺序见证（回归可观测，SEC-067/070 演进）：终态断言（明文文件不存在）在
        正确序与「先删后验」的回归形态下收敛到同终态——回归不可观测。此处以
        spy 记录 keyring 写入与 secure_delete 的调用顺序，锚定 delete 晚于
        keyring 写入成功（回归形态 delete 先于写入，在此失败）。
        """
        import base64

        import keyring as keyring_mod

        import src.config_key_store as cks
        from src.config_key_store import ConfigKeyStore

        keyring_store: dict[tuple[str, str], str] = {}
        self._linux_keyring_stub(monkeypatch, keyring_store)
        events: list[str] = []
        real_set = keyring_mod.set_password
        real_delete = cks.secure_delete_file

        def _witness_set(service, user, password):
            result = real_set(service, user, password)
            events.append("keyring-write")
            return result

        def _witness_delete(path):
            result = real_delete(path)
            events.append("secure_delete")
            return result

        monkeypatch.setattr(keyring_mod, "set_password", _witness_set)
        monkeypatch.setattr(cks, "secure_delete_file", _witness_delete)

        store = ConfigKeyStore(tmp_path / "config.key", tmp_path)
        # 明文回退文件持有有效密钥（可能是最后的有效回退）
        valid_plaintext = b"\x99" * 32
        store._write_integrity_key_file(valid_plaintext)
        # keyring 记录可解码但长度错（损坏形态）
        keyring_store[("CipherBox", store._keyring_entry_name())] = base64.b64encode(
            b"\x01" * 31
        ).decode("ascii")

        key = store.load_or_create()

        # 损坏记录不被采信：新生成合法长度密钥（随机值，非明文回退亦非损坏记录值）
        assert len(key) == 32
        assert key != valid_plaintext
        assert key != b"\x01" * 31
        # keyring 记录已被新密钥覆写自愈
        assert keyring_store[("CipherBox", store._keyring_entry_name())] == base64.b64encode(
            key
        ).decode("ascii")
        # 新密钥已成功持久化到 keyring：明文残留本启动即清理（SEC-070）
        assert not (tmp_path / "config.key").exists()
        # 顺序见证：清理晚于 keyring 写入成功——「先删后验」的回归形态在此失败
        assert "secure_delete" in events and "keyring-write" in events
        assert events.index("secure_delete") > events.index("keyring-write")

    def test_b64_corrupt_keyring_regenerate_cleans_plaintext_residue(self, tmp_path, monkeypatch):
        """keyring 记录非法 base64（b64 解码失败分支）→ 新生成入 keyring → 残留清理。

        SEC-070 的另一损坏形态：b64 解码失败同样 return None 走新生成，原实现
        只在 keyring 命中有效密钥时清理明文残留，该路径的暴露面残留至下次启动。
        """
        import base64

        from src.config_key_store import ConfigKeyStore

        keyring_store: dict[tuple[str, str], str] = {}
        self._linux_keyring_stub(monkeypatch, keyring_store)

        store = ConfigKeyStore(tmp_path / "config.key", tmp_path)
        store._write_integrity_key_file(b"\x66" * 32)  # 降级期遗留的明文残留
        keyring_store[("CipherBox", store._keyring_entry_name())] = "!!!not base64!!!"

        key = store.load_or_create()

        assert len(key) == 32
        # 新密钥已成功写入 keyring（平台安全存储就位，自愈覆写损坏记录）
        assert keyring_store[("CipherBox", store._keyring_entry_name())] == base64.b64encode(
            key
        ).decode("ascii")
        # 明文残留文件被清理（SEC-070）
        assert not (tmp_path / "config.key").exists()
