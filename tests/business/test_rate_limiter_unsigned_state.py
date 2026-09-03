"""RateLimiter 无签名降级不落盘测试（SEC-042 / SEC-057）。

签名密钥不可用（无 config、瞬时 keyring/DPAPI 故障或会话级临时密钥）时
``_save_state`` 完全不落盘、不建哨兵：若仍写无签名状态文件，下次会话密钥恢复后
会按「签名被剥离」误判为篡改并降级最高阶梯锁定（SEC-029 保守分支），对合法用户
形成误锁。
"""

from __future__ import annotations

from src.business.services.rate_limiter import RateLimiter


class _BrokenKeyConfig:
    """integrity_key 抛异常的 config 替身（模拟瞬时 keyring/DPAPI 故障）。"""

    session_only = False

    @property
    def integrity_key(self) -> bytes:
        raise RuntimeError("keyring unavailable")


class _SessionOnlyConfig:
    """session_only=True 的 config 替身（模拟 DPAPI protect 失败的会话级降级）。"""

    session_only = True

    @property
    def integrity_key(self) -> bytes:
        raise AssertionError("session_only 会话不应取持久化密钥签名")


def test_no_config_instance_does_not_persist_state(tmp_path):
    """无 config 实例：record_failure 仅内存生效，状态文件与哨兵均不创建。"""
    state = tmp_path / "login_rate_limit.json"
    rl = RateLimiter(state)  # 无 config → _signing_key 为 None
    assert rl._signing_key is None

    rl.record_failure()
    rl.record_failure()

    assert rl.fail_count == 2  # 内存限流仍生效（公开观察面，MAINT-095）
    assert not state.exists()
    assert not (tmp_path / "login_rate_limit.json.sentinel").exists()


def test_failing_signing_key_does_not_persist_state(tmp_path):
    """config 注入但取密钥抛异常（瞬时故障）同样不落盘（SEC-042）。"""
    state = tmp_path / "login_rate_limit.json"
    rl = RateLimiter(state, config=_BrokenKeyConfig())  # type: ignore[arg-type]
    assert rl._signing_key is None

    rl.record_failure()
    rl.record_success()
    rl.record_failure()

    assert not state.exists()
    assert not (tmp_path / "login_rate_limit.json.sentinel").exists()


def test_degraded_session_next_session_treated_as_first_use(tmp_path):
    """降级会话不落盘后，下次会话（密钥恢复）按首次使用处理，不误判锁定。

    守护端到端链路：无签名状态文件形态不存在 → 哨兵/config 见证均未登记 →
    新会话 ``check()`` 返回 None（不触发 SEC-029 的篡改/删除降级锁定）。
    """
    state = tmp_path / "login_rate_limit.json"
    degraded = RateLimiter(state)
    for _ in range(5):
        degraded.record_failure()
    assert not state.exists()

    # 下次会话：仍无 config（密钥未恢复），状态缺失按首次使用
    recovered_like = RateLimiter(state)
    assert recovered_like.check() is None
    assert recovered_like.fail_count == 0  # 公开观察面（MAINT-095）


class TestSessionOnlyKeyDoesNotPersist:
    """会话级临时密钥（SEC-057）不签名限流状态落盘，走 SEC-042 既有不落盘路径。

    触发链（修复前）：DPAPI protect 失败 → ConfigKeyStore 返回会话级内存密钥 →
    RateLimiter 以临时密钥签名状态落盘 → 下次启动密钥重新生成 → 签名失配按
    SEC-029 保守分支降级最高阶梯锁定（15 次 / 600 秒）——DPAPI 持续故障时用户
    每次启动都误锁 10 分钟。修复后 ``config.session_only`` 置位时签名密钥解析为
    None，状态文件与哨兵均不落盘，下次启动按首次使用处理。
    """

    def test_session_only_stub_does_not_persist_state(self, tmp_path):
        """session_only=True 的 config：仅内存限流，状态文件与哨兵均不创建。"""
        state = tmp_path / "login_rate_limit.json"
        rl = RateLimiter(state, config=_SessionOnlyConfig())  # type: ignore[arg-type]
        assert rl._signing_key is None

        rl.record_failure()
        rl.record_failure()

        assert rl.fail_count == 2  # 内存限流仍生效（公开观察面，MAINT-095）
        assert rl.check() is None  # 未达锁定阈值
        assert not state.exists()
        assert not (tmp_path / "login_rate_limit.json.sentinel").exists()

    def test_dpapi_failure_end_to_end_does_not_persist_state(self, tmp_path, monkeypatch):
        """端到端：模拟 protect 失败 → session_only 置位 → 状态不落盘、下次按首次使用。

        经真实 ConfigManager + ConfigKeyStore 链路（monkeypatch cks.IS_WINDOWS=True
        与 protect_with_dpapi 返回 None，平台打桩按 _platform docstring 约定 patch
        消费方模块绑定），跨平台可跑（Linux CI 同样覆盖 win32 分支，参照
        tests/config/test_config_integrity.py 的 TestDpapiProtectFailureFallback）。
        """
        import src.config_key_store as cks
        from tests.helpers import make_test_config

        monkeypatch.setattr(cks, "IS_WINDOWS", True)
        monkeypatch.setattr(cks, "protect_with_dpapi", lambda data: None)

        config = make_test_config(tmp_path)
        assert config.session_only is True  # DPAPI 失败 → 会话级临时密钥（SEC-055/056）
        assert len(config.integrity_key) == 32  # 内存密钥照常可用

        state = tmp_path / "login_rate_limit.json"
        rl = RateLimiter(state, config)
        assert rl._signing_key is None  # 临时密钥不用于状态签名（SEC-057）
        for _ in range(5):
            rl.record_failure()
        # 内存限流生效（第 5 次失败触发第二档锁定），但状态与哨兵均不落盘
        assert rl.check() is not None
        assert not state.exists()
        assert not (tmp_path / "login_rate_limit.json.sentinel").exists()

        # 下次启动（DPAPI 恢复）：状态/哨兵成对缺失 → 按首次使用，不误锁 600 秒
        monkeypatch.setattr(cks, "protect_with_dpapi", lambda data: b"dpapi:" + data)
        recovered_config = make_test_config(tmp_path)
        assert recovered_config.session_only is False
        recovered = RateLimiter(state, recovered_config)
        assert recovered.check() is None
        assert recovered.fail_count == 0  # 公开观察面（MAINT-095）


class TestUnsignedStateFileTrustedAtFaceValue:
    """读侧对无法验签状态文件的按面值采信（SEC-064 权衡修正）。

    ``_signing_key is None``（session_only / 密钥获取异常 / 无 config）而磁盘状态
    文件存在时，文件内容无法验签。曾按「无法验证即不信任」降级最高阶梯锁定
    （600 秒），但这会**确定性**误伤诚实降级会话——磁盘上留有上次正常会话的
    合法签名状态文件，而 ``_save_state`` 无签名密钥时不落盘（SEC-042），文件
    永不重签，每次启动都重复零失败锁定，打破 SEC-057「避免每次启动误锁」承诺。
    篡改被采信需要「签名密钥故障 + 文件被篡改」双条件同时成立，前者不可由
    攻击者诱发——权衡后采信内容并记 WARNING；内容损坏仍走损坏分支保守锁定。
    """

    def test_unsigned_state_file_with_no_config_trusted_at_face_value(self, tmp_path):
        """无 config + 磁盘存在（上次正常会话遗留）状态文件 → 内容按面值采信，不误锁。"""
        state = tmp_path / "login_rate_limit.json"
        # 上次正常会话遗留形态：格式合法 JSON（本会话无法验签其签名）
        state.write_text('{"fail_count": 2, "remaining_seconds": 0}', encoding="utf-8")

        rl = RateLimiter(state)  # 无 config → _signing_key None
        assert rl._signing_key is None
        # 内容按面值采信：计数照常恢复、不叠加误锁
        assert rl.fail_count == 2
        assert rl.check() is None  # 无锁定
        # SEC-042：无签名密钥不落盘——文件保持原样（不产生无签名新形态）
        assert state.read_text(encoding="utf-8").startswith("{")
        assert "#__sig__:" not in state.read_text(encoding="utf-8")

    def test_unsigned_state_file_with_broken_key_config_trusted(self, tmp_path):
        """config 注入但取密钥异常（瞬时故障）+ 磁盘存在状态文件 → 同样按面值采信。"""
        state = tmp_path / "login_rate_limit.json"
        state.write_text('{"fail_count": 3, "remaining_seconds": 0}', encoding="utf-8")

        rl = RateLimiter(state, config=_BrokenKeyConfig())  # type: ignore[arg-type]
        assert rl._signing_key is None
        assert rl.fail_count == 3
        assert rl.check() is None

    def test_unsigned_corrupt_content_still_degrades_to_max_lockdown(self, tmp_path):
        """按面值采信不豁免损坏分支：内容非法 JSON → 保守降级最高阶梯锁定。"""
        from src.config import RATE_LIMITS

        state = tmp_path / "login_rate_limit.json"
        state.write_text("not-a-json{{{", encoding="utf-8")

        rl = RateLimiter(state)  # 无 config → 无法验签，内容损坏走损坏分支

        assert rl.fail_count == RATE_LIMITS[-1][0]
        assert rl.check() is not None

    def test_signed_state_with_valid_key_still_trusted(self, tmp_path, monkeypatch):
        """对照：签名密钥可用时，合法签名的既有状态照常加载（守卫不误伤正常路径）。"""
        import hashlib
        import hmac as hmac_mod

        from tests.helpers import make_test_config

        # 真实 ConfigManager + 健康密钥链（win32 上 DPAPI、其他平台视 keyring 可用性）
        # 简化：直接用内存签名密钥构造已签名文件（签名/验签路径单测见 test_rate_limiter）。
        state = tmp_path / "login_rate_limit.json"
        payload = '{"fail_count": 2, "remaining_seconds": 0}'
        key = b"k" * 32
        sig = hmac_mod.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        state.write_text(f"{payload}\n#__sig__:{sig}", encoding="utf-8")

        cfg = make_test_config(tmp_path)
        # 注入已知签名密钥（绕过平台密钥链，专注读侧验签分支的行为对照）
        monkeypatch.setattr(type(cfg), "integrity_key", property(lambda self: key))

        rl = RateLimiter(state, config=cfg)
        assert rl._signing_key == key
        assert rl.fail_count == 2  # 合法签名内容被采信
        assert rl.check() is None
