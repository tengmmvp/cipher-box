"""VaultLifecycleOrchestrator 专属单元测试 — 保险库五阶段生命周期不变量守护。

经 ``build_vault`` 装配真实 orchestrator（``make_vault``），通过 ``VaultManager``
薄委托方法（``initialize``/``unlock``/``lock``/``change_master_password``/``close``）
间接驱动 :class:`VaultLifecycleOrchestrator`，验证每阶段可观察的状态与返回值，
不测 orchestrator 私有内部方法。

覆盖路径：
- initialize：首次设置主密码成功、重复初始化被拒绝（幂等保护）
- unlock：正确密码解锁成功、错误密码失败且保持锁定
- lock：清零主密钥与快照密钥并标记未解锁
- close：关闭数据库连接并清零密钥
- change_master_password：成功改密轮换凭据（旧失效/新可用）、错误旧密码被拒
- key_epoch 守卫：改密轮换 key_epoch，内存与数据库一致
- 解锁失败不留下半激活状态：错误密码失败后正确密码仍可立即解锁

conftest 的 autouse ``_weak_kdf_for_tests`` 已 patch
``vault_lifecycle.DEFAULT_KDF_PARAMS`` 为弱但合法的 Argon2id 参数，故本文件不显式
传 params 即可加速密钥派生，与 ``test_integration`` 风格一致。
"""

import pytest

from src.exceptions import VaultLockedError

# 与 conftest.vault fixture 同主密码，仅供本文件 fresh_vault 自驱初始化使用。
_MASTER_PASSWORD = "TestPassword123!"


@pytest.fixture
def fresh_vault(make_vault_env):
    """未初始化的全新 vault（make_vault_env(initialize=False)：完整装配不初始化）。

    每个测试自此空白状态自行驱动 initialize/unlock/lock 等阶段，互不干扰；
    teardown 幂等 close 由 make_vault_env 工厂统一承担。
    """
    return make_vault_env(initialize=False).vault


class TestInitialize:
    """initialize 阶段：首次设置主密码成功，重复初始化被拒绝。"""

    def test_first_initialize_sets_master_password(self, fresh_vault):
        """首次 initialize 返回成功，保险库进入已解锁态且密钥材料就位。

        守护不变量：initialize 经 activate_keys 原子激活主密钥/快照密钥/key_epoch
        并标记解锁，调用方无需额外 unlock 即可使用保险库。
        """
        ok, error = fresh_vault.initialize(_MASTER_PASSWORD)

        assert ok, f"首次初始化应成功，错误: {error}"
        assert error == ""
        assert fresh_vault.is_unlocked
        assert fresh_vault.key is not None
        assert fresh_vault.snapshot_key is not None
        assert fresh_vault.key_epoch is not None

    def test_second_initialize_is_rejected(self, vault):
        """已初始化的保险库再次 initialize 返回失败而非抛异常。

        守护不变量：initialize 检测到 master_salt/master_verify 已存在时经
        VaultAlreadyInitializedError 分支返回 (False, ...) 含「已经初始化」提示，
        避免覆盖现有凭据；UI/API 场景下不抛异常以防 traceback 延迟连接 GC。
        """
        ok, error = vault.initialize(_MASTER_PASSWORD)

        assert not ok
        assert "已经初始化" in error
        # 重复 initialize 走 VaultAlreadyInitializedError 分支返回失败，不调用
        # clear_vault_state，故 vault fixture initialize 后的已解锁态保持不变
        assert vault.is_unlocked is True


class TestUnlock:
    """unlock 阶段：凭据校验决定解锁成败。"""

    def test_unlock_with_correct_password_succeeds(self, fresh_vault):
        """正确主密码解锁成功，主密钥与快照密钥就位。

        守护不变量：unlock 经 MasterKeyManager.verify 校验通过后 set_master_key、
        校验 vault_meta_mac、load_snapshot_key、mark_unlocked，全程成功后返回 (True, "")。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        fresh_vault.lock()
        assert not fresh_vault.is_unlocked

        ok, error = fresh_vault.unlock(_MASTER_PASSWORD)

        assert ok, f"正确密码解锁应成功: {error}"
        assert fresh_vault.is_unlocked
        assert fresh_vault.key is not None
        assert fresh_vault.snapshot_key is not None

    def test_unlock_with_wrong_password_fails(self, fresh_vault):
        """错误主密码解锁失败，返回「主密码错误」且保险库保持锁定。

        守护不变量：verify 返回 None 时 unlock 立即返回 (False, "主密码错误")，
        不 set_master_key、不 mark_unlocked，密钥材料保持清零、is_unlocked 为 False。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        fresh_vault.lock()

        ok, error = fresh_vault.unlock("WrongPassword!999")

        assert not ok
        assert error == "主密码错误"
        assert not fresh_vault.is_unlocked
        # 锁定态访问 key 应 fail-fast 抛 VaultLockedError（MAINT-007）
        with pytest.raises(VaultLockedError):
            _ = fresh_vault.key


class TestLock:
    """lock 阶段：清零密钥材料并标记未解锁。"""

    def test_lock_clears_keys_and_marks_locked(self, fresh_vault):
        """lock 后主密钥与快照密钥被清零，is_unlocked 为 False，key 不可用。

        守护不变量：lock 经 clear_vault_state 清零 KeyManager 的主密钥/快照密钥/
        epoch 槽位并标记未解锁。is_unlocked 双条件（flag + key 就位）同时为假。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        assert fresh_vault.is_unlocked

        fresh_vault.lock()

        assert fresh_vault.is_unlocked is False
        # MAINT-007：锁定态访问 key/snapshot_key fail-fast 抛 VaultLockedError
        with pytest.raises(VaultLockedError):
            _ = fresh_vault.key
        with pytest.raises(VaultLockedError):
            _ = fresh_vault.snapshot_key
        # KeyManager 公开 property 观测内部 bytearray 槽位回落 None（secure_zero_buffer
        # 已原地清零；property 在槽位为 None 时才返回 None，见 test_lock_clear_chain 模块说明）
        assert fresh_vault._key_mgr.key is None
        assert fresh_vault._key_mgr.snapshot_key is None


class TestClose:
    """close 阶段：关闭数据库连接并清零密钥。"""

    def test_close_clears_keys_and_closes_db(self, fresh_vault):
        """close 后密钥清零、数据库连接关闭、保险库标记未解锁。

        守护不变量：close 经 lock() 清零密钥，再经 _db.close() 关闭连接。
        try/finally 保证 lock 异常时连接仍被关闭，避免文件句柄泄漏。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        assert fresh_vault.is_unlocked

        fresh_vault.close()

        assert fresh_vault.is_unlocked is False
        assert fresh_vault._key_mgr.key is None
        assert fresh_vault._key_mgr.snapshot_key is None
        # close 经 self._db.close() 关闭连接：is_open 回落 False
        assert fresh_vault._db.is_open is False


class TestChangeMasterPassword:
    """change_master_password 阶段：重加密全部数据并轮换凭据。"""

    def test_successful_change_rotates_credentials(self, fresh_vault):
        """正确旧密码+新密码改密成功，密钥轮换、旧密码失效、新密码可用。

        守护不变量：change_master_password 经 _re_encrypt_all 用新密钥重加密全部
        条目/分类/历史并写入新凭据，activate_keys 激活新密钥（内存 key 变化）。
        完成后锁定保险库，旧主密码无法解锁（凭据已轮换）、新主密码可解锁。
        """
        new_password = "NewMasterPassword!2026"
        fresh_vault.initialize(_MASTER_PASSWORD)
        key_before = fresh_vault.key

        ok, error = fresh_vault.change_master_password(_MASTER_PASSWORD, new_password)

        assert ok, f"改密应成功: {error}"
        # 改密需在解锁态进行（_re_encrypt_all 校验 is_unlocked），完成后仍解锁
        assert fresh_vault.is_unlocked
        # 新密钥已激活：内存主密钥字节变化
        assert fresh_vault.key != key_before

        # 锁定后凭据轮换生效：旧密码失败、新密码成功
        fresh_vault.lock()
        ok_old, _ = fresh_vault.unlock(_MASTER_PASSWORD)
        assert not ok_old, "旧主密码在改密后不应再能解锁"

        ok_new, err_new = fresh_vault.unlock(new_password)
        assert ok_new, f"新主密码解锁失败: {err_new}"
        assert fresh_vault.is_unlocked

    def test_wrong_old_password_is_rejected(self, fresh_vault):
        """错误旧密码改密被拒绝，凭据未变、原主密码仍可用。

        守护不变量：MasterKeyManager.change_password 校验旧密码失败返回 None，
        _change_master_password_locked 返回 (False, CHANGE_AUTH_FAILED_MESSAGE) 且
        不触达重加密，key_epoch 与凭据保持原状。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        original_epoch = fresh_vault.key_epoch

        ok, error = fresh_vault.change_master_password(
            "WrongOldPassword!999", "NewMasterPassword!2026"
        )

        assert not ok
        assert error == "当前主密码错误"
        # 凭据未变：epoch 未被推进
        assert fresh_vault.key_epoch == original_epoch
        # 原主密码仍可解锁，证实凭据未被破坏
        fresh_vault.lock()
        ok_orig, err_orig = fresh_vault.unlock(_MASTER_PASSWORD)
        assert ok_orig, f"旧密码错误改密被拒后，原主密码应仍可用: {err_orig}"

    def test_weak_new_password_raises_policy_error(self, fresh_vault):
        """新密码强度不足抛 MasterPasswordPolicyError，而非返回 (False, 文案)（ARCH-042）。

        (False, ...) 契约收窄为唯一语义「认证失败」——策略类可预期失败类型化走异常
        通道，改密对话框据返回值形态判定计入速率限制，不再比对文案字符串。
        """
        from src.exceptions import MasterPasswordPolicyError

        fresh_vault.initialize(_MASTER_PASSWORD)

        with pytest.raises(MasterPasswordPolicyError):
            fresh_vault.change_master_password(_MASTER_PASSWORD, "short")

    def test_same_password_raises_policy_error(self, fresh_vault):
        """新旧主密码相同抛 MasterPasswordPolicyError（含 Unicode 密码不抛 TypeError）。"""
        from src.exceptions import MasterPasswordPolicyError

        fresh_vault.initialize(_MASTER_PASSWORD)

        with pytest.raises(MasterPasswordPolicyError, match="相同"):
            fresh_vault.change_master_password(_MASTER_PASSWORD, _MASTER_PASSWORD)

    def test_system_error_message_survives_double_translation(self, fresh_vault, monkeypatch):
        """重加密系统错误经异常通道抛 VaultError，最终文案保留原始原因（ARCH-042）。

        对齐 unlock 的编码哲学：系统错误走 worker.error 异常通道，改密对话框按
        「非认证失败」处理（不计入速率限制），不惩罚遭遇故障的用户。包装用无固定
        映射的 VaultError 本体：worker error 通道（to_user_message）的二次翻译保留
        原文——此前包装为 VaultLockedError 时被 _FIXED_MESSAGES 归一为「保险库已
        锁定，请先解锁后重试。」罐头文案，磁盘满时误导用户（保险库明明已解锁）。
        """
        import errno

        from src.business.services.error_messages import to_user_message
        from src.exceptions import VaultError

        def _failing_re_encrypt(*args, **kwargs):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(
            "src.business.services.re_encryption.ReEncryptionService.re_encrypt_entries",
            _failing_re_encrypt,
        )
        fresh_vault.initialize(_MASTER_PASSWORD)

        with pytest.raises(VaultError) as exc_info:
            fresh_vault.change_master_password(_MASTER_PASSWORD, "NewMasterPassword!2026")
        # 系统错误不用 VaultLockedError 包装（其罐头映射正是二次翻译覆盖的根源）
        assert not isinstance(exc_info.value, VaultLockedError)
        # worker error 通道的二次翻译后，最终用户文案仍包含原始原因
        final_message = to_user_message(exc_info.value)
        assert "磁盘空间不足" in final_message
        assert "保险库已锁定" not in final_message


class TestKeyEpochRotation:
    """key_epoch 守卫：改密轮换 epoch，作为密钥版本不变量。"""

    def test_change_master_password_rotates_key_epoch(self, fresh_vault):
        """改密后 key_epoch 轮换为新值，内存与数据库一致。

        守护不变量：_re_encrypt_all 生成新 uuid 作为 key_epoch，事务内写入
        vault_meta（commit 落盘），事务后 activate_keys 同步内存。二者一致使
        enforce_key_epoch 写守卫能检测到旧会话的过期 epoch 并拒绝写入，杜绝
        旧密钥密文落到新 epoch 库的损坏窗口。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        epoch_before = fresh_vault.key_epoch
        assert epoch_before is not None

        ok, _ = fresh_vault.change_master_password(_MASTER_PASSWORD, "NewMasterPassword!2026")
        assert ok

        # 内存 epoch 已轮换为新值（不同于改密前）
        epoch_after = fresh_vault.key_epoch
        assert epoch_after is not None
        assert epoch_after != epoch_before
        # 内存 epoch 与数据库 epoch 一致：activate_keys 后库内已写入新 epoch
        db_epoch = fresh_vault.db.get_meta("key_epoch")
        assert db_epoch == epoch_after

    def test_initialize_session_lock_rejects_writes(self, fresh_vault):
        """首次建库会话锁定后写守卫仍生效（QL-052 守护）。

        守护不变量：initialize 经 activate_keys 与 mark_unlocked 对齐置位
        _ever_unlocked，故「首次建库→使用→锁定」的整个会话内（未重启、未经
        unlock）enforce_key_epoch 走「已锁定拒绝写入」分支抛 VaultLockedError，
        不会因漏置 _ever_unlocked 而使锁定写守卫整类失效。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        fresh_vault.lock()

        with pytest.raises(VaultLockedError):
            fresh_vault.enforce_key_epoch()


class TestUnlockFailureNoHalfState:
    """解锁失败不留下半激活状态。"""

    def test_wrong_password_unlock_then_correct_still_works(self, fresh_vault):
        """错误密码解锁失败后，紧接着正确密码仍能立即解锁。

        守护不变量：unlock 在凭据校验阶段（verify 返回 None）即返回失败，不会
        set_master_key/load_snapshot_key/mark_unlocked，故失败不污染状态——无需
        先 lock 复位，正确密码可立即解锁成功，不存在「半激活」中间态。
        """
        fresh_vault.initialize(_MASTER_PASSWORD)
        fresh_vault.lock()

        # 错误密码解锁失败，保险库保持锁定
        ok_wrong, _ = fresh_vault.unlock("WrongPassword!999")
        assert not ok_wrong
        assert not fresh_vault.is_unlocked

        # 紧接着正确密码解锁仍成功——失败未留下半激活状态
        ok_right, error = fresh_vault.unlock(_MASTER_PASSWORD)
        assert ok_right, f"错误密码失败后正确密码应仍能解锁: {error}"
        assert fresh_vault.is_unlocked
        assert fresh_vault.key is not None


def test_auth_failed_messages_contract():
    """认证失败文案常量按场景单源（ARCH-049）：登录/改密各自显式常量。

    原改密常量与 unlock 内联字面量双源，语义有别（登录/改密措辞不同）。UI 的
    空文案兜底默认值与各对话框测试断言均锚定这两个字面量——值变更属用户可见
    契约变化，须有意识地经本守护同步。
    """
    from src.business.managers.vault_lifecycle import (
        CHANGE_AUTH_FAILED_MESSAGE,
        LOGIN_AUTH_FAILED_MESSAGE,
    )

    assert LOGIN_AUTH_FAILED_MESSAGE == "主密码错误"
    assert CHANGE_AUTH_FAILED_MESSAGE == "当前主密码错误"
