"""lock()/close() 清零链端到端守护（真实保险库，非 mock）。

覆盖四条核心安全契约：

1. ``lock()`` 清零 KeyManager 的主密钥与快照密钥并标记未解锁；
2. ``clear_vault_state`` 清空 ``EncryptionEngine._cipher_cache``（AESGCM 实例缓存，
   其 C 层持有密钥拷贝）；
3. ``close()`` 安全：密钥清零、数据库连接关闭，且**双 close 幂等不抛异常**；
4. ``lock()`` 后再 unlock 仍可正常工作（清零不破坏后续解锁能力）。

经 ``vault._key_mgr.key`` / ``.snapshot_key``（KeyManager 公开只读 property）观测
内部 bytearray 槽位是否回落 None——property 仅在内部槽位为 None 时返回 None，
「清零了 bytearray 但未释放引用」的回归会返回全零 bytes（非 None）被本测试捕获。
``vault._key_mgr`` 单层私有访问保留：密钥清零是 KeyManager 的白盒安全属性，
VaultManager 无等价公开观测面（is_unlocked 无法区分标志清零与密钥清零）。
"""

from src.crypto.encryption import _cipher_cache
from src.crypto.master_key import KdfParams
from tests.helpers import make_vault

# 弱化但合法的 Argon2id 参数（过 validate_params 安全下限 time>=2 / mem>=16MB /
# par>=1），加速测试密钥派生。与 conftest._TEST_KDF_PARAMS 同值；生产路径仍用
# DEFAULT_KDF_PARAMS（time=3 / 64MB / parallelism=4）。
_WEAK_KDF = KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)
_MASTER_PASSWORD = "TestPassword123!"


class TestLockClearsKeys:
    """1. lock() 清零主密钥与快照密钥并标记未解锁。"""

    def test_lock_clears_keymanager_and_unlock_state(self, vault_config):
        vault = make_vault(vault_config)
        try:
            vault.initialize(_MASTER_PASSWORD, params=_WEAK_KDF)
            ok, _ = vault.unlock(_MASTER_PASSWORD)
            assert ok
            # 前置条件：解锁后密钥材料就位
            assert vault.is_unlocked
            assert vault._key_mgr.key is not None
            assert vault._key_mgr.snapshot_key is not None

            vault.lock()

            # is_unlocked 同时要求 _is_unlocked 标志与主密钥就位，二者均被清后为 False
            assert vault.is_unlocked is False
            # KeyManager 内部 bytearray 槽位置 None：secure_zero_buffer 已原地清零
            assert vault._key_mgr.key is None
            assert vault._key_mgr.snapshot_key is None
        finally:
            vault.close()


class TestClearVaultStateEmptiesCipherCache:
    """2. clear_vault_state 清空 EncryptionEngine 的 AESGCM 实例缓存。"""

    def test_clear_vault_state_empties_cipher_cache(self, vault_config):
        vault = make_vault(vault_config)
        try:
            vault.initialize(_MASTER_PASSWORD, params=_WEAK_KDF)
            ok, _ = vault.unlock(_MASTER_PASSWORD)
            assert ok
            # 解锁期间 load_snapshot_key 解密 snapshot_key_enc 填充了 AESGCM 实例缓存
            # （AESGCM 构造时在 OpenSSL C 层复制密钥，clear_cache 收缩该攻击面）
            assert len(_cipher_cache) > 0

            vault.clear_vault_state()

            assert len(_cipher_cache) == 0
        finally:
            vault.close()


class TestClearVaultStateRunsGcSynchronously:
    """5. clear_vault_state 在调用线程同步执行 GC（PERF-084 已撤销）。

    gc.collect 可能 finalize 引用循环中的无父 QObject，在非 GUI 线程删除 C++
    对象会破坏 Qt 线程亲和（「Timers cannot be stopped from another thread」
    警告或间歇崩溃）。PERF-084 曾把 GC 移入 threading.Timer 后台线程引入该风险，
    已撤销：清零与 GC 在调用线程（lock 的调用方为 GUI 线程）同步完成；锁定低频
    且窗口已隐藏，同步段的大堆遍历卡顿可接受。
    """

    def test_clear_vault_state_runs_gc_in_calling_thread(self, vault_config, monkeypatch):
        """清零同步段内于调用线程执行 GC；公开 force_gc 为同一立即执行入口。

        以实例级 spy 观察 force_gc（不 patch 全局 gc.collect，避免干扰 pytest
        内部的 GC 行为）。
        """
        import threading

        vault = make_vault(vault_config)
        try:
            vault.initialize(_MASTER_PASSWORD, params=_WEAK_KDF)
            ok, _ = vault.unlock(_MASTER_PASSWORD)
            assert ok

            gc_threads: list[int] = []
            real_force_gc = vault.force_gc
            monkeypatch.setattr(
                vault,
                "force_gc",
                lambda: (gc_threads.append(threading.get_ident()), real_force_gc()),
            )

            vault.clear_vault_state()

            # 清零与 GC 均已同步完成，且 GC 与调用方同线程（Qt 线程亲和）
            assert vault._key_mgr.key is None
            assert gc_threads == [threading.get_ident()]
        finally:
            try:
                vault.close()
            except Exception:
                pass


class TestCloseSafety:
    """3. close() 安全：密钥清零、数据库连接关闭，且双 close 幂等。"""

    def test_close_clears_keys_and_closes_db(self, vault_config):
        vault = make_vault(vault_config)
        try:
            vault.initialize(_MASTER_PASSWORD, params=_WEAK_KDF)
            ok, _ = vault.unlock(_MASTER_PASSWORD)
            assert ok

            vault.close()

            assert vault.is_unlocked is False
            assert vault._key_mgr.key is None
            assert vault._key_mgr.snapshot_key is None
            # close 经 self._db.close() 关闭连接：_conn 回落 None
            assert vault._db.is_open is False
        finally:
            # 防御性 close：保证 Windows 临时目录清理不受文件锁阻碍（幂等，不抛异常）
            try:
                vault.close()
            except Exception:
                pass

    def test_double_close_is_idempotent(self, vault_config):
        vault = make_vault(vault_config)
        try:
            vault.initialize(_MASTER_PASSWORD, params=_WEAK_KDF)
            vault.close()
            # 第二次 close 不得抛异常：close 经 lock()→clear_vault_state（已清零则空转）
            # 与 _db.close()（_conn 已 None 则跳过）均为幂等
            vault.close()
            # 终态值比对：双 close 后保持锁定且连接已关
            assert vault.is_unlocked is False
            assert vault._key_mgr.key is None
        finally:
            try:
                vault.close()
            except Exception:
                pass


class TestUnlockAfterLock:
    """4. lock() 后再 unlock 仍可正常工作（清零不破坏后续解锁能力）。"""

    def test_unlock_works_after_lock(self, vault_config):
        vault = make_vault(vault_config)
        try:
            vault.initialize(_MASTER_PASSWORD, params=_WEAK_KDF)
            ok, _ = vault.unlock(_MASTER_PASSWORD)
            assert ok

            vault.lock()
            assert vault.is_unlocked is False

            # 清零仅清除内存密钥材料，vault_meta（盐/验证令牌/snapshot_key_enc）仍完好，
            # 凭主密码可重新派生密钥并解锁
            ok2, msg = vault.unlock(_MASTER_PASSWORD)
            assert ok2, msg
            assert vault.is_unlocked
            assert vault._key_mgr.key is not None
            assert vault._key_mgr.snapshot_key is not None
        finally:
            vault.close()
