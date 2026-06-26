"""保险库生命周期编排 — 初始化、解锁、锁定、改密、关闭的状态机。

从 VaultManager 拆出的生命周期流程：跨密钥派生（Argon2id）、元数据持久化
（:class:`~src.business.services.vault_meta_store.VaultMetaStore`）、完整性校验
（vault_meta_mac）、全量重加密（ReEncryptionService）、snapshot_key 轮换与备份清理。
VaultManager 收窄为密钥/db/写守卫核心，仅保留这些流程所需的原子操作
（activate_keys / clear_vault_state / load_snapshot_key 等）。

VaultManager 的 ``initialize`` / ``unlock`` / ``lock`` / ``change_master_password`` /
``close`` 经薄委托调用本类，使调用方（app/login/dialog/test）无需感知 orchestrator。
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import os
import time
import uuid
from pathlib import Path

from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import (
    DEFAULT_KDF_PARAMS,
    KDF_NAME,
    KEY_SIZE,
    KdfParams,
    MasterKeyManager,
)
from ...crypto.password_generator import PasswordGenerator
from ...database.db_manager import DatabaseManager
from ...exceptions import (
    CipherBoxError,
    VaultAlreadyInitializedError,
    VaultIntegrityError,
    VaultLockedError,
)
from ...utils.memory import secure_zero_buffer
from ..services.crypto_utils import encrypt_plaintext_category_names
from ..services.metadata_signer import MetadataSigner
from ..services.re_encryption import ReEncryptionService
from ..services.vault_meta_store import VaultMetaStore
from .vault_manager import VaultManager

logger = logging.getLogger(__name__)

# 改密时旧主密码验证失败的错误消息。供 change_master_dialog 判定是否计入速率
# 限制——以常量而非硬编码字面量比较，使文案变更不需同步改 dialog（单一真相源）。
AUTH_FAILED_MESSAGE = '当前主密码错误'


def _friendly_error(exc: Exception, default: str) -> str:
    """将生命周期流程的底层异常映射为用户可读的中文提示。

    CipherBoxError 已由各流程的 ``except CipherBoxError: raise`` 分支向上传播
    （带领域语义），此处仅兜底未预期的底层异常，避免把英文 ``str(exc)`` 透传到
    UI（如 ``KeyError('master_salt')`` 会显示为 "'master_salt'"）。

    - ``ValueError`` 常携带校验函数的中文文案（主密码强度、参数非法等），原样保留；
    - ``binascii.Error``（base64 解码失败）提示数据格式错误；
    - ``KeyError``/``TypeError``/其他异常给通用默认提示。
    """
    if isinstance(exc, ValueError):
        msg = str(exc).strip()
        return msg or default
    if isinstance(exc, binascii.Error):
        return '保险库数据格式错误，可能已损坏'
    return default


# unlock 单次批量读取的 vault_meta 键，避免多次独立 DB 锁获取。
_VAULT_META_KEYS = [
    'master_salt', 'master_verify', 'master_kdf_time_cost',
    'master_kdf_memory_cost', 'master_kdf_parallelism',
    'master_kdf', 'ciphertext_format', 'key_epoch',
    'snapshot_key_enc', 'vault_meta_mac',
]


class VaultLifecycleOrchestrator:
    """保险库生命周期编排：初始化/解锁/锁定/改密/关闭。

    持有 :class:`VaultManager`（密钥/db/写守卫核心）与重加密服务、元数据存储，编排
    跨这些组件的完整生命周期流程。事务边界、密钥清零、snapshot_key 轮换等安全
    契约在此维护。
    """

    def __init__(
        self,
        vault: VaultManager,
        db: DatabaseManager,
        signer: MetadataSigner,
    ) -> None:
        self._vault = vault
        self._db = db
        self._signer = signer
        # 重加密服务仅负责纯加解密计算，事务与密钥状态由本类管理
        self._rotator = ReEncryptionService(db, signer)
        self._meta_store = VaultMetaStore()

    @staticmethod
    def _read_kdf_params(meta: dict[str, str | None]) -> KdfParams:
        """从 vault_meta 解析 Argon2id 参数，缺失或非法时抛 VaultLockedError。"""
        try:
            return KdfParams(
                int(meta['master_kdf_time_cost']),  # type: ignore[arg-type]
                int(meta['master_kdf_memory_cost']),  # type: ignore[arg-type]
                int(meta['master_kdf_parallelism']),  # type: ignore[arg-type]
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultLockedError('保险库缺少密钥派生参数') from exc

    def initialize(
        self,
        master_password: str,
        params: KdfParams | None = None,
    ) -> tuple[bool, str]:
        """首次初始化保险库，设置主密码。

        params 为 None 时用模块级 DEFAULT_KDF_PARAMS（可被测试 monkeypatch 为弱参数
        加速，生产保持 OWASP 级强度）。显式传入的参数（须过 validate_params）优先。
        """
        if params is None:
            params = DEFAULT_KDF_PARAMS
        try:
            valid, error = PasswordGenerator.validate_master_password(master_password)
            if not valid:
                raise ValueError(error)
            self._vault.ensure_db_open()
            if self._db.get_meta('master_salt') or self._db.get_meta('master_verify'):
                raise VaultAlreadyInitializedError('保险库已经初始化，不能重复设置主密码')
            salt, verify_token, derived_key = MasterKeyManager.create(master_password, params)
            snapshot_key = os.urandom(KEY_SIZE)
            key_epoch = uuid.uuid4().hex
            with self._db.transaction():
                self._meta_store.write(
                    self._db,
                    salt=salt, verify_token=verify_token, snapshot_key=snapshot_key,
                    key=derived_key, key_epoch=key_epoch, params=params,
                )
            self._vault.activate_keys(derived_key, snapshot_key, key_epoch)
            encrypt_plaintext_category_names(self._db, derived_key)
            return True, ''
        except VaultAlreadyInitializedError as exc:
            return False, str(exc)
        except CipherBoxError:
            raise
        except Exception as exc:
            logger.warning("保险库初始化失败", exc_info=True)
            # 强制清除可能已激活的密钥：activate_keys 已激活密钥并置 is_unlocked=True。
            # 不清除会使 initialize 报失败但保险库处于半解锁状态（持密钥），状态不一致。
            self._vault.clear_vault_state()
            return False, _friendly_error(exc, '保险库初始化失败')

    def unlock(self, master_password: str) -> tuple[bool, str]:
        """使用主密码解锁保险库。"""
        # 预声明 key：verify 未执行（凭据校验前异常）时，except 仍需引用它清零。
        key: bytearray | None = None
        try:
            t0 = time.monotonic()
            self._vault.ensure_db_open()

            # 单次查询获取全部元数据，避免多次独立 DB 锁获取
            meta = self._db.get_meta_batch(_VAULT_META_KEYS)

            salt_b64 = meta['master_salt']
            verify_token = meta['master_verify']

            if not salt_b64 or not verify_token:
                return False, '保险库凭据不完整'

            salt = base64.b64decode(salt_b64)
            params = self._read_kdf_params(meta)
            key = MasterKeyManager.verify(master_password, salt, verify_token, params)

            if key is None:
                return False, '主密码错误'

            # 先完成全部元数据格式校验，再持有密钥，遵循最小暴露原则：格式校验失败时
            # key 仅作局部变量，不写入 KeyManager 也不触发加密缓存。
            if meta['master_kdf'] != KDF_NAME:
                raise VaultLockedError('不支持的主密钥派生格式')
            if meta['ciphertext_format'] != EncryptionEngine.FORMAT_ID:
                raise VaultLockedError('不支持的密文格式')
            key_epoch = meta['key_epoch']
            if not key_epoch:
                raise VaultLockedError('保险库缺少当前格式的密钥版本')
            # snapshot_key_enc 用主密钥加密，load_snapshot_key 须在主密钥设置后调用，
            # 故无法进一步前置；其失败由下方 except 经 lock() 清零兜底。
            self._vault.set_master_key(key)
            self._vault.set_epoch(key_epoch)
            self._vault.set_domain_key(key)
            # vault_meta 完整性校验（强制）：verify 通过已保证 KDF 参数未被篡改（否则
            # 派生密钥错致 verify 失败），此处统一校验其余安全字段。mac 缺失亦拒绝——
            # initialize、改密、恢复均写入 mac，缺失意味着签名被删除篡改。mac 校验失败
            # 经 except CipherBoxError 清零 key + lock。
            stored_meta_mac = meta.get('vault_meta_mac')
            if not stored_meta_mac:
                raise VaultIntegrityError('保险库元数据完整性签名缺失')
            expected_meta_mac = MetadataSigner.compute_vault_meta_mac(meta, key)
            if not hmac.compare_digest(stored_meta_mac, expected_meta_mac):
                raise VaultIntegrityError('保险库元数据完整性校验失败，可能已被篡改')
            self._vault.load_snapshot_key(meta.get('snapshot_key_enc'))
            # 全部密钥材料就位后再标记解锁，缩小「主密钥已写入但 snapshot_key 尚未
            # 加载」的部分就位窗口：此窗口内 is_unlocked 为 False，并发读取者不会得到
            # 「已解锁但 snapshot_key 缺失」的中间态。
            self._vault.mark_unlocked()
            logger.info("解锁完成 (%.1fms)", (time.monotonic() - t0) * 1000)
            return True, ''
        except CipherBoxError:
            # key 可能已写入 KeyManager（load_snapshot_key 在 set_master_key 后调用，
            # snapshot_key 损坏时 key 已就位）。secure_zero_buffer 清零该 bytearray，
            # 随后的 lock() 统一清零全部密钥材料。key 已预声明，verify 未执行时为 None。
            if key is not None:
                secure_zero_buffer(key)
            self.lock()
            raise
        except Exception as exc:
            self.lock()
            logger.warning("解锁失败", exc_info=True)
            return False, _friendly_error(exc, '保险库无法解锁')

    def lock(self) -> None:
        """锁定保险库，清除内存中的密钥材料。

        安全注意：Python bytes 不可变，无法可靠原地清零。本方法经 secure_zero_buffer
        尽力清零密钥材料的可变副本以缩短驻留，原始 bytes 仍依赖 GC 回收（CPython 固限）。
        """
        # 主动通知进行中的改密/重加密取消，缩短 lock 获取写锁的阻塞窗口：改密循环检测
        # cancel_event 后抛异常回滚，尽快释放写锁，避免 UI 长时间冻结。
        self._vault.request_cancel()
        try:
            # 持 vault 写锁串行化与 create_backup：确保清零密钥前进行中的备份已完成，
            # 避免备份用密钥副本在 lock 后继续解密。回调在锁外执行，避免回调获取锁死锁。
            with self._vault.vault_write_lock():
                self._vault.clear_vault_state()
        finally:
            # 复位取消事件，避免残留影响后续改密
            self._vault.cancel_event.clear()
        # gc.collect() 已在 clear_vault_state 内执行。随后通知依赖方清除缓存。
        self._vault.invoke_lock_callbacks()

    def close(self) -> None:
        """关闭保险库。

        设置取消事件通知正在进行的密钥轮换等长时间操作提前终止，然后锁定保险库并
        关闭数据库连接。用 try/finally 保证 ``lock()`` 异常时数据库连接仍被关闭、取消
        事件仍被复位，避免连接泄漏与残留置位。
        """
        self._vault.request_cancel()
        try:
            self.lock()
        finally:
            try:
                self._db.close()
            except Exception:
                logger.warning("关闭数据库连接失败", exc_info=True)
            self._vault.cancel_event.clear()

    def change_master_password(
        self, old_password: str, new_password: str,
    ) -> tuple[bool, str]:
        """修改主密码。方法获取可重入写锁，与 _re_encrypt_all 的写操作串行化。"""
        with self._vault.vault_write_lock():
            return self._change_master_password_locked(old_password, new_password)

    def _change_master_password_locked(
        self, old_password: str, new_password: str,
    ) -> tuple[bool, str]:
        try:
            valid, error = PasswordGenerator.validate_master_password(new_password)
            if not valid:
                return False, error
            # 常量时间比较新旧主密码，避免明文密码比较的时序侧信道（短路比较会随首个
            # 不同字符提前返回，泄露前缀信息）。encode('utf-8')：主密码可含 Unicode（如
            # 中文），hmac.compare_digest 对 str 仅接受 ASCII，非 ASCII 直接比较会抛
            # TypeError。
            if hmac.compare_digest(
                old_password.encode('utf-8'), new_password.encode('utf-8')
            ):
                return False, '新密码不能与当前主密码相同'
            meta = self._db.get_meta_batch([
                'master_salt', 'master_verify', 'master_kdf_time_cost',
                'master_kdf_memory_cost', 'master_kdf_parallelism',
            ])
            salt_b64 = meta['master_salt']
            verify_token = meta['master_verify']
            if not salt_b64 or not verify_token:
                return False, '保险库凭据不完整'

            old_salt = base64.b64decode(salt_b64)
            old_params = self._read_kdf_params(meta)
            result = MasterKeyManager.change_password(
                old_password, new_password, old_salt, verify_token, old_params,
                DEFAULT_KDF_PARAMS,
            )
            if result is None:
                return False, AUTH_FAILED_MESSAGE

            new_salt, new_verify_token, new_key = result

            try:
                # 复用 MasterKeyManager.create 已派生的 new_key，省一次 Argon2id 派生
                failed_purges = self._re_encrypt_all(
                    new_key, new_salt, new_verify_token, new_params=DEFAULT_KDF_PARAMS,
                )
            except BaseException:
                # 重加密失败：new_key 未被 activate_keys 持有，原地清零收缩驻留，
                # 避免 Argon2id 派生的新密钥在异常栈帧残留、依赖 GC 回收。
                secure_zero_buffer(new_key)
                raise
            if failed_purges:
                # 改密成功但旧明文快照未能清理：明确反馈用户，避免误以为泄漏面已收缩
                return True, (
                    f'主密码已修改，但 {len(failed_purges)} 个历史明文快照未能删除'
                    '（可能被占用），建议在备份对话框手动清理以收缩泄漏面。'
                )
            return True, ''
        except CipherBoxError:
            raise  # 所有 CipherBox 自定义异常向上传播
        except Exception as exc:
            logger.warning("修改主密码失败", exc_info=True)
            return False, _friendly_error(exc, '修改主密码失败')

    def _re_encrypt_all(
        self,
        new_key: bytes | bytearray,
        new_salt: bytes,
        new_verify_token: str,
        new_params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> list[Path]:
        """使用新密钥重新加密所有条目（含已删除），受事务保护。

        调用方须已持有 vault 写锁（change_master_password 经 vault_write_lock 持有）。
        """
        if self._vault.key is None:
            raise VaultLockedError('保险库未解锁，无法执行重加密')

        # 重置取消事件，避免上一次 reject/close 的残留导致本次改密被误取消
        self._vault.cancel_event.clear()
        old_key = self._vault.key
        new_epoch = uuid.uuid4().hex
        # snapshot_key 随主密钥一同轮换：旧 snapshot_key 加密的快照与恢复点随后清理，
        # 彻底收缩历史明文泄漏面，使主密码一旦被攻破也无法解密历史快照。
        # bytearray 持有以便 finally 原地清零：activate_keys 总复制使 KeyManager 持独立
        # 副本，局部副本在 finally 清零不破坏激活态，收缩崩溃 dump 读取新生成 key 的窗口。
        new_snapshot_key = bytearray(os.urandom(KEY_SIZE))

        try:
            t0 = time.monotonic()
            # 通过 transaction() 持有 db_lock 并包裹真实事务：数据读取在事务内完成，
            # 防 TOCTOU 竞态；db_lock 持有期间阻止其他线程在此连接上插队写入导致跨
            # 线程部分回滚。异常时由 transaction() 自动回滚所有数据库变更。
            with self._db.transaction():
                self._rotator.re_encrypt_categories(old_key, new_key)
                self._rotator.re_encrypt_entries(
                    old_key, new_key, cancel_event=self._vault.cancel_event,
                )
                self._rotator.re_encrypt_history(
                    old_key, new_key, cancel_event=self._vault.cancel_event,
                )
                self._meta_store.update(
                    self._db, new_key, new_salt, new_verify_token, new_epoch,
                    snapshot_key=new_snapshot_key, params=new_params,
                )

            # 事务已提交。密钥赋值放在 commit 之后，避免后台线程在 commit 前读到新密钥、
            # 解密尚未提交的旧数据，造成解密窗口问题。若提交失败 transaction() 已回滚，
            # 下方 except 会清除密钥保证一致性。
            self._vault.activate_keys(new_key, new_snapshot_key, new_epoch)
            EncryptionEngine.clear_cache()  # 旧密钥 cipher 已失效，确保后续用新密钥
            logger.info("重加密完成 (%.1fms)", (time.monotonic() - t0) * 1000)
            # 清理旧 snapshot_key 加密的全部快照与恢复点，收缩泄漏面。
            failed_purges = self._vault.purge_snapshot_backups()
            if failed_purges:
                logger.warning(
                    "改密后未能删除 %d 个旧快照/恢复点（可能被占用或目录只读），"
                    "建议手动清理以收缩历史明文泄漏面：%s",
                    len(failed_purges),
                    ', '.join(str(p) for p in failed_purges),
                )
            # WAL 截断在事务提交之后执行；数据已落盘，截断失败非致命，单独捕获避免
            # 其异常冒泡导致 UI 显示模糊错误，而事务其实已成功。
            try:
                self._db.secure_checkpoint()
            except Exception:
                logger.warning("改密后 WAL 安全截断失败（非致命）", exc_info=True)

            return failed_purges

        except Exception:
            # transaction() 上下文已回滚所有数据库变更。
            # 即使 lock() 异常也必须确保密钥被清除，防止内存状态不一致。
            try:
                self.lock()
            except Exception:
                logger.error("改密后锁定失败，强制清除状态", exc_info=True)
                self._vault.clear_vault_state()
            logger.error("重加密失败: 回滚所有变更", exc_info=True)
            raise
        finally:
            # 清理取消事件，避免残留影响后续改密
            self._vault.cancel_event.clear()
            # 新 snapshot_key 局部副本（bytearray）在 activate_keys 总复制后立即原地
            # 清零——KeyManager 已持独立副本，清零局部副本不破坏激活态。
            secure_zero_buffer(new_snapshot_key)
            # 旧主密钥副本（bytes，不可原地清零）在新密钥生效后立即释放引用，缩短旧
            # 密钥在内存/swap 的驻留。CPython 下 bytes 不可变，del 后仍依赖 GC 回收。
            del old_key
