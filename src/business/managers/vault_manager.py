"""保险库安全边界核心 — 密钥持有、数据库连接、写守卫与原子状态操作。

生命周期流程（初始化/解锁/锁定/改密/关闭）拆至
:class:`VaultLifecycleOrchestrator`；本类聚焦密钥清零、写守卫（拒绝锁定态或
旧 epoch 会话写入）与供生命周期编排调用的原子状态操作。
"""

from __future__ import annotations

import gc
import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from ...config import ConfigManager
from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import KdfParams
from ...database.db_manager import DatabaseManager
from ...database.types import VaultDataStore
from ...exceptions import (
    DatabaseError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)
from ..services.key_manager import KeyManager
from ..services.metadata_signer import MetadataSigner
from ..services.vault_meta_store import VaultMetaStore

logger = logging.getLogger(__name__)

# 改密时旧主密码验证失败的错误消息（跨层契约常量）。供 change_master_dialog 判定
# 是否计入速率限制——以常量而非硬编码字面量比较，使文案变更不需同步改 dialog。
# 定义于本 facade 使 UI 经 VaultManager 取用，不穿透到 vault_lifecycle 编排器模块
# （LifecyclePort 抽象保持 vault ↔ lifecycle 解耦）。
AUTH_FAILED_MESSAGE = "当前主密码错误"


class LifecyclePort(Protocol):
    """保险库生命周期编排协议（初始化/解锁/锁定/改密/关闭）。

    VaultManager 经此协议委托生命周期流程，不再 ``TYPE_CHECKING`` 依赖具体
    :class:`VaultLifecycleOrchestrator` 类型（镜像 :class:`VaultDataStore` 切片模式）：
    消除 vault → lifecycle 的类型依赖，使 vault 仅持有协议接口、编排器为运行时注入的
    实现方，便于测试替身与解耦。``VaultLifecycleOrchestrator`` 结构化满足本协议。
    """

    def initialize(
        self,
        master_password: str,
        params: KdfParams | None = None,
    ) -> tuple[bool, str]: ...

    def unlock(self, master_password: str) -> tuple[bool, str]: ...

    def lock(self) -> None: ...

    def close(self) -> None: ...

    def change_master_password(
        self,
        old_password: str,
        new_password: str,
    ) -> tuple[bool, str]: ...


class VaultManager:
    """保险库安全边界核心：密钥、数据库、写守卫与原子状态操作。

    写守卫是本类的核心安全不变量：所有数据库写入经 :meth:`enforce_key_epoch`
    拒绝锁定态或主密钥已轮换（改密/恢复）的旧会话写入，杜绝旧密钥密文落到新 epoch
    库造成解密失败的损坏窗口。

    完整生命周期流程由 :class:`VaultLifecycleOrchestrator` 编排，本类仅提供其
    所需的原子操作（激活密钥、清零状态、加载 snapshot_key 等）。
    """

    def __init__(self, config: ConfigManager, db: DatabaseManager, signer: MetadataSigner):
        # db 与 signer 由组合根（composition）经 DatabaseBootstrap 创建并注入。
        self._config = config
        self._db = db
        self._signer = signer
        # write_guard 依赖本类密钥状态（enforce_key_epoch 比对 epoch），此处注入安全：
        # 未解锁时 key_epoch 为 None，enforce_key_epoch 直接返回不触发比对。
        self._db.set_write_guard(self.enforce_key_epoch)

        self._is_unlocked = False
        self._ever_unlocked = False  # 曾解锁过（解锁后不随 lock 重置，供 enforce_key_epoch 区分「从未激活」与「已锁定」）
        self._key_mgr = KeyManager()
        self._lock = threading.RLock()  # 串行化改密/重加密/备份/恢复等接触全量明文的长操作
        self._db_initialized = False  # 缓存标志，避免 ensure_db_open 重复打开数据库
        self._on_lock_callbacks: list[Callable[[], None]] = []
        # 密钥版本轮换（备份恢复后）回调列表，与锁定回调分离（ARCH-003）：两类事件
        # 语义不同，拆为独立通道使注册方明确订阅意图。
        self._on_epoch_rotated_callbacks: list[Callable[[], None]] = []
        self._cancel_event = threading.Event()  # close()/lock() 时设置，通知长操作提前终止
        # 生命周期编排器，经 attach_lifecycle 由组合根注入（创建 orchestrator 后立即
        # 调用）。以 LifecyclePort 协议持有，不依赖具体编排器类型。生命周期方法委托给它。
        self._lifecycle: LifecyclePort | None = None

    # ---- 密钥材料（KeyManager 代理）----
    # 密钥材料由 KeyManager 集中持有与清零，此处经 property 代理保持内部访问接口。
    @property
    def _key(self) -> bytes | None:
        return self._key_mgr.key

    @_key.setter
    def _key(self, value: bytes | bytearray) -> None:
        self._key_mgr.update_key(value)

    @property
    def _snapshot_key(self) -> bytes | None:
        return self._key_mgr.snapshot_key

    @_snapshot_key.setter
    def _snapshot_key(self, value: bytes | bytearray) -> None:
        self._key_mgr.update_snapshot_key(value)

    @property
    def _key_epoch(self) -> str | None:
        return self._key_mgr.key_epoch

    @_key_epoch.setter
    def _key_epoch(self, value: str) -> None:
        self._key_mgr.update_epoch(value)

    # ---- 锁定 / 密钥轮换回调（ARCH-003 拆分为两个独立通道）----
    def register_on_lock(self, callback: Callable[[], None]) -> None:
        """注册锁定时自动调用的回调，用于清除缓存等。

        仅在 :meth:`VaultLifecycleOrchestrator.lock` 锁定时触发（经
        :meth:`invoke_lock_callbacks`）。需在备份恢复后密钥版本轮换时也失效缓存的
        注册方应一并注册到 :meth:`register_on_epoch_rotated`。
        """
        self._on_lock_callbacks.append(callback)

    def invoke_lock_callbacks(self) -> None:
        """触发全部锁定回调（清缓存等）。

        调用点为 lock 清零密钥后。回调异常不中断后续回调，仅记 WARNING——单个回调
        失败不应阻止其余缓存清理，但安全相关失效（如锁定时明文缓存未清）应在生产日志
        可见（QL-014）。
        """
        self._invoke_callbacks(self._on_lock_callbacks, "锁定回调")

    def register_on_epoch_rotated(self, callback: Callable[[], None]) -> None:
        """注册密钥版本轮换（备份恢复后）时自动调用的回调，用于失效缓存等。

        仅在 :meth:`update_key_epoch` 备份恢复后密钥版本轮换时触发（保险库仍解锁，
        但数据整体替换需失效按 crypto_id 索引的明文缓存，防命中旧明文）。与锁定语义
        分离，使注册方明确订阅意图。
        """
        self._on_epoch_rotated_callbacks.append(callback)

    def invoke_epoch_rotated_callbacks(self) -> None:
        """触发全部密钥版本轮换回调（失效恢复后过期的明文/派生缓存）。"""
        self._invoke_callbacks(self._on_epoch_rotated_callbacks, "密钥轮换回调")

    @staticmethod
    def _invoke_callbacks(callbacks: list[Callable[[], None]], label: str) -> None:
        """逐个触发回调：单个回调异常不中断后续，记 WARNING 保留可审计性（QL-014）。"""
        for cb in callbacks:
            try:
                cb()
            except Exception:
                logger.warning("%s执行失败", label, exc_info=True)

    # ---- 数据库与配置 ----
    @property
    def db(self) -> VaultDataStore:
        """对外暴露收窄为 VaultDataStore 协议视图（不含 set_write_guard 等装配 setter）。

        业务 manager 经此 property 拿到协议视图，收窄暴露面。完整 DatabaseManager 仅
        作为 ``__init__`` 注入与 orchestrator 构造参数在内部流转，不再经 property 对外暴露。
        """
        return self._db

    @property
    def data_dir(self) -> Path:
        """保险库数据目录（vault.db、backups/、logs/ 等所在路径）。"""
        return self._config.data_dir

    @property
    def config(self) -> ConfigManager:
        """配置管理器，供备份清理等纯函数取 data_dir / backup_directory。

        ConfigManager 不持有主密钥/加密密钥（仅配置项与 config.json 完整性签名密钥），
        暴露给业务层 manager 调用备份清理纯函数不扩大密钥攻击面。备份域逻辑已下沉至
        :mod:`src.business.services.backup.purge`，本类不再承担该职责。
        """
        return self._config

    @property
    def is_initialized(self) -> bool:
        """纯查询：保险库是否已设置主密码（检查 master_salt）。无打开/关闭副作用。

        命令-查询分离（ARCH-004）：本 property 仅查询，不打开/关闭数据库。db 文件不
        存在时返回 False（无需打开）；存在时调用方须先 :meth:`ensure_db_open` 再查询，
        schema 损坏（``SchemaError``）或完整性失败（``VaultIntegrityError``）由
        :meth:`ensure_db_open` 的 schema 校验向上传播——不静默为 False，避免 UI 误判
        为未初始化后在损坏库上重新初始化导致数据覆盖。
        """
        if not self._config.db_path.exists():
            return False
        salt_b64 = self._db.get_meta("master_salt")
        return salt_b64 is not None

    def ensure_db_open(self) -> None:
        """确保数据库已打开且表已初始化（命令-查询分离中的「命令」侧，ARCH-004）。

        幂等方法，已打开则跳过。schema 损坏或完整性失败时抛 ``SchemaError``，由调用方
        决策（如登录流程据此提示用户而非覆盖损坏库）。``is_initialized`` 等纯查询须由
        调用方先经此方法打开数据库后再访问。
        """
        if self._db_initialized:
            return
        if not self._db.is_open and not self._db.open():
            raise DatabaseError("数据库无法打开")
        self._db.init_tables()
        self._db_initialized = True

    # ---- 解锁状态查询 ----
    @property
    def is_unlocked(self) -> bool:
        """保险库是否已解锁（双条件：解锁标志 + 主密钥实际就位）。

        flag 与 key 分离校验是防御性设计：lock() 先清零 key 再置 flag 为 False，
        并发读者在中间窗口不会因仅 flag=True 而误判为已解锁、用过期密钥读写。
        """
        return self._is_unlocked and self._key is not None

    @property
    def key(self) -> bytes:
        """当前主密钥；未解锁抛 VaultLockedError（与 snapshot_key 对称，MAINT-007）。

        加解密统一经 ``require_vault_key`` 守卫；本 property 补 fail-fast 使直接读取
        （如改密路径）也对称地抛而非返回 None 静默传播。
        """
        if not self.is_unlocked or self._key is None:
            raise VaultLockedError("保险库未解锁")
        return self._key

    @property
    def snapshot_key(self) -> bytes:
        """自动快照密钥；未解锁抛 VaultLockedError（与 key 对称，MAINT-007）。"""
        if not self.is_unlocked or self._snapshot_key is None:
            raise VaultLockedError("自动快照密钥不可用")
        return self._snapshot_key

    @property
    def key_epoch(self) -> str | None:
        """当前主密钥版本，改密时自动轮换，用于缓存失效判定。"""
        return self._key_epoch

    def update_key_epoch(self, new_epoch: str) -> None:
        """更新 key_epoch 并触发密钥版本轮换回调，用于备份恢复后同步状态。

        恢复整体替换数据，需失效按 crypto_id 索引的明文缓存（恢复保留 crypto_id，
        不清则命中旧明文）。经独立的 epoch 轮换通道触发（ARCH-003），与锁定回调分离。
        """
        self._key_epoch = new_epoch
        self.invoke_epoch_rotated_callbacks()

    # ---- 写守卫 ----
    def enforce_key_epoch(self) -> None:
        """拒绝锁定状态或主密钥已轮换的旧会话写入数据库。

        每次写入都比对 key_epoch，不做时间缓存，避免改密后旧会话在窗口内用旧密钥
        写入导致新会话解密失败的损坏窗口。检测到 epoch 不匹配时调用 clear_vault_state
        而非完整 lock：本守卫经 db 写路径在持有 db_lock 时调用，lock 会触发业务回调
        （清缓存等），回调中访问数据库形成 db_lock 重入与潜在锁顺序风险；
        clear_vault_state 仅清密钥状态、不触发回调，更可控。
        """
        if self._db.in_transaction:
            # 事务进行中跳过：写路径已在事务边界校验过 epoch，事务内重复比对属冗余。
            # 代价是事务期间的写入不受此守卫保护，故每个事务化写路径必须在事务开始时
            # 自行比对 epoch（见 epoch_guarded_transaction 的复查）。
            return
        # 曾解锁过但当前未解锁 = 已锁定：拒绝写（含后台线程持旧 key 副本在 lock 后
        # 提交写入的竞态）。用 _ever_unlocked 区分「从未激活」（initialize 前，允许
        # 写 vault_meta）与「已锁定」（lock 清零 key_epoch，单看 epoch is None 无法区分）。
        if self._ever_unlocked and not self.is_unlocked:
            raise VaultLockedError("保险库已锁定，不能写入数据")
        if self._key_epoch is None:
            return  # 从未激活（initialize 前），守卫放行 vault_meta 写入
        current_epoch = self._db.get_meta("key_epoch")
        if current_epoch and current_epoch != self._key_epoch:
            self.clear_vault_state()
            raise VaultKeyEpochMismatchError("保险库密钥已变更，请重新启动并解锁")

    @contextmanager
    def vault_write_lock(self) -> Iterator[None]:
        """获取保险库写锁，串行化接触全量明文的长操作（改密/重加密/备份/恢复）。

        外部协作者须通过此公共上下文访问锁，使「持锁才能接触全量明文」契约显式化，
        避免重构锁结构时静默破坏串行化保护。
        """
        with self._lock:
            yield

    @contextmanager
    def epoch_guarded_transaction(
        self,
        *,
        operation: str = "操作",
        pre_epoch: str | None = None,
    ) -> Iterator[None]:
        """事务 + epoch 守卫：进入时快照 key_epoch，事务内复查防并发改密。

        收敛各长写路径「pre_epoch 快照 → 开事务 → 事务内复查 key_epoch → 业务写入」
        重复样板。db_lock 已串行化改密，epoch 复查是冗余纵深防御——check 置于 yield 前，
        yield 块内的写入由此获得「事务期间密钥未变」的保证。

        pre_epoch：调用方在「锁外加密」前自行快照的 key_epoch（MAINT-004）。默认 None
        则进入本上下文时快照。导入路径把加密移出 db_lock 后，须在加密前快照 pre_epoch
        并传入——若「加密后→开事务前」发生改密（epoch 已变），此处复查 snapshot（旧）
        与当前 key_epoch（新）不等而中止，避免旧密钥密文落到新 epoch 库。
        """
        snapshot = self.key_epoch if pre_epoch is None else pre_epoch
        with self.db.transaction():
            if self.key_epoch != snapshot:
                raise VaultKeyEpochMismatchError(f"{operation}期间检测到密钥变更，已中止并回滚")
            yield

    @contextmanager
    def epoch_guarded_read(self) -> Iterator[None]:
        """读路径 epoch 守卫：持 db_lock 期间校验内存 key_epoch 与库内 epoch 一致。

        对称写路径 :meth:`epoch_guarded_transaction`，供读路径（``get_entry_summaries``
        等仅持 db_lock 不取 vault_write_lock 的操作）防护改密 commit 与 activate_keys
        间的微秒窗口：DB 已提交新密文+新 epoch，内存密钥仍旧，并发读会用旧密钥解密
        新密文致 GCM 认证失败。持 db_lock 后比对库内 ``key_epoch`` 与内存 ``key_epoch``，
        不一致则抛 :class:`VaultKeyEpochMismatchError` 中止读取（ARCH-005）。

        持 db_lock 期间写路径无法 commit（需同一锁），故校验通过后读路径全程密钥与
        密文版本一致。读路径仅持 db_lock、不取 vault_write_lock、不触发业务回调，故
        无锁顺序反转或重入死锁风险（区别于 :meth:`enforce_key_epoch` 须改调
        :meth:`clear_vault_state` 规避回调重入 db_lock）。未解锁（key_epoch 为 None）
        时跳过校验，供初始化前的元数据读取。
        """
        with self._db.db_lock:
            session_epoch = self._key_epoch
            if session_epoch is not None:
                db_epoch = self._db.get_meta("key_epoch")
                if db_epoch and db_epoch != session_epoch:
                    raise VaultKeyEpochMismatchError("读取期间检测到密钥变更，已中止")
            yield

    # ---- 原子状态操作（供 VaultLifecycleOrchestrator）----
    def set_master_key(self, key: bytes | bytearray) -> None:
        """设置主密钥（不标记解锁、不加载 snapshot_key）。

        供 unlock 在校验 vault_meta_mac 与加载 snapshot_key 前先设置主密钥——这两步
        须用主密钥，故 unlock 分步设置而非用 activate_keys 原子激活。
        """
        self._key = key

    def set_epoch(self, epoch: str) -> None:
        """设置 key_epoch（不触发缓存失效回调）。

        区别于 :meth:`update_key_epoch`（恢复专用，触发回调）：unlock/initialize/改密
        的 epoch 设置不应触发回调（此时缓存尚未建立或将由流程后续显式处理）。
        """
        self._key_epoch = epoch

    def set_domain_key(self, key: bytes | bytearray) -> None:
        """设置 MetadataSigner 的域密钥（由主密钥经 HKDF/HMAC 派生）。"""
        self._signer.set_domain_key(MetadataSigner.compute_domain_key(key))

    def load_snapshot_key(self, encrypted: str | None = None) -> None:
        """从 vault_meta 解密并加载 snapshot_key。

        须在主密钥设置后调用（snapshot_key_enc 用主密钥加密）。解密与长度校验委托
        :class:`VaultMetaStore`，与写入侧对称。
        """
        key = self._key
        if key is None:
            raise VaultLockedError("保险库未解锁")
        if encrypted is None:
            encrypted = self._db.get_meta("snapshot_key_enc")
        if not encrypted:
            raise VaultLockedError("保险库缺少自动快照密钥")
        self._snapshot_key = VaultMetaStore.decrypt_snapshot_key(encrypted, key)

    def mark_unlocked(self) -> None:
        """标记保险库为已解锁（在全部密钥材料就位后调用）。"""
        self._is_unlocked = True
        self._ever_unlocked = True

    def activate_keys(
        self,
        key: bytes | bytearray,
        snapshot_key: bytes | bytearray,
        epoch: str,
    ) -> None:
        """原子激活主密钥、快照密钥与 epoch，并设置域密钥、标记解锁。

        供 initialize/改密 在完成全部校验与事务提交后调用，避免密钥/epoch/域密钥/
        解锁标志分步赋值产生部分就位窗口。unlock 因须用主密钥校验 vault_meta_mac
        与加载 snapshot_key，改用 set_master_key/set_epoch/set_domain_key/
        load_snapshot_key/mark_unlocked 分步进行。
        """
        self._key_mgr.activate(key, snapshot_key, epoch)
        self.set_domain_key(key)
        self._is_unlocked = True

    def clear_vault_state(self) -> None:
        """清除密钥材料和加密缓存，并触发 gc 回收 AESGCM 缓存副本。

        用于 lock 与 enforce_key_epoch 等。末尾 gc.collect() 尽快回收 clear_cache 释放的
        AESGCM 实例（内部 C 层持有密钥拷贝），缩短密钥在内存/swap 的驻留。不触发业务
        回调（由 invoke_lock_callbacks 单独触发），避免持数据库锁时回调再获取数据库锁
        死锁。
        """
        # 密钥材料由 KeyManager 集中清零，含主密钥、快照密钥与 epoch
        self._key_mgr.clear()
        # 清零 MetadataSigner 中的域密钥：经 setter 传 None 触发内部 secure_zero_buffer
        # （MetadataSigner._rotate_domain_key 的 old is not None 分支），无需手动重复清零。
        self._signer.domain_key = None
        self._is_unlocked = False
        # 重置初始化标志：下次 ensure_db_open 将重新验证 schema。
        # 注意：不关闭数据库连接，_conn 仍可能被后续操作使用，但 _db_initialized=False
        # 确保 init_tables 在下次访问时重新运行。
        self._db_initialized = False
        EncryptionEngine.clear_cache()
        gc.collect()

    # ---- snapshot_key 操作（供恢复流程）----
    def encrypt_snapshot_key(self, snapshot_key: bytes | bytearray) -> str:
        """加密 snapshot_key 以写入 vault_meta，供恢复流程在事务内复用。

        恢复流程不改主密钥，故用当前 self._key 加密。将加密与 set_meta 解耦，使
        snapshot_key_enc 能与 key_epoch 在同一数据库事务内写入，消除事务外崩溃导致
        epoch 已提交而 snapshot_key_enc 未写入的不一致窗口。
        """
        if self._key is None:
            raise VaultLockedError("保险库未解锁")
        return VaultMetaStore.encrypt_snapshot_key(snapshot_key, self._key)

    def apply_snapshot_key(self, snapshot_key: bytes | bytearray) -> None:
        """仅同步内存中的 snapshot_key，不写库。

        供恢复流程在事务提交后同步内存状态——库内 snapshot_key_enc 已在事务内由
        调用方经 encrypt_snapshot_key + set_meta 写入，此处只更新 KeyManager。
        """
        self._key_mgr.update_snapshot_key(snapshot_key)

    # ---- 取消信号 ----
    def request_cancel(self) -> None:
        """请求中止进行中的重加密（改密取消或关闭应用时调用）。

        设置取消事件，重加密循环检测后抛出异常并回滚事务，避免提交半成品。
        """
        self._cancel_event.set()

    def is_cancel_requested(self) -> bool:
        """是否有进行中的取消/锁定请求，供长操作轮询提前退出。

        全量安全分析等长循环据此在锁定请求到来时主动中止并释放 vault 写锁，避免
        主线程 lock() 阻塞等锁导致 UI 冻结与明文驻留。
        """
        return self._cancel_event.is_set()

    @property
    def cancel_event(self) -> threading.Event:
        """取消事件原语，供改密重加密循环经 ReEncryptionService 轮询与重置。"""
        return self._cancel_event

    # ---- 生命周期门面委托 ----
    # 薄委托使调用方（app/login/dialog/test）无需感知 orchestrator。orchestrator 经
    # attach_lifecycle 由组合根紧接 VaultManager 构造之后注入，故委托时必已就位。
    def attach_lifecycle(self, lifecycle: LifecyclePort) -> None:
        """注入生命周期编排器，使本类的生命周期方法委托给它。

        须在组合根创建 orchestrator 后、任何生命周期调用前调用一次。
        """
        self._lifecycle = lifecycle

    def _require_lifecycle(self) -> LifecyclePort:
        """获取已注入的生命周期编排器，未注入时抛 RuntimeError。

        用显式 ``raise`` 而非 ``assert``：``python -O`` 会剔除 assert，导致未注入时
        抛无信息的 ``AttributeError`` 而非清晰的「attach_lifecycle 未调用」。
        """
        if self._lifecycle is None:
            raise RuntimeError("attach_lifecycle 未调用")
        return self._lifecycle

    def initialize(
        self,
        master_password: str,
        params: KdfParams | None = None,
    ) -> tuple[bool, str]:
        """首次初始化保险库（委托 VaultLifecycleOrchestrator）。"""
        return self._require_lifecycle().initialize(master_password, params=params)

    def unlock(self, master_password: str) -> tuple[bool, str]:
        """解锁保险库（委托 VaultLifecycleOrchestrator）。"""
        return self._require_lifecycle().unlock(master_password)

    def lock(self) -> None:
        """锁定保险库（委托 VaultLifecycleOrchestrator）。"""
        self._require_lifecycle().lock()

    def close(self) -> None:
        """关闭保险库（委托 VaultLifecycleOrchestrator）。"""
        self._require_lifecycle().close()

    def change_master_password(
        self,
        old_password: str,
        new_password: str,
    ) -> tuple[bool, str]:
        """修改主密码（委托 VaultLifecycleOrchestrator）。"""
        return self._require_lifecycle().change_master_password(old_password, new_password)
