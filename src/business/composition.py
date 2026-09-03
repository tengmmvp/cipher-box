"""业务层组装根（CompositionRoot）。

集中创建业务层 manager 并完成跨 manager 连线，使 MainWindow 不再自行 new
业务 manager，而是接收预组装的 :class:`BusinessContext`。QObject 控制器
（AutoLockController / AutoBackupController / ClipboardManager / EntryListController /
SidebarController）依赖 Qt 线程亲和性或 UI 配置，仍由 MainWindow 装配，不放入
此 frozen dataclass。
"""

import weakref
from dataclasses import dataclass

from ..config import ConfigManager
from .managers.backup_restore import BackupRestoreManager
from .managers.category_manager import CategoryManager
from .managers.entry_cache import EntryCacheManager
from .managers.entry_change_bus import EntryChangeBus
from .managers.entry_manager import EntryManager
from .managers.import_export import ImportExportManager
from .managers.restore_point_manager import RestorePointManager
from .managers.vault_lifecycle import VaultLifecycleOrchestrator
from .managers.vault_manager import VaultManager
from .services.database_bootstrap import DatabaseBootstrap
from .services.rate_limiter import (
    CHANGE_MASTER_RATE_LIMIT_FILENAME,
    LOGIN_RATE_LIMIT_FILENAME,
    RateLimiter,
)
from .services.security_analyzer import SecurityAnalyzer


@dataclass(frozen=True)
class BusinessContext:
    """业务层 manager 的组装容器。

    装载纯 Python manager（无线程亲和性）：保险库、条目、安全分析、导入导出、
    备份恢复。``config`` 与 ``vault`` 作为顶层依赖一并装入，使 MainWindow 仅需接收
    本容器即可取得全部业务依赖。缓存（EntryCacheManager）与变更总线（EntryChangeBus）
    仅为业务层内部 cache 失效连线而创建，不对外暴露——UI 经 entry_mgr 间接消费缓存
    派生状态，刷新走显式调用（``_do_refresh_after_entry_change``），避免容器面扩大与
    「字段存在即暗示应订阅」的误导。``change_master_rate_limiter`` 为改密对话框的
    依赖（ARCH-043），经容器随 ctx 流转至 MenuController，不在 UI 内构造。
    """

    config: ConfigManager
    vault: VaultManager
    entry_mgr: EntryManager
    security: SecurityAnalyzer
    import_export: ImportExportManager
    backup: BackupRestoreManager
    change_master_rate_limiter: RateLimiter


def build_login_rate_limiter(config: ConfigManager) -> RateLimiter:
    """创建登录限流器（ARCH-043：组合根显式装配，UI 对话框注入消费）。

    状态文件名常量归 rate_limiter 模块单一事实源；调用方（app.py 登录流程）每次
    构造 LoginWindow 时调用，限流器生命周期与登录窗口一致（跨会话状态经状态文件
    恢复）。
    """
    return RateLimiter(config.data_dir / LOGIN_RATE_LIMIT_FILENAME, config)


def build_change_master_rate_limiter(config: ConfigManager) -> RateLimiter:
    """创建改密限流器（ARCH-043），状态文件名常量同 rate_limiter 模块单一事实源。"""
    return RateLimiter(config.data_dir / CHANGE_MASTER_RATE_LIMIT_FILENAME, config)


def build_vault(config: ConfigManager, *, test_mode: bool = False) -> VaultManager:
    """创建并完整装配 VaultManager（db、signer、生命周期编排器）。

    集中 vault 装配：DatabaseBootstrap 创建 db+signer 并注入完整性 handler，
    VaultManager 持有 db+signer 并注入 write_guard，VaultLifecycleOrchestrator 注入
    生命周期委托。app.py 与测试经此单一入口取得完全装配的 vault。

    Args:
        config: 配置管理器。
        test_mode: True 时关闭 DatabaseManager 密文前缀断言（测试直接构造非密文数据）；
            生产路径保持默认 False。
    """
    db, signer = DatabaseBootstrap.bootstrap(config, test_mode=test_mode)
    vault = VaultManager(config, db, signer)
    # ARCH-044：orchestrator 的 db/signer 从 vault 单一装配参数派生——构造签名不再
    # 接受独立 db/signer，杜绝传入与 vault 内部不同域实例致编排器绕过 vault 写守卫。
    vault.attach_lifecycle(VaultLifecycleOrchestrator(vault))
    return vault


# 已完成业务上下文装配的 vault 弱引用集（ARCH-044 防重入）：弱引用不延长 vault 生命周期。
_assembled_vaults: "weakref.WeakSet[VaultManager]" = weakref.WeakSet()


def build_business_context(config: ConfigManager, vault: VaultManager) -> BusinessContext:
    """组装业务层 manager 并完成跨 manager 连线。

    创建 EntryCacheManager → EntryChangeBus → EntryManager → SecurityAnalyzer →
    ImportExportManager → BackupRestoreManager 的依赖链，并注册锁定/变更回调
    使缓存失效事件驱动化。调用方（app.py 解锁成功后）取得 ctx 传给 MainWindow。

    子服务装配规则（ARCH-033）：

    - **组合根显式创建注入**：有自持状态/独占缓存的子服务——CategoryManager（分类
      CRUD + change_bus 通知）、RestorePointManager（恢复点文件域）、SecurityAnalyzer
      （分析结果 TTL 缓存）、EntryCacheManager（5 套明文缓存）、EntryChangeBus（变更
      →失效→回调管线）。它们各有独立生命周期与失效语义，是可替换单元：组合根显式
      构造并注入保持替换间隙一致（测试替身/重配置单一改动点，呼应 MAINT-015 的
      必传签名强制）。
    - **宿主内部构造**：纯变换/共享缓存的无状态子服务——TotpService /
      PasswordHistoryService / EntryViewDecryptor（均无自有缓存或失效状态）。由
      EntryManager 内部构造并与其共用同一 EntryCacheManager 实例：无独立替换需求，
      单实例共享缓存避免多份缓存副本漂移（视图解密复用摘要缓存的前提，
      MAINT-021）。

    锁定与备份恢复（密钥轮换）失效 entry 缓存，条目变更失效安全分析缓存；两类
    事件经独立回调通道触发（ARCH-003），详见下方注册处注释。

    Raises:
        RuntimeError: 对同一 VaultManager 重复调用（ARCH-044）——重复注册锁定/轮换
            回调并泄漏旧 cache 实例，属装配错误而非合法复用路径；或传入未装配
            生命周期编排器的 vault（ARCH-047）——须经 ``build_vault`` 取得完整装配
            的 vault 再组装上下文。
    """
    if vault in _assembled_vaults:
        raise RuntimeError(
            "build_business_context 对同一 VaultManager 重复调用：会重复注册锁定/轮换"
            "回调并泄漏旧 cache 实例（ARCH-044）。同一会话应复用既有 BusinessContext。"
        )
    # 装配前置校验（ARCH-047）：未挂编排器的 vault 手工构造后直接传入时，生命周期
    # 方法（initialize/unlock/lock/close/change_master_password）会推迟到首次调用才
    # 抛「attach_lifecycle 未调用」——此处显式拒绝使错误前置且报错指向装配代码。
    if not vault.lifecycle_attached:
        raise RuntimeError(
            "build_business_context 接受的 VaultManager 未装配生命周期编排器"
            "（attach_lifecycle 未调用）：请经 build_vault 创建完整装配的 vault"
            "（ARCH-047），勿手工构造后直接传入。"
        )
    _assembled_vaults.add(vault)
    try:
        cache = EntryCacheManager(vault)
        change_bus = EntryChangeBus(cache)
        # CategoryManager / RestorePointManager 提升为一等依赖，由组合根显式创建并注入
        # （ARCH-033：保持替换间隙一致，便于测试替身与重配置）。
        category_mgr = CategoryManager(vault, cache, change_bus)
        entry_mgr = EntryManager(vault, cache, change_bus, category_mgr)
        security = SecurityAnalyzer(vault, cache)
        import_export = ImportExportManager(entry_mgr)
        restore_points = RestorePointManager(vault)
        backup = BackupRestoreManager(vault, entry_mgr, restore_points)
        # 改密限流器（ARCH-043）：有跨进程持久状态的业务安全模块，经组合根显式创建并
        # 经 BusinessContext 注入 MenuController→ChangeMasterDialog，UI 不再自行实例化。
        change_master_rate_limiter = build_change_master_rate_limiter(config)
        # 锁定与密钥版本轮换（备份恢复）是两类语义不同的事件（ARCH-003 拆为独立通道），
        # 但都要求失效全部明文/派生缓存：锁定清明文摘要/分类名/TOTP/标签缓存收缩内存泄漏面；
        # 恢复整体替换数据，按 crypto_id 索引的明文缓存须失效防命中旧明文，安全分析缓存亦
        # 失效。故两个回调均注册到两个通道以保持行为等价。category_mgr.invalidate_caches
        # 清 CategoryManager 自持的明文分类名会话缓存（SEC-053）——entry_mgr 的
        # invalidate_caches 只清 EntryCacheManager 五套缓存，不含该份。
        vault.register_on_lock(entry_mgr.invalidate_caches)
        vault.register_on_lock(category_mgr.invalidate_caches)
        vault.register_on_lock(security.invalidate_cache)
        vault.register_on_epoch_rotated(entry_mgr.invalidate_caches)
        vault.register_on_epoch_rotated(category_mgr.invalidate_caches)
        vault.register_on_epoch_rotated(security.invalidate_cache)
        # 条目变更回调携带 (password_changed, metadata_changed, crypto_id)：单条更新经
        # crypto_id 触发 SecurityAnalyzer 的单条增量失效（PERF-021，避免每次保存触发
        # 整库密码解密+HMAC 重算）；增删/批量（crypto_id=None）与上方锁定/轮换通道的
        # 零参调用保持全量失效。
        entry_mgr.register_on_change(security.invalidate_cache)
        return BusinessContext(
            config=config,
            vault=vault,
            entry_mgr=entry_mgr,
            security=security,
            import_export=import_export,
            backup=backup,
            change_master_rate_limiter=change_master_rate_limiter,
        )
    except BaseException:
        # 装配中途异常回退防重入登记（ARCH-046）：登记先行的原实现使「上次装配失败」
        # 的重试被误拒，且报错语义误导（述为「重复调用」）。回调注册仅为 list.append
        # 不抛异常，实际异常源是 manager 构造（此时尚未注册任何回调、无副作用），
        # discard 后重试等价全新装配。BaseException 连 KeyboardInterrupt 一并回退，
        # 不给「半登记」态留窗口。
        _assembled_vaults.discard(vault)
        raise
