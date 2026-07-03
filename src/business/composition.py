"""业务层组装根（CompositionRoot）。

集中创建业务层 manager 并完成跨 manager 连线，使 MainWindow 不再自行 new
业务 manager，而是接收预组装的 :class:`BusinessContext`。QObject 控制器
（AutoLockController / AutoBackupController / ClipboardManager / EntryListController /
SidebarController）依赖 Qt 线程亲和性或 UI 配置，仍由 MainWindow 装配，不放入
此 frozen dataclass。
"""

from dataclasses import dataclass

from ..config import ConfigManager
from .managers.backup_restore import BackupRestoreManager
from .managers.entry_cache import EntryCacheManager
from .managers.entry_change_bus import EntryChangeBus
from .managers.entry_manager import EntryManager
from .managers.import_export import ImportExportManager
from .managers.vault_lifecycle import VaultLifecycleOrchestrator
from .managers.vault_manager import VaultManager
from .services.database_bootstrap import DatabaseBootstrap
from .services.security_analyzer import SecurityAnalyzer


@dataclass(frozen=True)
class BusinessContext:
    """业务层 manager 的组装容器。

    装载纯 Python manager（无线程亲和性）：保险库、缓存、变更总线、条目、
    安全分析、导入导出、备份恢复。``config`` 与 ``vault`` 作为顶层依赖一并
    装入，使 MainWindow 仅需接收本容器即可取得全部业务依赖。
    """

    config: ConfigManager
    vault: VaultManager
    cache: EntryCacheManager
    change_bus: EntryChangeBus
    entry_mgr: EntryManager
    security: SecurityAnalyzer
    import_export: ImportExportManager
    backup: BackupRestoreManager


def build_vault(config: ConfigManager, *, test_mode: bool = False) -> VaultManager:
    """创建并完整装配 VaultManager（db、signer、生命周期编排器）。

    集中 vault 装配：DatabaseBootstrap 创建 db+signer 并注入条目/分类完整性 handler，
    VaultManager 持有 db+signer 并注入 write_guard，VaultLifecycleOrchestrator 注入
    生命周期委托（initialize/unlock/lock/change_master_password/close）。app.py 与测试
    经此单一入口取得完全装配的 vault，消除原先 VaultManager 内部 ``new DatabaseManager``
    的隐藏第二组合根与分散装配步骤。

    Args:
        config: 配置管理器。
        test_mode: True 时关闭 DatabaseManager 密文前缀断言（测试直接构造非密文数据）；
            生产路径保持默认 False。
    """
    db, signer = DatabaseBootstrap.bootstrap(config, test_mode=test_mode)
    vault = VaultManager(config, db, signer)
    vault.attach_lifecycle(VaultLifecycleOrchestrator(vault, db, signer))
    return vault


def build_business_context(config: ConfigManager, vault: VaultManager) -> BusinessContext:
    """组装业务层 manager 并完成跨 manager 连线。

    创建 EntryCacheManager → EntryChangeBus → EntryManager → SecurityAnalyzer →
    ImportExportManager → BackupRestoreManager 的依赖链，并注册锁定/变更回调
    使缓存失效事件驱动化。调用方（app.py 解锁成功后）取得 ctx 传给 MainWindow。

    连线集中于此使依赖关系显式且单一：锁定时失效 entry 缓存（``register_on_lock``），
    条目变更时失效安全分析缓存（``register_on_change``）。``register_on_lock`` 注册的
    回调也会在备份恢复（``update_key_epoch``）后触发——恢复整体替换数据，按 crypto_id
    索引的明文缓存须失效以防命中旧明文；当前注册的均为纯缓存清除、幂等，复用安全。
    原先散落在 MainWindow._register_callbacks，现上提至组装根，使 MainWindow 不再承担
    跨 manager 连线职责。
    """
    cache = EntryCacheManager(vault)
    change_bus = EntryChangeBus(cache)
    entry_mgr = EntryManager(vault, cache, change_bus)
    security = SecurityAnalyzer(vault, cache)
    import_export = ImportExportManager(entry_mgr)
    backup = BackupRestoreManager(vault, entry_mgr)
    vault.register_on_lock(entry_mgr.invalidate_caches)
    vault.register_on_lock(security.invalidate_cache)
    entry_mgr.register_on_change(security.invalidate_cache)
    return BusinessContext(
        config=config,
        vault=vault,
        cache=cache,
        change_bus=change_bus,
        entry_mgr=entry_mgr,
        security=security,
        import_export=import_export,
        backup=backup,
    )
