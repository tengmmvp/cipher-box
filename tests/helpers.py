"""共享测试辅助函数。"""

from typing import TYPE_CHECKING

from src.business.managers.category_manager import CategoryManager
from src.business.managers.entry_cache import EntryCacheManager
from src.business.managers.entry_change_bus import EntryChangeBus
from src.business.managers.entry_manager import EntryManager
from src.business.managers.vault_manager import VaultManager
from src.config import ConfigManager
from src.database.types import EntryQuery
from src.models import Entry

if TYPE_CHECKING:
    from src.business.managers.backup_restore import BackupRestoreManager


def make_test_config(data_dir) -> ConfigManager:
    """创建使用指定目录的 ConfigManager 测试实例。"""
    return ConfigManager.for_testing(data_dir)


def make_vault(config: ConfigManager, *, test_mode: bool = True) -> VaultManager:
    """创建完整装配的 VaultManager（db + signer + 生命周期编排器），测试专用。

    使测试经与生产一致的单一入口取得 vault，避免各
    测试复制 db/signer/orchestrator 装配步骤。test_mode=True 关闭密文前缀断言，
    适配测试直接构造的非密文数据。
    """
    from src.business.composition import build_vault

    return build_vault(config, test_mode=test_mode)


def make_entry_manager(vault: VaultManager) -> EntryManager:
    """构造 EntryManager 测试实例，绑定独立的缓存与变更总线。

    EntryManager 需 (vault, cache, change_bus, category_mgr) 四参（MAINT-015：
    category_mgr 必传注入）；集中此工厂避免各测试文件复制装配步骤。
    """
    cache = EntryCacheManager(vault)
    change_bus = EntryChangeBus(cache)
    category_mgr = CategoryManager(vault, cache, change_bus)
    return EntryManager(vault, cache, change_bus, category_mgr)


def make_backup_manager(
    vault: VaultManager, entry_mgr: EntryManager | None = None
) -> "BackupRestoreManager":
    """构造 BackupRestoreManager 测试实例（restore_point_mgr 必传注入，MAINT-015）。

    与 make_entry_manager 对称的工厂：restore_point_mgr 不再有兜底内部构造，
    集中在此装配避免各测试复制。
    """
    from src.business.managers.backup_restore import BackupRestoreManager
    from src.business.managers.restore_point_manager import RestorePointManager

    return BackupRestoreManager(
        vault,
        entry_mgr if entry_mgr is not None else make_entry_manager(vault),
        RestorePointManager(vault),
    )


def decrypt_all_entries(
    entry_mgr: EntryManager,
    *,
    deleted_only: bool = False,
    include_deleted: bool = False,
    category_id: int | None = None,
    favorite_only: bool = False,
) -> list[Entry]:
    """测试助手：一次性解密全部条目（含 password/totp_secret 等敏感字段，MAINT-098）。

    等价已退役的 ``EntryManager.get_entries``（src 零调用、仅测试消费的「一次性
    解密全部密码」入口，生产 API 面不再保留）：经公开 API 组装 ``db.get_entries``
    窄读 + ``decrypt_entry`` 详情解密。测试断言数据往返用此助手；防回退守护断言
    ``EntryManager`` 上无同名方法。

    与原实现的差异：不再包 ``epoch_guarded_read`` / epoch 失配返空——单线程测试
    体内无并发改密窗口，锁定态会经 ``decrypt_entry`` 的密钥守卫自然抛
    ``VaultLockedError``（原实现同样在锁定期传播该异常）。
    """
    raw_entries = entry_mgr.db.get_entries(
        EntryQuery(
            deleted_only=deleted_only,
            include_deleted=include_deleted,
            category_id=category_id,
            favorite_only=favorite_only,
        )
    )
    return [entry_mgr.decrypt_entry(raw) for raw in raw_entries]
