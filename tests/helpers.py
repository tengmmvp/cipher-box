"""共享测试辅助函数。

此处放置非 fixture 的工具函数，供 conftest.py 和各测试文件共同使用。
pytest fixture 仍定义在 conftest.py 中。
"""

from src.business.managers.entry_cache import EntryCacheManager
from src.business.managers.entry_change_bus import EntryChangeBus
from src.business.managers.entry_manager import EntryManager
from src.business.managers.vault_manager import VaultManager
from src.config import ConfigManager


def make_test_config(data_dir) -> ConfigManager:
    """创建使用指定目录的 ConfigManager 测试实例。

    委托给 ConfigManager.for_testing() 工厂方法。
    """
    return ConfigManager.for_testing(data_dir)


def make_vault(config: ConfigManager, *, test_mode: bool = True) -> VaultManager:
    """创建完整装配的 VaultManager（db + signer + 生命周期编排器），测试专用。

    委托 composition.build_vault，使测试经与生产一致的单一入口取得 vault，避免各
    测试复制 db/signer/orchestrator 装配步骤。test_mode=True 关闭密文前缀断言，
    适配测试直接构造的非密文数据。
    """
    from src.business.composition import build_vault

    return build_vault(config, test_mode=test_mode)


def make_entry_manager(vault: VaultManager) -> EntryManager:
    """构造 EntryManager 测试实例，绑定独立的缓存与变更总线。

    SRP 拆分后 EntryManager 需 (vault, cache, change_bus) 三参；集中此工厂
    避免各测试文件复制三行装配。
    """
    cache = EntryCacheManager(vault)
    return EntryManager(vault, cache, EntryChangeBus(cache))
