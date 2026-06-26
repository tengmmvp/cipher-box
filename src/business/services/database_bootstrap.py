"""数据库连接引导：创建 DatabaseManager 并注入元数据完整性 handler（从 VaultManager 下沉）。

集中「创建 db + 创建 signer + 注入 entry/category 完整性 handler」的装配步骤，使
组合根（composition）显式持有这些依赖，消除原先 VaultManager 内部 ``new
DatabaseManager`` 形成的隐藏第二组合根。

``write_guard`` 依赖运行时密钥状态（经 VaultManager.enforce_key_epoch 比对 epoch），
须在 VaultManager 构造后由其注入，故不在此处——本模块仅负责不依赖密钥的引导部分。
"""

from __future__ import annotations

from ...config import ConfigManager
from ...database.db_manager import DatabaseManager
from .metadata_signer import MetadataSigner


class DatabaseBootstrap:
    """数据库与签名器的引导装配。"""

    @staticmethod
    def bootstrap(
        config: ConfigManager, *, test_mode: bool = False,
    ) -> tuple[DatabaseManager, MetadataSigner]:
        """创建 DatabaseManager 与 MetadataSigner，并注入分类/条目完整性 handler。

        返回 ``(db, signer)`` 供组合根继续装配：``db`` 传给 VaultManager（并在其构造
        后注入 write_guard），``signer`` 同时供 VaultManager（域密钥）与
        VaultLifecycleOrchestrator（重加密 rotator）使用。

        Args:
            config: 配置管理器，提供 ``db_path``。
            test_mode: True 时关闭 DatabaseManager 的密文前缀断言，适配测试直接构造的
                非密文数据；生产路径保持默认 False（断言启用）。
        """
        db = DatabaseManager(config.db_path, test_mode=test_mode)
        signer = MetadataSigner()
        db.set_entry_integrity_handlers(signer.sign, signer.verify)
        db.set_category_integrity_handlers(signer.sign_category, signer.verify_category)
        return db, signer
