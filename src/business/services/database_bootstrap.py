"""数据库连接引导：创建 DatabaseManager 并注入元数据完整性 handler。

集中「创建 db + 创建 signer + 注入完整性 handler」的装配步骤，使组合根显式持有依赖。
``write_guard`` 依赖运行时密钥状态，须在 VaultManager 构造后由其注入，故不在此处。
"""

from __future__ import annotations

from ...config import ConfigManager
from ...database.db_manager import DatabaseManager
from .metadata_signer import MetadataSigner


class DatabaseBootstrap:
    """数据库与签名器的引导装配。"""

    @staticmethod
    def bootstrap(
        config: ConfigManager,
        *,
        test_mode: bool = False,
    ) -> tuple[DatabaseManager, MetadataSigner]:
        """创建 DatabaseManager 与 MetadataSigner，并注入分类/条目完整性 handler。

        返回 ``(db, signer)`` 供组合根继续装配。

        Args:
            config: 配置管理器，提供 ``db_path``。
            test_mode: True 时关闭密文前缀断言适配测试；生产路径保持默认 False。
        """
        db = DatabaseManager(config.db_path, test_mode=test_mode)
        signer = MetadataSigner()
        db.set_entry_integrity_handlers(signer.sign, signer.verify)
        db.set_category_integrity_handlers(signer.sign_category, signer.verify_category)
        return db, signer
