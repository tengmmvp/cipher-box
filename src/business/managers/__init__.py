"""业务管理器层：编排 Crypto 与 Data 层的核心管理器。

核心管理器：``vault_manager.VaultManager``、``entry_manager.EntryManager``、
``import_export.ImportExportManager``、``backup_restore.BackupRestoreManager``
（MAINT-085：原集中 re-export 零消费方——组合根与测试均走子模块全路径导入，
无人经 ``from src.business.managers import X``；无检查守护的声明面随时间必然
漂移，故删除，消费方导入路径不变）。
"""
