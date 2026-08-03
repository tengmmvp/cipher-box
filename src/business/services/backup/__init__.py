"""备份/恢复无状态纯函数模块子包。

承载备份二进制头编解码、恢复前载荷校验、命名约定、Portable 载荷类型、可移植数据
采集、恢复重建、自动备份策略与备份目录/快照/恢复点清理等无数据库事务的纯变换模块，
为 :class:`...managers.backup_restore.BackupRestoreManager` 与生命周期/恢复点管理器
下沉的无状态纯函数集合，经子包内分组以与 ``managers/importers/`` 子包模式对齐。
"""
