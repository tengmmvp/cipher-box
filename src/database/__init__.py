"""数据库层 — SQLite 持久化封装。

提供 WAL 模式连接、手动事务管理（begin/commit/rollback/savepoint）、经 ``RLock``
串行化的线程安全访问，以及表结构校验（拒绝打开不匹配的库，不做旧格式迁移）。加密
字段以 ``*_enc`` 列存储密文，本层只处理已加密数据、不持有密钥。

依赖方向：仅依赖共享层（models/exceptions/utils），被 Business 层经
``ConnectionProvider`` / ``EntryStore`` / ``CategoryStore`` / ``VaultDataStore`` 等
Protocol 切片访问，不反向依赖上层。
"""
