# 变更日志

本项目所有显著变更记录于此文件。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

CipherBox 尚未发布正式版本（`__version__ = "0.1.0.dev0"` 为开发阶段占位）。以下为开发阶段
经多轮五维度审查（架构/代码质量/性能/可维护性/安全）沉淀的基线变更。

### 重构
- **主窗口拆分**：MainWindow 实现拆为四个职责文件（`main_window` / `_menu` /
  `_entries` / `_filters`）+ 一个共享 mixin base，控制单文件规模。
- **生命周期拆分**：VaultManager 的 initialize/unlock/lock/change_master_password/close
  拆至 `VaultLifecycleOrchestrator`，VaultManager 收窄为密钥/db/写守卫核心。
- **SRP 拆分**：EntryManager 拆出 CategoryManager / TotpService /
  PasswordHistoryService 子服务与 EntryCacheManager（多级缓存）。
- **导入策略类包**：格式解析拆至 `importers/`（JSON/CSV/KeePass/Bitwarden 各一
  策略类），统一 `_IMPORTERS` 注册表 + `import_file` 单一 dispatch 入口。
- **HKDF 域分离**：主密钥与备份密钥经不同 `info` 派生，替代旧 salt 前缀的隐式
  域分离假设。
- **列序单一事实源**：`_ENTRY_COLUMNS` / `_ENTRY_COLUMN_GETTERS` 启动期自检，
  消除 SQL 列序与 RawEntry 字段序的双重维护。
- **分类 HMAC 完整性**：分类元数据纳入 HMAC 签名，改密对称重签。

### 安全
- AES-256-GCM：每个加密值独立随机 12 字节 nonce，AAD 全程参与认证。
- Argon2id 参数达 OWASP（time=3 / 64MiB / parallelism=4），salt 32 字节每用户随机。
- `vault_meta` HMAC 完整性签名 + KDF 参数防降级校验。
- 锁定态三层守卫：`_require_unlocked`（UI）+ `_db_write` 装饰器（DB）+ key_epoch 复查。
- 速率限制抗状态删除/抗系统时钟回拨；含明文的恢复点/快照经安全删除（随机覆写）。
- 数据库全参数化 SQL；导入数据卫生清洗（URL scheme 白名单、TOTP 校验、CSV 注入防护）。

### 性能
- 条目搜索全量解密后内存过滤 + EntryCacheManager 多级缓存（摘要/分类名/标签/TOTP）。
- 改密重加密批量化（executemany）；登录/改密/备份/恢复/导入导出/安全分析全部后台线程化。
- 条目列表虚拟化（QAbstractItemModel + 按需绘制）。
- WAL 模式 + 合理索引（`idx_entries_active_updated` 等）。

### 可维护性
- 零 TODO/FIXME 残留；ruff + mypy/pyright 全量通过；docstring 覆盖全部非 `__init__` 模块。
- 字段集与加密字段集「单一事实源 + 加载期断言 + 字段一致性测试」三重守护。
- 配置完整性（HMAC + Windows DPAPI 封装签名密钥 + 原子写入）。
- CI：三 OS × 两 Python 版本矩阵，分层覆盖率门槛，pip-audit 漏洞扫描。

### CI
- 依赖管理迁移至 uv（`uv.lock` 锁定完整传递闭包，CI 用 `uv sync --locked` 验证）。
