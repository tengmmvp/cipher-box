# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

CipherBox（密匣）是一个本地优先的加密密码管理器，使用 Python 3.10+ 和 PyQt6 构建。所有敏感数据通过 AES-256-GCM 加密存储在本地 SQLite 数据库中，无任何网络通信。UI 语言为简体中文。

## 常用命令

```bash
# 安装依赖（uv 按 uv.lock 同步完整传递闭包）
uv sync

# 启动应用
uv run python main.py

# 运行全部测试
uv run pytest tests/

# 运行单个测试文件
python -m pytest tests/test_crypto.py

# 运行单个测试方法
python -m pytest tests/test_crypto.py::TestEncryptionEngine::test_encrypt_decrypt -v

# 也可使用 unittest 运行
python -m unittest discover tests/
```

## 架构

分层架构，依赖方向为 UI → Business → Crypto/Data，各层职责清晰：

### Crypto 层 (`src/crypto/`)
纯密码学原语，无数据库或 UI 依赖。`EncryptionEngine` 提供静态 AES-256-GCM 加解密方法。`MasterKeyManager` 通过 Argon2id（time=3 / 64MB / 并行=4）从主密码派生主材料，再经 HKDF-Expand 按域 info 派生主密钥与备份密钥（显式域分离，替代旧 salt 前缀）。密码验证不存储哈希，而是加密一段已知明文（验证令牌）来确认密码正确性。

### Data 层 (`src/database/`)
SQLite WAL 模式，手动事务管理（begin/commit/rollback）。启动时校验固定格式标识（`cipherbox-schema`）与表结构，不匹配则拒绝打开，不做旧格式迁移。加密字段列名以 `_enc` 后缀标记。数据库层只处理加密后的数据，不了解密钥。数据模型（`@dataclass` 的 `Entry` / `Category` / `CustomField` / `PasswordHistory`）定义在顶层共享层 `src/models.py`，供 UI / Business / Database 三层引用。

### Business 层 (`src/business/`)
编排 Crypto 和 Data 层；顶层 `composition.py`（CompositionRoot）的 `build_business_context` 集中组装 `BusinessContext`（config/vault/cache/change_bus/entry_mgr/security/import_export/backup）并完成跨 manager 回调连线（锁定/变更→缓存失效），供 MainWindow 注入，使 UI 不再自行 new 业务 manager。其余分为两个子包：
- `managers/`（有状态编排）：`VaultManager` 持有加密密钥和数据库连接，是安全边界的核心；`EntryManager` 透明地在写入时加密、读取时解密，因加密字段无法在数据库层面搜索，`get_entries()` 先拉取全部条目解密后在内存中过滤，配套 `EntryCacheManager` 提供摘要/分类名/标签/TOTP secret 多级缓存，经 `EntryChangeBus` 统一「变更→缓存失效→回调」管线，并经 property 暴露 `categories`(`CategoryManager`)/`totp`(`TotpService`)/`password_history`(`PasswordHistoryService`) 子服务（SRP 拆分自原 EntryManager）；`ImportExportManager` 负责导入/导出编排（格式解析拆分至 `managers/importers/` 策略类包：JSON/CSV/KeePass/Bitwarden 各一策略类），导入写入经 `@_validate_import_input` 校验路径后，在 `_import_entries` 的 epoch 守卫事务内原子完成（加密移出 db_lock，MAINT-004）；`BackupRestoreManager` 实现可移植的二进制加密备份格式（持锁核心：创建/恢复/可移植数据采集），使用独立的备份密码派生密钥（经 HKDF 与主密钥域分离），支持跨主密码恢复，经 `restore_points` property 暴露 `RestorePointManager`；生命周期流程（初始化/解锁/锁定/改密/关闭）拆至 `VaultLifecycleOrchestrator`，`VaultManager` 收窄为密钥/db/写守卫核心，经薄委托调用 orchestrator，使调用方（app/login/dialog/test）无需感知编排层
- `services/`（无数据库事务编排的协作模块，可有缓存/派生状态）：`crypto_utils` 统一字段加解密入口与 `SENSITIVE_ENCRYPTED_FIELDS` 单一事实源；`entry_validation` 明文条目校验；`totp_service`/`password_history_service` 条目子域服务；`backup_header_codec`（备份二进制头编解码/检视）、`backup_validator`（恢复前载荷校验）、`backup_paths`（备份文件命名约定）、`backup_payload`（Portable 系列 TypedDict 与 PreparedBackup 载荷类型）、`backup_collector`（可移植数据采集+载荷大小校验）、`backup_rebuilder`（恢复重建纯变换：载荷→加密行逐表回写）、`auto_backup_policy`（自动备份间隔判定/retention 清理纯策略）为 `BackupRestoreManager` 下沉的无状态纯函数模块（SRP 拆分）；`key_manager` 持有/清零主密钥与快照密钥；`metadata_signer` 提供条目元数据、分类元数据与 `vault_meta` 的 HMAC 完整性签名；`re_encryption` 编排改密时的全量重加密；`security_analyzer` 弱密码/重复/过期分析（持 TTL 缓存）；`password_service`/`card_validation` 作为切断 UI→Crypto 跨层依赖的业务门面；`vault_meta_store`（`vault_meta` 键值持久化，供生命周期流程读写 salt/verify/kdf 参数/snapshot_key/mac 等）、`vault_meta_keys`（`vault_meta` 键名常量单一事实源，供 vault_lifecycle/metadata_signer/backup_restore 派生）、`error_messages`（领域异常→用户文案翻译，`to_user_message`）、`database_bootstrap`（初始数据库引导/默认分类注入）、`entry_batch_writer`（导入批量写入加密/落库编排，从 EntryManager 下沉，经 entry_mgr 参数注入加密原语）、`url_hygiene`（URL scheme 卫生清洗纯函数，导入与共享包共用）

### UI 层 (`src/ui/`)
PyQt6 桌面 GUI。`MainWindow` 是中心编排器，经 `BusinessContext`（由 `business/composition.py` 的 `build_business_context` 集中组装并完成跨 manager 回调连线）注入 Business 层 manager，自身仅装配依赖 Qt 线程亲和性的 QObject 控制器（AutoLock/AutoBackup/Clipboard 等）与 UI 子组件；职责经组合化 controller 分离（Mixin 已全部消除）：`main_window.py` 仅保留控件创建、生命周期编排（锁定/关闭/托盘/主题/事件过滤）与 `_locked_ui` 状态广播；菜单/对话框调度、条目 CRUD/分类/右键菜单、筛选/排序/列表刷新/状态栏/worker 分别由 `controllers/menu_controller`、`controllers/entry_actions_controller`、`controllers/list_refresh_controller` 承担（普通类，经冻结 dataclass 回调协作，锁定态守卫统一用 `controllers/_locked_guard.require_unlocked`）。`controllers/`（`entry_list_controller`/`sidebar_controller`/`auto_backup_controller`/`auto_lock_controller`/`menu_controller`/`entry_actions_controller`/`list_refresh_controller`/`list_refresh_helpers`（list_refresh 抽出的 EmptyState/StatusBar 纯渲染辅助））承载数据到控件的映射与生命周期逻辑，`components/` 承载可复用控件（详情面板、条目列表、TOTP、密码历史等）。`resources/` 子包为 UI 共享资源层：`theme_colors.py` 定义 80+ 颜色 token（浅色/深色），`styles.py` 渲染 QSS 样式表，`radius.py` 集中圆角档位常量，`font_loader.py` 启动期注册打包的 Inter 变量字体，`icons.py` 经 QtAwesome 语义化常量管理图标，`strings.py`/`constants.py` 汇集 UI 文案与尺寸/时长常量（其中 `constants.py` 运行时从 `src/config.py` 派生部分默认值，是有意的单一事实源设计，故 `resources/` 非纯声明式）。`error_messages.py` 统一领域异常→用户文案翻译。`ui/utils/` 承载依赖 PyQt6 的 UI 专用工具（如 `clipboard`），与跨层共享的 `src/utils/` 区分以保持共享层零上层依赖。

### 共享层
`src/models.py`（`Entry`/`Category`/`CustomField`/`PasswordHistory` 数据模型与字段常量）、`src/exceptions.py`（领域异常层次）、`src/config.py`（配置管理与完整性校验）、`src/logging_config.py`（脱敏日志）、`src/utils/`（`file_security`/`memory`/`format`/`purge_files` 工具）均为零上层依赖的共享基础设施，供 UI/Business/Database 三层引用（依赖 PyQt6 的 UI 工具归 `src/ui/utils/`，如 `clipboard`，不放入 `src/utils/`）。

### 应用入口
`CipherBoxApp`（`src/app.py`）管理生命周期：登录 → 主窗口 → 锁定 → 重新登录。`VaultManager` 实例贯穿整个生命周期。

## 关键约定

- **安全优先**：主密码永不明文存储；每个加密值使用独立随机 12 字节 nonce；Argon2id 参数（time/memory/parallelism）遵循 OWASP 建议
- **事务安全**：主密码修改和备份恢复包裹在数据库事务中，失败时回滚。配置保存使用原子写入（写 .tmp 后 `os.replace`）
- **软删除**：条目支持移入回收站和恢复，不直接物理删除
- **条目类型**：5 种模板（login/card/identity/note/server），由 `src/models.py` 中的常量定义
- **数据目录**：Windows 下为 `%APPDATA%\CipherBox\`，包含 `vault.db`、`config.json`、`backups/`、`logs/`
- **备份与恢复点**：恢复备份前自动创建恢复前快照（`pre_restore_*.cbox`，含恢复前全部条目明文，用保险库快照密钥加密）。改密与恢复均会轮换 `snapshot_key` 并自动清理旧快照与恢复点以收缩泄漏面，亦可在备份对话框手动清理
- **审计编号**：代码注释中的改进决策标注统一为 `<维度>-NNN` 三位零填充（`ARCH`/`MAINT`/`PERF`/`QL`/`SEC` 五维度），索引与新增登记见 `docs/audit_codes.md`；同号不再跨决策复用
