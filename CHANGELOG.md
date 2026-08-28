# 变更日志

本项目所有显著变更记录于此文件。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 性能
- 列表排序下推字段化：8 种排序中 6 种（更新时间/强度/创建时间双向）可 SQL
  `ORDER BY 字段 LIMIT` 下推——50k 库非默认排序全量路径 1756ms → ~50ms；
  标题序因密文列无法 SQL 排序保持全量（加密架构固有限制，注释声明）。
- 搜索路径窄投影：6 列投影替代宽行物化（实测 ~9×），命中行按 id 回查完整行
  做验签与摘要构建；50k 温态搜索 681→~250ms。
- 导入去重窄投影：去重对照只拉 title/username 三元组（50k 冷缓存 1834→~900ms）。
- 单条编辑增量分析差分：两次 O(n) 列表重建改就地移除 + 指纹反向索引，
  UI 线程 41-126ms → ~9ms（20k 库实测，规模近似常数）。
- Windows ACL 收紧/SID 提取 ctypes 化（子进程保留为回退）：收紧 41.5ms →
  0.4ms/文件（~100×），启动链省约 215ms，消除企业策略禁 whoami 的脆弱性。

### 安全
- 导入时间戳校验改归一化：空格分隔/Z 后缀/截断时间等可解析变体统一归一为
  标准 ISO 形态后落值（拒绝式校验实测存在绕过变体）；备份恢复路径共用同一
  归一函数，消除恢复绕过导入约束的分叉。
- 导入文件上限按同型口径（payload×2）从 200MB 下调至 80MB，物化峰值防护
  窗口收紧 2.5 倍。
- 修复首次建库会话的锁定写守卫失效（`activate_keys` 漏置 `_ever_unlocked`）。
- 共享包解密器补 4MB 大小上限与读取失败反馈；导出链补缓存世代守卫。

### 重构
- services 层依赖收窄「一删三协议两锚定」：删除 TotpService 零读取的 vault
  死依赖；KeyProvider/PasswordHistory/AnalysisCache 最小协议替代具体类
  TYPE_CHECKING 依赖；同构依赖显式锚定维持理由。
- UI 展示键集常量化 + 模块加载期完备性自检（新增类型漏更新文案表时启动即报，
  优于静默回退）。

### 修复与工程化
- `custom_fields` 非 list 形态显式拒绝导入（原静默置空丢字段无感知）；
  侧边栏锁定守卫责任显式声明；分类批量通知参数对齐。
- 导出序列化拆分 `managers/exporters/` 策略包（与 `importers/` 对称）；
  条目类型展示属性下沉 UI 资源层。
- CSV 导出进度终值契约、增量分析时钟注入、缓存引用拷贝与 LRU 联动等修复
  补齐守护测试（「修复了但没锁」收口）。
- ruff 启用 S/PERF 规则组使既有豁免真实生效；pre-commit 对齐 CI 命令形态。
- 重构残留的过时 docstring（已删符号引用、与实现矛盾声明、失实历史表述）
  批量修正；CHANGELOG 1.0.0 转正、审计索引漂移修正、零消费 re-export 清理。

## [1.0.0] - 2026-08-22

首个正式版本（`0.1.0.dev0` 开发占位于此终结）。以下为开发阶段经多轮五维度审查
（架构/代码质量/性能/可维护性/安全）沉淀的基线变更。

### 重构
- **主窗口拆分**：MainWindow 收窄为中心编排器，菜单/条目 CRUD/筛选刷新等职责
  拆至 `controllers/` 普通类（`menu_controller` / `entry_actions_controller` /
  `list_refresh_controller` 等），经冻结 dataclass 回调协作，控制单文件规模。
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
- CI：三 OS × 三 Python 版本矩阵，分层覆盖率门槛，pip-audit 漏洞扫描。

### CI
- 依赖管理迁移至 uv（`uv.lock` 锁定完整传递闭包，CI 用 `uv sync --locked` 验证）。
