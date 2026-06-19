# CipherBox 架构文档

本文档沉淀 CipherBox 的分层架构与关键设计决策，供后续接手者快速建立心智模型。
代码注释已记录多数局部权衡，此处仅汇总跨模块的不变量与边界。

## 1. 分层架构

依赖方向严格单向：**UI → Business → Crypto / Data**。`src/models.py` 是跨层共享
的数据模型层（`Entry` / `RawEntry` / `Category` / `CustomField` / `PasswordHistory`），
供三层引用，不依赖任何业务或数据访问逻辑。

| 层 | 目录 | 职责 | 依赖 |
|----|------|------|------|
| Crypto | `src/crypto/` | 纯密码学原语（AES-256-GCM、Argon2id、TOTP、密码生成） | 无 DB/UI |
| Data | `src/database/` | SQLite 持久化（schema、Repository、装饰器、连接/事务） | models |
| Business | `src/business/` | 编排 Crypto + Data，持有密钥与缓存 | Crypto、Data |
| UI | `src/ui/` | PyQt6 桌面 GUI，经 Business 访问数据 | Business |
| 共享 | `src/utils/`、`src/models.py`、`src/exceptions.py`、`src/config.py` | 工具、模型、异常、配置 | — |

**反向依赖禁止**：Crypto 层绝不依赖 Business/Data；Data 层不了解密钥（只处理密文）。

### 1.1 Business 层的 SRP 拆分

Business 层按「有状态编排」与「无状态服务」分为两个子包，模块清单如下（详细职责见
各模块 docstring 与 `CLAUDE.md`）：

- **`managers/`（有状态编排，持有 vault/密钥/缓存引用）**
  - `VaultManager`：安全边界核心，持有主密钥与数据库连接，生命周期贯穿登录→主窗口→
    锁定；改密/恢复在其 `vault_write_lock` 下串行化。
  - `EntryManager`：条目 CRUD，透明加解密；经 property 暴露子服务 `categories`
    （`CategoryManager`）/ `totp`（`TotpService`）/ `password_history`
    （`PasswordHistoryService`）。
  - `EntryCacheManager`：摘要/分类名/标签/TOTP secret 多级缓存（LRU + epoch 失效）。
  - `EntryChangeBus`：统一「变更→缓存失效→回调」管线，支持 crypto_id 单条精细失效。
  - `ImportExportManager`：CSV/JSON/浏览器导入导出，经 `@_transactional_import`
    保证写入原子性。
  - `BackupRestoreManager`：可移植二进制加密备份格式；经 `restore_points` property
    暴露 `RestorePointManager`（恢复点统计/清理）。
- **`services/`（无状态业务服务：加解密、校验、分析等，密钥经 vault 引用现取）**
  - 加解密与字段：`crypto_utils`（`SENSITIVE_ENCRYPTED_FIELDS` 单一事实源、统一加解密
    入口）、`entry_validation`、`password_service`、`card_validation`。
  - 条目子域：`totp_service`、`password_history_service`。
  - 完整性与重加密：`metadata_signer`（HMAC 签名）、`re_encryption`（改密全量重加密）、
    `security_analyzer`（弱密码/重复/过期分析）、`key_manager`（主密钥/快照密钥集中
    持有与清零）。
  - 备份无状态模块：`backup_header_codec`、`backup_validator`、`backup_paths`。

拆分原则：跨管理器协作走显式依赖注入（构造函数传入），不使用函数内延迟 import 规避
循环依赖；UI→business.services 纯函数模块是合法分层方向，无需经 manager 门面转发。

## 2. 加密设计

### 2.1 主密钥派生
- **KDF**：Argon2id（OWASP 推荐：`time_cost=3` / `memory_cost=64MB` / `parallelism=4`）。
- **盐**：每个保险库 32 字节随机盐，存于 `vault_meta.master_salt`。
- **密码验证**：不存哈希。加密一段已知明文（`VERIFY_PLAINTEXT`）作为验证令牌
  （`master_verify`），用 `hmac.compare_digest` 常数时间比对解密结果。
- **KDF 参数校验**：`MasterKeyManager._validate_params` 在派生前强制参数下限
  （`MIN_ARGON2_*`），防止 `vault_meta` 被篡改为弱参数。**注意**：即便参数被篡改，
  派生密钥会随之改变，导致 `master_verify` 解密失败 → 用户无法解锁（DoS），
  而非「静默降级暴力破解」——攻击者无法通过篡改 KDF 参数降低自身的离线暴力成本，
  因为验证令牌始终以原始参数派生的密钥加密。

### 2.2 字段级加密
- **算法**：AES-256-GCM，每个值独立 12 字节随机 nonce。
- **AAD**：`entry_aad(crypto_id, field_name)` 即 `entry:{crypto_id}:{field_name}`，
  绑定密文到具体条目与字段，防止密文置换/回滚。分类名用 `category_crypto_id(id)`。
- **密文格式**：`cb2:` 前缀 + base64(nonce + ciphertext + tag)。`_assert_encrypted`
  在数据层强制此前缀，防止明文静默落入加密列。

### 2.3 加密字段集单一来源
`crypto_utils.SENSITIVE_ENCRYPTED_FIELDS`（8 字段）是加密字段的单一事实来源，
被 `key_rotation` 重加密、加解密辅助引用。`MetadataSigner._payload` 对全部 8 个
加密字段签名（明文字段 title/url/tags 直接进签名 JSON，密文字段用 `_enc_hash`
绑定），无漏签。`tests/test_field_consistency.py` 守护字段集一致性。

## 3. 密钥生命周期

`KeyManager`（`src/business/services/key_manager.py`）集中持有主密钥、快照密钥与
密钥版本（epoch），统一清零：

- **bytearray 持有**：密钥以 `bytearray` 持有，使 `secure_zero_buffer` 能原地清零。
  `key` / `snapshot_key` property 返回 `bytes` 副本，调用方持有的副本不受 `clear()`
  清零影响。
- **CPython 固有限制**：`bytes` 不可变，OpenSSL 内部密钥副本依赖 GC 回收。
  `lock()` 主动 `gc.collect()` 缩短驻留。
- **epoch 守卫**：`key_epoch`（UUID）随改密/恢复轮换。`_enforce_key_epoch` 在每次
  写库前比对内存 epoch 与 `vault_meta.key_epoch`，不匹配则清除状态拒绝写入，
  防止改密后旧会话用旧密钥写入导致数据损坏。

## 4. 完整性签名

`MetadataSigner` 用主密钥派生的域密钥（`compute_domain_key`）对 `entries` 表行做
HMAC-SHA256 签名（`metadata_mac` 列）：

- 签名载荷含全部元数据字段 + 加密字段密文的 SHA-256 摘要，绑定密文防置换。
- **不改 epoch 显式入载荷**：跨 epoch 隔离由域密钥本身提供（主密钥变 → 域密钥变 →
  旧签名验证失败）。
- **校验模式**（`VerifyMode`）：`STRICT`（单条详情，失败抛异常）、`LENIENT`（全量
  解密，标记不抛）、`SKIP`（列表/搜索/标签高频路径，跳过 HMAC 以优化性能，篡改由
  STRICT 与写路径重签兜底；解密损坏仍由 strict 解密异常捕获并标记）。

## 5. 事务与并发

- **WAL 模式** + 手动事务（`begin`/`commit`/`rollback`），`synchronous=FULL`。
- **db_lock（RLock）**：所有 DB 操作经 `@_db_operation`/`@_db_write` 持锁。
- **vault_write_lock**：串行化接触全量明文的长操作（改密/重加密/备份/恢复）。
- **取消机制**：`threading.Event`（`_cancel_event`）通知长操作（重加密/全量分析）
  提前中止并回滚，避免 `lock()` 阻塞等锁致 UI 冻结。

## 6. RawEntry 与 Entry 双类型

- `RawEntry`：数据库行直射，加密字段为密文字符串。
- `Entry`：解密后的明文条目，敏感字段（password/totp_secret）以 `Sensitive` 包装。
- `copy_entry_fields` / `build_entry_summary` 处理二者转换。分离避免明文与密文态
  混用导致意外泄漏。`tests/test_field_consistency.py` 守护二者字段名一致。

## 7. 备份与恢复

`BackupRestoreManager` 实现可移植的二进制加密备份格式：

- **独立密钥域**：备份密码经 `derive_backup_key`（`b'backup:' + salt` 前缀）派生独立
  密钥，与主密钥域分离，支持跨主密码恢复。
- **固定头**：magic + flags + Argon2 参数 + salt，随后 AES-GCM 加密的 JSON payload。
- **恢复前快照**：恢复前用 `snapshot_key` 加密全量明文生成 `pre_restore_*.cbox`，
  恢复失败可回滚。恢复/改密轮换 `snapshot_key` 并清理旧快照以收缩泄漏面。
- **启动重试清理**：`purge_restore_points` 在应用启动时重试删除之前 purge 失败的
  `pre_restore_*.cbox` 残留（重启后占用进程已释放）。

## 8. 配置完整性

`ConfigManager` 对 `config.json` 做 HMAC-SHA256 签名（签名行附在文件末尾）：

- **安全关键键回退**：签名失败/缺失时，`auto_lock_minutes` 等安全键回退默认值，
  `get_safe` 再施加运行时下限，构成 load + 读取双层防御。
- **哨兵机制**：`RateLimiter` 用哨兵文件区分「首次使用」与「状态被恶意删除」，
  后者降级最高阶梯锁定。
- **本地威胁模型限制**：`config.key`（签名密钥）与配置同目录同权限，具备该目录
  读写权限的本地攻击者可重算签名。彻底修复需 OS 级机制（如 Windows DPAPI 封装
  `config.key`），属 feature 级改动。

## 9. 安全自省与已知边界

代码注释诚实标注了若干「本地威胁模型下的固有限制」，便于审计：

- CPython `bytes` 不可变，密钥原地清零是「尽力而为」。
- 配置签名密钥同权限，不防有意篡改。
- 恢复点 purge 失败时旧明文可能残留（启动重试 + 手动清理缓解）。
- 限流仅防在线尝试，主密码强度才是抗离线破解的根本（累进退避封顶 10 分钟）。

新增安全相关逻辑时，请延续此「注释说明威胁模型与边界」的传统。
