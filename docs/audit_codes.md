# 审计编号索引

代码注释中的审计编号（5 维度）登记表，供跨文件 grep 追踪同一改进决策的所有触点。

## 编号约定（新增遵循）

- **格式**：`<维度前缀>-NNN`，三位零填充（如 `SEC-003`、`PERF-012`、`ARCH-005`）。
- **维度前缀**：`ARCH`（架构）/ `MAINT`（维护·可维护性）/ `PERF`（性能）/ `QL`（质量·可读性）/ `SEC`（安全）。
- **编号分配**：新编号 = 该维度当前最大已用号 +1；历史断档（如 ARCH-012→021、
  MAINT-041→071）是批次审查的既成事实，**不回填**。当前下一可用：
  `ARCH-046 / MAINT-101 / PERF-085 / QL-068 / SEC-056`（由
  `scripts/verify_audit_codes.py` 校验，登记新编号后同步前移；CI 持续把关索引-代码一致性）。
- **新增编号**须在本文件对应维度表登记，避免跨文件漂移与编号复用。
- **双向引用**：新编号除登记索引外，须在对应代码注释以 ``（XXX-NNN）`` 引用，保证索引-代码一致（MAINT-014）。纯约定/已放弃编号（处数=0）豁免。
- **处数口径**：「处数」列按 ``src/**/*.py`` 内该编号的引用次数统计（rg 可复算）；
  引用仅在 src 之外的编号记 0 并在处数单元格加注位置（MAINT-008=ci.yml、
  MAINT-013=tests、MAINT-041=ci.yml 与 CLAUDE.md）。

## 历史重编号说明

早期存在两套并行的编号体系——未填充的 `SEC-1`/`MAINT-1`/`ARCH-3`/`QL-3`/`PERF-1` 与
填充的 `SEC-001`/`MAINT-001`/...，且性能维度有 `PF-`/`PERF-` 双前缀，同号异义冲突
（如 `SEC-2`=0600 落地窗口 ≠ `SEC-002`=key_epoch 校验）。2026-08 全量重编号为统一的
`PREFIX-NNN` 三位零填充格式，消除同号异义冲突（重编号当时连续；其后各批次审查按
「最大已用号 +1」分配，形成今日断档，见上节规则，不回填）。下表「旧编号」列保留以
追溯 git 历史 commit message 中的旧编号引用。

## 映射表（新编号为主序）

### ARCH — 架构（28 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `ARCH-001` | `ARCH-001` | 3 | """预扫描条目分类名，批量创建缺失分类并回填 ctx.categories（ARCH-001）。 |
| `ARCH-002` | `ARCH-002` | 2 | # ARCH-002：注入批量写回调，解耦 backup_rebuilder 与 EntryManager。 |
| `ARCH-003` | `ARCH-003` | 9 | 事件经独立回调通道触发（ARCH-003），详见下方注册处注释。 |
| `ARCH-004` | `ARCH-004` | 4 | 命令-查询分离（ARCH-004）：本 property 仅查询，不打开/关闭数据库。db 文件不 |
| `ARCH-005` | `ARCH-005` | 13 | 比对内存与库内 epoch 不一致时抛出（ARCH-005）：中止读路径以防用旧密钥解密新密文 |
| `ARCH-006` | `ARCH-006` | 3 | # ARCH-006：恢复点创建/统计/清理统一由 RestorePointManager 承载。备份加密管线 |
| `ARCH-007` | `ARCH-008` | 2 | 行为钩子（ARCH-007）以布尔标志形式挂入，消除消费方 ``if entry_type ==`` |
| `ARCH-008` | `ARCH-009` | 5 | # 应用全局样式；显式激活主题，使运行时 c() 解析的颜色与样式表一致（ARCH-008） |
| `ARCH-009` | `ARCH-019` | 1 | # sqlite 事务 + QThread running 析构崩溃（ARCH-009）。 |
| `ARCH-010` | `ARCH-024` | 3 | # 只读映射（MappingProxyType 防误写，ARCH-010）：均派生自 _INT_SPECS。 |
| `ARCH-011` | `ARCH-3` | 1 | # 的值再签，与恢复路径对称，消除手工键集漂移（ARCH-011）。回读须在调用方事务内， |
| `ARCH-012` | — | 1 | list_refresh_controller 删除 UI 侧重复的锁定缓存失效调用（组合根 register_on_lock 已连线，失效幂等但双源易漂移）。 |
| `ARCH-021` | — | 2 | update_entry 的 preserve_updated_at 参数退役（协议/委托/实现三层删除）：唯一 True 调用方是测试，恢复路径已改走 update_overwrite_batch。 |
| `ARCH-031` | — | 4 | CategoryStore 协议补 update_categories_batch，crypto_utils.encrypt_plaintext_category_names 参数解绑具体 DatabaseManager 改标 VaultDataStore，re_encryption 局部协议删除。 |
| `ARCH-032` | — | 7 | EntryViewDecryptor 的 cache 依赖改最小协议 ViewDecryptCacheProtocol（对齐 TotpService 模式，services 不反向依赖 managers 具体类）。 |
| `ARCH-033` | — | 2 | 组合根子服务装配规则显式化：有自持状态/独占缓存的组合根显式注入；纯变换/共享缓存无状态的宿主内部构造共用同一 cache 实例。 |
| `ARCH-034` | — | 2 | 双源常量收编：security_analyzer.DEFAULT_ANALYSIS_DAYS 改 import config.OLD_PASSWORD_WARNING_DAYS_DEFAULT（QL-005 的本地解耦理由已失效，business→config 合法），ui/constants.RECENT_ENTRY_LIMIT 改引 business 的 DEFAULT_RECENT_SUMMARIES_LIMIT（UI→business 合法，业务默认成唯一源）。 |
| `ARCH-035` | — | 2 | 主题默认值单一事实源：constants.THEME_LIGHT 与 theme_colors._current_theme 模块初值均直接派生自 config.DEFAULT_THEME（UI→config import 合法，无循环），消除三处 'light' 字面量靠注释约定同值的漂移面。 |
| `ARCH-036` | — | 1 | SidebarController 锁定态守卫责任显式化：方法均有返回值故不可套 require_unlocked（特化 Callable[...,None] 锁定返 None 是类型谎言），改为模块 docstring 声明「守卫在调用方」并列出各调用链现状与新增调用方须保持的隔离要求。 |
| `ARCH-037` | — | 9 | 条目类型展示属性下沉 UI：models.ENTRY_TYPES 收敛为 frozenset 类型键集合（仅合法性判定），中文 label 与图标占位符移 ui/resources/strings.py（ENTRY_TYPE_LABELS/ICONS + 带 login 回退的查表函数），Entry/RawEntry 的 type_icon/type_label property 与 EntryTypeSchema 的 label/icon 转发字段删除（后者无生产消费方）。 |
| `ARCH-038` | — | 8 | 导出格式策略包：export_to_json/export_to_csv 的序列化内联块拆 managers/exporters/（json_exporter/csv_exporter 写回调 + base 的 csv_safe 与密钥列豁免），manager 收窄为路径校验+原子写编排骨架，与 importers/ 对称；_sanitize_formula_prefix 随之下沉 services/url_hygiene（公共名 sanitize_formula_prefix，避免 manager↔exporters 循环）。与 importers 的差异为显式取舍：exporters 无策略协议/注册表——导出为用户显式选格式直调对应方法，无 dispatch 场景，2 格式下强行对称为过度抽象；格式≥3 或需按扩展名 dispatch 时再引入 FormatExporter 协议。 |
| `ARCH-039` | — | 11 | services 对 managers 具体类依赖的「一删三协议两锚定」：TotpService 删除零读取的 vault 死依赖（单参构造）；crypto_utils 定义 KeyProvider 两成员协议（require_vault_key/entry_view_decryption 共用）；password_history_service 的 PasswordHistoryVaultProtocol（KeyProvider+db+vault_write_lock）；security_analyzer 的 AnalysisCacheProtocol 四成员协议。security_analyzer 的 vault 依赖与 entry_batch_writer 整体**维持** TYPE_CHECKING 具体类并锚定理由（成员面与 VaultManager/EntryManager 核心同构，协议是影子类无净收益）。 |
| `ARCH-040` | — | 3 | strings.py 展示键集常量化+完备性自检：ENTRY_TYPE_LABELS/ICONS 键改用 models 的 ENTRY_TYPE_* 常量（消除与 frozenset 的字面量双源），模块加载期 if+RuntimeError 断言键集==ENTRY_TYPES（对齐 _ENTRY_COLUMNS 启动自检形式，-O 存活）——新增类型漏更新表时启动即炸，优于 UI 静默回退 login 文案。 |
| `ARCH-041` | — | 1 | DEFAULT_RECENT_SUMMARIES_LIMIT 移入 models 共享层，解开 ui/resources/constants 对业务栈的模块级依赖。 |
| `ARCH-042` | — | 12 | change_master_password 返回契约对齐 unlock——(False,...) 仅认证失败，策略失败抛 MasterPasswordPolicyError、系统错误走异常通道，UI 不再文案字符串比对。补全：系统错误包装改用无固定映射的 VaultError 本体（to_user_message 增纯 VaultError 保留 str 分支），worker error 通道二次翻译不再被 VaultLockedError 罐头文案「保险库已锁定，请先解锁后重试」覆盖（磁盘满/IO 错误时误导）；unlock/initialize 同款接入，「保险库凭据不完整」终译保留原文。 |
| `ARCH-043` | — | 9 | RateLimiter 状态文件名常量归业务模块、实例经组合根工厂创建注入 UI 对话框（ARCH-033 纪律回归）。 |
| `ARCH-044` | — | 8 | VaultLifecycleOrchestrator 改从 vault 单一装配参数取 db/signer；build_business_context 加 WeakSet 防重入守卫。 |
| `ARCH-045` | — | 5 | 恢复阶段方法以 RestoreAbortedError（BackupError 子类）替代 result-or-tuple 联合返回。 |

### MAINT — 维护/可维护性（38 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `MAINT-001` | `MAINT-001` | 1 | 包裹解密到 WAL 截断）由各阶段方法与 try/finally 维护（MAINT-001）。 |
| `MAINT-002` | `MAINT-002` | 1 | """两阶段加密写入单分类（MAINT-002）：占位 id 加密 INSERT → 真实 id 重加密 UPDATE。 |
| `MAINT-003` | `MAINT-003` | 1 | # add_entry 对称（MAINT-003）：UPDATE 含 category_id 外键，引用不存在的分类时 |
| `MAINT-004` | `MAINT-004` | 21 | """覆盖项加密预处理结果（MAINT-004）：写阶段所需的最小密文载荷。 |
| `MAINT-005` | `MAINT-005` | 1 | # 配置键名常量（MAINT-005 单一事实源）：DEFAULT_CONFIG / _INT_SPECS / _BOOL_KEYS / |
| `MAINT-006` | `MAINT-008` | 1 | 编排分两步（MAINT-006）：事务内重加密+元数据 → 事务后激活密钥+清理；异常兜底与 |
| `MAINT-007` | `MAINT-009` | 5 | default_category_id/duplicate_action/source_label 参数（MAINT-007），使方法签名 |
| `MAINT-008` | `MAINT-010` | 0（ci.yml） | # 分层覆盖率门槛（分支覆盖，MAINT-008）：开启 --cov-branch 后分支率严格 ≤ 行率， |
| `MAINT-009` | `MAINT-011` | 1 | # 限制 csv 解析器单字段最大长度（MAINT-009）：默认 128KB 与本项目逐项大小策略 |
| `MAINT-010` | `MAINT-019` | 1 | 统一字符类型校验为单一事实源（MAINT-010）。有效时错误信息为空串，无效时返回 |
| `MAINT-011` | `MAINT-1` | 1 | # 分支于测试框架存在性（MAINT-011）。 |
| `MAINT-012` | `MAINT-2` | 1 | # 平台判定单一常量（MAINT-012）：统一引用，避免 os.name=='nt' 与 sys.platform=='win32' 混用 |
| `MAINT-013` | `MAINT-3` | 0（tests） | """BackupDialog 接线测试：控件值→业务参数→结果文案（MAINT-013）。 |
| `MAINT-014` | — | 0 | 审计编号双向引用约定：新编号须在代码注释 ``（XXX-NNN）`` 引用，使 rg 可从代码回溯决策（本轮 PERF-017/QL-015/QL-016/QL-017 已补齐；纯约定/已放弃编号处数=0 豁免）。 |
| `MAINT-015` | — | 5 | EntryManager/BackupRestoreManager 的子 manager 参数改必传，删除 ``or`` 兜底构造，组合根显式注入契约由约定升级为签名强制。 |
| `MAINT-020` | — | 4 | config.py 签名密钥平台存储链（DPAPI→keyring→明文回退）下沉 ``src/config_key_store.py``，ConfigManager 组合持有并经 ``integrity_key`` property 供业务层复用。 |
| `MAINT-021` | — | 8 | EntryManager 视图解密族（detail/export/summary 三视图 + 严格/容错字段解密，约 300 行）下沉 ``services/entry_view_decryption.py``（``EntryViewDecryptor``），EntryManager 公开方法保持薄委托、调用方零改动。 |
| `MAINT-041` | — | 0（ci.yml、CLAUDE.md） | 命令统一 ``uv run -m <module>`` 形式（pytest/mypy/pyright/coverage）：trampoline 入口在部分 uv/Windows 组合报 canonicalize 失败；引用位于 ci.yml 与 CLAUDE.md（非 .py，处数按代码口径为 0）。 |
| `MAINT-071` | — | 8 | entry_repository（844 行全库最大）的密码历史块拆分 ``password_history_repository.py``（7 方法单表访问，镜像 category_repository 模式），DatabaseManager 委托纯搬迁零增减。 |
| `MAINT-081` | — | 0 | ``tests/utils/test_clipboard.py`` git mv 至 ``tests/ui/``：被测对象为 ``src/ui/utils/clipboard.py``，恢复 tests↔src 目录镜像约定（文件内均为绝对导入，移动零改动）。（tests 内的历史触点已随后续测试重构移除，全库无引用。） |
| `MAINT-082` | — | 0 | CHANGELOG 1.0.0 转正：Unreleased 段转 ``[1.0.0] - 2026-08-22`` 并终结 ``0.1.0.dev0`` 开发占位引用（版本已随 fa3d536 升至 1.0.0 但变更记录未跟随）。纯文档修正，代码无触点。 |
| `MAINT-083` | — | 0（pyproject.toml） | ruff select 补 ``S``/``PERF``：原 per-file-ignores 的 S105/S608/S603/PERF203 条目与代码内 14 处 nosec B608 全部空转（规则未启用、注释承诺的 lint 门禁不存在）；新增 app.py S110 行内豁免、password_history_repository S105 与 tests/** 测试固有形态整目录豁免，check src tests 全过使门禁真实生效。 |
| `MAINT-084` | — | 0（.pre-commit-config.yaml） | pre-commit entry 统一 ``uv run -m <module>``（pyright 为 ``uv run python -m pyright``），对齐 MAINT-041 的 CI 命令形态——裸 trampoline 入口在部分 uv/Windows 组合报 canonicalize 失败，与文件自述「与 CI 完全同源」矛盾。 |
| `MAINT-085` | — | 2 | crypto/ 与 business/managers/ 两个 ``__init__.py`` 的零消费类 re-export 删除（全库无 ``from src.crypto import X``/``from src.business.managers import X`` 类导入，无检查守护的声明面随时间漂移为谎言 API）；importers/ 的 re-export 有真实消费方（import_export 经包级导入四个类）保留。 |
| `MAINT-086` | — | 1 | backup_restore 恢复点 docstring 的「见恢复流程未尽事项」悬空指向删除：全库不存在该文档/章节（可能仅存于早期 commit message），追溯承诺无法兑现。 |
| `MAINT-088` | — | 0 | 第五轮守护测试补齐：QL-055 导出进度终值（test_export_progress，跳过条目 processed==total 可达 + 取消语义）；QL-056 get_failed_fields 拷贝与 QL-058 LRU 淘汰联动（test_username_cache，monkeypatch 解密与容量构造）；QL-057 now 注入增量时钟（test_security_analyzer，注入未来时钟重判过期）。「修复了但没锁」缺口的收口。（守护测试经 QL-055/056/057 各自编号锚定；tests 内 MAINT-088 标注已随后续测试重构移除。） |
| `MAINT-089` | — | 1 | update_entry 手写 epoch 事务样板收敛至 epoch_guarded_transaction(pre_epoch=)。 |
| `MAINT-090` | — | 1 | update_entry 的 preloaded_raw/preloaded_old_password 死参数删除。 |
| `MAINT-091` | — | 6 | 排序键单一事实源 entry_sort_key；删除 _fetch_for_filter 冗余重排（worker 线程读 QComboBox 一并消除）。 |
| `MAINT-092` | — | 4 | get_entry_summaries 190 行单体拆分（_SummaryRead 快照 + 搜索投影/SQL 下推两个私有构建方法）。 |
| `MAINT-093` | — | 6 | security_dashboard tab 元数据表驱动创建与懒填充分发，消除三方法复制与魔法索引。 |
| `MAINT-094` | — | 6 | 5 个对话框 _setup_ui 对齐 entry_dialog 的 _build_* 分块模式。 |
| `MAINT-095` | — | 9 | 测试观察用只读 property（QL-044 先例推广）：_HealthScoreWidget.score、_StatCard.count_text、EntryRefreshCoordinator.entry/tag_refresh_generation、EntryCacheManager.cache_epoch/search_metadata_cached_ids、EntryViewDecryptor.cache——测试对内部态的直读/直改收敛为公开观察面，生产行为零变化。 |
| `MAINT-096` | — | 3 | _restrict_windows_acl_via_api 127 行单体按「取 SID→构造 ACL→应用」三步拆私有函数 + 编排壳，ctypes 调用序列与 LocalFree 释放语义逐路径等价（Win32 直读测试守护）。 |
| `MAINT-097` | — | 4 | crypto_utils 名实相符收窄：搜索谓词拆出 entry_search_match、视图构造并入 entry_view_decryption、decrypt_entry_to_portable_dict 归位 backup/collector，原模块仅留加密单一事实源。 |
| `MAINT-098` | — | 1 | EntryManager.get_entries 退役（src 零调用、测试 40+ 处的「一次性解密全部密码」入口）：方法删除，等价测试助手移 tests/helpers.decrypt_all_entries（经 db.get_entries + decrypt_entry 公开 API 组装），防回退守护断言方法不存在。 |
| `MAINT-099` | — | 4 | 进度契约收敛至 entry_batch_writer（进度契约的家）：phase_progress(done,total,start,end) 加权映射（import_export._phase_progress 与 backup_restore._weighted_progress 字节级重复，改为薄委托）+ should_report_progress(done,total) 节流谓词（`% EVERY == 0 or done == total` 的 10 处手抄全库替换，含 exporters/entry_manager/rebuilder/collector）。 |
| `MAINT-100` | — | 1 | PERF-079 五处失效咒语收敛：add/update/delete/restore/permanent_delete 各自手写的「apply_tag_delta + invalidate_entry_counts_cache + notify kwargs」组合统一为 EntryManager._notify_entry_structure_changed 私有 helper（old_tags=None 表解密失败保守整表失效；EntryChangeBus 协议不动）。 |

### PERF — 性能（47 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `PERF-001` | `PF-001` | 27 | ``key`` 为 PERF-001 并发修补（M3）：调用方（如 :meth:`EntryManager.get_entry` |
| `PERF-002` | `PF-001-R` | 2 | # PERF-002：清理异常就地捕获降级 warning，不漂移致「备份已成功却被误报失败」 |
| `PERF-003` | `PF-002` | 1 | # 短路（PERF-003）：详情面板已显示同一条目（id + updated_at 未变）时跳过重复 |
| `PERF-004` | `PF-003` | 4 | """批量新增分类（恢复路径），返回按输入顺序的新 id 列表（PERF-004）。 |
| `PERF-005` | `PF-004` | 1 | # 复用面板已解密明文（PERF-005）：右键复制密码的常是当前详情条目，直接取其已解密 |
| `PERF-006` | `PF-005` | 6 | prepared 阶段逐条解密（PERF-006：不在 _prepare_overwrite_batch 批量预解密致全部旧密码同刻 |
| `PERF-007` | `PF-008` | 1 | count_files + secure_purge 各 glob 一遍同目录同模式（PERF-007），但恢复点文件 |
| `PERF-008` | `PF-009` | 1 | # CategoryManager.get_categories 在解密后按 name.casefold() 完成（PERF-008）。 |
| `PERF-009` | `PF-010` | 2 | 快照避免每条经 ``self._key`` 复制密钥（PERF-009）。失败回退空串，与 |
| `PERF-010` | `PERF-002` | 4 | # PERF-010：逐条解密已含 GCM 认证，_classify_entry 双重判定损坏， |
| `PERF-011` | `PERF-004` | 1 | # PERF-011：默认列表视图 ORDER BY is_favorite DESC, updated_at DESC 的复合索引， |
| `PERF-012` | `PERF-005` | 1 | # 阈值由 100 下调至 50（PERF-012）：冷缓存下 50-100 条目的全量摘要解密（每条 4 字段 |
| `PERF-013` | `PERF-1` | 2 | # 标签聚合仅需 tags 字段，用 VerifyMode.SKIP 跳过逐行元数据 HMAC 验签（PERF-013）。 |
| `PERF-014` | `PERF-2` | 2 | 不含 Entry 列表，获取时无需 :meth:`_refilter_cache` 深拷贝（PERF-014）。 |
| `PERF-015` | — | 0 | （已放弃）HMAC 验签结论缓存漏检 db 内容篡改（改字段不改 mac），安全优先放弃，代码无引用，详见 memory `perf015-skipped-verify-cache`。 |
| `PERF-016` | — | 3 | 搜索热路径一次取完整 SearchMetadata，摘要构建与小写匹配共用，省第二次缓存查询。 |
| `PERF-017` | — | 1 | generate_password 先 list comprehension 收必选字符、再 extend 填充剩余，替代逐次 append 循环（PERF401）。 |
| `PERF-018` | — | 1 | ``get_entry_summaries`` 搜索路径将 ``matches_search_lower`` 匹配检查前移到 ``_decrypt_summary`` 之前，仅命中条目才构建完整摘要，省去未命中条目的 Entry 构造与分类名/failed_fields 缓存查询。 |
| `PERF-019` | — | 2 | 搜索路径拉取不逐行验签、未命中行不验签的取舍：篡改检测由无搜索词的全量列表刷新覆盖（温态实测：验签+宽列读取反超解密成为主导成本）；命中行的 LENIENT 验签由 PERF-074 回查完整行时完成。（早期「补验签 1000 上界」（PERF-032）与「二次读库就地验签」（PERF-067）形态已随架构演进退役。） |
| `PERF-020` | — | 10 | entry_repository 新增窄投影读取（``get_entries_for_analysis``/``get_entries_tags_projection``），标签聚合与安全分析的全表扫描不再物化 notes_enc/custom_fields_enc/totp_secret_enc 大列。 |
| `PERF-021` | — | 10 | EntryChangeBus 回调透传 ``crypto_id``，SecurityAnalyzer 增量失效：单条编辑仅锁外重读重分类该条（copy-on-write 重建指纹桶），替代每次保存触发整库密码解密 + HMAC 重算。 |
| `PERF-022` | — | 4 | 导入统一通知改 ``clear_summaries=False``，含覆盖时先对被覆盖 crypto_id 批量 pop 再通知，兑现「导入新增保留既有摘要缓存」的设计声明。 |
| `PERF-023` | — | 7 | 安全仪表盘：徽章改 objectName+集中 QSS（消除每行 setStyleSheet）、tab 懒填充（切换才 populate）、单 tab 500 行上限+截断页脚；500 行填充 175ms→120ms。 |
| `PERF-032` | — | 0 | （已退役，实现随 PERF-074 移除）搜索补验签改对全部命中行（删除 1000 上界截断）：验签集合与 UI 重排后的渲染集合错位（SQL 序 vs 排序序）；命中行验签现随 PERF-074 回查架构在 get_entries_by_ids 中完成，src 无引用（tests 留 1 处历史性引用）。 |
| `PERF-062` | — | 7 | 分析缓存出口剥离内部键（_fingerprint_map/_summaries_with_dates 无消费方却每次出口深拷贝，50k 库 13ms/次）+ 增量重建改局部 copy-on-write（仅旧/新指纹桶）。 |
| `PERF-063` | — | 1 | decrypt_summary 六覆盖字段并入单次 copy_entry_fields（原 build_entry_summary+replace 双重 24-kwarg 构造，50k 次省 ~300ms）。 |
| `PERF-064` | — | 7 | 分类条目计数会话缓存（CategoryManager 持有，epoch 守卫 + change_bus 结构性变更自订阅 + 条目改分类显式失效；50k 库省 24.6ms/次的 UI 线程 GROUP BY）。 |
| `PERF-065` | — | 12 | 导入进度回调覆盖全阶段加权刻度（parse 5%/sanitize 10%/classify 15%/encrypt 70%/write 100%，每 100 行节流），替代只覆盖 7% 时长的先冲满后冻结。 |
| `PERF-066` | — | 1 | 无搜索全列表刷新 LIMIT 下推：EntryListController.fetch_all 把 MAX_SEARCH_RESULTS_DISPLAY 经 EntryQuery 下推 SQL LIMIT（UI 渲染本就截断、同一 PERF-011 复合索引序，行为等价），50k 温态全量拉取+逐行验签+Entry 构造 1.8-3s → ~60-70ms；搜索路径不下推（先截断后过滤致命中失真）。 |
| `PERF-067` | — | 2 | 搜索补验签改内存就地验签：metadata_signer 暴露纯函数 verify_raw（提取 db 层 entry_verifier 钩子的 HMAC 计算与比对），_reverify_search_matches 对已物化命中行就地验签（域密钥由锁内快照主密钥派生），删除经 get_entries_by_ids 的二次 SQL 全表读（实测 5000 ids 234.6ms、50k 1.3-2s，另驻留一份 208MB 宽行）。（第六轮注：verify_raw 与 _reverify_search_matches 已随 PERF-074 架构退役删除——搜索命中行现经 get_entries_by_ids 回查完整行，db 层 LENIENT 验签在回查中即完成，就地验签的「省二次读库」前提不复存在。） |
| `PERF-068` | — | 10 | 备份载荷估算改明文长度 + JSON 模板字节数运行期校准（消除密文估算 1.65 倍虚高）；上限 32→40MB/64→80MB 与 50k 条目上限联动（50k 空库 ≈17MB、典型画像 ≈38MB < 40MB）。 |
| `PERF-069` | — | 14 | 导入进度接入覆盖路径（prepare/write_overwrite 增 progress 参数，纯覆盖导入不再冻结在 15%）+ classify 阶段节流（对齐 encrypt 的每 100 行，消除 50k 次跨线程信号）。 |
| `PERF-070` | — | 11 | 导出确定进度：解密阶段 0→70 / 写文件 70→100 节流上报（50k 实测 5.1s/1.9s 定刻度），UI 收到确定值切确定模式。 |
| `PERF-071` | — | 2 | EntryItemDelegate 颜色缓存升级为直接持 QColor 对象（_get_color/_get_strength_color 共用，clear_color_cache 一并失效）：paint 每行 ~9 次 QColor(hex) 构造（~1.8-2.1µs/次）改 dict 命中（~0.06µs），offscreen 交替 A/B 实测典型行省 ~18µs、含警示/删除徽章行省 ~26µs。 |
| `PERF-072` | — | 3 | LIMIT 下推排序感知化 + 收藏/回收站补全：PERF-066 的下推仅在 sort_index==0（更新时间↓，与 PERF-011 索引序同构）时截断等价，其余 7 种排序下索引序前 N ≠ 排序序前 N（50k 库按标题序实测约半数条目永久不可见，前三轮优化回归）；fetch_favorite/fetch_trash 补同规则下推（50k 库收藏视图冷 1409ms→与 fetch_all 同级）；异步 worker 闭包按快照模式捕获 sort_index（QComboBox 不可跨线程访问）。 |
| `PERF-073` | — | 12 | 排序下推字段化（PERF-072「非默认序一律全量」过度保守的修正）：EntryQuery 的 sort_by_updated 布尔退役为 order_by/order_desc（ORDER_BY_FIELDS 白名单防注入，ORDER BY 列映射硬编码），8 种排序中 6 种（updated_at/password_strength/created_at 双向）下推 ``ORDER BY 字段 LIMIT``——50k 库标题序全量 1756ms vs 字段序下推 ~50ms；标题 2 种因密文列固有限制全量并注释声明；fetcher 下推判定从魔法索引 0 改字段化，UI 集↔db 白名单一致性由测试锚定。 |
| `PERF-074` | — | 13 | 搜索路径窄投影 SearchRow：db 层新增 get_entries_search_projection（6 列：id/crypto_id/4 摘要密文，行集与 get_entries 经共用子句构造一致），EntryCacheManager 摘要解密签名收窄为 SearchRowSource 最小协议（RawEntry/SearchRow 双满足），命中行经 get_entries_by_ids LENIENT 回查完整行做摘要构建+验签（PERF-067 就地验签随宽行不再物化而退役）；实测 2k 条宽行 94.2ms → 窄投影 10.1ms（~9×），50k 温态搜索 681→~250ms。 |
| `PERF-075` | — | 3 | 导入去重窄投影：_duplicate_plan 从 get_entry_summaries() 全量摘要（50k 冷缓存 1834ms）改 get_entry_dedup_index() 窄投影（title/username/id 三元组 + 摘要缓存解密 + epoch 守卫），_prepare_overwrite_map 的 existing 由回查 raw 解密（语义零变化）；预计 1834→~900ms。 |
| `PERF-076` | — | 7 | 单条编辑增量分析差分：weak/_summaries_with_dates 两轮 O(n) 列表推导改就地单点移除；旧指纹 O(桶数) 全扫描改 _crypto_id_to_fp 反向索引缓存内部键（full/增量平行维护，出口剥离保持 PERF-062；缺失回退扫描兜底）；old_entries O(n) 重过滤改差分。实测 20k 库 median 8.8ms（旧实现同比例约 17-50ms），5k→20k 仅增 3ms 近似常数。 |
| `PERF-077` | — | 10 | Windows ACL 子进程链 ctypes 化：SID 经 OpenProcessToken→GetTokenInformation→ConvertSidToStringSidW 免 whoami；ACL 经 TRUSTEE_W/EXPLICIT_ACCESS_W→SetEntriesInAclW→SetNamedSecurityInfoW(PROTECTED_DACL) 一次调用等价 icacls 两次子进程，子进程路径保留为失败回退。实测收紧 41.5ms→0.36-0.40ms/文件（~100×）、SID 28.7ms→亚毫秒；icacls 读回验证 ACL 等价（单显式 ACE 无继承标记）；消除 whoami 受限环境脆弱性。 |
| `PERF-078` | — | 13 | 排序/搜索统一「内存 meta 排序 + 仅前 N 回查宽行」路径（推翻 PERF-073「标题序固有限制」声明）：SearchRow 补 password_strength/created_at/updated_at 明文列（内存排序键完备），get_entry_summaries 的 order_by 扩展 "title" 语义（密文列不可 SQL 排序但 meta.title_lower 可内存排序），三 fetcher 统一透传 limit+排序由 manager 分流（fetcher 层路径判断退役）；搜索命中行按排序键取前 limit 回查（全量命中回查悬崖 187.7→50.6ms@5k，3.7×）。实测标题序 165.9→53.8ms@5k（3.1×，50k 等比 ~1750→~500ms）。附带修复：搜索分支 decrypt_summary 补 data_epoch（PERF-074 重写时掉落的 SEC-043 守卫回归）、回查段补 cancel_check。 |
| `PERF-079` | — | 19 | 增删恢复路径扩展增量框架：crypto_id 通知 + 分析器移除/插入差分 + 标签计数差分。 |
| `PERF-080` | — | 10 | 状态栏 worker 单飞守卫改「在飞置脏+完成回调消费重启」，消除失效被吞致计数陈旧。补全：SecurityAnalyzer 增失效世代计数（invalidate_cache 全量失效路径递增），full_analysis 启动时快照、写回缓存前在 _cache_lock 临界区内比对，读库后失效过的结果拒收写回（报告照常返回）——原「读库后删除（缓存为 None 时增量 no-op）→ 完成写回 fresh TTL 过期报告 → 重启轮 fast path 命中」链使脏标记重启无效，现重启轮走新全量。 |
| `PERF-081` | — | 1 | fetch_recent 搜索分支下推 limit+排序（复用 PERF-078 内存路径），删 UI 冗余 sort+截断。 |
| `PERF-082` | — | 5 | 锁定/退出前检测不可中断 worker 并经托盘系统通知等待原因。 |
| `PERF-083` | — | 14 | 恢复全程加权进度刻度（5/5-45/45-80/80-95/100），每 100 条节流。 |
| `PERF-084` | — | 3 | clear_vault_state 的 gc.collect 延迟至后台 daemon Timer，消除锁定 UI 卡顿。（已撤销：GC 移入后台线程破坏 Qt 线程亲和——gc 可能 finalize 引用循环中的无父 QObject，非 GUI 线程删除 C++ 对象致「Timers cannot be stopped from another thread」或间歇崩溃；锁定时 gc 恢复 GUI 线程同步执行，配套 QL-067 消除同步 GC 与排队未投递 worker 信号的投递层崩溃窗口。） |

### QL — 质量/可读性（52 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `QL-001` | `QL-001` | 2 | 「一次性获取全部明文」场景（QL-001）。 |
| `QL-002` | `QL-002` | 2 | # 恢复点含恢复前全部明文，删除失败意味着泄漏面未收缩，需可见日志（QL-002）。 |
| `QL-003` | `QL-003` | 1 | 供状态文件缺失/损坏等绕过嫌疑场景复用（QL-003，三处重复抽此方法）：最高阶梯 |
| `QL-004` | `QL-004` | 5 | 命名 ImportDataError（QL-004）以消除与 Python 内置 ``ImportError`` 的同名遮蔽—— |
| `QL-005` | `QL-006` | 0 | （已取代）过期检测默认天数与 config 对齐——引用已被 ARCH-034 的双源收编整体取代（security_analyzer 改 import config 常量），索引处数未随实施归零，本轮修正。 |
| `QL-006` | `QL-007` | 1 | # 启动期断言（QL-006）：overload 的 Literal 键集须与 DEFAULT_CONFIG 中对应类型键一致， |
| `QL-007` | `QL-008` | 2 | # 重加密内存峰值（QL-007，消除魔法数 200）。 |
| `QL-008` | `QL-009` | 1 | """自动备份间隔判定所需的 config 视图（QL-008，替代 ``object`` + ``type: ignore``）。 |
| `QL-009` | `QL-010` | 1 | """获取新增/编辑对话框预填的分类与标签，分类为空时回退全量查询（QL-009）。""" |
| `QL-010` | `QL-012` | 1 | ``estimated_size`` 入参参与 payload 上限校验，累计值不再返回（无调用方使用，QL-010）； |
| `QL-011` | `QL-013` | 1 | # 守卫，此处必非空，无需除零保护分支（QL-011）。 |
| `QL-012` | `QL-015` | 1 | :meth:`_to_bytearray` 保证为 bytearray，无需额外 isinstance 守卫（QL-012）。 |
| `QL-013` | `QL-016` | 1 | # `paintEvent` 绘制参数（QL-013，提取魔数）：圆环几何与 Qt `drawArc` 角度常量。 |
| `QL-014` | `QL-3` | 2 | 可见（QL-014）。 |
| `QL-015` | — | 1 | error_messages 用 ``_FIXED_MESSAGES`` 映射表替代 if-elif 链归一异常文案，降 to_user_message 圈复杂度（radon D→A）。 |
| `QL-016` | — | 1 | config 用 ``_KEY_VALIDATORS`` 分发表 + 校验辅助函数替代长 if-elif，降 ``_is_valid`` 圈复杂度（radon E→A）。 |
| `QL-017` | — | 2 | share_renderer/font_loader 用显式 ``if`` 检查替代 ``assert`` 收窄 pyright 推断（S101，避免 python -O 剥离致收窄失效）。 |
| `QL-018` | — | 4 | 严格解密字段枚举统一：crypto_utils 新增 ``decrypt_string_fields_strict`` 基于 ``STRING_ENCRYPTED_FIELDS`` 单一事实源循环 + password/totp 门控，导出 Entry 与 portable dict 两消费方共用，新增加密字段不再静默漏解密。 |
| `QL-019` | — | 5 | ``prepare_password_update`` 的 ``hmac.compare_digest`` 两边 ``encode("utf-8")``：str 版仅支持 ASCII，非 ASCII 密码条目编辑/覆盖导入抛 TypeError 永不可保存。 |
| `QL-023` | — | 1 | ``CategoryManager.update_category`` 补 ``add_category`` 同款事务内 casefold 明文查重（排除自身 id），杜绝同名分类并存与导入折叠歧义。 |
| `QL-028` | — | 1 | SharePackageDialog 密码预校验改走 ``PasswordService.validate_master_password``，删除本地 8 字符魔数，与业务层 15 字符阈值统一。 |
| `QL-029` | — | 1 | ``EntryDialog._collect_entry`` 新增模式按 ``visible_fields`` 门控 password 采集，类型切换后隐藏密码框的残留值不再隐式入库。 |
| `QL-030` | — | 1 | ``custom_fields_renderer.render`` 先收集非空行再挂分组，全空值字段不再渲染空「自定义字段」分组。 |
| `QL-031` | — | 1 | category_dialog 名称输入框 ``setMaxLength(MAX_CATEGORY_NAME)``，堵住对话框直达落库的超长名（256 上限此前仅在 from_dict/导入路径生效）。 |
| `QL-032` | — | 3 | 密码生成器复制反馈定时器回调补 ``sip.isdeleted`` 守卫、清理改 ``deleteLater``，消除按钮 C 层释放后回调访问崩溃窗口（镜像 detail_panel 既有加固模式）。 |
| `QL-033` | — | 1 | _collect_entry 的 username/url 补编辑模式豁免（与 password 同款门控）：card/identity/note 编辑既有条目时这两个字段曾被静默清空（QL-029 修复的对称遗漏）。 |
| `QL-042` | — | 2 | Entry.from_dict 对三个时间戳字段做 fromisoformat 可解析校验（非空时），堵住任意字符串入库破坏「ISO 字符串排序==时间排序」等价性与过期检测。 |
| `QL-043` | — | 3 | ShareError 归入 error_messages 保留 str 分支（原落 default 丢面向用户的消息）；category_repository 同「分类重名」条件的裸 ValueError 统一改 EntryError。 |
| `QL-044` | — | 2 | EntryManager 增只读 cache property 消除测试双层私有穿透（_category_mgr._cache）；prepare_password_update 改调 PasswordService.passwords_match 门面。 |
| `QL-045` | — | 1 | TOTP base32 尾随 = 边界：_normalize_base32 先剥离全部既有 = 再统一补齐——「对齐长度+多余尾随 =」形态（如 16 数据字符后跟 1 个 =）原「只补齐不剥离」会叠加成非法填充（8 个 =）抛 binascii.Error，与 docstring 兼容非标准填充的契约矛盾；合法对齐输入剥离后重补等幂无回归。 |
| `QL-046` | — | 3 | 加密侧循环化 + 守护：build_encrypted_entry_fields 与 build_encrypted_entry 改对 SENSITIVE_ENCRYPTED_FIELDS 循环产出（custom_fields JSON 序列化与 password override 特判，AAD 与原手工枚举一致），消除「解密/验签侧响亮失败、加密侧静默丢字段」的写读不对称（恢复往返断裂）；test_field_consistency 补键集/列集/往返两条守护。 |
| `QL-047` | — | 5 | 恢复点创建超限（PayloadTooLargeError）降级不阻断恢复：跳过恢复点 + 结果拼装「无回退快照，建议立即手动备份」警告；其余异常（磁盘满等）仍中止。 |
| `QL-048` | — | 2 | 自动快照业务失败（(False, msg) 元组）经 finished 检查走既有 Toast，兑现 QL-004 只覆盖异常路径的缺口。 |
| `QL-049` | — | 2 | Entry.from_dict 补 category 字段 isinstance+长度校验，堵住非 str 值导入中途裸 AttributeError 直达用户。 |
| `QL-050` | — | 3 | 启动入口双兜底：main() 包 try/except（构造期异常 basicConfig+logger.critical 落 stderr、尽力 QMessageBox.critical、退出码 1），_install_crash_handlers 前移至 QApplication 创建后立即安装；main.py 删除恒死代码 sys.path.insert（import 成功后插入无效果）。 |
| `QL-051` | — | 2 | share/renderer 占位替换改单遍 re.sub（回调按名分派）：原按序多次 str.replace 时后置占位符会扫描先注入的第三方 JS bundle，bundle 内 ``{{...}}`` 字面量会被二次替换。 |
| `QL-052` | — | 1 | activate_keys 补 ``_ever_unlocked = True``（与 mark_unlocked 对齐）：initialize 走 activate_keys 漏置该标志，使「首次建库→使用→锁定」的整个应用会话内 enforce_key_epoch 的 ``_ever_unlocked and not is_unlocked`` 短路恒 False，锁定拒绝写入的最后防线整类失效（实测复现；一行修复 + initialize→lock 抛 VaultLockedError 守护测试）。 |
| `QL-053` | — | 1 | Entry.from_dict 时间戳强制 T 分隔扩展格式（``^\d{4}-\d{2}-\d{2}T`` 锚 + 可解析性）：fromisoformat 亦接受空格分隔/纯日期/基本格式/周日期等可解析变体，与 isoformat() 产物混存时字符串排序不再等于时间排序（空格 0x20 < 'T' 0x54），QL-042 注释声称的排序等价修复存在缺口。 |
| `QL-054` | — | 1 | Entry.from_dict 的 custom_fields 非 list 形态显式抛 EntryError：原 ``if isinstance(..., list)`` 使 dict/str 静默置空，导入方丢字段无感知，与相邻字段「类型无效即拒绝」范式不对称。 |
| `QL-055` | — | 1 | CSV 导出进度改度量「遍历位置」（processed）而非「成功写出数」：两个防御性 continue（当前类型系统下不可达）使 ``processed == total`` 终值永不可达，PERF-070「终值恒上报」契约 silently 失效且与 JSON 导出不对称。 |
| `QL-056` | — | 2 | EntryCacheManager.get_failed_fields 返回内部 set 的拷贝：原 ``dict.get`` 返回存储引用，调用方原地修改即污染缓存；API 语义收口与「锁内采样」docstring 一致，新调用方无需自防。 |
| `QL-057` | — | 4 | 增量安全分析链（invalidate_cache→_try_incremental_update→_apply_reclassified_entry）补 now 注入透传：原硬编码 ``datetime.now(UTC)`` 使测试注入时钟时增量路径与全量路径（full_analysis/_refilter_cache 均可注入）行为分叉。 |
| `QL-058` | — | 1 | 摘要缓存 LRU 淘汰与 _search_metadata_failed 容量联动：popitem 淘汰条目时同步清理 failed 记录，堵「解密失败 + 缓存超上限」同现时的无界驻留。 |
| `QL-059` | — | 1 | add_categories_batch 空列表分支 notify 补 ``metadata_changed=False`` 与非空分支对齐：缺省 True 触发 SecurityAnalyzer 整库重算与分类计数缓存无谓失效（同方法两分支参数漂移）。 |
| `QL-060` | — | 3 | 时间戳归一化取代拒绝式校验：models.normalized_iso_timestamp（fromisoformat 解析 + isoformat() 归一）为导入（Entry.from_dict）与备份恢复（backup/validator 写回）共用单一事实源。QL-053 的正则拒绝存在 T 后变体漏网（逗号小数秒/截断时间/Z 后缀实测绕过，',' 0x2C < '.' 0x2E 等错序），恢复路径仅可解析性校验与导入侧强度分叉——归一化不拒任何可解析输入，形态唯一使「字符串排序==时间排序」绝对成立。 |
| `QL-061` | — | 1 | _check_import_file_size 的 stat 异常归一 ImportFormatError：裸 FileNotFoundError 违反「领域异常→用户文案」约定，manager 入口经装饰器归一而第二道防线无归一层，绕过 manager 的调用方会把裸异常直达用户。 |
| `QL-062` | — | 5 | 覆盖导入失败项索引统一 0 基（原 1 基/0 基错位致末项失败 IndexError、日志偏移）。 |
| `QL-063` | — | 2 | 导入去重键库内侧补 strip()，与导入侧 strip().casefold() 对称；「无标题不入去重」守卫改测 strip 后判空（' ' 不再因键归一成 '' 误配无标题导入项）。 |
| `QL-064` | — | 5 | register_security_sentinel 走保留完整性告警的 save 变体（keep_integrity_warning=True）；maybe_auto_backup 的自动备份时间戳与 MainWindow._persist_window_state（closeEvent/托盘退出的窗口状态持久化）save 同款接入——后台自动写盘均不清篡改证据。 |
| `QL-065` | — | 11 | 标签计数差分一致性三件套：apply_tag_delta 合并为 (old_tags, new_tags) 单次锁内先减后加（消编辑路径两段锁撕裂态）；expected_version 写回世代守卫（写事务前快照 invalidate_version，差分窗口内并发失效+重建则放弃，堵双扣）；逗号标签解析收敛 models.parse_tag_list 公开单一事实源（delta 与全量聚合共用）。 |
| `QL-066` | — | 8 | tags 解密失败语义显式化与收敛：EntryCacheManager.decrypt_tags_for_delta 单一事实源（None=解密失败保守整表失效 / ''=合法空差分 no-op，暖缓存经 _search_metadata_failed 区分），删除/恢复路径不再对损坏 tags 静默 no-op 致 _tags_cache 陈旧；EntryManager 两处消费与聚合口径包装共用。 |
| `QL-067` | — | 3 | wait_worker_shutdown 等待线程退出后断开 worker 全部信号（finished/error/cancelled/progress），丢弃仍排队未投递的延迟回调：worker 线程退出前发射的队列信号要到下次事件循环才送达，等待方在投递前执行完整 gc.collect()（锁定清零链 clear_vault_state 的同步 GC，PERF-084 撤销后恢复）会回收 PyQt 闭包槽连接的内部代理，其后投递该排队事件解引用悬挂指针 → access violation（实测进入槽函数体之前即崩溃，_locked/identity 守卫不可达）。 |

### SEC — 安全（43 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `SEC-001` | `SEC-001` | 2 | # CSV 列数硬上限（SEC-001）：先 ``list(reader)`` 物化行前校验 header 列数，防止单行 |
| `SEC-002` | `SEC-002` | 3 | 除 TTL 外校验 key_epoch（SEC-002）：改密轮换密钥后，旧 epoch 派生的报告即便在 |
| `SEC-003` | `SEC-003` | 11 | （SEC-003 威胁边界：明文可读意味着本地有读权限者可重算签名伪造安全配置，如把 |
| `SEC-004` | `SEC-004` | 2 | 重定向位置文件（SEC-004）。 |
| `SEC-005` | `SEC-005` | 3 | # 全量逐行断言加密列（SEC-005）：_assert_encrypted 仅做 O(1) ``cb2:`` 前缀检查， |
| `SEC-006` | `SEC-006` | 2 | # 备份校验的字符串型加密字段→明文长度上限映射，派生自 models 单一事实源（SEC-006）： |
| `SEC-007` | `SEC-007` | 1 | # SEC-007：此处把公开默认分类名以明文写入 name_enc 列，是有意为之——schema_manager |
| `SEC-008` | `SEC-008` | 8 | 把清洗点前移到入库边界（SEC-008）：导入阶段统一对受影响文本字段转义，使后续 |
| `SEC-009` | `SEC-009` | 2 | # mid-word 误匹配（donkey=…），中文关键词（密码/密钥/令牌）不受影响。SEC-009 补充 |
| `SEC-010` | `SEC-010` | 5 | （SEC-010）：让高敏感路径（清空回收站/改密/恢复/解锁）感知旧密文/明文可能 |
| `SEC-011` | `SEC-011` | 1 | # SEC-011：id 反查须在 _auto_commit() 之前完成——插入与反查在同一隐式事务内 |
| `SEC-012` | `SEC-013` | 1 | # 与 entry_repository._row_to_entry 一致向上传播（SEC-012），让调用方 |
| `SEC-013` | `SEC-014` | 5 | old_password 不在计划中收集（SEC-013）：延迟到 :meth:`_prepare_overwrite_batch` 写入前 |
| `SEC-014` | `SEC-1` | 3 | 避免 purge 经恶意链接把覆写重定向到任意目标（SEC-014，与 :func:`validate_file_path` 同源）。 |
| `SEC-015` | `SEC-2` | 7 | # 经 atomic_write 落地即 0600，消除「写明文密钥 → 关闭 → secure_file 收紧」间的世界可读窗口（SEC-015）。 |
| `SEC-016` | `SEC-CLIP-001` | 5 | # Windows 剪贴板原子写入（SEC-016）：单次 OpenClipboard 周期同时写 CF_UNICODETEXT 与 Win+V 历史排除标记，消除分两次写入的时序窗口。 |
| `SEC-017` | `SEC-CLIP-002` | 2 | # setText 容错（SEC-017）：text()/clear()/setText() 在剪贴板被占用时吞 RuntimeError 降级，不阻断 UI/锁定/托盘清理。 |
| `SEC-018` | `SEC-LOGIN-001` | 2 | # SEC-018：``password`` 已作为闭包传入 worker，KDF 派生期间（后台线程耗时）避免控件明文驻留。 |
| `SEC-019` | `SEC-LOG-001` | 1 | # SEC-019：关键词后可选引号捕获并在替换串回填，覆盖 dict/dataclass repr 的 ``'password': ...`` 形态（repr 中 key 带引号，原 ``\s*[:=]`` 漏匹配）。 |
| `SEC-020` | `SEC-TAGS-001` | 1 | # 读路径 epoch 守卫（SEC-020，对称 ``resolve_totp_secret`` 的 ARCH-005）：改密 commit 与 tags 聚合读的微秒窗口内裸读会用旧密钥解密新密文致 GCM 失败、tags 回退空串丢失。 |
| `SEC-021` | — | 1 | Windows ``_load_dpapi_integrity_key`` 检测到 pre-SEC-003 明文 config.key（合法长度但未 DPAPI 封装）时，重新经 DPAPI 封装原子覆盖写回，完成一次性升级迁移，消除明文密钥原样保留的泄漏面。（已退役：项目未发布不存在 pre-SEC-003 遗留形态，迁移分支经 SEC-052 删除、非 DPAPI 封装一律按损坏处理；残留 1 处引用即 config_key_store 的退役注记。） |
| `SEC-027` | — | 3 | 恢复流程 finally 直接置空 ``_DecryptedPayload.plaintext/.data`` 字段（``del`` 局部别名不释放调用方持有的引用），明文在 WAL checkpoint/purge 收尾期间不再驻留。 |
| `SEC-028` | — | 4 | ``atomic_write`` 临时文件名加 urandom 随机后缀 + opener ``O_EXCL``（POSIX 叠加 ``O_NOFOLLOW``），消除可预测名 unlink→open 窗口的 symlink 植入竞态。 |
| `SEC-029` | — | 7 | RateLimiter 状态文件包 HMAC-SHA256 签名行（复用 config 完整性密钥），验签失败按最高阶梯保守锁定并自愈重写，堵住「改写合法 JSON 归零计数」的绕过。 |
| `SEC-030` | — | 14 | 承载用户/导入数据的 QLabel 统一经 create_plain_text_label 工厂固定 PlainText（默认 AutoText 会被启发式判富文本：伪造信任样式、`<` 开头密码显示被吞、本地 SVG 解析链触达）；URL 标签的 RichText+转义路径保留。第三轮补齐：主窗列表标题（分类名 setText）、密码历史 changed_at 时间标签；TOTP 验证码标签评估为纯数字生成值安全不动。 |
| `SEC-031` | — | 4 | 确认密码常量时间比较统一 PasswordService.passwords_match 门面（utf-8 encode），四处调用点收编，防 QL-019 同型漏 encode 复发。 |
| `SEC-039` | — | 7 | CSV 含密码导出对 password/totp_secret 列跳过公式前缀转义（与 SEC-008 导入侧「不清洗密钥字段」决策对称）；导入侧 password 列不再 strip。 |
| `SEC-040` | — | 3 | _try_incremental_update 二次校验改比快照 epoch（原比实时 epoch，跨 epoch 重填会把旧密钥指纹并入新缓存——当前 UI 时序不可达的防御纵深）。 |
| `SEC-041` | — | 19 | 摘要缓存回写增加写入方世代守卫（data_epoch）：跨恢复的旧 worker 不能把恢复前明文写入重臂后的新 epoch 缓存。 |
| `SEC-042` | — | 2 | RateLimiter 无签名降级时状态完全不落盘（消除「无签名状态文件」这一下次会话被误判篡改的形态；降级近乎不可达，跨会话计数丢失可接受）。 |
| `SEC-043` | — | 11 | SEC-041 的 data_epoch 写入方世代守卫全读路径接入：非搜索列表/get_recent_summaries/get_entry 详情（含 decrypt_summary/decrypt_entry 透传与 ViewDecryptCacheProtocol 声明）、SecurityAnalyzer._make_summary 调用链（full_analysis/_classify_entry/_try_incremental_update）、decrypt_category_name 均在锁内快照世代传入，堵「跨恢复后旧明文植入新 epoch 缓存」的四条遗留漏点。 |
| `SEC-044` | — | 6 | TOTP secret 缓存回写世代守卫：resolve_totp_secret 解密前锁内采样 epoch+version、回写前双重复查（TOTP 定时器是真实并发读者）；store_totp 增可选 data_epoch 复查（未提供保持无条件落缓存，既有调用方无跨世代窗口）。 |
| `SEC-045` | — | 1 | 导入侧公式注入清洗扩至 custom_fields 非 password 类型的 name/value（password 值豁免保持密钥完整性，与 SEC-039 决策对称），补齐 SEC-008「复制/导出无需各自防护」声明对该字段的不变量。 |
| `SEC-046` | — | 10 | EncryptionEngine.encrypt/decrypt/encrypt_bytes/decrypt_bytes 增 keyword-only ``cache_key``（False 时直接构造 AESGCM 不入模块级缓存）：一次性密钥（share 包派生密钥已接入）secure_zero 后 C 层副本不再滞留 _cipher_cache 至容量淘汰。backup_restore 两处调用点（cache_key=False）与恢复路径 clear_cache 已全部落地（原「未尽事项」描述过时，本轮核实修正）。 |
| `SEC-047` | — | 0（decrypter_template.html） | share 解密器 JS 的 onFileChange 补 file.size 4MB 前置上限（镜像 Python 侧 header_codec.MAX_SHARE_FILE_SIZE）与 arrayBuffer promise 的 .catch：GB 级恶意文件全量读入致标签页 OOM、读取失败（权限/占用）UI 停留「正在读取文件…」无反馈。 |
| `SEC-048` | — | 4 | 导入文件大小前置上限单一事实源 models.MAX_IMPORT_FILE_SIZE（200MB）：importers/base 新增 _check_import_file_size 供四策略类 parse 入口调用（第二道纵深），manager 的 _validate_import_path 引用同一常量（第一道）——原本地 25MB 与 models 新常量同名异值成双源，且 25MB 拒绝满配自导出文件（50k 条 JSON ≈35-38MB 的「能导出不能导入」断层）。 |
| `SEC-049` | — | 3 | decrypt_entry_for_export 三层补 data_epoch 世代守卫透传（ViewDecryptor→EntryManager 薄委托→get_entries_for_export 锁内快照）：导出 worker 在飞 + 恢复提交重臂新世代交错下，旧密钥解出的分类名经缓存回写植入新世代——SEC-043 全读路径接入的 export 链漏点（SEC-040 同级防御纵深）。 |
| `SEC-050` | — | 1 | 导入文件上限 200MB→80MB 口径对齐：同型防护（备份 80MB/共享包 4MB）均按 payload×2 取余量，导入满配自导出基准 ≈38MB（50k×~758B/条）应取 80MB；原 200MB 是 5 倍余量，json.load 物化膨胀 5-10 倍时（≈1-2GB 峰值）低内存机防护窗口过宽。 |
| `SEC-051` | — | 0（decrypter_template.html、tests） | 解密器 CSP meta（default-src 'none' + 内联 script/style + wasm-unsafe-eval + data: 图标）：esc() 转义之外的第二层 XSS 约束，封死外联加载与表单/嵌入通道。 |
| `SEC-052` | — | 4 | 删除 pre-SEC-003 明文 config.key 迁移分支，非 DPAPI 封装一律按损坏处理（SEC-021 退役）；写侧配套见 SEC-055。 |
| `SEC-053` | — | 5 | CategoryManager 明文分类缓存接入锁定/epoch 轮换清零回调。 |
| `SEC-054` | — | 4 | TOTP preloaded 预热写入补写入方世代守卫（SEC-044 漏点）。 |
| `SEC-055` | — | 5 | Windows DPAPI protect 失败时不再回退写明文 32 字节 config.key（读侧 SEC-052 只认 DPAPI 封装，该文件下次启动必被判损坏 → 假完整性告警 + 敏感键回退 + RateLimiter 签名失配降级最大锁定）：_store_dpapi_integrity_key 返回 False 不落盘，load_or_create 的 win32 分支保持内存密钥运行本会话并记 CRITICAL（下次启动重新生成，签名失配告警与日志共同如实反映「密钥未能安全持久化」）；非 Windows 明文回退链不变。 |
