# 审计编号索引

代码注释中的审计编号（5 维度）登记表，供跨文件 grep 追踪同一改进决策的所有触点。

## 编号约定（新增遵循）

- **格式**：`<维度前缀>-NNN`，三位零填充（如 `SEC-003`、`PERF-012`、`ARCH-005`）。
- **维度前缀**：`ARCH`（架构）/ `MAINT`（维护·可维护性）/ `PERF`（性能）/ `QL`（质量·可读性）/ `SEC`（安全）。
- **编号分配**：新编号 = 该维度当前最大已用号 +1；历史断档（如 ARCH-012→021、
  MAINT-041→071）是批次审查的既成事实，**不回填**。当前下一可用：
  `ARCH-060 / MAINT-118 / PERF-096 / QL-079 / SEC-073`（由
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

### ARCH — 架构（42 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `ARCH-001` | `ARCH-001` | 3 | """预扫描条目分类名，批量创建缺失分类并回填 ctx.categories（ARCH-001）。 |
| `ARCH-002` | `ARCH-002` | 2 | # ARCH-002：注入批量写回调，解耦 backup_rebuilder 与 EntryManager。 |
| `ARCH-003` | `ARCH-003` | 9 | 事件经独立回调通道触发（ARCH-003），详见下方注册处注释。 |
| `ARCH-004` | `ARCH-004` | 4 | 命令-查询分离（ARCH-004）：本 property 仅查询，不打开/关闭数据库。db 文件不 |
| `ARCH-005` | `ARCH-005` | 17 | 比对内存与库内 epoch 不一致时抛出（ARCH-005）：中止读路径以防用旧密钥解密新密文 |
| `ARCH-006` | `ARCH-006` | 3 | # ARCH-006：恢复点创建/统计/清理统一由 RestorePointManager 承载。备份加密管线 |
| `ARCH-007` | `ARCH-008` | 2 | 行为钩子（ARCH-007）以布尔标志形式挂入，消除消费方 ``if entry_type ==`` |
| `ARCH-008` | `ARCH-009` | 5 | # 应用全局样式；显式激活主题，使运行时 c() 解析的颜色与样式表一致（ARCH-008） |
| `ARCH-009` | `ARCH-019` | 1 | # sqlite 事务 + QThread running 析构崩溃（ARCH-009）。 |
| `ARCH-010` | `ARCH-024` | 3 | # 只读映射（MappingProxyType 防误写，ARCH-010）：均派生自 _INT_SPECS。 |
| `ARCH-011` | `ARCH-3` | 1 | # 的值再签，与恢复路径对称，消除手工键集漂移（ARCH-011）。回读须在调用方事务内， |
| `ARCH-012` | — | 1 | list_refresh_controller 删除 UI 侧重复的锁定缓存失效调用（组合根 register_on_lock 已连线，失效幂等但双源易漂移）。 |
| `ARCH-021` | — | 2 | update_entry 的 preserve_updated_at 参数退役（协议/委托/实现三层删除）：唯一 True 调用方是测试，恢复路径已改走 update_overwrite_batch。 |
| `ARCH-031` | — | 4 | CategoryStore 协议补 update_categories_batch，crypto_utils.encrypt_plaintext_category_names 参数解绑具体 DatabaseManager 改标 VaultDataStore，re_encryption 局部协议删除。 |
| `ARCH-032` | — | 8 | EntryViewDecryptor 的 cache 依赖改最小协议 ViewDecryptCacheProtocol（对齐 TotpService 模式，services 不反向依赖 managers 具体类）。 |
| `ARCH-033` | — | 4 | 组合根子服务装配规则显式化：有自持状态/独占缓存的组合根显式注入；纯变换/共享缓存无状态的宿主内部构造共用同一 cache 实例。 |
| `ARCH-034` | — | 2 | 双源常量收编：security_analyzer.DEFAULT_ANALYSIS_DAYS 改 import config.OLD_PASSWORD_WARNING_DAYS_DEFAULT（QL-005 的本地解耦理由已失效，business→config 合法），ui/constants.RECENT_ENTRY_LIMIT 改引 business 的 DEFAULT_RECENT_SUMMARIES_LIMIT（UI→business 合法，业务默认成唯一源）。 |
| `ARCH-035` | — | 2 | 主题默认值单一事实源：constants.THEME_LIGHT 与 theme_colors._current_theme 模块初值均直接派生自 config.DEFAULT_THEME（UI→config import 合法，无循环），消除三处 'light' 字面量靠注释约定同值的漂移面。 |
| `ARCH-036` | — | 1 | SidebarController 锁定态守卫责任显式化：方法均有返回值故不可套 require_unlocked（特化 Callable[...,None] 锁定返 None 是类型谎言），改为模块 docstring 声明「守卫在调用方」并列出各调用链现状与新增调用方须保持的隔离要求。 |
| `ARCH-037` | — | 9 | 条目类型展示属性下沉 UI：models.ENTRY_TYPES 收敛为 frozenset 类型键集合（仅合法性判定），中文 label 与图标占位符移 ui/resources/strings.py（ENTRY_TYPE_LABELS/ICONS + 带 login 回退的查表函数），Entry/RawEntry 的 type_icon/type_label property 与 EntryTypeSchema 的 label/icon 转发字段删除（后者无生产消费方）。 |
| `ARCH-038` | — | 8 | 导出格式策略包：export_to_json/export_to_csv 的序列化内联块拆 managers/exporters/（json_exporter/csv_exporter 写回调 + base 的 csv_safe 与密钥列豁免），manager 收窄为路径校验+原子写编排骨架，与 importers/ 对称；_sanitize_formula_prefix 随之下沉 services/url_hygiene（公共名 sanitize_formula_prefix，避免 manager↔exporters 循环）。与 importers 的差异为显式取舍：exporters 无策略协议/注册表——导出为用户显式选格式直调对应方法，无 dispatch 场景，2 格式下强行对称为过度抽象；格式≥3 或需按扩展名 dispatch 时再引入 FormatExporter 协议。 |
| `ARCH-039` | — | 15 | services 对 managers 具体类依赖的「一删三协议两锚定」：TotpService 删除零读取的 vault 死依赖（单参构造）；crypto_utils 定义 KeyProvider 两成员协议（require_vault_key/entry_view_decryption 共用）；password_history_service 的 PasswordHistoryVaultProtocol（KeyProvider+db+vault_write_lock）；security_analyzer 的 AnalysisCacheProtocol 四成员协议。security_analyzer 的 vault 依赖与 entry_batch_writer 整体**维持** TYPE_CHECKING 具体类并锚定理由（成员面与 VaultManager/EntryManager 核心同构，协议是影子类无净收益）。 |
| `ARCH-040` | — | 5 | strings.py 展示键集常量化+完备性自检：ENTRY_TYPE_LABELS/ICONS 键改用 models 的 ENTRY_TYPE_* 常量（消除与 frozenset 的字面量双源），模块加载期 if+RuntimeError 断言键集==ENTRY_TYPES（对齐 _ENTRY_COLUMNS 启动自检形式，-O 存活）——新增类型漏更新表时启动即炸，优于 UI 静默回退 login 文案。（backup_restore 的恢复进度段表启动期校验援引同一 if+RuntimeError 形式。） |
| `ARCH-041` | — | 1 | DEFAULT_RECENT_SUMMARIES_LIMIT 移入 models 共享层，解开 ui/resources/constants 对业务栈的模块级依赖。 |
| `ARCH-042` | — | 12 | change_master_password 返回契约对齐 unlock——(False,...) 仅认证失败，策略失败抛 MasterPasswordPolicyError、系统错误走异常通道，UI 不再文案字符串比对。补全：系统错误包装改用无固定映射的 VaultError 本体（to_user_message 增纯 VaultError 保留 str 分支），worker error 通道二次翻译不再被 VaultLockedError 罐头文案「保险库已锁定，请先解锁后重试」覆盖（磁盘满/IO 错误时误导）；unlock/initialize 同款接入，「保险库凭据不完整」终译保留原文。 |
| `ARCH-043` | — | 9 | RateLimiter 状态文件名常量归业务模块、实例经组合根工厂创建注入 UI 对话框（ARCH-033 纪律回归）。 |
| `ARCH-044` | — | 8 | VaultLifecycleOrchestrator 改从 vault 单一装配参数取 db/signer；build_business_context 加 WeakSet 防重入守卫。 |
| `ARCH-045` | — | 5 | 恢复阶段方法以 RestoreAbortedError（BackupError 子类）替代 result-or-tuple 联合返回。 |
| `ARCH-046` | — | 1 | build_business_context 装配体异常回退 `_assembled_vaults` 登记：原登记先行使「上次装配失败」的重试被误拒、报错述为「重复调用」（ARCH-044 语义误伤）；回调注册纯 append 不抛，实际异常源是 manager 构造（无副作用），discard 后重试等价全新装配。 |
| `ARCH-047` | — | 4 | 组合根装配前置校验 vault.lifecycle_attached（VaultManager 新增公开 property）：绕过 build_vault 手工构造、未挂编排器的 vault 被即时拒绝，生命周期错误前置到装配期而非推迟到首次调用才抛「attach_lifecycle 未调用」。 |
| `ARCH-048` | — | 2 | maybe_auto_backup 的 config 参数删除，配置读取统一经 self._vault.config 单一通道（与同类 create_backup 的 purge 路径一致）：消灭「调用方传参另一 ConfigManager 实例（即便当前同对象）」的双源漂移面，AutoBackupController 与测试同步。 |
| `ARCH-049` | — | 3 | 认证失败文案拆 LOGIN_AUTH_FAILED_MESSAGE / CHANGE_AUTH_FAILED_MESSAGE 两个显式常量（原改密单常量 + unlock 内联「主密码错误」字面量双源）：登录/改密场景语义与措辞有别，各自单源；值由契约测试锚定。UI 空文案兜底收编：改密对话框 ``error_msg or CHANGE_AUTH_FAILED_MESSAGE`` 与登录窗口 ``error_default = LOGIN_AUTH_FAILED_MESSAGE`` 同引常量，第四处同值字面量消除。 |
| `ARCH-050` | — | 2 | matches_search 签名收窄为仅 Entry（原 Entry \| RawEntry 联合签名暗示密文态是合法输入，docstring 却声明生产不应传）：RawEntry 可搜索字段是密文，明文子串匹配无意义；matches_tag 核查本就仅 Entry。 |
| `ARCH-051` | — | 1 | get_entry_summaries 排序分流白名单驱动：「不可下推」判定由硬编码 ``order_by == "title"`` 改为 ORDER_BY_FIELDS 否定式（``in_memory_path = bool(search) or (order_by is not None and order_by not in ORDER_BY_FIELDS)``），白名单增删字段时分流自动跟随单一事实源（原双源：新增可下推字段时硬编码判定不跟随）；UI SORT_OPTIONS 字段集 ⊆ 白名单 ∪ {title} 由测试守护。 |
| `ARCH-052` | — | 3 | 投影缓存键构造收敛：get_entry_summaries 手工拼五元组键映射 EntryQuery 的 9 维度中 5 个（双源——未来加过滤维度漏改键则不同行集共享同键静默错数据），收敛为单一函数（MAINT-116 随查询族迁 services/entry_queries，现 projection_cache_key，原 entry_manager._projection_cache_key），从 EntryQuery 显式提取影响行集的维度（deleted_only/category_id/favorite_only + 排序段，复合序规范化 (None,True)），docstring 列「键维度↔query 维度」契约；include_deleted/after_id/limit（影响行集未入键，消费方恒传默认值）与「order_by 非 None 而 tie_break_order=False」（键不区分并列裁决形态）以入口 ValueError 显式拒绝（静默错数据→响亮失败）；TestProjectionCacheKeyContract 行为锚定。 |
| `ARCH-053` | — | 6 | SearchMetadata（搜索摘要缓存条目 NamedTuple）自 managers/entry_cache 迁至 services/entry_view_decryption：services 消费方（decrypt_summary 的 ``meta`` 参数）此前 TYPE_CHECKING 反向引用 managers 的纯数据类型，违反 MAINT-104 的「services→managers 收敛为 ARCH-039 论证的具体 manager 依赖」纪律；该类为纯数据 NamedTuple（零 managers 依赖）且唯一 services 消费方在视图解密域，home 随之迁移，entry_cache/entry_manager 经 managers→services 正向 import 引用（entry_manager 的 ``from .entry_cache import SearchMetadata`` 经模块属性继续成立，不改 UI 侧消费方）。 |
| `ARCH-054` | — | 4 | entry_cache 模块 docstring 集中声明 TOTP 刷新的线程模型约束：「TOTP secret 的解密与缓存回写（TotpService.generate_cached/get_state）必须留在 GUI 线程（TOTPWidget 的 QTimer 驱动）」，含理由（pop_totp 失效防护与 resolve/store 回写守卫的对手方是 worker 线程写路径，移入后台线程会扩大交错空间并放大旧 secret 可见窗口）与违反后果（旧 totp_secret 持续生成错误 2FA 验证码，对齐 SEC-063 修复前形态）——此前约束只散落在方法注释，多线程守卫的并发对手方实际依赖线程模型巧合。评估过 apply_change(crypto_id=...) 顺带 pop TOTP 的替代（使防护不依赖线程模型），因 TOTP 缓存按 entry_id 键控而 apply_change 只有 crypto_id、需增参数映射且与既有 QL-070 先于写库的单条 pop 重复，侵入度不值，选集中声明。后续 SEC-063 统一失效 seam（任何写事务提交后自动 clear_totp，vault_manager 侧接线引用本条）对该约束做了结构性兜底——seam 不覆盖非事务写与「写库→提交」间窗口，GUI 线程约束仍是必要纵深；entry_manager 写路径区域的单条写纪律 checklist 亦引用本条为窗口推演的纵深前提。 |
| `ARCH-055` | — | 2 | get_entry_dedup_index 接投影行集缓存：原直连 get_entries_search_projection 与 PERF-086 缓存路径并行（50k ~160ms 全量拉取每次重复支付，导入去重与前后脚的列表/搜索刷新无法互相摊销），改经 search_projection_rows 的「未删除全量+复合序」键（与搜索路径无排序投影同键复用）；invalidate_if_epoch_changed 同步前移至读块前（对齐 PERF-086 前移论证：首次调用的 epoch 重臂不废自己刚回填的投影行集）；去重对照保持仅未删除条目（回收站条目不参与覆盖判定，与原语义一致）。（PERF-094 复核修正：「同键复用」仅对未指定排序/title 序的搜索成立，带 SQL 白名单排序下推的搜索键含排序段不互摊，且导入提交后全键失效——代码侧 docstring 已如实化。） |
| `ARCH-056` | — | 2 | get_recent_summaries 的 invalidate_if_epoch_changed 位置对齐：原在读块后（锁外解密前）与 get_entry_summaries 的 PERF-086 前移位置（读块前）模式分裂——recent 虽不消费投影行集缓存，旧位置会误导后来者在新读路径复制；统一前移后任何读路径首次调用的 epoch 重臂都发生在拉取/解密之前，不废自己刚回填的缓存；调用顺序 spy（invalidate 先于 db.get_entries）与首调重臂行为测试守护。 |
| `ARCH-057` | — | 3 | 组合根回调注册后置到构造全部成功之后：build_business_context 的 register_on_transaction_committed 与 lock/epoch_rotated 回调原夹杂在 manager 构造链中间，链上构造抛异常时 vault 已永久持有孤儿回调（clear 幂等故无功能错误，但 ARCH-046 注释「此时尚未注册任何回调」的声明不变量为假，discard 重试会再注册一套）；重排为「构造段 → 注册段」两段式，构造失败路径零注册，「失败回退无回调残留」由结构保证而非注释声明。 |
| `ARCH-058` | — | 6 | epoch_guarded_transaction 嵌套契约入口防御：seam 两承诺（成功提交后触发 + db_lock 释放后执行）仅顶层事务成立——嵌套调用走 SAVEPOINT 分支（RELEASE 非提交、锁仍持），内层退出即触发使承诺失真。守卫在 db_lock 内检查 in_transaction（事务全程持 db_lock，持锁期间 depth>0 只可能是同线程重入，精确区分「同线程嵌套」拒绝与「跨线程排队」等待后照常顶层执行，锁外裸查会误报并发写路径），嵌套即抛清晰错误并在 docstring 声明不支持嵌套。当前全部调用点均为顶层，守卫把该前提从 docstring 约定升级为结构保证（运行期等价于「模块加载即炸优于运行期漂移」纪律）。演进：顶层判定收敛进 db_manager.transaction(require_top_level=) 参数——检查与分支选择在同一 db_lock 临界区原子完成，VaultManager 删除「先取锁自查 in_transaction 再释放、transaction() 再取锁」的双锁往返与跨层等价论证注释，错误形态定为 TransactionError；跨线程排队不受断言误伤由并发竞争测试锚定。 |
| `ARCH-059` | — | 3 | cancel_event 跨路径 clear 竞态登记（不根治）：lock()/close()/change_master_password 三路径共用同一 threading.Event，各自「取写锁前 set → finally clear」——A 路径 finally 的 clear 可能抹掉并发 B 路径刚 set 的取消请求（B 将等满在飞分析全程而非检查点间隔）。单用户桌面应用的 lock/close/改密均由 GUI 线程顺序触发，该交错实际不可达、无正确性影响；根治须改代次计数（set 递增代次、消费方比对快照代次），对不可达路径侵入不值，lock() 的 finally 集中登记 + close()/change_master_password 指针注释备查。 |

### MAINT — 维护/可维护性（54 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `MAINT-001` | `MAINT-001` | 1 | 包裹解密到 WAL 截断）由各阶段方法与 try/finally 维护（MAINT-001）。 |
| `MAINT-002` | `MAINT-002` | 1 | """两阶段加密写入单分类（MAINT-002）：占位 id 加密 INSERT → 真实 id 重加密 UPDATE。 |
| `MAINT-003` | `MAINT-003` | 1 | # add_entry 对称（MAINT-003）：UPDATE 含 category_id 外键，引用不存在的分类时 |
| `MAINT-004` | `MAINT-004` | 22 | """覆盖项加密预处理结果（MAINT-004）：写阶段所需的最小密文载荷。 |
| `MAINT-005` | `MAINT-005` | 1 | # 配置键名常量（MAINT-005 单一事实源）：DEFAULT_CONFIG / _INT_SPECS / _BOOL_KEYS / |
| `MAINT-006` | `MAINT-008` | 1 | 编排分两步（MAINT-006）：事务内重加密+元数据 → 事务后激活密钥+清理；异常兜底与 |
| `MAINT-007` | `MAINT-009` | 5 | default_category_id/duplicate_action/source_label 参数（MAINT-007），使方法签名 |
| `MAINT-008` | `MAINT-010` | 0（ci.yml） | # 分层覆盖率门槛（分支覆盖，MAINT-008）：开启 --cov-branch 后分支率严格 ≤ 行率， |
| `MAINT-009` | `MAINT-011` | 1 | # 限制 csv 解析器单字段最大长度（MAINT-009）：默认 128KB 与本项目逐项大小策略 |
| `MAINT-010` | `MAINT-019` | 1 | 统一字符类型校验为单一事实源（MAINT-010）。有效时错误信息为空串，无效时返回 |
| `MAINT-011` | `MAINT-1` | 1 | # 分支于测试框架存在性（MAINT-011）。 |
| `MAINT-012` | `MAINT-2` | 2 | # 平台判定单一常量（MAINT-012）：统一引用，避免 os.name=='nt' 与 sys.platform=='win32' 混用 |
| `MAINT-013` | `MAINT-3` | 0（tests） | """BackupDialog 接线测试：控件值→业务参数→结果文案（MAINT-013）。 |
| `MAINT-014` | — | 0 | 审计编号双向引用约定：新编号须在代码注释 ``（XXX-NNN）`` 引用，使 rg 可从代码回溯决策（本轮 PERF-017/QL-015/QL-016/QL-017 已补齐；纯约定/已放弃编号处数=0 豁免）。 |
| `MAINT-015` | — | 5 | EntryManager/BackupRestoreManager 的子 manager 参数改必传，删除 ``or`` 兜底构造，组合根显式注入契约由约定升级为签名强制。 |
| `MAINT-020` | — | 4 | config.py 签名密钥平台存储链（DPAPI→keyring→明文回退）下沉 ``src/config_key_store.py``，ConfigManager 组合持有并经 ``integrity_key`` property 供业务层复用。 |
| `MAINT-021` | — | 10 | EntryManager 视图解密族（detail/export/summary 三视图 + 严格/容错字段解密，约 300 行）下沉 ``services/entry_view_decryption.py``（``EntryViewDecryptor``），EntryManager 公开方法保持薄委托、调用方零改动。 |
| `MAINT-041` | — | 0（ci.yml、CLAUDE.md） | 命令统一 ``uv run -m <module>`` 形式（ruff/pytest/mypy/pyright/coverage，ci.yml 的 Ruff check/format 两步后续从裸 trampoline 补齐统一）：trampoline 入口在部分 uv/Windows 组合报 canonicalize 失败；引用位于 ci.yml 与 CLAUDE.md（非 .py，处数按代码口径为 0）。 |
| `MAINT-071` | — | 8 | entry_repository（844 行全库最大）的密码历史块拆分 ``password_history_repository.py``（7 方法单表访问，镜像 category_repository 模式），DatabaseManager 委托纯搬迁零增减。 |
| `MAINT-081` | — | 0 | ``tests/utils/test_clipboard.py`` git mv 至 ``tests/ui/``：被测对象为 ``src/ui/utils/clipboard.py``，恢复 tests↔src 目录镜像约定（文件内均为绝对导入，移动零改动）。（tests 内的历史触点已随后续测试重构移除，全库无引用。） |
| `MAINT-082` | — | 0 | CHANGELOG 1.0.0 转正：Unreleased 段转 ``[1.0.0] - 2026-08-22`` 并终结 ``0.1.0.dev0`` 开发占位引用（版本已随 fa3d536 升至 1.0.0 但变更记录未跟随）。纯文档修正，代码无触点。 |
| `MAINT-083` | — | 0（pyproject.toml） | ruff select 补 ``S``/``PERF``：原 per-file-ignores 的 S105/S608/S603/PERF203 条目与代码内 14 处 nosec B608 全部空转（规则未启用、注释承诺的 lint 门禁不存在）；新增 app.py S110 行内豁免、password_history_repository S105 与 tests/** 测试固有形态整目录豁免，check src tests 全过使门禁真实生效。 |
| `MAINT-084` | — | 0（.pre-commit-config.yaml） | pre-commit entry 统一 ``uv run -m <module>``（pyright 为 ``uv run python -m pyright``），对齐 MAINT-041 的 CI 命令形态——裸 trampoline 入口在部分 uv/Windows 组合报 canonicalize 失败，与文件自述「与 CI 完全同源」矛盾。 |
| `MAINT-085` | — | 4 | crypto/ 与 business/managers/ 两个 ``__init__.py`` 的零消费类 re-export 删除（全库无 ``from src.crypto import X``/``from src.business.managers import X`` 类导入，无检查守护的声明面随时间漂移为谎言 API）；importers/ 的 re-export 有真实消费方（import_export 经包级导入四个类）保留。MAINT-109 复核该先例扩展至 importers/exporters 的常量/数据类孤儿 re-export。 |
| `MAINT-086` | — | 1 | backup_restore 恢复点 docstring 的「见恢复流程未尽事项」悬空指向删除：全库不存在该文档/章节（可能仅存于早期 commit message），追溯承诺无法兑现。 |
| `MAINT-088` | — | 0 | 第五轮守护测试补齐：QL-055 导出进度终值（test_export_progress，跳过条目 processed==total 可达 + 取消语义）；QL-056 get_failed_fields 拷贝与 QL-058 LRU 淘汰联动（test_username_cache，monkeypatch 解密与容量构造）；QL-057 now 注入增量时钟（test_security_analyzer，注入未来时钟重判过期）。「修复了但没锁」缺口的收口。（守护测试经 QL-055/056/057 各自编号锚定；tests 内 MAINT-088 标注已随后续测试重构移除。） |
| `MAINT-089` | — | 1 | update_entry 手写 epoch 事务样板收敛至 epoch_guarded_transaction(pre_epoch=)。 |
| `MAINT-090` | — | 1 | update_entry 的 preloaded_raw/preloaded_old_password 死参数删除。 |
| `MAINT-091` | — | 5 | 排序键单一事实源 entry_sort_key；删除 _fetch_for_filter 冗余重排（worker 线程读 QComboBox 一并消除）。 |
| `MAINT-092` | — | 4 | get_entry_summaries 190 行单体拆分（_SummaryRead 快照 + 搜索投影/SQL 下推两个私有构建方法）。 |
| `MAINT-093` | — | 6 | security_dashboard tab 元数据表驱动创建与懒填充分发，消除三方法复制与魔法索引。 |
| `MAINT-094` | — | 6 | 5 个对话框 _setup_ui 对齐 entry_dialog 的 _build_* 分块模式。 |
| `MAINT-095` | — | 15 | 测试观察用只读 property（QL-044 先例推广）：_HealthScoreWidget.score、_StatCard.count_text、EntryRefreshCoordinator.entry/tag_refresh_generation、EntryCacheManager.cache_epoch/search_metadata_cached_ids、EntryViewDecryptor.cache、RateLimiter.fail_count/state_path、DetailPanel.holds_secret_values、EntryItemDelegate.cached_color_keys、ClipboardManager.clear_scheduled——测试对内部态的直读/直改收敛为公开观察面，生产行为零变化。判据：测试断言内部状态须走观察 property（docstring 注明测试观察用）；monkeypatch 注入点与白盒安全属性守护（密钥清零、装配不变量）除外。剩余深链豁免集中登记于下方「MAINT-095 测试深链豁免台账」。 |
| `MAINT-096` | — | 3 | _restrict_windows_acl_via_api 127 行单体按「取 SID→构造 ACL→应用」三步拆私有函数 + 编排壳，ctypes 调用序列与 LocalFree 释放语义逐路径等价（Win32 直读测试守护）。 |
| `MAINT-097` | — | 5 | crypto_utils 名实相符收窄：搜索谓词拆出 entry_search_match、视图构造并入 entry_view_decryption、decrypt_entry_to_portable_dict 归位 backup/collector，原模块仅留加密单一事实源（entry_sorting 迁出 managers 时援引本先例，MAINT-104）。 |
| `MAINT-098` | — | 1 | EntryManager.get_entries 退役（src 零调用、测试 40+ 处的「一次性解密全部密码」入口）：方法删除，等价测试助手移 tests/helpers.decrypt_all_entries（经 db.get_entries + decrypt_entry 公开 API 组装），防回退守护断言方法不存在。 |
| `MAINT-099` | — | 3 | 进度契约收敛至 entry_batch_writer（进度契约的家）：phase_progress(done,total,start,end) 加权映射（import_export._phase_progress 与 backup_restore._weighted_progress 字节级重复，改为薄委托）+ should_report_progress(done,total) 节流谓词（`% EVERY == 0 or done == total` 的 10 处手抄全库替换，含 exporters/entry_manager/rebuilder/collector）。两份薄委托随 MAINT-112 段表化整体收敛为 segment_progress，触发点净减。 |
| `MAINT-100` | — | 1 | PERF-079 五处失效咒语收敛：add/update/delete/restore/permanent_delete 各自手写的「apply_tag_delta + invalidate_entry_counts_cache + notify kwargs」组合统一为 EntryManager._notify_entry_structure_changed 私有 helper（old_tags=None 表解密失败保守整表失效；EntryChangeBus 协议不动）。 |
| `MAINT-101` | — | 4 | SecurityAnalyzer 聚合公式提取 _recompute_aggregates 单一函数（weak_count==len(_weak_map)、old==len(_old_map)、duplicate_count==Σ(len(g)-1)），full_analysis 与 _apply_reclassified_entry 两路共用——此前各维护一份，对不齐时增量与全量静默分叉；「线性扫描找 crypto_id 后 del」的四连写随 PERF-085 的 dict 化定位一并消失。 |
| `MAINT-102` | — | 1 | 删除零调用死代码 EntryCacheManager.search_lower_no_check（docstring 自述被 cached_search_metadata_full 取代，全库零调用，能力为 full 后 4 字段子集）；cached_search_metadata/cached_search_metadata_full docstring 中对它的过时引用同步修正。 |
| `MAINT-103` | — | 12 | 敏感字段行三件套三份平行实现收敛共享工厂：secret_field 新增 SharedHideTimer 共享单定时器模式（同屏单显式、任一揭示先掩码上一显式行、stop 掩码当前显式行），detail_panel 主密码分支（原 _pwd_hide_timer+_current_password+_pwd_label_ref 专属实现）回归工厂，password_history 每行复用工厂（保持每行独立定时器语义不变）；PWD_MASK 掩码动作与 sip.isdeleted 竞态守卫收敛单处（原共享工厂超时回调无守卫一并补齐）。复制路径收敛时守卫一度丢失（同工厂 _mask_row/_toggle 均有），回归补齐为 _make_copy_secret 模块级工厂（销毁窗口期挂起 clicked 事件触发时静默跳过，不触反馈图标写入）。 |
| `MAINT-104` | — | 6 | entry_sort_key 排序键域迁出 managers：键函数 + EntrySortKeySource 协议 + _SortKeySource 适配 NamedTuple（随迁去下划线公开为 SortKeySource）迁 services/entry_sorting.py，与 entry_search_match（MAINT-097）同属「条目查询域纯函数」的 services 归属对齐——UI 的 entry_list_controller 不再为消费 4 键逻辑 import managers.entry_manager。 |
| `MAINT-105` | — | 1 | entry_type_schema 的 visible_fields 组装数据化：原 if CARD/IDENTITY…elif SERVER…elif NOTE…else LOGIN 四分支硬编码改「title + 专用字段 + common_tail_by_type 注册表尾段」统一公式，兑现模块「新增类型只需扩展注册表」承诺；未登记类型沿用 LOGIN 尾部（原 else 语义），逐类型快照测试守护与 elif 链时代等价。 |
| `MAINT-106` | — | 5 | entry_batch_writer.write_chunks 分块写入共享原语：write_new_entries/write_overwrite_updates/backup rebuilder.restore_entries 三份逐字节相同的「按 WRITE_PROGRESS_CHUNK 分块调用 + 逐块 (done,total) 上报」循环收敛为单一函数（write_fn 参数化，各块结果按序返回、合并策略留在调用方；无 on_progress 保持整批单次原路径），直接行为测试 + monkeypatch 锚点迁移守护。 |
| `MAINT-107` | — | 7 | 恢复加权进度六闭包收敛：_point_entries/_point_history 与四个 rebuild 段的 ~66 行复制闭包（仅 base/span 不同）收敛为 backup_restore._segment_progress_reporter 单一闭包工厂（import_export._offset_phase_reporter 同型）；六组 base/span 常量对改结构化段表（_ProgressSegment/_RestoreSegments NamedTuple），跨段相邻性（45+17==62 等）由模块导入期 if+RuntimeError 断言 + 段表契约测试双重守护（此前纯手工维护无校验）。段表行类型与段内映射随 MAINT-112 下沉共享，引用扩展至 entry_batch_writer/import_export。 |
| `MAINT-109` | — | 4 | importers/exporters 包级 ``__init__`` 孤儿 re-export 删除（MAINT-085 先例复核）：ParsedImport（importers）与 CSV_SECRET_COLUMNS（exporters）的包级 re-export 零消费（子模块与消费方均直接 ``from .base`` 导入），删 import 与 ``__all__`` 项并注释声明保留面（FormatImporter 与四个策略类经 import_export 包级消费、两个 write_* 另有 test_export_progress 包级消费、csv_safe 有 test_csv_safe 包级消费——首轮误判 csv_safe 为孤儿致测试收集失败，复查 tests 包级导入后恢复保留）；同批删除 share/renderer、list_refresh_controller、share_package_dialog 三处赋值后全文件零使用的死 logger（连同 import logging，零决策含量不占触点）。 |
| `MAINT-110` | — | 3 | share 头检视链保留决策显式化：read_share_header→inspect_share 生产链 src 零消费（Python 端只写包、解密在浏览器 decrypt.html），评估后保留——read_share_header 与 write_share_header 构成头格式编解码对称，往返测试据此在 CI 守护写头字节布局（删除后写头正确性只剩 JS 端运行期解密失败的隐式验证）；inspect_share 预留共享包检视 UI（备份侧 inspect_backup 有 UI 消费先例）。MAX_SHARE_KDF_MULTIPLIER 核实 decrypter_template.html 的 ``D.time * 2`` 等三处内联上界字面量与之同值对应，锚点注释补两端对应声明。 |
| `MAINT-111` | — | 0（tests） | 零断言测试补记录断言：test_memory（空输入短路不落入 bytes 误传告警分支的 caplog 区分）、test_entry_change_bus（回调异常「吞掉但 logger.warning 可见」双契约）、test_auto_backup_policy（缺失目录不被误建）、test_file_security（secure_directory 重复调用返回路径）四例原「不抛即通过」补轻量记录断言；mark_secret_discarded 等语义占位类确无可断言者保留并沿用 docstring 论证。后续批次（2026-09-03）对新增放行用例补齐：test_file_security 的 Windows 合法路径/verbatim 文件系统两组放行参数化（断言校验函数返回 None 即放行，区分「校验完整执行后放行」与「校验未执行」）、test_repository_boundaries 空批 no-op（断言既有行不变）、test_main_window_lifecycle 无托盘日志回退（caplog 断言 info 日志真实发生）；test_backup_corruption 的 progress=None 跳过用例确无可断言物（下游回调本体为 None，无上报记录可查）保留语义占位。 |
| `MAINT-112` | — | 10 | 导入/导出加权进度刻度段表化（MAINT-107 治理横向推广）：import_export 的 8 组隐式相邻常量（PARSE_DONE=5→SANITIZE=10→PLAN=12→CLASSIFY 12→15→ENCRYPT 15→70→WRITE 70→100 及 export 侧 DECRYPT 70/WRITE 70→100）改 _ImportSegments/_ExportSegments 具名段表 + validate_progress_segments 启动期相邻性校验（首段承接 0、逐段无缝、尾段精确止于 100）；段表件（ProgressSegment 行类型/segment_progress 段内映射）自 backup_restore 下沉 entry_batch_writer（进度契约的家）单一实现——backup_restore._weighted_progress 与 import_export._phase_progress 两份逐字符相同的薄委托随之收敛，backup_restore 删本地副本改共享；契约测试对齐 TestRestoreProgressSegmentTable 形态（无缝/单调/终值 + PERF-065/070 刻度画像锚定）。 |
| `MAINT-113` | — | 6 | 普通字段行四件套收敛共享工厂 secret_field.make_plain_field_row：detail_panel 与 custom_fields_renderer 的近逐行双胞胎（标签+布局+值标签+复制按钮）合并为单一实现，主条目普通字段（如账号）改间接引用 store（原 `_plain_values_main` 字典，现由 MAINT-115 的 RowValueStore holder 收口）；复制闭包的 `sip.isdeleted` 竞态守卫泛化为 `_make_guarded_copy` 单一事实源——renderer 侧原 `_copy_value` 缺失守卫（MAINT-103 收敛敏感行时的同型遗漏），按钮销毁窗口期内挂起 `clicked` 投递直达反馈图标写入抛 RuntimeError→qFatal；敏感行 `_make_copy_secret` 改为该工厂的薄委托。 |
| `MAINT-114` | — | 1 | security_analyzer.full_analysis docstring 引用更正：线程安全段落引用不存在的 ``get_entries``（实际调用窄投影入口 get_entries_for_analysis），一处更正消除误导性 API 引用。 |
| `MAINT-115` | — | 12 | 间接引用状态管理收敛三件套（MAINT-113 的同域后继）：a) secret_field 新增 RowValueStore holder——detail_panel 的 `_plain_values_main`/`_plain_row_counter`/清理块与 custom_fields_renderer 的双份「dict + 计数器 + mark_secret_discarded 清理块」逐字重复，安全纪律（明文丢弃与计数复位成对）双份漂移面收敛为「store 暴露 + next_key() + clear()」单一实现；b) secret_field 增 `_make_icon_btn`——敏感行显示/隐藏与复制按钮、普通行复制按钮三份「QPushButton+set_icon+iconBtn+BTN_COPY+tooltip」配方收敛；c) PlainFieldEnv 去泛型——两个构造点均为 dict[int, str] 行号键控，TypeVar 暗示的键型多样性不存在（SecretFieldEnv 保持泛型：detail_panel 敏感行用 str 标签名键控）。 |
| `MAINT-116` | — | 15 | EntryManager 查询读族下沉 services/entry_queries.py（`EntryQueryService`，对齐 MAINT-021 视图解密族/MAINT-104 排序键迁出先例）：get_entry_with_epoch（含 EntryRead）/get_entry_summaries（含 MAINT-092 的 `_SummaryRead` 载荷与搜索投影/SQL 下推两个私有构建方法）/get_recent_summaries/get_entry_dedup_index/get_entries_for_export 七方法逐块搬移、语义零变化，EntryManager 公开查询方法保持薄委托（调用方/UI 零改动；tests 仅 `_projection_cache_key` 一处导入路径同步为 services 的公开名 projection_cache_key）。依赖形态：vault 经 TYPE_CHECKING 具体类（ARCH-039 锚定：读路径核心 4 成员，协议即影子类）；cache 协议化 `QueryCacheProtocol`（4 成员，ARCH-032 模式，含批量会话最小视图 `_MetadataBatchView`）；view_decryptor 注入宿主共享实例（对 `entry_mgr._view_decryptor` 的实例级 spy 语义保持，ARCH-033 宿主内部构造）。`ProjectionCacheKey` home 随唯一 services 消费方（键构造函数）迁入并对齐 ARCH-053 先例（entry_cache 经 managers→services 正向 import 引用），`_projection_cache_key` 去下划线公开（跨模块消费，对齐 MAINT-104 的 SortKeySource）。 |
| `MAINT-117` | — | 7 | file_security 983 行按关注域拆分（沿 MAINT-097/104 的模块拆分先例，全库显式改 import、不留兼容门面）：Win32 SID/ACL ctypes 链与 whoami/icacls 子进程回退及 SID/LRU 缓存拆 ``win_acl.py``（MAINT-096/PERF-077 注释随迁，pyproject 的 S603 豁免随迁）；Windows 路径安全校验（保留设备名/ADS/设备命名空间/reparse，SEC-061/066）拆 ``path_validation.py``；DPAPI 封装拆 ``dpapi.py``（唯一消费方 config_key_store——独立模块而非并入消费方：与 win_acl 同属 Win32 ctypes 原语层，config_key_store 保持存储链编排单一职责，且 tests/utils/test_dpapi.py 已有镜像）；IS_WINDOWS 平台常量下沉 ``_platform.py`` 供四模块共享（MAINT-012 单一事实源与处数=1 保持）；file_security 保留文件权限（secure_file/secure_directory）、安全覆写删除（secure_delete_file）与独占临时文件原子写（atomic_write）域并 import win_acl 的 _restrict_windows_acl。公开 API 函数名/签名零变化，既有编号注释随函数原样迁移（SEC-014/015/028/061/066、MAINT-012/096、PERF-077 的 src 处数逐一保持）；测试镜像拆分 test_win_acl.py/test_path_validation.py（测试内容不变仅改 import 与模块引用，icacls 读回的 Win32 直读等价性守护原样保留）。（编号让号说明：并行批次的 entry_queries 下沉已先在 src 使用 MAINT-116，本批次让号取 117。） |

#### MAINT-095 测试深链豁免台账

判据（见上 MAINT-095 行）：测试断言内部状态须走观察 property；monkeypatch 注入点与白盒安全属性守护除外。此前豁免说明散在各测试文件 docstring、总数不可复算；本台账集中登记豁免类别、代表文件与数量口径，各豁免文件 docstring 指向此处。**数量为登记时快照，随迁移演进以复算命令现算值为准**（多代理并行期间 tests 变动频繁，快照允许陈旧、命令必须可复算）。下表快照数最近一次复算刷新为 2026-09-03（`RateLimiter.fail_count` 观察面深链随批迁移清零后）。

| 类别 | 判定理由 | 代表文件 | 快照数 | 复算口径 |
|---|---|---|---|---|
| A. monkeypatch 注入点 | 判据明示豁免：注入/spy 生产私有名是模拟并发窗口/失败注入的标准手段，公开面无法表达「解密中途失效」等时序 | test_entry_cache.py（解密 impl 中途 apply_change）、test_backup_corruption.py、test_file_security.py | 28 处调用（总 setattr 271） | `monkeypatch.setattr` 调用中目标名末段以 `_` 开头（多行调用需脚本级匹配：首个字符串字面量参数按 `.` 取末段判 `_` 前缀） |
| B. UI 控件树深链 | Qt 控件树无公开观察面约定：QDialog/MainWindow 内部控件（`_title_edit`/`_pwd_labels` 等）经 findChildren+私有属性驱动与断言是 Qt 测试惯用形态，逐控件开观察 property 得不偿失 | test_main_window_lifecycle.py、test_entry_dialog.py、test_entry_actions_menus.py | 817 行 | `rg -n --pcre2 '(?<!self)\.\_[A-Za-z]\w*' tests/ui -g '*.py' \| rg -v 'monkeypatch\.setattr' \| wc -l` |
| C. 非 UI 深链（三分见下） | 断言对象是业务/加密/数据层对象的内部形态：或为白盒安全守护（公开面无法表达），或为私有纯函数/常量直测（无实例状态，直调是唯一路径） | 见 C1/C2/C3 | 445 行（token 453） | 同上命令，路径换 `tests/ -g '!tests/ui/**'` |
| C1. 状态观测/写注入 | 白盒安全与结构守护：密钥清零（`vault._key_mgr`）、剪贴板 hash（`_last_text_hash`）、分析缓存内部键（`_analysis_cache`）、篡改注入（`db._conn` 直写 SQL）、缓存播种/成员断言（`_search_metadata_cache` 写路径无公开面）、装配不变量（`_on_lock_callbacks`） | test_lock_clear_chain.py、test_clipboard.py、test_security_analyzer.py、test_vault_meta_integrity.py、test_composition.py | 324 token | C 的 token 级细分：非 C2/C3 形态者 |
| C2. 私有纯函数/方法直测 | 被测对象即模块私有纯函数（归一化/解析/校验等无实例状态逻辑），直调是唯一测试路径 | test_totp_error.py（`_normalize_base32`/`_extract_period`）、test_path_validation.py（路径拒绝链，MAINT-117 拆分自 test_file_security）、test_crypto.py（`_get_cipher`） | 110 token | token 首字母小写且后随 `(` |
| C3. 模块私有常量引用 | 测试锚定生产模块级私有常量值（进度段表/列集/AAD 等契约数据） | test_import_orchestration.py（进度段常量）、test_repository_boundaries.py（`_ENTRY_COLUMNS`） | 19 token | token 首字母大写 |

判据违例（观察面已存在仍深链）不属豁免、随批迁移清零：本批迁移 cache_epoch（3 处）→ `EntryCacheManager.cache_epoch`、`entry_mgr._cache`（9 处）→ `EntryManager.cache`、delegate 颜色缓存（16 处）→ 新增观察面 `EntryItemDelegate.cached_color_keys`、剪贴板定时器（4 处）→ 新增观察面 `ClipboardManager.clear_scheduled`。后续新增观察面时对应深链须随迁并更新本表快照数。2026-09-03 补迁 `RateLimiter._fail_count` 读断言深链 21 处（tests/ui/test_rate_limiter.py 17、tests/business/test_rate_limiter_unsigned_state.py 2、tests/config/test_login_lock.py 2）→ 公开观察面 `fail_count`（c2e590d 登记）；test_login_lock 的写播种（预设「已过期锁定」形态，公开 API 无对应写面）按注入点豁免保留并加注释，`_lock_until` 无观察面（check() 为间接观察面）暂列 C1。

noqa 决策（SLF001 不启用）：`# noqa: SLF001` 为 no-op（ruff select 未含 SLF 规则，MAINT-083 只激活了 S/PERF），本批删除存量 23 处注解（多代理并行期间其它批次新增的同类注解按同一决策随其批次清理）；经评估不启用 SLF001——B/C 两类豁免体量（1200+ 行）会把 lint 门禁整体打红，per-file-ignores 全豁免又使规则形同虚设，深链纪律由本台账 + MAINT-095 判据治理优于 lint 强制。同型 no-op `# noqa: ARG002`（ARG 规则同样未启用）存量 3 处（entry_list_widget.py 的 Qt 重写签名）已于 2026-09-03 按同一决策删除，改为签名上一行的中文注释标注未用参数（ruff format 对行尾中文注释按 East Asian 宽度计行宽、签名行会触发拆行）。（ARG 若未来启用须同步评估 B 桶豁免体量后再激活。）

### PERF — 性能（58 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `PERF-001` | `PF-001` | 29 | ``key`` 为 PERF-001 并发修补（M3）：调用方（如 :meth:`EntryManager.get_entry` |
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
| `PERF-062` | — | 6 | 分析缓存出口剥离内部键（_fingerprint_map/_summaries_with_dates 无消费方却每次出口深拷贝，50k 库 13ms/次）+ 增量重建改局部 copy-on-write（仅旧/新指纹桶）。 |
| `PERF-063` | — | 1 | decrypt_summary 六覆盖字段并入单次 copy_entry_fields（原 build_entry_summary+replace 双重 24-kwarg 构造，50k 次省 ~300ms）。 |
| `PERF-064` | — | 7 | 分类条目计数会话缓存（CategoryManager 持有，epoch 守卫 + change_bus 结构性变更自订阅 + 条目改分类显式失效；50k 库省 24.6ms/次的 UI 线程 GROUP BY）。 |
| `PERF-065` | — | 12 | 导入进度回调覆盖全阶段加权刻度（parse 5%/sanitize 10%/classify 15%/encrypt 70%/write 100%，每 100 行节流），替代只覆盖 7% 时长的先冲满后冻结。 |
| `PERF-066` | — | 1 | 无搜索全列表刷新 LIMIT 下推：EntryListController.fetch_all 把 MAX_SEARCH_RESULTS_DISPLAY 经 EntryQuery 下推 SQL LIMIT（UI 渲染本就截断、同一 PERF-011 复合索引序，行为等价），50k 温态全量拉取+逐行验签+Entry 构造 1.8-3s → ~60-70ms；搜索路径不下推（先截断后过滤致命中失真）。 |
| `PERF-067` | — | 2 | 搜索补验签改内存就地验签：metadata_signer 暴露纯函数 verify_raw（提取 db 层 entry_verifier 钩子的 HMAC 计算与比对），_reverify_search_matches 对已物化命中行就地验签（域密钥由锁内快照主密钥派生），删除经 get_entries_by_ids 的二次 SQL 全表读（实测 5000 ids 234.6ms、50k 1.3-2s，另驻留一份 208MB 宽行）。（第六轮注：verify_raw 与 _reverify_search_matches 已随 PERF-074 架构退役删除——搜索命中行现经 get_entries_by_ids 回查完整行，db 层 LENIENT 验签在回查中即完成，就地验签的「省二次读库」前提不复存在。） |
| `PERF-068` | — | 10 | 备份载荷估算改明文长度 + JSON 模板字节数运行期校准（消除密文估算 1.65 倍虚高）；上限 32→40MB/64→80MB 与 50k 条目上限联动（50k 空库 ≈17MB、典型画像 ≈38MB < 40MB）。 |
| `PERF-069` | — | 13 | 导入进度接入覆盖路径（prepare/write_overwrite 增 progress 参数，纯覆盖导入不再冻结在 15%）+ classify 阶段节流（对齐 encrypt 的每 100 行，消除 50k 次跨线程信号）。 |
| `PERF-070` | — | 12 | 导出确定进度：解密阶段 0→70 / 写文件 70→100 节流上报（50k 实测 5.1s/1.9s 定刻度），UI 收到确定值切确定模式。 |
| `PERF-071` | — | 2 | EntryItemDelegate 颜色缓存升级为直接持 QColor 对象（_get_color/_get_strength_color 共用，clear_color_cache 一并失效）：paint 每行 ~9 次 QColor(hex) 构造（~1.8-2.1µs/次）改 dict 命中（~0.06µs），offscreen 交替 A/B 实测典型行省 ~18µs、含警示/删除徽章行省 ~26µs。 |
| `PERF-072` | — | 3 | LIMIT 下推排序感知化 + 收藏/回收站补全：PERF-066 的下推仅在 sort_index==0（更新时间↓，与 PERF-011 索引序同构）时截断等价，其余 7 种排序下索引序前 N ≠ 排序序前 N（50k 库按标题序实测约半数条目永久不可见，前三轮优化回归）；fetch_favorite/fetch_trash 补同规则下推（50k 库收藏视图冷 1409ms→与 fetch_all 同级）；异步 worker 闭包按快照模式捕获 sort_index（QComboBox 不可跨线程访问）。 |
| `PERF-073` | — | 14 | 排序下推字段化（PERF-072「非默认序一律全量」过度保守的修正）：EntryQuery 的 sort_by_updated 布尔退役为 order_by/order_desc（ORDER_BY_FIELDS 白名单防注入，ORDER BY 列映射硬编码），8 种排序中 6 种（updated_at/password_strength/created_at 双向）下推 ``ORDER BY 字段 LIMIT``——50k 库标题序全量 1756ms vs 字段序下推 ~50ms；标题 2 种因密文列固有限制全量并注释声明；fetcher 下推判定从魔法索引 0 改字段化，UI 集↔db 白名单一致性由测试锚定。 |
| `PERF-074` | — | 13 | 搜索路径窄投影 SearchRow：db 层新增 get_entries_search_projection（6 列：id/crypto_id/4 摘要密文，行集与 get_entries 经共用子句构造一致），EntryCacheManager 摘要解密签名收窄为 SearchRowSource 最小协议（RawEntry/SearchRow 双满足），命中行经 get_entries_by_ids LENIENT 回查完整行做摘要构建+验签（PERF-067 就地验签随宽行不再物化而退役）；实测 2k 条宽行 94.2ms → 窄投影 10.1ms（~9×），50k 温态搜索 681→~250ms。 |
| `PERF-075` | — | 4 | 导入去重窄投影：_duplicate_plan 从 get_entry_summaries() 全量摘要（50k 冷缓存 1834ms）改 get_entry_dedup_index() 窄投影（title/username/id 三元组 + 摘要缓存解密 + epoch 守卫），_prepare_overwrite_map 的 existing 由回查 raw 解密（语义零变化）；预计 1834→~900ms。 |
| `PERF-076` | — | 3 | 单条编辑增量分析差分：weak/_summaries_with_dates 两轮 O(n) 列表推导改就地单点移除；旧指纹 O(桶数) 全扫描改 _crypto_id_to_fp 反向索引缓存内部键（full/增量平行维护，出口剥离保持 PERF-062；缺失回退扫描兜底）；old_entries O(n) 重过滤改差分。实测 20k 库 median 8.8ms（旧实现同比例约 17-50ms），5k→20k 仅增 3ms 近似常数。 |
| `PERF-077` | — | 11 | Windows ACL 子进程链 ctypes 化：SID 经 OpenProcessToken→GetTokenInformation→ConvertSidToStringSidW 免 whoami；ACL 经 TRUSTEE_W/EXPLICIT_ACCESS_W→SetEntriesInAclW→SetNamedSecurityInfoW(PROTECTED_DACL) 一次调用等价 icacls 两次子进程，子进程路径保留为失败回退。实测收紧 41.5ms→0.36-0.40ms/文件（~100×）、SID 28.7ms→亚毫秒；icacls 读回验证 ACL 等价（单显式 ACE 无继承标记）；消除 whoami 受限环境脆弱性。 |
| `PERF-078` | — | 14 | 排序/搜索统一「内存 meta 排序 + 仅前 N 回查宽行」路径（推翻 PERF-073「标题序固有限制」声明）：SearchRow 补 password_strength/created_at/updated_at 明文列（内存排序键完备），get_entry_summaries 的 order_by 扩展 "title" 语义（密文列不可 SQL 排序但 meta.title_lower 可内存排序），三 fetcher 统一透传 limit+排序由 manager 分流（fetcher 层路径判断退役）；搜索命中行按排序键取前 limit 回查（全量命中回查悬崖 187.7→50.6ms@5k，3.7×）。实测标题序 165.9→53.8ms@5k（3.1×，50k 等比 ~1750→~500ms）。附带修复：搜索分支 decrypt_summary 补 data_epoch（PERF-074 重写时掉落的 SEC-043 守卫回归）、回查段补 cancel_check。 |
| `PERF-079` | — | 20 | 增删恢复路径扩展增量框架：crypto_id 通知 + 分析器移除/插入差分 + 标签计数差分。 |
| `PERF-080` | — | 10 | 状态栏 worker 单飞守卫改「在飞置脏+完成回调消费重启」，消除失效被吞致计数陈旧。补全：SecurityAnalyzer 增失效世代计数（invalidate_cache 全量失效路径递增），full_analysis 启动时快照、写回缓存前在 _cache_lock 临界区内比对，读库后失效过的结果拒收写回（报告照常返回）——原「读库后删除（缓存为 None 时增量 no-op）→ 完成写回 fresh TTL 过期报告 → 重启轮 fast path 命中」链使脏标记重启无效，现重启轮走新全量。 |
| `PERF-081` | — | 1 | fetch_recent 搜索分支下推 limit+排序（复用 PERF-078 内存路径），删 UI 冗余 sort+截断。 |
| `PERF-082` | — | 5 | 锁定/退出前检测不可中断 worker 并经托盘系统通知等待原因。 |
| `PERF-083` | — | 15 | 恢复全程加权进度刻度（5/5-45/45-80/80-95/100），每 100 条节流。 |
| `PERF-084` | — | 3 | clear_vault_state 的 gc.collect 延迟至后台 daemon Timer，消除锁定 UI 卡顿。（已撤销：GC 移入后台线程破坏 Qt 线程亲和——gc 可能 finalize 引用循环中的无父 QObject，非 GUI 线程删除 C++ 对象致「Timers cannot be stopped from another thread」或间歇崩溃；锁定时 gc 恢复 GUI 线程同步执行，配套 QL-067 消除同步 GC 与排队未投递 worker 信号的投递层崩溃窗口。） |
| `PERF-085` | — | 17 | 安全分析增量差分全 O(1) 化：_summaries_with_dates dict 化（crypto_id→(Entry,changed_utc)）+ 新增 _weak_map/_old_map/_duplicate_groups_map 内部键作 weak/old/重复分组的事实源（出口公开列表键经 _export_report 从 map 派生；后续收口：缓存本体只持内部形态计数+map，公开列表键不入本体——双表示中列表键自首次差分起陈旧且无内部读方，纯维护陷阱，full_analysis 返回内部形态、SecurityReport TypedDict 拆为内部/出口两型，_export_report 的 map 缺失回退分支删除）；_crypto_id_to_fp 反向索引以 None 哨兵收录无指纹条目（键集==summaries 键集），无密码条目（note/identity 等常态）差分不再因 pop miss 落入逐桶 any() 全扫描；fp_map/fp_index 撤销每轮 dict() 全量拷贝改就地修改（出口已隔离）；duplicate_groups 增量维护（旧/新指纹桶跨越 len>1 边界时增删组）。实测 50k+25k 混合库：有密码编辑 13.2→0.042ms、无密码编辑/删除 ~37→0.03ms。 |
| `PERF-086` | — | 30 | 搜索暖缓存两件套：a) EntryCacheManager 投影行集缓存 search_projection_rows——键=(deleted_only, category_id, favorite_only, order_by, order_desc)（复合序规范化为 (None,True) 防同义键占槽；有序行集因消费方依赖行序不可与无序混存），容量 4 键 LRU（单键最坏 50k 行 SearchRow ~20MB，全密文+明文定位/排序列，无明文驻留顾虑），以主域 _invalidate_version 失效（增删改/导入/恢复/锁定/改密全路径经 apply_change/invalidate_all 推进；QL-070 分域后单条 TOTP 失效不再击穿本缓存）；出口浅拷贝隔离（命中/回填两路径均返回 list 新容器，调用方变异不污染缓存，50k 行引用拷贝 ~0.4ms 可忽略）；b) search_metadata_batch 批量摘要会话：循环外一次持锁快照命中集（dict 拷贝）+ 锁外解密 + 一次持锁整批 epoch+version 守卫回写（try/finally 包 yield，with 体抛异常退出同样回写 pending），替代逐行 RLock+move_to_end（50k 行 ~78ms）；批量命中不推进 LRU recency（仅超条目数上限的理论场景产生淘汰、无正确性影响）。get_entry_summaries 的 invalidate_if_epoch_changed 前移至读块前（原在块后，首次调用的 epoch 重臂会把刚回填的投影缓存清掉）。实测 5k 暖态：search+limit 44.3→5.1ms、全量搜索 349.8→231.5ms。 |
| `PERF-087` | — | 10 | 内存路径排序下推：搜索非空 + order_by 属 SQL 白名单 + limit 非 None 时投影查询下推 ORDER BY（entry_repository 的投影查询经 _entry_query_clauses 本就支持 order_by，无需增参），行集即目标序——匹配循环按序扫描凑满 limit 即 break，跳过 O(n log n) 全量收集+内存排序（50k ~100ms）。语义与「全量收集→内存排序→取前 N」同构，含并列裁决（后续补齐）：SQL 序带固定 tie-breaker（ORDER BY <列> <方向>, is_favorite DESC, updated_at DESC，见 _entry_query_clauses 的尾部子句），与内存稳定排序继承的复合序逐层一致——排序键同值并列（强度刻度 0-4、批量导入 created_at 同刻）时，limit 截断边界上的入选集合与「全量收集→稳定排序→截断」完全相同（原单列 SQL 序的并列行为引擎内序，边界选集分叉）；cancel_check 语义保持。实测 5k 暖态：recent+search 46.4→1.7ms（27×，20k 库 5.2ms）。 |
| `PERF-088` | — | 1 | empty_trash 通知降级为 password_changed=metadata_changed=False：回收站条目软删除时已按 PERF-079 增量差分移出 SecurityAnalyzer 缓存与标签计数，物理清空不改变活跃集合——分析器对双 False 直接返回（跳过整库 O(n) 重算），category_mgr 计数订阅同跳过（get_category_entry_counts 过滤 is_deleted=0）；摘要/标签/投影行集缓存仍经 apply_change（默认 tags_changed/clear_summaries=True + version 推进）全量失效，回收站视图行集正确性保持。 |
| `PERF-089` | — | 12 | 恢复进度段内长无上报冻结窗口消除：restore_entries 批量写入段按 WRITE_PROGRESS_CHUNK（原 _WRITE_PROGRESS_CHUNK，随 backup/rebuilder 复用转公开）分块上报（单次 executemany 50k 实测 ~2.85s 冻结）、restore_history 分组写入段按行数累计上报、collector.collect_portable_history 解密段节流上报；权重并入 PERF-083 刻度按比例细分（恢复点条目 5→33/历史 33→45 按条目:历史 7:3 同重建段、条目重建加密 45→62/写入 62→80 按各半、历史加密 80→90/写入 90→95）。 |
| `PERF-090` | — | 10 | 并列裁决键收窄至搜索的排序下推分支（修 PERF-087 无条件追加裁决键引入的回归）：EntryQuery 增 tie_break_order 开关（默认 False 纯单列序），tie-breaker（ORDER BY <列> <方向>, is_favorite DESC[, updated_at DESC]，首键为 updated_at 时第三裁决键与首键同列恒 no-op 冗余省去）仅在 get_entry_summaries 的 order_pushdown 分支传 True（该分支依赖「行集序==内存稳定排序序」的等价性）；SQL 直连路径（主列表字段序/recent 视图）不追加——裁决键使 ORDER BY 不再是 idx_entries_active_updated 的索引前缀、计划退化为 TEMP B-TREE filesort（50k 基准：recent LIMIT 100 索引序 0.66ms 无 TEMP B-TREE，主列表 updated_at DESC LIMIT 1000 5.49ms，搜索下推分支保留裁决键）。EXPLAIN 计划守护测试锚定三条路径无 TEMP B-TREE。 |
| `PERF-091` | — | 4 | 分类计数 GROUP BY 覆盖索引 idx_entries_deleted_category (is_deleted, category_id)：get_category_entry_counts 的 WHERE is_deleted=0 AND category_id IS NOT NULL GROUP BY category_id 原走 idx_entries_deleted + USE TEMP B-TREE FOR GROUP BY（50k 实测 24.5-49.8ms 且增删后防抖刷新在 UI 线程同步执行），单一复合索引同时承担过滤与分组（计划 SEARCH USING COVERING INDEX 无 TEMP B-TREE，同数据 4.4ms，EXPLAIN 守护测试锚定）；索引入 _INDEX_DEFINITIONS 单一事实源（建表与校验自动跟随），缺该索引的旧开发库按「不做旧格式迁移」约定重开被拒（开发期重建库即可）。 |
| `PERF-092` | — | 3 | full_analysis 全程持 vault_write_lock（50k 库 ~5s）的取锁阻塞收敛——改密入口对称取消 + 持锁取舍显式化：a) change_master_password 取写锁前 request_cancel（与 lock()/close() 同款），在飞分析的阻塞从「分析全程」缩短到「取消检查点间隔（64 条）+ unwind」，finally 兜底清事件防认证失败路径残留置位误取消后续分析（_re_encrypt_all 开头 clear 自行复位）；b) 评估「锁内快照 entries+key、锁外分类」的锁拆分后**维持全程持锁**并在 full_analysis 注释声明取舍——正确性守卫（_cached_analysis 写回的 epoch+失效世代、_make_summary 的 SEC-043）确已支撑锁外执行，但全程持锁承载的是安全不变量：lock()/close() 清零密钥并 gc.collect 须等 worker 释放全部密钥/明文引用后才真正可回收，拆分会重开「后台 Worker 超时后仍持密钥」窗口（持锁设计要关闭的）；取消机制已把所有时敏竞争方（lock/close/改密）的等待封顶，唯一不取消方 password_history_service.decrypt 为 UI 短操作，接受其余时长阻塞。 |
| `PERF-093` | — | 1 | write_overwrite_updates 写库后的 TOTP 缓存逐条 evict 循环删除（50k 覆盖即 50k 次持锁 pop，实测 30-50ms 纯耗）：提交后的失效改由 VaultManager.epoch_guarded_transaction 的统一提交回调 seam 承担（SEC-063 结构性根治，一次 clear_totp 覆盖全部覆盖条目），事务持 db_lock 期间重解密读者阻塞至提交后见新行，「prepare evict → 提交」窗口内回写的旧 secret 必被 seam 清空或被版本守卫拒收；prepare 阶段的前置 evict 保留（覆盖「evict → 写库」窗口的并发回写）。 |
| `PERF-094` | — | 1 | get_entry_dedup_index 的逐行摘要取值接批量会话：原循环逐行调 cached_search_metadata_full（每行 2 次 RLock 往返：命中读 + move_to_end，50k 逐行实测 ~78ms），改经 _SearchMetadataBatch（PERF-086 为搜索路径建的同一会话）一次持锁快照命中集 + 锁外解密 + 一次持锁整批守卫回写，对齐搜索路径同款调用形态，暖缓存连续导入零逐行锁（spy 测试锚定逐行路径零调用）；docstring 的「与搜索路径无排序投影同键复用」声明同步如实化——互摊仅对未指定排序/title 序（order_by 规范化为 None 复合序键）的搜索成立，带 SQL 白名单排序下推的搜索键含排序段不互摊，且导入提交后全键失效（行集已变，失效是正确性要求而非损耗）。 |
| `PERF-095` | — | 7 | entries 索引再平衡（删 4 补 2 净 10→8，50k 库两阶段实测）：删 idx_entries_favorite/idx_entries_updated（EXPLAIN 证实 planner 恒选复合索引前缀，收藏视图两列等值走 idx_entries_active_favorite_updated、全部 updated_at 序走 idx_entries_active_updated）与 idx_entries_type/idx_entries_password_changed（全库零谓词消费，过期检测在内存按解密值算）四个纯写放大索引（50k UPDATE 5690→3460ms、empty_trash DELETE 141→74ms）；补 idx_entries_active_created (is_deleted, created_at DESC)（created_at 排序 SQL 直连路径原走 is_deleted 过滤 + TEMP B-TREE 68.8ms，补后索引前缀直接满足纯单列序 4.3ms，与 PERF-090 裁决键论证无冲突）与 idx_entries_active_category_updated (is_deleted, category_id, updated_at DESC)（分类视图点查原只用 is_deleted 前缀扫全未删除行过滤：updated_at 序 42.0→3.9ms、分类+搜索 tie-break 投影 37.4→2.5ms）；保留原候选删除的 idx_entries_deleted——删除后全表回表扫描形态（标签投影/分析扫描/strength 序 filesort 源扫描）改走复合索引前缀致回表行序从 rowid 序随机化，74→228/243→382/64→205ms，保留的额外写成本仅 ~1%；已知 planner 误选（分类+created_at 序误选 active_created 全扫 24→50ms）记录不强改（非默认排序×分类过滤低频组合，同 PERF-091 批次「估算行为可接受」口径）；EXPLAIN 守护测试扩展（字段序 parametrize 含 created_at + 分类点查/单分类计数）。 |

### QL — 质量/可读性（63 项）

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
| `QL-014` | `QL-3` | 3 | 可见（QL-014）。 |
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
| `QL-042` | — | 1 | Entry.from_dict 对三个时间戳字段做 fromisoformat 可解析校验（非空时），堵住任意字符串入库破坏「ISO 字符串排序==时间排序」等价性与过期检测。 |
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
| `QL-056` | — | 3 | EntryCacheManager.get_failed_fields 返回内部 set 的拷贝：原 ``dict.get`` 返回存储引用，调用方原地修改即污染缓存；API 语义收口与「锁内采样」docstring 一致，新调用方无需自防。search_projection_rows 出口同纪律（命中/回填两路径返回 list 浅拷贝，不外泄缓存内部行集引用）。 |
| `QL-057` | — | 4 | 增量安全分析链（invalidate_cache→_try_incremental_update→_apply_reclassified_entry）补 now 注入透传：原硬编码 ``datetime.now(UTC)`` 使测试注入时钟时增量路径与全量路径（full_analysis/_refilter_cache 均可注入）行为分叉。 |
| `QL-058` | — | 1 | 摘要缓存 LRU 淘汰与 _search_metadata_failed 容量联动：popitem 淘汰条目时同步清理 failed 记录，堵「解密失败 + 缓存超上限」同现时的无界驻留。 |
| `QL-059` | — | 1 | add_categories_batch 空列表分支 notify 补 ``metadata_changed=False`` 与非空分支对齐：缺省 True 触发 SecurityAnalyzer 整库重算与分类计数缓存无谓失效（同方法两分支参数漂移）。 |
| `QL-060` | — | 3 | 时间戳归一化取代拒绝式校验：models.normalized_iso_timestamp（fromisoformat 解析 + isoformat() 归一）为导入（Entry.from_dict）与备份恢复（backup/validator 写回）共用单一事实源。QL-053 的正则拒绝存在 T 后变体漏网（逗号小数秒/截断时间/Z 后缀实测绕过，',' 0x2C < '.' 0x2E 等错序），恢复路径仅可解析性校验与导入侧强度分叉——归一化不拒任何可解析输入，形态唯一使「字符串排序==时间排序」绝对成立。 |
| `QL-061` | — | 1 | _check_import_file_size 的 stat 异常归一 ImportFormatError：裸 FileNotFoundError 违反「领域异常→用户文案」约定，manager 入口经装饰器归一而第二道防线无归一层，绕过 manager 的调用方会把裸异常直达用户。 |
| `QL-062` | — | 5 | 覆盖导入失败项索引统一 0 基（原 1 基/0 基错位致末项失败 IndexError、日志偏移）。 |
| `QL-063` | — | 2 | 导入去重键库内侧补 strip()，与导入侧 strip().casefold() 对称；「无标题不入去重」守卫改测 strip 后判空（' ' 不再因键归一成 '' 误配无标题导入项）。 |
| `QL-064` | — | 5 | register_security_sentinel 走保留完整性告警的 save 变体（keep_integrity_warning=True）；maybe_auto_backup 的自动备份时间戳与 MainWindow._persist_window_state（closeEvent/托盘退出的窗口状态持久化）save 同款接入——后台自动写盘均不清篡改证据。 |
| `QL-065` | — | 12 | 标签计数差分一致性三件套：apply_tag_delta 合并为 (old_tags, new_tags) 单次锁内先减后加（消编辑路径两段锁撕裂态）；expected_version 写回世代守卫（写事务前快照 invalidate_version，差分窗口内并发失效+重建则放弃，堵双扣）；逗号标签解析收敛 models.parse_tag_list 公开单一事实源（delta 与全量聚合共用）。 |
| `QL-066` | — | 8 | tags 解密失败语义显式化与收敛：EntryCacheManager.decrypt_tags_for_delta 单一事实源（None=解密失败保守整表失效 / ''=合法空差分 no-op，暖缓存经 _search_metadata_failed 区分），删除/恢复路径不再对损坏 tags 静默 no-op 致 _tags_cache 陈旧；EntryManager 两处消费与聚合口径包装共用。 |
| `QL-067` | — | 3 | wait_worker_shutdown 等待线程退出后断开 worker 全部信号（finished/error/cancelled/progress），丢弃仍排队未投递的延迟回调：worker 线程退出前发射的队列信号要到下次事件循环才送达，等待方在投递前执行完整 gc.collect()（锁定清零链 clear_vault_state 的同步 GC，PERF-084 撤销后恢复）会回收 PyQt 闭包槽连接的内部代理，其后投递该排队事件解引用悬挂指针 → access violation（实测进入槽函数体之前即崩溃，_locked/identity 守卫不可达）。 |
| `QL-068` | — | 3 | _apply_reclassified_entry 反向索引不一致兜底与读/写两阶段化：索引有旧指纹但指纹桶缺失（撕裂）时 fp_map.get 判空视同无旧桶，不再 KeyError（与键缺失回退逐桶扫描的正向兜底对称）；全部读取/判定先于就地修改完成——change_bus 回调吞异常后缓存继续被出口消费，此前「先改 weak/summaries、后访问指纹桶」的中途异常会停留撕裂态，两阶段化后写阶段仅剩 dict 基本操作、无数据依赖型异常。 |
| `QL-069` | — | 4 | get_all_tags 回填守卫升级 epoch+version 双比对（对齐摘要/分类名回填的同款双守卫）：「聚合出锁→回填」窗口内主线程写入+notify 只推进 version 不动 epoch，旧行为基于旧库的快照落入 _tags_cache 且无自愈（标签缓存无 TTL）；配套 apply_tag_delta 应用即推进 _invalidate_version（否则差分成为唯一「改缓存不推进版本」的路径，在飞聚合的旧快照可经 version 比对覆盖已差分的正确缓存），推进的额外代价（丢弃在飞摘要回写）可忽略——差分后紧随的 notify→apply_change 本就会推进。 |
| `QL-070` | — | 18 | 标签差分与 TOTP 失效的「第三态」收口：apply_tag_delta 返回是否应用，被世代守卫放弃（或缓存未填充）时 _notify_entry_structure_changed 保守置 tags_changed=True 整表失效——旧行为放弃后仍 tags_changed=False，缓存正确性靠 apply_change 的未声明不变量巧合收敛；pop_totp/clear_totp 持锁推进失效版本，使 resolve_totp_secret 回写守卫的「单条失效不回写」承诺真实生效（原 pop 只清 dict 不推进版本，防护名存实亡）。后续分域迭代：失效版本拆主域 _invalidate_version（守卫投影行集/摘要回写/标签差分）与 TOTP 域 _totp_invalidate_version（守卫 TOTP secret 回写）——pop 只推进 TOTP 域（detail_panel 离开带 TOTP 条目的 evict 是高频无 DB 写交互，推进主域会击穿 PERF-086 投影缓存），resolve 回写比对 TOTP 域，全局失效（apply_change/invalidate_all 等）经 _advance_global_invalidation 两域一并推进；update/delete/permanent_delete 的 pop_totp 保持先于写库（「写库→pop」窗口内定时器命中旧 secret；分域后不再影响差分世代快照，时序由 TestTotpInvalidateOrdering 的调用顺序 spy 守护）。 |
| `QL-071` | — | 1 | category_repository.update_category 重名异常文案去内嵌明文分类名（对齐同文件 add_category 的固定文案示范）：本层 category.name 生产路径为密文、测试路径为明文分类名，直接调 db 层的调用方异常若经 logger.error 落盘，内嵌明文名会绕过日志脱敏过滤器。 |
| `QL-072` | — | 4 | get_entry_summaries 的 limit=0 两路径语义统一为空集：内存路径原 ``if limit`` 视 0 为 falsy 跳过截断返回全部，与 SQL 路径 LIMIT 0 返回空集分叉；统一 ``is not None`` 判定（排序下推分支 limit=0 循环首轮即 break）。 |
| `QL-073` | — | 2 | normalized_iso_timestamp 归一化补 astimezone(UTC)：带偏移输入（Z/+08:00 等）统一转 +00:00——偏移原样保留时「字符串排序==时间排序」仅在全库统一偏移下成立，导入/恢复混入非零偏移会使 SQL 与内存排序按钟面字面比较、与真实时间序错位数小时（03:04+02:00 实为 01:04Z 却按字面排在 02:04+00:00 之后）；aware 形态唯一后排序等价绝对成立，本地生成（utc_now_iso 恒 +00:00）转换幂等、存量值零变化；naive 输入保持 naive 落库（无偏移信息不可转换，消费侧统一按 UTC 解释，见 format_datetime 与 security_analyzer 的时间认知），导入与恢复两路径共用单一事实源收严。 |
| `QL-074` | — | 4 | EntryListController.sort_entries 死代码删除：全仓生产零调用（仅测试与注释引用），留着误导后来者以为 UI 有独立重排路径；entry_sort_key 的唯一生产消费方回归 manager 内存排序路径，entry_sorting/entry_manager/list_refresh_controller 注释中对其作为消费方的引用同步更新；TestSortEntries 删除（entry_sort_key 已有专测），PERF-078 标题序等价性测试的对照组改直接经 entry_sort_key 复现旧 UI 键语义。 |
| `QL-075` | — | 1 | empty_trash 的 clear_totp 前移至 db.empty_trash 之前：原「物理删除在前、TOTP 缓存清空在后」在 db 抛异常时已物理删除条目的 TOTP secret 残留缓存（违反自家 pop-before-write 纪律，QL-070 同族）；clear_totp 幂等、先行清空不改变成功路径行为；调用顺序 spy 与异常路径（db.empty_trash 抛异常时缓存已清空）双测试锁定。 |
| `QL-076` | — | 0（tests） | 测试期望独立性四件套：托盘图标锁定态断言经 `_create_icon` 重建期望值的半镜像补独立性论证（期望侧颜色/文字由测试独立选定）与颜色差分断言（brand 色同文字产物不等，证明颜色真实参与）；EntryChangeBus 摘要播种由裸 4 元组改 SearchMetadata 构造（8 字段 NamedTuple 的半镜像表示一改即碎）；密码历史「揭示」改走真实行内 toggle 闭包（原直接 setText 绕过揭示链路）；delegate favorite 测试以两次 paint 各自的 spy 文本证明均真实执行（颜色缓存键跨两次 paint 共享，无法证明两次均执行）。 |
| `QL-077` | — | 3 | resolve_totp_secret 捕获 VaultIntegrityError 优雅降级：db.get_entry 默认 STRICT 验签，条目元数据被篡改时异常直通 Qt 槽——TOTP 定时器每秒触发一条异常日志冲刷且条目 TOTP 静默停止；对齐 ARCH-005 对 epoch 失配的优雅处理返回 None（调用方停表），单次 warning 记 entry_id 定位符（验签失败时 raw 不可得；定时器随首个 None 即停，不刷屏），篡改明细警示由列表路径（LENIENT 标记 integrity_error）承担，此处不重复验签。演进（半应用补齐）：get_entry_with_epoch 详情读改走 get_entries_by_ids（LENIENT）而非 db.get_entry（STRICT）——STRICT 的 VaultIntegrityError 直入 Qt 选择槽（do_select_entry）被全局钩子吞掉，详情面板静默空白、detail_panel._render_integrity_warning（为此而建）不可达；LENIENT 失败仅标记 integrity_error 经 decrypt_entry 透传，详情面板渲染既有完整性警示并禁用编辑/共享，与列表路径标记一致（取径先例：EntryManager._read_raw_for_delta 的同款论证）。 |
| `QL-078` | — | 1 | TotpService.get_state 拒收回退的锁定交错守卫：「store 拒收 → resolve」窗口内发生锁定时 require_vault_key 抛 VaultLockedError——get_state 由 Qt 槽（TOTPWidget._build）同步调用，未捕获异常在 PyQt6 槽内 qFatal；旧 preloaded 分支（直接用 preloaded 计算验证码）无此异常面，系 SEC-063 拒收回退引入。兜住后返回 None 与 TOTPWidget 的既有空值处理一致；DecryptionError 不捕获——resolve 的解密为非 strict 容错模式（失败归空串），该异常不可达，捕获面按实际收窄。 |

### SEC — 安全（59 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `SEC-001` | `SEC-001` | 2 | # CSV 列数硬上限（SEC-001）：先 ``list(reader)`` 物化行前校验 header 列数，防止单行 |
| `SEC-002` | `SEC-002` | 3 | 除 TTL 外校验 key_epoch（SEC-002）：改密轮换密钥后，旧 epoch 派生的报告即便在 |
| `SEC-003` | `SEC-003` | 18 | （SEC-003 威胁边界：明文可读意味着本地有读权限者可重算签名伪造安全配置，如把 |
| `SEC-004` | `SEC-004` | 2 | 重定向位置文件（SEC-004）。 |
| `SEC-005` | `SEC-005` | 3 | # 全量逐行断言加密列（SEC-005）：_assert_encrypted 仅做 O(1) ``cb2:`` 前缀检查， |
| `SEC-006` | `SEC-006` | 2 | # 备份校验的字符串型加密字段→明文长度上限映射，派生自 models 单一事实源（SEC-006）： |
| `SEC-007` | `SEC-007` | 1 | # SEC-007：此处把公开默认分类名以明文写入 name_enc 列，是有意为之——schema_manager |
| `SEC-008` | `SEC-008` | 8 | 把清洗点前移到入库边界（SEC-008）：导入阶段统一对受影响文本字段转义，使后续 |
| `SEC-009` | `SEC-009` | 3 | # mid-word 误匹配（donkey=…），中文关键词（密码/密钥/令牌）不受影响。SEC-009 补充 |
| `SEC-010` | `SEC-010` | 5 | （SEC-010）：让高敏感路径（清空回收站/改密/恢复/解锁）感知旧密文/明文可能 |
| `SEC-011` | `SEC-011` | 1 | # SEC-011：id 反查须在 _auto_commit() 之前完成——插入与反查在同一隐式事务内 |
| `SEC-012` | `SEC-013` | 1 | # 与 entry_repository._row_to_entry 一致向上传播（SEC-012），让调用方 |
| `SEC-013` | `SEC-014` | 5 | old_password 不在计划中收集（SEC-013）：延迟到 :meth:`_prepare_overwrite_batch` 写入前 |
| `SEC-014` | `SEC-1` | 3 | 避免 purge 经恶意链接把覆写重定向到任意目标（SEC-014，与 :func:`validate_file_path` 同源）。 |
| `SEC-015` | `SEC-2` | 8 | # 经 atomic_write 落地即 0600，消除「写明文密钥 → 关闭 → secure_file 收紧」间的世界可读窗口（SEC-015）。 |
| `SEC-016` | `SEC-CLIP-001` | 5 | # Windows 剪贴板原子写入（SEC-016）：单次 OpenClipboard 周期同时写 CF_UNICODETEXT 与 Win+V 历史排除标记，消除分两次写入的时序窗口。 |
| `SEC-017` | `SEC-CLIP-002` | 2 | # setText 容错（SEC-017）：text()/clear()/setText() 在剪贴板被占用时吞 RuntimeError 降级，不阻断 UI/锁定/托盘清理。 |
| `SEC-018` | `SEC-LOGIN-001` | 2 | # SEC-018：``password`` 已作为闭包传入 worker，KDF 派生期间（后台线程耗时）避免控件明文驻留。 |
| `SEC-019` | `SEC-LOG-001` | 1 | # SEC-019：关键词后可选引号捕获并在替换串回填，覆盖 dict/dataclass repr 的 ``'password': ...`` 形态（repr 中 key 带引号，原 ``\s*[:=]`` 漏匹配）。 |
| `SEC-020` | `SEC-TAGS-001` | 1 | # 读路径 epoch 守卫（SEC-020，对称 ``resolve_totp_secret`` 的 ARCH-005）：改密 commit 与 tags 聚合读的微秒窗口内裸读会用旧密钥解密新密文致 GCM 失败、tags 回退空串丢失。 |
| `SEC-021` | — | 1 | Windows ``_load_dpapi_integrity_key`` 检测到 pre-SEC-003 明文 config.key（合法长度但未 DPAPI 封装）时，重新经 DPAPI 封装原子覆盖写回，完成一次性升级迁移，消除明文密钥原样保留的泄漏面。（已退役：项目未发布不存在 pre-SEC-003 遗留形态，迁移分支经 SEC-052 删除、非 DPAPI 封装一律按损坏处理；残留 1 处引用即 config_key_store 的退役注记。） |
| `SEC-027` | — | 3 | 恢复流程 finally 直接置空 ``_DecryptedPayload.plaintext/.data`` 字段（``del`` 局部别名不释放调用方持有的引用），明文在 WAL checkpoint/purge 收尾期间不再驻留。 |
| `SEC-028` | — | 4 | ``atomic_write`` 临时文件名加 urandom 随机后缀 + opener ``O_EXCL``（POSIX 叠加 ``O_NOFOLLOW``），消除可预测名 unlink→open 窗口的 symlink 植入竞态。 |
| `SEC-029` | — | 10 | RateLimiter 状态文件包 HMAC-SHA256 签名行（复用 config 完整性密钥），验签失败按最高阶梯保守锁定并自愈重写，堵住「改写合法 JSON 归零计数」的绕过。 |
| `SEC-030` | — | 11 | 承载用户/导入数据的 QLabel 统一经 create_plain_text_label 工厂固定 PlainText（默认 AutoText 会被启发式判富文本：伪造信任样式、`<` 开头密码显示被吞、本地 SVG 解析链触达）；URL 标签的 RichText+转义路径保留。第三轮补齐：主窗列表标题（分类名 setText）、密码历史 changed_at 时间标签；TOTP 验证码标签评估为纯数字生成值安全不动。 |
| `SEC-031` | — | 5 | 确认密码常量时间比较统一 PasswordService.passwords_match 门面（utf-8 encode），四处调用点收编，防 QL-019 同型漏 encode 复发。 |
| `SEC-039` | — | 8 | CSV 含密码导出对 password/totp_secret 列跳过公式前缀转义（与 SEC-008 导入侧「不清洗密钥字段」决策对称）；导入侧 password 列不再 strip。UI 侧（import_export_dialog.export_warning_text）在 CSV+包含密码的确认警告中向用户明示该有意豁免。 |
| `SEC-040` | — | 3 | _try_incremental_update 二次校验改比快照 epoch（原比实时 epoch，跨 epoch 重填会把旧密钥指纹并入新缓存——当前 UI 时序不可达的防御纵深）。 |
| `SEC-041` | — | 20 | 摘要缓存回写增加写入方世代守卫（data_epoch）：跨恢复的旧 worker 不能把恢复前明文写入重臂后的新 epoch 缓存。 |
| `SEC-042` | — | 4 | RateLimiter 无签名降级时状态完全不落盘（消除「无签名状态文件」这一下次会话被误判篡改的形态；降级近乎不可达，跨会话计数丢失可接受）。 |
| `SEC-043` | — | 12 | SEC-041 的 data_epoch 写入方世代守卫全读路径接入：非搜索列表/get_recent_summaries/get_entry 详情（含 decrypt_summary/decrypt_entry 透传与 ViewDecryptCacheProtocol 声明）、SecurityAnalyzer._make_summary 调用链（full_analysis/_classify_entry/_try_incremental_update）、decrypt_category_name 均在锁内快照世代传入，堵「跨恢复后旧明文植入新 epoch 缓存」的四条遗留漏点。 |
| `SEC-044` | — | 10 | TOTP secret 缓存回写世代守卫：resolve_totp_secret 解密前锁内采样 epoch+version、回写前双重复查（TOTP 定时器是真实并发读者）；store_totp 增可选 data_epoch 复查（未提供保持无条件落缓存，既有调用方无跨世代窗口）。 |
| `SEC-045` | — | 1 | 导入侧公式注入清洗扩至 custom_fields 非 password 类型的 name/value（password 值豁免保持密钥完整性，与 SEC-039 决策对称），补齐 SEC-008「复制/导出无需各自防护」声明对该字段的不变量。 |
| `SEC-046` | — | 10 | EncryptionEngine.encrypt/decrypt/encrypt_bytes/decrypt_bytes 增 keyword-only ``cache_key``（False 时直接构造 AESGCM 不入模块级缓存）：一次性密钥（share 包派生密钥已接入）secure_zero 后 C 层副本不再滞留 _cipher_cache 至容量淘汰。backup_restore 两处调用点（cache_key=False）与恢复路径 clear_cache 已全部落地（原「未尽事项」描述过时，本轮核实修正）。 |
| `SEC-047` | — | 0（decrypter_template.html） | share 解密器 JS 的 onFileChange 补 file.size 4MB 前置上限（镜像 Python 侧 header_codec.MAX_SHARE_FILE_SIZE）与 arrayBuffer promise 的 .catch：GB 级恶意文件全量读入致标签页 OOM、读取失败（权限/占用）UI 停留「正在读取文件…」无反馈。 |
| `SEC-048` | — | 4 | 导入文件大小前置上限单一事实源 models.MAX_IMPORT_FILE_SIZE（200MB）：importers/base 新增 _check_import_file_size 供四策略类 parse 入口调用（第二道纵深），manager 的 _validate_import_path 引用同一常量（第一道）——原本地 25MB 与 models 新常量同名异值成双源，且 25MB 拒绝满配自导出文件（50k 条 JSON ≈35-38MB 的「能导出不能导入」断层）。 |
| `SEC-049` | — | 3 | decrypt_entry_for_export 三层补 data_epoch 世代守卫透传（ViewDecryptor→EntryManager 薄委托→get_entries_for_export 锁内快照）：导出 worker 在飞 + 恢复提交重臂新世代交错下，旧密钥解出的分类名经缓存回写植入新世代——SEC-043 全读路径接入的 export 链漏点（SEC-040 同级防御纵深）。 |
| `SEC-050` | — | 1 | 导入文件上限 200MB→80MB 口径对齐：同型防护（备份 80MB/共享包 4MB）均按 payload×2 取余量，导入满配自导出基准 ≈38MB（50k×~758B/条）应取 80MB；原 200MB 是 5 倍余量，json.load 物化膨胀 5-10 倍时（≈1-2GB 峰值）低内存机防护窗口过宽。 |
| `SEC-051` | — | 0（decrypter_template.html、tests） | 解密器 CSP meta（default-src 'none' + 内联 script/style + wasm-unsafe-eval + data: 图标）：esc() 转义之外的第二层 XSS 约束，封死外联加载与表单/嵌入通道。 |
| `SEC-052` | — | 4 | 删除 pre-SEC-003 明文 config.key 迁移分支，非 DPAPI 封装一律按损坏处理（SEC-021 退役）；写侧配套见 SEC-055。 |
| `SEC-053` | — | 5 | CategoryManager 明文分类缓存接入锁定/epoch 轮换清零回调。 |
| `SEC-054` | — | 19 | TOTP preloaded 预热写入补写入方世代守卫（SEC-044 漏点）；残余窗口彻底闭合：EntryManager 新增 get_entry_with_epoch 随 entry 携带读锁内快照世代（get_entry 薄委托丢弃世代），detail_panel.show_entry 增 data_epoch 透传并记录 _current_data_epoch 供 force 重建（主题切换持旧条目重显）复用——「解密后→预热前」窗口内恢复轮换世代时旧 secret 被缓存守卫拒收，主路径与 force 路径均不误判为零间隙。data_epoch 后改必传签名（无默认值）并增 current_data_epoch 只读 property 供 force 重建回传：「未传时现时快照 key_epoch」的最弱回退分支删除——漏传调用方原会编译通过却静默走弱分支，重开本编号关闭的窗口。SEC-063 b 层接入后 data_version 与 data_epoch 同源透传（同款必传/记录/force 复用模式）。 |
| `SEC-055` | — | 14 | Windows DPAPI protect 失败时不再回退写明文 32 字节 config.key（读侧 SEC-052 只认 DPAPI 封装，该文件下次启动必被判损坏 → 假完整性告警 + 敏感键回退 + RateLimiter 签名失配降级最大锁定）：_store_dpapi_integrity_key 返回 False 不落盘，load_or_create 的 win32 分支保持内存密钥运行本会话并记 CRITICAL（下次启动重新生成，签名失配告警与日志共同如实反映「密钥未能安全持久化」）；非 Windows 明文回退链不变。 |
| `SEC-056` | — | 1 | _parse_changed_utc 解析失败日志只记 crypto_id 不记 changed_at_str 明文值——解密后字段值不入日志，对齐「只记 id」纪律。 |
| `SEC-057` | — | 10 | 会话级临时密钥标记 session_only（ConfigKeyStore 置位、ConfigManager 透出、RateLimiter 消费）：Windows DPAPI protect 失败（SEC-055 降级）产生仅本会话有效的内存密钥，限流器此前仍以其签名状态落盘——下次启动密钥重新生成 → 签名失配按 SEC-029 保守分支降级最高阶梯锁定（15 次/600 秒），DPAPI 持续故障时每次启动误锁 10 分钟；现 _resolve_signing_key 对 session_only 返回 None 走 SEC-042 不落盘路径（仅内存限流、不建哨兵，下次按首次使用处理）；配合读侧 SEC-064 权衡（无法验签的既有状态文件按面值采信），诚实降级会话既不产生失配签名也不被叠加误锁。 |
| `SEC-058` | — | 1 | 自动备份调度三键（last_auto_backup_at/auto_backup_interval_hours/auto_backup_retention）纳入 _INTEGRITY_SENSITIVE_KEYS：last 被篡改为远期合法 ISO 使 is_auto_backup_due 恒 False、interval 拉满 168h 同为「自动备份静默停摆」通道（用户只见完整性告警却无从知晓备份停止），retention 压低收缩回滚快照保有量；完整性失败回退默认即恢复调度。 |
| `SEC-059` | — | 2 | SecureRotatingFileHandler：标准 doRollover 以进程 umask 重建新 baseFilename（POSIX 0644 世界可读），启动时的一次 secure_file 只覆盖首个文件；覆写轮转后对当前文件与全部轮转备份重新 secure_file（strict=False 降级不崩），configure_logging 启动 glob 一并收紧既有遗留备份。 |
| `SEC-060` | — | 1 | 日志脱敏关键词补充 nonce/salt/title/url/notes/tags：均为加密列对应明文或其派生输入（nonce/salt 是密文/密钥派生参数，title/url/notes/tags 是条目元数据），与 password 同级敏感（防未来误写纵深，当前无调用点命中）。 |
| `SEC-061` | — | 5 | validate_file_path 的 Windows 分支补保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9，按组件 stem 大小写不敏感整词匹配，含 CON.txt 带扩展名与尾随空格/点形态）与 NTFS 备用数据流冒号拒绝（剥 \\?\ / \\.\ 前缀与盘符首冒号后任何残留 ':'）；非 Windows 不检查（POSIX 合法字符，按 sys.platform 分支）；错误文案固定不回显用户输入。补强：\\.\ 设备命名空间仅放行「首组件为盘符且带后续路径」形态（\\.\C:\data\file.txt），\\.\PhysicalDrive0/\\.\Serial0/裸卷 \\.\C: 等设备对象本体拒绝——该前缀正是无冒号 Win32 设备对象命名空间，剥前缀后的残留冒号/保留名检查对其全放行。当前到达路径不可利用，属中央路径安全边界的未来功能纵深。 |
| `SEC-063` | — | 52 | 导入覆盖路径的 TOTP 缓存失效 + store_totp 补 TOTP 域版本守卫（审查确认的唯一真实可达正确性 bug），三层递进：a) prepare 阶段 evict（worker 线程锁外，先于写库对齐 QL-070）；b) **统一失效 seam（结构性根治）**——VaultManager.epoch_guarded_transaction 新增事务提交回调 register_on_transaction_committed（组合根注入 EntryCacheManager.clear_totp），任何写事务成功提交后自动清空 TOTP secret 缓存，写路径遗漏 per-site 失效不再静默留下旧 secret（原五处失效形态各自正确仅靠「GUI 线程亲和」纪律，见 ARCH-054）；旁路写事务（toggle_favorite）也触发，展示中条目下次 tick 重解密一次（低频可接受）；per-site 前置失效保留为「写库→提交」间窗口的纵深；原 write_overwrite_updates 写库后逐条 evict 循环删除（50k 持锁 pop 30-50ms，PERF-093）；c) **b 层真实通道**——get_entry_with_epoch 在读锁内与 raw/key/epoch 同刻快照 TOTP 域版本（EntryRead 三元组返回），经 detail_panel.show_entry（data_version 必传，对齐 data_epoch 模式）→ TOTPWidget.start → get_state 透传 store_totp：「解密 → 预热」窗口内的失效使旧 preloaded secret 被拒收（自采样与 store 侧比对同源、窗口外失效检测不到，降级为未传时的兜底）。（守卫粒度演进）store_totp 的版本拒收改按条目粒度：pop_totp 记录单条失效水位（_totp_invalidated_versions）并与整体失效水位（_totp_global_invalidated_version）并存——TOTP→TOTP 条目切换时 show_entry 对上一条目的 evict 必然推进全局版本，原守卫全局比对使新条目预热恒失配（时序自冲突）、在最常见浏览场景被结构性击穿，改条目粒度后被覆盖条目自身的旧 secret 仍拒收、整体失效仍整体拒收（水位随任何全局失效清空，内存驻留以无写操作的浏览会话为界）；store_totp 返回 bool，get_state 检测拒收时丢弃 preloaded 改走 resolve（DB 重解密）计算验证码——封死「被拒收的旧 secret 仍参与一次性显示/复制」出口。（演进：resolve_totp_secret 的回写守卫同款两级水位对齐——原全局版本精确相等比对使**其他条目**的 pop（详情切换 evict 上一条目）误拒正在解密条目的回写，免重解密在 resolve 侧部分失效；另「无实际写入的事务不触发 seam」——not-found 的 toggle_favorite 前置读检查移出事务、全判重导入的空写批次跳过事务，churn-only 空提交不再清空全部 TOTP 缓存并推进全局水位。） |
| `SEC-064` | — | 4 | RateLimiter 读侧对未验签状态文件的行为（权衡修正）：``_signing_key is None``（session_only/密钥获取异常/无 config）而状态文件存在时曾按「无法验证即不信任」降级最高阶梯锁定——但 session_only 降级会话（SEC-055/065）磁盘上留有上次正常会话的合法签名状态文件，而 _save_state 无签名密钥不落盘（SEC-042）、文件永不重签，每次启动都重复 600 秒零失败锁定，确定性误伤诚实用户、打破 SEC-057「避免每次启动误锁」承诺。篡改被采信需「签名密钥故障 + 文件被篡改」双条件，前者不可由攻击者诱发——确定性误伤 > 低概率理论窗口，改为采信文件内容并记 WARNING（内容损坏仍走损坏分支保守锁定）；签名密钥可用时的验签分支不变。残余面（如实登记）：「签名密钥故障不可由攻击者诱发」的前提不完全成立——文件写权限者可把 config.key 置为不可写（写盘 OSError 走 SEC-065 会话级降级），使此后每个会话按面值采信：限流退化仅内存（跨重启清零），配合每次启动前篡改状态文件可绕过跨会话退避（会话内 3 次→10 秒仍生效）；该能力下攻击者可直接复制 vault.db 离线攻击（严格更优），实际增量有限，属可接受残余（threat_model §2 已同步补注）。 |
| `SEC-065` | — | 10 | 密钥文件写盘失败不再崩启动（兑现「绝不阻断启动」契约）：_write_integrity_key_file 的 atomic_write（secure_file strict=True）在磁盘满/只读介质抛 OSError，沿 _store_secure_integrity_key→load_or_create→ConfigManager.__init__ 全链无捕获、启动即崩；修复对两个写盘分支（Windows DPAPI 封装写盘 / 非 Windows 明文回退写盘）捕 OSError 统一降级 session_only 语义（内存密钥 + CRITICAL，与 protect 失败的 SEC-055 分支对称），三处降级共用 _degrade_to_session_only 收口（session_only 置位使签名落盘方拒以临时密钥签名，SEC-057；session_only docstring 同步为三分支事实）。 |
| `SEC-066` | — | 5 | ``\\?\`` verbatim 前缀的设备对象绕过封堵（SEC-061 的残留缺口）：Win32 对象管理器把 \\?\ 解析为 \??\、与 \\.\ 一样查 DOS 设备目录，\\?\PhysicalDrive0/\\?\Serial0/裸卷 \\?\C: 同为可达设备对象，此前设备内容形态检查只挂 \\.\ 分支致三者放行；修复后 \\?\ 非 UNC 分支同样进入设备形态检查（首组件须盘符且带后续路径），\\?\UNC\ 剥除前缀后豁免（纯文件系统共享路径）；\\?\C:\data\file.txt 等文件系统 verbatim 形态不受影响。 |
| `SEC-067` | — | 5 | keyring 命中时明文 config.key 残留统一清理：两个残留面——a) keyring 记录损坏返回 None 走新生成，降级期明文文件遗留；b) 回迁时 secure_delete 失败（占用/权限），下次启动 keyring 直接命中、旧「迁移失败再清理」分支不再进入。修复：_load_keyring_integrity_key 命中有效密钥且 _key_path 明文文件存在时（无论来源）统一尝试 secure_delete_file（幂等、失败 ERROR 不阻断启动，下次启动重试），密钥既已由 keyring 供应，明文文件只是「本地读权限者可重算签名」的暴露面（SEC-003）。补强：长度校验（len==32）先于 secure_delete——原实现对任何可 base64 解码的 keyring 值先删明文文件，keyring 值损坏（可解码但非 32 字节）时会把可能唯一有效的明文回退密钥一并销毁（K1 签名链锁死断裂且无自愈路径），读取侧不先行销毁；前置条件经 SEC-070 演化为「密钥已由平台安全存储有效供应」（keyring 命中有效密钥，或新生成密钥已成功持久化）。 |
| `SEC-068` | — | 4 | SecureRotatingFileHandler 覆写 _open 以 0600 opener 创建日志文件（对齐 SEC-015 为 atomic_write 建立的「落地即 0600」标准）：super().doRollover() 内经 _open() 以 umask（POSIX 典型 0644）重建 baseFilename、其后 secure_file 收紧存在毫秒级世界可读窗口（SEC-059 只消除了轮转后的稳态宽松，未消除创建窗口）；opener（os.open 第三参 0o600）使创建那一刻即 0600、窗口归零，doRollover 的 secure_file 保留为幂等纵深（覆盖升级前遗留宽松备份）；Windows 忽略 POSIX mode 位（父目录 ACL），无行为差异。 |
| `SEC-069` | — | 3 | add_entry 接 epoch_guarded_transaction(pre_epoch=)：对齐 update_entry/toggle_favorite/导入/恢复的写路径防御层——原「锁外加密（实时 self._key）→ 直接 db.add_entry」仅靠写入瞬间 enforce_key_epoch，「加密后 → 写入前」窗口内改密完成 commit+activate 时旧密钥密文落入已轮换为新 epoch 的库且永久不可解密（不可达仅靠 GUI 线程模态串行的巧合，SEC-063 注释点名的形态）；pre_epoch 在加密前快照（MAINT-004 导入路径的透传形态），加密保持事务外不占 db_lock；注入改密时序的测试锚定中止回滚且不落库。 |
| `SEC-070` | — | 4 | keyring 记录损坏走新生成后的明文残留清理：b64 解码失败/长度错 → return None → 新生成并成功写入 keyring 后，同盘明文回退文件既不作为回退候选也不被删除（SEC-067 原仅 keyring 命中有效密钥时清理），暴露面残留至下次启动的命中分支。与命中分支共用 _purge_plaintext_key_residue（幂等 secure_delete + 失败 ERROR 不阻断启动）；此时旧明文密钥已退役（新密钥生效、旧签名本就失配告警并经下次保存自愈），清理无 SEC-067「销毁可能唯一有效回退」之虞。win32 不适用：stored=True 时 key_path 刚被 DPAPI 封装写占（非明文残留），且 win32 无明文回退形态（SEC-055）。 |
| `SEC-071` | — | 7 | compare_digest 非 ASCII 陷阱根治：共享常量时间 ASCII 比较器 ``src/utils/secure_compare.constant_time_mac_equals``（非 ASCII stored 短路 False——期望值恒为 hexdigest，短路结论与任何输入下的比较结果同为「必不相等」，无时序泄露意义），五个 MAC 比较站点全部收编单一入口、禁止 call-site 内联（PasswordService.passwords_match 的 SEC-031 纪律）：config.json 签名行与 rate_limiter 状态文件验签（原两份 isascii 内联手抄删除）、vault_lifecycle 的 vault_meta_mac 比对（原无守卫——非 ASCII 篡改抛 TypeError 落 unlock 的 generic except 被包装为 VaultError，篡改误分类为系统错误、告警语义被稀释）、metadata_signer 的 verify/verify_category（原无守卫——TypeError 逃出 db 层 _row_to_entry 的 except VaultIntegrityError 捕获面（STRICT/LENIENT 双模式）与 QL-077 的捕获，篡改条目每读必崩、TOTP 定时器每秒冲刷异常日志）。修复后非 ASCII 一律走「验签失败」既有语义：config→integrity_reason="mismatch" 告警链与敏感键回退、unlock→VaultIntegrityError（清零密钥 + lock）、条目/分类→STRICT 抛 / LENIENT 标记。首处修复为 config.json 签名行（后演进为共享比较器收编全站点）。（SEC-069 已让号予 entry_manager 的 add_entry epoch_guarded_transaction 写守卫，并行批次先用。） |
| `SEC-072` | — | 6 | 非事务删除写的「写后 TOTP 再清」软删重入窗口封堵：soft_delete/permanent_delete/empty_trash 不经 epoch_guarded_transaction（各自隐式提交，SEC-063 seam 不覆盖），前置 pop/clear 记录的水位为失效完成时刻的版本 N——「恰在 pop 后快照」（data_version=N）的读者读到尚未删除的活跃行，删除提交后其 store 复查 N > N 为 False 仍被放行，已删条目的明文 secret 重入缓存（当前靠 GUI 线程串行不可达，ARCH-054 窗口推演的纵深）。修复选「写后再 pop/clear 一轮」（delete_entry/permanent_delete_entry 的 pop_totp + empty_trash 的 clear_totp）使水位越过一切提交前快照，写路径自身闭环不依赖其后的通知链；评估过备选「pop 水位改记 version+1」并否决——快照恰等于 pop 时版本的真实重访流（点击条目→点空白 evict→再点同一条目，无其他 TOTP 域推进介入）会被恒拒收，退化为展示期每秒重解密。配套：restore_entry 不自带 TOTP 失效的跨方法耦合（依赖 delete 已 pop）经注释+行为测试 pin；entry_manager 写路径区域新增单条写纪律 checklist（pop-before-write / 写后闭环 / epoch 守卫 / 差分世代快照，ARCH-054 指针）。 |
