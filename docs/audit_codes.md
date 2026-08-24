# 审计编号索引

代码注释中的审计编号（5 维度）登记表，供跨文件 grep 追踪同一改进决策的所有触点。

## 编号约定（新增遵循）

- **格式**：`<维度前缀>-NNN`，三位零填充（如 `SEC-003`、`PERF-012`、`ARCH-005`）。
- **维度前缀**：`ARCH`（架构）/ `MAINT`（维护·可维护性）/ `PERF`（性能）/ `QL`（质量·可读性）/ `SEC`（安全）。
- **新增编号**须在本文件对应维度表登记，避免跨文件漂移与编号复用。
- **双向引用**：新编号除登记索引外，须在对应代码注释以 ``（XXX-NNN）`` 引用，保证索引-代码一致（MAINT-014）。纯约定/已放弃编号（处数=0）豁免。
- **处数口径**：「处数」列按 ``src/**/*.py`` 内该编号的引用次数统计（rg 可复算）；
  引用仅在 src 之外的编号记 0 并在处数单元格加注位置（MAINT-008=ci.yml、
  MAINT-013=tests、MAINT-041=ci.yml 与 CLAUDE.md）。

## 历史重编号说明

早期存在两套并行的编号体系——未填充的 `SEC-1`/`MAINT-1`/`ARCH-3`/`QL-3`/`PERF-1` 与
填充的 `SEC-001`/`MAINT-001`/...，且性能维度有 `PF-`/`PERF-` 双前缀，同号异义冲突
（如 `SEC-2`=0600 落地窗口 ≠ `SEC-002`=key_epoch 校验）。2026-08 全量重编号为统一的
`PREFIX-NNN` 三位连续编号，消除冲突与跳号。下表「旧编号」列保留以追溯 git 历史 commit
message 中的旧编号引用。

## 映射表（新编号为主序）

### ARCH — 架构（18 项）

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
| `ARCH-032` | — | 4 | EntryViewDecryptor 的 cache 依赖改最小协议 ViewDecryptCacheProtocol（对齐 TotpService 模式，services 不反向依赖 managers 具体类）。 |
| `ARCH-033` | — | 2 | 组合根子服务装配规则显式化：有自持状态/独占缓存的组合根显式注入；纯变换/共享缓存无状态的宿主内部构造共用同一 cache 实例。 |
| `ARCH-034` | — | 2 | 双源常量收编：security_analyzer.DEFAULT_ANALYSIS_DAYS 改 import config.OLD_PASSWORD_WARNING_DAYS_DEFAULT（QL-005 的本地解耦理由已失效，business→config 合法），ui/constants.RECENT_ENTRY_LIMIT 改引 business 的 DEFAULT_RECENT_SUMMARIES_LIMIT（UI→business 合法，业务默认成唯一源）。 |
| `ARCH-035` | — | 2 | 主题默认值单一事实源：constants.THEME_LIGHT 与 theme_colors._current_theme 模块初值均直接派生自 config.DEFAULT_THEME（UI→config import 合法，无循环），消除三处 'light' 字面量靠注释约定同值的漂移面。 |

### MAINT — 维护/可维护性（20 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `MAINT-001` | `MAINT-001` | 1 | 包裹解密到 WAL 截断）由各阶段方法与 try/finally 维护（MAINT-001）。 |
| `MAINT-002` | `MAINT-002` | 1 | """两阶段加密写入单分类（MAINT-002）：占位 id 加密 INSERT → 真实 id 重加密 UPDATE。 |
| `MAINT-003` | `MAINT-003` | 1 | # add_entry 对称（MAINT-003）：UPDATE 含 category_id 外键，引用不存在的分类时 |
| `MAINT-004` | `MAINT-004` | 20 | """覆盖项加密预处理结果（MAINT-004）：写阶段所需的最小密文载荷。 |
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
| `MAINT-021` | — | 7 | EntryManager 视图解密族（detail/export/summary 三视图 + 严格/容错字段解密，约 300 行）下沉 ``services/entry_view_decryption.py``（``EntryViewDecryptor``），EntryManager 公开方法保持薄委托、调用方零改动。 |
| `MAINT-041` | — | 0（ci.yml、CLAUDE.md） | 命令统一 ``uv run -m <module>`` 形式（pytest/mypy/pyright/coverage）：trampoline 入口在部分 uv/Windows 组合报 canonicalize 失败；引用位于 ci.yml 与 CLAUDE.md（非 .py，处数按代码口径为 0）。 |
| `MAINT-071` | — | 8 | entry_repository（844 行全库最大）的密码历史块拆分 ``password_history_repository.py``（7 方法单表访问，镜像 category_repository 模式），DatabaseManager 委托纯搬迁零增减。 |
| `MAINT-081` | — | 0（tests） | ``tests/utils/test_clipboard.py`` git mv 至 ``tests/ui/``：被测对象为 ``src/ui/utils/clipboard.py``，恢复 tests↔src 目录镜像约定（文件内均为绝对导入，移动零改动）。 |

### PERF — 性能（34 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `PERF-001` | `PF-001` | 31 | ``key`` 为 PERF-001 并发修补（M3）：调用方（如 :meth:`EntryManager.get_entry` |
| `PERF-002` | `PF-001-R` | 2 | # PERF-002：清理异常就地捕获降级 warning，不漂移致「备份已成功却被误报失败」 |
| `PERF-003` | `PF-002` | 1 | # 短路（PERF-003）：详情面板已显示同一条目（id + updated_at 未变）时跳过重复 |
| `PERF-004` | `PF-003` | 4 | """批量新增分类（恢复路径），返回按输入顺序的新 id 列表（PERF-004）。 |
| `PERF-005` | `PF-004` | 1 | # 复用面板已解密明文（PERF-005）：右键复制密码的常是当前详情条目，直接取其已解密 |
| `PERF-006` | `PF-005` | 5 | prepared 阶段逐条解密（PERF-006：不在 _prepare_overwrite_batch 批量预解密致全部旧密码同刻 |
| `PERF-007` | `PF-008` | 1 | count_files + secure_purge 各 glob 一遍同目录同模式（PERF-007），但恢复点文件 |
| `PERF-008` | `PF-009` | 1 | # CategoryManager.get_categories 在解密后按 name.casefold() 完成（PERF-008）。 |
| `PERF-009` | `PF-010` | 2 | 快照避免每条经 ``self._key`` 复制密钥（PERF-009）。失败回退空串，与 |
| `PERF-010` | `PERF-002` | 4 | # PERF-010：逐条解密已含 GCM 认证，_classify_entry 双重判定损坏， |
| `PERF-011` | `PERF-004` | 2 | # PERF-011：默认列表视图 ORDER BY is_favorite DESC, updated_at DESC 的复合索引， |
| `PERF-012` | `PERF-005` | 1 | # 阈值由 100 下调至 50（PERF-012）：冷缓存下 50-100 条目的全量摘要解密（每条 4 字段 |
| `PERF-013` | `PERF-1` | 2 | # 标签聚合仅需 tags 字段，用 VerifyMode.SKIP 跳过逐行元数据 HMAC 验签（PERF-013）。 |
| `PERF-014` | `PERF-2` | 2 | 不含 Entry 列表，获取时无需 :meth:`_refilter_cache` 深拷贝（PERF-014）。 |
| `PERF-015` | — | 0 | （已放弃）HMAC 验签结论缓存漏检 db 内容篡改（改字段不改 mac），安全优先放弃，代码无引用，详见 memory `perf015-skipped-verify-cache`。 |
| `PERF-016` | — | 3 | 搜索热路径一次取完整 SearchMetadata，摘要构建与小写匹配共用，省第二次缓存查询。 |
| `PERF-017` | — | 1 | generate_password 先 list comprehension 收必选字符、再 extend 填充剩余，替代逐次 append 循环（PERF401）。 |
| `PERF-018` | — | 1 | ``get_entry_summaries`` 搜索路径将 ``matches_search_lower`` 匹配检查前移到 ``_decrypt_summary`` 之前，仅命中条目才构建完整摘要，省去未命中条目的 Entry 构造与分类名/failed_fields 缓存查询。 |
| `PERF-019` | — | 5 | 搜索路径 fetch 改 ``VerifyMode.SKIP``，仅命中行补 LENIENT 验签（上界后被 PERF-032 取消、二次读库被 PERF-067 改就地验签）；未命中行不验签，篡改检测由无搜索词的全量列表刷新覆盖（温态实测：验签+宽列读取反超解密成为主导成本）。 |
| `PERF-020` | — | 9 | entry_repository 新增窄投影读取（``get_entries_for_analysis``/``get_entries_tags_projection``），标签聚合与安全分析的全表扫描不再物化 notes_enc/custom_fields_enc/totp_secret_enc 大列。 |
| `PERF-021` | — | 9 | EntryChangeBus 回调透传 ``crypto_id``，SecurityAnalyzer 增量失效：单条编辑仅锁外重读重分类该条（copy-on-write 重建指纹桶），替代每次保存触发整库密码解密 + HMAC 重算。 |
| `PERF-022` | — | 4 | 导入统一通知改 ``clear_summaries=False``，含覆盖时先对被覆盖 crypto_id 批量 pop 再通知，兑现「导入新增保留既有摘要缓存」的设计声明。 |
| `PERF-023` | — | 7 | 安全仪表盘：徽章改 objectName+集中 QSS（消除每行 setStyleSheet）、tab 懒填充（切换才 populate）、单 tab 500 行上限+截断页脚；500 行填充 175ms→120ms。 |
| `PERF-032` | — | 1 | 搜索补验签改对全部命中行（删除 1000 上界截断）：验签集合与 UI 重排后的渲染集合错位（SQL 序 vs 排序序）；PERF-067 就地验签后全量验签仅剩纯 HMAC 计算。 |
| `PERF-062` | — | 5 | 分析缓存出口剥离内部键（_fingerprint_map/_summaries_with_dates 无消费方却每次出口深拷贝，50k 库 13ms/次）+ 增量重建改局部 copy-on-write（仅旧/新指纹桶）。 |
| `PERF-063` | — | 1 | decrypt_summary 六覆盖字段并入单次 copy_entry_fields（原 build_entry_summary+replace 双重 24-kwarg 构造，50k 次省 ~300ms）。 |
| `PERF-064` | — | 4 | 分类条目计数会话缓存（CategoryManager 持有，epoch 守卫 + change_bus 结构性变更自订阅 + 条目改分类显式失效；50k 库省 24.6ms/次的 UI 线程 GROUP BY）。 |
| `PERF-065` | — | 10 | 导入进度回调覆盖全阶段加权刻度（parse 5%/sanitize 10%/classify 15%/encrypt 70%/write 100%，每 100 行节流），替代只覆盖 7% 时长的先冲满后冻结。 |
| `PERF-066` | — | 1 | 无搜索全列表刷新 LIMIT 下推：EntryListController.fetch_all 把 MAX_SEARCH_RESULTS_DISPLAY 经 EntryQuery 下推 SQL LIMIT（UI 渲染本就截断、同一 PERF-011 复合索引序，行为等价），50k 温态全量拉取+逐行验签+Entry 构造 1.8-3s → ~60-70ms；搜索路径不下推（先截断后过滤致命中失真）。 |
| `PERF-067` | — | 2 | 搜索补验签改内存就地验签：metadata_signer 暴露纯函数 verify_raw（提取 db 层 entry_verifier 钩子的 HMAC 计算与比对），_reverify_search_matches 对已物化命中行就地验签（域密钥由锁内快照主密钥派生），删除经 get_entries_by_ids 的二次 SQL 全表读（实测 5000 ids 234.6ms、50k 1.3-2s，另驻留一份 208MB 宽行）。 |
| `PERF-068` | — | 10 | 备份载荷估算改明文长度 + JSON 模板字节数运行期校准（消除密文估算 1.65 倍虚高）；上限 32→40MB/64→80MB 与 50k 条目上限联动（50k 空库 ≈17MB、典型画像 ≈38MB < 40MB）。 |
| `PERF-069` | — | 14 | 导入进度接入覆盖路径（prepare/write_overwrite 增 progress 参数，纯覆盖导入不再冻结在 15%）+ classify 阶段节流（对齐 encrypt 的每 100 行，消除 50k 次跨线程信号）。 |
| `PERF-070` | — | 8 | 导出确定进度：解密阶段 0→70 / 写文件 70→100 节流上报（50k 实测 5.1s/1.9s 定刻度），UI 收到确定值切确定模式。 |
| `PERF-071` | — | 2 | EntryItemDelegate 颜色缓存升级为直接持 QColor 对象（_get_color/_get_strength_color 共用，clear_color_cache 一并失效）：paint 每行 ~9 次 QColor(hex) 构造（~1.8-2.1µs/次）改 dict 命中（~0.06µs），offscreen 交替 A/B 实测典型行省 ~18µs、含警示/删除徽章行省 ~26µs。 |

### QL — 质量/可读性（36 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `QL-001` | `QL-001` | 3 | 「一次性获取全部明文」场景（QL-001）。 |
| `QL-002` | `QL-002` | 2 | # 恢复点含恢复前全部明文，删除失败意味着泄漏面未收缩，需可见日志（QL-002）。 |
| `QL-003` | `QL-003` | 1 | 供状态文件缺失/损坏等绕过嫌疑场景复用（QL-003，三处重复抽此方法）：最高阶梯 |
| `QL-004` | `QL-004` | 5 | 命名 ImportDataError（QL-004）以消除与 Python 内置 ``ImportError`` 的同名遮蔽—— |
| `QL-005` | `QL-006` | 1 | # 过期检测默认天数（QL-005）：数值与 config.OLD_PASSWORD_WARNING_DAYS_DEFAULT 对齐， |
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
| `QL-042` | — | 1 | Entry.from_dict 对三个时间戳字段做 fromisoformat 可解析校验（非空时），堵住任意字符串入库破坏「ISO 字符串排序==时间排序」等价性与过期检测。 |
| `QL-043` | — | 3 | ShareError 归入 error_messages 保留 str 分支（原落 default 丢面向用户的消息）；category_repository 同「分类重名」条件的裸 ValueError 统一改 EntryError。 |
| `QL-044` | — | 2 | EntryManager 增只读 cache property 消除测试双层私有穿透（_category_mgr._cache）；prepare_password_update 改调 PasswordService.passwords_match 门面。 |
| `QL-045` | — | 1 | TOTP base32 尾随 = 边界：_normalize_base32 先剥离全部既有 = 再统一补齐——「对齐长度+多余尾随 =」形态（如 16 数据字符后跟 1 个 =）原「只补齐不剥离」会叠加成非法填充（8 个 =）抛 binascii.Error，与 docstring 兼容非标准填充的契约矛盾；合法对齐输入剥离后重补等幂无回归。 |
| `QL-046` | — | 3 | 加密侧循环化 + 守护：build_encrypted_entry_fields 与 build_encrypted_entry 改对 SENSITIVE_ENCRYPTED_FIELDS 循环产出（custom_fields JSON 序列化与 password override 特判，AAD 与原手工枚举一致），消除「解密/验签侧响亮失败、加密侧静默丢字段」的写读不对称（恢复往返断裂）；test_field_consistency 补键集/列集/往返两条守护。 |
| `QL-047` | — | 5 | 恢复点创建超限（PayloadTooLargeError）降级不阻断恢复：跳过恢复点 + 结果拼装「无回退快照，建议立即手动备份」警告；其余异常（磁盘满等）仍中止。 |
| `QL-048` | — | 2 | 自动快照业务失败（(False, msg) 元组）经 finished 检查走既有 Toast，兑现 QL-004 只覆盖异常路径的缺口。 |
| `QL-049` | — | 2 | Entry.from_dict 补 category 字段 isinstance+长度校验，堵住非 str 值导入中途裸 AttributeError 直达用户。 |
| `QL-050` | — | 2 | 启动入口双兜底：main() 包 try/except（构造期异常 basicConfig+logger.critical 落 stderr、尽力 QMessageBox.critical、退出码 1），_install_crash_handlers 前移至 QApplication 创建后立即安装；main.py 删除恒死代码 sys.path.insert（import 成功后插入无效果）。 |
| `QL-051` | — | 2 | share/renderer 占位替换改单遍 re.sub（回调按名分派）：原按序多次 str.replace 时后置占位符会扫描先注入的第三方 JS bundle，bundle 内 ``{{...}}`` 字面量会被二次替换。 |

### SEC — 安全（34 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `SEC-001` | `SEC-001` | 2 | # CSV 列数硬上限（SEC-001）：先 ``list(reader)`` 物化行前校验 header 列数，防止单行 |
| `SEC-002` | `SEC-002` | 3 | 除 TTL 外校验 key_epoch（SEC-002）：改密轮换密钥后，旧 epoch 派生的报告即便在 |
| `SEC-003` | `SEC-003` | 11 | （SEC-003 威胁边界：明文可读意味着本地有读权限者可重算签名伪造安全配置，如把 |
| `SEC-004` | `SEC-004` | 2 | 重定向位置文件（SEC-004）。 |
| `SEC-005` | `SEC-005` | 3 | # 全量逐行断言加密列（SEC-005）：_assert_encrypted 仅做 O(1) ``cb2:`` 前缀检查， |
| `SEC-006` | `SEC-006` | 2 | # 备份校验的字符串型加密字段→明文长度上限映射，派生自 models 单一事实源（SEC-006）： |
| `SEC-007` | `SEC-007` | 1 | # SEC-007：此处把公开默认分类名以明文写入 name_enc 列，是有意为之——schema_manager |
| `SEC-008` | `SEC-008` | 6 | 把清洗点前移到入库边界（SEC-008）：导入阶段统一对受影响文本字段转义，使后续 |
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
| `SEC-021` | — | 1 | Windows ``_load_dpapi_integrity_key`` 检测到 pre-SEC-003 明文 config.key（合法长度但未 DPAPI 封装）时，重新经 DPAPI 封装原子覆盖写回，完成一次性升级迁移，消除明文密钥原样保留的泄漏面。 |
| `SEC-027` | — | 3 | 恢复流程 finally 直接置空 ``_DecryptedPayload.plaintext/.data`` 字段（``del`` 局部别名不释放调用方持有的引用），明文在 WAL checkpoint/purge 收尾期间不再驻留。 |
| `SEC-028` | — | 4 | ``atomic_write`` 临时文件名加 urandom 随机后缀 + opener ``O_EXCL``（POSIX 叠加 ``O_NOFOLLOW``），消除可预测名 unlink→open 窗口的 symlink 植入竞态。 |
| `SEC-029` | — | 7 | RateLimiter 状态文件包 HMAC-SHA256 签名行（复用 config 完整性密钥），验签失败按最高阶梯保守锁定并自愈重写，堵住「改写合法 JSON 归零计数」的绕过。 |
| `SEC-030` | — | 13 | 承载用户/导入数据的 QLabel 统一经 create_plain_text_label 工厂固定 PlainText（默认 AutoText 会被启发式判富文本：伪造信任样式、`<` 开头密码显示被吞、本地 SVG 解析链触达）；URL 标签的 RichText+转义路径保留。第三轮补齐：主窗列表标题（分类名 setText）、密码历史 changed_at 时间标签；TOTP 验证码标签评估为纯数字生成值安全不动。 |
| `SEC-031` | — | 4 | 确认密码常量时间比较统一 PasswordService.passwords_match 门面（utf-8 encode），四处调用点收编，防 QL-019 同型漏 encode 复发。 |
| `SEC-039` | — | 6 | CSV 含密码导出对 password/totp_secret 列跳过公式前缀转义（与 SEC-008 导入侧「不清洗密钥字段」决策对称）；导入侧 password 列不再 strip。 |
| `SEC-040` | — | 3 | _try_incremental_update 二次校验改比快照 epoch（原比实时 epoch，跨 epoch 重填会把旧密钥指纹并入新缓存——当前 UI 时序不可达的防御纵深）。 |
| `SEC-041` | — | 18 | 摘要缓存回写增加写入方世代守卫（data_epoch）：跨恢复的旧 worker 不能把恢复前明文写入重臂后的新 epoch 缓存。 |
| `SEC-042` | — | 2 | RateLimiter 无签名降级时状态完全不落盘（消除「无签名状态文件」这一下次会话被误判篡改的形态；降级近乎不可达，跨会话计数丢失可接受）。 |
| `SEC-043` | — | 12 | SEC-041 的 data_epoch 写入方世代守卫全读路径接入：非搜索列表/get_recent_summaries/get_entry 详情（含 decrypt_summary/decrypt_entry 透传与 ViewDecryptCacheProtocol 声明）、SecurityAnalyzer._make_summary 调用链（full_analysis/_classify_entry/_try_incremental_update）、decrypt_category_name 均在锁内快照世代传入，堵「跨恢复后旧明文植入新 epoch 缓存」的四条遗留漏点。 |
| `SEC-044` | — | 4 | TOTP secret 缓存回写世代守卫：resolve_totp_secret 解密前锁内采样 epoch+version、回写前双重复查（TOTP 定时器是真实并发读者）；store_totp 增可选 data_epoch 复查（未提供保持无条件落缓存，既有调用方无跨世代窗口）。 |
| `SEC-045` | — | 1 | 导入侧公式注入清洗扩至 custom_fields 非 password 类型的 name/value（password 值豁免保持密钥完整性，与 SEC-039 决策对称），补齐 SEC-008「复制/导出无需各自防护」声明对该字段的不变量。 |
| `SEC-046` | — | 10 | EncryptionEngine.encrypt/decrypt/encrypt_bytes/decrypt_bytes 增 keyword-only ``cache_key``（False 时直接构造 AESGCM 不入模块级缓存）：一次性密钥（share 包派生密钥已接入）secure_zero 后 C 层副本不再滞留 _cipher_cache 至容量淘汰。backup_restore 两处调用点接入与恢复路径 clear_cache 为未尽事项。 |
