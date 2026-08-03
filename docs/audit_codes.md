# 审计编号索引

代码注释中的审计编号（5 维度）登记表，供跨文件 grep 追踪同一改进决策的所有触点。

## 编号约定（新增遵循）

- **格式**：`<维度前缀>-NNN`，三位零填充（如 `SEC-003`、`PERF-012`、`ARCH-005`）。
- **维度前缀**：`ARCH`（架构）/ `MAINT`（维护·可维护性）/ `PERF`（性能）/ `QL`（质量·可读性）/ `SEC`（安全）。
- **新增编号**须在本文件对应维度表登记，避免跨文件漂移与编号复用。
- **双向引用**：新编号除登记索引外，须在对应代码注释以 ``（XXX-NNN）`` 引用，保证索引-代码一致（MAINT-014）。纯约定/已放弃编号（处数=0）豁免。

## 历史重编号说明

早期存在两套并行的编号体系——未填充的 `SEC-1`/`MAINT-1`/`ARCH-3`/`QL-3`/`PERF-1` 与
填充的 `SEC-001`/`MAINT-001`/...，且性能维度有 `PF-`/`PERF-` 双前缀，同号异义冲突
（如 `SEC-2`=0600 落地窗口 ≠ `SEC-002`=key_epoch 校验）。2026-08 全量重编号为统一的
`PREFIX-NNN` 三位连续编号，消除冲突与跳号。下表「旧编号」列保留以追溯 git 历史 commit
message 中的旧编号引用。

## 映射表（新编号为主序）

### ARCH — 架构（11 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `ARCH-001` | `ARCH-001` | 3 | """预扫描条目分类名，批量创建缺失分类并回填 ctx.categories（ARCH-001）。 |
| `ARCH-002` | `ARCH-002` | 2 | # ARCH-002：注入批量写回调，解耦 backup_rebuilder 与 EntryManager。 |
| `ARCH-003` | `ARCH-003` | 9 | 事件经独立回调通道触发（ARCH-003），详见下方注册处注释。 |
| `ARCH-004` | `ARCH-004` | 8 | 命令-查询分离（ARCH-004）：本 property 仅查询，不打开/关闭数据库。db 文件不 |
| `ARCH-005` | `ARCH-005` | 13 | 比对内存与库内 epoch 不一致时抛出（ARCH-005）：中止读路径以防用旧密钥解密新密文 |
| `ARCH-006` | `ARCH-006` | 3 | # ARCH-006：恢复点创建/统计/清理统一由 RestorePointManager 承载。备份加密管线 |
| `ARCH-007` | `ARCH-008` | 2 | 行为钩子（ARCH-007）以布尔标志形式挂入，消除消费方 ``if entry_type ==`` |
| `ARCH-008` | `ARCH-009` | 5 | # 应用全局样式；显式激活主题，使运行时 c() 解析的颜色与样式表一致（ARCH-008） |
| `ARCH-009` | `ARCH-019` | 1 | # sqlite 事务 + QThread running 析构崩溃（ARCH-009）。 |
| `ARCH-010` | `ARCH-024` | 3 | # 只读映射（MappingProxyType 防误写，ARCH-010）：均派生自 _INT_SPECS。 |
| `ARCH-011` | `ARCH-3` | 1 | # 的值再签，与恢复路径对称，消除手工键集漂移（ARCH-011）。回读须在调用方事务内， |

### MAINT — 维护/可维护性（14 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `MAINT-001` | `MAINT-001` | 1 | 包裹解密到 WAL 截断）由各阶段方法与 try/finally 维护（MAINT-001）。 |
| `MAINT-002` | `MAINT-002` | 1 | """两阶段加密写入单分类（MAINT-002）：占位 id 加密 INSERT → 真实 id 重加密 UPDATE。 |
| `MAINT-003` | `MAINT-003` | 1 | # add_entry 对称（MAINT-003）：UPDATE 含 category_id 外键，引用不存在的分类时 |
| `MAINT-004` | `MAINT-004` | 19 | """覆盖项加密预处理结果（MAINT-004）：写阶段所需的最小密文载荷。 |
| `MAINT-005` | `MAINT-005` | 1 | # 配置键名常量（MAINT-005 单一事实源）：DEFAULT_CONFIG / _INT_SPECS / _BOOL_KEYS / |
| `MAINT-006` | `MAINT-008` | 1 | 编排分两步（MAINT-006）：事务内重加密+元数据 → 事务后激活密钥+清理；异常兜底与 |
| `MAINT-007` | `MAINT-009` | 6 | default_category_id/duplicate_action/source_label 参数（MAINT-007），使方法签名 |
| `MAINT-008` | `MAINT-010` | 1 | # 分层覆盖率门槛（分支覆盖，MAINT-008）：开启 --cov-branch 后分支率严格 ≤ 行率， |
| `MAINT-009` | `MAINT-011` | 1 | # 限制 csv 解析器单字段最大长度（MAINT-009）：默认 128KB 与本项目逐项大小策略 |
| `MAINT-010` | `MAINT-019` | 1 | 统一字符类型校验为单一事实源（MAINT-010）。有效时错误信息为空串，无效时返回 |
| `MAINT-011` | `MAINT-1` | 2 | # 分支于测试框架存在性（MAINT-011）。 |
| `MAINT-012` | `MAINT-2` | 1 | # 平台判定单一常量（MAINT-012）：统一引用，避免 os.name=='nt' 与 sys.platform=='win32' 混用 |
| `MAINT-013` | `MAINT-3` | 3 | """BackupDialog 接线测试：控件值→业务参数→结果文案（MAINT-013）。 |
| `MAINT-014` | — | 0 | 审计编号双向引用约定：新编号须在代码注释 ``（XXX-NNN）`` 引用，使 rg 可从代码回溯决策（本轮 PERF-017/QL-015/QL-016/QL-017 已补齐；纯约定/已放弃编号处数=0 豁免）。 |

### PERF — 性能（18 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `PERF-001` | `PF-001` | 26 | ``key`` 为 PERF-001 并发修补（M3）：调用方（如 :meth:`EntryManager.get_entry` |
| `PERF-002` | `PF-001-R` | 2 | # PERF-002：清理异常就地捕获降级 warning，不漂移致「备份已成功却被误报失败」 |
| `PERF-003` | `PF-002` | 1 | # 短路（PERF-003）：详情面板已显示同一条目（id + updated_at 未变）时跳过重复 |
| `PERF-004` | `PF-003` | 2 | """批量新增分类（恢复路径），返回按输入顺序的新 id 列表（PERF-004）。 |
| `PERF-005` | `PF-004` | 1 | # 复用面板已解密明文（PERF-005）：右键复制密码的常是当前详情条目，直接取其已解密 |
| `PERF-006` | `PF-005` | 5 | prepared 阶段逐条解密（PERF-006：不在 _prepare_overwrite_batch 批量预解密致全部旧密码同刻 |
| `PERF-007` | `PF-008` | 1 | count_files + secure_purge 各 glob 一遍同目录同模式（PERF-007），但恢复点文件 |
| `PERF-008` | `PF-009` | 1 | # CategoryManager.get_categories 在解密后按 name.casefold() 完成（PERF-008）。 |
| `PERF-009` | `PF-010` | 2 | 快照避免每条经 ``self._key`` 复制密钥（PERF-009）。失败回退空串，与 |
| `PERF-010` | `PERF-002` | 1 | # PERF-010：逐条解密已含 GCM 认证，_classify_entry 双重判定损坏， |
| `PERF-011` | `PERF-004` | 1 | # PERF-011：默认列表视图 ORDER BY is_favorite DESC, updated_at DESC 的复合索引， |
| `PERF-012` | `PERF-005` | 1 | # 阈值由 100 下调至 50（PERF-012）：冷缓存下 50-100 条目的全量摘要解密（每条 4 字段 |
| `PERF-013` | `PERF-1` | 1 | # 标签聚合仅需 tags 字段，用 VerifyMode.SKIP 跳过逐行元数据 HMAC 验签（PERF-013）。 |
| `PERF-014` | `PERF-2` | 3 | 不含 Entry 列表，获取时无需 :meth:`_refilter_cache` 深拷贝（PERF-014）。 |
| `PERF-015` | — | 0 | （已放弃）HMAC 验签结论缓存漏检 db 内容篡改（改字段不改 mac），安全优先放弃，代码无引用，详见 memory `perf015-skipped-verify-cache`。 |
| `PERF-016` | — | 2 | 搜索热路径一次取完整 SearchMetadata，摘要构建与小写匹配共用，省第二次缓存查询。 |
| `PERF-017` | — | 1 | generate_password 先 list comprehension 收必选字符、再 extend 填充剩余，替代逐次 append 循环（PERF401）。 |
| `PERF-018` | — | 1 | ``get_entry_summaries`` 搜索路径将 ``matches_search_lower`` 匹配检查前移到 ``_decrypt_summary`` 之前，仅命中条目才构建完整摘要，省去未命中条目的 Entry 构造与分类名/failed_fields 缓存查询。 |

### QL — 质量/可读性（17 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `QL-001` | `QL-001` | 2 | 「一次性获取全部明文」场景（QL-001）。 |
| `QL-002` | `QL-002` | 2 | # 恢复点含恢复前全部明文，删除失败意味着泄漏面未收缩，需可见日志（QL-002）。 |
| `QL-003` | `QL-003` | 1 | 供状态文件缺失/损坏等绕过嫌疑场景复用（QL-003，三处重复抽此方法）：最高阶梯 |
| `QL-004` | `QL-004` | 4 | 命名 ImportDataError（QL-004）以消除与 Python 内置 ``ImportError`` 的同名遮蔽—— |
| `QL-005` | `QL-006` | 1 | # 过期检测默认天数（QL-005）：数值与 config.OLD_PASSWORD_WARNING_DAYS_DEFAULT 对齐， |
| `QL-006` | `QL-007` | 1 | # 启动期断言（QL-006）：overload 的 Literal 键集须与 DEFAULT_CONFIG 中对应类型键一致， |
| `QL-007` | `QL-008` | 1 | # 重加密内存峰值（QL-007，消除魔法数 200）。 |
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

### SEC — 安全（21 项）

| 新编号 | 旧编号 | 处数 | 语义（代表性首处） |
|---|---|---|---|
| `SEC-001` | `SEC-001` | 2 | # CSV 列数硬上限（SEC-001）：先 ``list(reader)`` 物化行前校验 header 列数，防止单行 |
| `SEC-002` | `SEC-002` | 3 | 除 TTL 外校验 key_epoch（SEC-002）：改密轮换密钥后，旧 epoch 派生的报告即便在 |
| `SEC-003` | `SEC-003` | 3 | （SEC-003 威胁边界：明文可读意味着本地有读权限者可重算签名伪造安全配置，如把 |
| `SEC-004` | `SEC-004` | 2 | 重定向位置文件（SEC-004）。 |
| `SEC-005` | `SEC-005` | 4 | # 全量逐行断言加密列（SEC-005）：_assert_encrypted 仅做 O(1) ``cb2:`` 前缀检查， |
| `SEC-006` | `SEC-006` | 3 | # 备份校验的字符串型加密字段→明文长度上限映射，派生自 models 单一事实源（SEC-006）： |
| `SEC-007` | `SEC-007` | 1 | # SEC-007：此处把公开默认分类名以明文写入 name_enc 列，是有意为之——schema_manager |
| `SEC-008` | `SEC-008` | 3 | 把清洗点前移到入库边界（SEC-008）：导入阶段统一对受影响文本字段转义，使后续 |
| `SEC-009` | `SEC-009` | 4 | # mid-word 误匹配（donkey=…），中文关键词（密码/密钥/令牌）不受影响。SEC-009 补充 |
| `SEC-010` | `SEC-010` | 4 | （SEC-010）：让高敏感路径（清空回收站/改密/恢复/解锁）感知旧密文/明文可能 |
| `SEC-011` | `SEC-011` | 1 | # SEC-011：id 反查须在 _auto_commit() 之前完成——插入与反查在同一隐式事务内 |
| `SEC-012` | `SEC-013` | 1 | # 与 entry_repository._row_to_entry 一致向上传播（SEC-012），让调用方 |
| `SEC-013` | `SEC-014` | 5 | old_password 不在计划中收集（SEC-013）：延迟到 :meth:`_prepare_overwrite_batch` 写入前 |
| `SEC-014` | `SEC-1` | 5 | 避免 purge 经恶意链接把覆写重定向到任意目标（SEC-014，与 :func:`validate_file_path` 同源）。 |
| `SEC-015` | `SEC-2` | 9 | # 经 atomic_write 落地即 0600，消除「写明文密钥 → 关闭 → secure_file 收紧」间的世界可读窗口（SEC-015）。 |
| `SEC-016` | `SEC-CLIP-001` | 6 | # Windows 剪贴板原子写入（SEC-016）：单次 OpenClipboard 周期同时写 CF_UNICODETEXT 与 Win+V 历史排除标记，消除分两次写入的时序窗口。 |
| `SEC-017` | `SEC-CLIP-002` | 2 | # setText 容错（SEC-017）：text()/clear()/setText() 在剪贴板被占用时吞 RuntimeError 降级，不阻断 UI/锁定/托盘清理。 |
| `SEC-018` | `SEC-LOGIN-001` | 2 | # SEC-018：``password`` 已作为闭包传入 worker，KDF 派生期间（后台线程耗时）避免控件明文驻留。 |
| `SEC-019` | `SEC-LOG-001` | 1 | # SEC-019：关键词后可选引号捕获并在替换串回填，覆盖 dict/dataclass repr 的 ``'password': ...`` 形态（repr 中 key 带引号，原 ``\s*[:=]`` 漏匹配）。 |
| `SEC-020` | `SEC-TAGS-001` | 1 | # 读路径 epoch 守卫（SEC-020，对称 ``resolve_totp_secret`` 的 ARCH-005）：改密 commit 与 tags 聚合读的微秒窗口内裸读会用旧密钥解密新密文致 GCM 失败、tags 回退空串丢失。 |
| `SEC-021` | — | 1 | Windows ``_load_dpapi_integrity_key`` 检测到 pre-SEC-003 明文 config.key（合法长度但未 DPAPI 封装）时，重新经 DPAPI 封装原子覆盖写回，完成一次性升级迁移，消除明文密钥原样保留的泄漏面。 |
