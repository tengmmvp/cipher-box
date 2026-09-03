# CipherBox 威胁模型

CipherBox 是**本地优先**的加密密码管理器：无任何网络通信，所有敏感数据经
AES-256-GCM 加密存储在本地 SQLite 数据库。威胁模型聚焦**本地内存与磁盘取证**
（攻击者已获得对运行进程或磁盘的访问），而非远程攻击。

本文档如实声明 CipherBox 在 CPython / 操作系统固有限制下**无法**提供密码学保证
的边界，以及对应的缓解措施。这些限制不是代码缺陷，而是本地优先桌面应用在标准
Python 运行时下的根本约束。

## 1. 已知限制（非密码学保证的边界）

### 1.1 AESGCM cipher 缓存的 C 层密钥副本

`EncryptionEngine._cipher_cache` 缓存 `AESGCM` 实例以避免重复 key schedule。
`AESGCM` 构造时会把密钥复制到 OpenSSL C 层；`clear_cache()` 仅清除 Python 侧
`OrderedDict` 引用，C 层副本依赖 `gc.collect()` 回收。

- **风险**：进程崩溃 dump（Windows Error Reporting、第三方崩溃收集器）在退出路径
  未完成 GC 时，可能包含上一次解锁密钥的 AESGCM C 层副本。
- **缓解**：缓存容量上限 `_MAX_CACHE_SIZE = 2`（仅容纳改密瞬间的旧+新双密钥窗口），
  最小化驻留副本数量；`lock()` / 改密后显式 `clear_cache()`，随后在调用线程（锁定
  即 GUI 线程）同步执行完整 `gc.collect()`。曾改经后台 Timer 延迟执行以免锁定卡顿，
  已撤销（PERF-084）：gc 可能 finalize 引用循环中的无父 QObject，非 GUI 线程删除
  C++ 对象违反 Qt 线程亲和。
- **残余风险**：CPython 无法从 Python 层强制释放 C 层内存。

### 1.2 不可变 `bytes` 密钥副本无法原地清零

CPython 的 `bytes` 不可变。`KeyManager` 内部以 `bytearray` 持有主密钥与快照密钥
（`secure_zero_buffer` 经 `ctypes.memset` 原地清零），但 `key` / `snapshot_key`
property 读取时返回 `bytes()` **副本**（防止并发清零风险），该副本不可原地清零，
依赖 GC 回收。

- **风险**：调用方持有的 `bytes` 密钥副本在引用释放前驻留内存，崩溃 dump 可读取。
- **缓解**：副本按需生成、用后即弃；改密/恢复路径的新密钥以 `bytearray` 持有并在
  `finally` 原地清零（见 `_re_encrypt_all` / `_restore_data`）。
- **残余风险**：CPython 下 `bytes` 不可变是根本限制。

### 1.3 安全删除在 SSD / 写时复制文件系统上非密码学保证

`secure_delete_file` 对文件内容覆写 + `fsync` 后 unlink。这在传统 HDD 上有效，
但在 SSD（磨损均衡）、压缩 NTFS 卷、写时复制文件系统（OpenZFS、Btrfs）上，覆写
不一定作用于原始扇区。

- **风险**：恢复点（`pre_restore_*.cbox`，含恢复前全部条目明文）、旧快照被「安全
  删除」后，原始扇区可能被取证工具部分还原。
- **缓解**：改密/恢复轮换 `snapshot_key` 使旧文件无法用新密钥解密；恢复点失败时
  明确提示用户「请重启应用以自动清理」；自动备份/改密后尽力清理。
- **残余风险**：存储介质层面的残留无法从应用层消除。

### 1.4 Python `str` 明文不可原地清零

UI 控件（`QLineEdit` / `QTextEdit`）持有的明文字符串是不可变 `str`，`clear()` 只
是重置控件文本，原始 `str` 对象依赖 GC 回收。`mark_secret_discarded` 是纯语义
标记（函数体仅 `del` 解除本帧对参数的引用，无任何擦除动作）——真正的明文释放
依赖调用方置空引用 / `clear()` 控件后由 GC 回收（历史上的「encode 出临时
bytearray 再清零」实现只擦除自身刚创建的副本、原串未动，反而短暂增加明文
副本数，已删除）。

- **风险**：UI 中曾显示的明文（密码、备注）在 GC 前驻留内存。
- **缓解**：保存/关闭后立即 `clear()` 控件释放引用；敏感字段经 `Sensitive` 包装
  抑制意外进入日志 / `repr`。
- **残余风险**：CPython `str` 不可变。

### 1.5 swap / 页面文件

操作系统可能将进程内存（含密钥、明文）换出到磁盘的 swap / 页面文件。

- **风险**：即使进程退出，明文/密钥可能残留在 swap 等待 OS 回收。
- **缓解**：Argon2id 派生用 64MB 内存硬化，提高换出成本；密钥以 `bytearray` 持有
  尽早清零。
- **残余风险**：应用层无法控制 OS 换页。

## 2. 缓解措施汇总

| 威胁 | 缓解 |
|------|------|
| GPU/ASIC 暴力破解主密码 | Argon2id（time=3 / 64MB / parallelism=4，OWASP 量级） |
| 密码验证令牌泄漏 | 不存哈希，加密已知明文验证；常量时间比较 |
| GCM nonce 重用 | 每次加密独立 `os.urandom(12)` |
| 密文置换/篡改 | GCM 认证 + 字段级 AAD（crypto_id + field_name）+ metadata HMAC |
| 时序侧信道 | `hmac.compare_digest` 用于密码/令牌/签名校验 |
| SQL 注入 | 全部参数化绑定（`?`），DDL/列名硬编码常量 |
| 共享包解密器页面 XSS | 输出统一 `esc()` 转义 + CSP `default-src 'none'`（仅放行内联脚本/样式与 WASM，封死外联加载与表单/嵌入通道） |
| 日志明文泄漏 | `RedactingFormatter` + `SensitiveDataFilter` 脱敏固定模式 |
| 改密/恢复期间崩溃 | 事务原子性 + epoch 守卫 + 异常路径密钥清零 |
| 历史明文快照泄漏 | snapshot_key 随主密钥轮换 + 旧快照/恢复点自动清理 |
| 重加密损坏静默清空 | `strict=True` 解密失败立即中止 + 事务回滚（A1） |
| 锁定后 worker 残留持密钥 | emergency_cancel 短超时 wait（A4） |

## 3. 高敏感用户建议

针对上述残余风险，对威胁模型有更高要求的用户建议：

1. **禁用 Windows Error Reporting**（系统属性 → 高级 → 错误报告），减少崩溃 dump
   含密钥残留的概率（见 §1.1）。
2. **启用全盘加密**（BitLocker / FileVault / LUKS），使磁盘上的 swap、崩溃 dump、
   被安全删除但未彻底清除的扇区在静态下受加密保护（见 §1.3 / §1.5）。
3. **关闭或加密 swap**，防止明文/密钥换出到磁盘（见 §1.5）。
4. **物理安全**：CipherBox 不防御攻击者获得运行中进程的内存读权限——锁屏后密钥
   已清零，但解锁期间任何能读进程内存的恶意软件均可获取密钥。

## 4. 不在威胁模型内

- **远程网络攻击**：CipherBox 无网络通信，不存在远程攻击面（依赖、操作系统网络
  漏洞除外）。
- **硬件级取证**：冷启动攻击、DMA 攻击等需物理接触的硬件级手段超出本地优先桌面
  应用的防御范围，应由全盘加密与物理安全措施覆盖。
- **特权恶意软件**：能读任意进程内存的恶意软件可在解锁期间直接窃取密钥，CipherBox
   不防御此类强对手（见 §3）。
