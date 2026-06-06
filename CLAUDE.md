# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

CipherBox（密匣）是一个本地优先的加密密码管理器，使用 Python 3.10+ 和 PyQt6 构建。所有敏感数据通过 AES-256-GCM 加密存储在本地 SQLite 数据库中，无任何网络通信。UI 语言为简体中文。

## 常用命令

```bash
# 安装依赖
pip install -r requirements.txt

# 启动应用
python main.py

# 运行全部测试
python -m pytest tests/

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
纯密码学原语，无数据库或 UI 依赖。`EncryptionEngine` 提供静态 AES-256-GCM 加解密方法。`MasterKeyManager` 通过 PBKDF2-HMAC-SHA256（600k 迭代）从主密码派生密钥。密码验证不存储哈希，而是加密一段已知明文（验证令牌）来确认密码正确性。

### Data 层 (`src/database/`)
SQLite WAL 模式，手动事务管理（begin/commit/rollback）。Schema 当前为 V3，支持从 V1/V2 迁移。数据模型使用 `@dataclass`（`Entry`, `Category`, `CustomField`, `PasswordHistory`）。加密字段列名以 `_enc` 后缀标记。数据库层只处理加密后的数据，不了解密钥。

### Business 层 (`src/business/`)
编排 Crypto 和 Data 层。关键设计：
- `VaultManager` 持有加密密钥和数据库连接，是安全边界的核心
- `EntryManager` 透明地在写入时加密、读取时解密。因加密字段无法在数据库层面搜索，`get_entries()` 先拉取全部条目解密后在内存中过滤
- `ImportExportManager` 使用 `@_transactional_import` 装饰器确保导入操作的原子性
- `BackupRestoreManager` 实现可移植 V3 二进制备份格式，使用独立的备份密码派生密钥，支持跨主密码恢复

### UI 层 (`src/ui/`)
PyQt6 桌面 GUI。`MainWindow` 是中心编排器，创建所有 Business 层管理器和子组件。主题系统通过 `theme_colors.py` 定义 80+ 颜色 token（浅色/深色），QSS 样式表在 `styles.py` 中。图标通过 QtAwesome 语义化常量管理（`icons.py`）。

### 应用入口
`CipherBoxApp`（`src/app.py`）管理生命周期：登录 → 主窗口 → 锁定 → 重新登录。`VaultManager` 实例贯穿整个生命周期。

## 关键约定

- **安全优先**：主密码永不明文存储；每个加密值使用独立随机 12 字节 nonce；PBKDF2 迭代次数遵循 OWASP 2023 建议
- **事务安全**：主密码修改和备份恢复包裹在数据库事务中，失败时回滚。配置保存使用原子写入（写 .tmp 后 `os.replace`）
- **软删除**：条目支持移入回收站和恢复，不直接物理删除
- **条目类型**：5 种模板（login/card/identity/note/server），由 `models.py` 中的常量定义
- **数据目录**：Windows 下为 `%APPDATA%\CipherBox\`，包含 `vault.db`、`config.json`、`backups/`、`logs/`
