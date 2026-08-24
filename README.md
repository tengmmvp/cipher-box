<div align="center">

# CipherBox

**安全可靠的本地密码管理器**

所有敏感数据使用 AES-256-GCM 加密，存储在本地 SQLite 数据库中，不上传至任何服务器。

[![Version](https://img.shields.io/badge/Version-1.0.0-orange?style=for-the-badge)](src/__init__.py)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PyQt6](https://img.shields.io/badge/PyQt6-6.6+-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

<a href="https://bigmodel.cn/glm-coding">
  <img src="https://raw.githubusercontent.com/tengmmvp/img2code/main/img/zhipu-glm-coding-plan.png" alt="Powered by 智谱 GLM Coding Plan · 智谱编码套餐" />
</a>

</div>

---

## ✨ 核心特性

<table>
<tr>
<td width="50%">

### 🔑 密码保险库
- Argon2id 内存硬化密钥派生（OWASP 推荐量级）
- 主密码修改时自动全量重加密
- 自动锁定 · 登录限流 · 事务安全

</td>
<td width="50%">

### 📋 条目管理
- 5 种模板：登录 / 信用卡 / 身份 / 笔记 / 服务器
- 软删除回收站 · 自定义字段 · 密码历史
- 收藏 · 标签 · 分类 · TOTP 两步验证

</td>
</tr>
<tr>
<td width="50%">

### 🛡️ 安全分析
- 密码强度 5 级评分
- 弱密码 / 重复密码 / 过期密码检测
- 安全仪表盘（健康评分一览）

</td>
<td width="50%">

### 📦 导入 / 导出 / 备份
- JSON / CSV + Chrome / Bitwarden / KeePass（CSV 导出）导入
- 独立密码保护的可移植加密备份
- 本地自动快照 · 导入去重与原子回滚

</td>
</tr>
</table>

---

## 🚀 快速开始

```bash
# 安装依赖（uv 按 uv.lock 同步完整传递闭包）
uv sync

# 启动应用
uv run python main.py
```

首次启动将引导设置主密码，之后每次启动需输入主密码解锁。

## 📂 数据存储

程序数据默认保存在以下目录：

- Windows：`%APPDATA%\CipherBox`
- Linux：`$XDG_DATA_HOME/CipherBox`，未设置时为 `~/.local/share/CipherBox`

主要文件：

- `vault.db`：保险库数据库，账号、密码、备注、自定义字段和 TOTP 密钥均以 AES-256-GCM 加密保存
- `config.json`：界面与行为设置，不保存主密码和条目明文
- `backups/`：自动快照与恢复前安全快照

数据库、密文和备份均只接受当前固定格式；格式标识不匹配时直接拒绝打开，不执行旧格式迁移。

<details>
<summary><b>📦 依赖说明</b></summary>

| 包名 | 用途 |
|------|------|
| `PyQt6 >= 6.6.0` | 桌面端 UI 框架 |
| `cryptography >= 50.0.0` | AES-256-GCM 加密 |
| `argon2-cffi >= 25.1.0` | Argon2id 密钥派生 |
| `QtAwesome >= 1.3.0` | 统一矢量图标系统 |

> 上表为声明下限；实际安装版本以 `uv.lock` 为准（锁定完整传递闭包）。

</details>

---

## 🧪 测试

```bash
uv run -m pytest tests/          # pytest（经 uv 运行锁定环境）
python -m unittest discover tests/  # unittest
```

---

## 🔒 安全设计

| 组件 | 算法 | 说明 |
|:-----|:-----|:-----|
| 密钥派生 | Argon2id | time=3 / 64MB / 并行=4，32 字节盐 |
| 数据加密 | AES-256-GCM | 每值独立随机 nonce，并绑定条目和字段上下文 |
| 密码验证 | 加密验证令牌 | 不存储密码哈希 |
| 数据库写入 | SQLite WAL + FULL 同步 | 事务写入、外键约束、安全删除与检查点 |
| 备份 | AES-256-GCM | 独立备份密码或保险库快照密钥 |

> ⚠️ **主密码遗忘将无法恢复数据** — 请务必妥善保管。
> 导出默认不包含密码；手动选择包含密码时，文件为明文敏感数据。

本项目保护本地静态数据，不承诺抵御已控制当前系统账户的恶意程序、键盘记录、屏幕录制、进程内存读取或用户主动导出的明文文件。

---

## 📂 项目结构

```
src/
├── crypto/          # 加密引擎（AES-256-GCM、Argon2id、TOTP）
├── database/        # SQLite 数据层与固定结构校验
├── business/        # 业务编排
│   ├── managers/    #   有状态编排（保险库、条目、导入导出、备份恢复）
│   └── services/    #   协作模块（加解密、校验、签名、重加密、安全分析）
├── ui/              # PyQt6 界面
│   ├── windows/     #   主窗口（中心编排器，职责拆至 controllers/ 普通类）
│   ├── dialogs/     #   对话框（登录、条目编辑、备份、设置等）
│   ├── components/  #   可复用控件（详情面板、条目列表、TOTP、密码历史）
│   ├── controllers/ #   数据到控件的映射与生命周期
│   └── resources/   #   样式表 · 主题色 · 图标 · 常量
└── utils/           # 共享工具（文件安全、内存清零、格式化、安全擦除）
tests/               # 测试套件（按 crypto/database/business/ui/utils/config 分层）
```

---

## 📄 许可证

[MIT License](LICENSE)
