<div align="center">

# CipherBox 密匣

**安全可靠的本地密码管理器**

所有敏感数据使用 AES-256-GCM 加密，存储在本地 SQLite 数据库中，不上传至任何服务器。

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![PyQt6](https://img.shields.io/badge/PyQt6-6.6+-41CD52?logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.1.0-orange.svg)](src/__init__.py)

</div>

---

## ✨ 核心特性

<table>
<tr>
<td width="50%">

### 🔑 密码保险库
- PBKDF2-HMAC-SHA256 密钥派生（600K 迭代）
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
- JSON / CSV + Chrome / Bitwarden / KeePass 导入
- 独立密码保护的可移植 V3 加密备份
- 本地自动快照 · 导入去重与原子回滚

</td>
</tr>
</table>

---

## 🚀 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 启动应用
python main.py
```

首次启动将引导设置主密码，之后每次启动需输入主密码解锁。

<details>
<summary><b>📦 依赖说明</b></summary>

| 包名 | 用途 |
|------|------|
| `PyQt6 >= 6.6.0` | 桌面端 UI 框架 |
| `cryptography >= 42.0.0` | AES-256-GCM 加密、PBKDF2 密钥派生 |
| `QtAwesome >= 1.3.0` | 统一矢量图标系统 |

</details>

---

## 🧪 测试

```bash
python -m pytest tests/          # pytest
python -m unittest discover tests/  # unittest
```

---

## 🔒 安全设计

| 组件 | 算法 | 说明 |
|:-----|:-----|:-----|
| 密钥派生 | PBKDF2-HMAC-SHA256 | 600K 迭代，32 字节盐 |
| 数据加密 | AES-256-GCM | 每值独立 12 字节随机 nonce |
| 密码验证 | 加密验证令牌 | 不存储密码哈希 |

> ⚠️ **主密码遗忘将无法恢复数据** — 请务必妥善保管。
> 明文导出文件包含未加密密码，使用后请立即删除。

---

## 📂 项目结构

```
src/
├── crypto/          # 加密引擎（AES-256-GCM、PBKDF2、TOTP）
├── database/        # SQLite 数据层（Schema V3）
├── business/        # 业务编排（保险库、条目、安全分析、导入导出）
├── ui/              # PyQt6 界面（主题系统、QSS 样式）
│   └── resources/   #   样式表 · 主题色 · 图标
└── utils/           # 剪贴板管理
tests/               # 测试套件
```

---

## 📄 许可证

[MIT License](LICENSE)
