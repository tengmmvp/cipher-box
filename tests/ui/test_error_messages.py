"""error_messages 模块测试 — 异常到用户文案的统一翻译。

覆盖 to_user_message 对各 CipherBoxError 家族异常的映射顺序（具体→一般）
与兜底通用提示。注意：本函数仅服务于技术性失败归一，用户输入校验类
（ValueError 等非家族异常）由调用方保留原消息，不应走本函数。
"""

import binascii
import json

import pytest

from src.exceptions import (
    BackupError,
    CipherBoxError,
    DatabaseError,
    DecryptionError,
    PayloadTooLargeError,
    SchemaError,
    VaultError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)
from src.ui.error_messages import to_user_message


class TestToUserMessage:
    """各异常类型 → 用户文案映射。"""

    def test_vault_locked(self):
        """VaultLockedError → 提示需解锁保险库。"""
        msg = to_user_message(VaultLockedError("locked"))
        assert "解锁" in msg

    def test_plain_vault_error_preserves_message(self):
        """纯 VaultError 本体保留 str 原文（ARCH-042 系统错误包装通道）。

        vault_lifecycle 把系统错误经 to_user_message 翻译后以 VaultError 包装，
        worker error 通道的二次翻译须保留该原文——否则磁盘满/IO 错误的准确文案
        被兜底文案覆盖。子类（如 VaultLockedError）仍走固定映射，先于本体分支。
        """
        assert to_user_message(VaultError("磁盘空间不足。")) == "磁盘空间不足。"
        assert to_user_message(VaultError(""), default="修改主密码失败") == "修改主密码失败"

    def test_vault_key_epoch_mismatch(self):
        """采用「操作期间检测到主密码已被修改」文案：准确描述改密/恢复/导入
        期间 ``epoch`` 复查失败的场景（多数为同进程另一操作改密，非字面「其他进程」）。"""
        msg = to_user_message(VaultKeyEpochMismatchError("epoch"))
        assert "已被修改" in msg or "重试" in msg

    def test_payload_too_large_precedes_backup_error(self):
        """PayloadTooLargeError（BackupError 子类）应优先于 BackupError 匹配。"""
        msg = to_user_message(PayloadTooLargeError("too big"))
        assert "大小" in msg or "限制" in msg
        assert "损坏" not in msg

    def test_backup_error(self):
        """BackupError → 备份损坏/格式提示，且不泄漏内部加密字段名。"""
        msg = to_user_message(BackupError("detail username_enc leaked"))
        assert "损坏" in msg or "格式" in msg
        # 不应泄漏内部技术细节
        assert "username_enc" not in msg

    def test_vault_integrity_error(self):
        """VaultIntegrityError → 完整性校验失败提示，且不泄漏 hmac 等技术细节。"""
        msg = to_user_message(VaultIntegrityError("hmac mismatch"))
        assert "完整性" in msg
        assert "hmac" not in msg

    def test_decryption_error(self):
        """DecryptionError → 解密失败提示，且不泄漏 InvalidTag 等内部细节。"""
        msg = to_user_message(DecryptionError("InvalidTag"))
        assert "解密" in msg
        assert "InvalidTag" not in msg

    def test_schema_error_precedes_database_error(self):
        """SchemaError（DatabaseError 子类）应优先于 DatabaseError 匹配。"""
        msg = to_user_message(SchemaError("cipherbox-schema mismatch"))
        assert "数据库结构" in msg or "结构" in msg

    def test_database_error(self):
        """DatabaseError → 数据库错误提示，且不泄漏 sqlite3、字段名等内部细节。"""
        msg = to_user_message(DatabaseError("sqlite3 error: entry_id"))
        assert "数据库" in msg
        assert "sqlite3" not in msg
        assert "entry_id" not in msg

    def test_unknown_cipherbox_error_falls_back(self):
        """未明确归类的 CipherBoxError 子类应兜底为通用提示。"""

        class OtherError(CipherBoxError):
            pass

        msg = to_user_message(OtherError("internal detail crypto_id"))
        assert "操作失败" in msg
        assert "crypto_id" not in msg

    def test_plain_exception_falls_back(self):
        """非 CipherBoxError 家族的异常兜底为通用提示，不泄漏 str。"""
        msg = to_user_message(RuntimeError("internal stack trace"))
        assert "操作失败" in msg
        assert "stack" not in msg


@pytest.mark.parametrize(
    "exc",
    [
        VaultLockedError("x"),
        VaultKeyEpochMismatchError("x"),
        PayloadTooLargeError("x"),
        BackupError("x"),
        VaultIntegrityError("x"),
        DecryptionError("x"),
        SchemaError("x"),
        DatabaseError("x"),
    ],
)
def test_all_messages_are_user_friendly(exc):
    """所有家族异常翻译结果都应为非空中文短句，不含英文异常细节。"""
    msg = to_user_message(exc)
    assert isinstance(msg, str)
    assert msg.strip()
    # 翻译结果应以中文标点或句号结尾（友好提示风格）
    assert msg.endswith("。") or msg.endswith("！")


class TestIOAndFormatErrors:
    """FileNotFoundError / PermissionError / IsADirectoryError / JSONDecodeError /
    binascii.Error / OSError(ENOSPC) 各分支的固定文案映射。

    这些是驱动层（文件系统 / JSON 解析 / base64 解码）抛出的非 CipherBoxError
    异常，``to_user_message`` 按类型分别归一为面向用户的固定提示，避免把
    ``str(exc)`` 的路径/技术细节透传给用户。各分支文案互不相同，可据返回值
    锁定命中的分支，守护「具体→一般」匹配顺序不回归。
    """

    def test_file_not_found_error(self):
        """FileNotFoundError → 找不到文件提示。"""
        msg = to_user_message(FileNotFoundError("/secret/path/vault.db"))
        assert "找不到" in msg
        # 不泄漏内部路径
        assert "/secret/path" not in msg

    def test_permission_error(self):
        """PermissionError → 权限提示。"""
        msg = to_user_message(PermissionError("/root/config.json"))
        assert "权限" in msg
        assert "/root/" not in msg

    def test_is_a_directory_error(self):
        """IsADirectoryError → 选择文件而非目录的提示。"""
        msg = to_user_message(IsADirectoryError("/some/dir"))
        assert "目录" in msg
        assert "文件" in msg

    def test_json_decode_error(self):
        """json.JSONDecodeError → 格式无效/损坏提示。"""
        msg = to_user_message(json.JSONDecodeError("Expecting value", "{bad", 1))
        assert "格式" in msg
        # 不透传解析器内部诊断
        assert "Expecting" not in msg

    def test_binascii_error(self):
        """binascii.Error（非法 base64）→ 数据格式错误提示。"""
        msg = to_user_message(binascii.Error("Non-base64 digit"))
        assert "格式" in msg or "损坏" in msg
        assert "base64" not in msg.lower() or "格式" in msg

    def test_os_error_no_space(self):
        """OSError errno=ENOSPC → 磁盘空间不足（细分分支）。"""
        import errno

        exc = OSError(errno.ENOSPC, "No space left on device")
        msg = to_user_message(exc)
        assert "磁盘空间" in msg

    def test_os_error_generic(self):
        """其余 OSError → 通用文件读写失败提示。"""
        exc = OSError("I/O boom")
        msg = to_user_message(exc)
        assert "读写" in msg or "文件" in msg


class TestValueErrorBranch:
    """用户输入校验类 ValueError：保留 str(exc) 作为面向用户的可操作消息。

    ``DecryptionError`` 虽双继承 ValueError，但已在上方按 CipherBoxError 归一，
    不会落入此处。本组守护两条边界：非空消息透传、空消息回退 default。
    """

    def test_non_empty_message_passthrough(self):
        """str(exc) 非空时原样返回（保留可操作校验消息）。"""
        exc = ValueError("标题过长")
        assert to_user_message(exc) == "标题过长"

    def test_empty_message_falls_back_to_default(self):
        """str(exc) 为空时回退 default 文案（不返回空串）。"""
        assert to_user_message(ValueError("")) == "操作失败，请重试。"
        assert to_user_message(ValueError("   ")) == "操作失败，请重试。"

    def test_empty_message_uses_custom_default(self):
        """调用方可定制 default 文案，空消息时使用之。"""
        exc = ValueError("")
        assert to_user_message(exc, default="备份失败") == "备份失败"
