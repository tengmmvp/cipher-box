"""error_messages 模块测试 — 异常到用户文案的统一翻译。

覆盖 to_user_message 对各 CipherBoxError 家族异常的映射顺序（具体→一般）
与兜底通用提示。注意：本函数仅服务于技术性失败归一，用户输入校验类
（ValueError 等非家族异常）由调用方保留原消息，不应走本函数。
"""

import pytest

from src.exceptions import (
    BackupError,
    CipherBoxError,
    DatabaseError,
    DecryptionError,
    PayloadTooLargeError,
    SchemaError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)
from src.ui.error_messages import to_user_message


class TestToUserMessage:
    """各异常类型 → 用户文案映射。"""

    def test_vault_locked(self):
        msg = to_user_message(VaultLockedError('locked'))
        assert '解锁' in msg

    def test_vault_key_epoch_mismatch(self):
        msg = to_user_message(VaultKeyEpochMismatchError('epoch'))
        # 收敛后采用「操作期间检测到主密码已被修改」文案：准确描述改密/恢复/导入
        # 期间 epoch 复查失败的场景（多数为同进程另一操作改密，非字面「其他进程」）。
        assert '已被修改' in msg or '重试' in msg

    def test_payload_too_large_precedes_backup_error(self):
        """PayloadTooLargeError（BackupError 子类）应优先于 BackupError 匹配。"""
        msg = to_user_message(PayloadTooLargeError('too big'))
        assert '大小' in msg or '限制' in msg
        assert '损坏' not in msg

    def test_backup_error(self):
        msg = to_user_message(BackupError('detail username_enc leaked'))
        assert '损坏' in msg or '格式' in msg
        # 不应泄漏内部技术细节
        assert 'username_enc' not in msg

    def test_vault_integrity_error(self):
        msg = to_user_message(VaultIntegrityError('hmac mismatch'))
        assert '完整性' in msg
        assert 'hmac' not in msg

    def test_decryption_error(self):
        msg = to_user_message(DecryptionError('InvalidTag'))
        assert '解密' in msg
        assert 'InvalidTag' not in msg

    def test_schema_error_precedes_database_error(self):
        """SchemaError（DatabaseError 子类）应优先于 DatabaseError 匹配。"""
        msg = to_user_message(SchemaError('cipherbox-schema mismatch'))
        assert '数据库结构' in msg or '结构' in msg

    def test_database_error(self):
        msg = to_user_message(DatabaseError('sqlite3 error: entry_id'))
        assert '数据库' in msg
        assert 'sqlite3' not in msg
        assert 'entry_id' not in msg

    def test_unknown_cipherbox_error_falls_back(self):
        """未明确归类的 CipherBoxError 子类应兜底为通用提示。"""

        class OtherError(CipherBoxError):
            pass

        msg = to_user_message(OtherError('internal detail crypto_id'))
        assert '操作失败' in msg
        assert 'crypto_id' not in msg

    def test_plain_exception_falls_back(self):
        """非 CipherBoxError 家族的异常兜底为通用提示，不泄漏 str。"""
        msg = to_user_message(RuntimeError('internal stack trace'))
        assert '操作失败' in msg
        assert 'stack' not in msg


@pytest.mark.parametrize(
    'exc', [
        VaultLockedError('x'),
        VaultKeyEpochMismatchError('x'),
        PayloadTooLargeError('x'),
        BackupError('x'),
        VaultIntegrityError('x'),
        DecryptionError('x'),
        SchemaError('x'),
        DatabaseError('x'),
    ],
)
def test_all_messages_are_user_friendly(exc):
    """所有家族异常翻译结果都应为非空中文短句，不含英文异常细节。"""
    msg = to_user_message(exc)
    assert isinstance(msg, str)
    assert msg.strip()
    # 翻译结果应以中文标点或句号结尾（友好提示风格）
    assert msg.endswith('。') or msg.endswith('！')
