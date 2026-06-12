"""改密对话框失败计数语义测试。

验证 ChangeMasterDialog 仅对明确的认证失败（旧密码错误）计入速率限制，
新密码校验问题或系统错误不惩罚用户，避免偶发系统错误导致意外锁定。
"""

from unittest.mock import MagicMock


class TestChangeMasterDialogRateLimit:
    """验证改密失败计数的认证语义。"""

    def test_auth_failure_counts_toward_rate_limit(self, qapp):
        """旧密码错误（认证失败）应计入失败计数。"""
        from src.ui.dialogs.change_master_dialog import ChangeMasterDialog
        vault = MagicMock()
        dialog = ChangeMasterDialog(vault)
        try:
            dialog._on_change_done((False, '当前主密码错误'))
            assert dialog._rate_limiter._fail_count == 1
        finally:
            dialog.deleteLater()

    def test_non_auth_failure_does_not_count(self, qapp):
        """非认证失败（系统错误、凭据问题等）不计入失败计数。"""
        from src.ui.dialogs.change_master_dialog import ChangeMasterDialog
        vault = MagicMock()
        dialog = ChangeMasterDialog(vault)
        try:
            # 模拟系统错误或保险库凭据问题，文案非认证失败
            dialog._on_change_done((False, '保险库凭据不完整'))
            assert dialog._rate_limiter._fail_count == 0

            # 新密码校验问题同样不计入
            dialog._on_change_done((False, '新密码强度不足'))
            assert dialog._rate_limiter._fail_count == 0
        finally:
            dialog.deleteLater()
