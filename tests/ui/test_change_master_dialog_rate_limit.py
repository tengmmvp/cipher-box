"""改密对话框失败计数语义测试。

验证 ChangeMasterDialog 的速率限制语义（ARCH-042 契约）：
- ``(False, ...)`` 唯一语义为认证失败（旧主密码错误）→ 计入速率限制；
- 系统/策略错误经 worker.error 异常通道到达 → 不计入，避免偶发系统错误导致
  意外锁定（用户被惩罚）。
对话框不再比对文案字符串——文案调整/i18n 不会使改密暴力尝试脱离限流。
限流器经构造注入（ARCH-043），测试直接传入内存态实例（无状态文件）。
"""

from src.business.services.rate_limiter import RateLimiter


def _make_dialog(qapp, tmp_path, monkeypatch):
    """构造注入内存态限流器的改密对话框（vault 为 mock，模态弹窗已替换）。"""
    from unittest.mock import MagicMock

    from src.ui.dialogs.change_master_dialog import ChangeMasterDialog

    monkeypatch.setattr(
        "src.ui.dialogs.change_master_dialog.QMessageBox.critical",
        lambda *args, **kwargs: None,
    )
    vault = MagicMock()
    vault.data_dir = tmp_path
    return ChangeMasterDialog(vault, RateLimiter())


class TestChangeMasterDialogRateLimit:
    """验证改密失败计数的认证语义。"""

    def test_auth_failure_counts_toward_rate_limit(self, qapp, tmp_path, monkeypatch):
        """返回 False（认证失败，唯一语义）应计入失败计数。"""
        dialog = _make_dialog(qapp, tmp_path, monkeypatch)
        try:
            dialog._on_change_done((False, "当前主密码错误"))
            assert dialog._rate_limiter._fail_count == 1
        finally:
            dialog.deleteLater()

    def test_system_error_via_error_channel_does_not_count(self, qapp, tmp_path, monkeypatch):
        """系统错误经异常通道（worker.error）到达时不增加失败计数。"""
        dialog = _make_dialog(qapp, tmp_path, monkeypatch)
        try:
            dialog._rate_limiter.record_failure()  # 此前已有一次认证失败
            dialog._on_change_error("数据库操作失败，请稍后重试。")
            assert dialog._rate_limiter._fail_count == 1  # 计数未增加
        finally:
            dialog.deleteLater()

    def test_auth_failure_message_text_is_not_the_contract(self, qapp, tmp_path, monkeypatch):
        """契约回归守护：文案变化不影响计数语义（任意 False 文案均计入）。

        ARCH-042 修复前，对话框以 ``error_msg == AUTH_FAILED_MESSAGE`` 字符串比对
        决定是否计入限流——文案调整或 i18n 会静默使改密暴力尝试脱离限流。修复后
        计数语义只取决于返回值形态，本测试用一段「非既有文案」的 False 结果锚定。
        """
        dialog = _make_dialog(qapp, tmp_path, monkeypatch)
        try:
            dialog._on_change_done((False, "Password authentification échouée (i18n)"))
            assert dialog._rate_limiter._fail_count == 1
        finally:
            dialog.deleteLater()
