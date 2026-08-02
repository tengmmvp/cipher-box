"""LoginWindow 认证胶水行为级测试。

聚焦登录整合链路（不依赖真实 ``worker``/事件循环）：失败计数→限流器 ``record_failure``→
锁定态提示；成功→``record_success`` + ``login_success`` 信号；限流器 ``check()`` 锁定时 ``_on_confirm``
直接提示且不启动 ``worker``。底层（``RateLimiter`` 哨兵/``config`` 见证、``vault.unlock`` 成败、改密重加密）
已有专门测试，此处补整合胶水的状态机断言——登录是密码管理器最关键的安全入口，其整合
行为不应被 UI 18% 覆盖门槛均摊掉。
"""

from unittest.mock import MagicMock

from src.ui.dialogs.login_window import LoginWindow


def _make_vault(tmp_path, *, initialized: bool = True) -> object:
    """构造满足 LoginWindow.__init__ 契约的轻量 vault mock。

    与 test_product_hardening 的动态类型模式一致：提供 is_initialized / data_dir /
    ensure_db_open 三者即可通过 __init__，避免组装完整 VaultManager。
    """
    return type(
        "Vault",
        (),
        {
            "is_initialized": initialized,
            "data_dir": tmp_path,
            "ensure_db_open": lambda self: None,
        },
    )()


class TestLoginWindowAuthGlue:
    """认证结果→限流器联动→UI 状态机的整合胶水。"""

    def test_failure_records_and_shows_lock_wait(self, qapp, tmp_path):
        """认证失败经 ``record_failure``；返回锁定秒数时显示等待提示。"""
        dialog = LoginWindow(_make_vault(tmp_path))  # type: ignore[arg-type]
        try:
            dialog._rate_limiter = MagicMock()
            dialog._rate_limiter.record_failure.return_value = 30
            dialog._on_auth_result(False, "主密码错误")
            dialog._rate_limiter.record_failure.assert_called_once()
            assert "等待 30 秒" in dialog._message_label.text()
        finally:
            dialog.close()

    def test_failure_without_lock_shows_raw_error(self, qapp, tmp_path):
        """认证失败但未触发锁定（``record_failure`` 返回 0）时显示原始错误文案。"""
        dialog = LoginWindow(_make_vault(tmp_path))  # type: ignore[arg-type]
        try:
            dialog._rate_limiter = MagicMock()
            dialog._rate_limiter.record_failure.return_value = 0
            dialog._on_auth_result(False, "主密码错误")
            dialog._rate_limiter.record_failure.assert_called_once()
            assert dialog._message_label.text() == "主密码错误"
        finally:
            dialog.close()

    def test_success_records_and_emits_signal(self, qapp, tmp_path):
        """认证成功经 ``record_success`` 并发射 ``login_success`` 信号。"""
        dialog = LoginWindow(_make_vault(tmp_path))  # type: ignore[arg-type]
        try:
            dialog._rate_limiter = MagicMock()
            emitted: list[bool] = []
            dialog.login_success.connect(lambda: emitted.append(True))
            dialog._on_auth_result(True, "")
            dialog._rate_limiter.record_success.assert_called_once()
            assert emitted == [True]
        finally:
            dialog.close()

    def test_locked_check_aborts_before_worker(self, qapp, tmp_path):
        """限流器 ``check()`` 返回锁定提示时，``_on_confirm`` 直接提示且不启动后台 ``worker``。

        锁定态应短路在 ``worker`` 启动前，避免无谓的解锁尝试（被限流拒绝）与 ``worker`` 开销。
        """
        dialog = LoginWindow(_make_vault(tmp_path))  # type: ignore[arg-type]
        try:
            dialog._rate_limiter = MagicMock()
            dialog._rate_limiter.check.return_value = "请等待 60 秒后重试"
            dialog._on_confirm()
            assert "等待 60 秒" in dialog._message_label.text()
            assert dialog._worker is None  # 未启动后台 ``worker``
        finally:
            dialog.close()
