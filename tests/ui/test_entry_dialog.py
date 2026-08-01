"""EntryDialog._on_save 接线测试：校验守卫与三类异常分支（P0-B）。

业务层（EntryManager.add_entry/update_entry）已由 ``tests/business`` 充分覆盖；
本文件守护 ``_on_save`` 的「控件值→前置校验→业务调用→结果文案」接线层：
空标题守卫、信用卡字段校验派发（schema.validate_extra）、备注/URL 长度前置校验，
以及三类异常分支（领域 DatabaseError/DecryptionError/EntryIntegrityError → critical；
纯 ValueError → warning 透传 str(exc)；catch-all → 通用意外文案）。

直接构造 EntryDialog（MagicMock manager + 空 categories，真实控件经 qapp 渲染），
``QMessageBox.warning/critical`` 经 monkeypatch 捕获，避免真实模态阻塞。保存成功
路径（saved.emit/accept）由集成测试覆盖，本文件聚焦守卫与异常分支。
"""

from unittest.mock import MagicMock

import pytest

from src.exceptions import DatabaseError, DecryptionError, EntryIntegrityError
from src.models import MAX_FIELD_NOTES


def _recorder(cap: dict, key: str):
    """返回一个 mock：记录 QMessageBox.warning/critical 的调用参数。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return None

    return _fn


@pytest.fixture
def patched_msgbox(monkeypatch):
    """捕获 QMessageBox.warning / critical，避免模态对话框阻塞测试。"""
    cap: dict = {}
    monkeypatch.setattr(
        "src.ui.dialogs.entry_dialog.QMessageBox.warning",
        _recorder(cap, "warning"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.entry_dialog.QMessageBox.critical",
        _recorder(cap, "critical"),
    )
    return cap


def _make_dialog(qapp):
    """构造新增模式的 EntryDialog：MagicMock manager + 空 categories。"""
    from src.ui.dialogs.entry_dialog import EntryDialog

    return EntryDialog(MagicMock(), [])


def _switch_type(dlg, entry_type: str) -> None:
    """无副作用切换条目类型：blockSignals 跳过 _on_type_changed 的确认对话框，
    手动同步 _current_type 与字段可见性，供卡号/服务器类分支测试直接定位类型。"""
    idx = dlg._type_combo.findData(entry_type)
    dlg._type_combo.blockSignals(True)
    dlg._type_combo.setCurrentIndex(idx)
    dlg._type_combo.blockSignals(False)
    dlg._current_type = entry_type
    dlg._apply_type_visibility(entry_type)


class TestOnSaveValidationGuards:
    """_on_save 的前置校验守卫：空标题、卡号校验派发、长度校验。"""

    def test_empty_title_warns_and_returns(self, qapp, patched_msgbox):
        """空标题 → warning('请输入标题')，不调用 add_entry。"""
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("")
        dlg._on_save()
        assert patched_msgbox["warning"]
        assert any("标题" in str(arg) for arg in patched_msgbox["warning"][0])
        dlg._entry_mgr.add_entry.assert_not_called()

    def test_card_number_validation_dispatched(self, qapp, patched_msgbox):
        """card 类型 + 非法卡号 → validate_extra 派发 _validate_card_fields 失败告警。

        schema.validate_extra 标志驱动卡号校验：仅在 card 类型触发 _validate_card_fields，
        非法卡号（Luhn 校验失败）短路返回，不进入业务层。守护此派发防止 schema 标志
        被改后静默跳过信用卡格式校验。
        """
        dlg = _make_dialog(qapp)
        _switch_type(dlg, "card")
        dlg._title_edit.setText("我的卡")
        dlg._special_edits["card_number"].setText("1234")  # Luhn 不合法
        dlg._on_save()
        assert patched_msgbox["warning"]
        assert any("卡号" in str(arg) for arg in patched_msgbox["warning"][0])
        dlg._entry_mgr.add_entry.assert_not_called()

    def test_notes_too_long_warns(self, qapp, patched_msgbox):
        """备注超 MAX_FIELD_NOTES → _validate_field_lengths 告警，不进入业务层。

        QTextEdit 无 setMaxLength，长度上限仅由此前置校验守卫；超长时短路返回，
        避免到达业务层后以 ValueError 形式暴露（错误阶段错位、文案不一致）。
        """
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("标题")
        dlg._notes_edit.setPlainText("x" * (MAX_FIELD_NOTES + 1))
        dlg._on_save()
        assert patched_msgbox["warning"]
        assert any("备注过长" in str(arg) for arg in patched_msgbox["warning"][0])
        dlg._entry_mgr.add_entry.assert_not_called()


class TestOnSaveExceptionBranches:
    """_on_save 的三类异常分支：领域异常 / ValueError / catch-all。

    顺序敏感：DecryptionError 双继承 ValueError，必须被领域分支（DatabaseError/
    DecryptionError/EntryIntegrityError）先于 ValueError 捕获，否则解密失败会被
    误报为「输入有误」。各分支文案映射由 to_user_message / str(exc) 驱动。
    """

    def test_database_error_shows_critical_with_translated_message(self, qapp, patched_msgbox):
        """DatabaseError → critical，文案经 to_user_message 归一（不透传 str）。"""
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("标题")
        dlg._entry_mgr.add_entry.side_effect = DatabaseError("sqlite3 detail")
        dlg._on_save()
        assert patched_msgbox["critical"]
        # 领域异常经 to_user_message 归一，不泄漏 sqlite3 细节
        assert any("数据库" in str(arg) for arg in patched_msgbox["critical"][0])
        assert not any("sqlite3" in str(arg) for arg in patched_msgbox["critical"][0])

    def test_decryption_error_caught_before_value_error(self, qapp, patched_msgbox):
        """DecryptionError 被领域分支（先于 ValueError）捕获 → critical（非 warning）。

        DecryptionError 双继承 ValueError；若领域分支顺序错位，会被 ValueError 分支
        误捕为 warning 且透传 str(exc)。断言走 critical 即证明顺序正确。
        """
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("标题")
        dlg._entry_mgr.add_entry.side_effect = DecryptionError("InvalidTag detail")
        dlg._on_save()
        # 领域分支 → critical（解密失败文案），非 ValueError 分支的 warning
        assert patched_msgbox["critical"]
        assert not patched_msgbox.get("warning")
        assert any("解密" in str(arg) for arg in patched_msgbox["critical"][0])

    def test_entry_integrity_error_shows_critical(self, qapp, patched_msgbox):
        """EntryIntegrityError → 经领域分支（critical），而非 ValueError 分支（warning）。

        EntryIntegrityError 双继承 CipherBoxError 与 ValueError；``_on_save`` 经
        ``except Exception`` 委托 ``_handle_save_error``，其领域分支
        ``isinstance(exc, (DatabaseError, DecryptionError, EntryIntegrityError))`` 须先于
        ``isinstance(exc, ValueError)`` 判定，否则完整性错误会被降级为 warning。断言走 critical
        即证明领域分支顺序正确。
        """
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("标题")
        dlg._entry_mgr.add_entry.side_effect = EntryIntegrityError("hmac mismatch")
        dlg._on_save()
        assert patched_msgbox["critical"]
        assert not patched_msgbox.get("warning")

    def test_value_error_shows_warning_with_original_message(self, qapp, patched_msgbox):
        """纯 ValueError（字段校验）→ warning，透传 str(exc) 供用户操作。

        与领域分支区分：纯 ValueError 是业务层字段校验失败，其消息面向用户
        （如「标题过长」），透传比归一更有操作性。
        """
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("标题")
        dlg._entry_mgr.add_entry.side_effect = ValueError("字段校验未通过")
        dlg._on_save()
        assert patched_msgbox["warning"]
        assert any("字段校验未通过" in str(arg) for arg in patched_msgbox["warning"][0])
        assert not patched_msgbox.get("critical")

    def test_unexpected_exception_shows_generic_critical(self, qapp, patched_msgbox):
        """catch-all 分支：意外异常 → critical 通用意外文案，不透传异常细节。

        编程错误（如 RuntimeError）与领域错误文案区分，避免经 to_user_message
        归并为「用户数据问题」而误导排查。
        """
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("标题")
        dlg._entry_mgr.add_entry.side_effect = RuntimeError("internal boom")
        dlg._on_save()
        assert patched_msgbox["critical"]
        assert any("意外错误" in str(arg) for arg in patched_msgbox["critical"][0])
        # 不透传内部异常信息
        assert not any("internal boom" in str(arg) for arg in patched_msgbox["critical"][0])
