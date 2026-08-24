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


class TestCollectEntryPasswordGating:
    """_collect_entry 密码门控：新增模式按可见性、编辑模式按回读值（QL-029）。

    card/identity 的 visible_fields 不含 "password"，密码框隐藏；新增模式下
    残留值不得被隐式持久化（表单上看不见、无法清除）；编辑既有带密码的
    card/identity 条目时隐藏控件回读的密码须保留（详情面板会显示）。
    """

    def test_new_card_after_type_switch_drops_residual_password(self, qapp):
        """新增 login 输密码→切 card 保存：持久化的条目 password 为空。"""
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("我的卡")
        dlg._password_edit.setText("ResidualSecret!234")
        _switch_type(dlg, "card")  # 复现切换后密码框隐藏、控件值残留的状态
        dlg._on_save()
        dlg._entry_mgr.add_entry.assert_called_once()
        saved = dlg._entry_mgr.add_entry.call_args.args[0]
        assert saved.entry_type == "card"
        assert saved.password == ""

    def test_new_identity_after_type_switch_drops_residual_password(self, qapp):
        """identity 与 card 同构：visible_fields 不含 password，残留值同样丢弃。"""
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("我的身份")
        dlg._password_edit.setText("ResidualSecret!234")
        _switch_type(dlg, "identity")
        dlg._on_save()
        saved = dlg._entry_mgr.add_entry.call_args.args[0]
        assert saved.entry_type == "identity"
        assert saved.password == ""

    def test_new_login_keeps_visible_password(self, qapp):
        """login（password 在 visible_fields 中）不受门控影响，密码正常采集。

        守护门控不外溢：避免修复反向破坏常规登录条目的密码保存。
        """
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("我的账号")
        dlg._password_edit.setText("VisibleSecret!9")
        dlg._on_save()
        saved = dlg._entry_mgr.add_entry.call_args.args[0]
        assert saved.password == "VisibleSecret!9"

    def test_edit_existing_card_entry_keeps_its_password(self, qapp):
        """编辑既有带密码的 card 条目：隐藏密码框回读值原样保留并透传 id。"""
        from src.models import Entry
        from src.ui.dialogs.entry_dialog import EntryDialog

        entry = Entry(id=7, title="既有卡片", password="KeepMe!123456", entry_type="card")
        dlg = EntryDialog(MagicMock(), [], entry=entry)
        dlg._on_save()
        dlg._entry_mgr.update_entry.assert_called_once()
        updated = dlg._entry_mgr.update_entry.call_args.args[0]
        assert updated.id == 7
        assert updated.password == "KeepMe!123456"


class TestCollectEntryUsernameUrlGating:
    """_collect_entry username/url 门控：与 password 同款「编辑模式豁免」（QL-033）。

    card/identity/note 的 visible_fields 不含 username/url，但既有条目可合法持有
    这些字段（JSON 导入的带 username 的 card；详情面板对任何类型都显示账号/网址
    行）。编辑保存须保留隐藏控件回读的值；新增模式切类型后残留值仍不得入库。
    """

    def _edit_and_collect(self, entry) -> object:
        """构造编辑该条目的对话框并保存，返回提交给 update_entry 的 Entry。"""
        from src.ui.dialogs.entry_dialog import EntryDialog

        dlg = EntryDialog(MagicMock(), [], entry=entry)
        dlg._on_save()
        dlg._entry_mgr.update_entry.assert_called_once()
        return dlg._entry_mgr.update_entry.call_args.args[0]

    def test_edit_card_with_username_url_keeps_both(self, qapp):
        """编辑带 username/url 的 card 条目（复现场景）：两字段不被静默清空。"""
        from src.models import Entry

        entry = Entry(
            id=11,
            title="导入的卡片",
            username="alice@example.com",
            url="https://pay.example.com",
            entry_type="card",
        )
        updated = self._edit_and_collect(entry)
        assert updated.username == "alice@example.com"
        assert updated.url == "https://pay.example.com"

    def test_edit_identity_with_username_url_keeps_both(self, qapp):
        """编辑带 username/url 的 identity 条目：与 card 同构，字段保留。"""
        from src.models import Entry

        entry = Entry(
            id=12,
            title="身份条目",
            username="bob",
            url="https://example.com/bob",
            entry_type="identity",
        )
        updated = self._edit_and_collect(entry)
        assert updated.username == "bob"
        assert updated.url == "https://example.com/bob"

    def test_edit_note_with_username_url_keeps_both(self, qapp):
        """编辑带 username/url 的 note 条目（visible_fields 仅 title）：字段保留。"""
        from src.models import Entry

        entry = Entry(
            id=13, title="笔记", username="carol", url="https://example.com", entry_type="note"
        )
        updated = self._edit_and_collect(entry)
        assert updated.username == "carol"
        assert updated.url == "https://example.com"

    def test_edit_server_without_host_keeps_existing_url(self, qapp):
        """编辑无 host 的 server 条目：composes_url 组合为空时回读隐藏 url 控件值。

        _load_entry 无条件回填 url；导入的仅有 url 无 _server_host 的服务器条目，
        编辑保存后 url 不因 host 为空而丢失（组合值非空时仍优先覆盖）。
        """
        from src.models import Entry

        entry = Entry(id=14, title="服务器", url="ssh://legacy:22", entry_type="server")
        updated = self._edit_and_collect(entry)
        assert updated.url == "ssh://legacy:22"

    def test_new_card_after_type_switch_drops_residual_username_url(self, qapp):
        """新增 login 填账号网址→切 card 保存：残留的 username/url 不被隐式持久化。"""
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("我的卡")
        dlg._username_edit.setText("residual@example.com")
        dlg._url_edit.setText("https://residual.example.com")
        _switch_type(dlg, "card")
        dlg._on_save()
        dlg._entry_mgr.add_entry.assert_called_once()
        saved = dlg._entry_mgr.add_entry.call_args.args[0]
        assert saved.entry_type == "card"
        assert saved.username == ""
        assert saved.url == ""

    def test_new_server_composes_url_from_host(self, qapp):
        """新增 server 条目：host 非空时 url 由 protocol://host[:port] 组合而成。"""
        dlg = _make_dialog(qapp)
        dlg._title_edit.setText("新服务器")
        _switch_type(dlg, "server")
        dlg._special_edits["server_host"].setText("db-01.internal")
        dlg._special_edits["server_port"].setText("5432")
        dlg._on_save()
        saved = dlg._entry_mgr.add_entry.call_args.args[0]
        assert saved.url == "ssh://db-01.internal:5432"
