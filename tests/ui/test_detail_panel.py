"""``DetailPanel._build_url_label`` 的 scheme 白名单与注入防护测试。

覆盖 ``src/ui/components/detail_panel.py::_build_url_label``：
- http/https 渲染为可点击 ``<a href=...>`` 链接（RichText + 外链交互）。
- javascript:/file:/data: 等非白名单 scheme 渲染为纯文本（无链接），防止 XSS。
- URL 含 ``<>"'`` 等特殊字符时经 ``html.escape`` 转义，不破坏 ``<a>`` 标签结构、
  不注入 markup。

另覆盖主密码字段行的共享单定时器显隐行为（MAINT-103 收敛后的守护）：揭示/超时
掩码/清除掩码与间接引用释放。

``_build_url_label`` 不读实例状态，经 ``DetailPanel.__new__`` 裸实例直接调用，
避免完整 ``__init__`` 的控件树装配开销。``QLabel`` 构造需 QApplication，用 conftest
的 ``qapp`` fixture。
"""

from unittest.mock import MagicMock

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

from src.ui.components.detail_panel import DetailPanel
from src.ui.resources.constants import PWD_MASK


def _make_panel() -> DetailPanel:
    """构造跳过 __init__ 的 DetailPanel 裸实例（_build_url_label 不依赖实例状态）。"""
    return DetailPanel.__new__(DetailPanel)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/path?q=1",
        "HTTPS://EXAMPLE.COM",  # 大写 scheme 也应识别（.lower() 归一化）
    ],
)
def test_http_https_url_renders_as_link(qapp, url):
    """http/https scheme 渲染含 ``<a href=`` 的可点击链接。"""
    label = _make_panel()._build_url_label(url)

    text = label.text()
    assert "<a href=" in text
    assert label.textFormat() == Qt.TextFormat.RichText
    # 安全文档启用外链交互（TextBrowserInteraction + setOpenExternalLinks）
    assert label.textInteractionFlags() == Qt.TextInteractionFlag.TextBrowserInteraction
    assert label.openExternalLinks() is True


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",  # XSS 经典向量
        "file:///etc/passwd",  # 本地文件读取
        "data:text/html,<script>",  # data URI
        "vbscript:msgbox(1)",  # 另一种脚本 scheme
    ],
)
def test_non_http_scheme_renders_as_plain_text_without_link(qapp, url):
    """非白名单 scheme 渲染纯文本，无 ``<a>`` 链接，防脚本/文件 scheme 注入。"""
    label = _make_panel()._build_url_label(url)

    text = label.text()
    assert "<a " not in text
    assert "href=" not in text
    # 仍为 RichText（统一格式），但内容是转义后的纯文本
    assert label.textFormat() == Qt.TextFormat.RichText
    # 非安全 scheme 不启用外链交互
    assert label.openExternalLinks() is False


def test_url_with_special_chars_is_escaped_not_breaking_tag(qapp):
    """含 ``<>"'`` 的 URL 经转义，不破坏 ``<a>`` 标签结构、不注入 markup。

    href 用 ``urllib.parse.quote`` 编码（保留 URL 结构字符），显示文本用
    ``html.escape(quote=True)`` 转义——双重保护：href 内的特殊字符被 quote 处理，
    显示文本中的 ``<`` 变 ``&lt;``，杜绝标签逃逸。
    """
    url = 'https://example.com/<script>alert("x")</script>'
    label = _make_panel()._build_url_label(url)

    text = label.text()
    # 渲染为链接
    assert text.count("<a ") == 1
    assert text.count("</a>") == 1
    # 原始 ``<script>`` 不得作为 markup 出现（已转义为 &lt;script&gt;）
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    # 恰好一个 <a 开标签（无注入额外标签）
    assert text.startswith("<a href=")


def test_empty_scheme_url_treated_as_plain_text(qapp):
    """无 scheme（裸域名/相对路径）的 URL 不渲染为链接。

    urlparse 对 'example.com' 解析得 scheme=''，不在白名单 → 纯文本。
    """
    label = _make_panel()._build_url_label("example.com/path")

    assert "<a " not in label.text()


def test_link_contains_href_and_styled(qapp):
    """http 链接含 href 属性与内联样式（颜色取自主题 link token）。"""
    label = _make_panel()._build_url_label("https://example.com")

    text = label.text()
    assert 'href="https://example.com"' in text
    assert "text-decoration:none" in text


class TestMainPasswordSharedHide:
    """主密码字段行的共享单定时器显隐（MAINT-103 收敛后的行为守护）。

    原专属实现（_pwd_hide_timer + _current_password/_pwd_label_ref）收编为
    SharedHideTimer + 共享工厂行后，以下行为逐项保持：揭示显示明文并计时、
    超时自动掩码（槽位明文保留可再揭示）、手动掩码停止计时、清除内容时掩码
    当前显式行并释放间接引用。
    """

    def _make_panel(self) -> DetailPanel:
        """构造真实 DetailPanel（clipboard 以 mock 注入，不触真实剪贴板）。"""
        return DetailPanel(MagicMock())

    def _reveal(self, panel: DetailPanel, secret: str) -> tuple[QLabel, QWidget]:
        """经统一入口构建主密码行并点击揭示，返回值标签与行容器。

        行容器随测试持有（val_label 的 Qt parent），避免方法返回后行被 GC 连带
        销毁子标签。
        """
        _name, row = panel._make_field_row("密码", secret, secret=True, main_password=True)
        show_btn = next(
            btn for btn in row.findChildren(QPushButton) if btn.toolTip() == "显示/隐藏"
        )
        show_btn.click()
        val_label = row.findChildren(QLabel)[0]
        assert val_label.text() == secret
        return val_label, row

    def test_reveal_starts_shared_timer(self, qapp):
        """揭示主密码：显示明文并启动共享单定时器计时。"""
        panel = self._make_panel()

        self._reveal(panel, "Secret!2026")

        assert panel._pwd_hide.is_active

    def test_timeout_masks_and_allows_re_reveal(self, qapp):
        """超时自动掩码；槽位明文保留，可再次点击揭示。"""
        panel = self._make_panel()
        val_label, _row = self._reveal(panel, "Secret!2026")

        panel._pwd_hide._on_timeout()  # 直接触发超时回调（稳定于真实等待）

        assert val_label.text() == PWD_MASK
        # is_active 不在此断言：直调 _on_timeout 绕过 QTimer 真实超时事件，singleShot
        # 到期自停是 Qt 固有语义；计时停止行为由手动掩码（conceal）与清除（stop）测试覆盖
        assert panel._secret_values_main == {"密码": "Secret!2026"}  # 槽位保留

    def test_manual_mask_stops_timer(self, qapp):
        """再次点击掩码并停止计时。"""
        panel = self._make_panel()
        _name, row = panel._make_field_row("密码", "p", secret=True, main_password=True)
        show_btn = next(
            btn for btn in row.findChildren(QPushButton) if btn.toolTip() == "显示/隐藏"
        )
        show_btn.click()
        assert panel._pwd_hide.is_active

        show_btn.click()  # 手动掩码

        assert row.findChildren(QLabel)[0].text() == PWD_MASK
        assert not panel._pwd_hide.is_active

    def test_clear_content_masks_revealed_and_releases_store(self, qapp):
        """_clear_content：掩码当前显式行、停计时并释放间接引用（deleteLater 前明文收缩）。"""
        panel = self._make_panel()
        val_label, _row = self._reveal(panel, "Secret!2026")

        panel._clear_content()

        assert val_label.text() == PWD_MASK
        assert not panel._pwd_hide.is_active
        assert panel._secret_values_main == {}


class TestForceRebuildEpochGuard:
    """force 重建路径的 TOTP 预热世代守卫（SEC-054 残余窗口闭合）。

    主题切换的 ``show_entry(entry, force=True)`` 持面板已存的旧条目重显，其
    totp_secret 解密于旧世代——若恢复轮换恰发生在「初次解密后→force 重显前」，
    旧实现现时快照 ``key_epoch`` 会得到新世代而把旧 secret 植入新世代缓存；现
    复用初次展示时记录的世代，缓存守卫正确拒收。经真实 EntryCacheManager +
    TotpService 验证行为语义（stub vault 仅提供可变 key_epoch）。
    """

    _VALID_SECRET = "JBSWY3DPEHPK3PXP"
    _ENTRY_ID = 7

    class _EpochVault:
        """提供可变 key_epoch 的最小 vault stub（恢复轮换即改字段值）。"""

        def __init__(self, epoch: str) -> None:
            self.key_epoch = epoch

    def _make_panel_with_real_totp(self, epoch: str):
        """组装真实缓存/TOTP 服务的面板与观察用缓存引用。"""
        from src.business.managers.entry_cache import EntryCacheManager
        from src.business.services.totp_service import TotpService

        vault = self._EpochVault(epoch)
        cache = EntryCacheManager(vault)  # type: ignore[arg-type]
        entry_mgr = MagicMock()
        entry_mgr.key_epoch = epoch
        entry_mgr.totp = TotpService(cache)
        panel = DetailPanel(MagicMock(), entry_manager=entry_mgr)
        return panel, cache, vault

    @staticmethod
    def _teardown_panel(panel: DetailPanel) -> None:
        """收尾清理：停 TOTP 定时器并清空内容后交 Qt 异步销毁。

        show_entry(has_totp 条目) 会启动真实的 1s QTimer（TOTPWidget._timer），
        不停掉则跨测试进程级存活，在后续测试运行中触发 _refresh 访问已失效
        状态——全量套件中曾以此触发 0xC0000409 进程崩溃。
        """
        panel._totp_widget.stop()
        panel._clear_content()
        panel.deleteLater()
        # 刷事件循环使排队的 deleteLater 真正执行（残留未销毁控件会跨测试存活）
        QApplication.processEvents()

    def _totp_entry(self):
        from src.models import Entry

        return Entry(id=self._ENTRY_ID, title="t", password="p", totp_secret=self._VALID_SECRET)

    def test_force_rebuild_with_stale_epoch_rejected(self, qapp):
        """恢复轮换后 force 重建：旧世代 secret 不落新世代缓存（跨窗口回归守护）。"""
        panel, cache, vault = self._make_panel_with_real_totp("epoch-old")
        try:
            cache.invalidate_if_epoch_changed()  # 初次展示前缓存臂到旧世代
            entry = self._totp_entry()

            # 主路径：携带锁内带出的世代与版本展示（entry_actions_controller 同款）
            version = cache.totp_invalidate_version
            panel.show_entry(entry, data_epoch="epoch-old", data_version=version)
            assert cache._totp_secret_cache.get(self._ENTRY_ID) == self._VALID_SECRET

            # 模拟恢复提交：轮换世代 + 整体失效 + 新读路径重臂
            vault.key_epoch = "epoch-new"
            entry_mgr_epoch = panel._entry_mgr
            assert entry_mgr_epoch is not None
            entry_mgr_epoch.key_epoch = "epoch-new"
            cache.invalidate_all()
            cache.invalidate_if_epoch_changed()
            assert cache.cache_epoch == "epoch-new"  # 公开观察面（MAINT-095）

            # 主题切换 force 重建（main_window 同款：传记录世代/版本复用）
            panel.show_entry(
                entry,
                force=True,
                data_epoch=panel.current_data_epoch,
                data_version=panel.current_data_version,
            )

            assert self._ENTRY_ID not in cache._totp_secret_cache  # 旧 secret 被守卫拒收
        finally:
            self._teardown_panel(panel)

    def test_force_rebuild_same_epoch_still_cached(self, qapp):
        """无恢复交错时 force 重建正常落缓存（对照：守卫不误伤主题切换路径）。"""
        panel, cache, _vault = self._make_panel_with_real_totp("epoch-cur")
        try:
            cache.invalidate_if_epoch_changed()
            entry = self._totp_entry()

            panel.show_entry(
                entry,
                data_epoch="epoch-cur",
                data_version=cache.totp_invalidate_version,
            )
            panel.show_entry(
                entry,
                force=True,
                data_epoch=panel.current_data_epoch,
                data_version=panel.current_data_version,
            )

            assert cache._totp_secret_cache.get(self._ENTRY_ID) == self._VALID_SECRET
        finally:
            self._teardown_panel(panel)

    def test_force_rebuild_with_stale_version_rejected(self, qapp):
        """force 重建的版本守卫（SEC-063 b 层）：世代未变但 TOTP 域版本已推进时，
        旧 secret 被拒收——pop/seam 失效不改 epoch，世代守卫对该失效盲。"""
        panel, cache, _vault = self._make_panel_with_real_totp("epoch-stable")
        try:
            cache.invalidate_if_epoch_changed()
            entry = self._totp_entry()

            # 初次展示（携带解密时点版本快照），随后模拟「初次解密 → force 重显」
            # 窗口内的单条 TOTP 失效（pop 不改 epoch）
            panel.show_entry(
                entry,
                data_epoch="epoch-stable",
                data_version=cache.totp_invalidate_version,
            )
            assert cache._totp_secret_cache.get(self._ENTRY_ID) == self._VALID_SECRET
            cache.pop_totp(self._ENTRY_ID)

            panel.show_entry(
                entry,
                force=True,
                data_epoch=panel.current_data_epoch,
                data_version=panel.current_data_version,
            )

            assert self._ENTRY_ID not in cache._totp_secret_cache  # 版本守卫拒收
        finally:
            self._teardown_panel(panel)

    def test_show_entry_data_epoch_is_required_keyword(self):
        """show_entry 的 data_epoch 为必传 keyword（无默认值）——签名级守护。

        SEC-054 的最弱回退分支（未传时现时快照 key_epoch）曾使漏传调用方
        编译通过却静默走弱分支、旧世代 TOTP secret 植入新世代缓存；必传签名
        使漏传在调用点即报 TypeError 而非运行期静默降级。经 inspect 断言
        无默认值，防后续无意恢复默认值重开窗口。
        """
        import inspect

        param = inspect.signature(DetailPanel.show_entry).parameters["data_epoch"]
        assert param.default is inspect.Parameter.empty, "data_epoch 不得带默认值"
        assert param.kind is inspect.Parameter.KEYWORD_ONLY

    def test_show_entry_data_version_is_required_keyword(self):
        """show_entry 的 data_version 同为必传 keyword（无默认值）——签名级守护。

        SEC-063 b 层的漏传落点是 get_state 的自采样兜底（只覆盖微秒窗口，
        「解密 → 预热」窗口内的失效检测不到），必传签名防后续无意恢复默认值
        重开该窗口。
        """
        import inspect

        param = inspect.signature(DetailPanel.show_entry).parameters["data_version"]
        assert param.default is inspect.Parameter.empty, "data_version 不得带默认值"
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
