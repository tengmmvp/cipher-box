"""UI 通用文案集中层。

与 ``error_messages.py``（领域异常→用户文案翻译）对称：集中 UI 层通用文案，
消除分散在各处的硬编码字面量，为未来 i18n 提供单一改造入口。**不**收纳：
动态插值文案（保留在调用处保持上下文）、低复用的单对话框专用占位符、领域
异常文案（已在 ``error_messages.py``）。
"""

# 对话框通用标题（QMessageBox.windowTitle，高频复用）
DLG_TITLE_ERROR = "错误"
DLG_TITLE_INFO = "提示"
DLG_TITLE_SUCCESS = "成功"
