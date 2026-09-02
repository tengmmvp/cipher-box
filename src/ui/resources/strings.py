"""UI 高频复用文案与展示元数据集中层。

与 ``error_messages.py``（领域异常→用户文案翻译）对称：集中**高频复用**的 UI
通用文案，消除分散硬编码。本层不是全量 UI 中文字面量的收编层（单对话框专用
文案留在各自模块就近维护，不做 i18n 预收纳），仅按复用度收录。**不**收纳：
动态插值文案（保留在调用处保持上下文）、低复用的单对话框专用占位符、领域
异常文案（已在 ``error_messages.py``）。ARCH-037 后收纳范围扩展至**条目类型
展示元数据查表**（ENTRY_TYPE_LABELS/ICONS + 查表函数）——展示语义归 UI 层，
经 ``models`` 的类型常量构建键（ARCH-040，消除字面量双源）。UI→共享层 import
合法方向。
"""

from types import MappingProxyType

from ...models import (
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_IDENTITY,
    ENTRY_TYPE_LOGIN,
    ENTRY_TYPE_NOTE,
    ENTRY_TYPE_SERVER,
    ENTRY_TYPES,
)

# 对话框通用标题（QMessageBox.windowTitle，高频复用）
DLG_TITLE_ERROR = "错误"
DLG_TITLE_INFO = "提示"
DLG_TITLE_SUCCESS = "成功"

# 条目类型的 UI 展示元数据（ARCH-037）：中文标签与 delegate 绘制用的文本图标
# 占位符原定义在共享层 models.ENTRY_TYPES 的值内，消费方全部在 UI——改 UI 文案
# 不应触碰三层共享的数据模型文件。领域侧已收敛为合法类型键集合（frozenset）。
# 键经 models 的 ENTRY_TYPE_* 常量构建（ARCH-040）：字面量键与 frozenset 平行
# 声明构成双源，新增类型漏更新本表时 UI 静默回退 login 文案无报错；常量化后
# 键名漂移在 import 期即炸，键集完备性由 test 的断言守护。
ENTRY_TYPE_LABELS = MappingProxyType(
    {
        ENTRY_TYPE_LOGIN: "登录凭证",
        ENTRY_TYPE_CARD: "信用卡",
        ENTRY_TYPE_IDENTITY: "身份信息",
        ENTRY_TYPE_NOTE: "安全笔记",
        ENTRY_TYPE_SERVER: "服务器",
    }
)
ENTRY_TYPE_ICONS = MappingProxyType(
    {
        ENTRY_TYPE_LOGIN: "[KEY]",
        ENTRY_TYPE_CARD: "[CARD]",
        ENTRY_TYPE_IDENTITY: "[ID]",
        ENTRY_TYPE_NOTE: "[NOTE]",
        ENTRY_TYPE_SERVER: "[SRV]",
    }
)


def entry_type_label(entry_type: str) -> str:
    """条目类型的中文标签（未知类型回退 login）。"""
    return ENTRY_TYPE_LABELS.get(entry_type, ENTRY_TYPE_LABELS[ENTRY_TYPE_LOGIN])


def entry_type_icon(entry_type: str) -> str:
    """条目类型的文本图标占位符（未知类型回退 login）。"""
    return ENTRY_TYPE_ICONS.get(entry_type, ENTRY_TYPE_ICONS[ENTRY_TYPE_LOGIN])


# 键集完备性守卫（ARCH-040）：models 新增类型而本表漏更新时，UI 会静默回退
# login 文案——模块加载期即抛（对齐 _ENTRY_COLUMNS 启动期自检的 if+RuntimeError
# 形式，python -O 下存活，不随 assert 剥离）。
if set(ENTRY_TYPE_LABELS) != ENTRY_TYPES:
    raise RuntimeError("ENTRY_TYPE_LABELS 键集与 models.ENTRY_TYPES 漂移，UI 展示会静默回退")
if set(ENTRY_TYPE_ICONS) != ENTRY_TYPES:
    raise RuntimeError("ENTRY_TYPE_ICONS 键集与 models.ENTRY_TYPES 漂移，UI 展示会静默回退")
