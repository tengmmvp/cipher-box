"""Apple 风格圆角档位常量。

圆角与主题无关（浅/深共享），独立模块集中管理，供 QSS 模板（经 ``render_style``
注入占位符）与组件内联 ``setStyleSheet`` / QPainter 自绘直接 import 引用，消除
散落硬编码。Apple 设计语言仅两档：交互元素胶囊（``RADIUS_PILL``/``RADIUS_TAG``，
Qt6 QSS 对大值自动截断为高度一半）与其余 8px 卡片系。

档位：
- ``RADIUS_CARD`` 8：卡片/输入/列表/容器/GroupBox/QMenu/loginCard
- ``RADIUS_SMALL`` 6：进度条/dupGroup/secEntryRow/detailWarning
- ``RADIUS_TINY`` 4：scrollbar handle/QMenu::item/tooltip/iconBtn hover/小徽章
- ``RADIUS_PILL`` 980：胶囊文字按钮（Qt 自动截断为高度一半）
- ``RADIUS_TAG`` 980：tag/typeTag 胶囊
"""

RADIUS_CARD = 8
RADIUS_SMALL = 6
RADIUS_TINY = 4
RADIUS_PILL = 980
RADIUS_TAG = 980
