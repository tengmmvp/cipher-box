"""UI 层：基于 PyQt6 的桌面图形界面。

中心编排器 ``MainWindow``（``windows/``）经 ``BusinessContext`` 注入业务层 manager，
自身仅装配依赖 Qt 线程亲和性的控制器与子组件，把菜单调度、条目 CRUD、列表刷新等
委托给组合化 controller（``controllers/``）。子包分工：

- ``windows/`` — 顶层窗口（``MainWindow``）
- ``controllers/`` — 组合化 controller（普通类，经冻结 dataclass 回调协作）
- ``dialogs/`` — 模态对话框（登录、条目编辑、备份恢复、设置等）
- ``components/`` — 可复用控件与 worker（详情面板、条目列表、Toast 等）
- ``resources/`` — 主题颜色 token、QSS 样式、图标与常量
- ``utils/`` — 依赖 PyQt6 的 UI 专用工具（如剪贴板管理）
"""
