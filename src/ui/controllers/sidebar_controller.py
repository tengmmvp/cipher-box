"""侧边栏控制器：分类管理的纯数据操作，不操作 UI 控件。

锁定态守卫责任在调用方（ARCH-036），本控制器不经 ``_locked_guard.require_unlocked``：
该装饰器特化 ``Callable[..., None]``（锁定时静默返回 None），而本类方法均有返回值
（list/dict/bool/tuple），套用会使锁定态拿到 None 破坏类型契约、比异常更难排查。
现有调用方的守卫现状（新增调用方须保持同等隔离）：
- ListRefreshController 的信号槽（on_category_changed 等）自带 ``@require_unlocked``；
  refresh_* 系列仅在解锁后刷新/数据变更回调链上触发，锁定态不可达（prepare_for_lock
  已清空分类/标签控件并阻断信号）；
- EntryActionsController 的分类增删改均带 ``@require_unlocked``；
- 设置→主题切换（rebuild_for_theme）入口在菜单栏，锁定态经主窗口禁用/隐藏隔离，
  托盘菜单无设置入口。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...models import Category


class SidebarController:
    """侧边栏分类管理的纯数据逻辑控制器，不持有任何 UI 控件引用。"""

    def __init__(self, entry_manager: EntryManager) -> None:
        self._entry_mgr = entry_manager

    # ========== 分类数据读取 ==========

    def get_categories(self) -> list[Category]:
        return self._entry_mgr.categories.get_categories()

    def get_category_entry_counts(self) -> dict[int, int]:
        return self._entry_mgr.categories.get_category_entry_counts()

    def get_category_entry_count(self, category_id: int) -> int:
        return self._entry_mgr.categories.get_category_entry_count(category_id)

    def get_category(self, category_id: int) -> Category | None:
        return self._entry_mgr.categories.get_category(category_id)

    def get_all_tags(self) -> list[tuple[str, int]]:
        return self._entry_mgr.get_all_tags()

    @property
    def tags_cache_valid(self) -> bool:
        """标签缓存是否有效，委托 entry_manager。供主窗口决定标签下拉同步/异步刷新。"""
        return self._entry_mgr.tags_cache_valid

    # ========== 分类 CRUD ==========

    def build_category_label(self, cat: Category, count: int) -> str:
        """构建分类列表项的显示文本。

        分类元数据完整性校验失败时（``cat.integrity_error``）在名称前加 ⚠ 警告标识，
        使分类层 HMAC 篡改对用户可见（icon/color/sort_order 等非加密元数据被篡改）。
        """
        name = f"⚠ {cat.name}" if cat.integrity_error else cat.name
        if count > 0:
            return f"{cat.icon_char} {name} ({count})"
        return f"{cat.icon_char} {name}"

    def build_delete_message(self, category_id: int) -> tuple[str, bool, str]:
        """构建删除分类的确认消息。

        Returns:
            由确认消息、是否含条目、分类名称组成的三元组。has_entries 为 True
            表示该分类下有条目，需要额外提醒；category_name 为分类名称，供
            UI 反馈使用，分类不存在时为空串。
        """
        category = self._entry_mgr.categories.get_category(category_id)
        if not category:
            return "", False, ""
        count = self._entry_mgr.categories.get_category_entry_count(category_id)
        msg = f"确定要删除分类「{category.name}」吗？"
        if count > 0:
            msg += f"\n\n该分类下有 {count} 个条目，删除后将取消分类归属。"
        return msg, count > 0, category.name

    def delete_category(self, category_id: int) -> bool:
        """删除指定分类。

        Returns:
            分类存在并成功删除时返回 True，分类不存在时返回 False。
        """
        category = self._entry_mgr.categories.get_category(category_id)
        if not category:
            return False
        self._entry_mgr.categories.delete_category(category_id)
        return True
