"""侧边栏控制器 — 从 MainWindow 分类管理中提取的纯数据操作

负责分类数据的读取和 CRUD 逻辑，不操作 UI 控件。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...config import ConfigManager
    from ...models import Category


class SidebarController:
    """侧边栏分类管理的纯数据逻辑控制器。

    通过构造函数注入 ``entry_manager`` 和 ``config``，
    不持有任何 UI 控件引用。
    """

    def __init__(
        self,
        entry_manager: EntryManager,
        config: ConfigManager,
    ) -> None:
        self._entry_mgr = entry_manager
        self._config = config

    # ========== 分类数据读取 ==========

    def get_categories(self) -> list[Category]:
        """获取所有分类。"""
        return self._entry_mgr.categories.get_categories()

    def get_category_entry_counts(self) -> dict[int, int]:
        """获取每个分类的条目数量。"""
        return self._entry_mgr.categories.get_category_entry_counts()

    def get_category_entry_count(self, category_id: int) -> int:
        """获取指定分类的条目数量。"""
        return self._entry_mgr.categories.get_category_entry_count(category_id)

    def get_category(self, category_id: int) -> Category | None:
        """获取指定分类对象。"""
        return self._entry_mgr.categories.get_category(category_id)

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其条目数量。"""
        return self._entry_mgr.get_all_tags()

    @property
    def tags_cache_valid(self) -> bool:
        """标签缓存是否有效，委托 entry_manager。供主窗口决定标签下拉同步/异步刷新。"""
        return self._entry_mgr.tags_cache_valid

    # ========== 分类 CRUD ==========

    def build_category_label(self, cat: Category, count: int) -> str:
        """构建分类列表项的显示文本。"""
        if count > 0:
            return f'{cat.icon_char} {cat.name} ({count})'
        return f'{cat.icon_char} {cat.name}'

    def build_delete_message(self, category_id: int) -> tuple[str, bool, str]:
        """构建删除分类的确认消息。

        Returns:
            由确认消息、是否含条目、分类名称组成的三元组。has_entries 为 True
            表示该分类下有条目，需要额外提醒；category_name 为分类名称，供
            UI 反馈使用，分类不存在时为空串。
        """
        category = self._entry_mgr.categories.get_category(category_id)
        if not category:
            return '', False, ''
        count = self._entry_mgr.categories.get_category_entry_count(category_id)
        msg = f'确定要删除分类「{category.name}」吗？'
        if count > 0:
            msg += f'\n\n该分类下有 {count} 个条目，删除后将取消分类归属。'
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
