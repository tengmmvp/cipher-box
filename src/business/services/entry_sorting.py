"""条目排序键提取器（纯函数，无加解密与缓存依赖）。

自 managers/entry_manager 迁出（MAINT-104）：排序键与搜索谓词（entry_search_match）
同属「条目查询域纯函数」，按 services 归属约定与 MAINT-097 的拆分先例归位——此前
驻留 managers 使 UI（entry_list_controller）为消费 4 键逻辑 import
managers.entry_manager，与同性质纯函数的归属不一致。消费方：EntryManager 内存
排序路径（窄投影行经 :class:`SortKeySource` 适配）。UI 侧的
``EntryListController.sort_entries`` 重排入口已随死代码删除（QL-074）——列表排序
统一由 manager 分流，本模块不再有 UI 直接调用方。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import NamedTuple, Protocol


class EntrySortKeySource(Protocol):
    """排序键字段的最小协议（MAINT-091）：明文 Entry 与窄投影适配行同时满足。"""

    @property
    def title(self) -> str: ...

    @property
    def password_strength(self) -> int | None: ...

    @property
    def created_at(self) -> str: ...

    @property
    def updated_at(self) -> str: ...


class SortKeySource(NamedTuple):
    """内存排序路径的排序键源（MAINT-091）：以 Entry 同名字段形态聚合窄投影行与摘要 meta。

    title 取 meta.title_lower（已小写，经 entry_sort_key 再 lower 幂等），其余三键
    来自 SearchRow 的明文列——使「窄投影+meta 排序」与「宽行 Entry 排序」共用同一
    键函数，消除 4 键排序在 business/UI 的双实现漂移面。MAINT-104 随模块迁出
    managers 时去掉下划线前缀：跨模块消费（entry_manager）的适配器不再是
    managers 的私有实现细节。
    """

    title: str
    password_strength: int | None
    created_at: str
    updated_at: str


def entry_sort_key(field: str) -> Callable[[EntrySortKeySource], str | int]:
    """按字段返回条目排序键提取器（单一事实源，MAINT-091）。

    消费方：EntryManager 内存排序路径（窄投影经 :class:`SortKeySource` 适配；
    UI 的重排入口已随 QL-074 删除，列表排序不经 UI 二次重排）——此前同一套
    4 键逻辑在 business/UI 两处各一份，键语义漂移会使 SQL 下推序与内存排序序
    不一致。未知字段回退 ``updated_at``，与 ``get_entry_summaries`` 内存路径的
    原回退分支一致；``title`` 键为小写形式（与 meta.title_lower 同源）。
    """
    if field == "title":
        return lambda e: (e.title or "").lower()
    if field == "password_strength":
        # password_strength 可能为 None（未评估），统一回退 0，避免与 int 混排抛 TypeError。
        return lambda e: e.password_strength or 0
    if field == "created_at":
        return lambda e: e.created_at or ""
    return lambda e: e.updated_at or ""
