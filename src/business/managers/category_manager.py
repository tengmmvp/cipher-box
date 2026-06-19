"""分类管理器 — 从 EntryManager 抽离的分类 CRUD 与加解密。

分类名经 crypto_utils 加密落库；读取时经 EntryCacheManager 解密并缓存。
写操作经 EntryChangeBus 通知缓存失效与回调（category_changed=True，
保留搜索摘要缓存，因分类变更不改变条目摘要内容）。

add_category 采用两阶段加密事务：先用 pending_id 占位加密写入获得真实
id，再在事务内用真实 category_crypto_id 重加密分类名并更新。该事务必须
整体迁移，不能拆，否则会残留 pending_id 密文。
"""

import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...models import Category
from ..services.crypto_utils import (
    category_crypto_id,
    encrypt_field,
    require_vault_key,
)
from .entry_cache import EntryCacheManager
from .entry_change_bus import EntryChangeBus


class CategoryManager:
    """分类的加密 CRUD、查询与缓存失效编排。"""

    def __init__(
        self,
        vault: 'VaultManager',
        cache: EntryCacheManager,
        change_bus: EntryChangeBus,
    ):
        self._vault = vault
        self._cache = cache
        self._change_bus = change_bus

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def get_categories(self) -> list[Category]:
        categories = self._vault.db.get_categories()
        for category in categories:
            if category.id is not None:
                category.name = self._cache.decrypt_category_name(
                    category.id, category.name,
                )
        return sorted(categories, key=lambda item: (item.sort_order, item.name.casefold()))

    def get_category(self, category_id: int) -> Category | None:
        category = self._vault.db.get_category(category_id)
        if category is not None:
            category.name = self._cache.decrypt_category_name(category_id, category.name)
        return category

    def get_category_entry_count(self, category_id: int) -> int:
        return self._vault.db.get_category_entry_count(category_id)

    def get_category_entry_counts(self) -> dict[int, int]:
        return self._vault.db.get_category_entry_counts()

    def add_category(self, category: Category, *, notify: bool = True) -> int:
        """新增分类（两阶段加密事务）。

        先用 pending_id 占位加密分类名写入数据库获得真实 id，再在事务内用
        真实 category_crypto_id 重加密并更新。事务必须整体迁移不能拆，否则
        会残留 pending_id 加密的分类名密文。
        """
        if not category.name.strip():
            raise ValueError('分类名称不能为空')
        if any(
            existing.name.casefold() == category.name.strip().casefold()
            for existing in self.get_categories()
        ):
            raise ValueError('分类名称已存在')
        plaintext_name = category.name.strip()
        pending_id = f'category-pending-{uuid.uuid4().hex}'
        stored = Category(
            name=encrypt_field(plaintext_name, self._key, pending_id, 'category_name'),
            icon_char=category.icon_char,
            color=category.color,
            sort_order=category.sort_order,
            created_at=category.created_at,
        )
        with self._vault.db.transaction():
            result = self._vault.db.add_category(stored)
            stored.id = result
            stored.name = encrypt_field(
                plaintext_name,
                self._key,
                category_crypto_id(result),
                'category_name',
            )
            self._vault.db.update_category(stored)
        category.id = result
        category.name = plaintext_name
        # 分类变更不改条目摘要内容（title/url/tags 不变），保留搜索摘要缓存；
        # 仅失效分类名缓存并通知回调刷新侧边栏分类列表。
        if notify:
            self._change_bus.notify(
                password_changed=False, tags_changed=False,
                category_changed=True, clear_summaries=False,
            )
        return result

    def update_category(self, category: Category) -> None:
        if category.id is None:
            raise ValueError('分类 ID 不能为空')
        plaintext_name = category.name.strip()
        stored = Category(
            id=category.id,
            name=encrypt_field(
                plaintext_name,
                self._key,
                category_crypto_id(category.id),
                'category_name',
            ),
            icon_char=category.icon_char,
            color=category.color,
            sort_order=category.sort_order,
            created_at=category.created_at,
        )
        self._vault.db.update_category(stored)
        # 分类名/icon 变更不影响条目摘要内容，仅失效分类名缓存。
        self._change_bus.notify(
            password_changed=False, tags_changed=False,
            category_changed=True, clear_summaries=False,
        )

    def delete_category(self, category_id: int) -> None:
        self._vault.db.delete_category(category_id)
        # 删除分类后关联条目 category_id 置 NULL，分类名缓存需失效；条目摘要
        # 内容（title/url/tags）不变，保留搜索摘要缓存避免全量重解密。
        self._change_bus.notify(
            password_changed=False, tags_changed=False,
            category_changed=True, clear_summaries=False,
        )
