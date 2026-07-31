"""分类管理器 — 分类的加密 CRUD 与加解密。

分类名经 crypto_utils 加密落库，读取时经 EntryCacheManager 解密并缓存。写操作
经 EntryChangeBus 通知（category_changed=True，保留搜索摘要缓存）。

add_category 采用两阶段加密事务：先用 pending_id 占位加密写入获得真实 id，
再在事务内用真实 category_crypto_id 重加密分类名并更新。该事务必须整体迁移，
不能拆，否则会残留 pending_id 密文。
"""

import uuid
from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...exceptions import EntryError
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
        """获取全部分类，分类名经缓存解密，按 sort_order 与名称排序。"""
        categories = self._vault.db.get_categories()
        decrypted: list[Category] = []
        for category in categories:
            if category.id is not None:
                category = replace(
                    category,
                    name=self._cache.decrypt_category_name(category.id, category.name),
                )
            decrypted.append(category)
        return sorted(decrypted, key=lambda item: (item.sort_order, item.name.casefold()))

    def get_category(self, category_id: int) -> Category | None:
        """获取指定分类，分类名经缓存解密。"""
        category = self._vault.db.get_category(category_id)
        if category is not None:
            category = replace(
                category,
                name=self._cache.decrypt_category_name(category_id, category.name),
            )
        return category

    def get_category_entry_count(self, category_id: int) -> int:
        """获取指定分类下的（未删除）条目数。"""
        return self._vault.db.get_category_entry_count(category_id)

    def get_category_entry_counts(self) -> dict[int, int]:
        """获取全部分类的条目数映射 {category_id: count}。"""
        return self._vault.db.get_category_entry_counts()

    def add_category(self, category: Category, *, notify: bool = True) -> int:
        """新增分类（两阶段加密事务）。

        先用 pending_id 占位加密写入获得真实 id，再在事务内用真实
        category_crypto_id 重加密并更新。事务必须整体迁移不能拆，否则残留
        pending_id 加密的分类名密文。

        查重在事务内进行，避免并发两次同名分类都通过查重后各自写入的 TOCTOU
        竞态（分类名以密文落库，UNIQUE 约束对密文无效）。
        """
        plaintext_name = category.name.strip()
        if not plaintext_name:
            raise EntryError('分类名称不能为空')
        pending_id = f'category-pending-{uuid.uuid4().hex}'
        with self._vault.db.transaction():
            existing_names = {
                existing.name.casefold() for existing in self.get_categories()
            }
            if plaintext_name.casefold() in existing_names:
                raise EntryError('分类名称已存在')
            stored = Category(
                name=encrypt_field(plaintext_name, self._key, pending_id, 'category_name'),
                icon_char=category.icon_char,
                color=category.color,
                sort_order=category.sort_order,
                created_at=category.created_at,
            )
            result = self._vault.db.add_category(stored)
            stored = replace(stored, id=result)
            stored = replace(
                stored,
                name=encrypt_field(
                    plaintext_name,
                    self._key,
                    category_crypto_id(result),
                    'category_name',
                ),
            )
            self._vault.db.update_category(stored)
        category = replace(category, id=result, name=plaintext_name)
        # 分类变更不改条目摘要内容（title/url/tags 不变），保留搜索摘要缓存；
        # 仅失效分类名缓存并通知回调刷新侧边栏分类列表。
        if notify:
            self._change_bus.notify(
                password_changed=False, tags_changed=False,
                category_changed=True, clear_summaries=False,
            )
        return result

    def update_category(self, category: Category) -> None:
        """更新分类，重加密分类名并失效分类名缓存（条目摘要内容不变）。"""
        if category.id is None:
            raise EntryError('分类 ID 不能为空')
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
        """删除分类，关联条目 category_id 置 NULL，失效分类名缓存。"""
        self._vault.db.delete_category(category_id)
        # 删除分类后关联条目 category_id 置 NULL，分类名缓存需失效；条目摘要
        # 内容（title/url/tags）不变，保留搜索摘要缓存避免全量重解密。
        self._change_bus.notify(
            password_changed=False, tags_changed=False,
            category_changed=True, clear_summaries=False,
        )
