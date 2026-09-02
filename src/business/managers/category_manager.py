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
        vault: "VaultManager",
        cache: EntryCacheManager,
        change_bus: EntryChangeBus,
    ):
        self._vault = vault
        self._cache = cache
        self._change_bus = change_bus
        # 会话级分类缓存（epoch 守卫）：分类数据变更频率低，缓存命中时跳过全量 DB
        # SELECT + HMAC 验签。分类 CRUD 后主动失效；锁定经组合根注册的
        # invalidate_caches 显式清空明文（SEC-053），改密/恢复经 epoch 守卫失效。
        self._categories_cache: list[Category] | None = None
        self._categories_cache_epoch: str | None = None
        # 分类条目计数会话缓存（PERF-064）：GROUP BY 全表计数在 50k 库实测 ~25ms/次，
        # 而条目变更后的侧边栏刷新（_do_refresh_after_entry_change）每次都会读。失效
        # 通道见 get_category_entry_counts 文档。
        self._entry_counts_cache: dict[int, int] | None = None
        self._entry_counts_cache_epoch: str | None = None
        # 结构性变更自订阅（PERF-064）：增删/批量/恢复等改变「分类×条目」分布的
        # notify 以 crypto_id=None 且安全维度非纯旁路触发；与 bus 内建的
        # cache.apply_change 同为「缓存失效挂总线」模式，自订阅使任何构造路径
        # （组合根/测试工厂）都获得失效连线。
        self._change_bus.register(self._on_entries_structurally_changed)

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    @property
    def categories_cache_present(self) -> bool:
        """明文分类会话缓存是否驻留（测试观察用，MAINT-095）。

        只读视图：守护 SEC-053 锁定清空连线的测试经此断言缓存置空，不再直读
        ``_categories_cache``（缓存置空时 epoch 一并由 invalidate_caches 同步置空）。
        """
        return self._categories_cache is not None

    @property
    def entry_counts_cache(self) -> dict[int, int] | None:
        """分类条目计数缓存的拷贝（测试观察用，MAINT-095），未填充返回 None。

        拷贝语义与 :meth:`get_category_entry_counts` 的出口一致，测试断言内容
        相等性（如「锁定保留纯计数缓存」的锚定）不污染内部缓存。
        """
        return None if self._entry_counts_cache is None else dict(self._entry_counts_cache)

    def invalidate_caches(self) -> None:
        """清空明文分类缓存（锁定/密钥轮换回调入口，SEC-053）。

        组合根注册到 register_on_lock / register_on_epoch_rotated：``_categories_cache``
        持有解密后的明文分类名，锁定后若驻留会使明文在锁定态（密钥已清零）仍可从
        内存 dump 读出——读时 epoch 守卫只防锁定后复用，不清内存，须显式置空收缩
        暴露面（与 list_refresh_controller.prepare_for_lock 清 UI 侧同源缓存的纪律
        对齐）。解锁后 epoch 不变也不会命中已置空缓存，重读 DB 即可。

        条目计数缓存（``_entry_counts_cache``）有意不清：纯 COUNT 整数、无明文，
        锁定驻留无泄漏面；且锁定不改数据，保留命中是正确行为（见
        :meth:`get_category_entry_counts` 的失效通道说明），轮换后由读时 epoch 守卫
        自然失效。
        """
        self._categories_cache = None
        self._categories_cache_epoch = None

    def get_categories(self) -> list[Category]:
        """获取全部分类，分类名经缓存解密，按 sort_order 与名称排序。

        会话级缓存（epoch 守卫）：缓存命中时跳过全量 DB SELECT + HMAC 验签。分类
        CRUD 后主动失效；锁定经 :meth:`invalidate_caches` 清空明文（SEC-053），改密/
        恢复经 epoch 守卫失效。返回浅拷贝避免调用方修改污染缓存（Category 为
        frozen dataclass，浅拷贝足够）。
        """
        current_epoch = self._vault.key_epoch
        if self._categories_cache is not None and self._categories_cache_epoch == current_epoch:
            return list(self._categories_cache)
        categories = self._vault.db.get_categories()
        decrypted: list[Category] = []
        for category in categories:
            if category.id is not None:
                category = replace(
                    category,
                    name=self._cache.decrypt_category_name(category.id, category.name),
                )
            decrypted.append(category)
        result = sorted(decrypted, key=lambda item: (item.sort_order, item.name.casefold()))
        self._categories_cache = result
        self._categories_cache_epoch = current_epoch
        return list(result)

    def _invalidate_categories_cache(self) -> None:
        """分类 CRUD 后失效会话缓存（含条目计数缓存），下次 get_* 重读 DB。

        计数缓存一并失效：add/delete 改变「当前分类集」的计数定义域（新分类补 0、
        删除分类的条目归 NULL），update_category 虽不改计数但属低频操作，统一失效
        保持单一失效点。
        """
        self._categories_cache = None
        self._categories_cache_epoch = None
        self.invalidate_entry_counts_cache()

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
        """获取全部分类的条目数映射 {category_id: count}（会话缓存，PERF-064）。

        缓存命中跳过 GROUP BY 全表扫描；返回浅拷贝防调用方就地变异污染缓存。失效
        通道（命中「分类×有效条目」分布变化的全部路径）：

        - 条目结构性变更（增/删/恢复/永久删除/清空回收站/导入批量）：经
          :meth:`_on_entries_structurally_changed` 的 change_bus 订阅失效。
        - 单条编辑改 category_id：bus 的 crypto_id 单条通道无法表达该维度，由
          :meth:`EntryManager._notify_entry_updated` 检测归属变化后显式调用
          :meth:`invalidate_entry_counts_cache`。
        - 分类 CRUD：:meth:`_invalidate_categories_cache` 内一并失效。
        - epoch 轮换（备份恢复整体替换数据）：读时 epoch 守卫自然失效。锁定不改
          数据，epoch 守卫在解锁后命中旧缓存是正确行为。
        - 纯旁路变更（toggle_favorite 等）：不失效，二次读取直接命中。
        """
        current_epoch = self._vault.key_epoch
        if self._entry_counts_cache is not None and self._entry_counts_cache_epoch == current_epoch:
            return dict(self._entry_counts_cache)
        counts = self._vault.db.get_category_entry_counts()
        self._entry_counts_cache = counts
        self._entry_counts_cache_epoch = current_epoch
        return dict(counts)

    def invalidate_entry_counts_cache(self) -> None:
        """失效条目计数缓存（结构性变更或单条编辑改 category_id 后调用）。"""
        self._entry_counts_cache = None
        self._entry_counts_cache_epoch = None

    def _on_entries_structurally_changed(
        self,
        password_changed: bool,
        metadata_changed: bool,
        crypto_id: str | None,
    ) -> None:
        """change_bus 订阅：条目结构性变更（crypto_id=None 的全量语义）失效计数缓存。

        判定：crypto_id 非 None 属单条编辑（归属变化由 EntryManager 显式失效，纯
        字段编辑不失效以保缓存命中）；password_changed/metadata_changed 皆 False 的
        纯旁路变更（toggle_favorite、分类 CRUD 通知）不改变计数，跳过——分类 CRUD
        的失效经 :meth:`_invalidate_categories_cache` 独立完成。
        """
        if crypto_id is None and (password_changed or metadata_changed):
            self.invalidate_entry_counts_cache()

    def _insert_category_two_phase(self, category: Category) -> int:
        """两阶段加密写入单分类（MAINT-002）：占位 id 加密 INSERT → 真实 id 重加密 UPDATE。

        add_category 与 add_categories_batch 共用此核心，消除两阶段加密样板重复。两阶段
        必要：分类名密文含 ``category_crypto_id`` 绑定（验签/解密定位），须先 INSERT 获
        真实 id 再用真实 id 重加密 name 更新——单阶段无法在 INSERT 前知道真实 id。不含
        查重（add_category 在调用前查重）与通知（调用方统一 notify）。调用方须保证非空名。
        """
        plaintext_name = category.name.strip()
        pending_id = f"category-pending-{uuid.uuid4().hex}"
        stored = Category(
            name=encrypt_field(plaintext_name, self._key, pending_id, "category_name"),
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
                "category_name",
            ),
        )
        self._vault.db.update_category(stored)
        return result

    def add_category(self, category: Category, *, notify: bool = True) -> int:
        """新增分类（查重 + 两阶段加密写入）。

        查重在事务内进行（防 TOCTOU：并发两次同名分类都通过查重后各自写入），再经
        :meth:`_insert_category_two_phase` 占位→真实 id 两阶段加密写入。
        """
        plaintext_name = category.name.strip()
        if not plaintext_name:
            raise EntryError("分类名称不能为空")
        with self._vault.db.transaction():
            existing_names = {existing.name.casefold() for existing in self.get_categories()}
            if plaintext_name.casefold() in existing_names:
                raise EntryError("分类名称已存在")
            result = self._insert_category_two_phase(category)
        category = replace(category, id=result, name=plaintext_name)
        # 分类变更不改条目摘要内容（title/url/tags 不变），保留搜索摘要缓存；
        # 仅失效分类名缓存并通知回调刷新侧边栏分类列表。先失效会话分类缓存，
        # 使 notify 触发的回调读到含新分类的列表。
        self._invalidate_categories_cache()
        if notify:
            self._change_bus.notify(
                password_changed=False,
                tags_changed=False,
                category_changed=True,
                clear_summaries=False,
                metadata_changed=False,  # 分类不进入安全报告判定，跳过安全缓存失效
            )
        return result

    def add_categories_batch(
        self,
        categories: list[Category],
        *,
        notify: bool = True,
    ) -> list[int]:
        """批量新增分类（恢复路径），返回按输入顺序的新 id 列表（PERF-004）。

        恢复前已 ``clear_vault_data`` 清空分类表，故无需逐条查重——逐条 ``add_category``
        经 ``get_categories`` 全表解密查重为 O(N²)。经 :meth:`_insert_category_two_phase`
        在单事务内批量两阶段加密写入，无逐次 commit/fsync。空名项记 0（调用方应过滤）。
        """
        new_ids: list[int] = []
        if not categories:
            if notify:
                # 参数与非空分支对齐（QL-059）：metadata_changed=False 跳过安全缓存
                # 失效——空列表无数据变更，缺省 True 会触发 SecurityAnalyzer 整库
                # 重算与分类计数缓存无谓失效（同方法两分支参数漂移的典型）。
                self._change_bus.notify(
                    password_changed=False,
                    tags_changed=False,
                    category_changed=True,
                    clear_summaries=False,
                    metadata_changed=False,
                )
            return new_ids
        with self._vault.db.transaction():
            for category in categories:
                if not category.name.strip():
                    new_ids.append(0)
                    continue
                new_ids.append(self._insert_category_two_phase(category))
        self._invalidate_categories_cache()
        if notify:
            self._change_bus.notify(
                password_changed=False,
                tags_changed=False,
                category_changed=True,
                clear_summaries=False,
                metadata_changed=False,  # 分类不进入安全报告判定，跳过安全缓存失效
            )
        return new_ids

    def update_category(self, category: Category) -> None:
        """更新分类，重加密分类名并失效分类名缓存（条目摘要内容不变）。

        改名前按 :meth:`add_category` 同款 casefold 明文查重（QL-023）：分类名密文含
        随机 nonce，相同明文永不产生相同密文，仓库层查重永不命中；缺此守卫时侧边栏
        可并存同名分类，且与导入路径按折叠名坍缩、add_category 拒绝新建同名自相
        矛盾。查重与写入同事务（防并发 add/update 的 TOCTOU），比对时排除自身 id
        （改回自身当前名合法）。
        """
        if category.id is None:
            raise EntryError("分类 ID 不能为空")
        plaintext_name = category.name.strip()
        with self._vault.db.transaction():
            existing_names = {
                existing.name.casefold()
                for existing in self.get_categories()
                if existing.id != category.id
            }
            if plaintext_name.casefold() in existing_names:
                raise EntryError("分类名称已存在")
            stored = Category(
                id=category.id,
                name=encrypt_field(
                    plaintext_name,
                    self._key,
                    category_crypto_id(category.id),
                    "category_name",
                ),
                icon_char=category.icon_char,
                color=category.color,
                sort_order=category.sort_order,
                created_at=category.created_at,
            )
            self._vault.db.update_category(stored)
        # 分类名/icon 变更不影响条目摘要内容，仅失效分类名缓存。先失效会话分类缓存
        # 使 notify 回调读到更新后的分类。
        self._invalidate_categories_cache()
        self._change_bus.notify(
            password_changed=False,
            tags_changed=False,
            category_changed=True,
            clear_summaries=False,
            metadata_changed=False,  # 分类不进入安全报告判定，跳过安全缓存失效
        )

    def delete_category(self, category_id: int) -> None:
        """删除分类，关联条目 category_id 置 NULL，失效分类名缓存。"""
        self._vault.db.delete_category(category_id)
        # 删除分类后关联条目 category_id 置 NULL，分类名缓存需失效；条目摘要
        # 内容（title/url/tags）不变，保留搜索摘要缓存避免全量重解密。先失效会话
        # 分类缓存使 notify 回调读到删除后的列表。
        self._invalidate_categories_cache()
        self._change_bus.notify(
            password_changed=False,
            tags_changed=False,
            category_changed=True,
            clear_summaries=False,
            metadata_changed=False,  # 分类不进入安全报告判定，跳过安全缓存失效
        )
