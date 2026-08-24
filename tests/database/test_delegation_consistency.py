"""DatabaseManager ↔ Repository 委托透传一致性测试。

DatabaseManager 在「委托与编排」区（db_manager.py 尾部）大量手写委托方法，
把调用透传到 ``_entry_repo`` / ``_category_repo`` / ``_password_history_repo``。
Repository 新增公有方法后
若漏写 DatabaseManager 透传，是高频回归点——业务层经 ``VaultManager.db.<method>()``
访问会在运行时抛 AttributeError。

本测试用 inspect 枚举 EntryRepository / CategoryRepository /
PasswordHistoryRepository 的全部公有方法
（不含下划线前缀、不含 property），断言每个都经 DatabaseManager 实例可访问
（``hasattr`` 为 True），把「Repository 新增方法 / DatabaseManager 漏透传」
的双源漂移从运行时 AttributeError 提到测试期。

为何不用 ``__getattr__`` 动态委托：Pyright 严格模式下动态委托会让调用方丢失
返回类型推断，故项目刻意保留显式手写委托（见 db_manager.py「委托与编排」区注释）。
显式委托的代价即本测试守护的漂移风险。

豁免说明：``clear_category_signatures`` 是 EntryRepository 公开供
``DatabaseManager.delete_category`` 在事务内调用的跨表编排接口（解关联条目 +
重算签名），非对称 CRUD 透传，业务层不经 ``db.clear_category_signatures()`` 访问，
故登记在 ``_DELEGATION_EXEMPT`` 豁免。
"""

import inspect

import pytest

from src.database.category_repository import CategoryRepository
from src.database.db_manager import DatabaseManager
from src.database.entry_repository import EntryRepository
from src.database.password_history_repository import PasswordHistoryRepository

# 豁免透传断言的 (Repository 类, 方法名) 对；新增项须在此登记并说明理由（理由见模块 docstring）。
_DELEGATION_EXEMPT: set[tuple[type, str]] = {
    (EntryRepository, "clear_category_signatures"),
}


def _public_methods(cls: type) -> set[str]:
    """枚举类直接定义的公有方法名（不含下划线前缀、不含 dunder、不含 property）。

    仅取本类 ``__dict__`` 中的函数（不爬父类），聚焦「Repository 自身声明的数据
    访问方法」；排除 property 描述符（如 ``in_transaction``，它反向代理回 manager，
    非 Repository 数据访问方法），避免把 property 当方法断言。
    """
    return {
        name
        for name, member in cls.__dict__.items()
        if not name.startswith("_") and inspect.isfunction(member)
    }


@pytest.fixture
def db(tmp_path):
    """DatabaseManager 实例（未打开连接），仅做 hasattr 断言。

    ``__init__`` 已构造 ``_entry_repo`` / ``_category_repo`` /
    ``_password_history_repo`` 子 Repository，
    ``hasattr`` 校验透传方法是否声明只需实例存在，无需活动连接或表结构，
    故不调用 ``open()`` / ``init_tables()``，保持测试轻量且无文件 I/O 副作用。
    """
    return DatabaseManager(tmp_path / "test_delegation.db", test_mode=True)


@pytest.mark.parametrize(
    "repo_cls",
    [EntryRepository, CategoryRepository, PasswordHistoryRepository],
    ids=["EntryRepository", "CategoryRepository", "PasswordHistoryRepository"],
)
def test_all_repository_public_methods_accessible_on_database_manager(db, repo_cls):
    """每个 Repository 公有方法都应经 DatabaseManager 实例可访问。

    新增 Repository 方法漏写 DatabaseManager 透传会让经 ``db.<method>()`` 访问的
    调用方运行时 AttributeError；本测试把该漂移提到测试期。豁免项见模块 docstring
    与 ``_DELEGATION_EXEMPT``。
    """
    public_methods = _public_methods(repo_cls)
    # 防御：若重构导致枚举返回空集（如方法被改成 property / 类结构变化），
    # 断言将无意义，此处显式守护枚举非空。
    assert public_methods, f"{repo_cls.__name__} 未枚举到任何公有方法，断言失去意义"

    missing = {
        name
        for name in public_methods
        if (repo_cls, name) not in _DELEGATION_EXEMPT and not hasattr(db, name)
    }
    assert not missing, (
        f"{repo_cls.__name__} 的公有方法未在 DatabaseManager 上找到对应透传/原生方法："
        f"{sorted(missing)}。请在 src/database/db_manager.py「委托与编排」区补齐"
        f"显式透传方法；或若属跨表编排/非对称接口，在 _DELEGATION_EXEMPT 显式登记"
        f"并说明理由。"
    )


def test_delegation_exempt_methods_are_actually_public_and_absent(db):
    """豁免项健康检查：豁免的方法确实仍是 Repository 公有方法，且确实不在 DatabaseManager 上。

    防止豁免集失效（方法被重命名/删除后豁免项成为死代码）以及豁免项被滥用
    （方法实际已被透传却仍登记豁免，掩盖漏写）。若豁免方法已被补上透传，
    应从 _DELEGATION_EXEMPT 移除而非保留。
    """
    for repo_cls, method_name in _DELEGATION_EXEMPT:
        assert method_name in _public_methods(repo_cls), (
            f"{repo_cls.__name__}.{method_name} 不再是公有方法，"
            f"请从 _DELEGATION_EXEMPT 移除该失效豁免项"
        )
        assert not hasattr(db, method_name), (
            f"DatabaseManager 已提供 {method_name} 透传，"
            f"请从 _DELEGATION_EXEMPT 移除该豁免项（豁免仅用于未透传的方法）"
        )
