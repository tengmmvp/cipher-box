"""共享测试辅助函数。

此处放置非 fixture 的工具函数，供 conftest.py 和各测试文件共同使用。
pytest fixture 仍定义在 conftest.py 中。
"""

from src.config import ConfigManager


def make_test_config(data_dir) -> ConfigManager:
    """创建使用指定目录的 ConfigManager 测试实例。

    委托给 ConfigManager.for_testing() 工厂方法。
    """
    return ConfigManager.for_testing(data_dir)
