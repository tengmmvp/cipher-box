"""共享测试辅助函数。

此处放置非 fixture 的工具函数，供 conftest.py 和各测试文件共同使用。
pytest fixture 仍定义在 conftest.py 中。
"""

from pathlib import Path

from src.config import DEFAULT_CONFIG, ConfigManager


def make_test_config(data_dir) -> ConfigManager:
    """创建使用指定目录的 ConfigManager 实例（绕过 __init__，不加载真实配置）。

    各测试文件应调用此函数而非重复 ConfigManager.__new__() + 手动属性设置。
    """
    cfg = ConfigManager.__new__(ConfigManager)
    cfg._data_dir = Path(data_dir)
    cfg._config_path = Path(data_dir) / 'config.json'
    cfg._config = dict(DEFAULT_CONFIG)
    cfg._config['show_tray_icon'] = False
    cfg._integrity_warning = False
    return cfg
