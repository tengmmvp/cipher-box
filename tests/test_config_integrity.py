"""测试配置文件 HMAC 完整性签名与篡改检测。"""

import json

import pytest

from src.config import DEFAULT_CONFIG

from tests.helpers import make_test_config


@pytest.fixture
def config(tmp_path):
    """创建使用临时目录的 ConfigManager 实例。"""
    return make_test_config(tmp_path)


class TestConfigIntegrity:
    def test_save_load_round_trip(self, config):
        """save() 写入 HMAC 签名，load() 正常加载且无警告。"""
        config._config['theme'] = 'dark'
        config.save()
        assert config._config_path.exists()

        # 重新加载
        config2 = make_test_config(config._data_dir)
        config2.load()

        assert config2._config['theme'] == 'dark'
        assert config2.check_integrity() is True

    def test_tampered_content_detected(self, config):
        """篡改 JSON 内容后 load() 应标记完整性警告。"""
        config.save()

        # 篡改文件内容（修改 JSON 但保留签名行）
        raw = config._config_path.read_text(encoding='utf-8')
        lines = raw.rsplit('\n', 1)
        assert len(lines) == 2
        json_text = lines[0]
        sig_line = lines[1]

        # 修改一个值
        tampered = json_text.replace('"theme": "light"', '"theme": "dark"')
        config._config_path.write_text(tampered + '\n' + sig_line, encoding='utf-8')

        # 重新加载
        config2 = make_test_config(config._data_dir)
        config2.load()

        assert config2.check_integrity() is False

    def test_missing_signature_no_warning(self, config):
        """旧格式文件无签名行，不触发完整性警告。"""
        # 写入无签名的 JSON
        raw_json = json.dumps(dict(DEFAULT_CONFIG))
        config._config_path.write_text(raw_json, encoding='utf-8')

        config.load()
        assert config.check_integrity() is True  # 无签名=旧格式，不算篡改

    def test_atomic_write_uses_tmp(self, config):
        """save() 使用 .json.tmp 中间文件再 os.replace。"""
        config.save()
        # .tmp 文件不应残留
        tmp_file = config._config_path.with_suffix('.json.tmp')
        assert not tmp_file.exists()
        # 目标文件存在
        assert config._config_path.exists()
