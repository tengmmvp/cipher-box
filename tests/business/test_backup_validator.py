"""backup_validator 模块测试 — 恢复前载荷结构、键完整性与长度上限校验。

覆盖 validate_restore_data 顶层校验链与 validate_categories / validate_entries /
validate_entry_fields / validate_entry_custom_fields / validate_history /
require_keys / require_text 各级子校验的合法通过与各类非法拒绝路径。
"""

import pytest

from src.business.services.backup_header_codec import BACKUP_FORMAT
from src.business.services.backup_validator import (
    MAX_BACKUP_ENTRIES,
    MAX_CUSTOM_FIELDS_PER_ENTRY,  # noqa: F401  仅用于断言一致性
    MAX_ENTRY_JSON_SIZE,
    MAX_HISTORY_PER_ENTRY,
    require_keys,
    require_text,
    validate_categories,
    validate_entries,
    validate_entry_custom_fields,
    validate_entry_fields,
    validate_history,
    validate_restore_data,
)
from src.business.services.crypto_utils import STRING_ENCRYPTED_FIELDS
from src.exceptions import BackupError, PayloadTooLargeError
from src.models import MAX_PASSWORD_HISTORY


def _valid_category(category_id: int = 1, name: str = '工作') -> dict:
    return {
        'id': category_id,
        'name': name,
        'icon_char': '[DIR]',
        'color': '#666666',
        'sort_order': 0,
        'created_at': '2024-01-01T00:00:00',
    }


def _valid_entry(
    entry_id: int = 1,
    crypto_id: str = 'a' * 32,
    category_id: int | None = 1,
) -> dict:
    return {
        'id': entry_id,
        'crypto_id': crypto_id,
        'title': '标题',
        'username': 'user',
        'password': 'pass',
        'url': 'https://example.com',
        'category_id': category_id,
        'tags': 'tag1',
        'notes': '',
        'custom_fields': [],
        'is_favorite': False,
        'is_deleted': False,
        'password_strength': 3,
        'entry_type': 'login',
        'totp_secret': '',
        'created_at': '2024-01-01T00:00:00',
        'updated_at': '2024-01-01T00:00:00',
        'deleted_at': '',
        'password_changed_at': '',
    }


def _valid_history(entry_id: int = 1) -> dict:
    return {
        'entry_id': entry_id,
        'password': 'old-pass',
        'changed_at': '2024-01-01T00:00:00',
    }


def _valid_restore_data() -> dict:
    return {
        'format': BACKUP_FORMAT,
        'version': 1,
        'entries': [_valid_entry()],
        'categories': [_valid_category()],
        'password_history': [_valid_history()],
    }


class TestValidateRestoreData:
    """顶层校验链。"""

    def test_valid_data_passes(self):
        validate_restore_data(_valid_restore_data())  # 不抛即通过

    def test_bad_format_rejected(self):
        data = _valid_restore_data()
        data['format'] = 'OtherFormat'
        with pytest.raises(BackupError, match='格式'):
            validate_restore_data(data)

    def test_bad_version_rejected(self):
        data = _valid_restore_data()
        data['version'] = 2
        with pytest.raises(BackupError, match='版本'):
            validate_restore_data(data)

    def test_unsupported_version_zero_rejected(self):
        data = _valid_restore_data()
        data['version'] = 0
        with pytest.raises(BackupError, match='版本'):
            validate_restore_data(data)

    def test_entries_not_list_rejected(self):
        data = _valid_restore_data()
        data['entries'] = 'not-a-list'
        with pytest.raises(BackupError, match='结构'):
            validate_restore_data(data)

    def test_categories_not_list_rejected(self):
        data = _valid_restore_data()
        data['categories'] = {}
        with pytest.raises(BackupError, match='结构'):
            validate_restore_data(data)

    def test_too_many_entries_rejected(self):
        data = _valid_restore_data()
        data['entries'] = [_valid_entry(i) for i in range(MAX_BACKUP_ENTRIES + 1)]
        with pytest.raises(PayloadTooLargeError, match='条目'):
            validate_restore_data(data)

    def test_too_many_categories_rejected(self):
        data = _valid_restore_data()
        data['categories'] = [
            _valid_category(i) for i in range(10_001)
        ]
        # categories 数量校验在 validate_entries 之前
        with pytest.raises(PayloadTooLargeError, match='分类'):
            validate_restore_data(data)

    def test_too_many_history_rejected(self):
        data = _valid_restore_data()
        # 单条目但历史数超过 len(entries)*MAX_HISTORY_PER_ENTRY
        data['entries'] = [_valid_entry(1)]
        data['password_history'] = [
            _valid_history(1) for _ in range(MAX_HISTORY_PER_ENTRY + 2)
        ]
        with pytest.raises(PayloadTooLargeError, match='历史'):
            validate_restore_data(data)

    def test_history_limit_scales_with_entries(self):
        """历史数上限应随条目数等比放大。"""
        data = _valid_restore_data()
        data['entries'] = [_valid_entry(1), _valid_entry(2)]
        data['password_history'] = [
            _valid_history(1 if i % 2 else 2)
            for i in range(MAX_HISTORY_PER_ENTRY * 2 + 1)
        ]
        # entries=2 → 上限 2*MAX_HISTORY_PER_ENTRY；此处略超应被拒
        with pytest.raises(PayloadTooLargeError, match='历史'):
            validate_restore_data(data)


class TestValidateCategories:
    """分类校验。"""

    def test_valid_returns_ids(self):
        ids = validate_categories([_valid_category(1), _valid_category(2)])
        assert ids == {1, 2}

    def test_duplicate_id_rejected(self):
        with pytest.raises(BackupError, match='重复'):
            validate_categories([_valid_category(1), _valid_category(1)])

    def test_non_dict_item_rejected(self):
        with pytest.raises(BackupError, match='格式'):
            validate_categories(['not-a-dict'])

    def test_missing_key_rejected(self):
        cat = _valid_category(1)
        del cat['color']
        with pytest.raises(BackupError, match='不完整'):
            validate_categories([cat])

    def test_extra_key_rejected(self):
        cat = _valid_category(1)
        cat['extra'] = 'x'
        with pytest.raises(BackupError, match='不完整'):
            validate_categories([cat])

    def test_bad_id_type_rejected(self):
        cat = _valid_category(1)
        cat['id'] = '1'  # 字符串
        with pytest.raises(BackupError, match='ID'):
            validate_categories([cat])

    def test_bool_id_rejected(self):
        """bool 是 int 子类，应被 is_real_int 排除。"""
        cat = _valid_category(1)
        cat['id'] = True
        with pytest.raises(BackupError, match='ID'):
            validate_categories([cat])

    def test_empty_name_rejected(self):
        cat = _valid_category(1)
        cat['name'] = '   '
        with pytest.raises(BackupError, match='不能为空'):
            validate_categories([cat])

    def test_bad_sort_order_rejected(self):
        cat = _valid_category(1)
        cat['sort_order'] = '0'
        with pytest.raises(BackupError, match='排序'):
            validate_categories([cat])


class TestValidateEntries:
    """条目集合校验（crypto_id / id / 分类引用）。

    validate_entries 先调 validate_entry_fields（校验分类引用），再校验
    crypto_id / id。故 crypto_id/id 相关用例需保证分类引用合法（cat_ids 含 1
    且 category_id=1），否则会在字段校验阶段先行失败。
    """

    def test_valid_returns_ids(self):
        cat_ids = {1}
        ids = validate_entries(
            [_valid_entry(1, 'a' * 32, 1), _valid_entry(2, 'b' * 32, None)],
            cat_ids,
        )
        assert ids == {1, 2}

    def test_non_dict_item_rejected(self):
        with pytest.raises(BackupError, match='格式'):
            validate_entries(['x'], set())

    def test_crypto_id_wrong_length_rejected(self):
        entry = _valid_entry(1, 'a' * 31, category_id=1)
        with pytest.raises(BackupError, match='加密标识'):
            validate_entries([entry], {1})

    def test_crypto_id_non_hex_rejected(self):
        entry = _valid_entry(1, 'g' * 32, category_id=1)  # g 非十六进制
        with pytest.raises(BackupError, match='加密标识'):
            validate_entries([entry], {1})

    def test_crypto_id_non_string_rejected(self):
        entry = _valid_entry(1, 'a' * 32, category_id=1)
        entry['crypto_id'] = 123
        with pytest.raises(BackupError, match='加密标识'):
            validate_entries([entry], {1})

    def test_duplicate_crypto_id_rejected(self):
        with pytest.raises(BackupError, match='加密标识'):
            validate_entries(
                [_valid_entry(1, 'a' * 32, 1), _valid_entry(2, 'a' * 32, 1)],
                {1},
            )

    def test_duplicate_entry_id_rejected(self):
        with pytest.raises(BackupError, match='ID'):
            validate_entries(
                [_valid_entry(1, 'a' * 32, 1), _valid_entry(1, 'b' * 32, 1)],
                {1},
            )

    def test_zero_entry_id_rejected(self):
        entry = _valid_entry(0, 'a' * 32, category_id=1)
        with pytest.raises(BackupError, match='ID'):
            validate_entries([entry], {1})

    def test_negative_entry_id_rejected(self):
        entry = _valid_entry(-5, 'a' * 32, category_id=1)
        with pytest.raises(BackupError, match='ID'):
            validate_entries([entry], {1})

    def test_category_reference_unknown_rejected(self):
        entry = _valid_entry(1, 'a' * 32, category_id=999)
        with pytest.raises(BackupError, match='分类'):
            validate_entries([entry], {1})


class TestValidateEntryFields:
    """单条目字段校验。"""

    def test_valid_passes(self):
        validate_entry_fields(_valid_entry(), {1})  # 不抛即通过

    def test_category_id_none_allowed(self):
        entry = _valid_entry(category_id=None)
        validate_entry_fields(entry, set())  # None 不参与引用校验

    def test_oversize_entry_json_rejected(self):
        entry = _valid_entry()
        # notes 字段填超长文本，使整体字节超过 MAX_ENTRY_JSON_SIZE
        entry['notes'] = 'x' * (MAX_ENTRY_JSON_SIZE + 10)
        with pytest.raises(BackupError, match='大小'):
            validate_entry_fields(entry, {1})

    def test_missing_key_rejected(self):
        entry = _valid_entry()
        del entry['title']
        with pytest.raises(BackupError, match='不完整'):
            validate_entry_fields(entry, {1})

    def test_field_too_long_rejected(self):
        """单字段超过其精确长度上限（notes > MAX_FIELD_NOTES）时，应由 require_text 抛
        PayloadTooLargeError（SEC-006：字段精确上限取代统一 1MB）。"""
        entry = _valid_entry()
        from src.business.services.backup_validator import _BACKUP_FIELD_LIMITS
        entry['notes'] = 'x' * (_BACKUP_FIELD_LIMITS['notes'] + 10)
        with pytest.raises(PayloadTooLargeError):
            validate_entry_fields(entry, {1})

    def test_field_non_string_rejected(self):
        entry = _valid_entry()
        entry['title'] = 123
        with pytest.raises(BackupError, match='类型'):
            validate_entry_fields(entry, {1})

    def test_is_favorite_non_bool_rejected(self):
        entry = _valid_entry()
        entry['is_favorite'] = 'yes'
        with pytest.raises(BackupError, match='布尔'):
            validate_entry_fields(entry, {1})

    def test_is_deleted_non_bool_rejected(self):
        entry = _valid_entry()
        entry['is_deleted'] = 1
        with pytest.raises(BackupError, match='布尔'):
            validate_entry_fields(entry, {1})

    def test_strength_out_of_range_rejected(self):
        entry = _valid_entry()
        entry['password_strength'] = 5
        with pytest.raises(BackupError, match='强度'):
            validate_entry_fields(entry, {1})

    def test_strength_negative_rejected(self):
        entry = _valid_entry()
        entry['password_strength'] = -1
        with pytest.raises(BackupError, match='强度'):
            validate_entry_fields(entry, {1})

    def test_invalid_entry_type_rejected(self):
        entry = _valid_entry()
        entry['entry_type'] = 'unknown'
        with pytest.raises(BackupError, match='类型'):
            validate_entry_fields(entry, {1})

    def test_unknown_category_reference_rejected(self):
        entry = _valid_entry(category_id=888)
        with pytest.raises(BackupError, match='分类'):
            validate_entry_fields(entry, {1})


class TestValidateEntryCustomFields:
    """自定义字段校验。"""

    def test_valid_passes(self):
        validate_entry_custom_fields([
            {'name': 'n1', 'value': 'v1', 'field_type': 'text'},
            {'name': 'n2', 'value': 'v2', 'field_type': 'password'},
        ])

    def test_too_many_rejected(self):
        fields = [
            {'name': f'f{i}', 'value': 'v', 'field_type': 'text'}
            for i in range(MAX_CUSTOM_FIELDS_PER_ENTRY + 1)
        ]
        with pytest.raises(BackupError, match='自定义字段'):
            validate_entry_custom_fields(fields)

    def test_non_list_rejected(self):
        with pytest.raises(BackupError, match='自定义字段'):
            validate_entry_custom_fields('not-a-list')

    def test_non_dict_item_rejected(self):
        with pytest.raises(BackupError, match='格式'):
            validate_entry_custom_fields(['x'])

    def test_missing_key_rejected(self):
        with pytest.raises(BackupError, match='不完整'):
            validate_entry_custom_fields([{'name': 'n', 'value': 'v'}])

    def test_bad_field_type_rejected(self):
        with pytest.raises(BackupError, match='类型'):
            validate_entry_custom_fields([
                {'name': 'n', 'value': 'v', 'field_type': 'secret'},
            ])


class TestValidateHistory:
    """密码历史校验。"""

    def test_valid_passes(self):
        validate_history([_valid_history(1)], {1})

    def test_non_dict_rejected(self):
        with pytest.raises(BackupError, match='格式'):
            validate_history(['x'], {1})

    def test_unknown_entry_reference_rejected(self):
        with pytest.raises(BackupError, match='不存在'):
            validate_history([_valid_history(999)], {1})

    def test_non_int_entry_id_rejected(self):
        h = _valid_history(1)
        h['entry_id'] = '1'
        with pytest.raises(BackupError, match='整数'):
            validate_history([h], {1})

    def test_missing_key_rejected(self):
        h = _valid_history(1)
        del h['changed_at']
        with pytest.raises(BackupError, match='不完整'):
            validate_history([h], {1})


class TestRequireKeys:
    """require_keys 多余/缺失键拒绝。"""

    def test_exact_match_passes(self):
        require_keys({'a': 1, 'b': 2}, {'a', 'b'}, '测试')

    def test_missing_key_rejected(self):
        with pytest.raises(BackupError, match='不完整'):
            require_keys({'a': 1}, {'a', 'b'}, '测试')

    def test_extra_key_rejected(self):
        with pytest.raises(BackupError, match='不完整'):
            require_keys({'a': 1, 'b': 2, 'c': 3}, {'a', 'b'}, '测试')


class TestRequireText:
    """require_text 字节/类型/空校验。"""

    def test_valid_string_passes(self):
        require_text('hello', '测试', 1024)

    def test_oversize_bytes_rejected(self):
        with pytest.raises(PayloadTooLargeError):
            require_text('x' * 100, '测试', 50)

    def test_non_string_rejected(self):
        with pytest.raises(BackupError, match='类型'):
            require_text(123, '测试', 50)

    def test_empty_allowed_by_default(self):
        require_text('', '测试', 50)

    def test_empty_rejected_when_disallowed(self):
        with pytest.raises(BackupError, match='不能为空'):
            require_text('   ', '测试', 50, allow_empty=False)


def test_history_limit_constant_matches_model():
    """守护 MAX_HISTORY_PER_ENTRY 与 MAX_PASSWORD_HISTORY 的 2 倍关系。"""
    assert MAX_HISTORY_PER_ENTRY == MAX_PASSWORD_HISTORY * 2


class TestEncryptedFieldsSingleSource:
    """守护 validate_entry_fields 对字符串型加密字段的长度校验来自单一事实源
    STRING_ENCRYPTED_FIELDS：新增加密字段时校验自动跟随，不漏字段。"""

    @pytest.mark.parametrize('field', list(STRING_ENCRYPTED_FIELDS))
    def test_each_encrypted_field_length_enforced(self, field):
        """每个字符串型加密字段超其精确上限均被拒绝，验证校验覆盖全部加密字段。

        若未来把新字段加入 SENSITIVE_ENCRYPTED_FIELDS，此处自动新增用例；若校验侧
        漏跟该字段，对应用例会因未抛 PayloadTooLargeError 而失败。
        """
        from src.business.services.backup_validator import _BACKUP_FIELD_LIMITS
        entry = _valid_entry()
        entry[field] = 'x' * (_BACKUP_FIELD_LIMITS[field] + 1)
        with pytest.raises(PayloadTooLargeError):
            validate_entry_fields(entry, {1})

    def test_encrypted_fields_subset_of_required_keys(self):
        """守护加载期断言的不变量：STRING_ENCRYPTED_FIELDS ⊆ REQUIRED_ENTRY_KEYS。

        缺失会使 require_text(item[field]) 因键不存在而 KeyError（而非静默跳过），
        模块加载期断言已强制此关系，此处冗余守护以在字段集演进时即时发现。
        """
        from src.business.services.backup_validator import REQUIRED_ENTRY_KEYS
        assert set(STRING_ENCRYPTED_FIELDS) <= REQUIRED_ENTRY_KEYS
