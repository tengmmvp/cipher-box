"""条目视图解密服务：密文 RawEntry → 明文视图 Entry 的纯变换（MAINT-021）。

从 EntryManager 下沉的视图解密族（同类先例：entry_batch_writer 下沉导入批量写入）。
三条解密链路各有完整性语义：

- :meth:`EntryViewDecryptor.decrypt_entry`（详情/编辑路径）：字段级容错，失败字段
  汇总到 ``integrity_message``，password/totp 包 :class:`Sensitive` 防明文进日志/repr；
- :meth:`EntryViewDecryptor.decrypt_entry_for_export`（导出路径）：严格语义，任一
  字段损坏立即抛 :class:`DecryptionError` 拒绝导出损坏数据；
- :meth:`EntryViewDecryptor.decrypt_summary`（列表摘要路径）：仅解密展示字段，
  复用摘要/分类名缓存，不让密码等明文进入列表模型。

职责边界：输入 raw + 密钥 + 缓存，输出 Entry——不触数据库事务、写路径、变更通知
（notify_*）与缓存失效决策（缓存只读取：摘要/分类名/失败字段集，失效由
EntryManager 与 EntryChangeBus 负责）。密钥经 vault 引用实时获取（与
EntryCacheManager 等子服务一致的注入面），并发安全由调用方在 ``epoch_guarded_read``
锁内快照 ``key`` 传入（PERF-001）。
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.entry_cache import EntryCacheManager, SearchMetadata
    from ..managers.vault_manager import VaultManager

from ...exceptions import DecryptionError, EntryIntegrityError
from ...models import CustomField, Entry, RawEntry, Sensitive
from .crypto_utils import (
    build_entry_summary,
    copy_entry_fields,
    decrypt_field as _decrypt_field_impl,
    decrypt_string_fields_strict,
    require_vault_key,
)

logger = logging.getLogger(__name__)

# 完整性失败字段→中文标签映射，构造 integrity_message 用。模块级常量避免重建。
_INTEGRITY_FIELD_LABELS: dict[str, str] = {
    "title": "标题",
    "username": "账号",
    "url": "URL",
    "tags": "标签",
    "category": "分类",
}


class EntryViewDecryptor:
    """条目视图解密器：详情/导出/摘要三条解密链路的纯变换子服务（MAINT-021）。"""

    def __init__(self, vault_manager: VaultManager, cache: EntryCacheManager):
        self._vault = vault_manager
        # 摘要/分类名/失败字段集缓存：仅读取，失效决策留在 EntryManager/EntryChangeBus。
        self._cache = cache

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def _decrypt_field(
        self,
        encrypted: str,
        crypto_id: str,
        field_name: str,
        strict: bool = False,
        *,
        key: bytes | None = None,
    ) -> str:
        """解密单个字段，委托给 crypto_utils.decrypt_field。

        ``key`` 为 PERF-001 并发修补（M3）：调用方在 ``epoch_guarded_read`` with 块内
        快照的主密钥，锁外解密期间改密 activate 后用快照而非实时 ``self._key`` 解密
        本批旧密文，避免旧密文+新密钥 GCM 认证失败。默认 None 用实时 ``self._key``，
        保持非并发调用方零改动。
        """
        return _decrypt_field_impl(
            encrypted,
            key if key is not None else self._key,
            crypto_id,
            field_name,
            strict=strict,
        )

    def _decrypt_custom_fields(
        self,
        encrypted: str,
        crypto_id: str,
        *,
        key: bytes | None = None,
    ) -> list[CustomField]:
        """解密自定义字段列表。

        密文通过 GCM 认证后内容仍可能损坏：``json.loads`` 失败或结构不符时抛
        :class:`EntryIntegrityError`（而非裸 ``ValueError``），可与 :class:`DecryptionError`
        一并精确捕获，避免外层 ``except ValueError`` 兜底吞掉无关 ValueError
        （DecryptionError 亦是 ValueError 子类）。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）。
        """
        if not encrypted:
            return []
        data = self._decrypt_field(
            encrypted,
            crypto_id,
            "custom_fields",
            strict=True,
            key=key,
        )
        try:
            items = json.loads(data)
        except ValueError as exc:
            # JSONDecodeError 是 ValueError 子类；归一为领域异常避免裸 ValueError 逃逸
            raise EntryIntegrityError("自定义字段内容损坏（非有效 JSON）") from exc
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise EntryIntegrityError("自定义字段结构无效")
        return [CustomField.from_dict(item) for item in items]

    def decrypt_entry(self, raw_entry: RawEntry, *, key: bytes | None = None) -> Entry:
        """解密条目的所有敏感字段，返回新的 Entry 对象（详情/编辑路径）。

        字段解密失败时容错：失败字段收集到 ``integrity_message``，password/totp
        包 :class:`Sensitive` 防明文意外进入日志/repr。title/username/url/tags
        复用列表摘要缓存避免重复解密。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）：锁外解密期间改密
        activate 后用快照而非实时 ``self._key`` 解密本批旧密文，避免 GCM 认证失败。
        """
        integrity_errors: list[str] = []
        if raw_entry.integrity_error:
            integrity_errors.append(raw_entry.integrity_message or "元数据")

        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
                key=key,
            )
        except (DecryptionError, EntryIntegrityError) as exc:
            # 精确捕获两类损坏（不吞其他异常），区分故障层记日志：DecryptionError=
            # 密文层损坏（GCM 认证失败/密钥问题）；EntryIntegrityError=结构层损坏
            # （已解密但内容损坏——非合法 JSON 或结构不符）。
            layer = "密文" if isinstance(exc, DecryptionError) else "结构"
            logger.warning(
                "条目 %s 自定义字段%s层损坏",
                raw_entry.crypto_id,
                layer,
            )
            integrity_errors.append("自定义字段")
            custom_fields = []

        cid = raw_entry.crypto_id
        password = Sensitive(
            self._decrypt_field_lenient(
                raw_entry.password,
                cid,
                "password",
                integrity_errors,
                key=key,
            )
        )
        totp_secret = Sensitive(
            self._decrypt_field_lenient(
                raw_entry.totp_secret,
                cid,
                "totp_secret",
                integrity_errors,
                key=key,
            )
        )

        # 分类名密文损坏时回退空串并记入完整性错误，与摘要路径 (decrypt_summary)
        # 对齐——避免详情面板因分类名解密失败而崩溃（上游 get_entry 未捕获 DecryptionError）。
        try:
            category_name = self._cache.decrypt_category_name(
                raw_entry.category_id,
                raw_entry.category_name,
                key=key,
            )
        except DecryptionError:
            category_name = ""
            integrity_errors.append("分类名")

        # detail 路径复用列表摘要缓存（title/username/url/tags 已解密），避免详情面板
        # 选中时重复解密这 4 字段；仅 notes/password/totp/custom_fields 需解密。摘要解密
        # 失败的字段经 get_failed_fields 取，按原容错语义（英文字段名）计入 integrity_errors。
        title, username, url, tags = self._cache.cached_search_metadata(raw_entry, key=key)
        failed = self._cache.get_failed_fields(cid)
        integrity_errors.extend(
            _INTEGRITY_FIELD_LABELS[name]
            for name in ("title", "username", "url", "tags")
            if name in failed
        )
        return copy_entry_fields(
            raw_entry,
            title=title,
            username=username,
            password=password,
            url=url,
            category_name=category_name,
            tags=tags,
            notes=self._decrypt_field_lenient(
                raw_entry.notes,
                cid,
                "notes",
                integrity_errors,
                key=key,
            ),
            custom_fields=custom_fields,
            totp_secret=totp_secret,
            integrity_error=bool(integrity_errors),
            integrity_message="、".join(dict.fromkeys(integrity_errors)),
        )

    def decrypt_entry_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool = False,
        *,
        key: bytes | None = None,
    ) -> Entry:
        """解密条目字段（导出路径）。

        任一完整性/解密失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据）；
        password/totp 返回明文（普通 str）供备份序列化。``include_secrets=False``
        时跳过 password/totp_secret 解密，默认 False 与 EntryManager 公开委托入口的
        安全默认对齐（避免内部入口默认解出密码，与公开 API 保守默认矛盾）。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）。
        """
        if raw_entry.integrity_error:
            raise DecryptionError(f"条目 {raw_entry.id} 元数据完整性校验失败，已拒绝导出")

        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
                key=key,
            )
        except (DecryptionError, EntryIntegrityError) as exc:
            layer = "密文" if isinstance(exc, DecryptionError) else "结构"
            logger.warning(
                "条目 %s 自定义字段%s层损坏",
                raw_entry.crypto_id,
                layer,
            )
            raise DecryptionError(f"条目 {raw_entry.id} 导出失败，数据可能已损坏") from None

        # 字符串加密字段统一经单一事实源解密（QL-018）：新增加密字段自动跟随，
        # 消除此前 7 处手工 _decrypt_field_strict 枚举的漏解密风险。
        fields = self._decrypt_string_fields_strict_for_export(
            raw_entry,
            include_secrets,
            key=key,
        )

        try:
            category_name = self._cache.decrypt_category_name(
                raw_entry.category_id,
                raw_entry.category_name,
                key=key,
            )
        except DecryptionError:
            raise DecryptionError(f"条目 {raw_entry.id} 导出失败，数据可能已损坏") from None

        return copy_entry_fields(
            raw_entry,
            title=fields["title"],
            username=fields["username"],
            password=fields["password"],
            url=fields["url"],
            category_name=category_name,
            tags=fields["tags"],
            notes=fields["notes"],
            custom_fields=custom_fields,
            totp_secret=fields["totp_secret"],
            integrity_error=False,
            integrity_message="",
        )

    def decrypt_summary(
        self,
        raw_entry: RawEntry,
        *,
        skip_epoch_check: bool = False,
        key: bytes | None = None,
        meta: SearchMetadata | None = None,
    ) -> Entry:
        """仅解密列表展示所需字段，不让密码等明文进入列表模型。

        title/username/url/tags 经统一摘要缓存复用，避免列表与搜索重复解密。
        摘要不包含 password/totp_secret/notes/custom_fields 等高敏字段；
        epoch 变化、锁定或条目更新时缓存立即失效。

        skip_epoch_check=True 跳过单条 epoch 校验，供批量循环路径复用——调用方
        须在循环外已调用缓存失效，避免每条目重复加锁。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）：锁外解密期间改密
        activate 后用快照而非实时 ``self._key`` 解密本批旧密文，避免 GCM 认证失败、
        错误摘要以新 epoch 写入缓存持续污染。

        ``meta``：调用方预取的完整 :class:`SearchMetadata`，提供则跳过内部缓存查询
        （搜索热路径一次取 meta 供摘要与小写匹配共用，PERF-016）。
        """
        if meta is not None:
            title, username, url, tags = meta.title, meta.username, meta.url, meta.tags
        else:
            title, username, url, tags = (
                self._cache.search_metadata_for_analysis(raw_entry, key=key)
                if skip_epoch_check
                else self._cache.cached_search_metadata(raw_entry, key=key)
            )
        # 失败字段集经 cache 锁内采样，避免与并发失效的 .clear() 竞态。
        failed = self._cache.get_failed_fields(raw_entry.crypto_id)
        summary = build_entry_summary(raw_entry, username)
        category_name = summary.category_name
        try:
            category_name = self._cache.decrypt_category_name(
                raw_entry.category_id,
                raw_entry.category_name,
                key=key,
            )
        except DecryptionError:
            # 解密失败时强制置空：summary.category_name 透传自 raw_entry.category_name，
            # 是 base64 密文——保留会把不可读的密文当作分类名显示给用户（信息泄漏）。
            category_name = ""
            failed = set(failed)
            failed.add("category")
        integrity_error = raw_entry.integrity_error or bool(failed)
        messages = []
        if raw_entry.integrity_error:
            messages.append(raw_entry.integrity_message or "元数据")
        messages.extend(_INTEGRITY_FIELD_LABELS[name] for name in failed)
        integrity_message = "、".join(dict.fromkeys(messages))
        return replace(
            summary,
            title=title,
            url=url,
            tags=tags,
            category_name=category_name,
            integrity_error=integrity_error,
            integrity_message=integrity_message,
        )

    def _decrypt_field_lenient(
        self,
        encrypted: str,
        crypto_id: str,
        name: str,
        errors: list[str],
        *,
        key: bytes | None = None,
    ) -> str:
        """详情路径字段级容错解密：失败记入 errors 返回空串。

        始终用 strict=True 解密以触发 GCM 认证，失败处置为本方法的容错语义。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）。
        """
        try:
            return self._decrypt_field(encrypted, crypto_id, name, strict=True, key=key)
        except DecryptionError:
            errors.append(name)
            return ""

    def _decrypt_string_fields_strict_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool,
        *,
        key: bytes | None = None,
    ) -> dict[str, str]:
        """导出路径的字符串加密字段统一解密（QL-018 单一事实源）。

        委托 :func:`crypto_utils.decrypt_string_fields_strict` 按
        STRING_ENCRYPTED_FIELDS 循环解密，消除手工逐字段枚举（新增加密字段不再
        静默漏解密）；失败统一包装为含条目 id 的 DecryptionError，拒绝导出损坏数据。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）。
        """
        try:
            return decrypt_string_fields_strict(
                raw_entry,
                key if key is not None else self._key,
                include_secrets=include_secrets,
            )
        except DecryptionError:
            raise DecryptionError(f"条目 {raw_entry.id} 导出失败，数据可能已损坏") from None
