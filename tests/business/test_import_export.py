"""导入导出序列化测试。

覆盖 Entry 与 CustomField 的 JSON、CSV 序列化往返，以及
to_dict 在是否包含密码下的字段取舍。
"""

import csv
import json
from typing import cast

from src.models import CustomField, Entry, Sensitive
from tests.helpers import decrypt_all_entries


def test_entry_json_roundtrip(tmp_path):
    """条目 JSON 序列化与反序列化往返。"""
    entry = Entry(
        title="测试条目",
        username="user@example.com",
        password="MyP@ssw0rd",
        url="https://example.com",
        category_name="社交",
        tags="test,demo",
        notes="这是一条测试备注",
        custom_fields=[
            CustomField(name="API Key", value="sk-xxx", field_type="password"),
            CustomField(name="邮箱", value="test@test.com", field_type="email"),
        ],
        is_favorite=True,
        password_strength=3,
        created_at="2024-01-01T00:00:00",
        updated_at="2024-01-01T00:00:00",
    )

    d = entry.to_dict(include_password=True)
    assert d["title"] == "测试条目"
    assert d["password"] == "MyP@ssw0rd"
    assert len(d["custom_fields"]) == 2

    filepath = tmp_path / "entry.json"
    filepath.write_text(json.dumps({"entries": [d]}, ensure_ascii=False), encoding="utf-8")
    data = json.loads(filepath.read_text(encoding="utf-8"))

    restored = Entry.from_dict(data["entries"][0])
    assert restored.title == "测试条目"
    assert restored.username == "user@example.com"
    assert restored.password == "MyP@ssw0rd"
    assert len(restored.custom_fields) == 2
    assert cast(list[CustomField], restored.custom_fields)[0].name == "API Key"


def test_entry_csv_export(tmp_path):
    """条目 CSV 导出。"""
    entries = [
        Entry(title="Entry1", username="user1", password="pass1", url="https://a.com"),
        Entry(title="Entry2", username="user2", password="pass2", url="https://b.com"),
    ]

    filepath = tmp_path / "entries.csv"
    with filepath.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["title", "username", "password", "url"], extrasaction="ignore"
        )
        writer.writeheader()
        for e in entries:
            writer.writerow(e.to_dict(include_password=True))

    with filepath.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 2
    assert rows[0]["title"] == "Entry1"
    assert rows[1]["password"] == "pass2"


def test_export_without_password():
    """不含密码的导出应剔除 password 字段。"""
    entry = Entry(title="Test", username="u", password="secret")
    d = entry.to_dict(include_password=False)
    assert "password" not in d


def test_entry_export_excludes_secrets_by_default():
    """默认导出应排除密码等敏感字段。"""
    entry = Entry(title="Test", password="secret")
    assert "password" not in entry.to_dict()


def test_sanitize_url_scheme_rejects_dangerous_schemes():
    """url scheme 白名单：javascript:/data:/file: 清空，http/https/裸域名保留。

    覆盖全部导入路径（CSV/Chrome CSV/KeePass/JSON/Bitwarden 共享 _sanitize_url_scheme），
    防止恶意 scheme 被详情面板渲染为可点击链接导致钓鱼/协议注入。
    """
    from src.business.services.url_hygiene import sanitize_url_scheme as _sanitize_url_scheme

    assert _sanitize_url_scheme("javascript:alert(1)") == ""
    assert _sanitize_url_scheme("data:text/html,<script>") == ""
    assert _sanitize_url_scheme("file:///etc/passwd") == ""
    assert _sanitize_url_scheme("vbscript:msgbox") == ""
    assert _sanitize_url_scheme("http://example.com") == "http://example.com"
    assert _sanitize_url_scheme("https://example.com/path?q=1") == "https://example.com/path?q=1"
    assert _sanitize_url_scheme("ftp://ftp.example.com") == "ftp://ftp.example.com"
    assert _sanitize_url_scheme("ssh://user@host") == "ssh://user@host"
    assert _sanitize_url_scheme("mailto:a@b.com") == "mailto:a@b.com"
    # 空 scheme（裸域名/相对路径）保留，UI 点击按默认 http 处理
    assert _sanitize_url_scheme("example.com") == "example.com"
    assert _sanitize_url_scheme("/relative/path") == "/relative/path"
    assert _sanitize_url_scheme("") == ""
    # 大小写不敏感
    assert _sanitize_url_scheme("JavaScript:alert(1)") == ""
    assert _sanitize_url_scheme("HTTPS://x.com") == "HTTPS://x.com"


def test_sanitize_totp_secret_rejects_invalid():
    """totp_secret 清洗：无效 base32 或解码后过短清空，合法 secret 与 otpauth URI 保留。

    覆盖全部导入路径（CSV/KeePass/JSON/Bitwarden 共享 _sanitize_totp_secret），防止
    损坏密钥静默入库导致后续验证码生成失败且用户无反馈。
    """
    from src.business.managers.importers.base import _sanitize_totp_secret

    assert _sanitize_totp_secret("not-valid-base32!!!") == ""
    assert _sanitize_totp_secret("ABCD") == ""
    assert _sanitize_totp_secret("") == ""
    assert _sanitize_totp_secret("GEZDGNBVGY3TQOJQ") == "GEZDGNBVGY3TQOJQ"
    otpauth = "otpauth://totp/Example:alice@google.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example"
    assert _sanitize_totp_secret(otpauth) == otpauth


def test_custom_field_serialization():
    """自定义字段序列化与反序列化往返。"""
    cf = CustomField(name="test", value="val", field_type="password")
    d = cf.to_dict()
    assert d["name"] == "test"
    assert d["field_type"] == "password"

    restored = CustomField.from_dict(d)
    assert restored.name == "test"
    assert restored.value == "val"


def test_sensitive_representations_are_redacted():
    secret = "TopSecret!2026"
    entry = Entry(
        title="Account",
        password=Sensitive(secret),
        notes=secret,
        custom_fields=[CustomField("api_key", secret, "password")],
    )

    assert secret not in repr(Sensitive(secret))
    assert secret not in repr(entry)
    assert secret not in repr(entry.custom_fields[0])


def test_import_from_bitwarden_json_sanitizes_url_and_totp(entry_mgr, tmp_path):
    """Bitwarden 导入清洗危险 url scheme 与无效 totp（与 CSV/JSON 路径一致）。

    回归 P2-1：此前 Bitwarden 路径遗漏 _sanitize_url_scheme / _sanitize_totp_secret，
    是唯一产出含 javascript: scheme 与无效 totp 条目的导入路径。
    """
    from src.business.managers.import_export import ImportExportManager

    mgr = ImportExportManager(entry_mgr)
    bw_path = tmp_path / "bitwarden.json"
    bw_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "name": "Danger",
                        "type": 1,
                        "login": {
                            "username": "alice",
                            "password": "Pass123!",
                            "uris": [{"uri": "javascript:alert(1)"}],
                            "totp": "not-valid-base32!!!",
                        },
                    },
                    {
                        "name": "Safe",
                        "type": 1,
                        "login": {
                            "username": "bob",
                            "password": "Secret456@",
                            "uris": [{"uri": "https://github.com"}],
                            "totp": "GEZDGNBVGY3TQOJQ",  # base32('1234567890')，10 字节合法 secret
                        },
                    },
                ],
                "folders": [],
            }
        ),
        encoding="utf-8",
    )

    count = mgr.import_file(str(bw_path), "bitwarden_json")

    assert count == 2
    by_title = {e.title: e for e in decrypt_all_entries(entry_mgr)}
    danger = by_title["Danger"]
    assert danger.url == ""  # javascript: scheme 已清空
    assert danger.totp_secret == ""  # 无效 base32 已清空
    safe = by_title["Safe"]
    assert safe.url == "https://github.com"
    assert safe.totp_secret == "GEZDGNBVGY3TQOJQ"


# ======== 导出确定进度（PERF-070）========


class TestExportWriteProgress:
    """export_to_json / export_to_csv 的写文件进度上报（PERF-070）。

    50k 条写文件实测 1.9s；progress 按已写条目数上报原始 ``(written, total)``
    计数，每 ``PROGRESS_REPORT_EVERY=100`` 条节流、终值恒上报。
    """

    ROWS = 250

    @staticmethod
    def _entries(rows: int) -> list[Entry]:
        return [Entry(title=f"E{i:04d}", username=f"u{i}", password=f"P{i}!x") for i in range(rows)]

    @staticmethod
    def _mgr():
        from unittest.mock import MagicMock

        from src.business.managers.import_export import ImportExportManager

        # 导出函数不触 entry_mgr（_csv_safe 为静态方法），mock 注入即可
        return ImportExportManager(MagicMock())

    def test_json_write_progress_throttled_final(self, tmp_path):
        """JSON 导出：250 条 → 3 次节流上报，终值 (250, 250)。"""
        events: list[tuple[int, int]] = []
        ok = self._mgr().export_to_json(
            str(tmp_path / "p.json"),
            self._entries(self.ROWS),
            include_password=True,
            progress=lambda done, total: events.append((done, total)),
        )
        assert ok is True
        assert events == [(100, 250), (200, 250), (250, 250)]

    def test_csv_write_progress_throttled_final(self, tmp_path):
        """CSV 导出：与 JSON 同款节流与终值语义。"""
        events: list[tuple[int, int]] = []
        ok = self._mgr().export_to_csv(
            str(tmp_path / "p.csv"),
            self._entries(self.ROWS),
            include_password=True,
            progress=lambda done, total: events.append((done, total)),
        )
        assert ok is True
        assert events == [(100, 250), (200, 250), (250, 250)]

    def test_empty_export_reports_final(self, tmp_path):
        """空导出上报单点 (0, 0)（UI 侧映射为 100，进度不留悬挂）。"""
        for writer in ("export_to_json", "export_to_csv"):
            events: list[tuple[int, int]] = []
            ok = getattr(self._mgr(), writer)(
                str(tmp_path / f"empty.{writer[-1]}"),
                [],
                include_password=False,
                progress=lambda done, total, sink=events: sink.append((done, total)),
            )
            assert ok is True
            assert events == [(0, 0)]


class TestExportPercentMappers:
    """导出两阶段百分比映射函数（PERF-070）：解密 0→70、写文件 70→100。"""

    def test_decrypt_percent(self):
        from src.business.managers.import_export import export_decrypt_percent

        assert export_decrypt_percent(0, 100) == 0
        assert export_decrypt_percent(50, 100) == 35
        assert export_decrypt_percent(100, 100) == 70
        # 空阶段取满（segment_progress 语义）：零条目直接到阶段终点
        assert export_decrypt_percent(0, 0) == 70

    def test_write_percent(self):
        from src.business.managers.import_export import export_write_percent

        assert export_write_percent(0, 100) == 70
        assert export_write_percent(50, 100) == 85
        assert export_write_percent(100, 100) == 100
        assert export_write_percent(0, 0) == 100

    def test_mappers_compose_monotonic(self):
        """两阶段映射拼接单调不减且终值 100（UI 进度条契约）。"""
        from src.business.managers.import_export import (
            export_decrypt_percent,
            export_write_percent,
        )

        values = [export_decrypt_percent(d, 250) for d in (100, 200, 250)]
        values += [export_write_percent(d, 250) for d in (100, 200, 250)]
        assert all(a <= b for a, b in zip(values, values[1:], strict=False))
        assert values[-1] == 100


class TestExportProgressSegmentTable:
    """导出进度段表契约（PERF-070 段刻度、MAINT-112 结构化收敛）。

    与导入段表（TestImportProgressSegmentTable）/恢复段表
    （TestRestoreProgressSegmentTable）同形态：相邻性由模块导入期
    RuntimeError 断言 + 本测试双重守护，后者在手改段表时给出可读的失败定位。
    """

    def test_segments_seamless_from_zero_to_total(self):
        """两段无缝：解密 0→70、写文件 70→100，尾段精确止于总刻度。"""
        from src.business.managers import import_export as ie_module

        cursor = 0
        marks = [cursor]
        for seg in ie_module._EXPORT_SEG:
            assert seg.base == cursor, f"段起点 {seg.base} 与上一段终点 {cursor} 有缝隙/重叠"
            assert seg.span > 0, "段跨度须为正（零跨度段不上报中间值）"
            cursor = seg.base + seg.span
            marks.append(cursor)
        assert marks == sorted(marks)
        # 尾段终点精确等于总刻度：导出完成即 write 段终点，无终值跳变
        assert cursor == ie_module._EXPORT_PROGRESS_TOTAL

    def test_segment_seams_anchor_profiled_weights(self):
        """段边界锚定 PERF-070 实测权重画像（解密 5.1s/写 1.9s ≈ 73/27 取整 70/30）。"""
        from src.business.managers import import_export as ie_module

        seg = ie_module._EXPORT_SEG
        assert (seg.decrypt.base, seg.decrypt.span) == (0, 70)
        assert (seg.write.base, seg.write.span) == (70, 30)
        # 两段共享边界 70：解密终点 == 写文件起点（阶段切换无跳变）
        assert seg.decrypt.base + seg.decrypt.span == seg.write.base
