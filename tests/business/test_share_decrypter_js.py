"""share 解密器内联 JS 的 node 端到端跨语言 round-trip 测试。

价值锚点：真实跨语言解密。Python 侧经业务层 ``create_share_package`` 用**生产 KDF
参数**（Argon2id t3/64MiB/p4——解密器 JS 内置 KDF 参数下界校验会拒绝弱化参数，故本
文件刻意不做 test_share_package.py 那样的 KDF 弱化）生成 ``.cboxshare``，随包写出的
``decrypt.html`` 即 ``render_decrypter()`` 真实渲染产物；node 在最小 DOM stub 中执行
其内联解密 JS（hash-wasm Argon2id 派生 → HKDF-Expand 域分离 → asmcrypto
AES-256-GCM 解密 → 明文渲染进 DOM），完整驱动「选择文件→输入密码→点击解密」事件流。

Python 侧 round-trip（``tests/business/test_share_package.py``）测不了浏览器端 JS；
本文件填补该空档，守护 Python 打包端与 decrypter_template.html 内联 JS 之间的
隐式跨语言契约（头部布局/AAD/HKDF info/Argon2 参数映射）。本机无 node 时自动
skip（模块级 skipif 保证无 node 环境仍可正常收集）。
"""

import json
import shutil
import subprocess

import pytest

from src.business.services.share.package import EXPIRE_NEVER, create_share_package
from src.models import CustomField, Entry

NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node 不可用，跳过解密器 JS 端到端测试")

# 强共享密码：19 位四类字符，过 create_share_package 的 validate_master_password 兜底。
_PASSWORD = "JsRoundTrip-2026#Xq"

# node 驱动脚本：执行 decrypt.html 的三个内联 <script>（hash-wasm / asmcrypto / 解密器
# 主体），以 DOM stub 驱动事件流。退出码 0 = harness 正常完成（业务结果在 stdout JSON），
# 退出码 2 = harness 自身故障（区别于「解密失败」这一合法业务结果）。
_DRIVER_JS = r""""use strict";
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const htmlPath = process.argv[2];
const sharePath = process.argv[3];
const password = process.argv[4];

function die(msg) {
  console.error("DRIVER-ERROR: " + msg);
  process.exit(2);
}

if (!htmlPath || !sharePath || typeof password !== "string") {
  die("usage: node decrypter_driver.js <decrypt.html> <share.cboxshare> <password>");
}

const html = fs.readFileSync(htmlPath, "utf8");
const scripts = [];
const scriptRe = /<script>([\s\S]*?)<\/script>/g;
let match;
while ((match = scriptRe.exec(html)) !== null) scripts.push(match[1]);
if (scripts.length !== 3) {
  die("expected 3 inline <script> blocks, got " + scripts.length);
}

// ---- 最小 DOM stub：仅覆盖 decrypter_template.html 用到的 API 面 ----
function makeEl(id) {
  return {
    id: id,
    hidden: false,
    disabled: false,
    value: "",
    textContent: "",
    innerHTML: "",
    className: "",
    style: {},
    files: [],
    listeners: {},
    addEventListener: function (type, fn) {
      (this.listeners[type] = this.listeners[type] || []).push(fn);
    },
    removeEventListener: function () {},
    querySelectorAll: function () { return []; },
    getAttribute: function () { return null; },
    setAttribute: function () {},
    focus: function () {},
    select: function () {},
    classList: { contains: function () { return false; } },
  };
}
const elements = {};
function element(id) {
  return elements[id] || (elements[id] = makeEl(id));
}

const shareBytes = fs.readFileSync(sharePath);

const sandbox = {
  console: console,
  TextEncoder: TextEncoder, // vm 上下文无宿主全局，须显式注入
  TextDecoder: TextDecoder,
  Buffer: Buffer,
  navigator: {},
  // setTimeout 同步执行（模板回调为 fire-and-forget、无返回值；完成态经 DOM 状态轮询观察）
  setTimeout: function (fn, ms) { fn(); },
  clearTimeout: function () {},
  document: {
    getElementById: element,
    createElement: function () { return makeEl(); },
    body: makeEl("body"),
  },
};
sandbox.window = sandbox;
sandbox.self = sandbox;

const context = vm.createContext(sandbox);
try {
  for (const script of scripts) {
    vm.runInContext(script, context, { timeout: 60000 });
  }
} catch (err) {
  die("inline script eval failed: " + ((err && err.stack) || err));
}
if (!sandbox.hashwasm) die("hashwasm global not attached after eval");
if (!sandbox.asmCrypto) die("asmCrypto global not attached after eval");

function nextTick() {
  return new Promise(function (resolve) { setImmediate(resolve); });
}

// 轮询等待状态文案离开 busy 态（正在派生密钥…）。doDecrypt 为 async，其完成态
// 对外唯一可观察契约是 DOM 状态/明文渲染（真实浏览器用户视角一致）。
async function waitForDecryptDone(busyText, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (element("status").textContent === busyText) {
    if (Date.now() > deadline) return false;
    await nextTick();
  }
  await nextTick(); // 状态翻转同批微任务内的后续 DOM 写入（渲染/清空）也完成
  return true;
}

async function main() {
  // 1) 模拟选择 .cboxshare 文件（change → arrayBuffer → parseHeader）
  element("file-input").files = [{
    name: path.basename(sharePath),
    arrayBuffer: function () {
      return Promise.resolve(shareBytes.buffer.slice(
        shareBytes.byteOffset, shareBytes.byteOffset + shareBytes.byteLength));
    },
  }];
  for (const fn of element("file-input").listeners["change"] || []) {
    fn({ target: element("file-input") });
  }
  await nextTick();
  if (!element("status").textContent) die("no status text after file load");

  // 2) 输入密码并点击「解密」（onDecrypt 经 setTimeout 30ms 触发 doDecrypt）
  element("password").value = password;
  for (const fn of element("decrypt-btn").listeners["click"] || []) fn();
  const done = await waitForDecryptDone("正在派生密钥（Argon2id，约 1-2 秒）…", 60000);
  if (!done) die("decrypt did not finish within 60s (status stayed busy)");

  process.stdout.write(JSON.stringify({
    status: element("status").textContent,
    entriesHtml: element("entries").innerHTML,
    fileInfo: element("file-info").textContent,
  }));
}

main().catch(function (err) { die("driver failed: " + ((err && err.stack) || err)); });
"""


@pytest.fixture(scope="module")
def share_package(tmp_path_factory):
    """模块级创建一次真实共享包（生产 KDF，Argon2id 64MB 派生约秒级），供两个用例复用。"""
    entry = Entry(
        title="跨语言往返条目",
        username="js-user",
        password="JsSecret-77!",
        url="https://example.com/js",
        tags="js,roundtrip",
        notes="来自 node 解密器的备注",
        entry_type="login",
        totp_secret="JBSWY3DPEHPK3PXP",
        custom_fields=[CustomField("cf_text", "文本字段值", "text")],
    )
    out_dir = tmp_path_factory.mktemp("share_js_roundtrip")
    share_path, decrypter_path = create_share_package(
        [entry],
        _PASSWORD,
        include_secrets=True,
        expire_at=EXPIRE_NEVER,
        output_dir=str(out_dir),
    )
    return share_path, decrypter_path


def _run_decrypter(tmp_path, decrypter_path, share_path, password: str) -> dict:
    """写出 node 驱动并执行，返回 {status, entriesHtml, fileInfo}。"""
    driver = tmp_path / "decrypter_driver.js"
    driver.write_text(_DRIVER_JS, encoding="utf-8")
    proc = subprocess.run(
        [NODE, str(driver), str(decrypter_path), str(share_path), password],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, "node 驱动自身故障: " + proc.stderr.decode("utf-8", "replace")
    return json.loads(proc.stdout.decode("utf-8"))


class TestDecrypterJsRoundTrip:
    """浏览器解密器 JS 端到端：正确密码解密渲染、错误密码拒绝。"""

    def test_correct_password_decrypts_and_renders(self, share_package, tmp_path):
        """正确密码：Argon2id+HKDF+GCM 全链路在 JS 侧复现，明文完整渲染进 DOM。"""
        share_path, decrypter_path = share_package
        result = _run_decrypter(tmp_path, decrypter_path, share_path, _PASSWORD)

        assert result["status"] == "解密成功"
        html = result["entriesHtml"]
        assert "共 1 个条目" in html
        # 全字段明文断言：标题/账号/密码（data-reveal）/TOTP/网址/标签/备注/自定义字段
        for expected in (
            "跨语言往返条目",
            "js-user",
            "JsSecret-77!",
            "JBSWY3DPEHPK3PXP",
            "https://example.com/js",
            "js,roundtrip",
            "来自 node 解密器的备注",
            "文本字段值",
        ):
            assert expected in html, f"解密明文应包含 {expected!r}"
        assert result["fileInfo"].startswith("已加载：")

    def test_wrong_password_fails_without_leaking_plaintext(self, share_package, tmp_path):
        """错误密码：认证失败归一为固定错误文案，不向 DOM 泄漏任何明文。"""
        share_path, decrypter_path = share_package
        result = _run_decrypter(tmp_path, decrypter_path, share_path, "Wrong-Pwd-2026#z")

        assert result["status"] == "解密失败：密码错误或文件已损坏"
        assert result["entriesHtml"] == ""
        assert result["fileInfo"].startswith("已加载：")
