"""常量时间 MAC/签名比较的共享单一入口（str 形态，SEC-071 演进）。

``hmac.compare_digest`` 对 ``str`` 仅接受 ASCII：任一侧非 ASCII 即抛 ``TypeError``。
MAC/签名的期望值恒为本机 ``hexdigest()`` 产物（ASCII），但存储侧值来自磁盘文件
（config.json 签名行 / 限流状态文件签名行）或数据库行（entries.metadata_mac /
vault_meta.vault_meta_mac），可被篡改为非 ASCII。各站点此前各自为战：config 与
rate_limiter 内联 isascii 守卫（两份手抄），vault_lifecycle 与 metadata_signer
漏守卫——漏守卫站点的 ``TypeError`` 落入通用 except 被误分类为系统错误、篡改
告警被抑制，或直接逃出调用方 ``except VaultIntegrityError`` 的捕获面。比较器
统一前置守卫；全部 MAC 比较站点须经此入口，不得在 call-site 内联展开（纪律
先例：PasswordService.passwords_match 的 SEC-031）。

纪律豁免（QL-081）：本入口面向 str 形态的 MAC/签名比较；bytes 形态的摘要比较
（如 ``src/ui/utils/clipboard`` 的哈希比对）无非 ASCII ``TypeError`` 风险，直接
使用 ``hmac.compare_digest`` 属有意豁免。
"""

import hmac


def constant_time_mac_equals(stored: str, expected: str) -> bool:
    """常量时间比较存储侧 MAC/签名与本地重算的期望值，相等返回 True。

    非 ASCII ``stored`` 短路返回 False 而非抛 ``TypeError``：``isascii`` 判定
    本身非常量时间，但该分支的结论与后续比较结果同为「必不相等」——期望值恒为
    ASCII hexdigest，非 ASCII 存储值在任何密钥/载荷下都不可能相等，分支结论不
    随密文内容变化，无时序泄露意义（SEC-071）。

    Args:
        stored: 存储侧签名（来自磁盘文件或数据库行，可被篡改为非 ASCII）。
        expected: 本地重算的期望签名。契约恒为 ``hexdigest()`` 产物（ASCII）——
            传入非 ASCII 期望值属编程错误，``TypeError`` 响亮失败不做兜底。
    """
    if not stored.isascii():
        return False
    return hmac.compare_digest(stored, expected)
