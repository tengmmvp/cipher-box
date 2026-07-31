"""vault_meta 表键名的单一事实源。

unlock 批量读取与完整性签名覆盖的键集均由此派生，消除两处手工维护键集的漂移
风险——漏键会致写入即签错、下次 unlock 比对失败。

设计：``VAULT_META_ALL_KEYS`` 为完整键序列，``VAULT_META_SIGNED_KEYS`` 由其剔除
``master_kdf``（算法名，信息性，派生正确性由 verify 保证）与 ``vault_meta_mac``
（签名不能含自身）派生。MAC 载荷经 ``sort_keys=True`` 规范化，故 SIGNED 顺序不
影响签名，保留与 ALL 一致的相对顺序以利阅读。
"""

# unlock 单次批量读取的全部 vault_meta 键（顺序固定供单次查询）。新增键须在此登记，
# 使 unlock 与签名同步覆盖。
VAULT_META_ALL_KEYS: tuple[str, ...] = (
    'master_salt', 'master_verify',
    'master_kdf_time_cost', 'master_kdf_memory_cost', 'master_kdf_parallelism',
    'master_kdf', 'ciphertext_format', 'key_epoch',
    'snapshot_key_enc', 'vault_meta_mac',
)

# 完整性签名不覆盖的键：master_kdf 为算法名（信息性），vault_meta_mac 不能签自身。
_META_UNSIGNED_KEYS = frozenset({'master_kdf', 'vault_meta_mac'})

# 完整性签名覆盖的安全相关键。含 snapshot_key_enc：虽加密保护但 GCM 用常量 AAD 不
# 防重放，有 DB 写权限者可用旧密文替换；纳入签名后回滚/重放使 mac 失配被 unlock 拒绝。
VAULT_META_SIGNED_KEYS: tuple[str, ...] = tuple(
    k for k in VAULT_META_ALL_KEYS if k not in _META_UNSIGNED_KEYS
)
