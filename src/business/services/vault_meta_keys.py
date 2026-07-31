"""vault_meta 表键名的单一事实源。

unlock 批量读取（``VaultLifecycleOrchestrator``）与 vault_meta 完整性签名覆盖的
键集（``MetadataSigner`` / ``VaultMetaStore``）均由此派生，消除原先
``vault_lifecycle._VAULT_META_KEYS`` 与 ``metadata_signer.VAULT_META_SIGNED_KEYS``
两处手工维护键集的漂移风险——漏键会致写入即签错、下次 unlock 比对失败。

设计：``VAULT_META_ALL_KEYS`` 为完整键序列（单一源），``VAULT_META_SIGNED_KEYS``
由其剔除 ``master_kdf``（KDF 算法名，仅信息性，派生正确性已由 verify 保证）与
``vault_meta_mac``（签名不能包含自身）派生。MAC 载荷经 ``sort_keys=True`` 规范化，
故 SIGNED 的元组顺序不影响签名结果，但保留与 ALL 一致的相对顺序以利阅读。
"""

# unlock 单次批量读取的全部 vault_meta 键（顺序固定，供 get_meta_batch 单次查询
# 避免多次独立 DB 锁获取）。新增 vault_meta 键须在此登记，使 unlock 与签名同步覆盖。
VAULT_META_ALL_KEYS: tuple[str, ...] = (
    'master_salt', 'master_verify',
    'master_kdf_time_cost', 'master_kdf_memory_cost', 'master_kdf_parallelism',
    'master_kdf', 'ciphertext_format', 'key_epoch',
    'snapshot_key_enc', 'vault_meta_mac',
)

# 完整性签名不覆盖的键：master_kdf 为算法名（信息性），vault_meta_mac 不能签自身。
_META_UNSIGNED_KEYS = frozenset({'master_kdf', 'vault_meta_mac'})

# vault_meta 完整性签名覆盖的安全相关键（密码派生与密钥版本元数据）。含
# snapshot_key_enc：虽由主密钥加密保护，但 GCM 用常量 AAD 不防重放——有 DB 写权限
# 者可用旧有效密文替换而绕过；纳入签名后此类回滚/重放使 mac 失配而被 unlock 拒绝。
VAULT_META_SIGNED_KEYS: tuple[str, ...] = tuple(
    k for k in VAULT_META_ALL_KEYS if k not in _META_UNSIGNED_KEYS
)
