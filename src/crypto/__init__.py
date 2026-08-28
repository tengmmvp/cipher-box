"""密码学原语层：AES-256-GCM 加解密、Argon2id 主密钥派生、密码生成、TOTP。

本层为纯密码学原语，不依赖数据库或 UI。核心类：``encryption.EncryptionEngine``、
``master_key.MasterKeyManager``、``password_generator.PasswordGenerator``、
``totp.TOTPGenerator``（MAINT-085：原集中 re-export 零消费方——全部调用方走子模块
全路径导入，无人经 ``from src.crypto import X``；无检查守护的声明面随时间必然
漂移，故删除，消费方导入路径不变）。
"""
