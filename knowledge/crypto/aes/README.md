# AES

## 这层是什么

模式误用、IV、padding oracle、侧信道。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AES 密钥仅缺少量字节：已知前缀 + 24 位后缀爆破解密](crypto-aes-partial-key-suffix-bruteforce.md) | verified | high | 2026-11-06 |
| [AES-CBC 填充预言机：证书校验服务用两种错误响应逐字节恢复密文](crypto-aes-cbc-padding-oracle-certificate-service.md) | verified | high | 2026-11-06 |
| [AES-ECB 字节恢复 Oracle：可控前缀 + 固定隐藏后缀逐字节还原水印](crypto-aes-ecb-byte-at-a-time-hidden-suffix-oracle.md) | verified | high | 2026-11-06 |
| [AES-GCM nonce 复用：同 key/nonce 两段密文异或恢复目标明文](crypto-aes-gcm-nonce-reuse-keystream-xor.md) | verified | high | 2026-11-06 |
| [KMS 固定 nonce AES-CTR：import_dek(全零) 泄露 keystream 还原被包装 DEK](crypto-aes-ctr-fixed-nonce-keystream-dek-unwrap.md) | verified | high | 2026-11-06 |
| [三重 AES-CBC + sha256(3 字符) 密钥穷举：PKCS7 与 UUID 格式剪枝恢复 flag](crypto-aes-short-password-sha256-triple-cbc-bruteforce.md) | verified | medium | 2026-11-07 |
| [二进制内固定 key/明文的 AES-128 ECB 识别与密文复现](crypto-aes-fixed-key-ecb-ciphertext-reproduce.md) | verified | high | 2026-11-05 |
| [固定 salt/IV + PBKDF2(uid) 派生 AES key：批量还原脱敏数据](crypto-aes-pbkdf2-uid-fixed-salt-iv-mask-decrypt.md) | verified | high | 2026-11-06 |
| [已知 AES-CBC KEY/IV 的明文条件伪造：按约束构造明文再加密通过校验](crypto-aes-cbc-known-key-constraint-plaintext-forgery.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
