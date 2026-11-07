---
id: defense-forensics-config-aes-key-iv-database-field-decrypt
title: 应用配置泄露 AES key/IV：离线解密数据库敏感字段（PbootCMS AES-128-CBC 实例）
type: scenario
domain: defense
path: defense/forensics
technique: config-aes-key-iv-database-field-decrypt
tags:
- forensics
- incident-response
- aes
- cbc
- config
- database
- pbootcms
- data-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:24:28+08:00'
  notes: 已对照原文 MISC3 与图10-13核对：PbootCMS 配置 aes key=2024DataSecurity、iv=2024、method=AES-128-CBC，密文 AwzqHMb3htntFHkwB4rDdJ3+y69ajMUZHiwRUGfk18E= 解出 31010119841012143X，与原文一致；未验证点：未对原始 SQLite 库复跑批量解密。
url: /docs/defense/forensics/defense-forensics-config-aes-key-iv-database-field-decrypt/
draft: false
kb_aliases:
- 配置文件 AES 解密
- 数据库字段解密
- PbootCMS AES 解密
- AES-128-CBC 零填充 IV
- 身份证号解密
- 硬编码密钥取证
---

## 一句话结论

应用常把数据库字段加密用的 AES key/IV 明文写进配置文件；一旦拿到配置与数据库（源码泄露、备份、WebShell 下载或主机镜像），即可离线按配置中的模式（本例 PbootCMS：`AES-128-CBC`、key=`2024DataSecurity`、IV=`2024` 补 `\0` 到 16 字节）对 Base64 密文解密并去 PKCS#7 填充，还原身份证号等敏感字段。

## 原理

- 字段级加密通常由业务代码在写入前 `openssl_encrypt(明文, method, key, 0, iv)`，把结果 Base64 后存库；读取时反向解密。配置文件为了让每个进程都能加解密，往往直接保存 `key`、`iv`、`method`。
- 对称加密的机密性完全取决于 key 的保密；配置文件与数据库经常一起出现在同一份泄露物料中（源码仓库、备份包、Web 目录、WebShell 下载、磁盘镜像），所以拿到其中任意一个都可能同时拿到 key 和密文，从而离线解密。
- IV 长度必须等于分组长度（AES 为 16 字节）。示例配置里 `'iv' => '2024'` 只有 4 字节，代码通常用 `str_pad($iv, 16, "\0")` 或 `ljust(16, b'\0')` 补零；解密时必须复现同样的补零方式，否则首块会乱码（CBC 下首块错误只影响首块，后续块仍可解，但填充校验通常失败）。
- `AES-128-CBC` 需要 16 字节 key；key 为 24/32 字节时对应 AES-192/256。PKCS#7 填充在解密后必须去除；若明文长度恰好是块大小整数倍，填充为整块 16 字节。
- 为什么能解：加密是确定性的（固定 key/IV 下同一明文得到同一密文），且 key 没有被 KMS/硬件保护；一旦配置泄露，任何持有密文的人都能解密。字段值若为中文身份证号，解密结果长度/字符集/校验位可直接验证是否成功。

## 触发条件

- 获得应用配置文件（`config.php`、`.env`、`application.yml` 等），其中包含 `aes`/`key`/`iv`/`method` 等字段。
- 获得数据库文件或备份（SQLite 文件、MySQL dump），且目标字段存储的是 Base64/hex 密文。
- 知道或能从代码推断加密模式、填充方式与 IV 补零/截断规则。
- 仅用于授权取证与数据恢复；解密结果按敏感数据处置要求保管。

## 利用步骤

1. 在源码/配置中定位加密配置，记录 `key`、`iv`、`method`（如 `AES-128-CBC`）以及是否有 `str_pad`/`substr` 处理 IV。
2. 导出或打开数据库，找到疑似密文字段：值通常为 Base64 字符集、长度是 16 的倍数（Base64 后长度约 24/44/…），与明文格式（手机号/身份证号/地址）长度不符。
3. 按配置复现密钥长度与 IV：key 16/24/32 字节 → AES-128/192/256；IV 不足 16 字节补 `\0`，超过则截断（以代码为准）。
4. Base64 解码 → AES-CBC 解密 → 去 PKCS#7 填充；若解出乱码，先检查 IV、key 是否被 `md5`/`sha1` 处理过，或配置是否对应另一套环境。
5. 验证明文：身份证号应为 18 位（末位可为 X）、手机号 11 位、地址/姓名符合字符集；必要时用身份证校验位算法验证。
6. 统计泄露记录数、去重、按用户/时间排序；对同一配置下的其他表/字段批量解密。
7. 若数据库本身是 SQLCipher 等整库加密，先解库（见关联卡），再做字段级解密。

## PoC

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 来自应用配置
key = "2024DataSecurity".encode("utf-8")   # 16 字节 -> AES-128
iv = "2024".encode("utf-8").ljust(16, b"\0")  # 不足 16 字节补零

cipher_b64 = "AwzqHMb3htntFHkwB4rDdJ3+y69ajMUZHiwRUGfk18E="
plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(cipher_b64)), 16)
print(plain.decode("utf-8"))   # 31010119841012143X

# 批量：对数据库某字段的每个值重复上述步骤
```

说明：PoC 与原文脚本一致，未在本机对原始数据库复跑；实际 IV 补零/截断与填充方式必须按目标代码确认。

## 变体与关联

- **ECB 模式**：无 IV，同样 Base64 存储；直接 `AES.new(key, AES.MODE_ECB)` 解密，安全性与取证方式都更简单。
- **key 派生**：配置里可能是口令，代码用 `md5`/`sha256` 派生 16/32 字节 key；需按代码复现。
- **IV 随密文存储**：密文前 16 字节为随机 IV，Base64 解码后先切 IV 再解密；不要误用配置里的固定 IV。
- **整库加密**：SQLCipher/WCDB 等是页级 AES，需先从内存/配置取库密钥；见 [[defense-forensics-wcdb4-sqlcipher-offline-decrypt]]。
- **数据来源**：数据库可能是从冰蝎流量中外带的；见 [[defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode]]。
- 关联：[[defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery]]（从样本恢复 key/IV 的另一路径）、[[defense-forensics-java-rat-encrypted-config-h2-db]]（配置解密）。

## 检测与防御

- 防御：不要把长期密钥硬编码在 Web 根目录/源码中；使用 KMS/HSM/密钥管理服务，配置通过环境变量或密文注入；字段加密使用每记录随机 IV 与 AEAD（AES-GCM），避免 ECB。
- 加固：配置文件权限最小化，禁止 Web 直接访问 `.env`/`config.php` 备份；源码仓库与备份加密；定期轮换密钥。
- 检测：源码/配置扫描硬编码 `aes`/`key`/`iv`；数据库字段高熵 Base64 且长度固定；异常大批量读取敏感表的查询。
- 响应：确认泄露范围后轮换 key、重加密存量数据、通知受影响用户；保留原始数据库与配置作为证据，避免二次泄露。
