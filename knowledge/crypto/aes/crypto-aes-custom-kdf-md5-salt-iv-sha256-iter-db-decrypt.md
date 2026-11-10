---
id: crypto-aes-custom-kdf-md5-salt-iv-sha256-iter-db-decrypt
title: 复现自建 KDF 解 AES-128-CBC 数据库密文：md5(pass+saltseed/IVseed) 作 salt/IV、SHA-256 迭代 10000 派生 key
type: scenario
domain: crypto
path: crypto/aes
technique: custom-kdf-md5-salt-iv-sha256-iterations-aes-cbc-db-decrypt
aliases:
- aesweblog
- aes128 数据库解密
- 自建 KDF
- md5 saltseed IVseed
- SHA256 迭代 10000
- 密钥派生复现
- flag 倒序存储
tags:
- crypto
- aes
- cbc
- kdf
- sha256
- md5
- database
- decryption
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V364-fix
  verified_at: '2026-11-09T04:08:56+08:00'
  notes: V364 核对指出 flag 行序错误：建库脚本 count 递减，flag1 是最后一行（LIMIT 23,1），flag6 是倒数第 6 行（LIMIT 18,1），原卡一句话结论误写 flag6 在前 6 行。已修正一句话结论与倒序插入段为倒数第 6 行。其余 KDF/PoC（salt=MD5(pass+saltseed)、iv=MD5(pass+IVseed)、SHA256×10000 取前16、AES-128-CBC+PKCS7）核对不变。
---

## 一句话结论

当应用把敏感字段用 AES-128-CBC 加密后存库、并提供建库/写入脚本时，按脚本复现 KDF 即可离线解密：`salt = MD5(passphrase + "saltseed")`、`iv = MD5(passphrase + "IVseed")`，密钥由 `SHA-256` 连续迭代 10000 次（每轮把上一轮 digest 作为下一轮输入）取前 16 字节；拿到 secrets 表的 passphrase 和 user_flag 表的 Base64 密文后，用同一 KDF + AES-CBC + PKCS#7 去填充还原明文。注意脚本倒序插入（count 递减），flag1 是最后一行、flag6 是倒数第 6 行，需要按 `LIMIT 23,1` / `LIMIT 18,1` 这类倒序行号定位。

## 原理

- **字段加密与 KDF**：应用用 `passphrase` 派生 AES key/IV/salt，避免在数据库里直接存密钥；只要 passphrase 与密文都能从库中取出，且派生算法公开在脚本里，就能离线重建全部参数解密密文。
- **本题 KDF 细节**：
  - `salt = MD5(passphrase_utf8 + b"saltseed").digest()`（16 字节）
  - `iv = MD5(passphrase_utf8 + b"IVseed").digest()`（16 字节）
  - `key = SHA256` 连续迭代 10000 次后取前 16 字节：`h = SHA256(); u = passphrase + salt; for _ in range(10000): h.update(u); u = h.digest(); key = h.digest()[:16]`
  - 加密算法 `AES-128-CBC`，密文 Base64 存入 `user_flag.flagvalue`，note 字段明确写 “encrypted with aes128, associated key, iv & salt are derived from passphrase”。
- **为什么必须完全复现**：salt/IV 不是随机存储而是由 passphrase 与固定字符串派生，迭代次数、更新顺序（先 update 再 digest）、截断长度都影响结果；任何一步偏差都会导致首块乱码或 padding 校验失败。
- **倒序插入**：建库脚本从 `count = len(usernames)` 开始，每插一条 `count -= 1`，因此 `flag{count}` 编号与插入顺序相反：编号最大的 flag 对应表里最靠前的行，flag1 在最后一行、flag6 是倒数第 6 行。盲注/查询时要按倒序行号取（`LIMIT 23,1` 取第 24 行即最后一行；`LIMIT 18,1` 取倒数第 6 行）。
- **数据获取**：secrets 表的 passphrase 与 user_flag 表的密文可经布尔盲注二分逐字符取出（响应长度/状态差异作 oracle，参考关联卡片）；拿到 passphrase 与 Base64 密文后即可本地解密。
- **flag 组装**：本题只取 flag1 与 flag6 两段，拼成完整 flag；中间 flag 不影响最终结果。

## 触发条件

- 拿到应用的建库/写库脚本（或等价代码），能复现 KDF 的全部参数（salt 串、IV 串、迭代次数、摘要/截断）。
- 能读取数据库中的 passphrase（secrets）与密文（user_flag），例如通过 SQL 注入、备份、镜像或源码泄漏。
- 密文为 Base64 + AES-CBC + PKCS#7 填充；passphrase 已知。
- 表数据可能乱序/倒序存储，需要按脚本的插入顺序或业务编号重建行序。

## 利用步骤

1. **读脚本确定 KDF**：找 `derive_key`/`md5_hash`/`AES.new` 等调用，记录 salt/IV 的固定串、迭代次数、digest 截断长度与模式。
2. **确定行序**：看插入循环是 `count++` 还是 `count--`；若是倒序，按业务编号（flag1、flag6）换算 SQL `LIMIT offset,1`。
3. **取 passphrase 与密文**：用已有注入/查询能力逐字符取 `secrets.passphrase` 与 `user_flag.flagvalue`（Base64）。
4. **复现 KDF**：按脚本用 `hashlib` 计算 salt、IV、key；注意 UTF-8 编码与字节拼接顺序。
5. **解密**：`base64.b64decode` → `AES.new(key, AES.MODE_CBC, iv).decrypt` → `unpad(..., 16)`；若 padding 失败，检查 IV/迭代/截断/行序。
6. **验证**：明文应匹配 `flag{...}` 格式；多段 flag 按题目要求拼接。

## PoC

```python
import base64, hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def derive_key(passphrase, salt, iterations, key_length):
    h = hashlib.sha256()
    u = passphrase.encode("utf-8") + salt
    for _ in range(iterations):
        h.update(u)
        u = h.digest()
    return h.digest()[:key_length]

def decrypt_data(passphrase, encrypted_data_b64):
    iterations = 10000
    key_length = 16
    salt = hashlib.md5(passphrase.encode("utf-8") + b"saltseed").digest()
    iv   = hashlib.md5(passphrase.encode("utf-8") + b"IVseed").digest()
    key  = derive_key(passphrase, salt, iterations, key_length)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = base64.b64decode(encrypted_data_b64)
    return unpad(cipher.decrypt(data), AES.block_size)

if __name__ == "__main__":
    import sys
    print(decrypt_data(sys.argv[1], sys.argv[2]))
```

运行示例（两段分别解密后拼接）：

```text
python3 decrypt.py 7xjo0DHFsoF1Jrus lTr01ZNX8R9xotVanrPtKiBjCfQD5U5dD+KLRPgjnQ4=
# b'flag1{...}'
python3 decrypt.py TJOC6+L+vTajLOGqfJMweoLFZqvJ PgH8ySWqsB1IJEradvOouNWEP5mpHZnu5e9ShkiS1LWLb81hRUjAZLD4zzzxO5Tn
# b'flag6{...}'
```

## 变体与关联

- **密钥在配置中**：若应用直接把 key/IV 写在配置文件，按配置解密即可，见 [[defense-forensics-config-aes-key-iv-database-field-decrypt]]。
- **标准 KDF**：PBKDF2/固定 salt/UID 派生等变体见 [[crypto-aes-pbkdf2-uid-fixed-salt-iv-mask-decrypt]]、[[crypto-aes-short-password-sha256-triple-cbc-bruteforce]]。
- **数据获取**：布尔盲注按响应长度/状态差异逐字符还原，见 [[web-generic-sqli-blind-log-pcap-response-length-recovery]]。
- **边界**：若 KDF 使用随机 salt 且 salt 也加密/未存储，则无法离线解密；若 passphrase 未获得，只能爆破（受迭代次数限制）。
- **行序陷阱**：倒序插入/自增编号混用时，按业务名称而不是物理行号取数据，避免取错 flag 段。

## 检测与防御

- **设计**：数据库字段加密的 key 应由 KMS/HSM 管理，salt 随机存储，避免“passphrase + 固定串”这类可复现 KDF；passphrase 不应以明文存库。
- **实现**：使用标准 KDF（PBKDF2/scrypt/Argon2）并保存随机 salt；迭代次数足够高，避免 SHA-256 手工迭代 10000 次这类弱构造。
- **审计**：检查建库/迁移脚本是否把密钥派生逻辑与 passphrase 一起入库；数据库账号最小权限，禁止应用账号读 secrets 表。
- **检测**：数据库中出现 Base64 长字段 + note 提示加密；异常大量二分查询 secrets/user_flag；同一 passphrase 被反复用于解密。
