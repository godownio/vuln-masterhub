---
id: defense-forensics-wcdb4-sqlcipher-offline-decrypt
title: 微信 4.x WCDB 数据库离线解密：AES-256-CBC + PBKDF2-HMAC-SHA512 256000 次，4096 页/80 reserve 并修复 SQLite 头
type: scenario
domain: defense
path: defense/forensics
technique: wcdb4-sqlcipher-offline-decrypt
aliases:
- 微信数据库解密
- WCDB 4.x 解密
- SQLCipher 4 页解密
- AES-256-CBC 聊天记录
- PBKDF2 256000
- page 4096 reserve 80
- SQLite format 3
- message_0.db
tags:
- forensics
- sqlcipher
- wcdb
- wechat
- aes-256-cbc
- pbkdf2
- sqlite
- decryption
cve: []
severity: medium
confidence: high
status: verified
affected_versions: WeChat 4.x（WCDB/SQLCipher 4，文章实测 4.1.8.67）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:30:33+08:00'
  notes: 已对照原文与截图核对：SQLCipher 4 AES-256-CBC+HMAC-SHA512、PBKDF2 256000、4096/80 reserve、首頁 salt 16 字节、第 1 页 [16:-80] 与其他页 [0:-80] 解密、补 SQLite 魔数与 80 零、dec[5:8]==40 20 20 指纹、7680 页解密成功均一致（卡片按原文代码而非其“每页前 16 字节”口误处理首页 salt）；affected_versions 已标 WeChat 4.x/4.1.8.67；未实际运行。
---

## 一句话结论

微信 4.x 的 WCDB 数据库是 SQLCipher 4 格式：AES-256-CBC 加密、HMAC-SHA512 防伪、PBKDF2-HMAC-SHA512 迭代 256000 次派生密钥，页大小 4096、每页尾部 reserve 80 字节（16 字节 IV + 64 字节 HMAC）；拿到 32 字节 raw key 后按页解密，删掉每页的 salt/reserve、给第 1 页补回 `SQLite format 3\0` 魔数，就能得到可被 sqlite3 直接打开的明文库。

## 原理

- WCDB 是微信的 SQLCipher 封装。SQLCipher 4 默认参数：AES-256-CBC 为主加密算法，HMAC-SHA512 做完整性校验，PBKDF2-HMAC-SHA512 迭代 256000 次从口令派生密钥；每个数据库有独立的 salt 和 enc_key。
- 数据库按 4096 字节分页。每页尾部保留 80 字节：前 16 字节是该页的 IV，后 64 字节是 HMAC-SHA512 标签。第 1 页最前面的 16 字节是 salt（对应内存中的 32 位 hex salt），不是密文；其余页从第 0 字节开始就是密文。
- 解密第 1 页：`iv = page[4096-80 : 4096-64]`，`ciphertext = page[16 : 4096-80]`，用 32 字节 raw key 做 AES-256-CBC 解密，得到 4000 字节明文。这 4000 字节对应原 SQLite 页的第 16 字节之后的内容，所以开头缺少 `SQLite format 3\0` 这 16 字节魔数。
- 解密其余页：`iv = page[4096-80 : 4096-64]`，`ciphertext = page[0 : 4096-80]`，解密得到 4016 字节。
- 组装明文库：第 1 页写 `b"SQLite format 3\x00" + dec_page1 + b"\x00"*80`；其余页写 `dec_page + b"\x00"*80`。补 80 个零是为了保持每页 4096 字节对齐；HMAC 标签在离线读取时不需要保留。
- 指纹校验：第 1 页解密结果 `dec_data` 的第 5~7 字节（即原 SQLite 头偏移 21~23）应为 `0x40 0x20 0x20`（最大/最小 payload 分数 64/32/32）。如果不对，说明 key、salt 或页参数不匹配。
- 文章直接用内存中提取的 64 位 hex enc_key（32 字节 raw key）作为 AES key，而不是用口令再跑 PBKDF2；如果只有口令，则需要按 SQLCipher 4 的 PBKDF2-HMAC-SHA512/256000 次派生，salt 取自数据库第 1 页前 16 字节。
- 根因是加密数据库的密钥/口令在客户端可获取；SQLCipher 本身是可靠的，但 raw key 缓存在内存、且数据库文件可被复制，离线解密就成为可能。

## 触发条件

- 已获得微信 4.x 的 WCDB 加密数据库文件（如 `message_0.db`）和对应的 32 字节 raw key（可从内存镜像提取，见关联卡片）。
- 目标数据库为 SQLCipher 4 格式（页大小 4096、reserve 80、AES-256-CBC）；SQLCipher 3 或自定义参数需要调整。
- 有可用的 AES-256-CBC 实现（如 Python `pycryptodome`、OpenSSL）或 SQLCipher 命令行工具。
- 分析已获授权，遵守隐私与合规要求。

## 利用步骤

1. 读取数据库第 1 页前 16 字节作为 salt，与内存扫描得到的候选 salt 比对，锁定正确的 raw key。
2. 按 4096 字节逐页读取数据库；第 1 页单独处理，其余页循环处理。
3. 第 1 页：取尾部 80 字节中的前 16 字节为 IV，取 `[16:-80]` 为密文，AES-256-CBC 解密；校验 `dec_data[5:8] == b"\x40\x20\x20"`。
4. 写出第 1 页：`SQLite format 3\0` + 解密结果 + 80 个零字节。
5. 其余页：取 `[-80:-64]` 为 IV、`[0:-80]` 为密文，解密后追加 80 个零字节。
6. 用 `file`/`sqlite3` 验证输出：应识别为 SQLite 3 数据库，`.tables` 可看到 `Msg_*`、`Name2Id`、`TimeStamp` 等表。
7. 对其它 WCDB 数据库（如联系人、媒体索引）重复同样流程；必要时用 sqlcipher CLI 的 `PRAGMA key = "x'<64hex>'"` 直接打开验证。

## PoC

```python
import os
from Crypto.Cipher import AES

DB_FILE = "message_0.db"
OUT_FILE = "message_0_decrypted.db"
PAGE_SIZE = 4096
RESERVE_SIZE = 80
RAW_KEY_HEX = "<64位hex enc_key>"   # 从内存镜像提取的 32 字节 raw key

raw_key = bytes.fromhex(RAW_KEY_HEX)

with open(DB_FILE, "rb") as f_in, open(OUT_FILE, "wb") as f_out:
    page1 = f_in.read(PAGE_SIZE)
    iv = page1[PAGE_SIZE - RESERVE_SIZE : PAGE_SIZE - RESERVE_SIZE + 16]
    enc = page1[16 : PAGE_SIZE - RESERVE_SIZE]
    dec = AES.new(raw_key, AES.MODE_CBC, iv).decrypt(enc)

    if dec[5:8] != b"\x40\x20\x20":
        raise SystemExit("指纹校验失败：key/salt/页参数不匹配")

    f_out.write(b"SQLite format 3\x00" + dec + b"\x00" * RESERVE_SIZE)

    while True:
        page = f_in.read(PAGE_SIZE)
        if not page:
            break
        iv = page[PAGE_SIZE - RESERVE_SIZE : PAGE_SIZE - RESERVE_SIZE + 16]
        enc = page[0 : PAGE_SIZE - RESERVE_SIZE]
        dec = AES.new(raw_key, AES.MODE_CBC, iv).decrypt(enc)
        f_out.write(dec + b"\x00" * RESERVE_SIZE)

print("done:", OUT_FILE)
```

验证：

```bash
file message_0_decrypted.db
# SQLite 3.x database ...
sqlite3 message_0_decrypted.db ".tables"
```

SQLCipher CLI 等价验证：

```text
PRAGMA key = "x'<64位hex enc_key>'";
.tables
```

## 变体与关联

- **SQLCipher 版本变体**：SQLCipher 3 的 KDF（PBKDF2-HMAC-SHA1）、迭代次数、页大小与 reserve 不同；SQLCipher 4 默认 4096/80/256000。必须按数据库头与版本调整参数。
- **密钥来源变体**：raw key（内存中的 64 位 hex enc_key）、口令（需 PBKDF2 派生）、DPAPI/凭据保险库封装（需先解封）。
- **文件变体**：`message_*.db`、联系人/朋友圈/媒体索引库、`-wal`/`-shm` 文件；WAL 中的页也需要按同样参数解密或先做 checkpoint。
- **工具变体**：手写 AES-CBC 分页解密、SQLCipher 命令行 `PRAGMA key`、sqlcipher Python 绑定、lovelymem 等自动化取证工具。
- **关联**：[[defense-forensics-wechat4-memory-image-key-extraction]]（从内存镜像提取 enc_key/salt）；[[defense-forensics-sqlcipher-im-db-memory-key-extraction]]（在线 `sqlite3_key` 断点 + SQLCipher DLL 解密）；[[defense-forensics-core-dump-secret-extraction]]（通用内存密钥提取）。
- **边界**：数据库使用非默认页参数、密钥被硬件封装且无法解封、或数据库文件不完整（缺少页）时，需要额外处理；仅用于授权取证。

## 检测与防御

- **检测**：对微信数据库文件的大量读取/复制、异常 AES-CBC 解密行为、生成 `*_decrypted.db`；内存镜像中出现 `x'<64hex><32hex>'` 特征。
- **防御**：客户端不要把 raw key 长期明文留在内存；使用 OS 凭据保险库/DPAPI、每用户派生密钥，使用后清零；数据库文件权限最小化，启用磁盘加密。
- **取证侧**：先做镜像再离线解密，保留原始文件哈希与解密日志；解密后的数据库只读保存，避免污染证据。
- **合规**：聊天记录属于个人通信数据，提取与解密需有明确授权与合法依据。
