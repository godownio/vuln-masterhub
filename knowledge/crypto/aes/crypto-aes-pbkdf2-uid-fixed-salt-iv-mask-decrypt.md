---
id: crypto-aes-pbkdf2-uid-fixed-salt-iv-mask-decrypt
title: 固定 salt/IV + PBKDF2(uid) 派生 AES key：批量还原脱敏数据
type: scenario
domain: crypto
path: crypto/aes
technique: pbkdf2-public-uid-fixed-salt-iv-aes-cbc-mask-decrypt
aliases:
- PBKDF2(uid) 派生密钥
- 固定 salt/IV AES-CBC
- 脱敏手机号还原
- 自定义字符映射 hex
- 批量解密 CSV
tags:
- crypto
- aes
- cbc
- pbkdf2
- fixed-iv
- key-derivation
- masking
- data-recovery
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:48:12+08:00'
  notes: 已对照原文代码与图06核对：固定 salt/固定 IV、PBKDF2(str(uid))、自定义字符映射、逐行解密 CSV，输出解密 flag；脚本未在本机运行
---

## 一句话结论

如果脱敏数据用 `AES-CBC(PBKDF2(str(uid), 固定 salt, 固定迭代次数), 固定 IV)` 加密，而 `uid` 是公开字段、salt/IV 又硬编码在程序里，那么拿到 CSV 和加密脚本的人可以对每条记录重新派生 key 并批量解密，所谓“脱敏”只是自定义字符映射加一层可复现的对称加密。

## 原理

- 示例代码使用：
  ```python
  _SALT = b"Hidden_Salt_Value"
  _IV   = b"Dynamic_IV_2026!"
  key = PBKDF2(str(uid).encode(), _SALT, dkLen=16, count=1000)
  cipher = AES.new(key, AES.MODE_CBC, _IV)
  plain = cipher.decrypt(bytes.fromhex(mask_to_hex(masked)))
  ```
- `uid` 不是秘密：它通常就在同一行 CSV 的 `user_id` 列，攻击者可以逐行读取。PBKDF2 的 salt 固定、迭代次数固定，因此同一 uid 每次派生出相同 key；`IV` 也固定，AES-CBC 变成确定性加密。
- `_MAP` 只是把 16 个字母映射成十六进制字符（`m→0, n→1, ..., y→F`），不是加密；把 masked 字段逐字符替换后 `bytes.fromhex` 即可得到密文。
- 由于 key 仅由公开 uid 和公开盐派生，攻击者不需要任何服务端密钥；对每一行用同样的 PBKDF2 参数与 AES-CBC 解密、去掉 PKCS#7 填充，即可还原明文（示例为手机号/flag）。
- 固定 IV 还会带来另一个问题：相同明文前缀在 CBC 下产生相同首块密文，可用于确认记录是否重复或猜测明文。
- 根因是把“可逆加密”当成“脱敏”，并让唯一秘密（salt/密钥）落在客户端可读的代码/数据里；真正的脱敏应使用不可逆哈希、令牌化，或服务端 KMS 管理的随机 per-record 密钥。

## 触发条件

- 拿到脱敏数据文件（CSV/JSON/数据库导出）以及加密/解密代码或可反编译的程序。
- 记录中包含公开的 `uid`/`user_id`，且 key 派生只依赖它和固定 salt/迭代次数。
- AES 使用 CBC（或 ECB/CTR 固定 nonce）且 IV 固定；密文以 hex/base64 或自定义字符映射存储。
- 代码中的 salt、IV、迭代次数、字符映射表可读；若 salt/IV 未知，需要额外泄露或暴力。

## 利用步骤

1. 从代码/二进制中提取 salt、IV、PBKDF2 迭代次数、PRF、AES 模式与字符映射表。
2. 读取数据文件，逐行取 `uid` 与 `masked` 字段；确认 `masked` 的字符集与映射表一致（示例只映射部分小写字母）。
3. 实现 `mask_to_hex`：按映射表逐字符替换，未命中的字符原样保留，再 `bytes.fromhex`。
4. 用 `PBKDF2(str(uid), salt, dkLen=16, count=..., prf=...)` 派生 key；注意不同库的默认 PRF 可能不同（PyCryptodome 默认 HMAC-SHA1），需按代码/输出验证。
5. `AES-CBC` 解密后按 PKCS#7 去填充；若填充不合法，检查 key 派生参数、IV、映射表或是否有多层编码。
6. 批量输出结果；用一条已知明文（如测试账号手机号）验证脚本，再处理全量数据。
7. 若数据还有一层 base64/hex/URL 编码，按实际格式解码后再解密。

## PoC

```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import csv

SALT = b"Hidden_Salt_Value"
IV = b"Dynamic_IV_2026!"
MAP = {
    'm': '0', 'n': '1', 'b': '2', 'v': '3',
    'c': '4', 'x': '5', 'z': '6', 'l': '7',
    'k': '8', 'j': '9', 'h': 'A', 'g': 'B',
    'f': 'C', 'd': 'D', 's': 'E', 'y': 'F',
}

def derive_key(uid: int) -> bytes:
    # 示例使用 PyCryptodome 默认 PBKDF2(HMAC-SHA1)，按目标代码确认 PRF
    return PBKDF2(str(uid).encode(), SALT, dkLen=16, count=1000)

def unpad(buf: bytes) -> bytes:
    return buf[:-buf[-1]] if buf and 0 < buf[-1] <= 16 else buf

def decode_mask(s: str) -> bytes:
    return bytes.fromhex(''.join(MAP.get(ch, ch) for ch in s))

def decrypt(masked: str, uid: int) -> str:
    key = derive_key(uid)
    pt = AES.new(key, AES.MODE_CBC, IV).decrypt(decode_mask(masked))
    return unpad(pt).decode('utf-8')

with open('user_data_masked.csv', encoding='utf-8') as fp:
    for row in csv.DictReader(fp):
        try:
            print(row['user_id'], decrypt(row['masked_phone'], int(row['user_id'])))
        except Exception as e:
            print(row['user_id'], 'ERROR', e)
```

## 变体与关联

- 变体：key 派生用 `MD5(uid)`、`SHA256(salt+uid)` 或直接 `uid` 作为 key；同样可复现，只需替换派生函数。
- 变体：AES 模式为 ECB 或 CTR 固定 nonce，确定性更强；CTR 下相同 key/nonce 的密文可直接异或恢复明文。
- 变体：salt/IV 不在代码中，而是固定字符串藏在配置文件、前端 JS 或日志里；先做源码/配置/日志搜索。
- 变体：多字段共用同一 uid 派生 key；一条记录解密成功后可批量套用。
- 关联卡片：[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定 key ECB 复现）、[[crypto-aes-cbc-known-key-constraint-plaintext-forgery]]（已知 key/IV 的 CBC 明文伪造）、[[crypto-aes-ctr-fixed-nonce-keystream-dek-unwrap]]（固定 nonce 的 CTR keystream）。
- 边界：如果 salt 随机且每条记录不同、IV 随机且随密文存储、key 由服务端 KMS 管理，则无法仅凭 CSV 解密；如果 PBKDF2 迭代次数很大但已知，仍可逐条计算，只是耗时。

## 检测与防御

- 检测：代码审计搜索 `PBKDF2`、`AES.MODE_CBC`、硬编码 `salt`/`iv`；检查导出数据是否包含 `user_id` 与密文两列。
- 修复：每条记录使用随机 salt 与随机 IV，并与密文一起存储；密钥由 KMS/HSM 管理，不放在客户端；使用 AES-GCM 等认证加密，避免可延展性。
- 加固：真正脱敏用不可逆哈希（带随机盐）或格式保留令牌化；对导出文件做访问控制、水印与审计；不要把“加密”当作“脱敏”。
- 边界：PBKDF2 的目的是增加暴力成本，不是让公开 uid 变成秘密；salt 固定时它无法阻止“知道 uid 就能派生 key”的问题。
