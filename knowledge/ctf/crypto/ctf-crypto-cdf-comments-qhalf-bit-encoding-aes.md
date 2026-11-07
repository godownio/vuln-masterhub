---
id: ctf-crypto-cdf-comments-qhalf-bit-encoding-aes
title: CDF 注释藏 Kyber 风格 u/v 块：q/2 偏移编码 bit 恢复 AES key 并解 CBC
type: scenario
domain: ctf
path: ctf/crypto
technique: cdf-comments-qhalf-bit-encoding-aes
aliases:
- lattice.cdf
- q=3329
- q/2 偏移
- 43 blocks
- AES key 128 bit
- Kyber 风格
- Can't have a salad without Lattice
tags:
- ctf
- crypto
- lattice
- kyber
- qhalf
- bit-encoding
- aes-cbc
- cdf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:08:02+08:00'
  notes: 已对照原文核对：q=3329、HALF=1665、5 种固定 u、43 block 共 129 bit、前 128 bit 为 AES key、Base64(IV||CBC) 与原文一致；未实际运行 PoC。
---

## 一句话结论

`lattice.cdf` 末尾注释有 `flag_enc` 与 43 组 `u/v`；数值范围 0~3328 提示 `q=3329`，每个固定 u 下每个 v 坐标只在 `base` 与 `base+1665 mod 3329` 两值间切换，按“base=1、shifted=0”提取 `43*3=129` bit，前 128 bit 组成 AES key `encryptionkey123`，解 Base64(IV||CBC 密文)。

## 原理

- **q/2 偏移编码 bit**：`q=3329`，`(q+1)//2=1665`；每维两个可能值满足 `a+1665 ≡ b (mod 3329)`，即一个 base 一个 shifted。不能按数值大小判断，因为模回绕会让小数成为 shifted（如 `1672+1665≡8`）。
- **固定 u 分组**：43 组里只有 5 种固定 u；同一 u 下每个坐标的两个值集合固定，可先统计集合再判定 base/shifted。
- **bit 规则**：本题 `值==base -> 1`、`值==shifted -> 0`；129 bit 中前 128 bit 为 AES key，最后 1 bit 是填充。
- **AES-CBC**：`flag_enc` Base64 解码后 48 字节 = 16 字节 IV + 32 字节密文；用恢复的 16 字节 key 做 AES-CBC 解密并去 PKCS#7 padding。

## 触发条件

- 文件（CDF/文本/注释）含 u/v 数值块与 Base64 密文。
- 数值范围可推断模数 q；每维只有两个值；存在 q/2 关系。
- 密文格式为 IV+密文，算法/key 长度可从上下文推断。

## 利用步骤

1. 把 `.cdf` 当文本打开，正则提取 `flag_enc` 与所有 `Block i: u=[...] v=[...]`。
2. 按 u 分组，收集每维出现的值集合；确认每维恰好两个值。
3. 判断 `(a+HALF)%q==b` 或 `(b+HALF)%q==a`，确定 base/shifted。
4. 按 block 顺序、每 block 3 维提取 bit；取前 128 bit，每 8 bit 转字节得 key。
5. Base64 解 `flag_enc`，前 16 字节为 IV，其余为密文；AES-CBC 解密，去 padding。

## PoC

```python
import re, base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

q, HALF = 3329, (3329 + 1) // 2
text = Path("lattice.cdf").read_text(encoding="latin1")
flag_enc = re.search(r"\(\* flag_enc = ([A-Za-z0-9+/=]+) \*\)", text).group(1)
pat = re.compile(r"\(\* Block (\d+): \*\)\s*\(\* u = \[(.*?)\] \*\)\s*\(\* v = \[(.*?)\] \*\)", re.S)
blocks = [(tuple(map(int, u.split(","))), tuple(map(int, v.split(",")))) for _, u, v in pat.findall(text)]

by_u = {}
for u, v in blocks:
    by_u.setdefault(u, [set(), set(), set()])
    for i in range(3): by_u[u][i].add(v[i])

mapping = {}
for u, cols in by_u.items():
    mapping[u] = []
    for s in cols:
        a, b = list(s)
        base, shifted = (a, b) if (a + HALF) % q == b else (b, a)
        mapping[u].append((base, shifted))

bits = [1 if v[i] == mapping[u][i][0] else 0 for u, v in blocks for i in range(3)]
key = bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, 128, 8))
data = base64.b64decode(flag_enc)
pt = Cipher(algorithms.AES(key), modes.CBC(data[:16])).decryptor().update(data[16:])
print(pt[:-pt[-1]].decode())
```

## 变体与关联

- **参数变体**：q 不同（如 7681、12289）、HALF 取 `q//2`、bit 规则反转、每维多于两个值（多 bit）。
- **结构变体**：u 随机、v 带 LWE 误差、需要先做格约减/最近平面；密文可能是 AES-GCM/ChaCha20。
- **载体变体**：CDF/PDF/图片注释/日志中的数值块；密文可能在文件尾/元数据。
- **关联卡片**：[[crypto-implementation-small-lwe-secret-bruteforce-aes-key]]（小 LWE 暴力）、[[ctf-crypto-dilithium-like-exact-t-as-linear-system-secret-recovery]]（格签名线性系统）、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（LWE 格攻击）。
- **边界**：若每维取值集合不唯一或 q 推断错误，bit 提取全错；若 AES key 不是 128 bit，需按实际长度截取。

## 检测与防御

- **CTF/验证**：先确认每维恰好两个值且满足 q/2 关系，再用 key 解密后检查 padding 与 flag 格式。
- **防御**：不要用固定 u/低熵 toy lattice 方案；密钥派生用 KDF；文件注释/元数据不要放密文或密钥材料。
- **检测信号**：CDF/文档注释中出现大量 `u=[...] v=[...]` 数值块；数值集中在 0~q-1 且成对出现；Base64 密文长度符合 IV+块。
