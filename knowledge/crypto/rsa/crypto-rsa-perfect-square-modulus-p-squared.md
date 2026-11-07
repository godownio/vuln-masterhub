---
id: crypto-rsa-perfect-square-modulus-p-squared
title: RSA 模数为完全平方 p²：φ=p(p−1) 直接求 d 并解密
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-perfect-square-modulus-p-squared
aliases:
- RSA n=p^2
- 模数完全平方
- phi(p^2)
- 单素数平方 RSA
- RSA 近素数
tags:
- rsa
- perfect-square
- factorization
- phi
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:36+08:00'
  notes: 已对照原文核对：n=p² 用 math.isqrt 直接开方、φ=p(p−1)、d=e^{-1} mod φ、m=c^d mod n、取明文末 16 字节作 AES key、AES-CBC 解 flag_ct、flag kashiCTF{wh3n_0n3_pr1m3_1s_n0t_3n0ugh_p_squared_1s_w0rs3} 均一致；卡片区分了完全平方与近素数 Fermat 场景。未验证点：无附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

RSA 模数 `n` 如果是某个素数的平方（`n = p²`），开平方即可得到 `p`，进而 `φ(n) = p(p−1)`、`d = e⁻¹ mod φ(n)`，无需分解大整数就能解密；原文还用解密明文的末 16 字节作为 AES key 解出 flag。

## 原理

- 正常 RSA 的 `n = p·q`（p≠q）；若生成代码错误地取 `p = q`，则 `n = p²`，`isqrt(n)` 直接得到 `p`。
- 欧拉函数 `φ(p²) = p² − p = p(p−1)`（p 为素数）；由 `ed ≡ 1 mod φ(n)` 求 `d`。
- 解密 `m = c^d mod n`；若明文被填充/拼接成固定长度，按 `n` 的字节长度转字节后取约定部分（原文取末 16 字节作为 AES key）。
- 为什么可行：完全平方是极弱的模数结构，开方成本可忽略；攻击者不需要分解 `n`，也不需要知道 `p` 以外的信息。
- 该场景常与“RSA 近素数”混淆：近素数需要 Fermat 分解（p、q 接近），而完全平方直接 `isqrt` 即可；先做 `isqrt(n)**2 == n` 检查。

## 触发条件

- 已知 `n, e` 与密文；`n` 为完全平方（`isqrt(n)` 的平方等于 n）。
- `n` 的平方根为素数（或至少 `φ` 计算正确）；`e` 与 `φ` 互素。
- 明文/密钥的编码方式已知（如固定长度、取末 16 字节、PKCS#1 v1.5 填充等）。

## 利用步骤

1. 对 `n` 做 `p = isqrt(n)`，检查 `p*p == n`；若是，确认 `p` 为素数（可选 Miller-Rabin）。
2. 计算 `φ = p*(p-1)`，`d = pow(e, -1, φ)`。
3. 对密文 `c` 计算 `m = pow(c, d, n)`，按 `n` 的字节长度转大端字节串。
4. 按题目约定解析明文：取末 16/32 字节作为 AES key、去掉 PKCS#1 v1.5 填充、或直接转文本。
5. 用得到的 key 解后续对称密文（AES-CBC/GCM），去填充得到 flag。
6. 若 `n` 不是完全平方，改试 Fermat 近素数、Pollard p−1、共模等路线。

## PoC

```python
import math, base64, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

n = int(re.search(r"n\s*=\s*0x([0-9a-fA-F]+)", open("output.txt").read()).group(1), 16)
e = int(re.search(r"e\s*=\s*(\d+)", open("output.txt").read()).group(1))
ct = int.from_bytes(base64.b64decode(re.search(r"ct\s*=\s*([A-Za-z0-9+/=]+)", open("output.txt").read()).group(1)), "big")

p = math.isqrt(n)
assert p * p == n
phi = p * (p - 1)
d = pow(e, -1, phi)
m = pow(ct, d, n)
klen = (n.bit_length() + 7) // 8
key = m.to_bytes(klen, "big")[-16:]

iv = base64.b64decode(re.search(r"iv\s*=\s*([A-Za-z0-9+/=]+)", open("output.txt").read()).group(1))
flag_ct = base64.b64decode(re.search(r"flag_ct\s*=\s*([A-Za-z0-9+/=]+)", open("output.txt").read()).group(1))
pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(flag_ct)
pad = pt[-1]
print(pt[:-pad].decode())
```

说明：PoC 为原文 exp 的结构化精简，未在本机执行；原文通过 `n=p²` 恢复 AES key，解出 `kashiCTF{wh3n_0n3_pr1m3_1s_n0t_3n0ugh_p_squared_1s_w0rs3}`。

## 变体与关联

- 变体（多素数平方）：`n = p²·q`、`n = p^e` 等，`φ` 公式不同；先做小指数/完全幂检测。
- 变体（近素数）：`p`、`q` 接近时用 Fermat 分解 `a=isqrt(n)+1` 递增找平方差。
- 变体（共享素因子）：多个模数两两 GCD；见关联卡。
- 关联：[[crypto-rsa-fermat-close-prime-factorization]]（近素数 Fermat）；[[crypto-rsa-shared-prime-batch-gcd]]（共享素因子）；[[crypto-rsa-wiener-small-private-exponent-large-e]]（小私钥）。
- 边界：`n` 不是完全平方、平方根不是素数、明文填充/编码未知时，需要换分解路线或补充信息。

## 检测与防御

- 检测：RSA 模数为完全平方、`p=q`、密钥生成日志中出现相同素数；`n` 的平方根为整数。
- 防御：使用标准 RSA 密钥生成库，确保 `p≠q` 且随机素数足够大；上线前校验 `n` 的分解结构、`p/q` 差值、`d` 大小。
- 加固：私钥使用 HSM/密钥管理；定期轮换；对异常模数（完全幂、共享因子）做批量扫描。
