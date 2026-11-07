---
id: crypto-ecc-ecdh-small-nonce-brute-shared-point-key
title: ECDH 小 nonce 暴力：从 R=kG 枚举 k，S=kQ 的 x 坐标 SHA256 派生 XOR 密钥
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdh-small-nonce-brute-shared-point-key
aliases:
- ECDH 小 nonce
- k 暴力
- R=kG
- 共享点 S=kQ
- S.x SHA256
- Excellent Crypto Challenge
tags:
- crypto
- ecc
- ecdh
- nonce
- brute-force
- xor
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:08:00+08:00'
  notes: 已对照原文核对：p=2^61-1、a=2、G=(5,1)、k=247439、S=kQ、sha256(str(S.x)) 派生 XOR 密钥与原文一致；未实际运行 PoC。
---

## 一句话结论

曲线参数 `p=2^61-1`、`a=2`、`G=(5,1)`，`R=kG` 中 `k` 只有 `247439`；枚举 `k` 使 `kG==R`，再算 `S=kQ`，取 `S.x` 的十进制字符串 SHA256 作为 XOR 密钥，即可解出两段密文。

## 原理

- **ECDH 共享点**：发送方用私钥 k 计算 `R=kG`，并用接收方公钥 Q 计算 `S=kQ`；接收方用私钥 d 计算 `S=dR`，双方共享 S。安全性依赖 k 的熵。
- **k 空间小**：题目中 k 只有 6 位十进制量级，直接线性枚举 `G, 2G, 3G, ...` 与 R 比较即可；EC 点加/倍乘用仿射坐标 + 模逆实现。
- **密钥派生**：`key = sha256(str(S[0]).encode()).digest()`，即取共享点 x 坐标的十进制字符串（不是字节）做 SHA256；两段密文用同一 keystream 循环 XOR。
- **为什么能解**：知道 k 就能算 S；S.x 是双方共享秘密，派生规则已知，XOR 可逆。

## 触发条件

- 已知曲线参数、G、接收方公钥 Q、发送方 `R=kG` 与密文。
- k 空间可枚举（小 nonce、低熵、部分泄露）。
- 密钥派生规则已知（S.x/S.y、哈希、HKDF）。
- 密文用流密钥/XOR 或可预测 keystream。

## 利用步骤

1. 实现 `ec_add`、`ec_mul`（模 p 逆元用 `pow(x,p-2,p)`）。
2. 从 1 开始累加 G，直到 `cur == R`，得到 k。
3. `S = ec_mul(k, Q)`；按题目规则取 `S[0]`（x 坐标）。
4. `key = sha256(str(S[0]).encode()).digest()`；对密文逐字节 `c ^ key[i % len(key)]`。
5. 检查明文是否为可打印文本/flag 格式；若规则用 S.y 或 compressed point，替换即可。

## PoC

```python
import hashlib

p, a, G = 2305843009213693951, 2, (5, 1)
Q = (1896662826602979990, 1425560687073180440)
R = (320761691192926716, 300507216662097367)
ct = bytes.fromhex("dcb9e7887358f88e5ba5c366b459f93889ed77a6")

def inv(x): return pow(x, p - 2, p)
def ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    lam = ((3*x1*x1 + a) * inv(2*y1 % p)) % p if P == Q else ((y2-y1) * inv((x2-x1) % p)) % p
    x3 = (lam*lam - x1 - x2) % p
    return (x3, (lam*(x1-x3) - y1) % p)
def ec_mul(n, P):
    R0, Q0 = None, P
    while n:
        if n & 1: R0 = ec_add(R0, Q0)
        Q0 = ec_add(Q0, Q0); n >>= 1
    return R0

cur, k = None, None
for i in range(1, 1_000_000):
    cur = ec_add(cur, G)
    if cur == R: k = i; break

S = ec_mul(k, Q)
key = hashlib.sha256(str(S[0]).encode()).digest()
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)))
```

## 变体与关联

- **nonce 变体**：k 由时间戳/计数器派生、k 部分比特泄露、k 重用；可用 HNP/格或直接枚举。
- **曲线变体**：Curve25519/Ed25519、NIST P-256、自定义小域曲线；点加公式与压缩格式不同。
- **派生变体**：S.x 字节串、S.y、`sha256(str(S))`、HKDF、AES-GCM key；密文可能是 AES-CBC/CTR 而非 XOR。
- **关联卡片**：[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]（ECDSA nonce 复用）、[[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]（ECDLP）、[[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]（部分 nonce 泄露）。
- **边界**：若 k 是 128 位以上随机数，枚举不可行；若派生规则未知，需要从上下文推断。

## 检测与防御

- **CTF/验证**：先确认 `kG==R`，再用 `S=kQ` 与接收方 `dR` 对比应一致；明文应符合 flag/业务格式。
- **防御**：使用 CSPRNG 生成 nonce；优先 X25519/Ed25519；密钥派生用 HKDF 并绑定上下文；不要用低熵 k 或时间戳。
- **检测信号**：R 点在不同会话重复/可预测；密文长度短且用 XOR；曲线参数异常小（p 约 61 位）。
