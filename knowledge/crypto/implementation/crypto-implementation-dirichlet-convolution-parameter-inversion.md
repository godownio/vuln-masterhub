---
id: crypto-implementation-dirichlet-convolution-parameter-inversion
title: 加权狄利克雷前缀和隐藏参数：h(n)=Σ d·w(d) 的递推反演还原密钥流
type: scenario
domain: crypto
path: crypto/implementation
technique: dirichlet-convolution-parameter-inversion
aliases:
- MobiusGuard
- 狄利克雷卷积反演
- 加权前缀和参数恢复
- h(n)=sum d*w(d)
- 数论函数隐藏密钥
- 递推求 w(k)
tags:
- crypto
- number-theory
- dirichlet-convolution
- parameter-recovery
- key-derivation
- stream-cipher
- xor
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:27+08:00'
  notes: 对照 Crypto470：h(n)=Σ d·w(d)、递推反演、w 大端拼接 SHA-256 流密码一致；w 字节编码宽度原文未明示
---

## 一句话结论

服务用 `h(n)=Σ_{d|n} d·w(d) mod p` 隐藏权重 w，但该变换是下三角的：按 k 从小到大用 `w(k)=(h(k)-Σ_{d|k,d<k} d·w(d))·k^{-1} mod p` 即可逐个还原全部 w，再把 w 按大端拼接做 SHA-256 得到流密码密钥，异或解密 flag。

## 原理

- 对每个 n，`h(n)` 只依赖 n 的因子 d 上的 w(d)，且 d≤n。按 k=1,2,3,... 递增计算时，`h(k)` 中除 w(k) 外的所有项都已在之前求出。
- 因此可直接反演：
  `w(k) = (h(k) - Σ_{d|k, d<k} d·w(d)) · k^{-1} mod p`
  其中 `k^{-1}` 是 k 在模 p 下的逆元（p 为素数且 k<p 时存在）。
- 复杂度为 `O(n log n)`（枚举每个 k 的真因子），n=1024 时瞬间完成；不需要解线性系统，也不需要知道隐藏参数的任何先验。
- 密钥派生：把还原出的 `w(1..n)` 按大端序拼成字节流，取 SHA-256 得 32 字节密钥；用该密钥与密文做循环异或（流密码）解出明文。
- 这个方案的安全性依赖“攻击者不知道 h 的生成方式/参数”，但变换本身是可逆的；一旦算法公开，隐藏的 w 等价于明文。属于典型的“自定义混淆代替加密”。

## 触发条件

- 服务公开 `h(n)` 或可查询多个 n 的 h 值，且 n 的范围有限（如 1..1024）。
- 变换形如 `h(n)=Σ_{d|n} f(d)·w(d) mod p`，其中 f 已知或可推测，p 为素数。
- 密钥由 w 的确定性编码（拼接、哈希）派生，并用简单流密码/异或加密 flag。
- 每次连接参数随机但算法固定，攻击者可在单次连接内完成反演。

## 利用步骤

1. 收集 h(1..n) 与模数 p；确认 h 的定义（因子求和、权重函数 d）。
2. 从 k=1 开始递推：枚举 k 的真因子 d，累加 `d*w(d)`，用 h(k) 减去后乘 `k^{-1} mod p` 得 w(k)。
3. 把 w(1..n) 按大端拼成字节串，SHA-256 得 32 字节密钥。
4. 用密钥与 `flag_enc` 循环异或，按 flag 格式/crib 验证；若不对，检查端序、权重函数（d、φ(d)、μ(d) 等）与归一化方式。
5. 对同一连接重复验证；不同连接的 p/h 会变，但明文固定，可用于交叉确认密钥派生正确。

## PoC

```python
import hashlib
from sympy import divisors

def recover_weights(h, p, n):
    w = [0] * (n + 1)
    for k in range(1, n + 1):
        s = h[k]
        for d in divisors(k)[:-1]:       # 真因子（不含 k 本身）
            s = (s - d * w[d]) % p
        w[k] = s * pow(k, -1, p) % p
    return w

def derive_key(w):
    raw = b"".join(int(x).to_bytes((max(1, (int(x).bit_length() + 7) // 8)), "big")
                   for x in w[1:])
    return hashlib.sha256(raw).digest()

def decrypt(enc, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(enc))

w = recover_weights(h, p, 1024)
pt = decrypt(flag_enc, derive_key(w))
print(pt)
```

```python
# 校验：用还原的 w 重新计算 h(k)，应与原始 h 完全一致
assert all(sum(d * w[d] for d in divisors(k)) % p == h[k] for k in range(1, n + 1))
```

## 变体与关联

- 变体：权重函数换成 `φ(d)`、`μ(d)`、`d^k` 等已知数论函数，反演公式相应调整；若 f(d) 未知，可用已知 crib 或线性代数求解。
- 变体：二维/多维前缀和、莫比乌斯反演、子集和卷积等同样可能因下三角结构被逐项反演。
- 关联：[[crypto-prng-mt19937-clock-seed-wallet-key-recovery]]（可预测参数导致密钥恢复）、[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（自定义加密代替标准方案）。
- 边界：n 很大或 p 非素数（k 不可逆）时需改用其他消元；若 h 只公开部分 n 或加了噪声，反演可能不完整；密钥派生细节（端序、哈希、截断）需与实现一致。

## 检测与防御

- 检测：代码/协议中出现“按因子求和”“狄利克雷卷积”“数论函数”等自定义参数隐藏；密钥由公开可查询的 h 派生；同一明文在不同连接下密文变化但密钥可复现。
- 修复：不要用可逆的数学变换隐藏密钥；使用标准 KEM/DEM 或 AEAD，密钥来自 CSPRNG/KDF（HKDF）；公开参数不应足以推导密钥。
- 加固：对自定义密码方案做密码学评审；避免“混淆即安全”；对 oracle 接口限速、认证与审计；密钥定期轮换。
