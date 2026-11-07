---
id: crypto-rsa-d-leak-factor-n-reuse-modulus-new-e
title: RSA 私钥 d 泄露后只换 e 不换 n：e·d−1 概率分解 N 并解新密文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-d-leak-factor-n-reuse-modulus-new-e
tags:
- crypto
- rsa
- private-exponent
- factorization
- modulus-reuse
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:57:59+08:00'
  notes: 已对照原文核对：e1*d1-1 分解 n、phi 计算、e2 求 d2、pow(c,d2,n) 解密，参数与 flag 均一致；算法描述正确；未复跑 PoC。
url: /docs/crypto/rsa/crypto-rsa-d-leak-factor-n-reuse-modulus-new-e/
draft: false
kb_aliases:
- RSA d 泄露
- e*d-1 分解 N
- 换 e 不换 n
- 同一模数新公钥
- Leaked_d
- 私钥指数泄露
---

## 一句话结论

RSA 私钥指数 `d1` 泄露后，即使服务端“生成新密钥对”只换了 `e2`、仍沿用同一个模数 `n1`（同一对 p,q），也不安全：由 `k = e1·d1 − 1 = 2^r·s`，随机取 `g` 计算 `g^s mod n` 并反复平方，可用 `gcd(x−1,n)` 概率分解 `n`；得到 p,q 后求 `φ(n)`，再用新公钥 `e2` 计算 `d2 = e2^{-1} mod φ(n)` 即可解密新密文。

## 原理

- **RSA 关系**：`e·d ≡ 1 (mod λ(n))`，因此 `e·d − 1` 是 `λ(n)` 的倍数，也是 `φ(n)` 的倍数；写 `k = e·d − 1 = 2^r·s`（s 为奇数）。
- **概率分解**：对随机 `g ∈ [2,n−2]`，计算 `x = g^s mod n`。若 `x ≠ 1, n−1`，则对 `x` 反复平方（最多 r 次），在某个 `x^{2^i}` 处 `gcd(x−1,n)` 会给出 p 或 q；这是 Miller-Rabin 分解思路的逆用。
- **为什么换 e 不换 n 不安全**：`d1` 泄露等价于泄露 `φ(n)` 的倍数，进而分解 n；攻击者拿到 p,q 后，任何基于同一 n 的新公钥 `e2` 都能求出对应私钥 `d2`，旧模数上的所有新密文都可解。
- **攻击步骤**：分解 n → `φ=(p−1)(q−1)` → `d2=inverse(e2,φ)` → `m=pow(c,d2,n)` → long_to_bytes。
- **修复误区**：只换 e、重新生成 d 但不换 p,q/n，等于没换密钥；必须重新生成模数（新 p,q）或直接弃用旧密钥对。

## 触发条件

- 攻击者已知旧模数 `n`、旧公钥指数 `e1`、旧私钥指数 `d1`（泄露/日志/内存/侧信道），以及新公钥 `e2` 和新密文 `c`。
- 新密钥对复用了同一个 `n`（同一对 p,q），只换了 `e`；`e2` 与 `φ(n)` 互素。
- 目标未在 d 泄露后轮换模数/未撤销旧密钥；密文使用标准 RSA（无随机化/填充问题）。
- 计算资源足以做几次模幂/ gcd（分解概率算法通常很快）。

## 利用步骤

1. **计算 k**：`k = e1*d1 - 1`；写 `k = 2^r * s`（s 奇数）。
2. **概率分解**：循环随机取 `g`，`x = pow(g, s, n)`；若 `x==1` 或 `x==n-1` 重试；否则对 `i in range(r)`：`p = gcd(x-1,n)`，若 `1<p<n` 成功，否则 `x = x^2 mod n`。
3. **验证**：`p*q == n`；得到 p,q。
4. **求新私钥**：`φ=(p-1)*(q-1)`；`d2 = inverse(e2, φ)`。
5. **解密**：`m = pow(c, d2, n)`；`long_to_bytes(m)` 得明文/flag。
6. **若 e2 与 φ 不互素**：需要先分解 φ 或求 `λ(n)`，用扩展欧几里得处理；通常 e2 为质数且不整除 φ。

## PoC

```python
from math import gcd
from random import randrange
from Crypto.Util.number import long_to_bytes, inverse

n  = ...      # 旧模数
e1 = 65537
d1 = ...      # 泄露的旧私钥指数
e2 = 6767671
c  = ...

k = e1 * d1 - 1
s, r = k, 0
while s % 2 == 0:
    s //= 2; r += 1

def factor_from_d(n, s, r):
    while True:
        g = randrange(2, n - 1)
        x = pow(g, s, n)
        if x in (1, n - 1):
            continue
        for _ in range(r):
            p = gcd(x - 1, n)
            if 1 < p < n:
                return p, n // p
            x = pow(x, 2, n)

p, q = factor_from_d(n, s, r)
assert p * q == n
phi = (p - 1) * (q - 1)
d2 = inverse(e2, phi)
m = pow(c, d2, n)
print(long_to_bytes(m))
```

原文在给定 `n,e1,d1,e2,c` 下成功分解并解出 flag；本卡不执行 PoC。

## 变体与关联

- **只泄露 d 的低位/高位**：需要 Coppersmith/格方法补全，见 [[crypto-rsa-private-exponent-low-bits-partial-p]]；本卡是完整 d 泄露。
- **泄露 φ(n)/λ(n)**：同样可分解 n 或直接求 d；与 d 泄露等价。
- **多把公钥同模数**：若 e1,e2 共用 n 且 d1 泄露，全部可解；即使没有 d，共用模数的多把密钥也可能被 GCD/共模攻击。
- **关联**：[[crypto-rsa-continued-fraction-lambda-factorization]]（由 e·g/n 恢复 λ 并分解）、[[crypto-rsa-wiener-small-private-exponent-large-e]]（小 d 攻击）、[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]（同模数多密钥）。
- **边界**：需要完整 d1 和同一 n；若服务端在 d 泄露后真正更换了 p,q/n，或使用 RSA-KEM/抗量子方案，本攻击不成立。

## 检测与防御

- **密钥轮换**：d 泄露后必须重新生成 p,q 和 n，不能只换 e；撤销旧证书/密钥，通知依赖方。
- **最小暴露**：私钥指数不出现在日志/内存转储/错误信息/侧信道可达位置；使用 HSM/TPM 保护私钥，常时算法。
- **密钥管理**：定期轮换、分离密钥用途、监控同一 n 被多把 e 复用；对历史密文评估是否需重新加密。
- **检测**：同一模数对应多个公钥指数、d 出现在日志/配置文件、异常的大数 gcd/模幂行为；证书透明度/密钥泄露监控。
- **响应**：立即轮换模数与所有相关密钥，重新加密敏感数据，审计是否已被解密。
