---
id: crypto-rsa-private-exponent-low-bits-partial-p
title: RSA 私钥 d 低位泄露：solve_mod 求 p 低位候选后 Coppersmith 恢复 p
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-partial-d-low-bits
tags:
- rsa
- partial-key-exposure
- private-exponent
- coppersmith
- small-roots
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:52+08:00'
  notes: 已对照原文核对：e·d0·X-k·X·(n-X+1)+k·n≡X (mod 2^kbits)、solve_mod 枚举 k=1..e、p=p0+2^kbits·x 的 small_roots(beta=0.3, X=2^(nbits/2-kbits))、n//p 后 inverse 解密，与原文代码一致。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-private-exponent-low-bits-partial-p/
draft: false
kb_aliases:
- RSA 部分私钥泄露
- d 低位泄露
- 已知 d 的后若干位
- partial d attack
- solve_mod 恢复 p
---

## 一句话结论

已知 RSA 私钥 `d` 的低 `kbits` 位时，利用 `e·d ≡ 1 (mod φ(n))` 在模 `2^kbits` 下枚举乘数 `k`，用 `solve_mod` 解出 `p` 的低位候选，再把“已知 p 低位”转成 Coppersmith 小根问题恢复完整 `p`，最终分解 `n` 并解密。

## 原理

- 由 `e·d ≡ 1 (mod φ(n))` 可写 `e·d = 1 + k·φ(n)`，其中 `1 ≤ k < e`。`φ(n) = n - p - q + 1`，且 `q ≡ n·p^{-1} (mod 2^kbits)`。
- 只取模 `2^kbits`：`e·d0 ≡ 1 + k·(n - p - q + 1) (mod 2^kbits)`。两边乘 `p` 并用 `p·q = n` 消去 `q`，得到关于 `p mod 2^kbits` 的同余方程：
  `e·d0·X - k·X·(n - X + 1) + k·n ≡ X (mod 2^kbits)`。
- 对每个可能的 `k` 用 `solve_mod` 求出 `X` 的解，就得到 `p` 的低 `kbits` 位候选 `p0`。
- 接着把 `p = p0 + 2^kbits·x` 看作未知高位 `x` 的线性多项式，模 `n` 求小根；`x` 的位数约为 `p` 位数减 `kbits`，通常远小于 Coppersmith 界，可恢复完整 `p`。
- 得到 `p` 后 `q = n//p`，计算 `φ` 与 `d`，解密密文。`d` 本身不需要完整恢复。

## 触发条件

- 已知 `n`、`e`、`c`，以及 `d` 的低 `kbits` 位（连续低位）。
- `kbits` 足够大，使 `solve_mod` 能唯一定出 `p` 的低位候选；同时剩余未知高位足够小，满足 Coppersmith 界。
- `e` 通常为 65537；需要枚举 `k=1..e`，计算量可接受。
- 能运行 Sage 的 `solve_mod` 与 `small_roots`。

## 利用步骤

1. 取 `d0 = d mod 2^kbits`，确认 `kbits` 与 `e`。
2. 对 `k = 1..e`，在模 `2^kbits` 下解方程 `e·d0·X - k·X·(n-X+1) + k·n ≡ X`，收集所有 `X` 作为 `p0` 候选。
3. 对每个 `p0` 构造 `f(x) = p0 + 2^kbits·x`，在 `Zmod(n)` 上求 `small_roots(X=2^(pbits-kbits), beta≈0.3)`。
4. 对根计算候选 `p = p0 + 2^kbits·x`，用 `n % p == 0` 校验；成功即分解。
5. 计算 `d = inverse(e, (p-1)(q-1))`，解密 `c`，回代验证。

## PoC

```python
from gmpy2 import *
from Crypto.Util.number import *

n = ...
e = ...
c = ...
d0 = ...            # 已知的 d 低位
KBITS = 410         # 已知低位位数

def partial_p(p0, kbits, n):
    nbits = n.nbits()
    PR.<x> = PolynomialRing(Zmod(n))
    f = p0 + 2^kbits * x
    f = f.monic()
    roots = f.small_roots(X=2^(nbits // 2 - kbits), beta=0.3)
    if roots:
        x0 = roots[0]
        p = gcd(int(p0 + 2^kbits * x0), n)
        return int(p)

def find_p(d0, kbits, e, n):
    X = var('X')
    for k in range(1, e + 1):
        results = solve_mod([e * d0 * X - k * X * (n - X + 1) + k * n == X], 2^kbits)
        for x in results:
            p0 = ZZ(x[0])
            p = partial_p(p0, kbits, n)
            if p:
                return p

p = find_p(d0, KBITS, e, n)
q = n // p
D = inverse(e, (p - 1) * (q - 1))
print(long_to_bytes(pow(c, int(D), n)))
```

## 变体与关联

- 变体：已知 `d` 的高位而非低位时，可用 `e·d = 1 + k·φ(n)` 建立关于 `p+q` 的方程，配合 Coppersmith 或格方法；具体形式与低位版本不同。
- 变体：已知 `d` 的中间一段、或同时知道 `d` 与部分 `p` 时，可组合多个同余条件缩小搜索。
- 变体：若 `e` 很大，枚举 `k=1..e` 不可行，需要先缩小 `k` 的范围或改用格方法。
- 关联：[[crypto-rsa-partial-prime-high-bits-coppersmith]]（已知 p 高位/低位的通用 Coppersmith）、[[crypto-rsa-boneh-durfee-small-private-exponent]]（d 整体很小但未知）、[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]（部分 e 与多密钥小 d）。

## 检测与防御

- 防御：私钥 `d` 必须完整保密，不要输出、截断打印或写入日志；密钥文件损坏后不要继续使用。
- 防御：使用标准库生成密钥，`d` 应接近模数规模；启用 RSA blinding 降低侧信道泄露风险。
- 检测：审计日志/接口中是否出现 `d` 的部分十六进制、`d & ((1<<k)-1)` 等字段；CTF 中看到“已知 d 的低 410 位”即可按本卡尝试。
- 响应：确认私钥部分泄露后视为密钥失陷，立即吊销并轮换，排查历史签名/解密记录。
