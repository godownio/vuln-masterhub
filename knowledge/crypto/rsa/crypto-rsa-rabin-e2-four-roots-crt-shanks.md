---
id: crypto-rsa-rabin-e2-four-roots-crt-shanks
title: Rabin 加密 e=2 解密：已知 p/q 用 (p+1)/4 或 Tonelli-Shanks 求模平方根，CRT 组合四个根并按明文筛选
type: scenario
domain: crypto
path: crypto/rsa
technique: rabin-e2-four-square-roots-crt-shanks
aliases:
- Rabin 加密
- Rabin 解密 四根
- e=2 RSA
- 二次剩余求平方根
- Tonelli-Shanks RSA
- CRT 四组明文
tags:
- rsa
- rabin
- e2
- quadratic-residue
- tonelli-shanks
- crt
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V599
  verified_at: '2026-11-12T17:14:03+08:00'
  notes: 已对照原文与唯一图（CRT 定义）核对：e=2、p≡q≡3(mod4) 时 pow(c,(p+1)//4,p) 求根、一般素数 Tonelli-Shanks、CRT 四组合、按明文筛选，均与原文一致（原文标题 Rabbit 为 Rabin 笔误，卡已用正确名称）。用原文两组数据实测复算：①p=13934102561950901579/q=14450452739004884887，p·q=n 成立、p,q 均为素数且≡3 mod4，四根中得 flag{r4b1n#4c58}；②p=275127860351348928173285174381581152299/q=319576316814478949870590164193048041239，Tonelli_Shanks 求根后 CRT 四根中得 PCTF{sp3ci4l_rsa}。卡内 PoC 与原文代码等价。dedup rec=new 成立：与 crypto-rsa-rabin-random-square-root-oracle（预言机攻击分解 N）场景相反，与 AMM（开 e 次根）等仅共享数学工具，非同链。跳过项核对：Schmidt-Samoa、Pollard p-1、Williams p+1 均有已验证专卡，skip 正确。原文无组件版本。
---

## 一句话结论

Rabin 加密就是 `e=2` 的 RSA：`c = m² mod n`（`n=p·q`）。已知 `p、q` 时，分别在模 p、模 q 下求 `c` 的平方根（`p≡q≡3 (mod 4)` 时直接 `pow(c,(p+1)//4,p)`，否则用 Tonelli-Shanks），再用中国剩余定理把“± 根”的四种组合拼起来，得到模 n 的四个候选明文，按 flag 格式/冗余编码筛出唯一正确解。

## 原理

- **模素数平方根**：若 `m² ≡ c (mod p)`，则解为 `m ≡ ±r (mod p)`，其中 `r` 是任一平方根。欧拉准则判断可解性：`c^((p-1)/2) ≡ 1 (mod p)` 时 c 是二次剩余；对 `p ≡ 3 (mod 4)`，有 `r = c^((p+1)/4) mod p`，因为 `r² = c^((p+1)/2) = c·c^((p-1)/2) ≡ c`。
- **一般素数用 Tonelli-Shanks**：当 `p ≡ 1 (mod 4)` 时 `(p+1)/4` 不是整数，需要 Tonelli-Shanks 算法（把 p−1 写成 `q·2^s`，找非剩余 z，迭代求根）；Sage 的 `sqrt(c, p)` 或 `Mod(c,p).sqrt()` 内部即此算法。
- **CRT 组合**：得到 `m ≡ ±r (mod p)`、`m ≡ ±s (mod q)` 后，四种符号组合各对应模 n 的一个根（共 4 个）。用 CRT 系数 `inv_p = p^{-1} mod q`、`inv_q = q^{-1} mod p`，可写出：
  `a = (inv_p·p·s + inv_q·q·r) mod n`、`b = n − a`、`c' = (inv_p·p·s − inv_q·q·r) mod n`、`d = n − c'`，四个根即 `a,b,c',d`（顺序取决于 r、s 的符号取法，全部列出即可）。
- **为什么要筛**：Rabin 解密天生不唯一（四个根），正确明文只有一个。CTF 中按 `long_to_bytes` 后是否可打印、是否含 `flag{`/题目前缀、是否满足给定哈希/校验位筛选；工程实现则靠加密前的冗余编码（如加固定头、哈希）在解密后唯一确定。
- **与 Rabin 预言机攻击的区别**：本卡是“已分解 n、求明文”的正常解密算法；`e=2` 且服务随机返回平方根时的预言机攻击（两次查询分解 N）见 `[[crypto-rsa-rabin-random-square-root-oracle]]`，两者场景不同。

## 触发条件

- 密文满足 `c = m² mod n`（题目给出 `e=2` 或省略 e、提示 Rabin）。
- `n=p·q` 且 p、q 已知，或已通过其它方式分解 n。
- p、q 为奇素数；`p≡q≡3 (mod 4)` 时可用快速公式，否则需 Tonelli-Shanks/Sage。
- 明文有可识别的格式或额外校验信息用于在四个根中筛选。

## 利用步骤

1. 确认 `e=2`、拿到 `n、p、q、c`；验证 `p*q == n`。
2. 求 `r = sqrt(c) mod p`：若 `p % 4 == 3`，`r = pow(c,(p+1)//4,p)`；否则用 Tonelli-Shanks 或 Sage `sqrt(Mod(c,p))`。
3. 同法求 `s = sqrt(c) mod q`。
4. 计算 CRT 组合的四个根（`a、n-a`、`b、n-b`）。
5. 对每个根 `long_to_bytes`，按可打印性/flag 前缀/题目校验位筛选，得到正确明文。
6. 若四个根都不像明文，检查 c 是否真的是二次剩余（欧拉准则）、p/q 是否写反或 e 是否为 2 的倍数。

## PoC

`p ≡ q ≡ 3 (mod 4)` 的简化写法：

```python
import gmpy2, libnum
p, q, n, c = ..., ..., ..., ...
inv_p = gmpy2.invert(p, q)
inv_q = gmpy2.invert(q, p)
mp = pow(c, (p + 1) // 4, p)
mq = pow(c, (q + 1) // 4, q)
a = (inv_p * p * mq + inv_q * q * mp) % n
b = n - int(a)
c2 = (inv_p * p * mq - inv_q * q * mp) % n
d = n - int(c2)
for x in (a, b, c2, d):
    print(libnum.n2s(int(x)))
```

一般素数用 Tonelli-Shanks（或直接用 Sage `sqrt(Mod(c,p))`）：

```python
def Legendre(n, p):
    return pow(n, (p - 1) // 2, p)

def Tonelli_Shanks(n, p):
    assert Legendre(n, p) == 1
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2; s += 1
    for z in range(2, p):
        if Legendre(z, p) == p - 1:
            c_ = pow(z, q, p); break
    r = pow(n, (q + 1) // 2, p); t = pow(n, q, p); m = s
    if t % p == 1:
        return r
    i = 0
    while t % p != 1:
        temp = pow(t, 2 ** (i + 1), p); i += 1
        if temp % p == 1:
            b = pow(c_, 2 ** (m - i - 1), p)
            r = r * b % p; c_ = b * b % p; t = t * c_ % p; m = i; i = 0
    return r

r1 = Tonelli_Shanks(c, p)
r2 = Tonelli_Shanks(c, q)
from sympy.ntheory.modular import crt
for a1 in (r1, p - r1):
    for a2 in (r2, q - r2):
        m, _ = crt([p, q], [a1, a2])
        print(long_to_bytes(m))
```

## 变体与关联

- **Rabin 预言机攻击**：`e=2` 服务随机返回平方根，用 `gcd(a−y,N)` 分解 N，见 `[[crypto-rsa-rabin-random-square-root-oracle]]`；本卡假设已分解 n。
- **Schmidt-Samoa**：`N=p²q`、解密在 `p·q` 上进行且解唯一，见 `[[crypto-rsa-schmidt-samoa-known-d-factor]]`；与本卡的 e=2 四根不同。
- **AMM/一般模平方根**：`e=2` 可视为 AMM 的特例，模 p 求根算法见 `[[crypto-rsa-amm-nth-root-mod-p-unit-roots-crt]]`。
- **其它分解后解密**：Pollard p−1（`[[crypto-rsa-pollard-pminus1-smooth-prime]]`）、Williams p+1（`[[crypto-rsa-williams-p-plus-1-smooth-factor]]`）用于先得到 p/q，再回到本卡求根。

## 检测与防御

- **实现侧**：Rabin 加密必须配合冗余/确定性编码（固定头、哈希、OAEP 类方案），解密后校验冗余以唯一选根；不要把四个候选根或选根提示返回给调用方。
- **密钥侧**：使用足够大的随机素数（避免 Pollard p−1/p+1、费马等分解），私钥与明文不重复使用。
- **测试边界**：CTF 场景仅在本地求解，不对真实系统发起预言机查询。
