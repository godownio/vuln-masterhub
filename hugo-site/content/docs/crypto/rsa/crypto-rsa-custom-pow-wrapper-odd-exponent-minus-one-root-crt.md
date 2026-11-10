---
id: crypto-rsa-custom-pow-wrapper-odd-exponent-minus-one-root-crt
title: 自定义 pow 包装在指数为奇数时少乘一次，实际指数变成 e-1 且与 phi 不互素：分域开 e 次根再 CRT 组合
type: scenario
domain: crypto
path: crypto/rsa
technique: custom-pow-wrapper-odd-exponent-noncoprime-nth-root-crt
tags:
- rsa
- non-coprime-exponent
- nth-root
- crt
- sage
- custom-implementation
- ctf
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:15:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片；Mypow 奇偶分支、e=next_prime(666) 为奇数故实际指数 e-1、gcd(e,phi)=e、GF(p)/GF(q) 分别开 e 次根后 CRT、按 DASCTF 头筛选，均与原文一致；原文 hint 二次方程 2x^2+7n-hint*x 的解法与参数照抄无误；未验证点：脚本未在本机执行
url: /docs/crypto/rsa/crypto-rsa-custom-pow-wrapper-odd-exponent-minus-one-root-crt/
draft: false
kb_aliases:
- Mypow
- 幂函数包装 bug
- 指数与 phi 不互素
- 有限域开 e 次根
- CRT 组合多解
---

## 一句话结论

题目用自定义 `Mypow(b, e, mod)` 代替 `pow`：`e` 为偶数时等于 `pow(b,e,mod)`，为奇数时等于 `pow(b,e-1,mod)`。本例 `e = next_prime(666)` 必为奇数，实际指数变成 `e' = e-1`（偶数），而 `gcd(e', φ(n)) = e' ≠ 1`，于是 RSA 解密退化为「在 `GF(p)`、`GF(q)` 上分别开 `e'` 次根，再对多组根做 CRT 组合，最后按 flag 头筛选唯一明文」。

## 原理

- RSA 解密的必要条件是私钥指数存在，即 `e` 与 `φ(n)` 互素。包装函数悄悄把指数减 1 后，`e'` 为偶数，而 `φ(n) = (p-1)(q-1)` 也是偶数，`gcd(e', φ(n))` 至少为 2，`d = e'^{-1} mod φ` 不存在——不能走常规私钥解密。
- 但加密映射本身仍是「求 `e'` 次幂模 n」。只要在 `GF(p)` 和 `GF(q)` 上分别求 `x^{e'} ≡ c` 的所有根（`f(x) = x^{e'} - c` 的多项式求根），再用 CRT 把 `p` 侧根与 `q` 侧根两两组合，就能得到 `n` 上全部 `e'` 次根；真实明文必在其中。
- 根的数量等于 `gcd(e', p-1) · gcd(e', q-1)`，本例因 `e'` 是小的偶数，根数有限（每侧通常 2~若干个），两两 CRT 的枚举量很小，用 flag 固定前缀（`DASCTF`/`flag{`）即可唯一定位。
- 之所以可复用：这是“实现层 bug 改变数学前提”的典型——审计到 `pow` 被包装、指数被条件改写时，应先重算 `gcd(e, φ)`，而不是直接套脚本；一旦不互素就转向“求根 + CRT 筛选”而不是求逆。
- 前提是能分解 `n`：本例由 `hint` 与 `n` 的二次关系 `2x² + 7n - hint·x = 0` 直接解出 `p`。

## 触发条件

- 加密/签名实现里指数被自定义函数改写（减 1、加 1、按奇偶分支、按 bit 长度处理），且改写后与 `φ(n)` 不互素。
- 已知或可解出 `n` 的分解（提示方程、弱素数、共模等）。
- 单条密文，明文较短且带已知前缀，可用于在多解中筛选。

## 利用步骤

1. 读实现，确认 `pow` 包装的分支条件，算出真实指数 `e'`。
2. 由 `hint` 与 `n` 解二次方程得 `p`，`q = n // p`，校验 `p*q == n`。
3. 确认 `gcd(e', p-1)`、`gcd(e', q-1)` 均大于 1（不互素），放弃求逆。
4. 在 `Zmod(p)`、`Zmod(q)` 上分别对 `x^{e'} - ct` 求根。
5. 枚举两根集合并 CRT，逐候选转字节，筛含已知前缀者。

## PoC

```python
# sage
import gmpy2
from Crypto.Util.number import long_to_bytes

n = 36443283250594259606482132779262570582448178589602577809591307671554949253094255209079689901493052116793388954529442162972106210862341856282788030374324677114528044629385805693771773377070021111949953333360526159026822968061585876873187059674130307295006486032106471182393880915860569773206853864515489855553
hint = 57792516722001523643789088224096258172899052039145876393373730235406451592173971020702024058282699663364267742428240581839287357212741266617791207580236457
ct = 24482128269957355675512496312977308128712253968496848873519792376434347925427116612997489113223781321628516365811583310346553402215907938918891908853234881284620764982626375301219763593402089309909155204943747718536894186749932544428588048770663458669109073657836937287831725958017345747881678942488157429000

# 1) 由 hint 的二次关系解 p：2p^2 + 7n - hint*p = 0
R.<x> = Zmod()[]
f = 2*x^2 + 7*n - hint*x
p = int(f.roots()[0][0]); q = n // p
assert p * q == n

# 2) 真实指数是 next_prime(666) - 1（包装函数对奇数 e 少乘一次）
e = gmpy2.next_prime(666) - 1

# 3) 分域开 e 次根
R.<x> = Zmod(p)[]
r1 = (x^e - ct).monic().roots()
R.<x> = Zmod(q)[]
r2 = (x^e - ct).monic().roots()

# 4) CRT 组合 + 按 flag 头筛选
from sage.all import CRT_list
for i in r1:
    for j in r2:
        m = CRT_list([int(i[0]), int(j[0])], [p, q])
        flag = long_to_bytes(int(m))
        if b'DASCTF' in flag:
            print(flag); break
```

## 变体与关联

- 变体：包装函数导致指数加 1（`e+1`）时同样可能不互素，处理方式一致。
- 变体：`gcd(e',φ)` 很大（如 `e'` 含 `2^k`）时根数指数级增长，此时改用 `p-1 = 2^a·m` 的分解逐层开方（Tonelli-Shanks 的推广 / AMM 算法），并在每一步用已知明文前缀剪枝。
- 变体：若 `n` 无法分解，但 `gcd(e', φ)` 小且已知明文高位，可转向 Coppersmith 求小根。
- 关联：[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（同为“不开逆、改开根”的思路）、[[ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain]]（不互素指数的另一条恢复路径）、[[crypto-rsa-hint-difference-gcd-factorization]]（用提示关系分解 `n`）。
- 边界：`e'` 为素数且与 `φ` 互素时不存在多解，开根退化为唯一解；`p-1`/`q-1` 含大素因子时直接求根不可行。

## 检测与防御

- 本题为 CTF 题，工程侧教训：不要自己实现 `pow` 的“优化”包装；任何对公钥指数的改写都必须重新验证 `gcd(e, φ(n)) = 1`，并在初始化时断言。
- 实现层：加密/签名参数改动后跑自检（用已知明文验证 `dec(enc(m)) == m`），能第一时间暴露指数被改写。
- 协议层：私钥指数不存在时应直接报错而非退化处理，避免“多解”泄漏可区分信息。
