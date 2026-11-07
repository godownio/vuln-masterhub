---
id: crypto-rsa-dp-leak-composite-modulus-power-coppersmith
title: RSA 复合模数 P=m^p mod n、Q=m^q mod n 泄露 dp：枚举 k 分解 N，再用二次多项式 Coppersmith 还原 m
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-dp-leak-composite-modulus-power-coppersmith
aliases:
- dp 泄露复合 RSA
- m^p mod n 与 m^q mod n
- 二次多项式 Coppersmith
- P+Q 构造小根
- Beaufort RSA 题
- 小根还原明文
tags:
- crypto
- rsa
- dp-leak
- coppersmith
- small-root
- composite-modulus
- fermat
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:35:40+08:00'
  notes: 已对照原文 crypto1 题目、Sage 脚本与 img04-09 核对：dp*e-1 枚举 k 得 P/Q、f(x)=x^2-(P+Q)x+P*Q、small_roots 得 m、Beaufort+位置移位还原与 flag DASCTF{OVVCMCWIEUVYDSJRHDQPRG} 均一致；m=223bit/28 字节，满足 m<n^(1/2)。与 18856 标准 n 上 dp 分解卡为 related：本卡分解的是复合模数 N=P*Q 且多一步 Coppersmith，非重复。未验证点：未本机复跑 Sage。
---

## 一句话结论

题目把 RSA 的明文 m 分别做 `P=m^p mod n`、`Q=m^q mod n`，公开复合模数 `N=P*Q` 并泄露 `dp=d mod (P-1)`；利用 `dp*e-1` 是 `P-1` 的倍数枚举 k 可分解 N 得到 P、Q，再利用费马小定理 `P≡m (mod p)`、`Q≡m (mod q)` 构造二次多项式 `f(x)=x²-(P+Q)x+P*Q`，其根 m 在模 n 下满足 `f(m)≡0`，当 m<n^{1/2} 时用 Coppersmith 小根直接还原明文。

## 原理

- **dp 泄露分解 N**：`d` 是对 `φ(N)=(P-1)(Q-1)` 的逆，`dp=d mod (P-1)`，所以 `dp*e ≡ 1 (mod P-1)`，即 `P-1 | (dp*e-1)`。枚举小因子 k，令 `P_candidate=(dp*e-1)/k+1`，用 `N % P_candidate == 0` 验证，即可得到 P、Q。原文枚举 k 到 100000 命中。
- **费马小定理把 m 与 P/Q 联系起来**：在原 RSA 模数 n=p*q 上，`m^p ≡ m (mod p)`、`m^q ≡ m (mod q)`（p、q 为素数）。题目定义的 `P = m^p mod n`、`Q = m^q mod n`，因此 `P ≡ m (mod p)`、`Q ≡ m (mod q)`。
- **构造同余多项式**：`f(x)=(x-P)(x-Q)=x²-(P+Q)x+P*Q`。代入 x=m：模 p 时 `m-P≡0`，模 q 时 `m-Q≡0`，所以 p、q 都整除 f(m)，即 `n=p*q | f(m)`，也就是 `f(m) ≡ 0 (mod n)`。
- **Coppersmith 小根**：f 是首一二次多项式，m 是模 n 的一个小根；当 `m < n^{1/2}`（题目明文为 28 字节量级，n 为 1024-bit）时，Sage 的 `f.small_roots()` 可在多项式时间内求出 m。
- **后续解密**：m 转字节得到经过自定义位置移位 + Beaufort 的中间串；Beaufort 自反，再用相同密钥解一次，并按位置减回 index+1 即可恢复原始 flag。
- **根因**：泄露了与 P-1 相关的私钥指数，且把明文以低指数/幂形式嵌入可分解的复合模数，使明文成为可预测的小根。

## 触发条件

- 题目给出原 RSA 模数 n、复合模数 N=P*Q、dp、e；P、Q 为 `m^p mod n` 与 `m^q mod n`。
- m 足够小（约小于 n^{1/2}），满足 Coppersmith 小根条件。
- 能运行 SageMath（`small_roots`）或等价格算法。
- 明文还经过其他可逆变换（如 Beaufort、位置移位），需要按题目流程逆变换。

## 利用步骤

1. 计算 `temp = dp*e - 1`；枚举 k=1..100000，若 `temp % k == 0`，令 `P=(temp//k)+1`，检查 `N % P == 0`，命中后 `Q = N//P`。
2. 在 Sage 中构造 `f = x^2 - (P+Q)*x + P*Q` over `Zmod(n)`，调用 `f.small_roots()` 得到 m。
3. `m` 转 bytes 得到中间字符串；按题目格式补回 `{}`（若被截断）。
4. 用 Beaufort（密钥 "DASCTF"）解密一次（自反），再按字符位置减 `index+1` 恢复原始大写字母串。
5. 得到 flag。

## PoC

Sage（恢复 P、Q 与 m）：

```python
N = Integer(<N>)
n = Integer(<n>)
e = 65537
dp = Integer(<dp>)

temp = dp * e - 1
for k in range(1, 100000):
    if temp % k == 0:
        P = temp // k + 1
        if N % P == 0:
            Q = N // P
            break

R.<x> = Zmod(n)[]
f = x^2 - (P + Q) * x + P * Q
m = f.small_roots()[0]
print(m)
```

Python（逆 Beaufort + 位置移位）：

```python
from Crypto.Util.number import long_to_bytes
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
KEY = 'DASCTF'

def beaufort(text, key=KEY):
    res, ki = [], 0
    for ch in text:
        if ch in LETTERS:
            kch = key[ki % len(key)]
            res.append(LETTERS[(LETTERS.index(kch) - LETTERS.index(ch)) % 26])
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

s = long_to_bytes(m).decode()
if len(s) == 28:
    s = s[:6] + '{' + s[6:] + '}'
shifted = beaufort(s)
flag = ''.join(
    LETTERS[(LETTERS.index(ch) - (i + 1)) % 26] if ch in LETTERS else ch
    for i, ch in enumerate(shifted)
)
print(flag)
```

原文运行结果：`DASCTF{OVVCMCWIEUVYDSJRHDQPRG}`。

## 变体与关联

- 泄露变体：`dp=d mod (P-1)`、`dq=d mod (Q-1)`、`d` 的其它模数形式；核心都是 `e*dp-1` 的倍数关系。
- 多项式变体：若公开的是 `P+Q` 或 `P*Q` 的组合，可构造不同二次多项式；若 m 的界更小，可放宽 n 的规模。
- 变换变体：Beaufort/Vigenère、位置移位、Base 编码等，先逆变换再取 flag。
- 关联卡片：[[crypto-rsa-d-leak-factor-n-reuse-modulus-new-e]]、[[crypto-rsa-small-message-polynomial-root]]、[[crypto-rsa-known-prime-sum-quadratic-factorization]]、[[crypto-rsa-partial-plaintext-high-bits-coppersmith]]。
- 边界：m 不满足小根界时 Coppersmith 失败；k 的枚举范围需要根据 `dp*e-1` 的因子大小调整。

## 检测与防御

- 不要泄露 `dp`/`dq`/`d` 或任何与私钥指数相关的模余数；RSA 实现应使用标准库并做侧信道防护。
- 不要构造 `m^p mod n`、`m^q mod n` 这类把明文嵌入复合模数的自定义方案；使用 OAEP 等随机化填充。
- 若必须做多层加密，确保每层模数不可分解、明文足够大且不满足小根条件；对参数做安全审计。
- 红队/CTF 侧：看到 `N=P*Q` 与 `dp` 同时出现时优先尝试 `e*dp-1` 分解与 Coppersmith。
