---
id: crypto-rsa-permutation-count-nextprime
title: WKCTF2024 fl@g：排列组合计数生成 p 的 RSA——用容斥公式算 real_n 后 nextprime 解 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-permutation-count-nextprime-prime
tags:
- ctf
- crypto
- rsa
- permutation
- combinatorics
- nextprime
- inclusion-exclusion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T08:01:20+08:00'
  notes: 已对照原文核对：myprime 排列计数+nextprime；本机用原式 real_n=62!*63*4-4*58!*59*60+54!*55*56*57 与 sympy.nextprime 验证 n%p==0（p 可整除 n），公式成立。原文注释列 5 个模式而公式系数为 4，卡内已改为不强行断言模式数为 4。dup-scan 无本篇 pair；dedup 最高分为卡自身，related 均为不同素数生成结构。
url: /docs/crypto/rsa/crypto-rsa-permutation-count-nextprime/
draft: false
kb_aliases:
- WKCTF2024 fl@g
- myprime 排列组合
- nextprime(real_n)
- 组合数学 RSA
- real_n 容斥
---

## 一句话结论

题目用 `myprime()` 暴力枚举字符表的所有排列，统计包含 `flag`/`FLAG`/`f14G`/`7!@9`/`F1ag` 任一子串的排列数 `num`，再返回 `nextprime(num)` 作为 RSA 的 `p`；不必跑阶乘级枚举，文章用容斥公式 `real_n = 62!*63*4 - 4*58!*59*60 + 54!*55*56*57` 直接算出该计数，`p = nextprime(real_n)`、`q = n // p`，再按标准 RSA 求 `d` 解密。

## 原理

- **myprime 的定义**：`myprime()` 对长度为 62 的字符表做 `permutations` 全排列，把每个排列拼成字符串；若其中包含 `flag`、`FLAG`、`f14G`、`7!@9`、`F1ag` 任一子串就计数，最后 `nextprime(num)` 返回素数作为 RSA 的 p。直接跑 62! 次枚举不可行，必须用组合数学算 `num`。
- **把模式当成“块”**：一个 4 字符模式出现在排列中，可把它视为一个整体块；块的位置数乘以其余字符的排列数就是“包含该模式”的排列数。多个模式同时出现时，用容斥减去重叠、加回三重交叠。
- **文章的闭式**：
  ```text
  real_n = factorial(62)*63*4 - 4*factorial(58)*59*60 + factorial(54)*55*56*57
  ```
  第一项是各模式的“块”计数（`62!*63 = 63!` 再乘原文系数 4；原文注释列了 5 个模式，系数与模式数的对应原文未展开）；第二项减去两两重叠的计数（`58!*59*60 = 60!` 乘系数 4）；第三项加回三重交叠（`54!*55*56*57 = 57!`）。系数/项数取决于字符表与模式的重叠关系，关键是先识别“块 + 容斥”的结构；文章用该式得到的 `real_n` 与 `myprime` 的暴力计数一致。
- **为什么能用 nextprime 作为 p**：题目把 p 定义成“计数后的下一个素数”，因此 p 不是随机素数，而是由公开的字符表/模式完全决定的；攻击者只要重算计数就能得到 p，进而 `q = n // p` 分解 n。这是“p 的生成算法可复现”类 RSA 题，而不是依赖分解难题。
- **标准 RSA 收尾**：`phi=(p-1)*(q-1)`、`d=invert(e,phi)`、`m=pow(c,d,n)`、`long_to_bytes(m)` 得 flag。

## 触发条件

- RSA 题给出 `n`、`e`、`c`，同时给出 `myprime()` 一类“用排列/组合计数生成 p”的源码或描述。
- 字符表长度、模式集合、计数规则可复现（或可从源码读出）；`nextprime` 的行为明确。
- `p` 只由该计数决定，`n = p*q` 且 q 为普通素数；没有其他隐藏随机性。
- 允许用 Python `math.factorial`/`sympy.nextprime`/`gmpy2` 做高精度计算。

## 利用步骤

1. 读 `myprime()`：确认字符表长度、模式列表、计数条件、`nextprime` 的调用位置。
2. 用“块 + 容斥”推导 `real_n`；文章直接给出 `62!*63*4 - 4*58!*59*60 + 54!*55*56*57`。若字符表/模式不同，按同样结构重算（必要时用小规模暴力校验公式）。
3. `p = nextprime(real_n)`；`q = n // p`；检查 `p*q == n`。
4. `phi=(p-1)*(q-1)`；`d=invert(e,phi)`；`m=pow(c,d,n)`；`long_to_bytes(m)`。
5. 若 `nextprime` 结果不整除 n，尝试 `prevprime`/邻近素数，或检查公式的边界（模式是否可重叠、是否允许重复字符）。

## PoC

```python
import gmpy2
from sympy import nextprime, factorial
from Crypto.Util.number import long_to_bytes

n = 10179374723747373757354331803486491859701644330006662145185130847839571647703918266478112837755004588085165750997749893646933873398734236153637724985137304539453062753420396973717
c = 1388132475577742501308652898326761622837921103707698682051295277382930035244575886211234081534946870195081797116999020335515058810721612290772127889245497723680133813796299680596
e = 65537

# 文章用容斥公式直接算 myprime() 的计数（不用跑 62! 全排列）
real_n = factorial(62) * 63 * 4 - 4 * factorial(58) * 59 * 60 + factorial(54) * 55 * 56 * 57

p = nextprime(real_n)
q = n // p
assert p * q == n

phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
flag = long_to_bytes(pow(c, d, n))
print(flag)
```

## 变体与关联

- **计数结构变体**：模式长度/数量不同、字符表有重复字符、模式可重叠/不可重叠；容斥的系数和阶乘项需按实际重算，必要时用 DP/自动机计数替代闭式。
- **素数生成变体**：`nextprime(num)`、`prevprime(num)`、`num` 附近偏移、`sympy.nextprime` 与自定义 Miller-Rabin 的差异；先验证 `p*q==n`。
- **RSA 收尾变体**：若 `e` 与 `phi` 不互素，需用 `e` 的因子/AMM 开根；若 n 有多个因子，先分解再逐个求逆。
- **关联**：[[crypto-rsa-pell-equation-prime-generation]]（另一类结构化 p 生成）、[[crypto-rsa-next-prime-square-moduli-continued-fraction]]（next-prime 结构）、[[crypto-rsa-prime-bit-chunks-multivariate-coppersmith-tiered]]（p 的比特/结构线索）、[[crypto-rsa-hidden-e-prime-counting-close-prime]]（用素数计数恢复参数）。
- **边界**：若 `myprime` 还混入随机数/时间/隐藏表，计数不可复现，本链不成立；若 `n` 不是两个素数之积，`q=n//p` 不成立。

## 检测与防御

- **题目设计视角**：不要用“可复现的计数/公式”生成 RSA 素数 p；p 必须来自密码学安全的随机源。
- **审计**：检查 RSA 密钥生成代码是否 `p = nextprime(f(public_data))` 一类可预测结构；用已知算法复算 p 并验证 n。
- **检测**：CTF 中先看 `n` 是否有结构化因子；若 p 由计数生成，重算 `real_n` 与 `nextprime` 通常即可分解。
- **说明**：本文为 CTF 数学题解法，不是现实漏洞；公式中的系数依赖题目字符表/模式，换题需重新推导。
