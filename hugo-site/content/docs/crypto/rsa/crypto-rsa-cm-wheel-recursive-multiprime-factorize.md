---
id: crypto-rsa-cm-wheel-recursive-multiprime-factorize
title: 用 crypto-attacks 的 complex_multiplication 轮子做 CM 分解：先按判别式 43 拆出 p，再按 67 递归拆 qr，多素数 RSA 分别取模解密
type: scenario
domain: crypto
path: crypto/rsa
technique: cm-wheel-recursive-multiprime-factorize
tags:
- crypto
- rsa
- factorization
- cm-method
- multiprime
- sage
- ctf
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:42:27+08:00'
  notes: 已对照原文核对；本次核对未读取图片；complex_multiplication.factorize 轮子路径、判别式 43/67 递归拆分、sys.setrecursionlimit、Sage 导入 attacks/shared 等与正文 exp 一致；已修正触发条件中 n 位数的笔误（按正文 n 实算为 3075 位，原写 2048 位）；分段解密 d'=e^-1 mod (q-1)(r-1) 的写法按正文 exp 保留（正文同款），轮子运行结果仅在截图中故 confidence=low；未访问文中 URL、未执行文内 PoC
url: /docs/crypto/rsa/crypto-rsa-cm-wheel-recursive-multiprime-factorize/
draft: false
kb_aliases:
- complex_multiplication.factorize
- crypto-attacks 轮子
- CM 分解轮子
- 多素数递归拆分
- 判别式 43 / 67
- sage 本地导入 attacks
---

## 一句话结论

当 RSA 模数 `n` 是三个大素数的乘积、常规分解（试除/费马/Pollard p-1/ECM）都跑不动时，可以直接用 `crypto-attacks` 项目里的 `complex_multiplication.factorize(n, D)` 轮子做 CM 分解：先用判别式 43 的 CM 曲线拆出一个素因子 `p`，再把剩余部分 `qr` 用判别式 67 递归拆成 `q` 与 `r`；拿到三个素数后，后两段合起来按 `q*r` 取模解密即可（`m = c^(e^{-1} mod (q-1)(r-1)) mod qr`），不必按完整 `φ(n)` 求逆。

## 原理

- **CM 分解的适用面**：常规方法对"随机大素数"的乘积无能为力，但若能用虚二次域判别式 `-D` 构造出与该合数"适配"的 CM 椭圆曲线，那么在曲线上的除法多项式取范数再与 `n` 求 gcd，就有较高概率掉出一个非平凡因子。它属于"用额外结构信息换分解速度"的一类方法，与 ECM 的随机曲线思路互补。
- **为什么要试多个 D**：判别式决定 CM 曲线的自同态环与类数，只有与 `n` 的素因子"匹配"的 D 才会成功；轮子把 D 作为参数，失败就换一个。本例 43 与 67 分别对 `n` 与 `qr` 有效，说明不同素因子可能对应不同判别式。
- **递归拆分多素数模数**：`factorize(n, D)` 返回的是一对因子 `(p, rest)`，不保证两个都是素数。多素数场景下把它当"二分"用：先拆 `n → p, qr`，再对 `qr` 递归 `→ q, r`，直到每段都是素数。轮子内部对递归深度敏感，Python 默认递归上限不够时需 `sys.setrecursionlimit`。
- **多素数解密的取模技巧**：若只关心后两段拼出的明文（题目常把 flag 分块放在不同素因子组合里），可用 `d' = e^{-1} mod (q-1)(r-1)`、`m = c^{d'} mod (q*r)`，等于在子模数上做一次 RSA 解密；要恢复完整明文再对 `p*q*r` 走标准 `φ(n)` 解密。
- **为什么先取 cube/triple 结构无关**：CM 分解只依赖 `n` 的因子结构，不要求 `e` 小、也不要求明文短，这与低指数广播攻击是两条完全不同的路；区分点是"能否分解 n"而不是"是否需要更多同明文密文"。
- **工程要点**：轮子是纯 Sage 代码，需要把 `attacks/` 与 `shared/` 目录解压到可导入路径（如 Sage 的工作目录），再新建一个 `.ipynb` 或 `.sage` 文件运行；直接 `python exp.py` 往往因缺 Sage 运行时失败。

## 触发条件

- 目标 `n` 为大合数（本例约 3075 位、三个素因子），常规分解无果。
- 有 SageMath 环境，且能拿到 `crypto-attacks` 仓库的 `attacks/factorization/complex_multiplication.py` 与 `shared/` 依赖。
- 题目暗示或允许枚举判别式 `D`（本例 43、67 来自题目给定/尝试）。
- 有足够的运行时间与内存（CM 分解的耗时与 D 的类数正相关）。

## 利用步骤

1. 准备 SageMath 环境，把 `crypto-attacks` 解压得到 `attacks/` 与 `shared/`，置于 Sage 工作目录；新建 `.ipynb`/`.sage` 文件，`from attacks.factorization import complex_multiplication` 验证导入。
2. `sys.setrecursionlimit(10**6)`，避免递归拆分时爆栈。
3. `p, qr = complex_multiplication.factorize(n, 43)`：得到素因子 `p` 与剩余合数 `qr`。
4. `q, r = complex_multiplication.factorize(qr, 67)`：把剩余部分再拆成两个素数。
5. 校验 `p*q*r == n` 且三者均为素数（`is_prime`），不满足就换 D 重试。
6. 解密：若 flag 落在 `q*r` 段，用 `d' = pow(e, -1, (q-1)*(r-1))`、`m = pow(c, d', q*r)` 再 `long_to_bytes`；否则按 `φ(n)` 走标准解密。
7. 若某次 `factorize` 返回的因子不是素数，继续对合数递归，不要假设返回值一定是素数。

## PoC

```python
from attacks.factorization import complex_multiplication
import sys, math

sys.setrecursionlimit(10 ** 6)

# n 为三素数模数，c 为密文，e 为公钥指数
p, qr = complex_multiplication.factorize(n, 43)   # 判别式 D=43
q, r  = complex_multiplication.factorize(qr, 67)  # 判别式 D=67
assert p * q * r == n

# 只解 q*r 段
d = pow(65537, -1, (q - 1) * (r - 1))
m = pow(c, d, q * r)
print(bytes.fromhex(hex(m)[2:]))
```

```text
环境要点（踩坑点）：
1) 必须用 Sage 运行时（sage -n / .ipynb），纯 CPython 跑不动；
2) attacks/ 与 shared/ 需同时解压到工作目录，只放 attacks 会 ImportError；
3) complex_multiplication.factorize 返回的是 (factor, rest)，rest 可能是合数，需递归；
4) D 不正确时函数会长时间无返回或抛异常，换 D 而不是加大轮数。
```

## 变体与关联

- 关联：[[crypto-rsa-cm-factorization-hilbert-class-polynomial]]（手写 CM 分解：用 `hilbert_class_polynomial` 构造商环、取除法多项式范数 gcd；本卡是同一数学基础但直接用现成轮子并把重点放在"递归拆多素数"与"分段解密"）、[[crypto-rsa-fermat-close-prime-factorization]]、[[crypto-rsa-pollard-pminus1-smooth-prime]]（应优先尝试的低成本方法，失败后再上 CM）。
- 变体：换判别式（如 11/19/43/67/163 等类数小的 D 更快）；因子多于三个时继续递归；若题目给出 `n = p·q^r` 之类的幂结构，另有 φ 因子类方法可用。
- 边界：D 的类数过大时 Hilbert 类多项式计算不可行，轮子会退化为"跑不完"；若 `n` 的素因子较小，ECM/试除更快；轮子内部若对不可逆元素处理不当会静默失败，需自行加 `is_prime`/乘积校验。

## 检测与防御

- 检测（CTF 侧）：`n` 极大但常规分解无果、题目给出判别式或"后门/曲线"提示；解题耗时与 D 的类数相关。
- 防御（生成侧）：用标准随机大素数生成 RSA 模数，避免由特殊构造（CM 友好、共享判别式、弱素数）产生的模数；不复用题目/工具的密钥生成器；密钥长度 2048 位以上并做素数性验证。
