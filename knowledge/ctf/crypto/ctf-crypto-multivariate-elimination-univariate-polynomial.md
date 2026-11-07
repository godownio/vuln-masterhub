---
id: ctf-crypto-multivariate-elimination-univariate-polynomial
title: 多元对称方程消元：把 a³+b⁶ 与 ac 表示为 b 的多项式，降为单变量高次方程
type: scenario
domain: ctf
path: ctf/crypto
technique: multivariate-equation-elimination-univariate-root
aliases:
- baby_equation
- 多元方程消元
- 单变量高次多项式
- a^3+b^6=K1+K3
- ac 表达式
- Sage roots
tags:
- ctf
- crypto
- algebra
- elimination
- polynomial
- sage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:46:07+08:00'
  notes: 已对照原文 baby_equation 核对并用 sympy 复跑：S=K1-K3、T=K1-(2/3)K3、poly=(b^5+2bY-K2)X+6Y³；复跑得整数根 b=311960913464334198969500852124413736815，回代得 c 并解出 ISCTF{y0u_93t_7h3_3qu4710n_50lv3}，与原文一致；已注明原文文字相加得 K1+K3 与可复现代码 S=K1-K3 的符号差异
---

## 一句话结论

面对 a、b、c 三个未知量的对称多项式方程组，先用两式相加得到 `a³+b⁶` 的表达式，再把它代回第三式得到 `ac` 关于 b 的表达式，最后代入第二式并清分母，即可把三元方程组降为关于 b 的单变量高次多项式；用 Sage 求整数根得到 b，再回代求 a、c。

## 原理

- **消元目标**：三个方程三个未知量通常可用结式/Gröbner 消元，但手工题往往设计了对称结构，先做线性组合可以大幅降维。
- **第一步**：原文文字称将第 1、3 式相加得到 `a³ + b⁶ = K1 + K3`，但其可复现代码实际按 `S = K1 - K3` 计算（符号/两式相减约定与文字不同），记 `X = S - b⁶`，则 `a³ = X`；以能产出 flag 的代码为准。
- **第二步**：把 `a³` 代回第 3 式并整理，可把 `ac` 写成 b 的函数。按本题实现记 `T = K1 - (2/3)K3`、`Y = T - 2b⁶`，则 `ac = Y`（题面文字若写作 `H1+(2/3)H3`，以实现代码/验证结果为准）。
- **第三步**：第 2 式形如 `b⁵ + 6c³ + 2acb = K2`；用 `c = Y/a`、`a³ = X` 代入，`6c³ = 6Y³/X`，两边乘 X 得单变量多项式：
  ```text
  (b⁵ + 2bY - K2) * X + 6Y³ = 0
  ```
  其中 X、Y 都是 b 的多项式，展开后是一个关于 b 的高次整系数多项式。
- **求解与回代**：对多项式在整数环上求根（`P.roots(ring=ZZ)`），取满足 `a³ = X`、`Y % a == 0` 的根；`a = X` 的整数立方根（注意符号），`c = Y // a`。c 的字节形式通常就是 flag。
- **为什么成立**：题目把三个未知量压缩进少数几个幂次关系，线性组合后未知量之间的耦合被打破；剩余的单变量方程次数虽高，但整数根可由 Sage 直接分解/求根。

## 触发条件

- 给出 2~3 个关于 a、b、c 的多项式等式，未知量次数较高但结构对称。
- 存在可消去其他项的线性组合（如两式相加/相减）。
- 消元后得到的单变量多项式有整数/有理根，或可在 Sage 中分解。
- 明文/flag 可由某个未知量（示例 c）直接转换。

## 利用步骤

1. 抄下所有方程，标出各单项式系数；寻找两式相加/相减能消去大部分项的组合。
2. 得到 `a³`（或类似幂）关于 b 的表达式 X。
3. 把 `a³` 代回另一式，整理出 `ac`（或 a·c 的组合）关于 b 的表达式 Y。
4. 代入剩余方程，清分母，得到只含 b 的多项式。
5. 在 Sage 中用 `R.<b> = ZZ[]` 构造多项式并 `roots(ring=ZZ)`；对每个根回代求 a、c，验证整除/幂次条件。
6. 将 c 转字节得到 flag；若根不唯一，用 flag 格式或额外等式筛选。

## PoC

```python
from sage.all import *

S = K1 - K3
T = K1 - (2*K3)//3
R.<b> = ZZ[]
X = S - b^6
Y = T - 2*b^6

poly = (b^5 + 2*b*Y - K2)*X + 6*Y^3
roots = poly.roots(ring=ZZ)
b0 = roots[0][0]

X0 = S - b0^6
a0 = abs(X0).nth_root(3)
if X0 < 0:
    a0 = -a0
assert a0^3 == X0

Y0 = T - 2*b0^6
assert Y0 % a0 == 0
c0 = Y0 // a0

from Crypto.Util.number import long_to_bytes
print(long_to_bytes(int(c0)).decode())
```

原文数据求得 c 的字节形式：

```text
ISCTF{y0u_93t_7h3_3qu4710n_50lv3}
```

## 变体与关联

- 消元方式变体：若手工组合不明显，直接用 Sage 的 `resultant`/`groebner_basis` 消元，再对单变量多项式求根。
- 方程结构变体：对称多项式、幂和、Vieta 关系；核心是先降维再求根。
- 关联：[[ctf-crypto-power-tower-composite-modulus-crt]]（同为多步数学分解）、[[crypto-rsa-bivariate-coppersmith-two-small-roots]]（二元多项式小根）。
- 边界：多项式无整数根、次数过高导致分解困难，或方程组本身欠定时，需补充信息/改用数值方法。

## 检测与防御

- 检测：CTF 中看到多个高次对称等式，先尝试线性组合消元；用 Sage 验证根是否满足所有原方程。
- 防御：不要用可代数消元的低维多项式构造密钥/flag；密码协议应使用经过证明的难题（大整数分解、DLP 等）。
- 加固：若必须用代数结构，增加随机化与高次项，避免未知量被少量等式约束。
