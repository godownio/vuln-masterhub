---
id: crypto-rsa-known-p2-plus-q2-cornacchia-factor
title: RSA 泄露 p²+q²：Cornacchia 两平方和表示直接恢复 p、q 并解密
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-known-p2-plus-q2-cornacchia
tags:
- rsa
- cornacchia
- sum-of-two-squares
- diophantine
- factorization
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-08T01:03:04+08:00'
  notes: 已对照原文 EZsquares 题目源码与 WP 核对：p,q=getPrime(512)、n0=p^2+q^2、e=65537、c=pow(m,e,p*q)；WP 用 sympy cornacchia(1,1,n0) 遍历表示、assert a^2+b^2==n0、isPrime(a)/isPrime(b) 筛出 p,q 后求 d 解密，与卡内一句话结论/原理/步骤/PoC 完全一致。未验证点：本机未跑 sympy 复算（未执行原文脚本）；原文未输出 flag 明文，但解法闭环；frontmatter 无 sources/source_url；CTF 题无 affected_versions。kb show 存在；dedup 无 duplicate（related 14），最高相关 crypto-rsa-known-prime-sum-quadratic-factorization 是已知 p+q 解二次方程，与本卡已知 p^2+q^2/Cornacchia 已知条件与算法不同；dup-scan 中与 14885 m>n/hidden-e 两卡判 related，非同一链，保留。单卡单一原子（Cornacchia 平方和分解）。
url: /docs/crypto/rsa/crypto-rsa-known-p2-plus-q2-cornacchia-factor/
draft: false
kb_aliases:
- EZsquares
- p^2+q^2
- 平方和分解 RSA
- cornacchia
- two_squares
- 丢番图方程分解
---

## 一句话结论

当 RSA 题目给出 `n0 = p² + q²`（p、q 为 512bit 素数）而不给 `n = p·q` 时，用 Cornacchia 算法把 `n0` 表示为两个平方数之和（sympy `cornacchia(1,1,n0)` 或 Sage `two_squares(n0)`），过滤素数即得 p、q；再计算 `n = p·q`、`φ = (p-1)(q-1)`、`d = e⁻¹ mod φ` 即可正常解密。

## 原理

- Cornacchia 算法求解 `a·x² + b·y² = m`（本场景 a=b=1），在 `m` 可表示为两平方和且已知 `-1` 模 `m` 的平方根时可求出表示。`n0 = p² + q²` 本身就是一组解，因此算法能把它还原出来。
- `n0` 可能存在多组两平方和表示（例如乘以单位或不同分解），需要遍历返回结果，用 `a² + b² == n0` 校验并筛出两个素数；只有真正的 p、q 都是素数。
- 得到 p、q 后 RSA 与标准流程完全一致；`n0` 与 `n` 的冗余信息使分解从大整数分解降为平方和表示问题。
- sympy 的 `cornacchia(1,1,n0)` 返回所有满足 `x²+y²=n0` 的候选；Sage 的 `two_squares(n0)` 给出一个表示，可用 `is_prime` 判断是否直接是 p、q，若不是可结合其他表示或枚举。

## 触发条件

- 题目公开 `n0 = p² + q²`，且未直接给出 `n = p·q`；或同时给出 n 但可从 n0 分解。
- p、q 为素数（典型各 512bit），`n0` 约为 1024bit；`c`、`e` 已知。
- 环境具备 sympy（`sympy.solvers.diophantine.diophantine.cornacchia`）或 Sage（`two_squares`）。

## 利用步骤

1. 读取 `n0`、`c`、`e`。
2. 调用 `cornacchia(1,1,n0)`（或 `two_squares(n0)`）获取平方和表示。
3. 对每组 `(a,b)` 校验 `a²+b²==n0` 且 `isPrime(a) and isPrime(b)`，得到 p、q。
4. 计算 `n=p*q`、`φ=(p-1)*(q-1)`、`d=inverse(e,φ)`，解密 `m=pow(c,d,n)`，`long_to_bytes(m)` 得 flag。

## PoC

```python
from Crypto.Util.number import *
from sympy.solvers.diophantine.diophantine import cornacchia

n0 = 192573744538639130845868727014075967669513667763315934161849620531683536696376138303320681922782003088094539724238109116416456294472461075668568088688287209898850985024632463251984323888765249950269595045648435192047990940593817086918399212487934262786817996341234806934640246045717955941049031252181676005098
c = 1541487946178344665369701061600511101386703525091161664845860490319891364778119340877432325104511886045675705355836238082338561882984242433897307540689460550149990099278522355182552369360471907683216881430656993369902193583200864277424101240184767762679012998894182000556316811264544736356326198994294262682
e = 65537

for a, b in cornacchia(1, 1, n0):
    assert a*a + b*b == n0
    if isPrime(a) and isPrime(b):
        p, q = a, b
        n = p * q
        d = inverse(e, (p-1)*(q-1))
        print(long_to_bytes(pow(c, d, n)))
```

## 变体与关联

- Sage：`two_squares(n0)` 通常直接返回一组表示；若结果不是两个素数，可结合 `n0` 的其他表示或与已知 `n=pq` 联立。
- 平方和泄露的其他形式：`n0 = p² - q²` 可用平方差分解；`p+q` 已知可用二次方程求 p、q；`p²` 模数见完全平方模数卡。
- 若 `n0` 不是两平方和（`-1` 非二次剩余），Cornacchia 不适用，需要换其他冗余关系。

## 检测与防御

- 不要把 `p²+q²`、`p+q`、`p-q` 等素数冗余关系作为公开参数；RSA 公钥只应暴露 `n`、`e`。
- 生成密钥时使用标准库与足够大的随机素数；CTF 之外避免自定义泄露额外代数关系的素数生成方式。
