---
id: crypto-rsa-polynomial-derivative-hidden-exponent-enum
title: RSA 隐藏私钥指数 c 的多项式导数泄露：量级差恢复系数 + 枚举 8-bit k
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-polynomial-derivative-coefficient-recovery-small-k-enum
aliases:
- polarisCTF 神秘学
- RSA 三次多项式
- 导数泄露
- 隐藏指数 c
- 8-bit k 枚举
- get_poly
tags:
- crypto
- rsa
- polynomial
- derivative-leak
- small-parameter-enum
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:07+08:00'
  notes: 已对照原文核对：f(x)=x^3-a x^2+b x-c-kn、f'(x)=3x^2-2ax+b、x1 约 511 bit 与 a/b 约 120 bit 的量级差、T=3x1^2-deriv1_num、a=T//(2x1)+1、b 回代、c=x1^3-a x1^2+b x1-kn、枚举 8-bit 素数 k、k=173 与 flag xmctf{e6d787beb9230217e692e130f718cdeb} 均一致。未验证点：PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

题目把 RSA 私钥指数 `c` 藏在三次多项式 `f(x)=x^3-a x^2+b x-c-k n` 的常数项里，只泄露某点 `x1` 的一阶导数；由于 `x1` 是 511 bit 而 `a,b` 只有约 120 bit，`2a x1` 压倒 `b`，可由导数恢复 `a,b`，再把 `c` 写成 `x1^3-a x1^2+b x1-k n`，枚举 `k` 的全部 8-bit 素数并检查明文前缀即可解出。

## 原理

- **RSA 结构**：`e = inverse(c, phi)`，`cipher = m^e mod n`；只要恢复 `c`，就有 `m = cipher^c mod n`。
- **多项式与导数**：`f(x) = x^3 - a x^2 + b x - c - k n`，`f'(x) = 3x^2 - 2a x + b`。题目输出 `x1` 与 `deriv1_num = f'(x1)`。
- **量级差**：`x1` 约 511 bit，`a,b` 约 120 bit，因此 `2a x1` 远大于 `b`。令 `T = 3x1^2 - deriv1_num = 2a x1 - b`，则 `a = floor(T/(2x1)) + 1`（`b` 只是小修正），`b = deriv1_num - 3x1^2 + 2a x1`。
- **恢复 c**：由 `f(x1) = 0 mod n` 得 `c = x1^3 - a x1^2 + b x1 - k n`（在整数上成立，`k` 为多项式构造时的乘数）。
- **枚举 k**：`k = getPrime(8)`，即 8-bit 素数，只有几十个。对每个 `k` 计算 `c`，再算 `m = cipher^c mod n`，检查明文是否以已知 flag 前缀开头；唯一命中即正确。
- **为什么可行**：直接枚举 `c` 是 1024-bit 空间不可行；但导数泄露把 `a,b` 固定，`c` 只随 8-bit `k` 变化，搜索空间从 2^1024 降到几十次模幂。
- **注意**：`a` 的取整方向依赖 `b` 的符号/大小；用 `b` 回代验证 `deriv1_num` 是否一致，必要时在 `floor` 附近微调。

## 触发条件

- RSA 使用自定义指数关系 `e = inverse(c, phi)`，且 `c` 被嵌入某个含 `n` 倍数的多项式。
- 题目泄露多项式在某点的导数值，且 `x1` 与系数 `a,b` 存在明显量级差。
- `k` 是小空间参数（如 8-bit 素数），可枚举。
- 已知明文前缀（如 `flag{`）用于唯一筛选。
- 攻击者能拿到 `n`、`e`、`cipher`、`x1`、`deriv1_num`。

## 利用步骤

1. 由 `T = 3*x1*x1 - deriv1_num`，计算 `a = T // (2*x1) + 1`，再回代 `b = deriv1_num - 3*x1*x1 + 2*a*x1`。
2. 验证 `3*x1^2 - 2*a*x1 + b == deriv1_num`；若不等，在 `a` 附近枚举 ±1 修正。
3. 对 `k` 取 8-bit 素数（`primerange(2,256)`），计算 `c = x1^3 - a*x1^2 + b*x1 - k*n`。
4. 计算 `m = pow(cipher, c, n)`，转字节并检查是否以 `flag{`/`xmctf{` 等前缀开头。
5. 命中后输出明文；若多个候选，增加前缀长度或检查可打印性。

## PoC

```python
from sympy import primerange

n = ...; x1 = ...; deriv1_num = ...; cipher = ...

T = 3 * x1 * x1 - deriv1_num
a = T // (2 * x1) + 1
b = deriv1_num - 3 * x1 * x1 + 2 * a * x1
assert 3 * x1 * x1 - 2 * a * x1 + b == deriv1_num

for k in primerange(2, 256):
    c = x1 ** 3 - a * x1 ** 2 + b * x1 - k * n
    m = pow(cipher, c, n)
    msg = m.to_bytes((m.bit_length() + 7) // 8, "big")
    if msg.lower().startswith(b"xmctf{"):
        print(k, msg.decode())
        break
```

```text
# 例：k=173，明文 xmctf{e6d787beb9230217e692e130f718cdeb}
```

## 变体与关联

- 多项式变体：三次式可换成二次/四次，只要导数泄露足以恢复除 `c` 外的系数；量级差是关键。
- 参数变体：`k` 可换成小范围整数、小素数、时间戳等；搜索空间越大越需要更多泄露。
- 关联：[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（小指数直接开方）、[[crypto-rsa-franklin-reiter-affine-related-message]]（相关明文 GCD）、[[crypto-rsa-partial-plaintext-high-bits-coppersmith]]（部分明文泄露）。

## 检测与防御

- 检测：自定义 RSA 实现中指数由隐藏参数派生；题目/接口泄露多项式系数或导数值；`k` 等参数空间过小。
- 防御：使用标准 RSA 密钥生成（`e=65537`，随机 `d`），不要把私钥指数嵌入可泄露的代数结构；避免小参数空间；使用 OAEP 填充。
- 加固：对错误信息/调试输出做脱敏；密钥材料不要参与可被观测的多项式运算；定期轮换密钥。
