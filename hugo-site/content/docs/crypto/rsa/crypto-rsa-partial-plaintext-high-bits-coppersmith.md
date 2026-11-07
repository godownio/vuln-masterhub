---
id: crypto-rsa-partial-plaintext-high-bits-coppersmith
title: RSA 明文高位泄露：Coppersmith 一元小根恢复 m 的未知低位
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-partial-plaintext-high-bits-coppersmith
tags:
- rsa
- partial-plaintext
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
  verified_at: '2026-11-06T04:10:20+08:00'
  notes: 已对照原文核对：m=m<<100 后构造 (m+x)^3-c 并 small_roots，恢复低位后 long_to_bytes，与原文代码一致。未验证点：PoC 未本机复跑；原文为 CTF 教学示例无受影响版本；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-partial-plaintext-high-bits-coppersmith/
draft: false
kb_aliases:
- RSA 部分明文泄露
- 已知 m 高位
- Coppersmith 恢复明文低位
- partial plaintext Coppersmith
---

## 一句话结论

已知 RSA 明文 `m` 的高位、只缺末尾 `k` 位时，把 `m = m_hi·2^k + x` 代入密文方程得到模 `n` 的一元多项式 `f(x) = (m_hi·2^k + x)^e - c`，当未知位数 `k` 小于 Coppersmith 小根界（约 `n^(1/e)`）时，用 `small_roots` 可直接恢复 `x`。

## 原理

- 密文满足 `m^e ≡ c (mod n)`。把 `m` 拆成已知高位与未知低位：`m = m_hi·2^k + x`，其中 `0 ≤ x < 2^k`。
- 代入后得到 `f(x) = (m_hi·2^k + x)^e - c ≡ 0 (mod n)`，即 `m` 是 `f` 模 `n` 的一个小根。
- Coppersmith 一元小根定理：首一多项式 `f` 次数为 `e` 时，若 `|x| < n^(1/e)`，可在多项式时间内求出小根。`e=3` 时未知位数需小于约 `n` 的三分之一位数；1024 位模数下约 341 bit，示例只缺 100 bit，余量充足。
- 根恢复后 `m = m_hi·2^k + x`，再转字节即得明文。
- 若已知的是明文低位而不是高位，可设 `m = x·2^k + m_lo`，未知量 `x` 是高位部分，同样可构造多项式求小根；此时要求的是 `x` 的绝对值足够小。

## 触发条件

- 已知 `n`、`e`、`c`，以及 `m` 的连续高位（或可拼出高位）。
- 未知低位位数 `k` 小于 Coppersmith 界；`e` 越小越容易。
- `f` 的首项系数在模 `n` 下可逆（`e` 次项系数为 1，通常自动满足）。
- 能运行 Sage 的 `small_roots` 或等价格算法。

## 利用步骤

1. 确认泄露的是明文高位，估计未知位数 `k`，把已知部分左移 `k` 位得到 `m_hi·2^k`。
2. 在 `PolynomialRing(Zmod(n))` 中构造 `f = (m_hi·2^k + x)^e - c`。
3. 调 `f.small_roots(X=2^k)`；若失败，检查 `k` 是否超过界、是否应改用 `beta` 或增大格参数。
4. 对每个候选根 `x` 回代 `pow(m_hi·2^k+x, e, n) == c` 校验。
5. 把整数转字节，按题目格式提取 flag。

## PoC

```python
from gmpy2 import *
from Crypto.Util.number import *

n = ...
c = ...
m_hi = ...          # 已知的明文高位
SHIFT = 100         # 未知低位位数

PR.<x> = PolynomialRing(Zmod(n))
f = (m_hi * 2^SHIFT + x)^3 - c
roots = f.small_roots(X=2^SHIFT)
assert roots
x = int(roots[0])
m = m_hi * 2^SHIFT + x
assert pow(m, 3, n) == c % n
print(long_to_bytes(m))
```

## 变体与关联

- 变体：`e=3/5/7` 时分别对应约 `n^(1/3)`、`n^(1/5)`、`n^(1/7)` 的未知位上限；`e` 越大可容忍的缺失位越少。
- 变体：已知明文低位时改设 `m = x·2^k + m_lo`，求高位 `x`；若高位数值不小，需要重新评估界。
- 变体：明文由多个字段拼接、只有中间一段未知时，可把未知段当作一个整体变量。
- 关联：[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（完全不知道高位、密文未模约减时直接开立方）、[[crypto-rsa-partial-prime-high-bits-coppersmith]]（同类小根用于素数因子）、[[crypto-rsa-affine-broadcast-crt-coppersmith]]（多模数 CRT 后再求小根）。

## 检测与防御

- 防御：使用 OAEP 等随机化填充，使明文整数不呈现“已知高位 + 小未知段”的结构。
- 防御：不要向外部泄露明文的任何连续比特；调试日志、报错信息、截断输出都可能成为泄露源。
- 检测：代码/接口中出现明文前缀、截断的十六进制串、或 `m >> k` 之类的字段；CTF 中看到“已知 flag 前缀”与密文即可按本卡尝试。
- 响应：确认明文部分泄露后按密钥失陷处理，轮换密钥并审计同密钥下的历史密文。
