---
id: crypto-rsa-rabin-random-square-root-oracle
title: Rabin 随机平方根预言机：两次 sqrt(a²) 查询用 gcd(a-y,N) 分解 1023 位模数
type: scenario
domain: crypto
path: crypto/rsa
technique: rabin-random-square-root-oracle
tags:
- rabin
- rsa
- oracle
- square-root
- factorization
- gcd
- tonelli-shanks
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:23+08:00'
  notes: 对照 Crypto246：sqrt 随机根、gcd(a-y,N) 分解、四根 CRT 与 parity/jacobi 筛选一致；未复跑
url: /docs/crypto/rsa/crypto-rsa-rabin-random-square-root-oracle/
draft: false
kb_aliases:
- QuadGuard
- Rabin 解密预言机
- sqrt 预言机分解 N
- 随机平方根 四根
- gcd(a-y,N) 因子
- parity jacobi 提示位
---

## 一句话结论

Rabin 加密的安全性依赖攻击者不知道四个平方根中是哪一个；当服务提供 `sqrt(x)` 并随机返回一个平方根时，攻击者提交 `a² mod N`，有 1/2 概率拿到 `±a` 之外的根，此时 `gcd(a-y,N)` 直接给出 p 或 q，期望两次查询即可分解任意位数的 N。

## 原理

- Rabin 加密是 `c = m² mod N`（N=pq，e=2）。在 `Z_N^*` 中每个二次剩余恰有 4 个平方根：`±x mod p` 与 `±x mod q` 的四种组合。
- 攻击者随机选 `a`，计算 `x=a² mod N` 并提交给 `sqrt` 预言机。预言机返回某个平方根 `y`：
  - 若 `y ≡ ±a mod p` 且 `y ≡ ±a mod q`（即 `y=±a mod N`，概率 1/2），`a-y ≡ 0 mod N`，`gcd` 为 N，无信息；
  - 若 `y` 是另外两个根（概率 1/2），则 `y` 在一个素因子下等于 `a`、在另一个下等于 `-a`，于是 `a-y` 与 N 共享且仅共享一个因子，`gcd(a-y,N)` 给出 p 或 q。
- 因此“随机返回平方根”等价于 Rabin 解密预言机：分解 N 的期望查询次数为 2，与模数位数无关。这是接口设计缺陷，不是算法被破解。
- 题目还直接给出 `parity=1`、`jacobi=1` 等提示位。标准 Rabin 中选根信息应由冗余编码承担，这里作为参数公开，等于把“四个根中选哪个”的信息交给攻击者；拿到 p、q 后可用这些提示位和 flag 格式筛出正确明文。

## 触发条件

- 服务实现 Rabin 加密/解密接口（`e=2`，无 e 或未给出 e）。
- 提供 `sqrt(x)` 类预言机，对任意二次剩余返回一个平方根，且根的选择是随机的（或至少可能是非 `±a` 的根）。
- 攻击者能在单次连接内完成查询与后续解密（每次连接 N 随机时尤其重要）。
- 目标明文有可识别格式（flag 前缀/后缀、parity/jacobi 约束、长度等）用于四选一。

## 利用步骤

1. 解析服务给出的 N、c 与提示位 parity/jacobi；确认 `sqrt` 命令可用。
2. 随机选 `a`，提交 `sqrt(a*a % N)`，取回根 `y`。
3. 计算 `g=gcd(a-y,N)`；若 `1<g<N` 即得到 p 或 q，否则换 `a` 重试（期望 2 次）。
4. 用 p、q 和 Tonelli-Shanks（如 `sympy.sqrt_mod`）求 c 在 p、q 下的平方根，再用 CRT 组合出 4 个根。
5. 按 parity/jacobi、flag 前缀/后缀、长度、可打印性筛出真正明文。

## PoC

```python
from math import gcd
from sympy.ntheory.residue_ntheory import sqrt_mod

t = Tube()                      # 已连接服务，解析出 t.N / t.c
g = None
for _ in range(200):
    a = randrange(2, t.N - 1)
    y = t.sqrt(a * a % t.N)
    if y is None or y * y % t.N != a * a % t.N:
        continue
    g = gcd(a - y, t.N)
    if 1 < g < t.N:
        break

p, q = g, t.N // g
rp, rq = sqrt_mod(t.c, p), sqrt_mod(t.c, q)
for s1 in (rp, p - rp):
    for s2 in (rq, q - rq):
        m = (s1 * q * pow(q, -1, p) + s2 * p * pow(p, -1, q)) % t.N
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if b"flag" in raw:
            print(raw)
```

## 变体与关联

- 变体：预言机返回“任一平方根”而非随机根时，若总是返回 `a` 的确定分支则无信息；需要找能控制/观察分支的接口。
- 变体：RSA 解密预言机（返回明文）也可用类似思路做 Bleichenbacher/Manger 类攻击；Rabin 的 gcd 法是最直接的形式。
- 关联：[[crypto-rsa-common-modulus]]（gcd 分解）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（另一种 RSA 参数缺陷）。
- 边界：需要 `sqrt` 确实返回非 `±a` 的根的概率；若服务只对特定格式的 x 响应、或 N 不满足 p≡q≡3 mod 4，Tonelli-Shanks 仍可用；每次连接 N 随机时必须单连接闭环。

## 检测与防御

- 检测：接口暴露 `sqrt`/平方根/解密 oracle；同一客户端短时间内大量提交完全平方数；响应中出现可预测的根选择偏差。
- 修复：不要向不可信方提供平方根预言机；Rabin 解密必须使用带冗余的编码并在内部选根，不把四个根或选根提示暴露给调用方。
- 加固：对预言机接口做认证、限速与审计；明文加随机填充/哈希校验；密钥与模数定期轮换；使用标准化的加密库而不是自定义 Rabin 接口。
