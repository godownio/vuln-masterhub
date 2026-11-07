---
id: crypto-rsa-small-exponent-multiround-close-prime-crt-backtrack
title: RSA 小指数 e=19 多轮加密 + 相邻素数模数：GF(p)/GF(q) 求根、CRT 组合并按位长回溯（初始 1 轮 + 重复 25 轮，共 26 个模数）
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-small-exponent-multiround-close-prime-crt-backtrack
tags:
- crypto
- rsa
- small-exponent
- crt
- finite-field
- root-finding
- close-primes
- multi-round
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:35:42+08:00'
  notes: 已对照原文 crypto2 代码与 img10 核对：初始 encrypt 1 次 + 循环 25 次共 26 个 N、q=next_prime(p)、isqrt 附近恢复 p/q、GF(p)/GF(q) 求根、CRT、位长过滤、逐轮回溯与 flag DASCTF{903c2394-feaa-4a22-9c4c-1f448f789849} 均一致；已将卡内 25 轮/25 层/25 个模数修正为 26 个模数（初始 1 轮+重复 25 轮）。与 Hastad 广播、dp 复合模数卡为 related，非重复。未验证点：未本机复跑 Sage。
url: /docs/crypto/rsa/crypto-rsa-small-exponent-multiround-close-prime-crt-backtrack/
draft: false
kb_aliases:
- 多轮 RSA 回溯
- e=19 小指数
- 相邻素数模数
- GF(p) 求根
- CRT 组合候选
- 26 个模数（初始 1 轮 + 重复 25 轮）
- 有限域多项式求根
---

## 一句话结论

题目用 e=19 对明文先加密 1 轮、再重复加密 25 轮（共 26 个模数），每轮都用 `p` 与 `q=next_prime(p)` 生成的相邻素数模数 `N=p*q`，并输出全部 N 与最终密文；由于 N≈p² 可在 `isqrt(N)` 附近分解出 p、q，再对每轮密文在 GF(p)、GF(q) 上求 `x^e≡C` 的全部根并用 CRT 组合，按明文位长过滤候选，即可从最后一轮逐轮回推到初始明文。

## 原理

- **相邻素数使 N 可分解**：生成方式保证 `q=next_prime(p)`，即 p、q 是相邻素数，`N=p*q≈p²`。取 `s=isqrt(N)+1`，`q=next_prime(s)`、`p=previous_prime(q)`（必要时微调），验证 `p*q==N` 即可恢复因子；不需要通用大数分解。
- **小指数使有限域求根可行**：e=19 很小，`C = m^e mod N`。分别在 GF(p)、GF(q) 上求多项式 `x^e - C` 的根，得到模 p 与模 q 的所有候选；用 CRT 组合成模 N 的候选。每侧最多 e 个根，组合数有界。
- **位长过滤压缩候选**：明文长度由 p 的 bit length 决定（原题 `bit_len=(m.bit_length()//2)+8`，对应明文位长 `2*(L-8)` 或 `2*(L-8)+1`），只保留位长符合的候选，候选集不会爆炸。
- **多轮回溯**：每轮输出 C 作为下一轮明文，形成 26 层嵌套。从最终 C 开始，用最后一轮的 N 求根、过滤，得到上一轮 C 的候选集合；再对该集合逐个用上一轮 N 求根，逐层向前，直到第一轮得到初始 m。
- **为什么能唯一化**：每层候选数受 e 与位长约束；26 层回溯后通常只剩一个可解码为 flag 格式的候选。若出现多个，继续向前回溯或按 flag 前缀筛选。
- **根因**：素数生成过弱（相邻素数、`p-1` 被 e² 整除）、指数过小、重复加密未加随机化填充。

## 触发条件

- 多轮 RSA 使用同一小指数 e（如 19），每轮重新生成相邻素数 p、q。
- 题目公开每轮的 N 与最终密文 C；明文长度可由 p 的位长推断。
- 能在 SageMath 中做 GF(p) 多项式求根与 CRT。
- 明文在每轮中都小于模数（RSA 正常加密前提）。

## 利用步骤

1. 收集所有 N（按加密顺序）和最终 C、e。
2. 对每个 N，用 `isqrt(N)+1` 附近的 `next_prime/previous_prime` 恢复 p、q，验证乘积。
3. 由 p 的 bit length 计算允许的明文位长集合。
4. 从最后一轮开始：对当前密文集合中的每个 x，在 GF(p)、GF(q) 上分别求 `x^e - x_cipher` 的根，CRT 组合，保留位长符合的候选；得到上一轮密文候选集。
5. 重复步骤 4 直到第一轮，得到初始 m 的候选；`long_to_bytes` 后按 flag 格式筛选。
6. 输出 flag。

## PoC

Sage（原文脚本核心）：

```python
from sage.all import *

def fsp(N):
    s = isqrt(N) + 1
    q = next_prime(s)
    p = previous_prime(q)
    if p * q != N:
        q = next_prime(s + 1)
        p = previous_prime(q)
    return int(p), int(q)

def eroot(y, p, e):
    F = GF(p)
    R.<x> = PolynomialRing(F)
    return [int(r[0]) for r in (x^e - F(y)).roots()]

def alens(p):
    L = int(p).bit_length()
    return {2 * (L - 8), 2 * (L - 8) + 1}

def itob(n):
    n = int(n)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b"\x00"

N = [ ... ]      # 26 个模数，按加密顺序
e = 19
C = ...          # 最终密文

c = {C}
for i in range(len(N) - 1, -1, -1):
    p, q = fsp(N[i])
    bl = alens(p)
    nc = set()
    for x in c:
        for rp in eroot(x, p, e):
            for rq in eroot(x, q, e):
                y = crt([rp, rq], [p, q])
                if int(y).bit_length() in bl:
                    nc.add(int(y))
    c = nc
    print(f"[{i+1}] {len(c)}")

for m in sorted(c):
    print("Result:", itob(m).decode(errors="ignore"))
```

原文运行结果：`DASCTF{903c2394-feaa-4a22-9c4c-1f448f789849}`。

## 变体与关联

- 素数关系变体：`q=next_prime(p)`、`q=p+2`、`p` 与 `q` 共享高位；只要 N 能在 sqrt 附近分解即可。
- 指数变体：e=3/5/17/19 等小指数；e 越小根数越少，回溯越容易。
- 过滤变体：按明文位长、flag 前缀、可打印字符、padding 结构筛选候选。
- 轮数变体：2 轮以上即可套用；轮数越多候选集越需要过滤策略。
- 关联卡片：[[crypto-rsa-next-prime-square-moduli-continued-fraction]]（相邻素数模数分解）、[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（小指数直接开方）、[[crypto-rsa-crt-multi-modulus-high-bits-coppersmith-low-bits]]、[[crypto-rsa-small-message-polynomial-root]]。
- 边界：若每轮使用不同小指数或大指数，求根不可行；若明文未做位长过滤导致候选爆炸，需要额外约束。

## 检测与防御

- 不要使用相邻素数生成 RSA 模数；使用密码学安全随机素数并验证 `|p-q|` 足够大。
- 不要用小指数（e=3/19）直接加密无填充明文；使用 OAEP 等随机化填充，确保每次加密结果不同。
- 避免对同一明文做多轮“裸 RSA”嵌套；需要多层时使用标准 KEM/DEM 结构。
- 红队侧：看到多个 N 与单个最终 C、e 较小且模数可分解时，优先尝试逐轮有限域求根 + CRT 回溯。
