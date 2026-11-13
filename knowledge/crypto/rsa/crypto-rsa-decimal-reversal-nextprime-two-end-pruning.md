---
id: crypto-rsa-decimal-reversal-nextprime-two-end-pruning
title: RSA 十进制逆序 nextprime 素数：低/高位泄露与两端逐位剪枝分解
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-decimal-reversal-nextprime-two-end-pruning
aliases:
- 十进制逆序素数 RSA
- nextprime(reverse(p))
- 双首尾剪枝
- 两端搜索分解 n
- 数字位剪枝
tags:
- rsa
- factoring
- nextprime
- digit-pruning
- decimal-reversal
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V511
  verified_at: '2026-11-11T04:57:12+08:00'
  notes: 已通读原文 13424 第二篇并独立验证关系：q=nextprime(reverse_decimal(p))（31 位素数模拟，nextprime 偏移 48）下，b=q mod 10^6 与 10^6 互素，枚举 i·b≡n (mod 10^6) 得到 p mod 10^6=202439 与原 p 一致；qhigh=reverse(plow) 等于 q 的高 6 位；phigh=reverse(b−offset) 等于 p 的高 6 位，均验证通过。卡中正确指出 a=p&10^6 是按位与且原文 exp 未使用，以及两端 DFS 的三条剪枝（0/9 乘积上下界、低位乘积同余）和不用 b 时的低 4 位爆破变体与原文代码一致。原文无图片。dedup 报告 new，候选均非同链。
---

## 一句话结论

当 RSA 素数满足 `q = nextprime(int(str(p)[::-1]))`（q 是 p 的十进制逆序再取下一个素数）且泄露 `b = q mod 10^6`（或仅给 n）时，可利用“q 的低位 = p 高位的逆序加一个小于约 2000 的 nextprime 偏移”这一关系，先由 `n mod 10^6 = p·q mod 10^6` 反解 p 的低位、再爆破偏移得到 p/q 的高位，最后从两端向中间逐十进制位搜索，用乘积上下界与低位乘积同余剪枝，快速分解 n。

## 原理

- **生成关系**：`p` 为随机 512 位素数（十进制 155 位），`q = nextprime(reverse_decimal(p))`。`reverse_decimal(p)` 的高位来自 p 的低位，低位来自 p 的高位；`nextprime` 通常只把数值增加不到约 2000，因此只影响低位。
- **由 b 反解 p 低位**：已知 `b = q mod 10^6`。因为 `n = p·q`，有 `n mod 10^6 ≡ p·b (mod 10^6)`。q 为奇素数且不含因子 5，`b` 与 `10^6` 互素，故 `p mod 10^6 ≡ n·b^{-1} (mod 10^6)`；题目脚本也可用枚举 `i·b ≡ n (mod 10^6)` 得到 p 的低 6 位 `plow`。注意题目里的 `a = p & 10^6` 是**按位与**而非取模，实验中并未使用；真正有用的是 `b`（或直接爆破 q 的低位）。
- **由低位关系推高位**：`q` 的低 6 位 `b` 等于 `reverse_decimal(p)` 的低 6 位加上 nextprime 偏移后取模，而 `reverse_decimal(p)` 的低 6 位正是 p 高 6 位的逆序。于是对偏移 `i < 2000`（必要时取模处理负数）计算 `phigh = reverse_decimal(b − i)`，用 `phigh`、`qhigh=reverse(plow)` 填充 0/9 校验 `p_low_bound·q_low_bound < n < p_high_bound·q_high_bound` 选出候选。
- **两端搜索**：把 p、q 的十进制表示从两端同时确定：已知 `ph`/`qh`（高位部分）与 `pl`/`ql`（低位部分），每一步尝试高位各加一个数字、低位各加一个数字（10×10 种），用三条剪枝：
  1. 未定位的位全填 0 时 `p·q < n`；
  2. 未定位的位全填 9 时 `p·q > n`；
  3. 低 k 位乘积同余：`(pl·ql) mod 10^k == n mod 10^k`。
- **中位收尾**：p、q 的十进制长度为奇数（155 位）时，两端搜索到剩中间一位，枚举 0..9 并检查 `n % p == 0` 即可。
- **为什么快**：每一位都同时受大小上下界与低位同余约束，绝大多数分支被剪掉；10×10 的分支在十几层内收敛，而 155 位暴力不可行。
- **第二解法（不用 b）**：直接爆破 q 的低 4 位（偏移最多几千，4 位足够），由 `(p_low·q_low) ≡ n (mod 10^4)` 解 p 低位，再用 nextprime 偏移关系推高位；注意 `b−i` 可能为负，要加 `10^4` 并 `zfill(4)` 补足四位。

## 触发条件

- RSA 的两个素数由十进制逆序 + `nextprime` 生成（q 与 reverse(p) 数值接近）。
- 已知 n、e、c；额外泄露 q 的低 6 位（b），或完全不泄露但可接受爆破低 4 位。
- p/q 的十进制位数足够长（搜索空间靠剪枝而不是暴力）。

## 利用步骤

1. 由 `b = q mod 10^6`（或枚举 q 低 4 位）与 `n mod 10^6` 反解 p 的低位 `plow`。
2. 取 `qhigh = reverse(plow)`；对 nextprime 偏移 i∈[0,2000) 计算候选 `phigh = reverse(b−i)`（负数补 `10^6`），用 0/9 填充的乘积上下界筛选。
3. 以 `(phigh,qhigh,plow,qlow)` 为初态做两端 DFS：每步枚举高位/低位各 0..9，按三条剪枝递归。
4. 长度为奇数时剩中间一位，枚举并检查整除，得到 p，`q=n//p`。
5. 计算 `d = inverse(e, (p−1)(q−1))` 解密得到 flag。

## PoC

```python
from Crypto.Util.number import inverse, long_to_bytes
import sys
sys.setrecursionlimit(100000)

def dec(p, q, c, n):
    d = inverse(65537, (p - 1) * (q - 1))
    print(long_to_bytes(pow(c, d, n)))

def find(ph, qh, pl, ql):
    pad0 = (dec_len - len(ph) - len(pl)) * "0"
    pad9 = (dec_len - len(ph) - len(pl)) * "9"
    if int(qh + pad0 + ql) * int(ph + pad0 + pl) > n:
        return
    if int(qh + pad9 + ql) * int(ph + pad9 + pl) < n:
        return
    mask = 10 ** len(pl)
    if (int(ql) * int(pl)) % mask != n % mask:
        return
    if len(ph + pl) == dec_len - 1:
        for i in range(10):
            if n % int(ph + str(i) + pl) == 0:
                p = int(ph + str(i) + pl)
                dec(p, n // p, c, n)
                exit()
    for i in range(10):
        for j in range(10):
            find(ph + str(i), qh + str(j), str(j) + pl, str(i) + ql)

# 由 b 求 plow（b 与 10^6 互素）
plow = next(i for i in range(10**6) if (i * b) % 10**6 == n % 10**6)
qhigh = str(plow)[::-1]
for off in range(2000):
    phigh = str(b - off)[::-1]
    if len(phigh) < 6:
        continue
    if int(phigh + "0" * (dec_len - 6)) * int(qhigh + "0" * (dec_len - 6)) < n \
       and int(phigh + "9" * (dec_len - 6)) * int(qhigh + "9" * (dec_len - 6)) > n:
        break
find(phigh, qhigh, str(plow), str(b))
```

## 变体与关联

- **二进制逆序版**：`q = nextprime(reverse_binary(p))`，用位移/位剪枝；十进制版只是把进位规则从 2 换成 10。
- **无 b 版**：爆破 q 低位 4 位即可，因为 nextprime 偏移有限；文章给了完整第二种 exp。
- **关联卡**：`crypto-rsa-permutation-count-nextprime`（nextprime 生成缺陷）、`crypto-rsa-low-bit-nonlinear-leak-bitlifting`（低位泄露逐位恢复）。
- **边界**：若 nextprime 偏移超过爆破范围、或 p/q 长度不同（逆序后高位/低位对应关系改变），需要调整位数与候选范围；搜索剪枝依赖 n 的十进制长度。

## 检测与防御

- **CTF/实现侧**：不要用“逆序素数 + nextprime”这类结构化方式生成 RSA 素数；素数应独立随机选取。
- **审计**：检查 p、q 的十进制/二进制表示是否存在镜像、重复、固定前缀等关系；对 n 做常规分解与结构化检测。
- **防御**：使用标准密钥生成库并校验素数独立性；不要把 q 的低位、随机种子或偏移量泄露给攻击者。
