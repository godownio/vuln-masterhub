---
id: crypto-rsa-low-bit-nonlinear-leak-bitlifting
title: RSA 低位非线性泄漏 bit-lifting：逐位枚举 p/q 使 N 与 leak 的低位同时一致
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-low-bit-nonlinear-leak-bitlifting
tags:
- crypto
- rsa
- partial-key-exposure
- bit-lifting
- low-bits
- leak
- factorization
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:40:09+08:00'
  notes: 已对照原文rsa Level3与图60核对：从p,q为奇数(1,1)起逐位枚举，要求p*q≡n mod 2^(k+1)且leak_mod(p,q,k+1)≡leak，循环range(1,1536)，leak表达式含p*C1^q*C2^(p&q)<<64^(p|q)<<48^(p^q)*C3、S=(p+q)&(2^128-1)、T=(p*q)&(2^64-1)、L=(A+S)^T，与原文逐行一致。PoC已用原文n/c/leak本机复跑，恢复3072-bit n的p/q并解出dart{379c9308-e9a8-45a1-bd55-45bbd822e86d}。未验证点：CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-low-bit-nonlinear-leak-bitlifting/
draft: false
kb_aliases:
- bit-lifting 分解 RSA
- p/q 低位泄漏
- 非线性 leak 恢复
- 部分密钥泄漏
- 逐位枚举分解 N
- 阿里CTF rsa level3
---

## 一句话结论

如果 RSA 除 `N=p·q` 外还泄漏了 `f(p,q)` 的低若干位（`f` 由乘法、加法、AND/OR/XOR、移位等 2-adic 局部运算组成），可以从 `p,q` 均为奇数出发，按位枚举 `(p_k,q_k) ∈ {0,1}²`，同时要求 `p·q ≡ N (mod 2^{k+1})` 且 `f(p,q) ≡ leak (mod 2^{k+1})`；每加一位只保留极少数候选，逐位提升到 `p,q` 的真实位长即可完整分解 `N`，再求 `d` 解密。

## 原理

- **低位局部性**：对整数做加、减、乘、按位与/或/异或、左移，结果的低 `k+1` 位只取决于操作数的低 `k+1` 位（不进位到更高位）。因此若 `f(p,q)` 只由这些运算组成，`f(p,q) mod 2^{k+1}` 只依赖 `p mod 2^{k+1}` 与 `q mod 2^{k+1}`。
- **已知 N 的约束**：`p·q = N`，所以对任意 `k` 都有 `p·q ≡ N (mod 2^{k+1})`。这条约束单独就能逐位枚举因子，但分支可能较多（尤其当 `N` 的低位有重复结构时）。
- **leak 的第二条约束**：泄漏 `L = f(p,q) mod 2^K` 再提供一条同余式 `f(p,q) ≡ L (mod 2^{k+1})`。两条约束联合后，每加一位通常只剩 1 个候选（最坏也很少），从而把搜索空间从 `2^{2n}` 降到线性。
- **起点**：`p,q` 均为奇数，所以最低位 `p_0=q_0=1`，候选集从 `{(1,1)}` 开始。
- **逐位提升**：设当前已恢复低 `k` 位 `(p0,q0)`，枚举 `pb,qb ∈ {0,1}` 得到
  `p = p0 | (pb << k)`、`q = q0 | (qb << k)`；用 `mask = 2^{k+1}-1` 检查
  `(p*q) & mask == N & mask` 且 `leak_mod(p,q,k+1) == L & mask`；符合的加入下一轮。
- **终止**：当 `p*q == N`（或枚举位数达到 `p,q` 的位长）时，`candidates[0]` 就是 `(p,q)`；计算 `φ=(p−1)(q−1)`、`d=e^{−1} mod φ`、`m=c^d mod N`。
- 原文的 leak 函数（Level3）：
  ```text
  A = (p*C1) ^ (q*C2) ^ ((p&q)<<64) ^ ((p|q)<<48) ^ ((p^q)*C3)
  S = (p+q) & (2^128 - 1)
  T = (p*q) & (2^64 - 1)
  L = (A + S) ^ T
  leak = L mod 2^k
  ```
  其中 `C1/C2/C3` 为固定常量。`A` 混合了 `p*q` 型乘法、`p&q`、`p|q`、`p^q` 与移位，`S` 引入 `p+q`，`T` 再引入 `p*q` 的低 64 位；这些都为低位提供独立约束。

## 触发条件

- 已知 `N,e,c`（或只需要分解 `N`）；
- 额外泄漏 `L = f(p,q) mod 2^K`，`f` 的表达式已知且只含低位局部运算；
- `K` 足够覆盖 `p,q` 的位长（至少到 `p*q == N` 可验证为止；原文循环 1536 位）；
- `p,q` 为奇数；泄漏值没有噪声（有噪声时需容错/多候选搜索）。

## 利用步骤

1. 确认 `f` 只含加、乘、位运算与移位；写出 `leak_mod(p,q,k)`。
2. 初始化候选 `[(1,1)]`。
3. 对 `k = 1..K-1`：
   - `mask = (1<<(k+1))-1`，目标 `N_low = N & mask`、`L_low = leak & mask`；
   - 对每个候选 `(p0,q0)` 枚举 `(pb,qb)`，拼接第 `k` 位；
   - 保留 `p*q & mask == N_low` 且 `leak_mod(p,q,k+1) == L_low` 的候选。
4. 若候选为空，说明 leak 表达式/常量或某位假设有误；若候选过多，继续多位或增加约束。
5. 当 `p*q == N` 时输出 `p,q`；计算 `d` 解密，验证明文格式。

## PoC

```python
from Crypto.Util.number import long_to_bytes

CONST1 = 0xDEADBEEFCAFEBABE123456789ABCDEFFEDCBA9876543210
CONST2 = 0xCAFEBABEDEADBEEF123456789ABCDEF0123456789ABCDEF
CONST3 = 0x123456789ABCDEFFEDCBA9876543210FEDCBA987654321
MOD128 = 2 ** 128
MASK64 = (1 << 64) - 1

def leak_mod(p, q, k):
    A = (p * CONST1) ^ (q * CONST2) ^ ((p & q) << 64) ^ ((p | q) << 48) ^ ((p ^ q) * CONST3)
    S = (p + q) & (MOD128 - 1)
    T = (p * q) & MASK64
    return ((A + S) ^ T) & ((1 << k) - 1)

def recover(n, leak, bits):
    candidates = [(1, 1)]                 # p, q 均为奇数
    for k in range(1, bits):
        mask = (1 << (k + 1)) - 1
        target_n, target_leak = n & mask, leak & mask
        nxt = []
        for p0, q0 in candidates:
            for pb in (0, 1):
                for qb in (0, 1):
                    p = p0 | (pb << k)
                    q = q0 | (qb << k)
                    if (p * q) & mask != target_n:
                        continue
                    if leak_mod(p, q, k + 1) != target_leak:
                        continue
                    nxt.append((p, q))
        candidates = nxt
        for p, q in candidates:
            if p * q == n:
                return p, q
    return candidates[0] if candidates else None

# n, e, c, leak = <目标数据>
# p, q = recover(n, leak, 1536)
# phi = (p - 1) * (q - 1)
# d = pow(e, -1, phi)
# print(long_to_bytes(pow(c, d, n)))
```

原文 Level3 用 `range(1, 1536)` 逐位恢复，最终 `pow(c,d,n)` 得到 flag。

## 变体与关联

- 若泄漏的是 `p` 或 `q` 的低位，直接 Coppersmith 小根即可，不需要 bit-lifting。
- 若泄漏的是 `d` 的低位，可用 `e·d − 1 = k·φ(n)` 对 `k` 枚举 + `solve_mod` 求 `p` 低位，再用 Coppersmith 补全。
- 若泄漏的是高位，走 Coppersmith 部分密钥攻击（已知 `p` 高位恢复低位）。
- 关联 [[crypto-rsa-private-exponent-low-bits-partial-p]]：`d` 低位泄漏的同类问题。
- 关联 [[crypto-rsa-crt-multi-modulus-high-bits-coppersmith-low-bits]]：高位分片 + Coppersmith 的路线。
- 关联 [[ctf-crypto-z3-short-input-128bit-state-constraint]]：把低位约束交给求解器的另一种实现。
- 边界：leak 含除法、取模大数、浮点或噪声时低位局部性被破坏；泄漏位数不足或表达式常量未知时无法唯一恢复。

## 检测与防御

- 不要向外泄漏任何与 `p,q` 相关的函数值（包括哈希前的中间量、调试日志、错误信息、时间/功耗侧信道）。
- 私钥运算使用恒定时间、盲化与硬件隔离；RSA 密钥定期轮换，避免长期泄漏累积。
- 生成密钥时确保 `p,q` 随机且不可预测；不要使用可被低位约束反推的弱素数生成器。
- 检测：异常的大量“分解/低位”查询、泄漏 `N` 之外模数相关值的 API、CTF 环境中可直接用本卡脚本验证。
