---
id: crypto-rsa-common-private-exponent-multiprime-lattice
title: 多组 RSA 公钥共用私钥指数 d：LLL 共私钥指数攻击恢复 d 并分解多素数模数
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-common-private-exponent-multiprime-lattice
tags:
- rsa
- lattice
- lll
- common-private-exponent
- multiprime
- key-reuse
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:14:34+08:00'
  notes: 已对照原文核对：5 组三素数(1536-bit)模数共用 425-bit d、M≈N^{2/3} 的 (t+1) 维格、LLL 恢复 d、k_i=e_i·d-1 用 Miller 型平方链分解、sha3_512(str(sum(primes)))[:16] 作 AES-ECB key，与原文 task.py/exp 一致。未验证点：未本机复跑 LLL/分解；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-common-private-exponent-multiprime-lattice/
draft: false
kb_aliases:
- 共私钥指数攻击
- common private exponent attack
- Hinek-Ravva 攻击
- 多组公钥共用 d
- 多素数 RSA 共用 d
- LLL 恢复私钥指数
- e_i d - k_i phi(N_i)
---

## 一句话结论

当多组 RSA 公钥 `(N_i, e_i)` 由不同模数但同一个较小私钥指数 `d` 生成时，有 `e_i·d = 1 + k_i·φ(N_i)`；对 r 素数模数有 `φ(N_i)=N_i-s_i`、`s_i≈N_i^{1-1/r}`，把 `dM` 与各 `1-k_i·s_i` 组成同一个格中的短向量，LLL 约减后即可恢复 `d`，再用 `k_i=e_i·d-1`（λ(N_i) 的倍数）做 Miller 型分解拆开每个模数，最终解密所有密文。

## 原理

- RSA 关键等式：对每个实例 `e_i·d = 1 + k_i·φ(N_i)`，`k_i` 为正整数。所有实例共享同一个 `d`，而 `e_i` 各不相同。
- 多素数模数 `N_i = ∏ p_j`（r 个 512-bit 素数）时，`φ(N_i) = ∏(p_j-1) = N_i - s_i`，其中 `s_i` 是所有一阶项之和（`p_1+p_2+…+p_r - 1` 量级），约为 `N_i^{1-1/r}`。r=3 时 `s_i ≈ N_i^{2/3}`，远小于 `N_i`。
- 改写等式：`e_i·d - k_i·N_i = 1 - k_i·s_i`。右端 `1-k_i·s_i` 与 `d`、`s_i` 同阶，是一个“小量”；这就是格攻击的入口。
- 构造 (t+1) 维格（t 组公钥）：前 t 行只有对角元 `N_i`，最后一行是 `(e_1, e_2, …, e_t, -M)`。取整数向量 `(k_1, …, k_t, d)` 右乘该基，得到 `(k_1N_1 + d·e_1, …, k_tN_t + d·e_t, -dM) = (1-k_1s_1, …, 1-k_ts_t, -dM)`。
- 缩放量 `M` 取与 `N^{1-1/r}` 同量级（多素数 r=3 时约 `N^{2/3}`，实践中取几何平均模数的 2/3 次幂再乘若干小倍数尝试），使前 t 个“小量”和最后一个 `dM` 的长度可比；该向量显著短于格中随机向量，LLL 能将其找出。
- 从短向量最后一维取 `d = |v_last| / M`（符号/倍数偏差需枚举校验）；用 `pow(pow(m,e_i,N_i), d, N_i) == m` 对随机 m 验证。
- 已知 `d` 后，`k_i = e_i·d - 1` 是 `λ(N_i)`（因而也是 `φ(N_i)` 相关量）的倍数。对任意底数 `a`，`a^{k_i} ≡ 1 (mod N_i)` 对所有素数因子成立；把 `k_i=2^s·u` 后用 Miller-Rabin 式的平方链 `gcd(a^{2^j·u}-1, N_i)` 可概率性拆出因子，多素数模数则递归拆分。
- 为什么成立：复用同一 `d` 让多个独立模数之间产生了共同的短向量结构；模数越多、维数越高，可容忍的 `d` 上界越高，接近 `N^{1/2}`。

## 触发条件

- 多组 RSA 公钥 `(N_i, e_i)` 共享同一个私钥指数 `d`（密钥生成脚本复用 `d`，或“同一口令派生 d”的实现缺陷）。
- `d` 相对模数较小（多模数下通常要求 `d` 明显小于 `N`，r=3、t=5 的实例中 425-bit `d` 配 1536-bit `N` 即可）。
- 攻击者已知全部 `N_i`、`e_i` 以及至少一个待解密密文。
- 能运行 LLL（fpylll 或 Sage）；模数规模相近时格平衡最好。
- 模数为多素数（r≥3）时 `s_i` 更小，攻击条件更宽松，但分解步骤需支持多因子。

## 利用步骤

1. 收集共享 `d` 的多组 `(N_i, e_i)`；计算模数几何平均值 `Nbar`，取 `M0 = Nbar**(1-1/r)`（r=3 时 `Nbar**(2/3)`）。
2. 对 `M = M0 × {1,2,3,4,6,8,…}` 逐个构造 (t+1) 维基：前 t 行第 i 行第 i 列为 `N_i`；最后一行前 t 列为 `e_i`、最后一列为 `-M`。
3. 对基做 LLL，按“前 t 维无穷范数”排序候选行；取最后一维能被 `M` 整除的行，令 `d = |v_last|/M`，用 `(e_i·d-1)` 的奇偶/可解性做粗筛，再用 `pow(pow(m,e_i,N_i),d,N_i)==m` 验证。
4. 对每个模数计算 `k_i = e_i·d - 1`，按 `k_i = 2^s·u` 分解，随机取底数 `a` 走平方链并用 `gcd` 拆因子；未拆开时用 Pollard Rho 兜底，递归直到全部因子为素数。
5. 若题目用素数之和等派生量加密（如 `sha3_512(str(sum(primes)))[:16]` 作 AES 密钥），按同一派生规则恢复密钥并解密密文。
6. 若 LLL 未直接命中，扩大 `M` 的倍数搜索范围或增加模数数量；仍失败则说明 `d` 超出该维数的可恢复界。

## PoC

```python
# fpylll 版本：t 组 (N_i, e_i) 共享同一个 d；r=3 多素数模数
from fpylll import IntegerMatrix, LLL
from math import gcd, prod
import random

def recover_d(ns, es, r=3, multipliers=(1,2,3,4,6,8,12,16,24,32)):
    t = len(ns)
    Nbar = prod(ns) ** (1.0 / t)
    M0 = int(Nbar ** (1 - 1.0 / r))          # r=3 时约为 N^(2/3)
    for mul in multipliers:
        M = M0 * mul
        B = IntegerMatrix(t + 1, t + 1)
        for i in range(t):
            B[i, i] = ns[i]
        for j in range(t):
            B[t, j] = es[j]
        B[t, t] = -M
        LLL.reduction(B)
        rows = [[int(B[i, j]) for j in range(t + 1)] for i in range(t + 1)]
        rows.sort(key=lambda v: max(abs(x) for x in v[:-1]))
        for v in rows[:6]:
            if v[-1] % M:
                continue
            d = abs(v[-1]) // M
            if d and all(pow(pow(2, es[i], ns[i]), d, ns[i]) == 2 for i in range(t)):
                return d
    raise RuntimeError("LLL failed; enlarge M multiplier range")

def factor_with_k(N, k, trials=64):
    # k 是 lambda(N) 的倍数；Miller 型平方链分解（适用于多素数 N）
    s = 0
    while k % 2 == 0:
        k //= 2; s += 1
    def split(n):
        for _ in range(trials):
            a = random.randrange(2, n - 1)
            x = pow(a, k, n)
            if x in (1, n - 1):
                continue
            for _ in range(s):
                y = pow(x, 2, n)
                if y == 1:
                    g = gcd(x - 1, n)
                    if 1 < g < n:
                        return g, n // g
                    break
                if y == n - 1:
                    break
                x = y
        return None
    out, stack = [], [N]
    while stack:
        cur = stack.pop()
        if is_probable_prime(cur):
            out.append(cur); continue
        part = split(cur)
        if part:
            stack.extend(part)
        else:
            g = pollard_rho(cur)
            stack.extend([g, cur // g])
    return sorted(out)

d = recover_d(ns, es)
all_primes = [factor_with_k(N, e * d - 1) for N, e in zip(ns, es)]
# 之后按题目的密钥派生规则（如 sha3_512(str(sum(所有素数)))）解密密文
```

```text
上述 recover_d/factor_with_k 为核心逻辑；is_probable_prime 与 pollard_rho 为标准辅助函数，按需补全。
```

## 变体与关联

- 变体：所有公钥共用同一个 `e` 且模数不同、共享 `d` 时属于 Dual RSA 的格构造（第一行 `(A,e,…,e)`），本卡的基是它的转置形式，对应不同的 `e_i`。
- 变体：模数为两个素数时 `s_i=p_i+q_i`，`φ=N-s`，同样代入；r 越大 `s` 相对模数越小，短向量越明显。
- 变体：`d` 略超界时，把 `d` 拆成已知高位与未知低位，在格中加入 `e_i·d_hi` 项并对低位小范围枚举。
- 关联：[[crypto-rsa-dual-rsa-lattice-small-d]]（同 `e` 多模数 Dual RSA）、[[crypto-rsa-wiener-small-private-exponent-large-e]]（单模数小 d）、[[crypto-rsa-boneh-durfee-small-private-exponent]]（单模数 Boneh-Durfee）、[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]（同模数多密钥 HGS）。

## 检测与防御

- 防御：每次密钥生成使用独立随机私钥指数 `d`，绝不在多个模数间复用；使用标准库生成密钥并校验 `d` 的位长与 `φ` 的关系。
- 防御：私钥指数必须足够大（通常与模数同阶），避免为了性能使用固定的较小 `d`；多素数 RSA 需额外校验各素数独立随机。
- 检测：审计多个公钥是否共享相同 `d`（可用 `pow(pow(2,e_i,N_i),d,N_i)` 对已知/疑似 `d` 交叉验证）；检查 `e_i` 是否由同一 `d` 派生、`d` 位长是否异常小。
- 响应：确认 `d` 复用或泄露后，视为所有相关模数全部失陷，立即轮换全部密钥并评估历史密文。
