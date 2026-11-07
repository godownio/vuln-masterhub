---
id: ctf-crypto-feistel-gf2-16-cubic-rank-drop-key-recovery
title: Feistel 立方轮函数 GF(2^16) 代数攻击：多项式基秩下降恢复 16-bit 轮密钥
type: scenario
domain: ctf
path: ctf/crypto
technique: feistel-gf2-16-cubic-rank-drop-key-recovery
aliases:
- Feistel 代数攻击
- GF(2^16) 三次函数
- 秩下降恢复轮密钥
- MyBlock
- 多项式基攻击
tags:
- ctf
- crypto
- feistel
- gf2
- rank
- polynomial
- key-recovery
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:48:03+08:00'
  notes: 已对照原文 MyBlock 节核对：F(x,k)=(x+k)^3、GF(2^16)、POLY 0x1002D、8 轮 16-bit key、675 对/512s、左零空间 Q+逐 key rank drop、fwd=3/bwd=round_idx-3、末轮向前 peel，均与原文 exp 一致。未验证点：PoC 未本机对远端 oracle 复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

对轮函数为 `F(x,k)=(x+k)^3`（GF(2^16) 上三次映射）的 8 轮 Feistel，可用“明文端多项式基约束 + 密文端逐 key 猜测”的秩下降攻击：把中间量写成 `L0,R0` 的单项式向量，求明文矩阵的左零空间 `Q`；对每个 16-bit 轮密钥猜测，从密文逆一轮后构造 `M_bwd`，正确 key 会使 `Q·M_bwd` 的秩明显下降，从而逐轮从末轮到首轮恢复 8 个 16-bit 轮密钥。

## 原理

- **Feistel 结构**：32-bit 状态拆成 `L0||R0`（各 16-bit），8 轮：
  `L_{i+1}=R_i`，`R_{i+1}=L_i ⊕ F(R_i,k_i)`；`F(x,k)=(x+k)^3`，加法是 GF(2) 异或，乘法按题目不可约多项式 `0x1002D` 约简。
- **为什么不能直接 MITM**：8 轮 key 共 128-bit；每轮 key 16-bit，完整 MITM 需要 `2^64` 级表，不可行。
- **代数增长慢**：三次幂在 GF(2^16) 上的展开项数增长远低于随机函数；把某个中间量 `S(L0,R0)` 写成 `Σ c_{a,b} L0^a R0^b`，基集合 `B` 的大小可控（不是所有幂次组合）。
- **左零空间约束**：对明文端走 `f` 轮（不猜 key，只用结构推导中间量必须落在的多项式空间），构造矩阵 `M_fwd`（每行是一组明文的单项式向量），求左零空间 `Q`，使 `Q·M_fwd≈0`；`Q` 的每一行就是一个合法中间量必须满足的线性约束。
- **秩下降判据**：对第 `t` 轮 key 猜 `k`，从密文端逆 `b` 轮得到候选中间量 `S_guess`，构造 `M_bwd`；若 `k` 正确，`Q·M_bwd` 接近零、秩明显下降；错误 key 时 `M_bwd` 近似随机矩阵，`Q·M_bwd` 基本满秩。实践中不必追求秩=0，稳定降 2 以上即可锁定。
- **逐轮剥离**：从末轮 `k7` 开始，猜 key 并逆一轮，把所有样本整体退一轮；再猜 `k6`……直到 `k0`。经验分配：`fwd=3` 轮，`bwd=round_idx-3`；当 `round_idx<3` 时数据已足够，直接纯 peel。
- **性能**：每个 key 一次 rank check，高斯消元是瓶颈；只取略多于列数的样本行、用 bitset/uint64 分块、rank drop 早停。

## 触发条件

- 题目给出加密 oracle/大量明密文对（本题最多 675 对，512 秒），轮函数为 GF(2^16) 上的低次多项式（三次）。
- Feistel 轮数较少（8 轮），key 每轮 16-bit。
- 已知/可推断不可约多项式、状态拆字方式（L/R 各 16-bit）。
- 有足够算力做 `2^16 × 8` 次密钥猜测 + 小矩阵高斯消元。

## 利用步骤

1. 确认轮函数与域参数：`F(x,k)=(x+k)^3`、`POLY=0x1002D`、`n=8`、16-bit 半块。
2. 采集明密文对；按 `L0||R0`、`L8||R8` 拆成 16-bit。
3. 写 GF(2^16) 乘法/求逆、`F`、`dec_one`（逆一轮）。
4. 生成前向/后向单项式基：从 `L={(1,0)}`、`R={(0,1)}` 开始，每轮把 `(R+k)^3` 展开为指数和，得到 `(a,b)` 集合；固定 `fwd=3`，`bwd=round_idx-3`。
5. 取略多于 `|fwd_basis|+|bwd_basis|` 的样本；构造 `M_fwd`，求左零空间 `Q`。
6. 对 `k=0..0xFFFF`：用 `dec_one` 逆一轮，构造 `M_bwd`，计算 `Q·M_bwd` 的秩；选秩最小/下降最大的 `k`。
7. 记录 `k`，对所有样本 peel 一轮，`round_idx-=1`，重复 5–6 直到 `k0`。
8. 用恢复的 8 个 key 解密/复验，按题目格式提交。

## PoC

```python
POLY = 0x1002D
MASK = 0xFFFF

def gf_mul(a, b):
    r = 0
    for i in range(16):
        if (b >> i) & 1:
            r ^= a << i
    for i in range(30, 15, -1):
        if (r >> i) & 1:
            r ^= POLY << (i - 16)
    return r & MASK

def gf_add(a, b): return a ^ b
def F(x, k):
    t = gf_add(x, k)
    return gf_mul(gf_mul(t, t), t)

def dec_one(L, R, k):
    # 逆 L'=R, R'=L^(R+k)^3
    return R, gf_add(L, F(R, k))

# rank / left_kernel_basis / basis_shape / eval_monomials 见原文；
# 核心循环：
# Q = left_kernel_basis(M_fwd)
# for k in range(0x10000):
#     peeled = [dec_one(L, R, k) for L, R in cts]
#     Mb = [eval_monomials(Lp, Rp, bwd_basis) for Lp, Rp in peeled]
#     rk = rank_gf(Q * Mb)
#     if rk < best_rank: best_key = k
```

说明：PoC 只保留 GF(2^16)、轮函数与逆轮；`basis_shape`/`left_kernel_basis`/`rank_gf` 需按原文实现（单项式指数跟踪 + GF(2^16) 高斯消元）。未在本机对远端 oracle 复跑。

## 变体与关联

- **不同次数**：`(x+k)^2`、`(x+k)^4` 等低次映射同样可用多项式基；次数越高基越大。
- **不同域**：GF(2^8)/GF(2^32) 调整乘法/求逆；32-bit key 猜测量变大，需要更细的剪枝。
- **更多轮**：增加 `fwd/bwd` 分配和样本量；秩下降信号可能变弱。
- **关联**：[[ctf-crypto-self-referential-key-tea-variant]]（TEA/Feistel 变体）、[[ctf-crypto-simon-period-measurement-gf2-nullspace]]（GF(2) 零空间攻击）。

## 检测与防御

- **设计**：避免低次代数轮函数；使用 AES/ChaCha 等成熟分组/流密码，增加轮数和非线性。
- **检测**：大量自适应明密文查询、固定差分/线性模式、针对末轮的 16-bit 猜测行为可作为代数攻击特征。
- **CTF**：本题是授权赛题；真实系统不要自创 Feistel + 低次轮函数。
