---
id: crypto-rsa-dual-rsa-lattice-small-d
title: Dual RSA 共模多模数：构造格同时求解小私钥 d 与各模数 φ
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-dual-rsa-lattice
aliases:
- Dual RSA
- 双模数 RSA
- 共私钥多模数
- 小 d 同时丢番图逼近
- 多模数格攻击
tags:
- rsa
- dual-rsa
- lattice
- small-d
- common-modulus
- lll
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:49+08:00'
  notes: 已对照原文与图06核对：ed=1+k_i·φ(N_i)、s_i=p_i+q_i-1、L=[[A,e,e],[0,-N1,0],[0,0,-N2]]、(d,k1,k2)L=(A·d,1-k1·s1,1-k2·s2)、A=e·N^{-1/2}、d<N^{1/3} 与图06 完全一致。卡片 PoC 为按矩阵补全的最小验证框架（原文未给可运行脚本），已注明。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

Dual RSA 用同一对 `(e,d)` 对应多个模数 `N_i`（`e·d ≡ 1 mod φ(N_i)`）。当 `d < N^{1/3}` 时，可构造格 `L=[[A,e,…,e],[0,-N_1,0,…],…]`，使 `(d,k_1,…)` 乘格基得到短向量 `(A·d, 1-k_1·s_1, …)`（`s_i=p_i+q_i-1`），LLL 约减后即可恢复 `d`，进而解密所有模数下的密文。

## 原理

- 同一私钥指数 `d` 用于多个模数：`e·d ≡ 1 (mod φ(N_i))`，因此存在整数 `k_i` 使 `e·d = 1 + k_i·φ(N_i)`。
- 写 `φ(N_i) = N_i - s_i`，其中 `s_i = p_i + q_i - 1 ≈ √N_i`。于是 `e·d - k_i·N_i + k_i·s_i = 1`，即 `e·d - k_i·N_i = 1 - k_i·s_i`。
- 构造格（两个模数为例）：
  `L = [[A, e, e], [0, -N_1, 0], [0, 0, -N_2]]`。
  取整数向量 `(d, k_1, k_2)` 右乘 `L`，得到 `(A·d, e·d - k_1·N_1, e·d - k_2·N_2) = (A·d, 1 - k_1·s_1, 1 - k_2·s_2)`。
- 选择 `A ≈ e/√N`（`N` 为单个模数量级），使 `A·d` 与 `k_i·s_i` 量级平衡。由于 `k_i ≈ d`、`s_i ≈ √N`，短向量长度约为 `d·√N`；格行列式约为 `A·∏N_i`，LLL 可找到该短向量的条件约为 `d < N^{1/3}`。
- 从约减后的短向量中取出第一分量 `A·d`，除以 `A` 即得 `d`；用 `pow(pow(m,e,N_i),d,N_i)==m` 对随机 `m` 校验，或直接解密目标密文。
- 模数越多，格维数越高，可容忍的 `d` 上界越接近 `N^{1/2}`；当 `d` 临近边界时，可用“已知部分 d 高位”的扩展格做小范围爆破（原文图示的第二组矩阵）。

## 触发条件

- 多个 RSA 模数 `N_i` 共用同一 `e` 与同一 `d`（Dual RSA 或多密钥复用私钥）。
- `d` 较小，约小于 `N^{1/3}`（两个模数时；更多模数可放宽）。
- 攻击者已知各 `N_i`、`e`，以及至少一个模数下的密文。
- 能运行 LLL/BKZ；`N_i` 规模相近时格平衡最好。

## 利用步骤

1. 收集共用 `(e,d)` 的多个模数 `N_1…N_l`，确认 `e` 相同且私钥复用。
2. 取 `A ≈ e / sqrt(N_1)`（或各模数的几何平均），构造格：
   - 第一行 `(A, e, e, …, e)`；
   - 第 `i+1` 行第 `i+1` 列为 `-N_i`，其余为 0。
3. 对格基做 LLL，在约减基中寻找第一分量能被 `A` 整除、且其余分量形如 `1 - k_i·s_i` 的短向量。
4. 由第一分量求 `d = |v_0| / A`；用随机 `m` 验证 `pow(pow(m,e,N_i),d,N_i)==m` 对所有 `i` 成立。
5. 用 `d` 解密目标密文；若 `d` 略大于界，改用部分 `d` 高位的扩展格或对低位小范围爆破。

## PoC

```python
# Sage 伪代码：两个模数的 Dual RSA 格
N1, N2, e = ...
A = round(e / sqrt(N1))          # 平衡系数
L = Matrix(ZZ, [
    [A,  e,  e],
    [0, -N1, 0],
    [0,  0, -N2],
])
B = L.LLL()
for row in B:
    if row[0] != 0 and abs(row[0]) % A == 0:
        d = abs(row[0]) // A
        if all(pow(pow(2, e, Ni), d, Ni) == 2 for Ni in (N1, N2)):
            print("d =", d)
            break
```

> 原文只给出格构造图与 `d < N^{1/3}` 的条件，未提供完整可运行 PoC；上式是按其矩阵补全的最小验证框架，实际参数需按模数规模调整。

## 变体与关联

- 变体：`l` 个模数时格为 `(l+1)` 维，第一行 `(A,e,…,e)`，其余为 `-N_i` 对角；模数越多，`d` 的上界越高。
- 变体：`d` 临近边界时，把 `d` 拆成已知高位 `d_h` 与未知低位 `d_s`，在格中加入 `ed_h` 项并小范围爆破 `d_s`。
- 变体：若只是同一明文在多个模数下加密（共模广播），不需要私钥，直接用 CRT/共模攻击。
- 关联：[[crypto-rsa-boneh-durfee-small-private-exponent]]（单模数小 d）、[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]（多密钥 HGS）、[[crypto-rsa-common-modulus]]（同模数共模攻击）。

## 检测与防御

- 防御：每个密钥使用独立模数与独立私钥指数，绝不复用 `(e,d)`。
- 防御：`d` 必须足够大（至少 `n^0.5` 量级）；使用标准库生成密钥并做参数自检。
- 检测：审计多个公钥是否共享相同 `e`/相同模数结构，检查私钥 `d` 的位长是否异常小；CTF 中看到“同一 d 加密多个 N”即可按本卡尝试。
- 响应：确认私钥复用或小 `d` 后，视为所有相关模数失陷，立即轮换全部密钥并审计历史密文。
