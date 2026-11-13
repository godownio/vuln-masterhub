---
id: ctf-crypto-superincreasing-knapsack-merkle-hellman-decrypt
title: 超递增背包密码（Merkle-Hellman）解密：密文乘 n 的模逆元还原 W 后，从最大项倒序贪心还原 0/1 明文
type: scenario
domain: ctf
path: ctf/crypto
technique: superincreasing-knapsack-merkle-hellman-decrypt
tags:
- ctf
- crypto
- knapsack
- subset-sum
- superincreasing
- merkle-hellman
- greedy
- public-key
cve: []
severity: low
confidence: high
status: draft
created: '2026-11-10'
updated: '2026-11-10'
url: /docs/ctf/crypto/ctf-crypto-superincreasing-knapsack-merkle-hellman-decrypt/
draft: false
kb_aliases:
- 背包密码解密
- Merkle-Hellman 背包
- 超递增序列
- 超递增背包
- knapsack cipher
- 背包加密
---

## 一句话结论

背包密码用超递增序列（每项大于前面所有项之和）作私钥陷门、`d_i = a_i·n mod m` 作公钥；已知私钥参数时，解密就是先把每个密文块 `c` 变换为 `W = c·n⁻¹ mod m`（还原出原始超递增域的背包和），再从序列最大项倒序按「`W ≥ a_i` 则位取 1 并令 `W -= a_i`，否则取 0」贪心，`O(n)` 还原出每块的 0/1 明文位。

## 原理

- 背包问题（子集和）：给定重量序列 `a_1..a_n` 与目标 `W`，求 0/1 向量 `b` 使 `Σ b_i·a_i = W`。一般情形是 NP 难的，这正是背包密码的困难性来源；但若序列是**超递增**的，问题线性可解，构成陷门。
- 超递增序列定义：对任意 `k`，`a_k > Σ_{i<k} a_i`。贪心正确性：
  - 若当前剩余目标 `W ≥ a_k`：假设 `b_k = 0`，则前面所有项全选也只有 `Σ_{i<k} a_i < a_k ≤ W`，不可能凑满 `W`，矛盾，故 `b_k` 必为 1；
  - 若 `W < a_k`：所有重量为正，选入 `a_k` 立即超过 `W`，故 `b_k` 必为 0。
  - 每步唯一确定一位，从 `a_n` 递推到 `a_1` 即完整解，无需搜索。
- Merkle-Hellman 构造：选超递增序列 `[a_i]`、模数 `m > Σ a_i`、乘数 `n` 满足 `gcd(n, m) = 1`，公钥为 `d_i = a_i·n mod m`。
- 模变换为什么可逆：加密 `c = Σ b_i·d_i ≡ n·Σ b_i·a_i (mod m)`。由于 `Σ b_i·a_i ≤ Σ a_i < m`，内层和没有超出模数，于是 `c·n⁻¹ mod m = Σ b_i·a_i` 精确等于超递增域的目标 `W`。知道 `n、m` 就能从公钥域退回超递增域；不知道的攻击者面对的是普通（低密度）子集和，需借助格约减攻击。
- 分块：明文二进制按序列长度 `L` 切块，每块独立算一个密文整数；解密每块还原 `L` 位。块间顺序与补位方式由题目约定，最后拼回字节得明文。

## 触发条件

- 题目给出私有参数：超递增序列，以及模数 `m`、乘数 `n`（或已通过其它手段恢复这些参数）；
- 密文按块给出，每块等于公钥元素的 0/1 加权和（可能取模）；
- 序列排序后满足严格超递增（`a_k > Σ_{i<k} a_i`，元素互不相同）；
- 明文每块位长不超过序列长度（教学/CTF 常见 6~64 位一块）。

## 利用步骤

1. 把序列按升序整理并验证超递增性质（不满足则不是超递增背包，需改用格攻击路线）。
2. 计算 `n_inv = pow(n, -1, m)`（要求 `gcd(n, m) = 1`）。
3. 对每个密文块 `c`：`W = c * n_inv % m`。
4. 从最大项倒序贪心：`W >= a_i` 时该位为 1 并 `W -= a_i`，否则为 0；结束后 `W` 应为 0。
5. 按块序拼接位串，按 8 位一组（及题目约定的补位/大小端）转 ASCII/flag。

## PoC

```python
def resolve(a, w):
    """a 为升序超递增序列；返回等长 0/1 位列表"""
    bits = []
    for x in reversed(a):
        if w >= x:
            bits.insert(0, 1)
            w -= x
        else:
            bits.insert(0, 0)
    assert w == 0, "序列非超递增或参数错误"
    return bits

def decrypt_block(c, n, m, priv):
    w = c * pow(n, -1, m) % m      # 模逆还原到超递增域
    return resolve(priv, w)

priv = [1, 3, 6, 11, 23, 45]
n, m = 41, 95
# 公钥 d_i = a_i*n mod m = [41, 28, 56, 71, 88, 40]
# 明文块 [0,1,1,0,0,1]（3+6+45=54）-> 密文 124
assert decrypt_block(124, n, m, priv) == [0, 1, 1, 0, 0, 1]
```

无 shell 可执行 PoC；以上为纯数论脚本，可在本地直接验证。

## 变体与关联

- 变体：题面直接给超递增序列和目标 `W`（无模变换）时，跳过步骤 2，直接贪心求解。
- 变体：私钥元素顺序被打乱时，先升序排序求解释放，再按原下标映射位序，见 [[ctf-crypto-shuffled-superincreasing-knapsack-reorder-decrypt]]。
- 变体：明文多块时注意块间顺序、补位方向与位序（MSB/LSB first），按题目输出约束（如 flag 字符集）筛选。
- 关联：只拿得到公钥（无 `n、m、a`）时不能贪心，属低密度子集和问题，需 LLL/CVP 或格攻击恢复私钥/选择向量，见 [[ctf-crypto-subset-sum-known-prefix-lll-cvp]]、[[ctf-reverse-apk-knapsack-chacha20-vault]]。
- 边界：Merkle-Hellman 是 1978 年最早的公钥加密方案之一，早已被基于格的攻击（Shamir 迭代还原等）破掉，不能用于真实系统；本卡仅覆盖「已知私钥参数」的合法解密/解题路径。

## 检测与防御

- 检测（CTF 识别）：题面给出一组大整数与若干密文整数，伴随模数/乘数或「公钥/私钥」字样；把该组数排序后逐项验证 `a_k > Σ_{i<k} a_i` 可确认超递增背包。
- 检测（真实环境）：出现自定义「背包/子集和」加解密实现而非标准算法；密钥参数以明文形式出现在题面、配置或代码中。
- 防御：不要使用 Merkle-Hellman/背包类自定义公钥密码，改用 RSA/ECC 等标准方案；超递增序列、`m`、`n` 任一泄露都等价于私钥泄露，必须按私钥级别保护。
- 加固：教学/CTF 场景明确与生产隔离；若确需演示背包困难性，避免同时暴露可用于验证的超递增结构参数。
